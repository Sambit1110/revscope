import { AsyncLocalStorage } from "node:async_hooks";

import {
  capabilityIssues,
  evidenceFromCapability,
  type CapabilityDescriptor,
} from "../domain/capability.js";
import {
  invalidInput,
  issuesFromZod,
  makeError,
  type ErrorEnvelope,
} from "../domain/errors.js";
import {
  stateTokenSchema,
  type Evidence,
  type EvidenceUnknown,
  type Subject,
} from "../domain/evidence.js";
import { canonicalJson, sha256Hex, type JsonObject } from "../domain/json.js";
import { err, ok, type Result } from "../domain/result.js";
import type {
  AnalysisProvider,
  ItemOutcome,
  Logger,
  ProviderCapability,
} from "./ports.js";

export const SNAPSHOT_SCHEMA = "revscope.session-snapshot/2";

export interface Uncertainty {
  readonly operation: string;
  readonly reason: string;
}

export interface SessionState {
  readonly consistency: "consistent" | "uncertain";
  /** True from the moment a mutation is requested until its outcome is recorded, including while it waits its turn. */
  readonly mutation_in_progress: boolean;
  /** Increments whenever cached knowledge stops describing the current state. */
  readonly revision: number;
  /** The provider state token the session has verified; null while uncertain. */
  readonly state_token: string | null;
  readonly uncertainty: Uncertainty | null;
}

export interface ReadResult {
  readonly evidence: Evidence;
  readonly cache: "hit" | "miss";
  /** False when the read was made while the session state was not verified. */
  readonly stateVerified: boolean;
}

export interface MutationResult {
  readonly evidence: Evidence;
  readonly items: readonly ItemOutcome[];
}

export interface ReconcileResult {
  readonly evidence: Evidence;
  readonly stateToken: string;
  readonly revision: number;
}

export interface SessionSnapshot {
  readonly schema: typeof SNAPSHOT_SCHEMA;
  readonly snapshot_id: string;
  readonly session_id: string;
  readonly provider: { readonly id: string; readonly version: string };
  readonly artifact_sha256: string;
  readonly state_revision: number;
  readonly state_token: string;
  readonly records: readonly Evidence[];
  readonly mutations: readonly Evidence[];
}

/** Built-in capability used to record each authoritative state observation. */
const OBSERVE_STATE: CapabilityDescriptor = {
  operation: "observe_state",
  description: "Observe the provider's current state token.",
  effect: "read",
  resultKind: "state-observation",
  limitations: [
    "Identifies the provider's analysis state as an opaque token; it does not describe the state's contents.",
  ],
};

const UNVERIFIED_UNKNOWN: EvidenceUnknown = {
  scope: "session-state",
  reason:
    "Produced while the session state was not verified; reconcile the session before relying on it together with other results.",
};

const MUTATION_IN_PROGRESS = "A mutation is in progress; its effect is not yet known.";
const MUTATION_PENDING =
  "A mutation has been requested and has not completed; its effect is not yet known.";

const itemsJson = (items: readonly ItemOutcome[]) =>
  items.map(({ key, status }) => ({ key, status }));

interface CacheEntry {
  readonly evidence: Evidence;
  readonly revision: number;
  readonly stateToken: string;
}

const validToken = (value: unknown): value is string =>
  stateTokenSchema.safeParse(value).success;

/**
 * Marks the asynchronous context of each queued operation with the session
 * running it, so a provider calling back into that session is detected
 * instead of queueing behind the operation it is part of.
 */
const activeOperation = new AsyncLocalStorage<AnalysisSession>();

/**
 * One provider-backed analysis session.
 *
 * Invariants:
 * - Reads are served from the cache only while the session is consistent, and
 *   only for entries recorded at the current revision and verified token.
 * - A mutation counts as in progress from the moment `mutate()` is called,
 *   including while it waits behind earlier operations, until its outcome is
 *   recorded. Throughout, `state()` reports uncertainty and `snapshot()`
 *   refuses, so neither can present the pre-mutation view as current.
 * - The session becomes uncertain before the provider is called, and returns
 *   to consistent only after the outcome and its evidence have been validated.
 * - Only a fresh `observeState()` result can end uncertainty. Ordinary reads
 *   never do.
 * - Reads, mutations, and reconciliation run one at a time in call order. A
 *   provider calling back into the session during one of them is refused with
 *   `session_reentry` rather than deadlocking.
 */
export class AnalysisSession {
  readonly #provider: AnalysisProvider;
  readonly #sessionId: string;
  readonly #logger: Logger | undefined;
  readonly #capabilities: ReadonlyMap<string, ProviderCapability>;
  #cache = new Map<string, CacheEntry>();
  readonly #mutations: Evidence[] = [];
  #revision = 0;
  #stateToken: string | null = null;
  #uncertainty: Uncertainty | null = null;
  /** Mutations requested and not yet settled, oldest first. */
  readonly #pendingMutations: { readonly operation: string }[] = [];
  #tail: Promise<unknown> = Promise.resolve();

  private constructor(
    provider: AnalysisProvider,
    sessionId: string,
    capabilities: ReadonlyMap<string, ProviderCapability>,
    logger: Logger | undefined,
  ) {
    this.#provider = provider;
    this.#sessionId = sessionId;
    this.#capabilities = capabilities;
    this.#logger = logger;
  }

  /**
   * Check every capability declaration, then establish the initial verified
   * state token with a fresh state observation.
   *
   * Provider results always describe analysis state, so a provider can never
   * declare a kind that speaks for the original artifact (such as presenting
   * decompiler output as artifact bytes), nor take the session's own
   * `observe_state` operation.
   */
  static async open(
    provider: AnalysisProvider,
    sessionId: string,
    logger?: Logger,
  ): Promise<Result<AnalysisSession, ErrorEnvelope>> {
    const capabilities = new Map<string, ProviderCapability>();
    for (const capability of provider.capabilities()) {
      const issues = capabilityIssues(capability, {
        subjectKind: "analysis-state",
        reservedOperations: [OBSERVE_STATE.operation],
      });
      if (capabilities.has(capability.operation)) issues.push("the operation is declared more than once");
      if (issues.length > 0)
        return err(
          makeError("internal_error", "The provider declared an invalid capability", {
            operation: String(capability.operation),
            issues,
          }),
        );
      capabilities.set(capability.operation, capability);
    }
    const session = new AnalysisSession(provider, sessionId, capabilities, logger);
    session.#uncertainty = { operation: "open", reason: "The initial state has not been observed yet." };
    const observed = await session.reconcile();
    return observed.ok ? ok(session) : observed;
  }

  /** What is currently known; a pending mutation always reads as uncertain. */
  state(): SessionState {
    const uncertainty = this.#currentUncertainty();
    return {
      consistency: uncertainty === null ? "consistent" : "uncertain",
      mutation_in_progress: this.#pendingMutations.length > 0,
      revision: this.#revision,
      state_token: uncertainty === null ? this.#stateToken : null,
      uncertainty,
    };
  }

  /** Read through the cache while consistent; always go to the provider otherwise. */
  read(operation: string, parameters: unknown): Promise<Result<ReadResult, ErrorEnvelope>> {
    return this.#exclusive("read", () => this.#read(operation, parameters));
  }

  /** Apply a mutation and record exactly what is known about its effect. */
  mutate(operation: string, parameters: unknown): Promise<Result<MutationResult, ErrorEnvelope>> {
    const reentry = this.#reentry("mutate");
    if (reentry !== null) return Promise.resolve(err(reentry));
    // Registered synchronously: from this call on, nothing may report the
    // pre-mutation state as current, even before the mutation's turn comes.
    const pending = { operation };
    this.#pendingMutations.push(pending);
    const settled = () => {
      this.#pendingMutations.splice(this.#pendingMutations.indexOf(pending), 1);
    };
    const run = this.#exclusive("mutate", () => this.#mutate(operation, parameters));
    run.then(settled, settled);
    return run;
  }

  /** Observe the provider's state token afresh; the only way to end uncertainty. */
  reconcile(): Promise<Result<ReconcileResult, ErrorEnvelope>> {
    return this.#exclusive("reconcile", () => this.#reconcile());
  }

  /**
   * Export cached knowledge for the current verified state, or refuse while
   * the state is uncertain, including while any mutation is pending.
   */
  snapshot(): Result<SessionSnapshot, ErrorEnvelope> {
    const uncertainty = this.#currentUncertainty();
    if (uncertainty !== null || this.#stateToken === null)
      return err(
        makeError("state_uncertain", "A snapshot cannot be exported while the session state is uncertain", {
          state_revision: this.#revision,
          mutation_in_progress: this.#pendingMutations.length > 0,
          uncertainty: uncertainty === null ? null : { ...uncertainty },
        }),
      );
    const stateToken = this.#stateToken;
    const records = [...this.#cache.values()]
      .filter((entry) => entry.revision === this.#revision && entry.stateToken === stateToken)
      .map(({ evidence }) => evidence)
      .toSorted((a, b) => (a.evidence_id < b.evidence_id ? -1 : a.evidence_id > b.evidence_id ? 1 : 0));
    const body: Omit<SessionSnapshot, "snapshot_id"> = {
      schema: SNAPSHOT_SCHEMA,
      session_id: this.#sessionId,
      provider: { ...this.#provider.identity },
      artifact_sha256: this.#provider.artifactSha256,
      state_revision: this.#revision,
      state_token: stateToken,
      records,
      mutations: [...this.#mutations],
    };
    return ok({
      ...body,
      snapshot_id: `snap_${sha256Hex(canonicalJson(body as unknown as JsonObject))}`,
    });
  }

  /** Recorded uncertainty, or the uncertainty implied by a pending mutation. */
  #currentUncertainty(): Uncertainty | null {
    if (this.#uncertainty !== null) return this.#uncertainty;
    const [oldest] = this.#pendingMutations;
    return oldest === undefined ? null : { operation: oldest.operation, reason: MUTATION_PENDING };
  }

  /** A call made from inside one of this session's own operations cannot be queued safely. */
  #reentry(method: string): ErrorEnvelope | null {
    if (activeOperation.getStore() !== this) return null;
    this.#logger?.error({ event: "session_reentry", operation: method });
    return makeError("session_reentry", `${method} was called from inside an operation of the same session`, {
      method,
    });
  }

  /** Queue a task behind every earlier operation and run it marked as this session's. */
  #exclusive<T>(
    method: string,
    task: () => Promise<Result<T, ErrorEnvelope>>,
  ): Promise<Result<T, ErrorEnvelope>> {
    const reentry = this.#reentry(method);
    if (reentry !== null) return Promise.resolve(err(reentry));
    const marked = () => activeOperation.run(this, task);
    const run = this.#tail.then(marked, marked);
    this.#tail = run.catch(() => undefined);
    return run;
  }

  #operationNames(): string[] {
    return [...this.#capabilities.keys()].toSorted();
  }

  #subject(stateToken: string, revision = this.#revision): Subject {
    return {
      kind: "analysis-state",
      artifact_sha256: this.#provider.artifactSha256,
      session_id: this.#sessionId,
      state_revision: revision,
      state_token: stateToken,
    };
  }

  #resolve(
    operation: string,
    effect: "read" | "mutate",
    parameters: unknown,
  ): Result<{ capability: ProviderCapability; parameters: JsonObject }, ErrorEnvelope> {
    const capability = this.#capabilities.get(operation);
    if (capability === undefined)
      return err(
        makeError("unsupported_operation", `The provider does not support operation ${operation}`, {
          operation,
          available_operations: this.#operationNames(),
        }),
      );
    if (capability.effect !== effect)
      return err(
        invalidInput(`Operation ${operation} is a ${capability.effect} operation`, [
          { path: "operation", message: `Use ${capability.effect} for this operation` },
        ]),
      );
    const parsed = capability.parameters.safeParse(parameters ?? {});
    if (!parsed.success)
      return err(
        invalidInput(`Parameters for ${operation} are invalid`, issuesFromZod(parsed.error, "params")),
      );
    return ok({ capability, parameters: parsed.data });
  }

  /** Discard everything cached and stop trusting the current state. */
  #becomeUncertain(operation: string, reason: string): void {
    this.#revision += 1;
    this.#uncertainty = { operation, reason };
    this.#cache = new Map();
  }

  #providerFailure(operation: string, reason?: string): ErrorEnvelope {
    return makeError("provider_failure", `The provider could not complete ${operation}`, {
      operation,
      ...(reason === undefined ? {} : { reason }),
    });
  }

  #logRaised(event: string, operation: string, cause: unknown): void {
    this.#logger?.warn({
      event,
      operation,
      error_class: cause instanceof Error ? cause.name : typeof cause,
    });
  }

  async #read(operation: string, rawParameters: unknown): Promise<Result<ReadResult, ErrorEnvelope>> {
    const resolved = this.#resolve(operation, "read", rawParameters);
    if (!resolved.ok) return resolved;
    const { capability, parameters } = resolved.value;
    const key = `${operation}:${canonicalJson(parameters)}`;
    const cached = this.#cache.get(key);
    if (
      this.#uncertainty === null &&
      cached !== undefined &&
      cached.revision === this.#revision &&
      cached.stateToken === this.#stateToken
    )
      return ok({ evidence: cached.evidence, cache: "hit", stateVerified: true });

    let outcome;
    try {
      outcome = await this.#provider.read(operation, parameters);
    } catch (cause: unknown) {
      this.#logRaised("provider_read_raised", operation, cause);
      return err(this.#providerFailure(operation));
    }
    if (outcome.status === "failed") return err(this.#providerFailure(operation, outcome.reason));
    if (!validToken(outcome.stateToken))
      return err(this.#providerFailure(operation, "The provider returned no valid state token."));

    if (this.#uncertainty === null && outcome.stateToken !== this.#stateToken)
      // The provider's state changed without this session's knowledge.
      this.#becomeUncertain(
        operation,
        "The provider reported a different state token than the one this session verified; the state changed outside the session.",
      );
    const verified = this.#uncertainty === null;
    const evidence = evidenceFromCapability(capability, {
      subject: this.#subject(outcome.stateToken),
      parameters,
      payload: outcome.payload,
      producer: this.#provider.identity,
      unknowns: [...outcome.unknowns, ...(verified ? [] : [UNVERIFIED_UNKNOWN])],
      limitations: outcome.limitations,
    });
    if (!evidence.ok) return evidence;
    if (verified)
      this.#cache.set(key, {
        evidence: evidence.value,
        revision: this.#revision,
        stateToken: outcome.stateToken,
      });
    return ok({ evidence: evidence.value, cache: "miss", stateVerified: verified });
  }

  async #mutate(
    operation: string,
    rawParameters: unknown,
  ): Promise<Result<MutationResult, ErrorEnvelope>> {
    const resolved = this.#resolve(operation, "mutate", rawParameters);
    if (!resolved.ok) return resolved;
    const { capability, parameters } = resolved.value;
    if (this.#uncertainty !== null || this.#stateToken === null)
      return err(
        makeError("state_uncertain", "Mutations are refused while the session state is uncertain", {
          state_revision: this.#revision,
          uncertainty: this.#uncertainty === null ? null : { ...this.#uncertainty },
        }),
      );

    // Become uncertain before handing control to the provider: from here on
    // the state may change at any moment, whatever the provider later reports.
    const before = { cache: this.#cache, stateToken: this.#stateToken };
    this.#becomeUncertain(operation, MUTATION_IN_PROGRESS);
    let outcome;
    try {
      outcome = await this.#provider.mutate(operation, parameters);
    } catch (cause: unknown) {
      this.#logRaised("provider_mutation_raised", operation, cause);
      return err(
        this.#remainUncertain(operation, "unknown", [], "The provider raised an exception during the mutation; its effect on analysis state is unknown."),
      );
    }

    if (outcome.status === "partial")
      return err(this.#remainUncertain(operation, outcome.stateEffect, outcome.items, outcome.reason));
    if (!validToken(outcome.stateToken))
      return err(
        this.#remainUncertain(operation, "unknown", outcome.status === "applied" ? outcome.items : [], "The provider returned no valid state token for the mutation."),
      );

    if (outcome.status === "rejected") {
      if (outcome.stateToken !== before.stateToken)
        return err(
          this.#remainUncertain(operation, "unknown", [], "The provider reported no change, but its state token changed."),
        );
      // Verified unchanged: keep what was known before the attempt, carried
      // into the current revision so revisions stay monotonic.
      this.#cache = new Map(
        [...before.cache].map(([key, entry]) => [key, { ...entry, revision: this.#revision }]),
      );
      this.#uncertainty = null;
      return err(
        makeError("mutation_rejected", `The provider rejected ${operation}`, {
          operation,
          possibly_mutated: false,
          state_effect: "none",
          reason: outcome.reason,
        }),
      );
    }

    // Validate the acknowledgement before trusting it: an applied change that
    // cannot be recorded leaves the session uncertain, never silently consistent.
    const evidence = evidenceFromCapability(capability, {
      subject: this.#subject(outcome.stateToken),
      parameters,
      payload: { items: itemsJson(outcome.items), result: outcome.payload },
      producer: this.#provider.identity,
      unknowns: [],
      limitations: [],
    });
    if (!evidence.ok)
      return err(
        this.#remainUncertain(operation, "unknown", outcome.items, "The provider reported the mutation as applied, but its acknowledgement could not be recorded as valid evidence."),
      );
    this.#stateToken = outcome.stateToken;
    this.#uncertainty = null;
    this.#mutations.push(evidence.value);
    return ok({ evidence: evidence.value, items: outcome.items });
  }

  /** Record why the state stays unverified after a mutation and describe it to the caller. */
  #remainUncertain(
    operation: string,
    stateEffect: "changed" | "unknown",
    items: readonly ItemOutcome[],
    reason: string,
  ): ErrorEnvelope {
    this.#uncertainty = { operation, reason };
    return makeError("partial_failure", `Mutation ${operation} did not complete as a verified change`, {
      operation,
      possibly_mutated: true,
      state_effect: stateEffect,
      items: itemsJson(items),
      reason,
      state_revision: this.#revision,
    });
  }

  async #reconcile(): Promise<Result<ReconcileResult, ErrorEnvelope>> {
    let observed;
    try {
      observed = await this.#provider.observeState();
    } catch (cause: unknown) {
      this.#logRaised("provider_observe_state_raised", "observe_state", cause);
      return err(this.#providerFailure("observe_state"));
    }
    if (observed.status === "failed") return err(this.#providerFailure("observe_state", observed.reason));
    if (!validToken(observed.stateToken))
      return err(this.#providerFailure("observe_state", "The provider returned no valid state token."));

    // A fresh authoritative token starts a new known epoch, committed only
    // once its observation has been recorded as valid evidence.
    const revision = this.#revision + 1;
    const evidence = evidenceFromCapability(OBSERVE_STATE, {
      subject: this.#subject(observed.stateToken, revision),
      parameters: {},
      payload: { state_token: observed.stateToken },
      producer: this.#provider.identity,
      unknowns: [],
      limitations: [],
    });
    if (!evidence.ok) return evidence;
    this.#revision = revision;
    this.#cache = new Map();
    this.#stateToken = observed.stateToken;
    this.#uncertainty = null;
    return ok({ evidence: evidence.value, stateToken: observed.stateToken, revision });
  }
}
