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
  /** True while a mutation has been handed to the provider and has not returned. */
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
 * One provider-backed analysis session.
 *
 * Invariants:
 * - Reads are served from the cache only while the session is consistent, and
 *   only for entries recorded at the current revision and verified token.
 * - A mutation makes the session uncertain before the provider is called, so
 *   `state()` and `snapshot()` never report stale state as consistent.
 * - Only a fresh `observeState()` result can end uncertainty. Ordinary reads
 *   never do.
 * - Reads, mutations, and reconciliation run one at a time in call order.
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
  #mutationInProgress = false;
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
   */
  static async open(
    provider: AnalysisProvider,
    sessionId: string,
    logger?: Logger,
  ): Promise<Result<AnalysisSession, ErrorEnvelope>> {
    const capabilities = new Map<string, ProviderCapability>();
    for (const capability of provider.capabilities()) {
      if (capabilityIssues(capability).length > 0 || capabilities.has(capability.operation))
        return err(
          makeError("internal_error", "The provider declared an invalid capability", {
            operation: capability.operation,
          }),
        );
      capabilities.set(capability.operation, capability);
    }
    const session = new AnalysisSession(provider, sessionId, capabilities, logger);
    session.#uncertainty = { operation: "open", reason: "The initial state has not been observed yet." };
    const observed = await session.reconcile();
    return observed.ok ? ok(session) : observed;
  }

  state(): SessionState {
    return {
      consistency: this.#uncertainty === null ? "consistent" : "uncertain",
      mutation_in_progress: this.#mutationInProgress,
      revision: this.#revision,
      state_token: this.#uncertainty === null ? this.#stateToken : null,
      uncertainty: this.#uncertainty,
    };
  }

  /** Read through the cache while consistent; always go to the provider otherwise. */
  read(operation: string, parameters: unknown): Promise<Result<ReadResult, ErrorEnvelope>> {
    return this.#exclusive(() => this.#read(operation, parameters));
  }

  /** Apply a mutation and record exactly what is known about its effect. */
  mutate(operation: string, parameters: unknown): Promise<Result<MutationResult, ErrorEnvelope>> {
    return this.#exclusive(() => this.#mutate(operation, parameters));
  }

  /** Observe the provider's state token afresh; the only way to end uncertainty. */
  reconcile(): Promise<Result<ReconcileResult, ErrorEnvelope>> {
    return this.#exclusive(() => this.#reconcile());
  }

  /**
   * Export cached knowledge for the current verified state, or refuse while
   * the state is uncertain, including while a mutation is in progress.
   */
  snapshot(): Result<SessionSnapshot, ErrorEnvelope> {
    if (this.#uncertainty !== null || this.#stateToken === null)
      return err(
        makeError("state_uncertain", "A snapshot cannot be exported while the session state is uncertain", {
          state_revision: this.#revision,
          mutation_in_progress: this.#mutationInProgress,
          uncertainty: this.#uncertainty === null ? null : { ...this.#uncertainty },
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

  #exclusive<T>(task: () => Promise<T>): Promise<T> {
    const run = this.#tail.then(task, task);
    this.#tail = run.catch(() => undefined);
    return run;
  }

  #operationNames(): string[] {
    return [...this.#capabilities.keys()].toSorted();
  }

  #subject(stateToken: string): Subject {
    return {
      kind: "analysis-state",
      artifact_sha256: this.#provider.artifactSha256,
      session_id: this.#sessionId,
      state_revision: this.#revision,
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
    this.#mutationInProgress = true;
    let outcome;
    try {
      outcome = await this.#provider.mutate(operation, parameters);
    } catch (cause: unknown) {
      this.#logRaised("provider_mutation_raised", operation, cause);
      return err(
        this.#remainUncertain(operation, "unknown", [], "The provider raised an exception during the mutation; its effect on analysis state is unknown."),
      );
    } finally {
      this.#mutationInProgress = false;
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

    this.#stateToken = outcome.stateToken;
    this.#uncertainty = null;
    const evidence = evidenceFromCapability(capability, {
      subject: this.#subject(outcome.stateToken),
      parameters,
      payload: { items: itemsJson(outcome.items), result: outcome.payload },
      producer: this.#provider.identity,
      unknowns: [],
      limitations: [],
    });
    if (!evidence.ok) return evidence;
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

    // A fresh authoritative token starts a new known epoch.
    this.#revision += 1;
    this.#cache = new Map();
    this.#stateToken = observed.stateToken;
    this.#uncertainty = null;
    const evidence = evidenceFromCapability(OBSERVE_STATE, {
      subject: this.#subject(observed.stateToken),
      parameters: {},
      payload: { state_token: observed.stateToken },
      producer: this.#provider.identity,
      unknowns: [],
      limitations: [],
    });
    if (!evidence.ok) return evidence;
    return ok({ evidence: evidence.value, stateToken: observed.stateToken, revision: this.#revision });
  }
}
