import type { z } from "zod";

import type { CapabilityDescriptor } from "../domain/capability.js";
import type { ErrorEnvelope } from "../domain/errors.js";
import type { EvidenceUnknown } from "../domain/evidence.js";
import type { JsonObject, JsonValue } from "../domain/json.js";
import type { Result } from "../domain/result.js";

/** Facts read from a local artifact without executing or interpreting it. */
export interface ArtifactFacts {
  /** Local file name, for display only; never part of evidence identity. */
  readonly displayName: string;
  readonly sizeBytes: number;
  readonly sha256: string;
  /** Up to the first 64 bytes, for signature classification. */
  readonly header: Uint8Array;
}

export interface ArtifactReader {
  read(path: string): Promise<Result<ArtifactFacts, ErrorEnvelope>>;
}

export interface JsonFileReader {
  read(path: string): Promise<Result<unknown, ErrorEnvelope>>;
}

export interface ProviderIdentity {
  readonly id: string;
  readonly version: string;
}

/** A capability plus the schema its parameters must satisfy. */
export interface ProviderCapability extends CapabilityDescriptor {
  readonly parameters: z.ZodType<JsonObject>;
}

/**
 * Every successful provider response names the exact state it describes with
 * an opaque state token. Providers must return a different token whenever
 * their analysis state differs, and the same token for the same state.
 */
export type ProviderReadOutcome =
  | {
      readonly status: "ok";
      readonly payload: JsonValue;
      readonly unknowns: readonly EvidenceUnknown[];
      readonly limitations: readonly string[];
      readonly stateToken: string;
    }
  | { readonly status: "failed"; readonly reason: string };

export interface ItemOutcome {
  readonly key: string;
  readonly status: "applied" | "failed" | "not_attempted";
}

/**
 * What a provider can truthfully say about a mutation. `rejected` claims that
 * nothing changed; its state token lets the session check that claim.
 * `partial` admits that state changed or may have changed.
 */
export type ProviderMutationOutcome =
  | {
      readonly status: "applied";
      readonly items: readonly ItemOutcome[];
      readonly payload: JsonValue;
      readonly stateToken: string;
    }
  | {
      readonly status: "rejected";
      readonly reason: string;
      readonly stateToken: string;
    }
  | {
      readonly status: "partial";
      readonly stateEffect: "changed" | "unknown";
      readonly items: readonly ItemOutcome[];
      readonly reason: string;
    };

/** A fresh, authoritative observation of the provider's current state token. */
export type ProviderStateObservation =
  | { readonly status: "ok"; readonly stateToken: string }
  | { readonly status: "failed"; readonly reason: string };

/**
 * A deep-analysis provider. Implementations may throw; the session treats an
 * exception during a mutation as an unknown effect on state. Providers must
 * not call back into the session that owns them; such calls are refused with
 * `session_reentry`.
 */
export interface AnalysisProvider {
  readonly identity: ProviderIdentity;
  /** Digest of the artifact the provider's analysis state describes. */
  readonly artifactSha256: string;
  capabilities(): readonly ProviderCapability[];
  read(operation: string, parameters: JsonObject): Promise<ProviderReadOutcome>;
  mutate(
    operation: string,
    parameters: JsonObject,
  ): Promise<ProviderMutationOutcome>;
  /** Re-observe the current state token without using any cache. */
  observeState(): Promise<ProviderStateObservation>;
}

/** Structured, typed log events; free-form payloads are deliberately impossible. */
export interface LogEvent {
  readonly event: string;
  readonly tool?: string;
  readonly operation?: string;
  readonly outcome?: "ok" | "error";
  readonly error_code?: string;
  readonly error_class?: string;
  readonly correlation_id?: string;
  readonly duration_ms?: number;
}

export interface Logger {
  debug(entry: LogEvent): void;
  info(entry: LogEvent): void;
  warn(entry: LogEvent): void;
  error(entry: LogEvent): void;
}

/** Limits for one engine run, already validated by the tool. */
export interface BinaryAnalysisLimits {
  /** Total time for the whole operation, including setup and cleanup. */
  readonly timeoutMs: number;
  readonly maxFunctions: number;
  readonly decompile: boolean;
  /** Per-function decompilation limit; never extends the total deadline. */
  readonly decompileTimeoutMs: number;
}

export interface BinaryAnalysisRequest {
  /** Absolute path supplied by the caller. */
  readonly path: string;
  readonly limits: BinaryAnalysisLimits;
  readonly signal: AbortSignal;
}

/** What is left of a run's processes and files after it returned. Fixed texts only, never paths. */
export interface EngineCleanup {
  readonly process: "not-started" | "not-needed" | "terminated" | "failed";
  readonly workspace: "not-created" | "removed" | "failed";
  readonly reason: string | null;
}

/** How much of the program the engine's export covers, and why it may cover less. */
export interface BinaryAnalysisCoverage {
  /** False when the export was cut off before its final record. */
  readonly exportComplete: boolean;
  /** Why an incomplete export stopped; null when it is complete. */
  readonly interruption: "timed-out" | "engine-exited" | null;
  /** Why a complete export covers less than the whole program; null when incomplete. */
  readonly stopped: "complete" | "function-limit" | "deadline" | null;
  /** Whether the engine's own auto-analysis hit its time limit; null when unknown. */
  readonly analysisTimedOut: boolean | null;
  /** Functions the engine found in the program; null when the export does not say. */
  readonly functionsTotal: number | null;
  readonly functionsExported: number;
}

export interface BinaryAnalysisRun {
  /** Read-only provider serving the validated export (see engineContract.ts). */
  readonly provider: AnalysisProvider;
  /** Facts about the exact bytes the engine analyzed. */
  readonly artifact: ArtifactFacts;
  readonly coverage: BinaryAnalysisCoverage;
  readonly cleanup: EngineCleanup;
}

/**
 * A native-code analysis engine run once per request. Implementations must
 * never execute the input, must return by `limits.timeoutMs` plus scheduling
 * latency, and must report cleanup failures instead of hiding them. Errors
 * carry `details.cleanup` when anything was started.
 */
export interface BinaryAnalysisEngine {
  analyze(request: BinaryAnalysisRequest): Promise<Result<BinaryAnalysisRun, ErrorEnvelope>>;
}
