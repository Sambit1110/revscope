import {
  RESULT_KINDS,
  RESULT_KIND_SEMANTICS,
  createEvidence,
  type Evidence,
  type EvidenceUnknown,
  type ResultKind,
  type Subject,
} from "./evidence.js";
import { makeError, type ErrorEnvelope } from "./errors.js";
import type { JsonObject, JsonValue } from "./json.js";
import { err, type Result } from "./result.js";

/**
 * A named operation, its effect, and the kind of result it produces. A
 * capability cannot choose confidence or authority; those follow from the kind.
 */
export interface CapabilityDescriptor {
  readonly operation: string;
  readonly description: string;
  readonly effect: "read" | "mutate";
  readonly resultKind: ResultKind;
  /** Limitations attached to every evidence record this capability produces. */
  readonly limitations: readonly string[];
}

/** Problems that make a capability declaration unusable. */
export const capabilityIssues = (capability: CapabilityDescriptor): string[] => {
  // Runtime check as well as a type check: declarations may come from untyped code.
  if (!(RESULT_KINDS as readonly string[]).includes(capability.resultKind))
    return [`unsupported result kind ${String(capability.resultKind)}`];
  const semantics = RESULT_KIND_SEMANTICS[capability.resultKind];
  const issues: string[] = [];
  if (capability.effect !== semantics.effect)
    issues.push(
      capability.effect === "mutate"
        ? "a mutating capability must produce mutation-acknowledgement results"
        : "only mutating capabilities may produce mutation-acknowledgement results",
    );
  if (semantics.requiresBasis && capability.limitations.length === 0)
    issues.push(`${capability.resultKind} capabilities must declare the basis of their results`);
  return issues;
};

/** Inputs a capability's evidence varies by; the kind and labels come from the declaration. */
export interface CapabilityEvidenceInput {
  readonly subject: Subject;
  readonly parameters: JsonObject;
  readonly payload: JsonValue;
  readonly producer: { readonly id: string; readonly version: string };
  readonly unknowns: readonly EvidenceUnknown[];
  readonly limitations: readonly string[];
}

/** Create evidence whose kind, and therefore labels, are exactly the capability's. */
export const evidenceFromCapability = (
  capability: CapabilityDescriptor,
  input: CapabilityEvidenceInput,
): Result<Evidence, ErrorEnvelope> => {
  const issues = capabilityIssues(capability);
  if (issues.length > 0)
    return err(
      makeError("internal_error", "A capability declaration is invalid", {
        operation: capability.operation,
      }),
    );
  return createEvidence({
    result_kind: capability.resultKind,
    subject: input.subject,
    operation: { name: capability.operation, parameters: input.parameters },
    producer: input.producer,
    payload: input.payload,
    unknowns: [...input.unknowns],
    limitations: [...capability.limitations, ...input.limitations],
  });
};
