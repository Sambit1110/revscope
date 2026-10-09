import {
  RESULT_KINDS,
  RESULT_KIND_SEMANTICS,
  createEvidence,
  operationNameSchema,
  type Evidence,
  type EvidenceUnknown,
  type ResultKind,
  type Subject,
  type SubjectKind,
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

/** Where a capability's results will be recorded, when the caller knows it. */
export interface CapabilityContext {
  /** The subject kind every result of this capability will describe. */
  readonly subjectKind?: SubjectKind;
  /** Operation names the caller reserves for itself. */
  readonly reservedOperations?: readonly string[];
}

/**
 * Problems that make a capability declaration unusable. Checked at runtime as
 * well as by the type system, because declarations may come from untyped code.
 */
export const capabilityIssues = (
  capability: CapabilityDescriptor,
  context: CapabilityContext = {},
): string[] => {
  if (!(RESULT_KINDS as readonly string[]).includes(capability.resultKind))
    return [`unsupported result kind ${String(capability.resultKind)}`];
  const semantics = RESULT_KIND_SEMANTICS[capability.resultKind];
  const issues: string[] = [];
  if (!operationNameSchema.safeParse(capability.operation).success)
    issues.push("the operation name must be lowercase snake_case");
  else if (context.reservedOperations?.includes(capability.operation) === true)
    issues.push(`the operation name ${capability.operation} is reserved`);
  if (capability.effect !== "read" && capability.effect !== "mutate")
    issues.push(`unsupported effect ${String(capability.effect)}`);
  else if (capability.effect !== semantics.effect)
    issues.push(
      capability.effect === "mutate"
        ? "a mutating capability must produce mutation-acknowledgement results"
        : "only mutating capabilities may produce mutation-acknowledgement results",
    );
  if (
    !Array.isArray(capability.limitations) ||
    !capability.limitations.every((entry) => typeof entry === "string" && entry.length > 0)
  )
    issues.push("limitations must be non-empty strings");
  else if (semantics.requiresBasis && capability.limitations.length === 0)
    issues.push(`${capability.resultKind} capabilities must declare the basis of their results`);
  if (context.subjectKind !== undefined && !semantics.subjectKinds.includes(context.subjectKind))
    issues.push(
      `${capability.resultKind} results cannot describe a subject of kind ${context.subjectKind}`,
    );
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
  // Subject compatibility is checked by createEvidence, which reports it as an integrity issue.
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
