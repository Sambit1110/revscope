import { describe, expect, it } from "vitest";

import {
  capabilityIssues,
  evidenceFromCapability,
  type CapabilityDescriptor,
} from "../../src/domain/capability.js";
import type { ResultKind } from "../../src/domain/evidence.js";
import { stateSubject } from "../support/evidence.js";

const capability = (
  overrides: Partial<CapabilityDescriptor> = {},
): CapabilityDescriptor => ({
  operation: "get_name",
  description: "read a name",
  effect: "read",
  resultKind: "state-observation",
  limitations: [],
  ...overrides,
});

const input = (subject = stateSubject()) => ({
  subject,
  parameters: {},
  payload: "int main(void);",
  producer: { id: "stub", version: "1" },
  unknowns: [],
  limitations: [],
});

describe("capability declarations", () => {
  it("accepts a consistent read capability", () => {
    expect(capabilityIssues(capability())).toEqual([]);
  });

  it("rejects result kinds outside the closed set, even from untyped code", () => {
    const declared = capability({ resultKind: "observed-fact" as ResultKind });
    expect(capabilityIssues(declared)).toEqual(["unsupported result kind observed-fact"]);
    expect(evidenceFromCapability(declared, input()).ok).toBe(false);
  });

  it("requires mutating capabilities to produce acknowledgements, and only them", () => {
    expect(capabilityIssues(capability({ effect: "mutate" }))).toEqual([
      "a mutating capability must produce mutation-acknowledgement results",
    ]);
    expect(capabilityIssues(capability({ resultKind: "mutation-acknowledgement" }))).toEqual([
      "only mutating capabilities may produce mutation-acknowledgement results",
    ]);
    expect(capabilityIssues(capability({ effect: "mutate", resultKind: "mutation-acknowledgement" }))).toEqual([]);
  });

  it("requires heuristic capabilities to declare their basis", () => {
    expect(capabilityIssues(capability({ resultKind: "unverified-assertion" }))).toEqual([
      "unverified-assertion capabilities must declare the basis of their results",
    ]);
  });
});

describe("evidence from a capability", () => {
  it("derives labels from the declared kind and appends declared limitations", () => {
    const decompile = capability({
      operation: "decompile",
      resultKind: "engine-interpretation",
      limitations: ["engine model, not source"],
    });
    const evidence = evidenceFromCapability(decompile, { ...input(), limitations: ["extra"] });
    expect(evidence.ok).toBe(true);
    if (evidence.ok) {
      expect(evidence.value.result_kind).toBe("engine-interpretation");
      expect(evidence.value.confidence).toBe("derived");
      expect(evidence.value.authority).toBe("analysis-engine");
      expect(evidence.value.limitations).toEqual(["engine model, not source", "extra"]);
    }
  });

  it("refuses a subject kind the result kind does not allow", () => {
    const evidence = evidenceFromCapability(
      capability(),
      input({ kind: "artifact", sha256: "a".repeat(64), size_bytes: 1, display_name: "x" } as never),
    );
    expect(evidence.ok).toBe(false);
    if (!evidence.ok) expect(evidence.error.code).toBe("evidence_integrity");
  });
});
