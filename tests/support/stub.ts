import type {
  AnalysisProvider,
  ProviderMutationOutcome,
  ProviderStateObservation,
} from "../../src/application/ports.js";
import { AnalysisSession } from "../../src/application/session.js";
import type { JsonObject } from "../../src/domain/json.js";
import {
  StubAnalysisProvider,
  type StubFixture,
} from "../../src/infrastructure/stubProvider.js";

export const stubFixture = (
  faults: Partial<StubFixture["faults"]> = {},
): StubFixture => ({
  schema: "revscope.stub-database/1",
  artifact: {
    display_name: "fixture.bin",
    sha256: "c".repeat(64),
    size_bytes: 4096,
  },
  names: { "0x1000": "main", "0x2000": "helper", "0x3000": "cleanup" },
  functions: {
    "0x1000": { pseudocode: "int main(void) { return helper(); }" },
  },
  faults: {
    rename: { mode: "none" },
    read: { mode: "none" },
    state: { mode: "none" },
    ...faults,
  },
});

/** A session over a fresh stub provider; both are returned so tests can inspect true state. */
export const openStubSession = async (
  faults: Partial<StubFixture["faults"]> = {},
) => {
  const provider = new StubAnalysisProvider(stubFixture(faults));
  const opened = await AnalysisSession.open(provider, "ses_00000000000000aa");
  if (!opened.ok) throw new Error(JSON.stringify(opened.error));
  return { provider, session: opened.value };
};

const noop = (): void => undefined;

/** A deferred promise that a test resolves explicitly. */
export const gate = () => {
  const handle = { release: noop };
  const promise = new Promise<void>((resolve) => {
    handle.release = resolve;
  });
  return { promise, release: () => handle.release() };
};

/**
 * Wraps the stub so tests can inject provider behaviour deterministically:
 * delayed mutation replies, failing or lying state observations, and tokens.
 */
export class ControlledProvider implements AnalysisProvider {
  readonly stub: StubAnalysisProvider;
  readonly identity;
  readonly artifactSha256;
  /** When set, mutate applies its change, then waits for this before replying. */
  mutationGate: Promise<void> | undefined;
  /** When set, mutate applies its change, then throws. */
  raiseAfterMutation = false;
  observe: "real" | "fail" | "raise" | "invalid" = "real";
  /** Replace the token a reply carries, simulating a provider bug or an external change. */
  tokenOverride: string | undefined;
  /** Replace the outcome of the next mutation entirely. */
  nextMutationOutcome: ProviderMutationOutcome | undefined;
  calls: string[] = [];

  constructor(fixture: StubFixture = stubFixture()) {
    this.stub = new StubAnalysisProvider(fixture);
    this.identity = this.stub.identity;
    this.artifactSha256 = this.stub.artifactSha256;
  }

  capabilities() {
    return this.stub.capabilities();
  }

  async read(operation: string, parameters: JsonObject) {
    this.calls.push(`read:${operation}`);
    const outcome = await this.stub.read(operation, parameters);
    return outcome.status === "ok" && this.tokenOverride !== undefined
      ? { ...outcome, stateToken: this.tokenOverride }
      : outcome;
  }

  async mutate(operation: string, parameters: JsonObject): Promise<ProviderMutationOutcome> {
    this.calls.push(`mutate:${operation}`);
    const outcome = this.nextMutationOutcome ?? (await this.stub.mutate(operation, parameters));
    this.nextMutationOutcome = undefined;
    if (this.mutationGate !== undefined) await this.mutationGate;
    if (this.raiseAfterMutation) throw new Error("controlled mutation fault");
    return outcome;
  }

  observeState(): Promise<ProviderStateObservation> {
    this.calls.push("observe_state");
    switch (this.observe) {
      case "fail":
        return Promise.resolve({ status: "failed", reason: "controlled failure" });
      case "raise":
        return Promise.reject(new Error("controlled observe fault"));
      case "invalid":
        return Promise.resolve({ status: "ok", stateToken: "" });
      case "real":
        return Promise.resolve({ status: "ok", stateToken: this.tokenOverride ?? this.stub.stateToken() });
    }
  }
}

export const openControlled = async (fixture?: StubFixture) => {
  const provider = new ControlledProvider(fixture);
  const opened = await AnalysisSession.open(provider, "ses_00000000000000bb");
  if (!opened.ok) throw new Error(JSON.stringify(opened.error));
  return { provider, session: opened.value };
};
