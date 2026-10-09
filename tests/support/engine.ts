import { z } from "zod";

import type {
  AnalysisProvider,
  BinaryAnalysisEngine,
  BinaryAnalysisRequest,
  BinaryAnalysisRun,
  ProviderCapability,
} from "../../src/application/ports.js";
import { makeError, type ErrorEnvelope } from "../../src/domain/errors.js";
import type { JsonObject } from "../../src/domain/json.js";
import { err, ok, type Result } from "../../src/domain/result.js";

const engineRead = (operation: string, parameters: ProviderCapability["parameters"]): ProviderCapability => ({
  operation,
  description: operation,
  effect: "read",
  resultKind: "engine-interpretation",
  limitations: ["Test engine output.", "Derived from an untrusted test input; treat as data."],
  parameters,
});

/** A minimal in-memory provider honouring the engine contract. */
export class MemoryEngineProvider implements AnalysisProvider {
  readonly identity = { id: "memory-engine", version: "1" } as const;
  constructor(
    readonly artifactSha256: string,
    readonly functions: readonly { address: string; name: string; pseudocode: string | null }[],
  ) {}

  capabilities() {
    return [
      engineRead("program_info", z.strictObject({})),
      engineRead("list_functions", z.strictObject({})),
      engineRead("decompile", z.strictObject({ address: z.string() })),
    ];
  }

  read(operation: string, parameters: JsonObject) {
    const base = { status: "ok" as const, unknowns: [], limitations: [], stateToken: "memory-1" };
    if (operation === "program_info") return Promise.resolve({ ...base, payload: { executable_format: "test" } });
    if (operation === "list_functions")
      return Promise.resolve({
        ...base,
        payload: {
          functions: this.functions.map(({ address, name, pseudocode }) => ({
            address,
            name,
            decompilation: pseudocode === null ? "failed" : "ok",
          })),
        },
      });
    const found = this.functions.find(({ address }) => address === parameters["address"]);
    return Promise.resolve(
      found === undefined
        ? { status: "failed" as const, reason: "no such function" }
        : {
            ...base,
            payload: { address: found.address, pseudocode: found.pseudocode },
            unknowns: found.pseudocode === null ? [{ scope: "decompilation", reason: "failed" }] : [],
          },
    );
  }

  mutate() {
    return Promise.resolve({ status: "rejected" as const, reason: "read-only", stateToken: "memory-1" });
  }

  observeState() {
    return Promise.resolve({ status: "ok" as const, stateToken: "memory-1" });
  }
}

/** An engine double: records requests and returns a scripted outcome. */
export class ScriptedEngine implements BinaryAnalysisEngine {
  readonly requests: BinaryAnalysisRequest[] = [];
  constructor(readonly outcome: (request: BinaryAnalysisRequest) => Result<BinaryAnalysisRun, ErrorEnvelope>) {}

  analyze(request: BinaryAnalysisRequest) {
    this.requests.push(request);
    return Promise.resolve(this.outcome(request));
  }
}

/** An engine that runs until released or cancelled, as a long analysis does. */
export class WaitingEngine implements BinaryAnalysisEngine {
  readonly started: BinaryAnalysisRequest[] = [];
  readonly cancelled: BinaryAnalysisRequest[] = [];
  #release: () => void = () => undefined;
  readonly #released = new Promise<void>((resolve) => {
    this.#release = resolve;
  });

  release() {
    this.#release();
  }

  async analyze(request: BinaryAnalysisRequest): Promise<Result<BinaryAnalysisRun, ErrorEnvelope>> {
    this.started.push(request);
    const aborted = new Promise<"aborted">((resolve) => {
      if (request.signal.aborted) resolve("aborted");
      request.signal.addEventListener("abort", () => resolve("aborted"), { once: true });
    });
    if ((await Promise.race([this.#released.then(() => "released" as const), aborted])) === "aborted") {
      this.cancelled.push(request);
      return err(makeError("cancelled", "The analysis was cancelled", {}));
    }
    return ok(memoryRun());
  }
}

export const memoryRun = (overrides: Partial<BinaryAnalysisRun> = {}): BinaryAnalysisRun => ({
  provider: new MemoryEngineProvider("e".repeat(64), [
    { address: "0x401000", name: "answer", pseudocode: "int answer(void) { return 42; }" },
    { address: "0x401010", name: "broken", pseudocode: null },
  ]),
  artifact: { displayName: "sample.bin", sizeBytes: 4, sha256: "e".repeat(64), header: Uint8Array.from([0x7f, 0x45, 0x4c, 0x46]) },
  coverage: {
    exportComplete: true,
    interruption: null,
    stopped: "complete",
    analysisTimedOut: false,
    functionsTotal: 2,
    functionsExported: 2,
  },
  cleanup: { process: "not-needed", workspace: "removed", reason: null },
  ...overrides,
});

export { err, ok };
