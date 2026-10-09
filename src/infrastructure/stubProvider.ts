import { z } from "zod";

import type {
  AnalysisProvider,
  ItemOutcome,
  ProviderCapability,
  ProviderMutationOutcome,
  ProviderReadOutcome,
  ProviderStateObservation,
} from "../application/ports.js";
import { sha256Schema } from "../domain/evidence.js";
import { canonicalJson, sha256Hex, type JsonObject } from "../domain/json.js";

export const STUB_FIXTURE_SCHEMA = "revscope.stub-database/1";

const addressSchema = z
  .string()
  .regex(/^0x[0-9a-f]+$/, "Must be a lowercase hexadecimal address such as 0x1000");
const symbolSchema = z
  .string()
  .regex(/^[A-Za-z_][A-Za-z0-9_.$]{0,255}$/, "Must be a symbol name");

/** A deterministic stand-in for an analysis database, including injected faults. */
export const stubFixtureSchema = z.strictObject({
  schema: z.literal(STUB_FIXTURE_SCHEMA),
  artifact: z.strictObject({
    display_name: z.string().min(1).max(255),
    sha256: sha256Schema,
    size_bytes: z.number().int().nonnegative(),
  }),
  names: z.record(addressSchema, symbolSchema),
  functions: z.record(addressSchema, z.strictObject({ pseudocode: z.string() })),
  faults: z.strictObject({
    rename: z.discriminatedUnion("mode", [
      z.strictObject({ mode: z.literal("none") }),
      z.strictObject({ mode: z.literal("reject") }),
      z.strictObject({
        mode: z.literal("fail_items"),
        addresses: z.array(addressSchema).min(1),
      }),
      z.strictObject({
        mode: z.literal("raise_after"),
        applied_items: z.number().int().nonnegative(),
      }),
    ]),
    read: z.discriminatedUnion("mode", [
      z.strictObject({ mode: z.literal("none") }),
      z.strictObject({
        mode: z.enum(["fail", "raise"]),
        operation: z.string().min(1),
      }),
    ]),
    /** Faults for observeState, the authoritative state refresh. */
    state: z.strictObject({ mode: z.enum(["none", "fail", "raise"]) }),
  }),
});
export type StubFixture = z.infer<typeof stubFixtureSchema>;

const STUB_STATE_LIMITATION =
  "Stub analysis state loaded from a fixture; it is not derived from a real binary.";

const stateRead = {
  effect: "read",
  resultKind: "state-observation",
  limitations: [STUB_STATE_LIMITATION],
} as const;

const STUB_CAPABILITIES: readonly ProviderCapability[] = [
  {
    ...stateRead,
    operation: "list_names",
    description: "List every address label in the stub analysis state.",
    parameters: z.strictObject({}),
  },
  {
    ...stateRead,
    operation: "get_name",
    description: "Read the label at one address.",
    parameters: z.strictObject({ address: addressSchema }),
  },
  {
    operation: "decompile",
    description: "Return fixture pseudocode standing in for decompiler output.",
    effect: "read",
    resultKind: "engine-interpretation",
    limitations: [
      "Stub output: fixture text standing in for an analysis engine's model. It is not decompilation of a real binary and not original source code.",
    ],
    parameters: z.strictObject({ address: addressSchema }),
  },
  {
    operation: "rename",
    description: "Assign labels to several addresses in the stub analysis state.",
    effect: "mutate",
    resultKind: "mutation-acknowledgement",
    limitations: [
      "Acknowledges a change to the analysis state only; the original artifact is neither modified nor described.",
      STUB_STATE_LIMITATION,
    ],
    parameters: z.strictObject({
      names: z
        .record(addressSchema, symbolSchema)
        .refine((names) => Object.keys(names).length > 0, "Provide at least one name"),
    }),
  },
];

/** Raised by the stub to simulate a provider crashing part-way through a mutation. */
export class StubFaultError extends Error {
  override readonly name = "StubFaultError";
}

/** In-memory provider whose state and failures are fully determined by its fixture. */
export class StubAnalysisProvider implements AnalysisProvider {
  readonly identity = { id: "stub", version: "1" } as const;
  readonly artifactSha256: string;
  readonly #fixture: StubFixture;
  readonly #names: Map<string, string>;

  constructor(fixture: StubFixture) {
    this.#fixture = fixture;
    this.artifactSha256 = fixture.artifact.sha256;
    this.#names = new Map(Object.entries(fixture.names));
  }

  capabilities(): readonly ProviderCapability[] {
    return STUB_CAPABILITIES;
  }

  /** Current labels, for tests that check what really changed. */
  currentNames(): Record<string, string> {
    return Object.fromEntries([...this.#names].toSorted(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
  }

  /** Content-derived token: equal label tables always produce equal tokens. */
  stateToken(): string {
    return `stub-${sha256Hex(canonicalJson(this.currentNames())).slice(0, 32)}`;
  }

  observeState(): Promise<ProviderStateObservation> {
    const fault = this.#fixture.faults.state.mode;
    if (fault === "raise") return Promise.reject(new StubFaultError("stub state fault"));
    if (fault === "fail")
      return Promise.resolve({ status: "failed", reason: "Injected stub state observation failure" });
    return Promise.resolve({ status: "ok", stateToken: this.stateToken() });
  }

  read(operation: string, parameters: JsonObject): Promise<ProviderReadOutcome> {
    const fault = this.#fixture.faults.read;
    if (fault.mode !== "none" && fault.operation === operation) {
      if (fault.mode === "raise")
        return Promise.reject(new StubFaultError("stub read fault"));
      return Promise.resolve({ status: "failed", reason: "Injected stub read failure" });
    }
    const address = typeof parameters["address"] === "string" ? parameters["address"] : "";
    switch (operation) {
      case "list_names":
        return Promise.resolve({
          status: "ok",
          payload: {
            names: Object.entries(this.currentNames()).map(([key, name]) => ({
              address: key,
              name,
            })),
          },
          unknowns: [],
          limitations: [],
          stateToken: this.stateToken(),
        });
      case "get_name": {
        const name = this.#names.get(address) ?? null;
        return Promise.resolve({
          status: "ok",
          payload: { address, name },
          unknowns:
            name === null
              ? [{ scope: "name", reason: "No label is defined at this address in the stub state." }]
              : [],
          limitations: [],
          stateToken: this.stateToken(),
        });
      }
      case "decompile": {
        const entry = this.#fixture.functions[address];
        return Promise.resolve(
          entry === undefined
            ? { status: "failed", reason: "No function is defined at this address in the stub state." }
            : {
                status: "ok",
                payload: { address, pseudocode: entry.pseudocode },
                unknowns: [],
                limitations: [],
                stateToken: this.stateToken(),
              },
        );
      }
      default:
        return Promise.resolve({ status: "failed", reason: "Unknown stub read operation" });
    }
  }

  mutate(operation: string, parameters: JsonObject): Promise<ProviderMutationOutcome> {
    if (operation !== "rename")
      return Promise.resolve({ status: "rejected", reason: "Unknown stub mutation", stateToken: this.stateToken() });
    const requested = parameters["names"];
    const names = Object.entries(
      typeof requested === "object" && requested !== null && !Array.isArray(requested)
        ? (requested as Record<string, string>)
        : {},
    ).toSorted(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));

    // Validate the whole batch first: a rejected batch changes nothing.
    const unknownAddress = names.find(([address]) => !this.#names.has(address));
    if (unknownAddress !== undefined)
      return Promise.resolve({
        status: "rejected",
        reason: "The batch names an address that has no label slot in the stub state.",
        stateToken: this.stateToken(),
      });
    const fault = this.#fixture.faults.rename;
    if (fault.mode === "reject")
      return Promise.resolve({ status: "rejected", reason: "Injected stub rejection.", stateToken: this.stateToken() });

    const items: ItemOutcome[] = [];
    let applied = 0;
    for (const [address, name] of names) {
      if (fault.mode === "raise_after" && applied === fault.applied_items)
        return Promise.reject(
          new StubFaultError(`stub fault after ${String(applied)} applied items`),
        );
      if (fault.mode === "fail_items" && fault.addresses.includes(address)) {
        items.push({ key: address, status: "failed" });
        continue;
      }
      this.#names.set(address, name);
      applied += 1;
      items.push({ key: address, status: "applied" });
    }
    if (items.some(({ status }) => status === "failed"))
      return Promise.resolve(
        applied === 0
          ? {
              status: "rejected",
              reason: "No item could be applied; the stub state is unchanged.",
              stateToken: this.stateToken(),
            }
          : {
              status: "partial",
              stateEffect: "changed",
              items,
              reason: "Some items were applied before others failed.",
            },
      );
    return Promise.resolve({
      status: "applied",
      items,
      payload: { applied_items: applied },
      stateToken: this.stateToken(),
    });
  }
}
