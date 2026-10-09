import { z } from "zod";
import { describe, expect, it } from "vitest";

import type { AnalysisProvider } from "../../src/application/ports.js";
import { AnalysisSession } from "../../src/application/session.js";
import type { ResultKind } from "../../src/domain/evidence.js";
import { errorEnvelopeSchema } from "../../src/domain/errors.js";
import { gate, openControlled, openStubSession } from "../support/stub.js";

const value = <T>(result: { ok: true; value: T } | { ok: false; error: unknown }): T => {
  if (!result.ok) throw new Error(JSON.stringify(result.error));
  return result.value;
};

const failure = (result: { ok: boolean; error?: unknown }) => {
  expect(result.ok).toBe(false);
  return errorEnvelopeSchema.parse(result.error);
};

/** Let queued promise callbacks run without involving timers. */
const settle = async () => {
  for (let index = 0; index < 10; index += 1) await Promise.resolve();
};

const declare = (resultKind: string, effect: "read" | "mutate"): AnalysisProvider => ({
  identity: { id: "bad", version: "1" },
  artifactSha256: "d".repeat(64),
  capabilities: () => [
    {
      operation: "decompile",
      description: "invalid",
      effect,
      resultKind: resultKind as ResultKind,
      limitations: [],
      parameters: z.strictObject({}),
    },
  ],
  read: () => Promise.reject(new Error("unused")),
  mutate: () => Promise.reject(new Error("unused")),
  observeState: () => Promise.resolve({ status: "ok", stateToken: "t" }),
});

describe("opening a session", () => {
  it("starts from a verified state token observed at open", async () => {
    const { session, provider } = await openControlled();
    expect(provider.calls).toEqual(["observe_state"]);
    expect(session.state()).toMatchObject({
      consistency: "consistent",
      mutation_in_progress: false,
      revision: 1,
      state_token: provider.stub.stateToken(),
    });
  });

  it("fails to open when the initial state cannot be observed", async () => {
    const provider = new (await import("../support/stub.js")).ControlledProvider();
    provider.observe = "fail";
    const opened = await AnalysisSession.open(provider, "ses_00000000000000cc");
    expect(failure(opened).code).toBe("provider_failure");
  });

  it("refuses providers that declare unsupported result kinds or mismatched effects", async () => {
    expect((await AnalysisSession.open(declare("observed-fact", "read"), "ses_00000000000000bb")).ok).toBe(false);
    expect((await AnalysisSession.open(declare("state-observation", "mutate"), "ses_00000000000000bb")).ok).toBe(false);
  });
});

describe("mutation in progress (regression for the snapshot race)", () => {
  it("never reports the stale state as consistent while the provider delays its reply", async () => {
    const { session, provider } = await openControlled();
    value(await session.read("get_name", { address: "0x1000" }));
    expect(session.snapshot().ok).toBe(true);
    const hold = gate();
    provider.mutationGate = hold.promise;

    const mutation = session.mutate("rename", { names: { "0x1000": "entry" } });
    await settle();
    // The provider has already changed its state but has not replied.
    expect(provider.stub.currentNames()["0x1000"]).toBe("entry");
    expect(session.state()).toMatchObject({
      consistency: "uncertain",
      mutation_in_progress: true,
      state_token: null,
    });
    const refused = failure(session.snapshot());
    expect(refused.code).toBe("state_uncertain");
    expect(refused.details).toMatchObject({ mutation_in_progress: true });

    // A read issued meanwhile waits for the mutation instead of using the old cache.
    let readSettled = false;
    const read = session.read("get_name", { address: "0x1000" }).then((result) => {
      readSettled = true;
      return result;
    });
    await settle();
    expect(readSettled).toBe(false);

    hold.release();
    value(await mutation);
    const fresh = value(await read);
    expect(fresh.cache).toBe("miss");
    expect(fresh.evidence.payload).toEqual({ address: "0x1000", name: "entry" });
    expect(session.state()).toMatchObject({ consistency: "consistent", mutation_in_progress: false });
    const snapshot = value(session.snapshot());
    expect(snapshot.state_token).toBe(provider.stub.stateToken());
    expect(snapshot.records.map(({ payload }) => payload)).toEqual([{ address: "0x1000", name: "entry" }]);
  });

  it("stays uncertain when a delayed mutation finally fails", async () => {
    const { session, provider } = await openControlled();
    const hold = gate();
    provider.mutationGate = hold.promise;
    provider.raiseAfterMutation = true;
    const mutation = session.mutate("rename", { names: { "0x1000": "entry" } });
    await settle();
    expect(failure(session.snapshot()).code).toBe("state_uncertain");
    hold.release();
    expect(failure(await mutation).details).toMatchObject({ possibly_mutated: true, state_effect: "unknown" });
    expect(session.state()).toMatchObject({ consistency: "uncertain", mutation_in_progress: false });
    expect(failure(session.snapshot()).code).toBe("state_uncertain");
  });

  it("runs concurrent operations one at a time in call order", async () => {
    const { session, provider } = await openControlled();
    const hold = gate();
    provider.mutationGate = hold.promise;
    const operations = [
      session.read("get_name", { address: "0x2000" }),
      session.mutate("rename", { names: { "0x2000": "util" } }),
      session.read("get_name", { address: "0x2000" }),
    ];
    await settle();
    hold.release();
    const [before, , after] = await Promise.all(operations);
    expect(value(before as never)).toMatchObject({ evidence: { payload: { name: "helper" } } });
    expect(value(after as never)).toMatchObject({ evidence: { payload: { name: "util" } } });
    expect(provider.calls).toEqual(["observe_state", "read:get_name", "mutate:rename", "read:get_name"]);
  });
});

describe("mutation outcomes", () => {
  it("acknowledges a successful change and binds new knowledge to the new token", async () => {
    const { session, provider } = await openStubSession();
    const beforeToken = session.state().state_token;
    value(await session.read("get_name", { address: "0x1000" }));
    const renamed = value(await session.mutate("rename", { names: { "0x1000": "entry" } }));
    expect(renamed.evidence.result_kind).toBe("mutation-acknowledgement");
    expect(renamed.evidence.authority).toBe("analysis-state");
    expect(renamed.evidence.limitations.join(" ")).toContain("the original artifact is neither modified nor described");
    expect(session.state().state_token).toBe(provider.stateToken());
    expect(session.state().state_token).not.toBe(beforeToken);
    const after = value(await session.read("get_name", { address: "0x1000" }));
    expect(after.cache).toBe("miss");
    expect(after.evidence.subject).toMatchObject({ state_token: provider.stateToken() });
  });

  it("keeps cached knowledge when a rejection is verified by an unchanged token", async () => {
    const { session, provider } = await openStubSession();
    value(await session.read("get_name", { address: "0x2000" }));
    const revision = session.state().revision;
    const error = failure(await session.mutate("rename", { names: { "0x2000": "a", "0x9000": "b" } }));
    expect(error.code).toBe("mutation_rejected");
    expect(error.details).toMatchObject({ possibly_mutated: false, state_effect: "none" });
    expect(provider.currentNames()["0x2000"]).toBe("helper");
    expect(session.state()).toMatchObject({ consistency: "consistent" });
    expect(session.state().revision).toBeGreaterThan(revision);
    expect(value(await session.read("get_name", { address: "0x2000" })).cache).toBe("hit");
    expect(session.snapshot().ok).toBe(true);
  });

  it("distrusts a rejection whose state token changed", async () => {
    const { session, provider } = await openControlled();
    provider.nextMutationOutcome = { status: "rejected", reason: "claims nothing changed", stateToken: "different" };
    const error = failure(await session.mutate("rename", { names: { "0x1000": "entry" } }));
    expect(error.code).toBe("partial_failure");
    expect(error.details).toMatchObject({ possibly_mutated: true, state_effect: "unknown" });
    expect(session.state().consistency).toBe("uncertain");
  });

  it("distrusts an applied mutation without a valid token", async () => {
    const { session, provider } = await openControlled();
    provider.nextMutationOutcome = { status: "applied", items: [], payload: null, stateToken: "" };
    expect(failure(await session.mutate("rename", { names: { "0x1000": "entry" } })).code).toBe("partial_failure");
    expect(session.state().consistency).toBe("uncertain");
  });

  it("reports item outcomes when only part of a batch applied", async () => {
    const { session, provider } = await openStubSession({ rename: { mode: "fail_items", addresses: ["0x2000"] } });
    const error = failure(await session.mutate("rename", { names: { "0x1000": "entry", "0x2000": "util" } }));
    expect(error.details).toMatchObject({
      possibly_mutated: true,
      state_effect: "changed",
      items: [
        { key: "0x1000", status: "applied" },
        { key: "0x2000", status: "failed" },
      ],
    });
    expect(provider.currentNames()).toMatchObject({ "0x1000": "entry", "0x2000": "helper" });
    expect(session.state().consistency).toBe("uncertain");
  });

  it("treats a provider exception as an unknown effect without leaking its message", async () => {
    const { session, provider } = await openStubSession({ rename: { mode: "raise_after", applied_items: 1 } });
    const error = failure(await session.mutate("rename", { names: { "0x1000": "entry", "0x2000": "util" } }));
    expect(error.details).toMatchObject({ possibly_mutated: true, state_effect: "unknown" });
    expect(provider.currentNames()["0x1000"]).toBe("entry");
    expect(JSON.stringify(error)).not.toContain("stub fault");
  });
});

describe("while uncertain", () => {
  it("never serves earlier cache entries, never caches, and blocks snapshots and mutations", async () => {
    const { session } = await openStubSession({ rename: { mode: "raise_after", applied_items: 1 } });
    expect(value(await session.read("get_name", { address: "0x1000" })).evidence.payload).toEqual({
      address: "0x1000",
      name: "main",
    });
    failure(await session.mutate("rename", { names: { "0x1000": "entry", "0x2000": "util" } }));
    const fresh = value(await session.read("get_name", { address: "0x1000" }));
    expect(fresh).toMatchObject({ cache: "miss", stateVerified: false });
    expect(fresh.evidence.payload).toEqual({ address: "0x1000", name: "entry" });
    expect(fresh.evidence.unknowns.map(({ scope }) => scope)).toContain("session-state");
    expect(value(await session.read("get_name", { address: "0x1000" })).cache).toBe("miss");
    expect(failure(session.snapshot()).code).toBe("state_uncertain");
    expect(failure(await session.mutate("rename", { names: { "0x3000": "fini" } })).code).toBe("state_uncertain");
  });

  it("does not let any ordinary read, even a complete listing, restore consistency", async () => {
    const { session } = await openStubSession({ rename: { mode: "fail_items", addresses: ["0x2000"] } });
    failure(await session.mutate("rename", { names: { "0x1000": "entry", "0x2000": "util" } }));
    value(await session.read("list_names", {}));
    expect(session.state().consistency).toBe("uncertain");
    expect(failure(session.snapshot()).code).toBe("state_uncertain");
  });
});

const runIdenticalHistory = async () => {
  const { session } = await openStubSession();
  value(await session.read("list_names", {}));
  value(await session.mutate("rename", { names: { "0x3000": "fini" } }));
  value(await session.read("get_name", { address: "0x3000" }));
  return value(session.snapshot()).snapshot_id;
};

describe("recovery through a fresh state token", () => {
  it("re-establishes consistency, with a new revision and a token-bound snapshot", async () => {
    const { session, provider } = await openStubSession({ rename: { mode: "raise_after", applied_items: 1 } });
    failure(await session.mutate("rename", { names: { "0x1000": "entry", "0x2000": "util" } }));
    const uncertainRevision = session.state().revision;
    const reconciled = value(await session.reconcile());
    expect(reconciled.stateToken).toBe(provider.stateToken());
    expect(reconciled.revision).toBeGreaterThan(uncertainRevision);
    expect(reconciled.evidence).toMatchObject({ result_kind: "state-observation", operation: { name: "observe_state" } });
    expect(session.state()).toMatchObject({ consistency: "consistent", state_token: provider.stateToken() });
    const read = value(await session.read("get_name", { address: "0x1000" }));
    expect(read).toMatchObject({ cache: "miss", stateVerified: true });
    const snapshot = value(session.snapshot());
    expect(snapshot.state_token).toBe(provider.stateToken());
    expect(snapshot.records.every((record) => record.subject.kind === "analysis-state" && record.subject.state_token === provider.stateToken())).toBe(true);
  });

  it.each(["fail", "raise", "invalid"] as const)(
    "keeps snapshots and mutations blocked when the refresh %s",
    async (mode) => {
      const { session, provider } = await openControlled();
      provider.raiseAfterMutation = true;
      failure(await session.mutate("rename", { names: { "0x1000": "entry" } }));
      provider.raiseAfterMutation = false;
      provider.observe = mode;
      expect(failure(await session.reconcile()).code).toBe("provider_failure");
      expect(session.state().consistency).toBe("uncertain");
      expect(failure(session.snapshot()).code).toBe("state_uncertain");
      expect(failure(await session.mutate("rename", { names: { "0x3000": "fini" } })).code).toBe("state_uncertain");
      provider.observe = "real";
      expect((await session.reconcile()).ok).toBe(true);
      expect(session.snapshot().ok).toBe(true);
    },
  );

  it("detects a stale token: state changed outside the session", async () => {
    const { session, provider } = await openControlled();
    value(await session.read("get_name", { address: "0x1000" }));
    // Someone else changes the provider's state directly.
    await provider.stub.mutate("rename", { names: { "0x2000": "external" } });
    const read = value(await session.read("get_name", { address: "0x2000" }));
    expect(read.stateVerified).toBe(false);
    expect(session.state().consistency).toBe("uncertain");
    expect(session.state().uncertainty?.reason).toContain("changed outside the session");
    expect(failure(session.snapshot()).code).toBe("state_uncertain");
    value(await session.reconcile());
    expect(session.snapshot().ok).toBe(true);
  });

  it("rejects a read whose state token is invalid without changing state", async () => {
    const { session, provider } = await openControlled();
    provider.tokenOverride = "";
    const error = failure(await session.read("get_name", { address: "0x1000" }));
    expect(error.code).toBe("provider_failure");
    expect(session.state().consistency).toBe("consistent");
  });

  it("produces deterministic snapshot identifiers for identical histories", async () => {
    expect(await runIdenticalHistory()).toBe(await runIdenticalHistory());
  });
});

describe("read semantics and validation", () => {
  it("labels decompiler output as derived engine interpretation", async () => {
    const { session } = await openStubSession();
    const evidence = value(await session.read("decompile", { address: "0x1000" })).evidence;
    expect(evidence).toMatchObject({ result_kind: "engine-interpretation", confidence: "derived", authority: "analysis-engine" });
    expect(evidence.limitations.join(" ")).toContain("not decompilation of a real binary");
  });

  it("reports read failures without changing session state", async () => {
    const failed = await openStubSession({ read: { mode: "fail", operation: "get_name" } });
    expect(failure(await failed.session.read("get_name", { address: "0x1000" })).code).toBe("provider_failure");
    const raised = await openStubSession({ read: { mode: "raise", operation: "get_name" } });
    const error = failure(await raised.session.read("get_name", { address: "0x1000" }));
    expect(error.retryable).toBe(true);
    expect(JSON.stringify(error)).not.toContain("stub read fault");
    expect(raised.session.state().consistency).toBe("consistent");
  });

  it("rejects unsupported operations, wrong effects, and invalid parameters", async () => {
    const { session } = await openStubSession();
    const unsupported = failure(await session.read("trace_calls", {}));
    expect(unsupported.code).toBe("unsupported_operation");
    expect(unsupported.details["available_operations"]).toEqual(["decompile", "get_name", "list_names", "rename"]);
    expect(failure(await session.read("rename", { names: {} })).code).toBe("invalid_input");
    expect(failure(await session.mutate("get_name", { address: "0x1000" })).code).toBe("invalid_input");
    expect(failure(await session.read("get_name", { address: "main" })).details["issues"]).toEqual([
      { path: "params.address", message: expect.any(String) },
    ]);
  });
});
