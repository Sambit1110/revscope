/**
 * Benchmark metrics: Revscope's output scored against predefined ground
 * truth. Pure functions only; the runner gathers the inputs.
 *
 * Three tiers, never mixed:
 * - exact: equality with ground truth (addresses, names, entry, outcome);
 * - approximate: recovered types and parameter counts against the source,
 *   with partial agreement kept apart from exact agreement;
 * - heuristic: tokens in pseudocode; a hint, never proof of semantics.
 */
import { z } from "zod";

import type { AddressMode, ExpectedFunction, NameExpectation } from "../manifest.ts";
import { compareType, parseSignature, type TypeAgreement } from "./signature.ts";

// ---- Revscope's output, as much of it as the metrics read -------------------

const namedSchema = z.looseObject({ name: z.string(), source: z.string() });

const functionSchema = z.looseObject({
  address: z.string(),
  name: z.string(),
  name_source: z.string(),
  name_confidence: z.string(),
  ghidra_name: z.string(),
  aliases: z.array(namedSchema.extend({ role: z.string() })),
  is_thunk: z.boolean(),
  is_program_entry: z.boolean(),
  decompilation: z.string(),
});

const decompileSchema = z.looseObject({
  address: z.string(),
  ghidra_name: z.string(),
  status: z.string(),
  pseudocode: z.string().nullable().optional(),
  decompiler: z.looseObject({
    signature: z.string(),
    calling_convention: z.looseObject({ name: z.string().nullable() }),
  }).nullable().optional(),
  signature_comparison: z.string(),
  fidelity: z.string().nullable(),
  diagnostics: z.array(z.looseObject({ kind: z.string(), severity: z.string() })),
});

const recordSchema = z.looseObject({
  operation: z.looseObject({ name: z.string() }),
  payload: z.unknown(),
});

export const successSchema = z.looseObject({
  ok: z.literal(true),
  records: z.array(recordSchema),
  data: z.looseObject({
    analysis: z.looseObject({
      complete: z.boolean(),
      export_complete: z.boolean(),
      functions_total: z.number(),
      functions_exported: z.number(),
      decompiled: z.number(),
      decompiled_with_uncertainty: z.number(),
    }),
    cleanup: z.looseObject({ process: z.string(), workspace: z.string() }),
  }),
});

const programInfoSchema = z.looseObject({
  min_address: z.string(),
  max_address: z.string(),
  program_entry: z.looseObject({ source: z.string(), addresses: z.array(z.string()) }),
  external_entry_points: z.array(z.string()),
  ghidra_version: z.string(),
  decompiler: z.string(),
});

const listSchema = z.looseObject({ functions: z.array(functionSchema) });

export type ObservedFunction = z.infer<typeof functionSchema>;
export type ObservedDecompilation = z.infer<typeof decompileSchema>;

export interface Observed {
  readonly programInfo: z.infer<typeof programInfoSchema>;
  readonly functions: readonly ObservedFunction[];
  readonly decompilations: readonly ObservedDecompilation[];
  readonly analysis: z.infer<typeof successSchema>["data"]["analysis"];
  readonly cleanup: z.infer<typeof successSchema>["data"]["cleanup"];
}

/** Read a successful CLI document; a shape mismatch is a harness-visible failure, not a skip. */
export const readSuccess = (document: unknown): { ok: true; observed: Observed } | { ok: false; problem: string } => {
  const parsed = successSchema.safeParse(document);
  if (!parsed.success) return { ok: false, problem: `unexpected success document: ${parsed.error.issues[0]?.message ?? "?"}` };
  const payloads = (name: string) => parsed.data.records.filter(({ operation }) => operation.name === name).map(({ payload }) => payload);
  const info = programInfoSchema.safeParse(payloads("program_info")[0]);
  const list = listSchema.safeParse(payloads("list_functions")[0]);
  const decompilations = z.array(decompileSchema).safeParse(payloads("decompile"));
  if (!info.success) return { ok: false, problem: "program_info record missing or malformed" };
  if (!list.success) return { ok: false, problem: "list_functions record missing or malformed" };
  if (!decompilations.success) return { ok: false, problem: "decompile record malformed" };
  return {
    ok: true,
    observed: {
      programInfo: info.data,
      functions: list.data.functions,
      decompilations: decompilations.data,
      analysis: parsed.data.data.analysis,
      cleanup: parsed.data.data.cleanup,
    },
  };
};

// ---- Ground truth -----------------------------------------------------------

export interface TruthFunction {
  /** The symbol-table name (with the platform prefix). */
  readonly symbol: string;
  readonly address: bigint;
  readonly expected: ExpectedFunction;
}

export interface GroundTruth {
  readonly addressMode: AddressMode;
  readonly names: NameExpectation;
  /** Whether every function must be recovered, or recovery is only measured (stripped inputs). */
  readonly recovery: "all" | "measured";
  readonly functions: readonly TruthFunction[];
  /** Every defined symbol name at each address, from the analyzed binary's own symbol table. */
  readonly symbolsAt: ReadonlyMap<bigint, readonly string[]>;
  /** Every name in the analyzed binary's symbol table, defined or undefined. */
  readonly symbolNames: ReadonlySet<string>;
  readonly entry: { readonly source: string; readonly addresses: readonly bigint[] };
}

// ---- Metrics ----------------------------------------------------------------

export interface Check {
  readonly pass: boolean;
  readonly detail: string;
}

export interface ExactMetrics {
  readonly export: Check & {
    readonly complete: boolean;
    readonly functions_total: number;
    readonly functions_exported: number;
    readonly decompile_records: number;
    readonly decompile_records_expected: number;
  };
  /** The reported program address range is well formed: both default-space addresses, min <= max. */
  readonly address_range: Check & { readonly min_address: string; readonly max_address: string };
  readonly entry: Check & { readonly expected: { source: string; addresses: string[] }; readonly observed: { source: string; addresses: string[] } };
  readonly recovery: Check & {
    readonly expected: number;
    readonly recovered: number;
    readonly missing: string[];
    /** Functions Ghidra reports that are not in the ground truth (stubs, runtime, generated). */
    readonly other_functions: number;
  };
  readonly names: Check & {
    readonly expectation: NameExpectation;
    readonly checked: number;
    readonly exact: number;
    readonly mismatches: { expected: string; observed: string }[];
    readonly symbols_missing_from_aliases: string[];
    /** Display names that claim to be imported but are not in the analyzed binary's symbol table. */
    readonly imported_claims_not_in_symbol_table: string[];
    readonly generated: number;
  };
}

export interface FunctionSignature {
  readonly function: string;
  readonly signature: string | null;
  readonly returns: TypeAgreement | "unavailable";
  readonly params: "match" | "mismatch" | "unavailable";
  readonly param_count: { expected: number; observed: number | null };
  readonly param_types: (TypeAgreement | "missing")[];
}

export interface ApproximateMetrics {
  readonly return_type: Record<TypeAgreement | "unavailable", number>;
  readonly param_count: { match: number; mismatch: number; unavailable: number };
  readonly param_types: Record<TypeAgreement | "missing", number>;
  readonly per_function: FunctionSignature[];
}

export interface HeuristicMetrics {
  readonly pseudocode_hints: { checked: number; present: number; absent: string[] };
}

export interface DecompilerMetrics {
  readonly decompiled: number;
  readonly fidelity: { complete: number; uncertain: number; none: number };
  readonly warnings: number;
  readonly diagnostics_by_kind: Record<string, number>;
  readonly signature_comparison: Record<string, number>;
  /** Uncertainty on ground-truth functions only, apart from stubs and runtime code. */
  readonly truth_functions_uncertain: string[];
}

export interface CaseMetrics {
  readonly exact: ExactMetrics;
  readonly approximate: ApproximateMetrics;
  readonly heuristic: HeuristicMetrics;
  readonly decompiler: DecompilerMetrics;
}

export const hex = (value: bigint): string => `0x${value.toString(16)}`;
const parseAddress = (text: string): bigint | null => (/^0x[0-9a-f]+$/iu.test(text) ? BigInt(text) : null);

const count = <K extends string>(keys: readonly K[]): Record<K, number> =>
  Object.fromEntries(keys.map((key) => [key, 0])) as Record<K, number>;

const TYPE_AGREEMENTS = ["exact", "sign-differs", "pointer-differs", "unknown-same-width", "mismatch"] as const;

const lowest = (values: Iterable<bigint>) => [...values].reduce((low, value) => (value < low ? value : low));

/** Map each ground-truth function to the observed function at its address, if any. */
export const matchFunctions = (truth: GroundTruth, functions: readonly ObservedFunction[]) => {
  const observedAt = new Map<bigint, ObservedFunction>();
  for (const entry of functions) {
    const address = parseAddress(entry.address);
    if (address !== null) observedAt.set(address, entry);
  }
  let delta = 0n;
  if (truth.addressMode === "relative" && truth.functions.length > 0 && observedAt.size > 0) {
    // A relocatable object is placed by Ghidra; compare offsets from the lowest address on each side.
    delta = lowest(observedAt.keys()) - lowest([...truth.symbolsAt.keys()]);
  }
  return {
    delta,
    pairs: truth.functions.map((fn) => ({ truth: fn, observed: observedAt.get(fn.address + delta) ?? null })),
  };
};

export const computeMetrics = (truth: GroundTruth, observed: Observed): CaseMetrics => {
  const { delta, pairs } = matchFunctions(truth, observed.functions);
  const truthAddresses = new Set(truth.functions.map(({ address }) => address + delta));
  const recovered = pairs.filter(({ observed: found }) => found !== null);
  const decompilationAt = new Map(observed.decompilations.map((entry) => [entry.address, entry]));

  // Export completeness: the counts agree, and every function marked decompiled has its record.
  const exportedDecompilations = observed.functions.filter(({ decompilation }) => decompilation !== "not-exported").length;
  const exportCheck = (() => {
    const { analysis } = observed;
    const problems: string[] = [];
    if (!analysis.complete) problems.push("analysis not complete");
    if (analysis.functions_exported !== analysis.functions_total) problems.push("not every function exported");
    if (analysis.functions_exported !== observed.functions.length) problems.push("function list length differs from count");
    if (observed.decompilations.length !== exportedDecompilations) problems.push("decompile records missing");
    return {
      pass: problems.length === 0,
      detail: problems.join("; ") || "complete",
      complete: analysis.complete,
      functions_total: analysis.functions_total,
      functions_exported: analysis.functions_exported,
      decompile_records: observed.decompilations.length,
      decompile_records_expected: exportedDecompilations,
    };
  })();

  // Program entry: source and addresses, exactly.
  const entryCheck = (() => {
    const expectedAddresses = truth.entry.addresses.map((address) => hex(address + delta));
    const observedEntry = observed.programInfo.program_entry;
    const pass =
      observedEntry.source === truth.entry.source &&
      observedEntry.addresses.length === expectedAddresses.length &&
      observedEntry.addresses.every((address, index) => parseAddress(address) === parseAddress(expectedAddresses[index] ?? ""));
    return {
      pass,
      detail: pass ? "matches" : `expected ${truth.entry.source} [${expectedAddresses.join(", ")}]`,
      expected: { source: truth.entry.source, addresses: expectedAddresses },
      observed: { source: observedEntry.source, addresses: [...observedEntry.addresses] },
    };
  })();

  const rangeCheck = (() => {
    const { min_address: min, max_address: max } = observed.programInfo;
    const low = parseAddress(min);
    const high = parseAddress(max);
    const pass = low !== null && high !== null && low <= high;
    return { pass, detail: pass ? "well formed" : `min ${min} is not at or below max ${max}`, min_address: min, max_address: max };
  })();

  const missing = pairs.filter(({ observed: found }) => found === null).map(({ truth: fn }) => fn.symbol);
  const recoveryCheck = {
    pass: truth.recovery === "measured" || missing.length === 0,
    detail: missing.length === 0 ? "all recovered" : `missing ${missing.join(", ")}${truth.recovery === "measured" ? " (measured only)" : ""}`,
    expected: pairs.length,
    recovered: recovered.length,
    missing,
    other_functions: observed.functions.filter(({ address }) => {
      const parsed = parseAddress(address);
      return parsed === null || !truthAddresses.has(parsed);
    }).length,
  };

  // Names.
  const mismatches: { expected: string; observed: string }[] = [];
  const symbolsMissing: string[] = [];
  let exactNames = 0;
  if (truth.names === "symbol-table")
    for (const { truth: fn, observed: found } of recovered) {
      if (found === null) continue;
      const symbols = truth.symbolsAt.get(fn.address) ?? [fn.symbol];
      if (symbols.includes(found.name)) exactNames += 1;
      else mismatches.push({ expected: symbols.join(" | "), observed: found.name });
      const reported = new Set([found.name, found.ghidra_name, ...found.aliases.map(({ name }) => name)]);
      for (const symbol of symbols) if (!reported.has(symbol)) symbolsMissing.push(symbol);
    }
  const importedClaims = observed.functions
    .filter(({ name_confidence: confidence, name }) => confidence === "imported" && !truth.symbolNames.has(name))
    .map(({ address, name }) => `${name}@${address}`);
  const generated = observed.functions.filter(({ name_confidence: confidence }) => confidence === "generated").length;
  const namesPass =
    truth.names === "symbol-table" ? mismatches.length === 0 && symbolsMissing.length === 0 : importedClaims.length === 0;
  const namesCheck = {
    pass: namesPass,
    detail: namesPass
      ? truth.names === "symbol-table"
        ? "every recovered function shows its symbol-table name"
        : "no name claims to come from a symbol table the binary does not have"
      : [
          ...mismatches.map(({ expected, observed: shown }) => `${shown} for ${expected}`),
          ...symbolsMissing.map((symbol) => `${symbol} not reported`),
          ...(truth.names === "not-recoverable" ? importedClaims.map((claim) => `${claim} claims imported`) : []),
        ].join("; "),
    expectation: truth.names,
    checked: truth.names === "symbol-table" ? recovered.length : 0,
    exact: exactNames,
    mismatches,
    symbols_missing_from_aliases: symbolsMissing,
    imported_claims_not_in_symbol_table: importedClaims,
    generated,
  };

  // Approximate: decompiler signatures against the source.
  const returnType = count([...TYPE_AGREEMENTS, "unavailable"] as const);
  const paramTypes = count([...TYPE_AGREEMENTS, "missing"] as const);
  const paramCount = { match: 0, mismatch: 0, unavailable: 0 };
  const perFunction: FunctionSignature[] = [];
  const hints = { checked: 0, present: 0, absent: [] as string[] };
  const truthUncertain: string[] = [];
  for (const { truth: fn, observed: found } of recovered) {
    if (found === null) continue;
    const decompiled = decompilationAt.get(found.address);
    if (decompiled?.fidelity === "uncertain") truthUncertain.push(fn.symbol);
    const signature = decompiled?.status === "ok" ? (decompiled.decompiler ?? null) : null;
    const parsed =
      signature === null ? null : parseSignature(signature.signature, decompiled?.ghidra_name ?? found.ghidra_name, signature.calling_convention.name);
    const returns = parsed === null ? "unavailable" : compareType(fn.expected.returns, parsed.returns);
    const params =
      parsed === null ? "unavailable" : parsed.params.length === fn.expected.params.length && !parsed.varargs ? "match" : "mismatch";
    const types = fn.expected.params.map((type, index) => {
      const recoveredType = parsed?.params[index];
      return recoveredType === undefined ? ("missing" as const) : compareType(type, recoveredType);
    });
    returnType[returns] += 1;
    paramCount[params] += 1;
    for (const agreement of types) paramTypes[agreement] += 1;
    perFunction.push({
      function: fn.symbol,
      signature: signature?.signature ?? null,
      returns,
      params,
      param_count: { expected: fn.expected.params.length, observed: parsed?.params.length ?? null },
      param_types: types,
    });
    if (fn.expected.pseudocodeHint !== undefined && decompiled?.status === "ok") {
      hints.checked += 1;
      if ((decompiled.pseudocode ?? "").includes(fn.expected.pseudocodeHint)) hints.present += 1;
      else hints.absent.push(`${fn.symbol}: ${fn.expected.pseudocodeHint}`);
    }
  }

  // Decompiler health across everything Ghidra exported.
  const diagnosticsByKind: Record<string, number> = {};
  const comparisons: Record<string, number> = {};
  let warnings = 0;
  for (const entry of observed.decompilations) {
    comparisons[entry.signature_comparison] = (comparisons[entry.signature_comparison] ?? 0) + 1;
    for (const { kind } of entry.diagnostics) {
      diagnosticsByKind[kind] = (diagnosticsByKind[kind] ?? 0) + 1;
      if (kind === "decompiler-warning") warnings += 1;
    }
  }

  return {
    exact: { export: exportCheck, address_range: rangeCheck, entry: entryCheck, recovery: recoveryCheck, names: namesCheck },
    approximate: { return_type: returnType, param_count: paramCount, param_types: paramTypes, per_function: perFunction },
    heuristic: { pseudocode_hints: hints },
    decompiler: {
      decompiled: observed.decompilations.filter(({ status }) => status === "ok").length,
      fidelity: {
        complete: observed.decompilations.filter(({ fidelity }) => fidelity === "complete").length,
        uncertain: observed.decompilations.filter(({ fidelity }) => fidelity === "uncertain").length,
        none: observed.decompilations.filter(({ fidelity }) => fidelity === null).length,
      },
      warnings,
      diagnostics_by_kind: diagnosticsByKind,
      signature_comparison: comparisons,
      truth_functions_uncertain: truthUncertain,
    },
  };
};

/** Parse `nm` output (`<hex address> <type> <name>`; undefined symbols have no address). */
export const parseNm = (text: string) => {
  const defined: { address: bigint; type: string; name: string }[] = [];
  const names = new Set<string>();
  for (const line of text.split("\n")) {
    const definedMatch = /^(?<address>[0-9a-f]+) (?<type>\S) (?<name>.+)$/iu.exec(line.trim());
    const undefinedMatch = /^(?<type>[Uuvw]) (?<name>.+)$/u.exec(line.trim());
    const groups = definedMatch?.groups;
    if (groups !== undefined) {
      const { address = "0", type = "?", name = "" } = groups;
      defined.push({ address: BigInt(`0x${address}`), type, name });
      names.add(name);
    } else if (undefinedMatch?.groups?.["name"] !== undefined) names.add(undefinedMatch.groups["name"]);
  }
  return { defined, names };
};

/** Defined code symbols grouped by address. */
export const textSymbols = (defined: readonly { address: bigint; type: string; name: string }[]): Map<bigint, string[]> => {
  const at = new Map<bigint, string[]>();
  for (const { address, type, name } of defined)
    if (type === "T" || type === "t") at.set(address, [...(at.get(address) ?? []), name]);
  return at;
};
