import { z } from "zod";

import { jsonShapeIssue } from "../../domain/json.js";
import { err, ok, type Result } from "../../domain/result.js";
import { NAME_SOURCES } from "./naming.js";

/**
 * The line-delimited JSON export written by Revscope's RevscopeExport Ghidra
 * script. Every line is one record: a header first, then function records
 * each optionally followed by its decompilation record, and a trailer last.
 * A missing trailer means the export was cut off.
 *
 * The export is untrusted input: it is produced by a large program that
 * parsed an untrusted binary. Everything is bounded and cross-checked here.
 */
export const GHIDRA_EXPORT_SCHEMA = "revscope.ghidra-export/3";

export const EXPORT_LIMITS = {
  /** Whole export, in bytes. */
  totalBytes: 32 * 1024 * 1024,
  /** One record line, in bytes. */
  lineBytes: 256 * 1024,
  /** Characters of pseudocode per function; the script truncates before this. */
  pseudocodeChars: 65_536,
  nameChars: 1_024,
  signatureChars: 4_096,
  entryPoints: 256,
} as const;

/**
 * - file-declared: addresses are those the file declares (executables loaded
 *   at their own base);
 * - rebased: Ghidra loaded the program at a base other than the file's;
 * - relocatable-object: the file has no load address (ELF ET_REL, Mach-O
 *   MH_OBJECT); Ghidra chose where to place it, so addresses are Ghidra's,
 *   not the file's;
 * - unknown: the header could not be read, or the format is not ELF or Mach-O.
 */
export const ADDRESS_PLACEMENTS = ["file-declared", "rebased", "relocatable-object", "unknown"] as const;

const address = z.string().regex(/^0x[0-9a-f]{1,32}$/, "Must be a lowercase hexadecimal address");
const label = (max: number) => z.string().min(1).max(max);

const headerSchema = z.strictObject({
  type: z.literal("header"),
  schema: z.literal(GHIDRA_EXPORT_SCHEMA),
  script_version: label(32),
  ghidra_version: label(64),
  program: z.strictObject({
    executable_format: label(256),
    language_id: label(256),
    compiler_spec: label(256),
    processor: label(128),
    endian: z.enum(["little", "big"]),
    address_size: z.number().int().min(1).max(128),
    image_base: address,
    /**
     * Where the program's addresses come from (see ADDRESS_PLACEMENTS).
     */
    address_placement: z.enum(ADDRESS_PLACEMENTS),
    /**
     * The lowest and highest address of memory Ghidra loaded from the file
     * into its default address space; null when there is none. Non-loaded
     * sections and Ghidra's synthetic EXTERNAL block are excluded.
     */
    min_address: address.nullable(),
    max_address: address.nullable(),
    /**
     * The entry point the file header declares, read with Ghidra's own format
     * parsers (ELF e_entry, Mach-O LC_MAIN), or why it is unavailable.
     * file_symbols: the names the file's own symbol tables define at that
     * address ([] when none, e.g. a stripped binary); null when the entry is
     * unavailable.
     */
    program_entry: z
      .strictObject({
        source: z.enum(["elf-header", "macho-lc-main", "unavailable"]),
        addresses: z.array(address).max(1),
        file_symbols: z.array(label(EXPORT_LIMITS.nameChars)).max(16).nullable(),
        reason: label(512).nullable(),
      })
      .refine(
        (entry) =>
          entry.source === "unavailable"
            ? entry.addresses.length === 0 && entry.reason !== null && entry.file_symbols === null
            : entry.addresses.length === 1 && entry.reason === null && entry.file_symbols !== null,
        "an available entry has one address, its file symbols and no reason; an unavailable one has a reason only",
      ),
    /** What Ghidra marks as external entry points: the program entry and exported or global symbols alike. */
    external_entry_points: z.array(address).max(EXPORT_LIMITS.entryPoints),
  }).refine(
    ({ min_address: min, max_address: max }) =>
      min === null || max === null ? min === max : BigInt(min) <= BigInt(max),
    "the loaded address range must have both bounds, min at or below max, or neither",
  ),
  analysis: z.strictObject({
    timed_out: z.boolean(),
    /** Whether Ghidra's native decompiler could start; on macOS it must be built locally. */
    decompiler: z.enum(["available", "unavailable", "not-requested"]),
  }),
  limits: z.strictObject({
    max_functions: z.number().int().min(1),
    decompile: z.boolean(),
    decompile_timeout_s: z.number().int().min(1),
  }),
});


const functionSchema = z.strictObject({
  type: z.literal("function"),
  address,
  name: label(EXPORT_LIMITS.nameChars),
  name_source: z.enum(NAME_SOURCES),
  /** Every symbol at the entry address, primary first. */
  symbols: z
    .array(z.strictObject({ name: label(EXPORT_LIMITS.nameChars), source: z.enum(NAME_SOURCES), primary: z.boolean() }))
    .max(16),
  body_bytes: z.number().int().nonnegative(),
  is_thunk: z.boolean(),
  is_external_entry_point: z.boolean(),
  calling_convention: label(256).nullable(),
  signature: label(EXPORT_LIMITS.signatureChars).nullable(),
  /** Ghidra's SourceType for the stored signature; "default" means not established. */
  signature_source: z.enum(NAME_SOURCES),
});

const decompilationSchema = z
  .strictObject({
    type: z.literal("decompilation"),
    address,
    status: z.enum(["ok", "failed", "timeout", "skipped"]),
    pseudocode: z.string().max(EXPORT_LIMITS.pseudocodeChars).nullable(),
    truncated: z.boolean(),
    /** The decompiler's own inferred signature and calling-convention model; null when unknown. */
    decompiler_signature: label(EXPORT_LIMITS.signatureChars).nullable(),
    decompiler_calling_convention: label(256).nullable(),
    /** The decompiler's warning comments, one per warning (structured: see RevscopeExport.java). */
    warnings: z.array(label(1024)).max(32),
    /** DecompileResults.getErrorMessage(), when not empty. */
    error_message: label(1024).nullable(),
  })
  .refine(
    (record) => (record.status === "ok") === (record.pseudocode !== null),
    "pseudocode must be present exactly when status is ok",
  )
  .refine(
    (record) => record.status === "ok" || (record.decompiler_signature === null && record.decompiler_calling_convention === null),
    "only a completed decompilation has a decompiler signature",
  );

const trailerSchema = z.strictObject({
  type: z.literal("trailer"),
  functions_total: z.number().int().nonnegative(),
  functions_exported: z.number().int().nonnegative(),
  stopped: z.enum(["complete", "function-limit", "deadline"]),
});

const recordSchema = z.discriminatedUnion("type", [
  headerSchema,
  functionSchema,
  decompilationSchema,
  trailerSchema,
]);

export type ExportHeader = z.infer<typeof headerSchema>;
export type ExportFunction = z.infer<typeof functionSchema>;
export type ExportDecompilation = z.infer<typeof decompilationSchema>;
export type ExportTrailer = z.infer<typeof trailerSchema>;

export interface GhidraExport {
  readonly header: ExportHeader;
  /** In ascending address order, as the script writes them. */
  readonly functions: readonly ExportFunction[];
  readonly decompilations: ReadonlyMap<string, ExportDecompilation>;
  /** Null when the export was cut off before its trailer. */
  readonly trailer: ExportTrailer | null;
}

/** What the export must agree with: the limits Revscope passed to the script. */
export interface ExportExpectations {
  readonly maxFunctions: number;
  readonly decompile: boolean;
  /** When known, the export must name the same Ghidra version. */
  readonly ghidraVersion?: string;
}

/**
 * Why an export cannot be used. Reasons are fixed texts; no content from the
 * export is echoed.
 */
export type ExportProblem =
  | { readonly kind: "empty" }
  | { readonly kind: "too_large" }
  | { readonly kind: "malformed"; readonly line: number; readonly reason: string };

const malformed = (line: number, reason: string): Result<never, ExportProblem> =>
  err({ kind: "malformed", line, reason });

/** Split into complete lines; a final segment without a newline was cut off mid-write. */
const completeLines = (bytes: Uint8Array): Uint8Array[] => {
  const lines: Uint8Array[] = [];
  let start = 0;
  for (let index = bytes.indexOf(0x0a); index !== -1; index = bytes.indexOf(0x0a, start)) {
    lines.push(bytes.subarray(start, index));
    start = index + 1;
  }
  return lines;
};

const parseLine = (bytes: Uint8Array, line: number): Result<z.infer<typeof recordSchema>, ExportProblem> => {
  if (bytes.length > EXPORT_LIMITS.lineBytes) return malformed(line, "record line too long");
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return malformed(line, "record is not valid UTF-8");
  }
  let value: unknown;
  try {
    value = JSON.parse(text) as unknown;
  } catch {
    return malformed(line, "record is not valid JSON");
  }
  if (jsonShapeIssue(value) !== null) return malformed(line, "record nesting or keys not supported");
  const parsed = recordSchema.safeParse(value);
  return parsed.success ? ok(parsed.data) : malformed(line, "record does not match the export schema");
};

const addressValue = (text: string): bigint => BigInt(text);

/** Parse and cross-check an export. A cut-off export parses with `trailer: null`. */
export const parseGhidraExport = (
  bytes: Uint8Array,
  expectations: ExportExpectations,
): Result<GhidraExport, ExportProblem> => {
  if (bytes.length > EXPORT_LIMITS.totalBytes) return err({ kind: "too_large" });
  const lines = completeLines(bytes);
  if (lines.length === 0) return err({ kind: "empty" });

  const first = parseLine(lines[0] ?? new Uint8Array(), 1);
  if (!first.ok) return first;
  if (first.value.type !== "header") return malformed(1, "the first record must be the header");
  const header = first.value;
  if (header.limits.max_functions !== expectations.maxFunctions || header.limits.decompile !== expectations.decompile)
    return malformed(1, "the export was produced with different limits");
  if (expectations.ghidraVersion !== undefined && header.ghidra_version !== expectations.ghidraVersion)
    return malformed(1, "the export names a different Ghidra version");
  if ((header.analysis.decompiler === "not-requested") === expectations.decompile)
    return malformed(1, "the decompiler state contradicts the request");

  const functions: ExportFunction[] = [];
  const decompilations = new Map<string, ExportDecompilation>();
  const exported = new Set<string>();
  let trailer: ExportTrailer | null = null;
  for (const [index, bytesOfLine] of lines.entries()) {
    if (index === 0) continue;
    const line = index + 1;
    if (trailer !== null) return malformed(line, "records after the trailer");
    const parsed = parseLine(bytesOfLine, line);
    if (!parsed.ok) return parsed;
    const record = parsed.value;
    switch (record.type) {
      case "header":
        return malformed(line, "more than one header");
      case "function": {
        const previous = functions.at(-1);
        if (previous !== undefined && addressValue(record.address) <= addressValue(previous.address))
          return malformed(line, "functions must be unique and in ascending address order");
        if (functions.length >= expectations.maxFunctions) return malformed(line, "more functions than the limit");
        functions.push(record);
        exported.add(record.address);
        break;
      }
      case "decompilation":
        if (!expectations.decompile) return malformed(line, "decompilation was not requested");
        if (!exported.has(record.address)) return malformed(line, "decompilation of a function not exported before it");
        if (decompilations.has(record.address)) return malformed(line, "more than one decompilation of a function");
        decompilations.set(record.address, record);
        break;
      case "trailer":
        if (record.functions_exported !== functions.length) return malformed(line, "trailer count disagrees with the records");
        if (record.functions_total < record.functions_exported) return malformed(line, "trailer total below the exported count");
        if (record.stopped === "function-limit" && functions.length !== expectations.maxFunctions)
          return malformed(line, "function limit reported below the limit");
        trailer = record;
        break;
    }
  }
  return ok({ header, functions, decompilations, trailer });
};
