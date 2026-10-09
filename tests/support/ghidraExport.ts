/** Builds `revscope.ghidra-export/1` exports for tests, one record per line. */

export interface ExportOptions {
  readonly ghidraVersion?: string;
  readonly maxFunctions?: number;
  readonly decompile?: boolean;
  readonly analysisTimedOut?: boolean;
  readonly functions?: readonly {
    readonly address: string;
    readonly name: string;
    readonly decompilation?: { readonly status: "ok" | "failed" | "timeout" | "skipped"; readonly pseudocode?: string; readonly truncated?: boolean } | null;
  }[];
  /** null omits the trailer, as when the engine is cut off. */
  readonly trailer?: { readonly functionsTotal?: number; readonly stopped?: "complete" | "function-limit" | "deadline" } | null;
}

export const DEFAULT_FUNCTIONS: NonNullable<ExportOptions["functions"]> = [
  { address: "0x401000", name: "answer", decompilation: { status: "ok", pseudocode: "int answer(void)\n{\n  return 0x2a;\n}\n" } },
  { address: "0x401010", name: "twice", decompilation: { status: "ok", pseudocode: "int twice(int x)\n{\n  return x * 2;\n}\n" } },
];

export const headerRecord = (options: ExportOptions = {}) => ({
  type: "header",
  schema: "revscope.ghidra-export/1",
  script_version: "1",
  ghidra_version: options.ghidraVersion ?? "11.4",
  program: {
    executable_format: "Executable and Linking Format (ELF)",
    language_id: "x86:LE:64:default",
    compiler_spec: "gcc",
    processor: "x86",
    endian: "little",
    address_size: 64,
    image_base: "0x400000",
    min_address: "0x400000",
    max_address: "0x401fff",
    entry_points: ["0x401000"],
  },
  analysis: { timed_out: options.analysisTimedOut ?? false },
  limits: { max_functions: options.maxFunctions ?? 200, decompile: options.decompile ?? true, decompile_timeout_s: 10 },
});

export const functionRecord = (address: string, name: string) => ({
  type: "function",
  address,
  name,
  name_source: "imported",
  body_bytes: 6,
  is_thunk: false,
  calling_convention: "__stdcall",
  signature: `int ${name}(void)`,
});

export const exportRecords = (options: ExportOptions = {}): object[] => {
  const functions = options.functions ?? DEFAULT_FUNCTIONS;
  const records: object[] = [headerRecord(options)];
  for (const entry of functions) {
    records.push(functionRecord(entry.address, entry.name));
    const decompilation = entry.decompilation;
    if ((options.decompile ?? true) && decompilation !== undefined && decompilation !== null)
      records.push({
        type: "decompilation",
        address: entry.address,
        status: decompilation.status,
        pseudocode: decompilation.status === "ok" ? decompilation.pseudocode ?? "" : null,
        truncated: decompilation.truncated ?? false,
      });
  }
  if (options.trailer !== null)
    records.push({
      type: "trailer",
      functions_total: options.trailer?.functionsTotal ?? functions.length,
      functions_exported: functions.length,
      stopped: options.trailer?.stopped ?? "complete",
    });
  return records;
};

export const exportText = (options: ExportOptions = {}): string =>
  exportRecords(options).map((record) => `${JSON.stringify(record)}\n`).join("");

export const exportBytes = (options: ExportOptions = {}): Uint8Array => new TextEncoder().encode(exportText(options));

export const linesToBytes = (lines: readonly string[]): Uint8Array =>
  new TextEncoder().encode(lines.map((line) => `${line}\n`).join(""));
