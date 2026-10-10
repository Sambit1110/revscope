/**
 * Benchmark cases and their predefined ground truth.
 *
 * Expectations come from the C sources in `cases/` (what the source declares)
 * and from the built binary's own symbol table (`nm`, read after the build,
 * independently of Ghidra). Nothing here is derived from Revscope's output.
 */

/** C types the sources use, with their width on every benchmark target. */
export type SourceType = "int" | "unsigned" | "char-pointer-pointer" | "const-char-pointer";

export interface ExpectedFunction {
  /** The source name; the platform's symbol prefix is added per target. */
  readonly name: string;
  readonly params: readonly SourceType[];
  readonly returns: SourceType;
  /**
   * Heuristic only: a token the pseudocode is expected to contain if the
   * operation survived compilation. Never treated as proof of semantics.
   */
  readonly pseudocodeHint?: string;
}

export const SOURCES = {
  "simple.c": [
    { name: "add", params: ["int", "int"], returns: "int", pseudocodeHint: "+" },
    { name: "sub", params: ["int", "int"], returns: "int", pseudocodeHint: "-" },
    { name: "mul_add", params: ["int", "int", "int"], returns: "int", pseudocodeHint: "*" },
    { name: "identity", params: ["int"], returns: "int" },
    { name: "main", params: ["int", "char-pointer-pointer"], returns: "int" },
  ],
  "calls.c": [
    { name: "leaf", params: ["int"], returns: "int", pseudocodeHint: "* 3" },
    { name: "middle", params: ["int"], returns: "int", pseudocodeHint: "leaf" },
    { name: "top", params: ["int"], returns: "int", pseudocodeHint: "middle" },
    { name: "factorial", params: ["int"], returns: "int" },
    { name: "fib", params: ["int"], returns: "int" },
    { name: "is_even", params: ["int"], returns: "int", pseudocodeHint: "is_odd" },
    { name: "is_odd", params: ["int"], returns: "int", pseudocodeHint: "is_even" },
    { name: "main", params: ["int", "char-pointer-pointer"], returns: "int" },
  ],
  "control.c": [
    { name: "sum_to", params: ["int"], returns: "int" },
    { name: "clamp", params: ["int", "int", "int"], returns: "int" },
    { name: "gcd", params: ["unsigned", "unsigned"], returns: "unsigned", pseudocodeHint: "%" },
    { name: "popcount", params: ["unsigned"], returns: "int" },
    { name: "abs_diff", params: ["int", "int"], returns: "int" },
    { name: "main", params: ["int", "char-pointer-pointer"], returns: "int" },
  ],
  // The existing real-engine fixture, tests/fixtures/binaries/macho/program.c.
  "program.c": [
    { name: "add", params: ["int", "int"], returns: "int", pseudocodeHint: "+" },
    { name: "factorial", params: ["int"], returns: "int" },
    { name: "greeting", params: [], returns: "const-char-pointer" },
    { name: "main", params: [], returns: "int", pseudocodeHint: "puts" },
  ],
} as const satisfies Record<string, readonly ExpectedFunction[]>;

export type SourceName = keyof typeof SOURCES;

/**
 * - symbol-table: every recovered function's display name must equal its
 *   symbol-table name, and every symbol at its address must be reported;
 * - not-recoverable: the binary has no names to recover (stripped); names are
 *   measured for honesty only (no generated name may claim to be imported).
 */
export type NameExpectation = "symbol-table" | "not-recoverable";

/**
 * How a case's ground-truth addresses compare with Ghidra's:
 * - absolute: the binary's addresses are final (executables);
 * - relative: a relocatable object; Ghidra chooses the load address, so only
 *   offsets from the first function are compared.
 */
export type AddressMode = "absolute" | "relative";

/** The program entry Revscope should report. */
export type ExpectedEntry =
  | { readonly source: "macho-lc-main"; readonly symbol: string }
  | { readonly source: "elf-header"; readonly address: string }
  | { readonly source: "unavailable" };

interface CaseBase {
  readonly id: string;
  /** The benchmark category, 1-7, from the plan. */
  readonly category: readonly number[];
  readonly description: string;
}

export interface CompiledCase extends CaseBase {
  readonly kind: "compiled";
  readonly source: SourceName;
  /** The source's directory: the benchmark's own cases, or the test fixtures. */
  readonly sourceDir: "benchmarks" | "fixture";
  readonly target: "macho-arm64" | "elf-x86_64-object" | "elf-aarch64-object";
  readonly optimization: "-O0" | "-O1" | "-O2" | "-Os";
  readonly stripped: boolean;
  readonly names: NameExpectation;
  readonly entry: ExpectedEntry;
}

export interface GeneratedElfCase extends CaseBase {
  readonly kind: "generated-elf";
  readonly stripped: boolean;
  readonly names: NameExpectation;
}

/** An input Revscope must refuse or handle without leaving anything behind. */
export interface RejectionCase extends CaseBase {
  readonly kind: "rejection";
  readonly input:
    | "text"
    | "random"
    | "empty"
    | "truncated-elf"
    | "truncated-macho"
    | "directory"
    | "symlink"
    | "missing"
    | "unauthorized";
  /**
   * The error codes that count as correct. Truncated headers have no single
   * right answer; any catalogued, structured refusal (or a clean success) is
   * accepted there and the observed outcome is recorded.
   */
  readonly accept: readonly string[];
  /** Whether the input reaches Ghidra at all (refusals before it are fast). */
  readonly reachesEngine: boolean;
}

export type BenchmarkCase = CompiledCase | GeneratedElfCase | RejectionCase;

/** Functions the generated ELF holds (see tests/fixtures/binaries/make-elf.mjs). */
export const GENERATED_ELF_FUNCTIONS: readonly ExpectedFunction[] = [
  { name: "answer", params: [], returns: "int", pseudocodeHint: "0x2a" },
  { name: "twice", params: ["int"], returns: "int", pseudocodeHint: "* 2" },
];
export const GENERATED_ELF_ENTRY = "0x400080";

const macho = (
  source: SourceName,
  optimization: CompiledCase["optimization"],
  category: readonly number[],
  description: string,
  stripped = false,
): CompiledCase => ({
  kind: "compiled",
  id: `macho-${source.replace(/\.c$/u, "")}${optimization}${stripped ? "-stripped" : ""}`,
  category,
  description,
  source,
  sourceDir: source === "program.c" ? "fixture" : "benchmarks",
  target: "macho-arm64",
  optimization,
  stripped,
  names: stripped ? "not-recoverable" : "symbol-table",
  entry: { source: "macho-lc-main", symbol: "_main" },
});

const elfObject = (
  source: SourceName,
  target: "elf-x86_64-object" | "elf-aarch64-object",
  optimization: CompiledCase["optimization"],
  description: string,
): CompiledCase => ({
  kind: "compiled",
  id: `${target === "elf-x86_64-object" ? "elf-x64-obj" : "elf-a64-obj"}-${source.replace(/\.c$/u, "")}${optimization}`,
  category: [4],
  description,
  source,
  sourceDir: "benchmarks",
  target,
  optimization,
  stripped: false,
  names: "symbol-table",
  // A relocatable object has no program entry (e_entry is 0).
  entry: { source: "unavailable" },
});

const rejection = (
  input: RejectionCase["input"],
  accept: readonly string[],
  reachesEngine: boolean,
  description: string,
): RejectionCase => ({ kind: "rejection", id: `reject-${input}`, category: [7], description, input, accept, reachesEngine });

export const CASES: readonly BenchmarkCase[] = [
  { kind: "generated-elf", id: "elf-generated", category: [1], description: "Existing ELF fixture: two functions, symbol table", stripped: false, names: "symbol-table" },
  macho("program.c", "-O0", [1, 6], "Existing Mach-O fixture (program.c), as the real-engine tests build it"),
  macho("simple.c", "-O0", [1, 4, 6], "Simple functions, unoptimized"),
  macho("simple.c", "-O1", [1, 4, 6], "Simple functions, -O1"),
  macho("simple.c", "-O2", [1, 4, 6], "Simple functions, -O2"),
  macho("simple.c", "-Os", [1, 4, 6], "Simple functions, -Os"),
  macho("calls.c", "-O0", [2, 6], "Nested calls and recursion, unoptimized"),
  macho("calls.c", "-O2", [2, 4, 6], "Nested calls and recursion, -O2"),
  macho("control.c", "-O0", [3, 6], "Loops, conditionals, arithmetic, unoptimized"),
  macho("control.c", "-O2", [3, 4, 6], "Loops, conditionals, arithmetic, -O2"),
  elfObject("control.c", "elf-x86_64-object", "-O0", "x86-64 ELF relocatable object, unoptimized"),
  elfObject("control.c", "elf-x86_64-object", "-O2", "x86-64 ELF relocatable object, -O2"),
  elfObject("control.c", "elf-aarch64-object", "-O2", "AArch64 ELF relocatable object, -O2"),
  macho("control.c", "-O2", [5, 6], "Stripped Mach-O, -O2", true),
  { kind: "generated-elf", id: "elf-generated-stripped", category: [5], description: "Generated ELF executable without .symtab/.strtab", stripped: true, names: "not-recoverable" },
  rejection("text", ["unsupported_target"], true, "Plain text file"),
  rejection("random", ["unsupported_target"], true, "4 KiB of seeded pseudo-random bytes"),
  rejection("empty", ["unsupported_target"], true, "Empty file"),
  rejection("truncated-elf", ["unsupported_target", "provider_failure", "ok"], true, "ELF fixture cut to its first 100 bytes"),
  rejection("truncated-macho", ["unsupported_target", "provider_failure", "ok"], true, "Mach-O cut to its first 512 bytes"),
  rejection("directory", ["unsupported_target"], false, "A directory"),
  rejection("symlink", ["unsupported_target"], false, "A symbolic link to the ELF fixture"),
  rejection("missing", ["target_not_found"], false, "A path that does not exist"),
  rejection("unauthorized", ["invalid_input"], false, "The ELF fixture without --authorized"),
];

/** The symbol prefix each target's C compiler adds. */
export const symbolPrefix = (target: CompiledCase["target"]): string => (target === "macho-arm64" ? "_" : "");
