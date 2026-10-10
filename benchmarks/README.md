# Real-binary benchmark

Measures Revscope's Ghidra provider on small, locally built binaries whose
answers are known in advance. Nothing it builds is ever executed.

```bash
REVSCOPE_GHIDRA_DIR=/abs/ghidra_12.1.4_PUBLIC npm run benchmark -- [--out <dir>] [--repeat <n>] [--only <regex>]
```

- Inputs, raw outputs, `results.json` (schema `revscope.benchmark/1`) and
  `report.md` go to `$TMPDIR/revscope-benchmark/<timestamp>/`, or `--out`.
  The harness refuses an output directory inside the source tree.
- `--repeat` (default 3, minimum 2) runs each analyzed case that many
  times; byte-identical output is required.
- Needs `clang`, `nm` and `strip` (Xcode command-line tools) for the
  compiled cases. A case that cannot be built or run is reported as
  **not run** and the exit status is non-zero; nothing is skipped silently.
- No dependencies beyond the repository's own; the scripts run with
  Node.js's built-in TypeScript type stripping.

## Cases

Defined in [`manifest.ts`](manifest.ts), with sources in [`cases/`](cases):

| Category | Inputs |
|---|---|
| 1 simple functions | `simple.c`; the existing ELF and Mach-O test fixtures |
| 2 nested calls, recursion | `calls.c` |
| 3 loops, conditionals, arithmetic | `control.c` |
| 4 optimization levels | Mach-O `-O0/-O1/-O2/-Os`; ELF x86-64 and AArch64 relocatable objects |
| 5 stripped | Mach-O after `strip`; the generated ELF without `.symtab`/`.strtab` |
| 6 native ARM64 Mach-O | all Mach-O cases |
| 7 unsupported or malformed | text, seeded random bytes, empty, truncated ELF and Mach-O, directory, symlink, missing path, missing authorization |
| reliability | a real timeout (engine API, Ghidra capped at 2 s) and a real SIGINT cancellation |

This toolchain has no ELF linker, so ELF executables come only from the
byte-level generator; compiled ELF inputs are relocatable objects.

## Ground truth and metrics

Expected names, parameter and return types come from the C sources;
addresses come from `nm` on the built binary, never from Ghidra. The
program entry is `_main`'s address on Mach-O, `e_entry` on the generated
ELF, and unavailable for relocatable objects.

Metrics are kept in three tiers:

- **Exact.** Each is a pass or fail against ground truth:
  - outcome or error code;
  - functions recovered at their addresses (relative offsets for relocatable objects);
  - display name equal to the symbol-table name, with every symbol at the address reported;
  - no name claiming a symbol table the binary lacks;
  - program entry;
  - a well-formed address range;
  - a complete export;
  - byte-identical repeat runs;
  - no files, processes or sensitive paths left behind.
- **Approximate.** Decompiler return and parameter types against the source. `exact`, `sign-differs`, `pointer-differs`, `unknown-same-width` and `mismatch` are counted separately; only `exact` counts as agreement. Parameters the source declares but never uses are not observable in a binary, so source-level expectations are an upper bound.
- **Heuristic.** An expected token in the pseudocode, such as `%` in `gcd`. It is a hint, never proof of semantic correctness.

Per-run wall time and the peak RSS of the largest process (from
`/usr/bin/time -l`, macOS) are recorded with every run.

## Comparison with REA (optional)

```bash
REA_DIR=/abs/rea-checkout REVSCOPE_GHIDRA_DIR=/abs/ghidra REVSCOPE_JAVA_HOME=/abs/jdk \
  node benchmarks/compare-rea.ts --from <benchmark output dir> [--only <regex>] [--repeat <n>]
```

Runs REA's CLI (Ghidra provider) and Revscope on the benchmark's exact input
files, with the same Ghidra and JDK, one at a time. REA gets a private
`HOME` and `TMPDIR` and a minimal environment. The script fails if any file
in the REA checkout changed during the run. Engine-level agreement (function
addresses, Ghidra names, decompiler signatures and pseudocode) is reported
apart from orchestration differences (invocations, time, memory, how names
are presented). Writes `comparison.json` (schema `revscope.rea-comparison/1`).
