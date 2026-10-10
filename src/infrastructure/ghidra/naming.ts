/**
 * How Revscope presents a function's name, given what Ghidra recorded.
 *
 * Ghidra keeps one primary name per function and may hold further symbols at
 * the same address. Each carries Ghidra's SourceType:
 * - imported: assigned by Ghidra's loader while importing the file, normally
 *   from the file's symbol tables, though loaders also create names of their
 *   own (Revscope does not re-read the symbol table to verify which);
 * - analysis, default, ai: produced by Ghidra itself (e.g. FUN_00401000),
 *   never read from the binary;
 * - user: set by a person in Ghidra.
 */
export const NAME_SOURCES = ["imported", "analysis", "default", "user", "ai", "other"] as const;
export type NameSource = (typeof NAME_SOURCES)[number];

export interface GhidraSymbol {
  readonly name: string;
  readonly source: NameSource;
  readonly primary: boolean;
}

export interface FunctionNaming {
  /** The name Revscope displays; pseudocode still uses Ghidra's name. */
  readonly name: string;
  /** Ghidra's source for the displayed name. */
  readonly name_source: NameSource;
  /**
   * Why this name was chosen:
   * - ghidra-name: Ghidra's own name for the function;
   * - imported-alias: another imported name at the address, preferred over
   *   Ghidra's name;
   * - loader-label: Ghidra's name, which its loader created for the program
   *   entry; the file's symbol table has no name there.
   */
  readonly name_basis: "ghidra-name" | "imported-alias" | "loader-label";
  /**
   * - user-assigned: a person named it in Ghidra;
   * - imported: the only imported name at the address, or the symbol-table
   *   name beside Ghidra's loader entry label;
   * - ambiguous: several imported names, none preferable on the evidence;
   * - loader-generated: Ghidra's loader made the label (`entry`) while
   *   importing; the binary does not contain it, even though Ghidra records
   *   its source as imported;
   * - generated: Ghidra made the name up during analysis; it does not come
   *   from the binary.
   */
  readonly name_confidence: "user-assigned" | "imported" | "ambiguous" | "loader-generated" | "generated";
  /** Ghidra's current (primary) name, unchanged. */
  readonly ghidra_name: string;
  readonly ghidra_name_source: NameSource;
  /** Every other name at the address. */
  readonly aliases: readonly { readonly name: string; readonly source: NameSource; readonly role: "alias" | "loader-entry-label" }[];
}

/**
 * Ghidra's ELF and Mach-O loaders label the program entry point `entry`,
 * with source IMPORTED, whether or not the binary names it (seen with Ghidra
 * 12.1.4 beside `_main` on Mach-O, and alone on stripped Mach-O and ELF).
 */
const LOADER_ENTRY_LABEL = "entry";

/**
 * What is known about the function's address from the file header:
 * - null: it is not the header-declared program entry;
 * - fileSymbols: the names the file's own symbol tables define at the
 *   program entry ([] for a stripped binary), or null if they were not read.
 */
export type ProgramEntryEvidence = { readonly fileSymbols: readonly string[] | null } | null;

/**
 * Whether Ghidra's `entry` here is its loader's label rather than a name from
 * the binary. With the file's symbols read, that is decided by them; without
 * them, only when exactly one other imported name sits at the entry (the
 * Phase 4.3 rule).
 */
const isLoaderEntryLabel = (
  ghidra: { readonly name: string; readonly source: NameSource },
  entry: ProgramEntryEvidence,
  importedOthers: readonly GhidraSymbol[],
): boolean => {
  if (entry === null || ghidra.name !== LOADER_ENTRY_LABEL || ghidra.source !== "imported") return false;
  return entry.fileSymbols === null ? importedOthers.length === 1 : !entry.fileSymbols.includes(LOADER_ENTRY_LABEL);
};

export const chooseFunctionName = (
  ghidra: { readonly name: string; readonly source: NameSource },
  symbols: readonly GhidraSymbol[],
  entry: ProgramEntryEvidence,
): FunctionNaming => {
  const others = symbols.filter(({ name }) => name !== ghidra.name);
  const importedOthers = others.filter(({ source }) => source === "imported");
  const result = (
    chosen: { readonly name: string; readonly source: NameSource },
    basis: FunctionNaming["name_basis"],
    confidence: FunctionNaming["name_confidence"],
    entryLabel = false,
  ): FunctionNaming => ({
    name: chosen.name,
    name_source: chosen.source,
    name_basis: basis,
    name_confidence: confidence,
    ghidra_name: ghidra.name,
    ghidra_name_source: ghidra.source,
    aliases: [
      ...(chosen.name === ghidra.name
        ? []
        : [{ name: ghidra.name, source: ghidra.source, role: entryLabel ? ("loader-entry-label" as const) : ("alias" as const) }]),
      ...others.filter(({ name }) => name !== chosen.name).map(({ name, source }) => ({ name, source, role: "alias" as const })),
    ],
  });

  if (ghidra.source === "user") return result(ghidra, "ghidra-name", "user-assigned");
  const [onlyImportedOther] = importedOthers;
  if (isLoaderEntryLabel(ghidra, entry, importedOthers)) {
    // Prefer the binary's own name for the entry; the file's symbol table settles a choice between several.
    const fileSymbols = entry?.fileSymbols ?? null;
    const inFile = fileSymbols === null ? importedOthers : importedOthers.filter(({ name }) => fileSymbols.includes(name));
    const [fileName] = inFile;
    if (importedOthers.length === 1 && onlyImportedOther !== undefined) return result(onlyImportedOther, "imported-alias", "imported", true);
    if (inFile.length === 1 && fileName !== undefined) return result(fileName, "imported-alias", "imported", true);
    if (importedOthers.length === 0) return result(ghidra, "loader-label", "loader-generated");
    return result(ghidra, "ghidra-name", "ambiguous");
  }
  if (ghidra.source === "imported") {
    if (importedOthers.length === 0) return result(ghidra, "ghidra-name", "imported");
    return result(ghidra, "ghidra-name", "ambiguous");
  }
  // Ghidra made this name up (default, analysis, ai, other); an imported name, if unique, is better evidence.
  if (importedOthers.length === 1 && onlyImportedOther !== undefined) return result(onlyImportedOther, "imported-alias", "imported");
  return result(ghidra, "ghidra-name", importedOthers.length > 1 ? "ambiguous" : "generated");
};
