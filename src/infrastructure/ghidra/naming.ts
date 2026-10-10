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
  /** Why this name was chosen. */
  readonly name_basis: "ghidra-name" | "imported-alias";
  /**
   * - user-assigned: a person named it in Ghidra;
   * - imported: the only imported name at the address, or the symbol-table
   *   name beside Ghidra's loader entry label;
   * - ambiguous: several imported names, none preferable on the evidence;
   * - generated: Ghidra made the name up; it does not come from the binary.
   */
  readonly name_confidence: "user-assigned" | "imported" | "ambiguous" | "generated";
  /** Ghidra's current (primary) name, unchanged. */
  readonly ghidra_name: string;
  readonly ghidra_name_source: NameSource;
  /** Every other name at the address. */
  readonly aliases: readonly { readonly name: string; readonly source: NameSource; readonly role: "alias" | "loader-entry-label" }[];
}

/**
 * Ghidra's loaders label the program entry point `entry` (seen on Mach-O
 * with Ghidra 12.1.4, beside the symbol-table name `_main`, both IMPORTED).
 * The label is only discounted where the evidence says it is that label: the
 * function is the header-declared program entry and exactly one other
 * imported name sits at the same address.
 */
const LOADER_ENTRY_LABEL = "entry";

export const chooseFunctionName = (
  ghidra: { readonly name: string; readonly source: NameSource },
  symbols: readonly GhidraSymbol[],
  isProgramEntry: boolean,
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
  if (ghidra.source === "imported") {
    if (importedOthers.length === 0) return result(ghidra, "ghidra-name", "imported");
    if (isProgramEntry && ghidra.name === LOADER_ENTRY_LABEL && importedOthers.length === 1 && onlyImportedOther !== undefined)
      return result(onlyImportedOther, "imported-alias", "imported", true);
    return result(ghidra, "ghidra-name", "ambiguous");
  }
  // Ghidra made this name up (default, analysis, ai, other); an imported name, if unique, is better evidence.
  if (importedOthers.length === 1 && onlyImportedOther !== undefined) return result(onlyImportedOther, "imported-alias", "imported");
  return result(ghidra, "ghidra-name", importedOthers.length > 1 ? "ambiguous" : "generated");
};
