import { describe, expect, it } from "vitest";

import { chooseFunctionName, type GhidraSymbol } from "../../../src/infrastructure/ghidra/naming.js";

const symbol = (name: string, source: GhidraSymbol["source"], primary = false): GhidraSymbol => ({ name, source, primary });

describe("choosing a function's display name", () => {
  it("uses the only imported name as is", () => {
    expect(chooseFunctionName({ name: "_add", source: "imported" }, [symbol("_add", "imported", true)], null)).toEqual({
      name: "_add",
      name_source: "imported",
      name_basis: "ghidra-name",
      name_confidence: "imported",
      ghidra_name: "_add",
      ghidra_name_source: "imported",
      aliases: [],
    });
  });

  it("prefers the symbol-table name over Ghidra's loader `entry` label at the program entry (Mach-O _main)", () => {
    const naming = chooseFunctionName(
      { name: "entry", source: "imported" },
      [symbol("entry", "imported", true), symbol("_main", "imported")],
      { fileSymbols: null },
    );
    expect(naming).toMatchObject({ name: "_main", name_source: "imported", name_basis: "imported-alias", name_confidence: "imported", ghidra_name: "entry" });
    // The loader label is kept and identified, not hidden.
    expect(naming.aliases).toEqual([{ name: "entry", source: "imported", role: "loader-entry-label" }]);
  });

  it("does not discount an `entry` name that is not at the program entry", () => {
    const naming = chooseFunctionName({ name: "entry", source: "imported" }, [symbol("entry", "imported", true), symbol("_main", "imported")], null);
    expect(naming).toMatchObject({ name: "entry", name_basis: "ghidra-name", name_confidence: "ambiguous" });
    expect(naming.aliases).toEqual([{ name: "_main", source: "imported", role: "alias" }]);
  });

  it("does not guess between several imported names", () => {
    const naming = chooseFunctionName(
      { name: "entry", source: "imported" },
      [symbol("entry", "imported", true), symbol("_main", "imported"), symbol("start", "imported")],
      { fileSymbols: null },
    );
    expect(naming).toMatchObject({ name: "entry", name_confidence: "ambiguous" });
    expect(naming.aliases.map(({ name }) => name)).toEqual(["_main", "start"]);
  });

  describe("at the program entry, with the file's own symbols", () => {
    const entryLabel = { name: "entry", source: "imported" } as const;

    it("does not present the loader's `entry` label as imported when the binary has no symbol there (stripped)", () => {
      // Regression (Phase 4.4 benchmark): stripped Mach-O and the stripped generated ELF reported entry as imported.
      expect(chooseFunctionName(entryLabel, [symbol("entry", "imported", true)], { fileSymbols: [] })).toEqual({
        name: "entry",
        name_source: "imported",
        name_basis: "loader-label",
        name_confidence: "loader-generated",
        ghidra_name: "entry",
        ghidra_name_source: "imported",
        aliases: [],
      });
    });

    it("shows the symbol-table name and keeps `entry` as the loader label (unstripped Mach-O)", () => {
      const naming = chooseFunctionName(entryLabel, [symbol("entry", "imported", true), symbol("_main", "imported")], { fileSymbols: ["_main"] });
      expect(naming).toMatchObject({ name: "_main", name_basis: "imported-alias", name_confidence: "imported", ghidra_name: "entry" });
      expect(naming.aliases).toEqual([{ name: "entry", source: "imported", role: "loader-entry-label" }]);
    });

    it("lets the file's symbols settle a choice between several imported names", () => {
      const naming = chooseFunctionName(
        entryLabel,
        [symbol("entry", "imported", true), symbol("_main", "imported"), symbol("start", "imported")],
        { fileSymbols: ["start"] },
      );
      expect(naming).toMatchObject({ name: "start", name_confidence: "imported" });
      expect(naming.aliases).toEqual([
        { name: "entry", source: "imported", role: "loader-entry-label" },
        { name: "_main", source: "imported", role: "alias" },
      ]);
    });

    it("treats `entry` as the binary's own name when its symbol table defines it there", () => {
      expect(chooseFunctionName(entryLabel, [symbol("entry", "imported", true)], { fileSymbols: ["entry"] })).toMatchObject({
        name: "entry",
        name_basis: "ghidra-name",
        name_confidence: "imported",
      });
    });

    it("leaves an imported entry name that is not `entry` alone (the generated ELF's `answer`)", () => {
      expect(chooseFunctionName({ name: "answer", source: "imported" }, [symbol("answer", "imported", true)], { fileSymbols: ["answer"] })).toMatchObject({
        name: "answer",
        name_basis: "ghidra-name",
        name_confidence: "imported",
      });
    });
  });

  it.each(["default", "analysis", "ai", "other"] as const)("never presents a %s name as coming from the binary", (source) => {
    const naming = chooseFunctionName({ name: "FUN_00401000", source }, [symbol("FUN_00401000", source, true)], null);
    expect(naming).toMatchObject({ name: "FUN_00401000", name_source: source, name_confidence: "generated" });
  });

  it("prefers a unique imported label over a generated function name", () => {
    const naming = chooseFunctionName({ name: "FUN_00401000", source: "default" }, [symbol("FUN_00401000", "default", true), symbol("helper", "imported")], null);
    expect(naming).toMatchObject({ name: "helper", name_source: "imported", name_basis: "imported-alias", name_confidence: "imported", ghidra_name: "FUN_00401000" });
    expect(naming.aliases).toEqual([{ name: "FUN_00401000", source: "default", role: "alias" }]);
  });

  it("keeps a name a person assigned in Ghidra", () => {
    expect(chooseFunctionName({ name: "parse_header", source: "user" }, [symbol("parse_header", "user", true), symbol("sub_1", "imported")], null)).toMatchObject({
      name: "parse_header",
      name_confidence: "user-assigned",
    });
  });
});
