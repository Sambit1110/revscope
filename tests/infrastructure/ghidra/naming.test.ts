import { describe, expect, it } from "vitest";

import { chooseFunctionName, type GhidraSymbol } from "../../../src/infrastructure/ghidra/naming.js";

const symbol = (name: string, source: GhidraSymbol["source"], primary = false): GhidraSymbol => ({ name, source, primary });

describe("choosing a function's display name", () => {
  it("uses the only imported name as is", () => {
    expect(chooseFunctionName({ name: "_add", source: "imported" }, [symbol("_add", "imported", true)], false)).toEqual({
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
      true,
    );
    expect(naming).toMatchObject({ name: "_main", name_source: "imported", name_basis: "imported-alias", name_confidence: "imported", ghidra_name: "entry" });
    // The loader label is kept and identified, not hidden.
    expect(naming.aliases).toEqual([{ name: "entry", source: "imported", role: "loader-entry-label" }]);
  });

  it("does not discount an `entry` name that is not at the program entry", () => {
    const naming = chooseFunctionName({ name: "entry", source: "imported" }, [symbol("entry", "imported", true), symbol("_main", "imported")], false);
    expect(naming).toMatchObject({ name: "entry", name_basis: "ghidra-name", name_confidence: "ambiguous" });
    expect(naming.aliases).toEqual([{ name: "_main", source: "imported", role: "alias" }]);
  });

  it("does not guess between several imported names", () => {
    const naming = chooseFunctionName(
      { name: "entry", source: "imported" },
      [symbol("entry", "imported", true), symbol("_main", "imported"), symbol("start", "imported")],
      true,
    );
    expect(naming).toMatchObject({ name: "entry", name_confidence: "ambiguous" });
    expect(naming.aliases.map(({ name }) => name)).toEqual(["_main", "start"]);
  });

  it.each(["default", "analysis", "ai", "other"] as const)("never presents a %s name as coming from the binary", (source) => {
    const naming = chooseFunctionName({ name: "FUN_00401000", source }, [symbol("FUN_00401000", source, true)], false);
    expect(naming).toMatchObject({ name: "FUN_00401000", name_source: source, name_confidence: "generated" });
  });

  it("prefers a unique imported label over a generated function name", () => {
    const naming = chooseFunctionName({ name: "FUN_00401000", source: "default" }, [symbol("FUN_00401000", "default", true), symbol("helper", "imported")], false);
    expect(naming).toMatchObject({ name: "helper", name_source: "imported", name_basis: "imported-alias", name_confidence: "imported", ghidra_name: "FUN_00401000" });
    expect(naming.aliases).toEqual([{ name: "FUN_00401000", source: "default", role: "alias" }]);
  });

  it("keeps a name a person assigned in Ghidra", () => {
    expect(chooseFunctionName({ name: "parse_header", source: "user" }, [symbol("parse_header", "user", true), symbol("sub_1", "imported")], false)).toMatchObject({
      name: "parse_header",
      name_confidence: "user-assigned",
    });
  });
});
