import { z } from "zod";
import { describe, expect, it } from "vitest";

import {
  ERROR_CATALOG,
  ERROR_CODES,
  errorEnvelopeSchema,
  failureOutputSchema,
  invalidInput,
  issuesFromZod,
  makeError,
} from "../../src/domain/errors.js";

describe("error catalog", () => {
  it.each(ERROR_CODES)("builds a schema-valid envelope for %s", (code) => {
    const envelope = makeError(code, "message");
    expect(errorEnvelopeSchema.safeParse(envelope).success).toBe(true);
    expect(envelope.category).toBe(ERROR_CATALOG[code].category);
    expect(envelope.remediation.action.length).toBeGreaterThan(10);
  });

  it("rejects an envelope whose category contradicts its code", () => {
    const envelope = { ...makeError("invalid_input", "bad"), category: "internal" };
    expect(errorEnvelopeSchema.safeParse(envelope).success).toBe(false);
  });

  it("rejects missing envelope fields", () => {
    const { remediation: _remediation, ...partial } = makeError("invalid_input", "bad");
    expect(errorEnvelopeSchema.safeParse(partial).success).toBe(false);
    expect(
      failureOutputSchema.safeParse({ ok: false, error: partial }).success,
    ).toBe(false);
  });

  it("only marks transient provider failures and cancellations as retryable", () => {
    const retryable = ERROR_CODES.filter((code) => ERROR_CATALOG[code].retryable);
    expect(retryable).toEqual(["provider_failure", "cancelled"]);
  });
});

describe("input issue projection", () => {
  it("reports paths and messages without echoing rejected values", () => {
    const secret = "s3cr3t-value-should-not-appear";
    const parsed = z
      .strictObject({ path: z.string().startsWith("/") })
      .safeParse({ path: secret });
    expect(parsed.success).toBe(false);
    if (!parsed.success) {
      const envelope = invalidInput("bad", issuesFromZod(parsed.error));
      expect(JSON.stringify(envelope)).not.toContain(secret);
      expect(envelope.details["issues"]).toEqual([
        { path: "path", message: expect.any(String) },
      ]);
    }
  });

  it("uses $ for issues at the root", () => {
    const parsed = z.strictObject({}).safeParse("text");
    if (!parsed.success)
      expect(issuesFromZod(parsed.error)[0]?.path).toBe("$");
  });
});
