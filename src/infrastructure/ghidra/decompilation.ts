import type { NameSource } from "./naming.js";

/**
 * Structured notes on one decompilation. Severity comes from the kind of
 * evidence, never from reading the message:
 * - material: the output or a value in the record is uncertain because of
 *   it; it is also reported as an evidence unknown;
 * - informational: worth knowing, but nothing in the output depends on it.
 */
export interface DecompilationDiagnostic {
  readonly kind: DiagnosticKind;
  readonly severity: "material" | "informational";
  readonly message: string;
}

export type DiagnosticKind =
  | "stored-signature-not-established"
  | "signature-disagreement"
  | "calling-convention-disagreement"
  | "decompiler-warning"
  | "decompiler-message"
  | "decompiler-calling-convention-unknown"
  | "pseudocode-truncated";

/**
 * - complete: decompiled, and nothing the decompiler or Revscope can detect
 *   makes the output uncertain (absence of warnings is not proof of
 *   faithfulness: the pseudocode is still a reconstruction);
 * - uncertain: decompiled, with at least one material diagnostic;
 * - null: not decompiled (failed, timed out, skipped, not exported).
 */
export type Fidelity = "complete" | "uncertain" | null;

/**
 * Diagnostics from the decompiler's structured signals. Every warning is
 * material: Revscope does not rank warning text, so a warning never
 * disappears, and it never turns a decompilation into a failure either.
 */
export const decompilerDiagnostics = (decompilation: {
  readonly status: "ok" | "failed" | "timeout" | "skipped" | "not-exported";
  readonly warnings: readonly string[];
  readonly errorMessage: string | null;
  readonly decompilerCallingConvention: string | null;
  readonly truncated: boolean;
}): DecompilationDiagnostic[] => {
  const completed = decompilation.status === "ok";
  const diagnostics: DecompilationDiagnostic[] = decompilation.warnings.map((message) => ({
    kind: "decompiler-warning",
    severity: "material",
    message,
  }));
  if (decompilation.errorMessage !== null)
    diagnostics.push({
      kind: "decompiler-message",
      // Beside a failure the message only explains it; beside output it qualifies it.
      severity: completed ? "material" : "informational",
      message: decompilation.errorMessage,
    });
  if (completed && decompilation.decompilerCallingConvention === null)
    diagnostics.push({
      kind: "decompiler-calling-convention-unknown",
      severity: "material",
      message: "The decompiler could not establish a calling convention; recovered parameters and return value may be wrong.",
    });
  if (decompilation.truncated)
    diagnostics.push({ kind: "pseudocode-truncated", severity: "material", message: "The pseudocode was truncated." });
  return diagnostics;
};

export const fidelityOf = (status: string, diagnostics: readonly DecompilationDiagnostic[]): Fidelity =>
  status !== "ok" ? null : diagnostics.some(({ severity }) => severity === "material") ? "uncertain" : "complete";

export interface StoredSignature {
  readonly text: string | null;
  readonly source: NameSource;
  readonly callingConvention: string | null;
}

export interface DecompilerSignature {
  readonly text: string;
  readonly callingConvention: string | null;
}

/**
 * - agree: the stored signature was established and matches the decompiler's;
 * - differ: both exist and they disagree;
 * - stored-not-established: the stored signature is Ghidra's default
 *   placeholder (e.g. `undefined f(void)`), so there is nothing to compare;
 * - unavailable: there is no decompiler signature.
 */
export type SignatureComparison = "agree" | "differ" | "stored-not-established" | "unavailable";

const escapeRegExp = (text: string): string => text.replaceAll(/[.*+?^${}()|[\]\\]/gu, "\\$&");

/**
 * Formatting-only normalization: trailing `;`, whitespace, spacing around
 * `*`, `,` and parentheses, and the calling-convention keyword the
 * decompiler prints but stored prototypes omit.
 */
export const normalizeSignature = (text: string, callingConvention: string | null): string => {
  let normalized = text.trim().replace(/;$/u, "");
  if (callingConvention !== null)
    normalized = normalized.replace(new RegExp(`(^|\\s)${escapeRegExp(callingConvention)}(?=\\s)`, "u"), " ");
  return normalized.replaceAll(/\s+/gu, " ").replaceAll(/\s*([*,()])\s*/gu, "$1").trim();
};

/** Compare Ghidra's stored signature with its decompiler's, without replacing either. */
export const compareSignatures = (
  stored: StoredSignature,
  decompiler: DecompilerSignature | null,
): { readonly comparison: SignatureComparison; readonly diagnostics: readonly DecompilationDiagnostic[] } => {
  if (decompiler === null) return { comparison: "unavailable", diagnostics: [] };
  const diagnostics: DecompilationDiagnostic[] = [];
  if (
    stored.callingConvention !== null &&
    decompiler.callingConvention !== null &&
    stored.callingConvention !== decompiler.callingConvention
  )
    diagnostics.push({
      kind: "calling-convention-disagreement",
      severity: "material",
      message: "Ghidra's stored calling convention and the one its decompiler used differ.",
    });
  if (stored.source === "default" || stored.text === null)
    return {
      comparison: "stored-not-established",
      diagnostics: [
        ...diagnostics,
        {
          kind: "stored-signature-not-established",
          severity: "informational",
          message: "Ghidra has not established this function's signature; only the decompiler's inferred signature is available.",
        },
      ],
    };
  const agree =
    normalizeSignature(stored.text, stored.callingConvention) === normalizeSignature(decompiler.text, decompiler.callingConvention);
  if (agree) return { comparison: "agree", diagnostics };
  return {
    comparison: "differ",
    diagnostics: [
      ...diagnostics,
      {
        kind: "signature-disagreement",
        severity: "material",
        message: "Ghidra's stored signature and its decompiler's signature differ; neither replaces the other.",
      },
    ],
  };
};
