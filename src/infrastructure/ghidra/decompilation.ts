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
  | "calling-convention-disagreement";

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
