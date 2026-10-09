/** Format labels Revscope can suggest from leading bytes alone. */
export type FormatLabel =
  | "elf"
  | "mach-o"
  | "mach-o-universal-or-java-class"
  | "pe-or-dos-mz"
  | "zip"
  | "gzip"
  | "pdf"
  | "png"
  | "utf8-text"
  | "unknown";

export interface FormatClassification {
  readonly label: FormatLabel;
  /** Hex of the matched signature bytes, or null when nothing matched. */
  readonly matched_signature_hex: string | null;
  readonly basis: string;
}

const SIGNATURES: readonly {
  readonly label: Exclude<FormatLabel, "utf8-text" | "unknown">;
  readonly bytes: readonly number[];
}[] = [
  { label: "elf", bytes: [0x7f, 0x45, 0x4c, 0x46] },
  { label: "mach-o", bytes: [0xfe, 0xed, 0xfa, 0xce] },
  { label: "mach-o", bytes: [0xfe, 0xed, 0xfa, 0xcf] },
  { label: "mach-o", bytes: [0xce, 0xfa, 0xed, 0xfe] },
  { label: "mach-o", bytes: [0xcf, 0xfa, 0xed, 0xfe] },
  // Fat Mach-O and Java class files share this magic number.
  { label: "mach-o-universal-or-java-class", bytes: [0xca, 0xfe, 0xba, 0xbe] },
  { label: "pdf", bytes: [0x25, 0x50, 0x44, 0x46, 0x2d] },
  { label: "png", bytes: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] },
  { label: "zip", bytes: [0x50, 0x4b, 0x03, 0x04] },
  { label: "gzip", bytes: [0x1f, 0x8b] },
  { label: "pe-or-dos-mz", bytes: [0x4d, 0x5a] },
];

const toHex = (bytes: readonly number[]): string =>
  bytes.map((byte) => byte.toString(16).padStart(2, "0")).join("");

const startsWith = (header: Uint8Array, signature: readonly number[]): boolean =>
  header.length >= signature.length &&
  signature.every((byte, index) => header[index] === byte);

const TEXT_CONTROL_BYTES = new Set([0x09, 0x0a, 0x0c, 0x0d]);

/**
 * Whether the sampled bytes are valid UTF-8 text. When the sample is a
 * truncated prefix of a longer file, a multi-byte character cut by the
 * sample boundary is allowed; invalid bytes never are, and a complete file
 * must end on a character boundary.
 */
const looksLikeUtf8Text = (header: Uint8Array, truncated: boolean): boolean => {
  if (header.length === 0) return false;
  if (header.some((byte) => byte < 0x20 && !TEXT_CONTROL_BYTES.has(byte)))
    return false;
  try {
    // In streaming mode an incomplete trailing sequence is held back, not
    // rejected; without it the decoder rejects one at the end of the input.
    new TextDecoder("utf-8", { fatal: true }).decode(header, { stream: truncated });
    return true;
  } catch {
    return false;
  }
};

export interface ClassifyOptions {
  /** True when the header is a prefix of a longer file. Default false: the header is the whole file. */
  readonly truncated?: boolean;
}

/** Suggest a format from leading bytes. This is a judgement, never validation. */
export const classifyHeader = (
  header: Uint8Array,
  options: ClassifyOptions = {},
): FormatClassification => {
  for (const signature of SIGNATURES)
    if (startsWith(header, signature.bytes))
      return {
        label: signature.label,
        matched_signature_hex: toHex(signature.bytes),
        basis: "leading magic bytes",
      };
  if (looksLikeUtf8Text(header, options.truncated ?? false))
    return {
      label: "utf8-text",
      matched_signature_hex: null,
      basis: "sampled leading bytes decode as UTF-8 without control characters",
    };
  return {
    label: "unknown",
    matched_signature_hex: null,
    basis: "no known signature matched the leading bytes",
  };
};
