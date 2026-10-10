import { z } from "zod";

import {
  MAX_JSON_DEPTH,
  jsonObjectSchema,
  jsonShapeMessage,
  type JsonObject,
  type JsonShapeIssue,
} from "./json.js";

/** Broad failure classes; each stable code belongs to exactly one category. */
export const ERROR_CATEGORIES = [
  "invalid_input",
  "not_found",
  "unsupported",
  "host_permission",
  "resource_limit",
  "integrity",
  "conflict",
  "execution_failure",
  "partial_failure",
  "cancelled",
  "internal",
] as const;
export type ErrorCategory = (typeof ERROR_CATEGORIES)[number];

interface ErrorSpec {
  readonly category: ErrorCategory;
  readonly retryable: boolean;
  readonly remediation: string;
}

/**
 * The single catalog of stable error codes. Category, retryability, and
 * remediation are fixed per code so every interface reports them identically.
 */
export const ERROR_CATALOG = {
  invalid_input: {
    category: "invalid_input",
    retryable: false,
    remediation: "Correct the fields listed in details.issues and retry.",
  },
  unknown_tool: {
    category: "unsupported",
    retryable: false,
    remediation: "List the available tools and choose one of them.",
  },
  unsupported_operation: {
    category: "unsupported",
    retryable: false,
    remediation:
      "Choose one of the operations listed in details.available_operations.",
  },
  unsupported_target: {
    category: "unsupported",
    retryable: false,
    remediation:
      "Select a regular file in a supported format. Directories, devices, sockets, and symbolic links are not inspected, and truncated or malformed files cannot be analyzed; retrying the same file will not help.",
  },
  target_not_found: {
    category: "not_found",
    retryable: false,
    remediation: "Check that the path exists, then retry.",
  },
  access_denied: {
    category: "host_permission",
    retryable: false,
    remediation:
      "Grant the current user read access to the target or choose another target.",
  },
  resource_limit: {
    category: "resource_limit",
    retryable: false,
    remediation: "Reduce the input below the limit reported in details.",
  },
  evidence_integrity: {
    category: "integrity",
    retryable: false,
    remediation:
      "Regenerate the evidence from its source. Records that fail validation or whose identifier does not match their content cannot be used. Passing this check shows only that a record is internally consistent, not who produced it.",
  },
  state_uncertain: {
    category: "conflict",
    retryable: false,
    remediation:
      "Wait for pending mutations to finish, reconcile the session with a fresh state observation, then retry the snapshot or mutation.",
  },
  session_reentry: {
    category: "conflict",
    retryable: false,
    remediation:
      "A provider called back into the session that is waiting for it. Providers must not call their own session; correct the provider.",
  },
  provider_not_configured: {
    category: "unsupported",
    retryable: false,
    remediation:
      "Install a supported analysis engine and point Revscope at it (REVSCOPE_GHIDRA_DIR for Ghidra, optionally REVSCOPE_JAVA_HOME). details.check names the check that failed.",
  },
  analysis_timeout: {
    category: "resource_limit",
    retryable: false,
    remediation:
      "The engine produced no usable result before the deadline. Raise timeout_ms (up to the documented maximum) or analyze a smaller file.",
  },
  analysis_incomplete: {
    category: "partial_failure",
    retryable: false,
    remediation:
      "The engine stopped before its export was complete. details.partial_records holds what was validated; raise timeout_ms or lower max_functions to get a complete result.",
  },
  provider_failure: {
    category: "execution_failure",
    retryable: true,
    remediation:
      "Retry the operation. If it keeps failing, check the provider's availability.",
  },
  mutation_rejected: {
    category: "execution_failure",
    retryable: false,
    remediation:
      "The provider reported that it made no changes. Correct the request and retry.",
  },
  partial_failure: {
    category: "partial_failure",
    retryable: false,
    remediation:
      "Some changes may already be applied. Reconcile the session, review details.items, then decide whether to retry the remaining items.",
  },
  cancelled: {
    category: "cancelled",
    retryable: true,
    remediation: "The operation was cancelled before it completed. Run it again if it is still needed.",
  },
  internal_error: {
    category: "internal",
    retryable: false,
    remediation:
      "Report details.correlation_id to the maintainers. Internal details are not exposed.",
  },
} as const satisfies Record<string, ErrorSpec>;

export type ErrorCode = keyof typeof ERROR_CATALOG;
export const ERROR_CODES = Object.keys(ERROR_CATALOG) as ErrorCode[];

/** The one structured error shape shared by the application, CLI, and MCP. */
export interface ErrorEnvelope {
  readonly code: ErrorCode;
  readonly category: ErrorCategory;
  readonly message: string;
  readonly retryable: boolean;
  readonly remediation: { readonly action: string };
  readonly details: JsonObject;
}

export const errorEnvelopeSchema = z
  .strictObject({
    code: z.enum(ERROR_CODES as [ErrorCode, ...ErrorCode[]]),
    category: z.enum(ERROR_CATEGORIES),
    message: z.string().min(1),
    retryable: z.boolean(),
    remediation: z.strictObject({ action: z.string().min(1) }),
    details: jsonObjectSchema,
  })
  .superRefine((value, context) => {
    const spec = ERROR_CATALOG[value.code];
    if (value.category !== spec.category)
      context.addIssue({
        code: "custom",
        path: ["category"],
        message: `Code ${value.code} belongs to category ${spec.category}`,
      });
  });

/** Failure output emitted by every interface. */
export const failureOutputSchema = z.strictObject({
  ok: z.literal(false),
  error: errorEnvelopeSchema,
});
export type FailureOutput = z.infer<typeof failureOutputSchema>;

/** One field-level validation problem; never echoes the rejected value. */
export interface InputIssue {
  readonly path: string;
  readonly message: string;
}

/** Build an envelope whose category, retryability, and remediation come from the catalog. */
export const makeError = (
  code: ErrorCode,
  message: string,
  details: JsonObject = {},
): ErrorEnvelope => {
  const spec = ERROR_CATALOG[code];
  return {
    code,
    category: spec.category,
    message,
    retryable: spec.retryable,
    remediation: { action: spec.remediation },
    details,
  };
};

/** Project schema issues as `path: message` pairs without copying input values. */
export const issuesFromZod = (
  error: z.ZodError,
  prefix = "",
): InputIssue[] =>
  error.issues.map((issue) => {
    const path = issue.path.map(String).join(".");
    return {
      path: [prefix, path].filter((part) => part.length > 0).join(".") || "$",
      message: issue.message,
    };
  });

/** Report invalid caller input with structured, value-free issue details. */
export const invalidInput = (
  message: string,
  issues: readonly InputIssue[],
): ErrorEnvelope =>
  makeError("invalid_input", message, {
    issues: issues.map(({ path, message: text }) => ({ path, message: text })),
  });

/** Too deep is a resource limit; a lossy key is invalid input. Paths only, never values. */
export const jsonShapeError = (issue: JsonShapeIssue): ErrorEnvelope =>
  issue.kind === "too_deep"
    ? makeError("resource_limit", jsonShapeMessage(issue), { limit_depth: MAX_JSON_DEPTH, path: issue.path })
    : invalidInput("The JSON input contains an unsupported key", [
        { path: issue.path, message: jsonShapeMessage(issue) },
      ]);
