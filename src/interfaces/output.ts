import type { ToolOutput } from "../application/tools/types.js";
import type { ErrorCategory } from "../domain/errors.js";

/** Documented CLI exit status for each error category. */
export const EXIT_CODES: Readonly<Record<ErrorCategory, number>> = {
  internal: 1,
  invalid_input: 2,
  not_found: 3,
  unsupported: 4,
  host_permission: 5,
  resource_limit: 6,
  integrity: 7,
  conflict: 8,
  partial_failure: 9,
  execution_failure: 10,
  cancelled: 130,
};

export const exitCodeFor = (output: ToolOutput): number =>
  output.ok ? 0 : EXIT_CODES[output.error.category];

export const renderJson = (value: unknown): string => `${JSON.stringify(value, null, 2)}\n`;
