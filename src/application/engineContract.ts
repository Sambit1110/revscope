import { z } from "zod";

/**
 * The read operations every binary analysis engine's provider serves, and
 * the parts of their payloads the analyze_binary tool relies on.
 */
export const ENGINE_OPERATIONS = {
  programInfo: "program_info",
  listFunctions: "list_functions",
  decompile: "decompile",
} as const;

export const DECOMPILATION_STATES = ["ok", "failed", "timeout", "skipped", "not-exported"] as const;
export type DecompilationState = (typeof DECOMPILATION_STATES)[number];

/** The function list as the tool reads it; engines may add fields. */
export const functionListPayloadSchema = z.looseObject({
  functions: z.array(
    z.looseObject({
      address: z.string().min(1),
      decompilation: z.enum(DECOMPILATION_STATES),
    }),
  ),
});
