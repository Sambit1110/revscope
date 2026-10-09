import type { LogEvent, Logger } from "../application/ports.js";

export const LOG_LEVELS = ["debug", "info", "warn", "error", "silent"] as const;
export type LogLevel = (typeof LOG_LEVELS)[number];

const RANK: Record<LogLevel, number> = { debug: 10, info: 20, warn: 30, error: 40, silent: 100 };

const FIELDS = [
  "event",
  "tool",
  "operation",
  "outcome",
  "error_code",
  "error_class",
  "correlation_id",
  "duration_ms",
] as const satisfies readonly (keyof LogEvent)[];

/** Copy only declared fields, even if a caller passes a wider object at runtime. */
const project = (entry: LogEvent): Partial<LogEvent> =>
  Object.fromEntries(
    FIELDS.filter((field) => entry[field] !== undefined).map((field) => [field, entry[field]]),
  );

/**
 * JSON-lines logger. It accepts only the typed LogEvent fields, so request
 * payloads, file contents, and environment values cannot be logged by accident.
 */
export const createLogger = (
  level: LogLevel,
  write: (line: string) => void,
  now: () => Date = () => new Date(),
): Logger => {
  const emit = (entryLevel: Exclude<LogLevel, "silent">) => (entry: LogEvent) => {
    if (RANK[entryLevel] < RANK[level]) return;
    write(`${JSON.stringify({ time: now().toISOString(), level: entryLevel, ...project(entry) })}\n`);
  };
  return { debug: emit("debug"), info: emit("info"), warn: emit("warn"), error: emit("error") };
};

export const silentLogger: Logger = createLogger("silent", () => undefined);
