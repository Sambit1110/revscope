import { describe, expect, it } from "vitest";

import type { LogEvent } from "../../src/application/ports.js";
import { createLogger } from "../../src/infrastructure/logger.js";

const capture = (level: Parameters<typeof createLogger>[0]) => {
  const lines: string[] = [];
  const logger = createLogger(level, (line) => lines.push(line), () => new Date(0));
  return { logger, lines };
};

describe("structured logger", () => {
  it("writes one JSON object per line with only declared fields", () => {
    const { logger, lines } = capture("debug");
    const smuggled = {
      event: "tool_completed",
      tool: "inspect_artifact",
      payload: "SECRET_PAYLOAD",
      env: { TOKEN: "SECRET_TOKEN" },
    } as unknown as LogEvent;
    logger.info(smuggled);
    expect(lines).toHaveLength(1);
    expect(JSON.parse(lines[0] ?? "")).toEqual({
      time: "1970-01-01T00:00:00.000Z",
      level: "info",
      event: "tool_completed",
      tool: "inspect_artifact",
    });
    expect(lines.join("")).not.toContain("SECRET");
  });

  it("filters by level and stays silent when asked", () => {
    const warn = capture("warn");
    warn.logger.info({ event: "hidden" });
    warn.logger.error({ event: "shown" });
    expect(warn.lines.map((line) => (JSON.parse(line) as { event: string }).event)).toEqual(["shown"]);
    const silent = capture("silent");
    silent.logger.error({ event: "never" });
    expect(silent.lines).toEqual([]);
  });
});
