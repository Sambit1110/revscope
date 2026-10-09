import { invalidInput, type ErrorEnvelope, type InputIssue } from "../domain/errors.js";
import { err, ok, type Result } from "../domain/result.js";

/** Variables a child receives from the host unless the policy replaces the baseline. */
export const DEFAULT_BASELINE: readonly string[] = Object.freeze([
  "PATH",
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
  "TZ",
]);

export interface EnvironmentPolicy {
  /** Host variables approved for every child; defaults to DEFAULT_BASELINE. */
  readonly baseline?: readonly string[];
  /** Additional host variables deliberately passed through by name. */
  readonly passthrough?: readonly string[];
  /** Values set explicitly for the child; they never come from the host. */
  readonly set?: Readonly<Record<string, string>>;
}

/**
 * What the child received, by name only. Values are never recorded, whether
 * inherited or set explicitly.
 */
export interface EnvironmentManifest {
  readonly approved_names: readonly string[];
  readonly inherited_names: readonly string[];
  readonly absent_names: readonly string[];
  readonly set_names: readonly string[];
}

export interface ChildEnvironment {
  readonly env: Readonly<Record<string, string>>;
  readonly manifest: EnvironmentManifest;
}

const NAME = /^[A-Za-z_][A-Za-z0-9_]*$/u;

/**
 * Build a child environment from an explicit allowlist. Nothing outside the
 * baseline, passthrough, and explicit set lists can reach the child.
 */
export const buildChildEnvironment = (
  host: Readonly<Record<string, string | undefined>>,
  policy: EnvironmentPolicy = {},
): Result<ChildEnvironment, ErrorEnvelope> => {
  const baseline = policy.baseline ?? DEFAULT_BASELINE;
  const passthrough = policy.passthrough ?? [];
  const set = policy.set ?? {};
  const issues: InputIssue[] = [];
  const checkName = (name: string, path: string) => {
    if (!NAME.test(name))
      issues.push({ path, message: "Environment variable names must match [A-Za-z_][A-Za-z0-9_]*" });
  };
  baseline.forEach((name, index) => checkName(name, `baseline.${String(index)}`));
  passthrough.forEach((name, index) => checkName(name, `passthrough.${String(index)}`));
  for (const [name, value] of Object.entries(set)) {
    checkName(name, `set.${name}`);
    if (value.includes("\0"))
      issues.push({ path: `set.${name}`, message: "Values cannot contain NUL characters" });
  }
  const approved = [...new Set([...baseline, ...passthrough])].toSorted();
  for (const name of Object.keys(set))
    if (approved.includes(name))
      issues.push({
        path: `set.${name}`,
        message: "A variable cannot be both inherited and set explicitly",
      });
  if (issues.length > 0)
    return err(invalidInput("The child environment policy is invalid", issues));

  const env: Record<string, string> = {};
  const inherited: string[] = [];
  const absent: string[] = [];
  for (const name of approved) {
    const value = host[name];
    if (value === undefined) absent.push(name);
    else {
      env[name] = value;
      inherited.push(name);
    }
  }
  for (const [name, value] of Object.entries(set)) env[name] = value;
  return ok({
    env,
    manifest: {
      approved_names: approved,
      inherited_names: inherited,
      absent_names: absent,
      set_names: Object.keys(set).toSorted(),
    },
  });
};
