# Contributing to Revscope

Thank you for helping. Revscope is small and young; issues and focused pull
requests are both welcome.

## Before you start

- For anything beyond a small fix, open an issue first so the approach can be
  agreed before you invest time.
- Security problems: do not open a public issue. Follow
  [SECURITY.md](SECURITY.md).
- Never attach or link binaries you are not allowed to share. Bug reports
  about analysis results should use a program you built yourself or one of
  the test fixtures.

## Development setup

```bash
npm ci
npm run check
```

See [docs/install.md](docs/install.md) for Ghidra. The test tiers are:

| Command | Needs | Runs |
|---|---|---|
| `npm run check` | Node.js only | Type checking, linting, build, every test that does not need Ghidra (including a fake `analyzeHeadless`) |
| `npm run test:ghidra` | `REVSCOPE_GHIDRA_DIR` | Real-engine tests. They fail, never skip, without Ghidra; Mach-O and compiled-object tests run on macOS only |
| `npm run benchmark` | Ghidra, macOS, Xcode command-line tools | The real-binary benchmark, written outside the source tree |
| `npm run licenses` | Node.js only | Declared licences of every locked dependency |

A pull request must pass `npm run check`. If it touches
`src/infrastructure/ghidra/` or `ghidra-scripts/`, also run
`npm run test:ghidra` and say in the pull request where you ran it.

## Expectations

- **Evidence labels are a contract.** Confidence and authority come from the
  result kind through one central table; do not let a producer choose them,
  and never present engine output as observed fact. See
  [docs/architecture.md](docs/architecture.md) and the ADRs in
  `docs/decisions/`.
- **Do not weaken tests to make them pass.** If an assertion is wrong, explain
  why in the pull request and correct it.
- **Errors never leak.** No host paths, environment values, stack traces or
  engine logs in public errors.
- **Claims follow evidence.** Do not document a platform, Ghidra version or
  input type as supported until a check has passed there; update
  [docs/support.md](docs/support.md) with what was run.
- **Dependencies.** Avoid new ones. If one is needed, pin it exactly, explain
  why, and make sure `npm run licenses` passes and
  [docs/dependencies.md](docs/dependencies.md) is updated.
- **Never execute analyzed inputs**, in code or in tests.
- Match the surrounding code's style; `npm run lint` must pass without
  warnings.
- Record significant design decisions as a new ADR in `docs/decisions/`, and
  user-visible changes in [CHANGELOG.md](CHANGELOG.md).

## Developer Certificate of Origin (DCO)

Revscope uses the [Developer Certificate of Origin 1.1](https://developercertificate.org/)
instead of a contributor licence agreement. By adding a `Signed-off-by` line
to a commit, you certify the DCO for that contribution: in short, that you
wrote it or otherwise have the right to submit it under the project's licence
(Apache-2.0). Read the full text at the link above.

Sign off every commit with your real name and an email address you control:

```bash
git commit -s -m "fix: describe the change"
```

which adds:

```text
Signed-off-by: Your Name <you@example.com>
```

To add a missing sign-off to your last commit: `git commit --amend -s`. For
several commits: `git rebase --signoff <base>` on your own branch.

Pull requests with commits that lack a sign-off cannot be merged. The DCO
check is not automated yet; maintainers check it during review.

## Licence of contributions

Unless you state otherwise, contributions are submitted under the Apache
License 2.0, as described in its section 5.
