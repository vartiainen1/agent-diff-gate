# Security Policy

## Reporting a vulnerability

This project is a small, dependency-free workflow tool. Please report
suspected vulnerabilities privately — do **not** open a public issue for
security problems:

- Open a **private advisory**: GitHub → *Security* → *Report a vulnerability*
- Or email the maintainer via the GitHub profile contact info.

You should get an acknowledgement within a few days. Please do not disclose
the issue publicly until it has been addressed.

## Scope & known limitations

- The log-before-fix gate is a **workflow discipline tool, not a security
  boundary**. `git commit --no-verify` bypasses local hooks by design.
- The diff gate is a **heuristic linter, not a SAST scanner**. It can miss
  real vulnerabilities and can report false positives — treat its findings
  as review aids, not proof of security.
- On GitHub-hosted repos the CI `commit-gate` job re-checks every pushed
  commit server-side, where `--no-verify` cannot reach.
- Secrets or credentials must never be written into `errors.txt`,
  `rules.txt`, `notes.txt`, or commit messages — treat all of these as
  public once pushed. The gate flags credential literals in diffs by
  design; that is a feature, not a bug.

## Trust model

Two surfaces execute or trust code from outside this file:

- **Plugin rules (`rules.d/`, `--rules-dir`)** are imported and executed as
  Python modules at scan time. **Only add plugins you trust** — a plugin
  runs with your user's privileges, exactly like the repository's own code.
  Never load a `rules.d/` you did not author. A *broken* plugin is skipped
  with a warning and can never crash the gate; a *malicious* one is code
  execution by design.
- **Diff input (`--stdin`, `--file`, and any scanned branch) is untrusted.**
  The gate keeps every file read **inside the repository root**: paths with
  `..`, absolute paths, NUL bytes, and symlinks that escape the root are
  refused (S1); Windows junction points are a documented residual limitation
  (creating one requires local privileges). Diff size is capped (8 MiB) so the gate cannot be made to
  exhaust memory (S4). Report text derived from the diff is stripped of
  terminal/bidi control characters (S3) and credential values are redacted
  from snippets (S2). The gate is fully offline — it never sends data
  anywhere.

## Supported versions

Security fixes land on `master` and are released per
[SemVer](https://semver.org/). Always use the latest release:
https://github.com/vartiainen1/agent-diff-gate/releases
