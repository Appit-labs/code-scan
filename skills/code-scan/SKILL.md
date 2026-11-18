---
name: code-scan
description: Run Skylos (Python dead code, secrets, security, quality) and Fallow (TypeScript/JavaScript unused code, dependencies, duplication, complexity) as one prioritised report, with a baseline gate so CI fails only on new findings. Use when the user asks to scan code, clean dead code or unused dependencies, check a branch before merging, review AI-generated code, or wire a scan into CI or a pre-commit hook.
allowed-tools:
  - Bash
  - Read
  - Write
license: MIT
permissions:
  - shell
  - file_write
---

# Code scan — Skylos + Fallow, one report

Two scanners, one gate. Skylos covers Python (dead code, secrets, risky flows, quality,
dependency advisories); Fallow covers TypeScript/JavaScript (unused exports, files and
dependencies, duplication, complexity, architecture cycles).

```
python3 "$SKILL_DIR/scripts/scan.py" <path> [--gate] [--changed[=ref]] [--json|--md] [--fix-plan]
```

## Portability

Works in any agent that can run shell commands. Commands use `$SKILL_DIR` for this skill's
folder — the one holding this `SKILL.md`:

```bash
SKILL_DIR=~/.claude/skills/code-scan     # or ~/.codex/skills/…, ~/.pi/agent/skills/…, .cursor/skills/…
```

## Prerequisites

- `pip install skylos` (Apache-2.0, local-first). The script finds a versioned pyenv binary
  before the shim, because the shim only works for the `pyenv global` version.
- `npm i -g fallow` or `npx fallow` (MIT). Same care with nvm.
- Nothing else: no account, no network. The script passes `--no-upload` to Skylos on every
  run, so code never leaves the machine. `skylos cloud` is a separate, opt-in decision the
  user makes themselves — this skill never enables it.

## The workflow that actually reduces findings

1. **Scan** — `scan.py .` for the table, `--md` when the output goes into a PR comment.
2. **`--fix-plan`** — groups findings into *delete* (unused functions, imports, files,
   dependencies: safe after a test run) and *needs a human* (secrets, injection paths,
   policy gaps). Start with the deletions: they are reversible and they shrink the surface
   the other findings hide in.
3. **Verify** — run the test suite. Then re-scan. An unused export that turns out to be
   framework-discovered is a false positive: Skylos supports `# skylos: ignore [SKY-…]`,
   Fallow supports `// fallow-ignore-next-line`. Add the narrowest annotation, never a
   blanket ignore, and say why in the comment.
4. **Gate** — `scan.py . --save-baseline` once, then `--gate` in CI or a pre-commit hook:
   it exits 1 **only on new** high-severity findings, so an existing codebase can adopt it
   without a cleanup project first. `--threshold=medium` when you want a stricter gate.

## Scope it to the change

```bash
scan.py . --changed              # Skylos --diff-base origin/main, Fallow audit --base origin/main
scan.py . --changed=origin/release
```

Waiting until a branch is done makes the report useless: run it on the diff, fix in the
same commit, and the baseline stays at zero.

## What it will not do

- It will not delete anything. Fallow's `fix` and Skylos's `clean` are interactive or
  auto-fixing and stay out of this skill; a scan you can trust should not be able to edit
  code in the same command.
- It will not upload, phone home, or enable a hosted service.
- It will not claim a clean repo when a scanner is missing — it says which tool was skipped.

## Licence and fair use

Both tools are permissive open source (Skylos Apache-2.0, Fallow MIT): calling them from a
skill is ordinary use. Do not vendor their code into a repo, do not republish their outputs
as your own product, and if you ever add a hosted tier of either, keep it opt-in and
disclosed. Anything beyond that is a conversation with their authors, not a technical trick.

## Reading the output

- `high` — a secret in code, an injection/SSRF/deserialisation path, a vulnerable
  dependency, or a Fallow audit verdict of `fail`. Fix before merging.
- `medium` — unused files and dependencies (write-throughput and supply-chain cost),
  missing type/lint policy.
- `low` — unused exports, imports, functions, classes, parameters, variables.
- `info` — the scanner could not analyse a file; treat as unknown, not as clean.
