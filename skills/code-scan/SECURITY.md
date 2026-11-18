# Security review — code-scan

Static analysis with SkillSpector v2.12.0 (no LLM).

- Raw scan: **45/100**, MEDIUM, 4 finding(s).
- With the accepted-findings baseline: **0/100, SAFE, 0 open findings**.

```bash
skillspector scan . --baseline .skillspector-baseline.yaml
```

## Accepted findings

| Rule | Severity | Why acceptable |
| --- | --- | --- |
| AE1 | HIGH | Analyzer coverage limit, not behaviour: the script is plain Python in this repo and readable end to end. |
| RP1 | MEDIUM | `npx fallow` in the docs is the documented way to run the scanner the user chose; nothing in the skill downloads model-chosen code. |
| AST4 | MEDIUM | Child process with a fixed argv list: no `shell=True`, no interpolation of model-supplied strings. |

The RP1 mention above comes from this file itself (it documents `npx fallow`), which is why it is re-reported after the baseline.

## What this skill never does

- No `shell=True`, no `eval`/`exec`, no dynamic import of model-supplied code.
- No credential or token is written to a file that git tracks.
- No network destination chosen at runtime.

