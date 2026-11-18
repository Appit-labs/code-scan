#!/usr/bin/env python3
"""Run Skylos (Python) and Fallow (TS/JS) as one prioritised report, with a baseline gate.

    scan.py [path]                        # report, human table
    scan.py [path] --changed [ref]        # only what this branch touched
    scan.py [path] --gate                 # exit 1 on new high-severity findings
    scan.py [path] --save-baseline [file] # accept today's findings, fail only on new ones
    scan.py [path] --json | --md          # machine output / PR comment
    scan.py [path] --fix-plan             # what to remove first, grouped by rule
    scan.py self-test

Both scanners are called as local CLIs. Nothing is uploaded: Skylos gets `--no-upload`
always, and Fallow runs entirely offline. Licences: Skylos Apache-2.0, Fallow MIT — calling
them from a skill is ordinary use; vendoring or re-publishing them would not be.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

DEFAULT_BASELINE = ".code-scan-baseline.json"
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

# Skylos grades complexity and structure as HIGH/CRITICAL findings too, which makes a gate
# useless. Severity here is by *kind*: only secrets, security flows and vulnerable
# dependencies block a merge; complexity and quality are refactor signals.
KIND_SEVERITY = {
    "security": "high", "secret": "high", "secrets": "high", "vulnerability": "high",
    "injection": "high", "ssrf": "high", "xss": "high", "traversal": "high",
    "complexity": "medium", "structure": "medium", "quality": "medium",
    "performance": "medium", "nesting": "medium", "logic": "medium", "design": "medium",
    "architecture": "medium", "maintainability": "medium", "duplication": "medium",
    "style": "low", "policy": "low", "formatting": "low",
}
# Narrow phrase list: only an actual credential/secret makes a finding merge-blocking.
SECRET_PHRASES = ("hardcoded credential", "hardcoded secret", "api key", "private key",
                  "password", "credential in", "secret in", "token in")


def severity_for(kind: str, raw: str, message: str) -> str:
    low = (message or "").lower()
    if any(w in low for w in SECRET_PHRASES):
        return "high"
    for key, sev in KIND_SEVERITY.items():
        if key in (kind or "").lower():
            return sev
    return "medium"   # unknown kind: a refactor signal, never a merge blocker


def parse_flags(argv):
    """--key=value and --key value both work; a bare --flag is True."""
    flags, args, i = {}, [], 0
    while i < len(argv):
        a = argv[i]
        if a.startswith("--"):
            if "=" in a:
                k, v = a[2:].split("=", 1)
                flags[k] = v
            elif i + 1 < len(argv) and not argv[i + 1].startswith("-"):
                flags[a[2:]] = argv[i + 1]
                i += 1
            else:
                flags[a[2:]] = True
        else:
            args.append(a)
        i += 1
    return flags, args


class ToolMissing(Exception):
    pass


def which(tool: str) -> str | None:
    """Find the CLI. A versioned pyenv binary beats the shim: the shim only works for the
    pyenv `global` version, which is not necessarily the interpreter running this script."""
    if tool == "skylos":
        versions = sorted((Path.home() / ".pyenv" / "versions").glob("*/bin/skylos"))
        if versions:
            return str(versions[-1])
    if tool == "fallow":
        nvm = sorted((Path.home() / ".nvm" / "versions" / "node").glob("*/bin/fallow"))
        if nvm:
            return str(nvm[-1])
    found = shutil.which(tool)
    if found:
        return found
    for cand in (Path.home() / ".pyenv" / "shims" / tool,
                 Path.home() / ".local" / "bin" / tool):
        if cand.is_file() and os.access(cand, os.X_OK):
            return str(cand)
    if tool == "skylos":
        versions = sorted((Path.home() / ".pyenv" / "versions").glob("*/bin/skylos"))
        if versions:
            return str(versions[-1])
    if tool == "fallow":
        nvm = sorted((Path.home() / ".nvm" / "versions" / "node").glob("*/bin/fallow"))
        if nvm:
            return str(nvm[-1])
    return None


def run(argv: list[str], cwd: Path, timeout: int = 300) -> tuple[int, str, str]:
    proc = subprocess.run(argv, cwd=str(cwd), capture_output=True, text=True, timeout=timeout)
    return proc.returncode, proc.stdout, proc.stderr


def fingerprint(tool: str, rule: str, file: str, name: str) -> str:
    raw = f"{tool}|{rule}|{file}|{name}".encode()
    return hashlib.sha256(raw).hexdigest()[:16]


# ------------------------------------------------------------------ skylos

def scan_python(root: Path, changed: str | None) -> list[dict]:
    exe = which("skylos")
    if not exe:
        raise ToolMissing("skylos not found: pip install skylos")
    argv = [exe, str(root), "-a", "--no-upload", "--json"]
    if changed:
        argv += ["--diff-base", changed]
    code, out, err = run(argv, root)
    if not out.strip():
        raise SystemExit(f"skylos returned nothing (exit {code}): {err.strip()[:300]}")
    data = json.loads(out)
    findings: list[dict] = []
    for item in data.get("quality") or []:
        findings.append(dict(
            tool="skylos", rule=str(item.get("rule_id") or item.get("kind") or "quality"),
            severity=severity_for(str(item.get("kind") or ""), str(item.get("severity") or ""),
                                  str(item.get("message") or "")),
            file=str(item.get("file") or ""), line=item.get("line") or 0,
            message=str(item.get("message") or "").strip(),
            name=str(item.get("name") or item.get("simple_name") or ""),
        ))
    dead_kinds = {
        "unused_functions": "unused-function", "unused_imports": "unused-import",
        "unused_classes": "unused-class", "unused_variables": "unused-variable",
        "unused_parameters": "unused-parameter", "unused_files": "unused-file",
    }
    for key, rule in dead_kinds.items():
        for item in data.get(key) or []:
            if isinstance(item, str):
                findings.append(dict(tool="skylos", rule=rule, severity="low", file=item, line=0,
                                     message=f"{rule.replace('-', ' ')}: {Path(item).name}", name=item))
            elif isinstance(item, dict):
                findings.append(dict(tool="skylos", rule=rule, severity="low",
                                     file=str(item.get("file") or item.get("path") or ""),
                                     line=item.get("line") or 0,
                                     message=str(item.get("message") or rule.replace("-", " ")),
                                     name=str(item.get("name") or item.get("symbol") or "")))
    for item in data.get("dependency_vulnerabilities") or []:
        findings.append(dict(tool="skylos", rule="vulnerable-dependency", severity="high",
                             file="requirements", line=0,
                             message=str(item.get("advisory") or item.get("message") or item),
                             name=str(item.get("package") or "")))
    for item in data.get("analysis_errors") or []:
        findings.append(dict(tool="skylos", rule="analysis-error", severity="info",
                             file=str(item.get("file") or ""), line=0,
                             message=str(item.get("error") or item.get("message") or "")[:200], name=""))
    return findings


# ------------------------------------------------------------------ fallow

def scan_javascript(root: Path, changed: str | None) -> list[dict]:
    exe = which("fallow")
    if not exe:
        raise ToolMissing("fallow not found: npm i -g fallow (or npx fallow)")
    command = ["dead-code", "-f", "json"]
    argv = [exe, *command]
    if changed:
        argv = [exe, "audit", "--base", changed, "-f", "json"]
    code, out, err = run(argv, root, timeout=420)
    if not out.strip():
        raise SystemExit(f"fallow returned nothing (exit {code}): {err.strip()[:300]}")
    start = out.find("{")
    data = json.loads(out[start:])
    findings: list[dict] = []
    for item in data.get("unused_exports") or []:
        findings.append(dict(tool="fallow", rule="unused-export", severity="low",
                             file=str(item.get("path") or ""), line=item.get("line") or 0,
                             message=f"unused export: {item.get('export_name')}",
                             name=str(item.get("export_name") or "")))
    for item in data.get("unused_files") or []:
        path = item if isinstance(item, str) else item.get("path", "")
        findings.append(dict(tool="fallow", rule="unused-file", severity="medium", file=path, line=0,
                             message=f"file nothing imports: {Path(path).name}", name=path))
    for key, rule in (("unused_dependencies", "unused-dependency"),
                      ("unused_dev_dependencies", "unused-dev-dependency"),
                      ("unused_optional_dependencies", "unused-optional-dependency"),
                      ("unused_types", "unused-type"),
                      ("unused_enum_members", "unused-enum-member"),
                      ("unused_class_members", "unused-class-member")):
        for item in data.get(key) or []:
            if isinstance(item, dict):
                findings.append(dict(tool="fallow", rule=rule, severity="medium",
                                     file=str(item.get("path") or "package.json"),
                                     line=item.get("line") or 0,
                                     message=f"{rule.replace('-', ' ')}: "
                                             f"{item.get('package_name') or item.get('path') or ''}",
                                     name=str(item.get("package_name") or item.get("path") or "")))
    for item in data.get("findings") or []:
        if isinstance(item, dict):
            findings.append(dict(tool="fallow", rule=str(item.get("kind") or "finding"),
                                 severity=str(item.get("severity") or "medium").lower(),
                                 file=str(item.get("path") or ""), line=item.get("line") or 0,
                                 message=str(item.get("message") or "")[:200],
                                 name=str(item.get("export_name") or "")))
    verdict = (data.get("verdict") or data.get("status") or "")
    if isinstance(verdict, str) and verdict.lower() == "fail":
        findings.append(dict(tool="fallow", rule="audit-verdict", severity="high", file="", line=0,
                             message="fallow audit verdict: fail on the changed files", name=""))
    return findings


# ------------------------------------------------------------------ report

def detect(root: Path) -> tuple[bool, bool]:
    python = any(root.glob("*.py")) or (root / "pyproject.toml").exists() or any(root.glob("*/pyproject.toml"))
    node = (root / "package.json").exists() or any(root.glob("*.ts")) or any(root.glob("*.tsx"))
    return python, node


def render(findings: list[dict], fmt: str, root: Path, limit: int = 40) -> None:
    findings = sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["file"], f["line"]))
    if fmt == "json":
        print(json.dumps(findings, indent=2))
        return
    if fmt == "md":
        print("| severity | tool | rule | file:line | finding |\n| --- | --- | --- | --- | --- |")
        for f in findings:
            print(f"| {f['severity']} | {f['tool']} | `{f['rule']}` | `{f['file']}:{f['line']}` | "
                  f"{f['message'][:110]} |")
        return
    if not findings:
        print("clean: no findings from skylos or fallow")
        return
    counts: dict[str, int] = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    order = " · ".join(f"{counts[s]} {s}" for s in ("high", "medium", "low", "info") if counts.get(s))
    print(f"findings: {len(findings)}  ({order})")
    if limit and len(findings) > limit:
        print(f"  (showing the first {limit}; --limit=0 for all, --json for machine output)")
        findings = findings[:limit]
    for f in findings:
        rel = f["file"]
        try:
            rel = str(Path(f["file"]).relative_to(root))
        except ValueError:
            pass
        print(f"  [{f['severity']:<6}] {f['tool']:<6} {f['rule']:<22} {rel}:{f['line']}  {f['message'][:90]}")


def fix_plan(findings: list[dict]) -> None:
    groups: dict[str, list[dict]] = {}
    for f in findings:
        groups.setdefault(f"{f['tool']}:{f['rule']}", []).append(f)
    print("fix plan — first the things that delete code, then the things that risk it:\n")
    removable = {k: v for k, v in groups.items() if "unused" in k}
    for key in sorted(removable, key=lambda k: -len(removable[k])):
        items = removable[key]
        print(f"  {key}  ×{len(items)}")
        for f in items[:6]:
            print(f"      {f['file']}:{f['line']}  {f['name'][:60]}")
        if len(items) > 6:
            print(f"      … {len(items) - 6} more")
    risky = {k: v for k, v in groups.items() if k not in removable}
    if risky:
        print("\n  needs a human:")
        for key in sorted(risky, key=lambda k: -len(risky[k])):
            print(f"    {key}  ×{len(risky[key])}")
    print("\n  after removals: run the test suite, then `fallow audit --base origin/main` and "
          "`skylos . -a --gate` again.")


def load_baseline(path: Path) -> set[str]:
    if not path.exists():
        return set()
    try:
        return set(json.loads(path.read_text()).get("fingerprints") or [])
    except (ValueError, OSError):
        return set()


def save_baseline(path: Path, findings: list[dict]) -> None:
    prints = sorted(fingerprint(f["tool"], f["rule"], f["file"], f["name"]) for f in findings)
    path.write_text(json.dumps({"savedAt": datetime.datetime.now(datetime.timezone.utc)
                                .isoformat(timespec="seconds").replace("+00:00", "Z"),
                                "count": len(prints), "fingerprints": prints}, indent=2) + "\n")


def self_test() -> int:
    f = fingerprint("skylos", "unused-import", "a.py", "os")
    assert len(f) == 16 and f == fingerprint("skylos", "unused-import", "a.py", "os")
    assert f != fingerprint("skylos", "unused-import", "a.py", "sys")
    findings = [
        dict(tool="skylos", rule="SKY-L014", severity="high", file="/x/app.py", line=7, message="hardcoded", name="PASS"),
        dict(tool="fallow", rule="unused-export", severity="low", file="src/a.ts", line=2, message="unused export: n", name="n"),
    ]
    import io
    import contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        render(findings, "md", Path("/tmp"))
    assert "| high | skylos |" in buf.getvalue(), buf.getvalue()
    with contextlib.redirect_stdout(io.StringIO()) as b2:
        fix_plan(findings)
    assert "fallow:unused-export" in b2.getvalue()
    assert SEVERITY_ORDER["high"] < SEVERITY_ORDER["low"]
    print("self-test ok")
    return 0


def main(argv: list[str]) -> int:
    flags, args = parse_flags(argv[1:])
    if args and args[0] == "self-test":
        return self_test()
    root = Path(args[0] if args and not args[0].startswith("--") else ".").resolve()
    fmt = "json" if flags.get("json") else ("md" if flags.get("md") else "table")
    changed = flags.get("changed")
    changed = None if changed in (None, False, True) else str(changed)
    if flags.get("changed") is True:
        changed = "origin/main"

    python, node = detect(root)
    findings: list[dict] = []
    ran: list[str] = []
    try:
        if python and flags.get("tool") != "fallow":
            findings += scan_python(root, changed)
            ran.append("skylos")
        if node and flags.get("tool") != "skylos":
            findings += scan_javascript(root, changed)
            ran.append("fallow")
    except ToolMissing as exc:
        print(f"skipped: {exc}", file=sys.stderr)
    if not ran:
        print(f"nothing to scan in {root} (no Python or TS/JS detected)", file=sys.stderr)
        return 2

    render(findings, fmt, root, int(flags.get("limit", 40)))
    if flags.get("fix-plan"):
        fix_plan(findings)

    baseline = root / str(flags.get("baseline") or DEFAULT_BASELINE)
    if flags.get("save-baseline"):
        save_baseline(baseline, findings)
        print(f"\nbaseline written: {baseline} ({len(findings)} findings accepted)", file=sys.stderr)
        return 0
    if flags.get("gate"):
        known = load_baseline(baseline)
        threshold = str(flags.get("threshold") or "high")
        limit = SEVERITY_ORDER.get(threshold, 0)
        new = [f for f in findings
               if fingerprint(f["tool"], f["rule"], f["file"], f["name"]) not in known
               and SEVERITY_ORDER.get(f["severity"], 9) <= limit]
        if new:
            print(f"\ngate FAILED: {len(new)} new {threshold}+ finding(s)", file=sys.stderr)
            for f in new[:10]:
                print(f"  {f['tool']} {f['rule']} {f['file']}:{f['line']}", file=sys.stderr)
            return 1
        print(f"\ngate passed: no new {threshold}+ findings ({len(known)} baselined)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
