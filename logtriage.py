#!/usr/bin/env python3
"""Triage recent system and authentication logs."""

import argparse
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from common.cmd import run_cmd
from common.output import emit_json
from common.redact import redact_text
from common.sec import marker, overall, print_findings
from common.state import resolve_state_dir
from common.warnings import command_warning


PATTERNS = {
    "auth_failed": re.compile(r"failed password|authentication failure|invalid user", re.I),
    "auth_success": re.compile(r"accepted (password|publickey)|session opened", re.I),
    "sudo": re.compile(r"\bsudo\b.*COMMAND=", re.I),
    "oom": re.compile(r"out of memory|oom|killed process", re.I),
    "segfault": re.compile(r"segfault|core dumped", re.I),
    "denied": re.compile(r"permission denied|apparmor=.*DENIED|avc:.*denied", re.I),
    "service_failed": re.compile(r"failed|failure|timeout", re.I),
}


def triage_lines(lines: Iterable[str]) -> Dict[str, Any]:
    counts = {key: 0 for key in PATTERNS}
    examples: Dict[str, List[str]] = {key: [] for key in PATTERNS}
    for line in lines:
        safe = redact_text(line)
        for key, pattern in PATTERNS.items():
            if pattern.search(line):
                counts[key] += 1
                if len(examples[key]) < 5:
                    examples[key].append(safe)
    return {"counts": counts, "examples": examples}


def classify_findings(summary: Dict[str, Any]) -> List[Dict[str, str]]:
    counts = summary.get("counts", {})
    findings = []
    if counts.get("oom", 0):
        findings.append({"severity": "WARN", "message": "recent OOM or killed-process log entries found"})
    if counts.get("denied", 0):
        findings.append({"severity": "WARN", "message": "recent access-control denied entries found"})
    if counts.get("auth_failed", 0) >= 10:
        findings.append({"severity": "WARN", "message": f"{counts['auth_failed']} recent authentication failures"})
    if counts.get("segfault", 0):
        findings.append({"severity": "INFO", "message": "recent segfault/core-dump indicators found"})
    return findings


def collect(lines: int = 300, state: Optional[str] = None) -> Dict[str, Any]:
    warnings = []
    collected: List[str] = []
    journal = run_cmd(["journalctl", "-n", str(lines), "--no-pager"], timeout=7)
    warning = command_warning("journalctl", journal)
    if warning:
        warnings.append(warning)
    if journal.stdout:
        collected.extend(journal.stdout.splitlines())
    if not collected:
        for path in (Path("/var/log/auth.log"), Path("/var/log/secure"), Path("/var/log/syslog"), Path("/var/log/messages")):
            try:
                collected.extend(path.read_text(encoding="utf-8", errors="replace").splitlines()[-lines:])
            except OSError:
                pass
    summary = triage_lines(collected)
    findings = classify_findings(summary)
    return {
        "tool": "logtriage",
        "state_dir": str(resolve_state_dir(state)),
        "lines_scanned": len(collected),
        "summary": summary,
        "findings": findings,
        "overall": overall(findings),
        "warnings": warnings,
    }


def print_human(report: Dict[str, Any], no_color: bool = False) -> None:
    print("logtriage: recent log triage")
    print(f"lines scanned: {report['lines_scanned']}")
    print(f"overall: {marker(report['overall'], no_color)} {report['overall']}")
    print()
    print("Counts")
    for key, value in sorted(report["summary"]["counts"].items()):
        print(f"  {key}: {value}")
    print()
    print("Findings")
    print_findings(report["findings"], no_color)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Summarize recent security-relevant logs.")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--state")
    parser.add_argument("--lines", type=int, default=300)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    report = collect(args.lines, args.state)
    emit_json(report) if args.json else print_human(report, args.no_color)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
