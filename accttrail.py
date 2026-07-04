#!/usr/bin/env python3
"""Summarize local login and account activity."""

import argparse
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from common.cmd import run_cmd
from common.output import emit_json, format_table
from common.sec import marker, overall, print_findings
from common.state import resolve_state_dir
from common.warnings import command_warning


def parse_last(text: str) -> List[Dict[str, str]]:
    rows = []
    for line in text.splitlines():
        if not line.strip() or line.startswith(("wtmp begins", "reboot ", "shutdown ")):
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        user = parts[0]
        source = parts[2] if len(parts) > 2 and parts[1].startswith(("pts", "tty", "ssh")) else ""
        rows.append({"user": user, "tty": parts[1], "source": source, "raw": line.strip()[:200]})
    return rows


def parse_lastlog(text: str) -> List[Dict[str, str]]:
    rows = []
    for index, line in enumerate(text.splitlines()):
        if index == 0 or not line.strip() or "**Never logged in**" in line:
            continue
        parts = line.split()
        if parts:
            rows.append({"user": parts[0], "raw": line.strip()[:200]})
    return rows


def parse_passwd(text: str) -> List[Dict[str, Any]]:
    users = []
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) >= 7:
            users.append({"user": parts[0], "uid": int(parts[2]) if parts[2].isdigit() else parts[2], "gid": parts[3], "home": parts[5], "shell": parts[6]})
    return users


def classify_findings(logins: List[Dict[str, str]], users: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    findings = []
    uid0 = [item["user"] for item in users if item.get("uid") == 0 and item.get("user") != "root"]
    for user in uid0:
        findings.append({"severity": "CRITICAL", "message": f"non-root UID 0 account: {user}"})
    shells = [item for item in users if str(item.get("shell", "")).endswith(("sh", "bash", "zsh", "fish")) and item.get("uid") not in {0, "0"}]
    if len(shells) > 20:
        findings.append({"severity": "INFO", "message": f"{len(shells)} non-root interactive shell accounts"})
    sources = Counter(item.get("source") for item in logins if item.get("source"))
    for source, count in sources.most_common(5):
        if count >= 10:
            findings.append({"severity": "INFO", "message": f"{count} recent sessions from {source}"})
    return findings


def collect(limit: int = 50, state: Optional[str] = None) -> Dict[str, Any]:
    warnings = []
    last_result = run_cmd(["last", "-n", str(limit)], timeout=5)
    lastlog_result = run_cmd(["lastlog"], timeout=5)
    for label, result in (("last", last_result), ("lastlog", lastlog_result)):
        warning = command_warning(label, result)
        if warning and not result.missing:
            warnings.append(warning)
    try:
        passwd = Path("/etc/passwd").read_text(encoding="utf-8", errors="replace")
    except OSError:
        passwd = ""
    logins = parse_last(last_result.stdout)
    lastlog_rows = parse_lastlog(lastlog_result.stdout)
    users = parse_passwd(passwd)
    findings = classify_findings(logins, users)
    return {"tool": "accttrail", "state_dir": str(resolve_state_dir(state)), "recent_logins": logins, "lastlog": lastlog_rows[:limit], "users": users, "findings": findings, "overall": overall(findings), "warnings": warnings}


def print_human(report: Dict[str, Any], no_color: bool = False) -> None:
    print("accttrail: login and account activity")
    print(f"overall: {marker(report['overall'], no_color)} {report['overall']}")
    print()
    print(format_table(report["recent_logins"][:20], ["user", "tty", "source"]) if report["recent_logins"] else "  no recent logins found")
    print()
    print("Findings")
    print_findings(report["findings"], no_color)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Summarize local login and account activity.")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--state")
    parser.add_argument("--limit", type=int, default=50)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    report = collect(args.limit, args.state)
    emit_json(report) if args.json else print_human(report, args.no_color)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
