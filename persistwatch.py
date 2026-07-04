#!/usr/bin/env python3
"""Inventory Linux persistence locations and flag risky entries."""

import argparse
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from common.output import emit_json, format_table
from common.redact import redact_text
from common.sec import marker, overall, print_findings, stat_metadata
from common.state import resolve_state_dir


AUTORUN_FILES = [
    "/etc/rc.local",
    "/etc/profile",
    "/etc/bash.bashrc",
    "/etc/zsh/zshrc",
    "/etc/ld.so.preload",
]
AUTORUN_DIRS = ["/etc/systemd/system", "/etc/init.d", "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily"]
SUSPICIOUS = re.compile(r"curl|wget|nc |ncat|socat|/dev/tcp|base64|chmod \+x|/tmp/|/dev/shm/", re.I)


def parse_systemd_unit(text: str) -> Dict[str, List[str]]:
    data: Dict[str, List[str]] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in {"ExecStart", "ExecStartPre", "ExecStartPost", "Environment", "EnvironmentFile", "User"}:
            data.setdefault(key, []).append(redact_text(value.strip()))
    return data


def suspicious_reasons(text: str) -> List[str]:
    reasons = []
    if SUSPICIOUS.search(text):
        reasons.append("contains network, temp-path, or encoded-command pattern")
    if "LD_PRELOAD" in text or "/etc/ld.so.preload" in text:
        reasons.append("uses dynamic-loader preload mechanism")
    return reasons


def read_entry(path: Path) -> Dict[str, Any]:
    entry = stat_metadata(path)
    if not entry.get("exists") or entry.get("type") == "dir":
        return entry
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        entry["error"] = str(exc)
        return entry
    entry["lines"] = len(text.splitlines())
    entry["suspicious_reasons"] = suspicious_reasons(text)
    if path.suffix == ".service" or "[Service]" in text:
        entry["unit"] = parse_systemd_unit(text)
    return entry


def iter_autorun_paths(extra: Iterable[str]) -> Iterable[Path]:
    for item in AUTORUN_FILES:
        yield Path(item)
    for raw_dir in AUTORUN_DIRS:
        directory = Path(raw_dir)
        if not directory.is_dir():
            continue
        for child in sorted(directory.iterdir()):
            if child.is_file() or child.is_symlink():
                yield child
    for item in extra:
        yield Path(item)


def collect(paths: Optional[str] = None, state: Optional[str] = None) -> Dict[str, Any]:
    extra = [item.strip() for item in paths.split(",")] if paths else []
    entries = [read_entry(path) for path in iter_autorun_paths(extra)]
    findings = []
    for item in entries:
        if item.get("world_writable"):
            findings.append({"severity": "CRITICAL", "message": f"{item['path']} is world-writable"})
        for reason in item.get("suspicious_reasons", []):
            findings.append({"severity": "WARN", "message": f"{item['path']}: {reason}"})
        if item.get("path") == "/etc/ld.so.preload" and item.get("exists") and item.get("size", 0):
            findings.append({"severity": "CRITICAL", "message": "/etc/ld.so.preload is populated"})
    return {
        "tool": "persistwatch",
        "state_dir": str(resolve_state_dir(state)),
        "entries": entries,
        "findings": findings,
        "overall": overall(findings),
        "warnings": [],
    }


def print_human(report: Dict[str, Any], no_color: bool = False) -> None:
    print("persistwatch: persistence inventory")
    print(f"entries inspected: {len(report['entries'])}")
    print(f"overall: {marker(report['overall'], no_color)} {report['overall']}")
    print()
    rows = [{"path": x.get("path"), "type": x.get("type", ""), "mode": x.get("mode", ""), "size": x.get("size", "")} for x in report["entries"][:25]]
    print(format_table(rows, ["path", "type", "mode", "size"]) if rows else "  none")
    print()
    print("Findings")
    print_findings(report["findings"], no_color)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Inventory common Linux persistence locations.")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--state")
    parser.add_argument("--paths", help="Additional comma-separated files to inspect.")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    report = collect(args.paths, args.state)
    emit_json(report) if args.json else print_human(report, args.no_color)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
