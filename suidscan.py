#!/usr/bin/env python3
"""Scan for SUID/SGID files and world-writable directories."""

import argparse
import os
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from common.output import emit_json, format_table
from common.sec import marker, overall, print_findings, stat_metadata
from common.state import resolve_state_dir


DEFAULT_PATHS = ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/tmp", "/var/tmp", "/dev/shm"]


def iter_paths(paths: Iterable[str], max_entries: int) -> Iterable[Path]:
    count = 0
    for root_text in paths:
        root = Path(root_text)
        if not root.exists():
            continue
        if root.is_file() or root.is_symlink():
            yield root
            count += 1
        else:
            for base, dirs, files in os.walk(str(root)):
                dirs[:] = [d for d in dirs if d not in {"proc", "sys", "dev"}]
                for name in dirs + files:
                    if count >= max_entries:
                        return
                    count += 1
                    yield Path(base) / name
        if count >= max_entries:
            return


def classify_entries(entries: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    findings = []
    for item in entries:
        if item.get("type") == "file" and item.get("setuid"):
            severity = "WARN"
            if str(item.get("path", "")).startswith(("/tmp/", "/var/tmp/", "/dev/shm/")):
                severity = "CRITICAL"
            findings.append({"severity": severity, "message": f"SUID file: {item['path']} mode {item.get('mode')}"})
        if item.get("type") == "dir" and item.get("world_writable") and item.get("sticky"):
            findings.append({"severity": "INFO", "message": f"world-writable sticky directory: {item['path']}"})
        elif item.get("type") == "dir" and item.get("world_writable"):
            findings.append({"severity": "WARN", "message": f"world-writable directory without sticky bit: {item['path']}"})
    return findings


def collect(paths: Optional[str] = None, max_entries: int = 20000, state: Optional[str] = None) -> Dict[str, Any]:
    scan_paths = [item.strip() for item in paths.split(",")] if paths else DEFAULT_PATHS
    interesting = []
    for path in iter_paths(scan_paths, max_entries):
        meta = stat_metadata(path)
        if meta.get("setuid") or meta.get("setgid") or meta.get("world_writable"):
            interesting.append(meta)
    findings = classify_entries(interesting)
    return {"tool": "suidscan", "state_dir": str(resolve_state_dir(state)), "paths": scan_paths, "interesting": interesting, "findings": findings, "overall": overall(findings), "warnings": []}


def print_human(report: Dict[str, Any], no_color: bool = False) -> None:
    print("suidscan: SUID/SGID and writable path scan")
    print(f"overall: {marker(report['overall'], no_color)} {report['overall']}")
    rows = [{"path": x.get("path"), "type": x.get("type"), "mode": x.get("mode")} for x in report["interesting"][:40]]
    print()
    print(format_table(rows, ["path", "type", "mode"]) if rows else "  none")
    print()
    print("Findings")
    print_findings(report["findings"], no_color)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Scan for SUID/SGID files and world-writable directories.")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--state")
    parser.add_argument("--paths", help="Comma-separated roots to scan.")
    parser.add_argument("--max-entries", type=int, default=20000)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    report = collect(args.paths, args.max_entries, args.state)
    emit_json(report) if args.json else print_human(report, args.no_color)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
