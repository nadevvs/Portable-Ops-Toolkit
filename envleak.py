#!/usr/bin/env python3
"""Find secret-like keys in local environment/config files without printing values."""

import argparse
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from common.output import emit_json, format_table
from common.redact import SENSITIVE_WORD
from common.sec import marker, overall, print_findings
from common.state import resolve_state_dir


DEFAULT_PATHS = ["/etc/environment", "/etc/profile", "/etc/default", ".env"]
KEY_RE = re.compile(rf"(?i)\b([A-Z0-9_./-]*(?:{SENSITIVE_WORD})[A-Z0-9_./-]*)\s*(=|:)")


def scan_text(text: str) -> List[Dict[str, Any]]:
    hits = []
    for number, line in enumerate(text.splitlines(), 1):
        if line.strip().startswith("#"):
            continue
        match = KEY_RE.search(line)
        if match:
            hits.append({"line": number, "key": match.group(1)})
    return hits


def iter_files(paths: Iterable[str], max_files: int) -> Iterable[Path]:
    count = 0
    for raw in paths:
        path = Path(raw).expanduser()
        if path.is_file():
            yield path
            count += 1
        elif path.is_dir():
            for base, dirs, files in os.walk(str(path)):
                dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "__pycache__"}]
                for name in files:
                    if count >= max_files:
                        return
                    if name.endswith((".env", ".conf", ".ini", ".service", ".sh", ".yml", ".yaml")) or name in {"environment"}:
                        count += 1
                        yield Path(base) / name
        if count >= max_files:
            return


def collect(paths: Optional[str] = None, max_files: int = 500, state: Optional[str] = None) -> Dict[str, Any]:
    scan_paths = [item.strip() for item in paths.split(",")] if paths else DEFAULT_PATHS
    hits = []
    warnings = []
    for path in iter_files(scan_paths, max_files):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            warnings.append(f"{path}: {exc}")
            continue
        for hit in scan_text(text):
            hits.append({"path": str(path), **hit})
    findings = [{"severity": "WARN", "message": f"secret-like key {hit['key']} in {hit['path']}:{hit['line']}"} for hit in hits]
    return {"tool": "envleak", "state_dir": str(resolve_state_dir(state)), "paths": scan_paths, "hits": hits, "findings": findings, "overall": overall(findings), "warnings": warnings}


def print_human(report: Dict[str, Any], no_color: bool = False) -> None:
    print("envleak: secret-like key exposure scan")
    print(f"overall: {marker(report['overall'], no_color)} {report['overall']}")
    rows = report["hits"][:40]
    print()
    print(format_table(rows, ["path", "line", "key"]) if rows else "  no secret-like keys found")
    print()
    print("Findings")
    print_findings(report["findings"], no_color)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Find secret-like keys without printing values.")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--state")
    parser.add_argument("--paths", help="Comma-separated files/directories.")
    parser.add_argument("--max-files", type=int, default=500)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    report = collect(args.paths, args.max_files, args.state)
    emit_json(report) if args.json else print_human(report, args.no_color)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
