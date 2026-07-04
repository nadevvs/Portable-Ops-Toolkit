#!/usr/bin/env python3
"""Scan local files for simple offline indicators of compromise."""

import argparse
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from common.output import emit_json
from common.redact import redact_text
from common.sec import file_sha256, marker, overall, parse_simple_config, print_findings
from common.state import resolve_state_dir


DEFAULT_SCAN_PATHS = ["/etc", "/tmp"]
HASH_RE = re.compile(r"^[a-fA-F0-9]{64}$")


def parse_iocs(text: str) -> Dict[str, List[str]]:
    parsed = {"sha256": [], "path": [], "domain": [], "ip": [], "text": []}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            kind, value = line.split(":", 1)
            kind = kind.strip().lower()
            value = value.strip()
            if kind in parsed and value:
                parsed[kind].append(value)
            continue
        if HASH_RE.match(line):
            parsed["sha256"].append(line.lower())
    return parsed


def load_iocs(path: str) -> Dict[str, List[str]]:
    try:
        return parse_iocs(Path(path).read_text(encoding="utf-8", errors="replace"))
    except OSError as exc:
        return {"sha256": [], "path": [], "domain": [], "ip": [], "text": [], "_errors": [str(exc)]}  # type: ignore[dict-item]


def iter_files(paths: Iterable[str], max_files: int) -> Iterable[Path]:
    seen = 0
    for raw in paths:
        root = Path(raw)
        if root.is_file():
            yield root
            seen += 1
        elif root.is_dir():
            for base, dirs, files in os.walk(str(root)):
                dirs[:] = [d for d in dirs if d not in {".git", "proc", "sys", "dev"}]
                for name in files:
                    if seen >= max_files:
                        return
                    seen += 1
                    yield Path(base) / name
        if seen >= max_files:
            return


def scan_file(path: Path, iocs: Dict[str, List[str]], max_bytes: int) -> List[Dict[str, Any]]:
    matches = []
    if str(path) in set(iocs.get("path", [])):
        matches.append({"type": "path", "indicator": str(path)})
    if iocs.get("sha256"):
        hashed = file_sha256(path, max_bytes)
        if hashed.get("sha256") in {value.lower() for value in iocs["sha256"]}:
            matches.append({"type": "sha256", "indicator": hashed["sha256"]})
    needles = iocs.get("domain", []) + iocs.get("ip", []) + iocs.get("text", [])
    if needles:
        try:
            data = path.read_bytes()[:max_bytes]
            text = data.decode("utf-8", errors="ignore")
        except OSError:
            text = ""
        for needle in needles:
            if needle and needle in text:
                matches.append({"type": "content", "indicator": redact_text(needle)})
    return matches


def collect(ioc_file: Optional[str], paths: Optional[str], max_files: int, max_bytes: int, state: Optional[str] = None) -> Dict[str, Any]:
    warnings = []
    iocs = load_iocs(ioc_file) if ioc_file else {"sha256": [], "path": [], "domain": [], "ip": [], "text": []}
    warnings.extend(iocs.pop("_errors", []))  # type: ignore[arg-type]
    scan_paths = [item.strip() for item in paths.split(",")] if paths else DEFAULT_SCAN_PATHS
    scanned = 0
    matches = []
    for path in iter_files(scan_paths, max_files):
        scanned += 1
        for match in scan_file(path, iocs, max_bytes):
            matches.append({"path": str(path), **match})
    findings = [
        {"severity": "CRITICAL", "message": f"{item['type']} IOC matched in {item['path']}: {item['indicator']}"}
        for item in matches
    ]
    return {
        "tool": "iocscan",
        "state_dir": str(resolve_state_dir(state)),
        "ioc_counts": {key: len(value) for key, value in iocs.items()},
        "paths": scan_paths,
        "files_scanned": scanned,
        "matches": matches,
        "findings": findings,
        "overall": overall(findings),
        "warnings": warnings,
    }


def print_human(report: Dict[str, Any], no_color: bool = False) -> None:
    print("iocscan: offline IOC scan")
    print(f"files scanned: {report['files_scanned']}")
    print(f"overall: {marker(report['overall'], no_color)} {report['overall']}")
    print()
    print("Findings")
    print_findings(report["findings"], no_color)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Scan local files for path/hash/string IOCs.")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--state")
    parser.add_argument("--iocs", help="IOC file with sha256:, path:, domain:, ip:, or text: lines.")
    parser.add_argument("--paths", help="Comma-separated files or directories to scan.")
    parser.add_argument("--max-files", type=int, default=1000)
    parser.add_argument("--max-bytes", type=int, default=1024 * 1024)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    report = collect(args.iocs, args.paths, args.max_files, args.max_bytes, args.state)
    emit_json(report) if args.json else print_human(report, args.no_color)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
