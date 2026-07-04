#!/usr/bin/env python3
"""Audit local cloud-init and cloud metadata posture."""

import argparse
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from common.output import emit_json, format_table
from common.redact import redact_text
from common.sec import marker, overall, print_findings
from common.state import resolve_state_dir


DEFAULT_PATHS = ["/etc/cloud", "/var/lib/cloud/instance/user-data.txt", "/var/lib/cloud/instances"]
METADATA_IP = "169.254.169.254"


def scan_cloud_text(text: str, path: str = "") -> List[Dict[str, str]]:
    hits = []
    for number, line in enumerate(text.splitlines(), 1):
        lowered = line.lower()
        if METADATA_IP in line:
            hits.append({"path": path, "line": str(number), "kind": "metadata-ip", "text": redact_text(line.strip()[:200])})
        if any(word in lowered for word in ("password:", "passwd:", "ssh_authorized_keys", "write_files:", "runcmd:", "bootcmd:")):
            hits.append({"path": path, "line": str(number), "kind": "cloud-init-sensitive", "text": redact_text(line.strip()[:200])})
    return hits


def iter_cloud_files(paths: Iterable[str], max_files: int) -> Iterable[Path]:
    count = 0
    for raw in paths:
        path = Path(raw)
        if path.is_file():
            yield path
            count += 1
        elif path.is_dir():
            for base, dirs, files in os.walk(str(path)):
                dirs[:] = [d for d in dirs if d not in {"obj.pkl"}]
                for name in files:
                    if count >= max_files:
                        return
                    if name.endswith((".cfg", ".txt", ".yml", ".yaml", ".json")) or name in {"user-data.txt", "meta-data.json"}:
                        count += 1
                        yield Path(base) / name
        if count >= max_files:
            return


def parse_routes(text: str) -> List[Dict[str, str]]:
    rows = []
    for line in text.splitlines():
        parts = line.split()
        if parts and parts[0] != "Iface":
            rows.append({"destination": parts[0], "raw": line.strip()})
    return rows


def classify_findings(hits: List[Dict[str, str]], routes: List[Dict[str, str]]) -> List[Dict[str, str]]:
    findings = []
    for hit in hits:
        if hit["kind"] == "cloud-init-sensitive":
            findings.append({"severity": "INFO", "message": f"cloud-init sensitive directive in {hit['path']}:{hit['line']}"})
        elif hit["kind"] == "metadata-ip":
            findings.append({"severity": "INFO", "message": f"metadata IP reference in {hit['path']}:{hit['line']}"})
    if any(METADATA_IP in item.get("raw", "") for item in routes):
        findings.append({"severity": "INFO", "message": "route table references cloud metadata IP"})
    return findings


def collect(paths: Optional[str] = None, max_files: int = 500, state: Optional[str] = None) -> Dict[str, Any]:
    scan_paths = [item.strip() for item in paths.split(",")] if paths else DEFAULT_PATHS
    hits = []
    warnings = []
    for path in iter_cloud_files(scan_paths, max_files):
        try:
            hits.extend(scan_cloud_text(path.read_text(encoding="utf-8", errors="replace"), str(path)))
        except OSError as exc:
            warnings.append(f"{path}: {exc}")
    routes_text = ""
    try:
        routes_text = Path("/proc/net/route").read_text(encoding="utf-8", errors="replace")
    except OSError:
        pass
    routes = parse_routes(routes_text)
    findings = classify_findings(hits, routes)
    return {"tool": "cloudaudit", "state_dir": str(resolve_state_dir(state)), "paths": scan_paths, "hits": hits, "routes": routes, "findings": findings, "overall": overall(findings), "warnings": warnings}


def print_human(report: Dict[str, Any], no_color: bool = False) -> None:
    print("cloudaudit: local cloud-init metadata audit")
    print(f"overall: {marker(report['overall'], no_color)} {report['overall']}")
    print()
    print(format_table(report["hits"][:30], ["path", "line", "kind", "text"]) if report["hits"] else "  no cloud-init hits found")
    print()
    print("Findings")
    print_findings(report["findings"], no_color)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit local cloud-init and cloud metadata posture.")
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
