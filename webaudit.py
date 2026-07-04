#!/usr/bin/env python3
"""Audit local nginx/apache configuration for exposure leads."""

import argparse
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from common.output import emit_json, format_table
from common.sec import marker, overall, print_findings
from common.state import resolve_state_dir


DEFAULT_PATHS = ["/etc/nginx", "/etc/apache2", "/etc/httpd"]


def parse_web_config(text: str, path: str = "") -> List[Dict[str, str]]:
    directives = []
    for number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        cleaned = line.rstrip(";")
        match = re.match(r"([A-Za-z_][A-Za-z0-9_]*)\s+(.+)", cleaned)
        if match:
            directives.append({"path": path, "line": str(number), "key": match.group(1).lower(), "value": match.group(2).strip()})
    return directives


def iter_config_files(paths: Iterable[str], max_files: int) -> Iterable[Path]:
    count = 0
    for raw in paths:
        path = Path(raw)
        if path.is_file():
            yield path
            count += 1
        elif path.is_dir():
            for base, dirs, files in os.walk(str(path)):
                dirs[:] = [d for d in dirs if d not in {".git", "cache"}]
                for name in files:
                    if count >= max_files:
                        return
                    if name.endswith((".conf", ".vhost")) or name in {"apache2.conf", "httpd.conf", "nginx.conf"}:
                        count += 1
                        yield Path(base) / name
        if count >= max_files:
            return


def classify_findings(directives: List[Dict[str, str]]) -> List[Dict[str, str]]:
    findings = []
    for item in directives:
        key = item["key"]
        value = item["value"].lower()
        location = f"{item['path']}:{item['line']}"
        if key == "autoindex" and value.startswith("on"):
            findings.append({"severity": "WARN", "message": f"directory listing enabled at {location}"})
        if key == "options" and "indexes" in value and "-indexes" not in value:
            findings.append({"severity": "WARN", "message": f"Apache Indexes option enabled at {location}"})
        if key == "ssl_protocols" and ("sslv3" in value or "tlsv1 " in f"{value} " or "tlsv1.1" in value):
            findings.append({"severity": "WARN", "message": f"legacy TLS protocol enabled at {location}"})
        if key in {"server_tokens", "servertokens"} and value in {"on", "full", "prod"}:
            findings.append({"severity": "INFO", "message": f"server version/banner exposure configured at {location}"})
        if key == "access_log" and value.startswith("off"):
            findings.append({"severity": "INFO", "message": f"access logging disabled at {location}"})
        if key == "listen" and ("0.0.0.0" in value or value.startswith("80") or value.startswith("443")):
            findings.append({"severity": "INFO", "message": f"web listener configured at {location}: {item['value']}"})
    return findings


def collect(paths: Optional[str] = None, max_files: int = 500, state: Optional[str] = None) -> Dict[str, Any]:
    scan_paths = [item.strip() for item in paths.split(",")] if paths else DEFAULT_PATHS
    directives = []
    warnings = []
    for path in iter_config_files(scan_paths, max_files):
        try:
            directives.extend(parse_web_config(path.read_text(encoding="utf-8", errors="replace"), str(path)))
        except OSError as exc:
            warnings.append(f"{path}: {exc}")
    findings = classify_findings(directives)
    return {"tool": "webaudit", "state_dir": str(resolve_state_dir(state)), "paths": scan_paths, "directives": directives[:5000], "findings": findings, "overall": overall(findings), "warnings": warnings}


def print_human(report: Dict[str, Any], no_color: bool = False) -> None:
    print("webaudit: local web server config audit")
    print(f"overall: {marker(report['overall'], no_color)} {report['overall']}")
    rows = [item for item in report["directives"] if item["key"] in {"listen", "server_name", "servername", "root", "documentroot"}][:30]
    print()
    print(format_table(rows, ["path", "line", "key", "value"]) if rows else "  no web directives parsed")
    print()
    print("Findings")
    print_findings(report["findings"], no_color)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit local nginx/apache configuration.")
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
