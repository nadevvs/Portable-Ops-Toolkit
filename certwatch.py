#!/usr/bin/env python3
"""Inventory local X.509 certificates and expiration windows."""

import argparse
import ssl
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from common.output import emit_json, format_table
from common.sec import marker, overall, print_findings
from common.state import resolve_state_dir


DEFAULT_PATHS = ["/etc/ssl/certs", "/etc/pki/tls/certs", "/etc/letsencrypt/live"]


def parse_cert_date(value: str) -> Optional[datetime]:
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return None


def decode_cert(path: Path) -> Dict[str, Any]:
    data: Dict[str, Any] = {"path": str(path)}
    try:
        decoded = ssl._ssl._test_decode_cert(str(path))  # type: ignore[attr-defined]
    except Exception as exc:
        data["error"] = str(exc)
        return data
    data["subject"] = decoded.get("subject", [])
    data["issuer"] = decoded.get("issuer", [])
    data["not_before"] = decoded.get("notBefore", "")
    data["not_after"] = decoded.get("notAfter", "")
    expires = parse_cert_date(data["not_after"])
    if expires:
        data["days_remaining"] = int((expires - datetime.now(timezone.utc)).total_seconds() // 86400)
    return data


def iter_cert_files(paths: Iterable[str], max_files: int) -> Iterable[Path]:
    count = 0
    for raw in paths:
        path = Path(raw)
        if path.is_file():
            yield path
            count += 1
        elif path.is_dir():
            for child in path.rglob("*"):
                if count >= max_files:
                    return
                if child.is_file() and child.suffix.lower() in {".crt", ".pem", ".cer"}:
                    count += 1
                    yield child
        if count >= max_files:
            return


def classify_findings(certs: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    findings = []
    for cert in certs:
        days = cert.get("days_remaining")
        if days is None:
            continue
        if days < 0:
            findings.append({"severity": "CRITICAL", "message": f"certificate expired: {cert['path']}"})
        elif days <= 14:
            findings.append({"severity": "WARN", "message": f"certificate expires in {days} days: {cert['path']}"})
        elif days <= 30:
            findings.append({"severity": "INFO", "message": f"certificate expires in {days} days: {cert['path']}"})
    return findings


def collect(paths: Optional[str] = None, max_files: int = 1000, state: Optional[str] = None) -> Dict[str, Any]:
    scan_paths = [item.strip() for item in paths.split(",")] if paths else DEFAULT_PATHS
    certs = [decode_cert(path) for path in iter_cert_files(scan_paths, max_files)]
    findings = classify_findings(certs)
    return {"tool": "certwatch", "state_dir": str(resolve_state_dir(state)), "paths": scan_paths, "certificates": certs, "findings": findings, "overall": overall(findings), "warnings": []}


def print_human(report: Dict[str, Any], no_color: bool = False) -> None:
    print("certwatch: local certificate expiry inventory")
    print(f"overall: {marker(report['overall'], no_color)} {report['overall']}")
    rows = [{"path": x.get("path"), "days": x.get("days_remaining", ""), "not_after": x.get("not_after", "")} for x in report["certificates"][:40]]
    print()
    print(format_table(rows, ["path", "days", "not_after"]) if rows else "  no certificates decoded")
    print()
    print("Findings")
    print_findings(report["findings"], no_color)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Inventory local X.509 certificate expiration.")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--state")
    parser.add_argument("--paths", help="Comma-separated files/directories.")
    parser.add_argument("--max-files", type=int, default=1000)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    report = collect(args.paths, args.max_files, args.state)
    emit_json(report) if args.json else print_human(report, args.no_color)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
