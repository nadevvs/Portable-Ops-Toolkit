#!/usr/bin/env python3
"""Build an offline package inventory and package-change ledger."""

import argparse
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from common.cmd import run_cmd
from common.output import emit_json, format_table
from common.sec import marker, overall, print_findings
from common.state import resolve_state_dir
from common.warnings import command_warning


def parse_dpkg(text: str) -> List[Dict[str, str]]:
    packages = []
    for line in text.splitlines():
        if not line.startswith("ii "):
            continue
        parts = line.split()
        if len(parts) >= 3:
            packages.append({"name": parts[1], "version": parts[2], "source": "dpkg"})
    return packages


def parse_rpm(text: str) -> List[Dict[str, str]]:
    packages = []
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.rsplit("-", 2)
        if len(parts) == 3:
            packages.append({"name": parts[0], "version": "-".join(parts[1:]), "source": "rpm"})
        else:
            packages.append({"name": line.strip(), "version": "", "source": "rpm"})
    return packages


def parse_apk(text: str) -> List[Dict[str, str]]:
    packages = []
    for line in text.splitlines():
        value = line.strip()
        if not value:
            continue
        match = re.match(r"^(.+)-([0-9][A-Za-z0-9._+~-]*(?:-r\d+)?)$", value)
        if match:
            packages.append({"name": match.group(1), "version": match.group(2), "source": "apk"})
        else:
            packages.append({"name": value, "version": "", "source": "apk"})
    return packages


def parse_apt_history(text: str) -> List[Dict[str, str]]:
    events = []
    current_date = ""
    for line in text.splitlines():
        if line.startswith("Start-Date:"):
            current_date = line.split(":", 1)[1].strip()
        elif line.startswith(("Install:", "Upgrade:", "Remove:", "Purge:")):
            action, rest = line.split(":", 1)
            events.append({"date": current_date, "action": action.lower(), "detail": rest.strip()[:300]})
    return events


def collect_package_manager() -> Dict[str, Any]:
    checks = [
        ("dpkg", ["dpkg-query", "-W", "-f=${db:Status-Abbrev} ${binary:Package} ${Version}\n"], parse_dpkg),
        ("rpm", ["rpm", "-qa"], parse_rpm),
        ("apk", ["apk", "info", "-v"], parse_apk),
    ]
    warnings = []
    for name, command, parser in checks:
        result = run_cmd(command, timeout=12)
        warning = command_warning(" ".join(command), result)
        if warning and not result.missing:
            warnings.append(warning)
        packages = parser(result.stdout) if result.stdout else []
        if packages:
            return {"manager": name, "packages": packages, "warnings": warnings}
    return {"manager": "unknown", "packages": [], "warnings": warnings}


def read_change_logs(limit: int) -> List[Dict[str, str]]:
    events = []
    for path in sorted(Path("/var/log/apt").glob("history.log*"))[:3]:
        try:
            events.extend(parse_apt_history(path.read_text(encoding="utf-8", errors="replace")))
        except OSError:
            pass
    return events[-limit:]


def classify_findings(packages: List[Dict[str, str]], events: List[Dict[str, str]]) -> List[Dict[str, str]]:
    findings = []
    names = {pkg["name"] for pkg in packages}
    risky = sorted(names & {"telnet", "rsh-client", "rsh-server", "vsftpd", "ftp", "netcat-traditional"})
    for name in risky:
        findings.append({"severity": "WARN", "message": f"legacy or high-risk network package installed: {name}"})
    for event in events:
        if event.get("action") in {"remove", "purge"} and re.search(r"auditd|ufw|iptables|openssh", event.get("detail", ""), re.I):
            findings.append({"severity": "WARN", "message": f"security-relevant package {event['action']} event: {event['detail'][:120]}"})
    return findings


def collect(limit: int = 30, state: Optional[str] = None) -> Dict[str, Any]:
    inventory = collect_package_manager()
    events = read_change_logs(limit)
    findings = classify_findings(inventory["packages"], events)
    return {
        "tool": "pkgledger",
        "state_dir": str(resolve_state_dir(state)),
        "manager": inventory["manager"],
        "package_count": len(inventory["packages"]),
        "packages": inventory["packages"][:5000],
        "recent_changes": events,
        "findings": findings,
        "overall": overall(findings),
        "warnings": inventory["warnings"],
    }


def print_human(report: Dict[str, Any], no_color: bool = False) -> None:
    print("pkgledger: offline package inventory")
    print(f"manager: {report['manager']}")
    print(f"packages: {report['package_count']}")
    print(f"overall: {marker(report['overall'], no_color)} {report['overall']}")
    print()
    print("Recent package changes")
    rows = report["recent_changes"][-10:]
    print(format_table(rows, ["date", "action", "detail"]) if rows else "  none")
    print()
    print("Findings")
    print_findings(report["findings"], no_color)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Create an offline package inventory and recent package-change ledger.")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--state")
    parser.add_argument("--limit", type=int, default=30, help="Recent package-change events to include.")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    report = collect(args.limit, args.state)
    emit_json(report) if args.json else print_human(report, args.no_color)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
