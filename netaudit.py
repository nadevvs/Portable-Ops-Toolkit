#!/usr/bin/env python3
"""Audit listening ports and active network sessions."""

import argparse
from collections import Counter
from typing import Any, Dict, List, Optional, Sequence

from common.cmd import run_cmd
from common.output import emit_json, format_table
from common.sec import marker, overall, print_findings
from common.state import resolve_state_dir
from common.warnings import command_warning
from svcdep import parse_ss_output


RISKY_PORTS = {
    "21": "FTP",
    "23": "Telnet",
    "111": "rpcbind",
    "445": "SMB",
    "873": "rsync",
    "2049": "NFS",
    "2375": "Docker API",
    "3306": "MySQL",
    "5432": "PostgreSQL",
    "6379": "Redis",
    "9200": "Elasticsearch",
    "11211": "Memcached",
    "27017": "MongoDB",
}


def classify_address(address: str) -> str:
    if address in {"127.0.0.1", "::1", "localhost"}:
        return "loopback"
    if address in {"0.0.0.0", "::", "*"}:
        return "all-interfaces"
    if address.startswith("10.") or address.startswith("192.168.") or address.startswith("172.16."):
        return "private"
    return "specific"


def parse_netstat_like(text: str) -> List[Dict[str, Any]]:
    rows = []
    for item in parse_ss_output(text):
        item["exposure"] = classify_address(str(item.get("address") or ""))
        rows.append(item)
    return rows


def summarize_connections(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    remotes: Counter[str] = Counter()
    listeners = []
    for row in rows:
        if row.get("state") in {"LISTEN", "UNCONN", ""}:
            listeners.append(row)
        elif row.get("state") in {"ESTAB", "ESTABLISHED"}:
            remote = str(row.get("remote") or "")
            if remote:
                remotes[remote.rsplit(":", 1)[0]] += 1
    return {"listeners": listeners, "top_remotes": remotes.most_common(10)}


def classify_findings(listeners: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    findings = []
    for item in listeners:
        port = str(item.get("port") or "")
        exposure = item.get("exposure")
        if exposure == "all-interfaces" and port in RISKY_PORTS:
            findings.append({"severity": "CRITICAL", "message": f"{RISKY_PORTS[port]} port {port} listens on all interfaces"})
        elif exposure == "all-interfaces":
            findings.append({"severity": "INFO", "message": f"port {port} listens on all interfaces"})
    return findings


def collect(state: Optional[str] = None) -> Dict[str, Any]:
    result = run_cmd(["ss", "-tulpna"], timeout=6)
    warning = command_warning("ss -tulpna", result)
    rows = parse_netstat_like(result.stdout) if result.stdout else []
    summary = summarize_connections(rows)
    findings = classify_findings(summary["listeners"])
    return {
        "tool": "netaudit",
        "state_dir": str(resolve_state_dir(state)),
        "listeners": summary["listeners"],
        "top_remotes": summary["top_remotes"],
        "findings": findings,
        "overall": overall(findings),
        "warnings": [warning] if warning else [],
    }


def print_human(report: Dict[str, Any], no_color: bool = False) -> None:
    print("netaudit: network listener and session audit")
    print(f"overall: {marker(report['overall'], no_color)} {report['overall']}")
    print()
    print("Listeners")
    rows = [
        {"proto": x.get("proto"), "local": x.get("local"), "process": x.get("process") or "", "exposure": x.get("exposure")}
        for x in report["listeners"][:30]
    ]
    print(format_table(rows, ["proto", "local", "process", "exposure"]) if rows else "  none")
    print()
    print("Findings")
    print_findings(report["findings"], no_color)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit network listeners without changing firewall or routes.")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--state")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    report = collect(args.state)
    emit_json(report) if args.json else print_human(report, args.no_color)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
