#!/usr/bin/env python3
"""Audit kernel and sysctl security posture."""

import argparse
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from common.output import emit_json, format_table
from common.sec import marker, overall, print_findings
from common.state import resolve_state_dir


SYSCTL_CHECKS = {
    "kernel.randomize_va_space": {"path": "/proc/sys/kernel/randomize_va_space", "expected": {"2"}, "severity": "WARN", "message": "ASLR is not fully enabled"},
    "kernel.kptr_restrict": {"path": "/proc/sys/kernel/kptr_restrict", "expected": {"1", "2"}, "severity": "INFO", "message": "kernel pointer exposure is not restricted"},
    "kernel.dmesg_restrict": {"path": "/proc/sys/kernel/dmesg_restrict", "expected": {"1"}, "severity": "INFO", "message": "unprivileged dmesg is not restricted"},
    "kernel.yama.ptrace_scope": {"path": "/proc/sys/kernel/yama/ptrace_scope", "expected": {"1", "2", "3"}, "severity": "WARN", "message": "ptrace is not restricted"},
    "net.ipv4.conf.all.accept_redirects": {"path": "/proc/sys/net/ipv4/conf/all/accept_redirects", "expected": {"0"}, "severity": "WARN", "message": "IPv4 ICMP redirects are accepted"},
    "net.ipv6.conf.all.accept_redirects": {"path": "/proc/sys/net/ipv6/conf/all/accept_redirects", "expected": {"0"}, "severity": "WARN", "message": "IPv6 ICMP redirects are accepted"},
    "net.ipv4.conf.all.rp_filter": {"path": "/proc/sys/net/ipv4/conf/all/rp_filter", "expected": {"1", "2"}, "severity": "INFO", "message": "reverse path filtering is not enabled"},
}


def read_value(path: str) -> Dict[str, Any]:
    try:
        return {"path": path, "value": Path(path).read_text(encoding="utf-8", errors="replace").strip(), "exists": True}
    except OSError as exc:
        return {"path": path, "value": "", "exists": False, "error": str(exc)}


def parse_modules(text: str) -> List[Dict[str, Any]]:
    modules = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            modules.append({"name": parts[0], "size": int(parts[1]) if parts[1].isdigit() else parts[1], "used_by": parts[3] if len(parts) > 3 else ""})
    return modules


def classify_sysctls(values: Dict[str, Dict[str, Any]], modules: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    findings = []
    for key, check in SYSCTL_CHECKS.items():
        item = values.get(key, {})
        if not item.get("exists"):
            continue
        if item.get("value") not in check["expected"]:
            findings.append({"severity": str(check["severity"]), "message": str(check["message"])})
    risky_modules = {"dccp", "sctp", "rds", "tipc", "usb_storage"}
    loaded = sorted({item["name"] for item in modules} & risky_modules)
    for name in loaded:
        findings.append({"severity": "INFO", "message": f"rare or removable-media kernel module loaded: {name}"})
    return findings


def collect(state: Optional[str] = None) -> Dict[str, Any]:
    values = {key: read_value(str(check["path"])) for key, check in SYSCTL_CHECKS.items()}
    try:
        modules = parse_modules(Path("/proc/modules").read_text(encoding="utf-8", errors="replace"))
    except OSError:
        modules = []
    findings = classify_sysctls(values, modules)
    return {"tool": "kernelguard", "state_dir": str(resolve_state_dir(state)), "sysctls": values, "modules": modules[:200], "findings": findings, "overall": overall(findings), "warnings": []}


def print_human(report: Dict[str, Any], no_color: bool = False) -> None:
    print("kernelguard: kernel and sysctl posture")
    print(f"overall: {marker(report['overall'], no_color)} {report['overall']}")
    rows = [{"key": key, "value": item.get("value", ""), "path": item.get("path", "")} for key, item in report["sysctls"].items()]
    print()
    print(format_table(rows, ["key", "value", "path"]))
    print()
    print("Findings")
    print_findings(report["findings"], no_color)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit kernel and sysctl security posture.")
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
