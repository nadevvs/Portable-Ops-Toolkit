#!/usr/bin/env python3
"""Audit local firewall posture without changing rules."""

import argparse
import re
from typing import Any, Dict, List, Optional, Sequence

from common.cmd import run_cmd
from common.output import emit_json
from common.sec import marker, overall, print_findings
from common.state import resolve_state_dir
from common.warnings import command_warning


def parse_ufw_status(text: str) -> Dict[str, Any]:
    enabled = "Status: active" in text
    inactive = "Status: inactive" in text
    rules = []
    for line in text.splitlines():
        if " ALLOW " in line or " DENY " in line or " REJECT " in line:
            rules.append(line.strip())
    return {"enabled": enabled, "inactive": inactive, "rules": rules}


def parse_iptables_policy(text: str) -> List[Dict[str, str]]:
    policies = []
    for line in text.splitlines():
        match = re.match(r"Chain\s+(\S+)\s+\(policy\s+([^) \t]+)", line)
        if match:
            policies.append({"chain": match.group(1), "policy": match.group(2)})
    return policies


def classify_findings(ufw: Dict[str, Any], iptables: List[Dict[str, str]], nft_text: str) -> List[Dict[str, str]]:
    findings = []
    if ufw.get("inactive") and not iptables and not nft_text.strip():
        findings.append({"severity": "WARN", "message": "no active firewall rules detected by ufw, iptables, or nft"})
    for item in iptables:
        if item["chain"] == "INPUT" and item["policy"] == "ACCEPT":
            findings.append({"severity": "INFO", "message": "iptables INPUT default policy is ACCEPT"})
    if re.search(r"dport\s+(23|6379|2375|9200)\b.*accept", nft_text, re.I):
        findings.append({"severity": "WARN", "message": "nftables appears to accept a high-risk service port"})
    return findings


def collect(state: Optional[str] = None) -> Dict[str, Any]:
    warnings = []
    ufw_result = run_cmd(["ufw", "status", "verbose"], timeout=5)
    ipt_result = run_cmd(["iptables", "-L", "-n"], timeout=5)
    nft_result = run_cmd(["nft", "list", "ruleset"], timeout=5)
    for label, result in (("ufw status", ufw_result), ("iptables -L", ipt_result), ("nft list ruleset", nft_result)):
        warning = command_warning(label, result)
        if warning and not result.missing:
            warnings.append(warning)
    if ufw_result.missing and ipt_result.missing and nft_result.missing:
        warnings.append("no supported firewall command available")
    ufw = parse_ufw_status(ufw_result.stdout)
    iptables = parse_iptables_policy(ipt_result.stdout)
    findings = classify_findings(ufw, iptables, nft_result.stdout)
    return {"tool": "fireaudit", "state_dir": str(resolve_state_dir(state)), "ufw": ufw, "iptables_policies": iptables, "nft_present": bool(nft_result.stdout.strip()), "findings": findings, "overall": overall(findings), "warnings": warnings}


def print_human(report: Dict[str, Any], no_color: bool = False) -> None:
    print("fireaudit: firewall posture")
    print(f"overall: {marker(report['overall'], no_color)} {report['overall']}")
    print(f"ufw enabled: {report['ufw'].get('enabled')}")
    print(f"iptables policies: {len(report['iptables_policies'])}")
    print(f"nft ruleset present: {report['nft_present']}")
    print()
    print("Findings")
    print_findings(report["findings"], no_color)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit local firewall posture without changing rules.")
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
