#!/usr/bin/env python3
"""Audit local audit/logging policy posture."""

import argparse
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from common.cmd import run_cmd
from common.output import emit_json, format_table
from common.sec import marker, overall, print_findings
from common.state import resolve_state_dir
from common.warnings import command_warning


WATCH_KEYWORDS = ("execve", "chmod", "chown", "setxattr", "openat", "unlink", "mount", "modules")


def parse_audit_rules(text: str) -> Dict[str, Any]:
    watches = []
    syscalls = []
    immutable = False
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped == "-e 2":
            immutable = True
        if stripped.startswith("-w "):
            watches.append(stripped)
        if "-S " in stripped:
            syscalls.append(stripped)
    return {"watches": watches, "syscalls": syscalls, "immutable": immutable}


def parse_auditd_conf(text: str) -> Dict[str, str]:
    parsed = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        parsed[key.strip()] = value.strip()
    return parsed


def classify_findings(status: str, rules: Dict[str, Any], conf: Dict[str, str]) -> List[Dict[str, str]]:
    findings = []
    if "enabled 0" in status.lower() or not status.strip():
        findings.append({"severity": "WARN", "message": "audit status is unavailable or disabled"})
    covered = "\n".join(rules.get("watches", []) + rules.get("syscalls", [])).lower()
    for keyword in WATCH_KEYWORDS:
        if keyword not in covered:
            findings.append({"severity": "INFO", "message": f"audit rules do not mention {keyword}"})
    if conf.get("max_log_file_action", "").lower() in {"ignore", "suspend"}:
        findings.append({"severity": "WARN", "message": f"audit log full action is {conf.get('max_log_file_action')}"})
    if not rules.get("immutable"):
        findings.append({"severity": "INFO", "message": "audit rules are not immutable (-e 2 not found)"})
    return findings


def collect(state: Optional[str] = None) -> Dict[str, Any]:
    warnings = []
    status = run_cmd(["auditctl", "-s"], timeout=5)
    rules_cmd = run_cmd(["auditctl", "-l"], timeout=5)
    for label, result in (("auditctl -s", status), ("auditctl -l", rules_cmd)):
        warning = command_warning(label, result)
        if warning and not result.missing:
            warnings.append(warning)
    rules_text = rules_cmd.stdout
    if not rules_text:
        chunks = []
        for path in (Path("/etc/audit/audit.rules"), Path("/etc/audit/rules.d/audit.rules")):
            try:
                chunks.append(path.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                pass
        rules_text = "\n".join(chunks)
    try:
        conf_text = Path("/etc/audit/auditd.conf").read_text(encoding="utf-8", errors="replace")
    except OSError:
        conf_text = ""
    rules = parse_audit_rules(rules_text)
    conf = parse_auditd_conf(conf_text)
    findings = classify_findings(status.stdout, rules, conf)
    return {"tool": "auditpol", "state_dir": str(resolve_state_dir(state)), "status": status.stdout.strip(), "rules": rules, "config": conf, "findings": findings, "overall": overall(findings), "warnings": warnings}


def print_human(report: Dict[str, Any], no_color: bool = False) -> None:
    print("auditpol: audit policy posture")
    print(f"overall: {marker(report['overall'], no_color)} {report['overall']}")
    rows = [{"kind": "watch", "count": len(report["rules"].get("watches", []))}, {"kind": "syscall", "count": len(report["rules"].get("syscalls", []))}]
    print()
    print(format_table(rows, ["kind", "count"]))
    print()
    print("Findings")
    print_findings(report["findings"], no_color)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit local auditd/auditctl posture.")
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
