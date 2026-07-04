#!/usr/bin/env python3
"""Audit running processes for common investigation leads."""

import argparse
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from common.cmd import run_cmd
from common.output import emit_json
from common.redact import redact_text
from common.sec import marker, overall, print_findings
from common.state import resolve_state_dir
from common.warnings import command_warning


SUSPICIOUS_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/")
NETWORK_TOOLS = ("curl", "wget", "nc", "ncat", "socat", "telnet")


def parse_ps(text: str) -> List[Dict[str, Any]]:
    rows = []
    for index, line in enumerate(text.splitlines()):
        if index == 0 or not line.strip():
            continue
        parts = line.split(None, 7)
        if len(parts) < 8:
            continue
        pid, ppid, user, comm, cpu, mem, etime, args = parts
        rows.append(
            {
                "pid": int_or_text(pid),
                "ppid": int_or_text(ppid),
                "user": user,
                "comm": comm,
                "cpu": float_or_zero(cpu),
                "mem": float_or_zero(mem),
                "etime": etime,
                "args": redact_text(args),
            }
        )
    return rows


def int_or_text(value: str) -> Any:
    try:
        return int(value)
    except ValueError:
        return value


def float_or_zero(value: str) -> float:
    try:
        return float(value)
    except ValueError:
        return 0.0


def inspect_proc(pid: Any) -> Dict[str, Any]:
    data: Dict[str, Any] = {}
    if not isinstance(pid, int):
        return data
    base = Path("/proc") / str(pid)
    for name in ("exe", "cwd"):
        try:
            data[name] = os.readlink(str(base / name))
        except OSError:
            data[name] = ""
    try:
        status = (base / "status").read_text(encoding="utf-8", errors="replace")
        for line in status.splitlines():
            if line.startswith("Uid:"):
                data["uid_line"] = line
            elif line.startswith("CapEff:"):
                data["cap_eff"] = line.split(":", 1)[1].strip()
    except OSError:
        pass
    return data


def classify_process(proc: Dict[str, Any]) -> List[str]:
    reasons = []
    args = str(proc.get("args", ""))
    comm = str(proc.get("comm", ""))
    exe = str(proc.get("exe", ""))
    cwd = str(proc.get("cwd", ""))
    combined = " ".join([comm, args, exe])
    if any(value.startswith(SUSPICIOUS_DIRS) for value in (exe, cwd)):
        reasons.append("running from temporary or shared-memory path")
    if "(deleted)" in exe or "(deleted)" in args:
        reasons.append("executable appears deleted")
    if re.search(r"\b(base64|openssl)\b.*\b(-d|decode|enc)\b", combined):
        reasons.append("contains decode/decrypt command pattern")
    if re.search(r"\b(sh|bash|python|perl|ruby)\b.*\|\s*(sh|bash)", combined):
        reasons.append("pipes data into a shell")
    if any(tool in combined for tool in NETWORK_TOOLS) and re.search(r"\b(sh|bash|python|perl|ruby)\b", combined):
        reasons.append("network client combined with interpreter or shell")
    if len(args) > 500:
        reasons.append("very long command line")
    return reasons


def collect(deep: bool = False, state: Optional[str] = None) -> Dict[str, Any]:
    result = run_cmd(["ps", "-eo", "pid,ppid,user,comm,%cpu,%mem,etime,args", "--sort=-%cpu"], timeout=6)
    warnings = []
    warning = command_warning("ps", result)
    if warning and not result.missing:
        fallback = run_cmd(["ps", "-eo", "pid,ppid,user,comm,%cpu,%mem,etime,args"], timeout=6)
        if fallback.stdout:
            result = fallback
            warning = None
    if warning:
        warnings.append(warning)
    processes = parse_ps(result.stdout) if result.stdout else []
    inspected = []
    findings = []
    for proc in processes:
        if deep:
            proc.update(inspect_proc(proc.get("pid")))
        reasons = classify_process(proc)
        if reasons:
            finding = {
                "severity": "WARN",
                "pid": proc.get("pid"),
                "comm": proc.get("comm"),
                "message": f"{proc.get('comm')} pid {proc.get('pid')}: {', '.join(reasons)}",
                "reasons": reasons,
            }
            if "executable appears deleted" in reasons or "pipes data into a shell" in reasons:
                finding["severity"] = "CRITICAL"
            findings.append(finding)
        inspected.append(proc)
    return {
        "tool": "procaudit",
        "state_dir": str(resolve_state_dir(state)),
        "process_count": len(inspected),
        "top_cpu": inspected[:10],
        "findings": findings,
        "overall": overall(findings),
        "warnings": warnings,
    }


def print_human(report: Dict[str, Any], no_color: bool = False) -> None:
    print("procaudit: process investigation leads")
    print(f"processes inspected: {report['process_count']}")
    print(f"overall: {marker(report['overall'], no_color)} {report['overall']}")
    print()
    print("Findings")
    print_findings(report["findings"], no_color)
    if report["warnings"]:
        print()
        print("Warnings")
        for item in report["warnings"]:
            print(f"  {item}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit running processes for suspicious local indicators.")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--state")
    parser.add_argument("--deep", action="store_true", help="Read best-effort /proc exe/cwd metadata.")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    report = collect(args.deep, args.state)
    emit_json(report) if args.json else print_human(report, args.no_color)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
