#!/usr/bin/env python3
"""Run toolkit tools as a local profile and collect JSON reports."""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from common.cmd import run_cmd
from common.output import emit_json, format_table
from common.sec import marker, overall
from common.state import ensure_state_dir, resolve_state_dir


PROFILES = {
    "ops": ["serverdoctor", "svcdep", "croninv", "permdrift", "sshexpose", "blackbox"],
    "dfir": ["procaudit", "netaudit", "logtriage", "iocscan", "persistwatch", "pkgledger", "containeraudit", "evidencetrail"],
    "posture": ["kernelguard", "fireaudit", "suidscan", "auditpol", "accttrail", "mountaudit", "envleak", "certwatch", "webaudit", "cloudaudit"],
}

SKIP_BY_DEFAULT = {"svcdep", "permdrift", "blackbox", "evidencetrail"}


def select_tools(profile: str, tools: Optional[str] = None, include_stateful: bool = False) -> List[str]:
    if tools:
        selected = [item.strip() for item in tools.split(",") if item.strip()]
    elif profile == "all":
        selected = sorted({tool for items in PROFILES.values() for tool in items})
    else:
        selected = list(PROFILES.get(profile, []))
    if not include_stateful:
        selected = [tool for tool in selected if tool not in SKIP_BY_DEFAULT]
    return selected


def run_tool(tool: str, state: Optional[str], timeout: int) -> Dict[str, Any]:
    script = Path(__file__).resolve().parent / f"{tool}.py"
    if not script.exists():
        return {"tool": tool, "error": f"script not found: {script}", "overall": "CRITICAL", "findings": [{"severity": "CRITICAL", "message": "script not found"}], "warnings": []}
    result = run_cmd([sys.executable, str(script), "--json", "--no-color", "--state", str(resolve_state_dir(state))], timeout=timeout)
    report: Dict[str, Any]
    try:
        report = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        report = {}
    if not report:
        report = {"tool": tool, "overall": "CRITICAL", "findings": [{"severity": "CRITICAL", "message": "tool did not return JSON"}], "warnings": []}
    report.setdefault("tool", tool)
    if result.returncode != 0:
        report.setdefault("warnings", []).append(f"exit code {result.returncode}")
    if result.timed_out:
        report.setdefault("warnings", []).append("timed out")
    if result.stderr:
        report.setdefault("stderr", result.stderr.strip().splitlines()[:5])
    return report


def summarize_reports(reports: List[Dict[str, Any]]) -> Dict[str, Any]:
    findings = []
    statuses = []
    for report in reports:
        statuses.append({"tool": report.get("tool", ""), "overall": report.get("overall", "OK"), "findings": len(report.get("findings", [])), "warnings": len(report.get("warnings", []))})
        for finding in report.get("findings", []):
            findings.append({"tool": report.get("tool", ""), **finding})
    return {"tools": statuses, "findings": findings, "overall": overall(findings)}


def bundle_path(state: Optional[str], name: str) -> Path:
    base = ensure_state_dir(state) / "opsrun" / name
    base.mkdir(parents=True, exist_ok=True)
    return base / "bundle.json"


def collect(profile: str, tools: Optional[str], include_stateful: bool, timeout: int, state: Optional[str], save: bool) -> Dict[str, Any]:
    selected = select_tools(profile, tools, include_stateful)
    reports = [run_tool(tool, state, timeout) for tool in selected]
    summary = summarize_reports(reports)
    bundle = {
        "tool": "opsrun",
        "profile": profile,
        "selected_tools": selected,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": summary,
        "reports": reports,
        "overall": summary["overall"],
        "state_dir": str(resolve_state_dir(state)),
    }
    if save:
        name = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        path = bundle_path(state, name)
        path.write_text(json.dumps(bundle, indent=2, sort_keys=True), encoding="utf-8")
        bundle["bundle_path"] = str(path)
    return bundle


def print_human(report: Dict[str, Any], no_color: bool = False) -> None:
    print("opsrun: toolkit profile bundle")
    print(f"profile: {report['profile']}")
    print(f"overall: {marker(report['overall'], no_color)} {report['overall']}")
    if report.get("bundle_path"):
        print(f"saved: {report['bundle_path']}")
    print()
    print(format_table(report["summary"]["tools"], ["tool", "overall", "findings", "warnings"]))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run selected toolkit tools and collect JSON reports.")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--state")
    parser.add_argument("--profile", choices=["ops", "dfir", "posture", "all"], default="posture")
    parser.add_argument("--tools", help="Comma-separated explicit tool names.")
    parser.add_argument("--include-stateful", action="store_true", help="Include tools that usually need subcommands or explicit targets.")
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--save", action="store_true", help="Save bundle under STATE/opsrun/TIMESTAMP/bundle.json.")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    report = collect(args.profile, args.tools, args.include_stateful, args.timeout, args.state, args.save)
    emit_json(report) if args.json else print_human(report, args.no_color)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
