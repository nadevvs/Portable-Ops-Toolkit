#!/usr/bin/env python3
"""Audit local Docker or Podman container posture."""

import argparse
import json
from typing import Any, Dict, List, Optional, Sequence

from common.cmd import run_cmd
from common.output import emit_json, format_table
from common.sec import marker, overall, print_findings
from common.state import resolve_state_dir
from common.warnings import command_warning


def parse_container_rows(text: str, runtime: str) -> List[Dict[str, Any]]:
    rows = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
            rows.append(
                {
                    "runtime": runtime,
                    "id": item.get("ID") or item.get("Id") or "",
                    "image": item.get("Image", ""),
                    "names": item.get("Names") or item.get("Names", ""),
                    "ports": item.get("Ports", ""),
                    "status": item.get("Status", ""),
                }
            )
        except json.JSONDecodeError:
            parts = line.split("\t")
            if len(parts) >= 5:
                rows.append({"runtime": runtime, "id": parts[0], "image": parts[1], "names": parts[2], "ports": parts[3], "status": parts[4]})
    return rows


def parse_inspect(text: str) -> List[Dict[str, Any]]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    rows = data if isinstance(data, list) else [data]
    parsed = []
    for item in rows:
        host = item.get("HostConfig", {}) if isinstance(item, dict) else {}
        config = item.get("Config", {}) if isinstance(item, dict) else {}
        parsed.append(
            {
                "id": item.get("Id", "")[:12],
                "name": str(item.get("Name", "")).lstrip("/"),
                "privileged": bool(host.get("Privileged")),
                "network_mode": host.get("NetworkMode", ""),
                "pid_mode": host.get("PidMode", ""),
                "user": config.get("User", ""),
                "binds": host.get("Binds") or [],
            }
        )
    return parsed


def classify_findings(containers: List[Dict[str, Any]], inspect_rows: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    findings = []
    for item in containers:
        ports = str(item.get("ports", ""))
        if "0.0.0.0:" in ports or ":::" in ports:
            findings.append({"severity": "WARN", "message": f"{item.get('names') or item.get('id')} publishes a port on all interfaces"})
    for item in inspect_rows:
        name = item.get("name") or item.get("id")
        if item.get("privileged"):
            findings.append({"severity": "CRITICAL", "message": f"{name} runs privileged"})
        if item.get("network_mode") == "host":
            findings.append({"severity": "WARN", "message": f"{name} uses host networking"})
        if item.get("pid_mode") == "host":
            findings.append({"severity": "WARN", "message": f"{name} uses host PID namespace"})
        if item.get("user") in {"", "0", "root"}:
            findings.append({"severity": "INFO", "message": f"{name} appears to run as root/default user"})
        for bind in item.get("binds", []):
            if str(bind).startswith("/:") or str(bind).startswith("/:/"):
                findings.append({"severity": "CRITICAL", "message": f"{name} bind-mounts the host root filesystem"})
    return findings


def collect(state: Optional[str] = None) -> Dict[str, Any]:
    warnings = []
    runtime = ""
    ps_result = None
    for candidate in ("docker", "podman"):
        result = run_cmd([candidate, "ps", "--format", "{{json .}}"], timeout=8)
        if result.stdout:
            runtime = candidate
            ps_result = result
            break
        warning = command_warning(f"{candidate} ps", result)
        if warning and not result.missing:
            warnings.append(warning)
    containers = parse_container_rows(ps_result.stdout, runtime) if ps_result else []
    inspect_rows = []
    if containers and runtime:
        ids = [item["id"] for item in containers if item.get("id")]
        inspected = run_cmd([runtime, "inspect"] + ids[:20], timeout=10)
        warning = command_warning(f"{runtime} inspect", inspected)
        if warning:
            warnings.append(warning)
        inspect_rows = parse_inspect(inspected.stdout) if inspected.stdout else []
    findings = classify_findings(containers, inspect_rows)
    return {
        "tool": "containeraudit",
        "state_dir": str(resolve_state_dir(state)),
        "runtime": runtime or "none",
        "containers": containers,
        "inspect": inspect_rows,
        "findings": findings,
        "overall": overall(findings),
        "warnings": warnings,
    }


def print_human(report: Dict[str, Any], no_color: bool = False) -> None:
    print("containeraudit: local container posture")
    print(f"runtime: {report['runtime']}")
    print(f"overall: {marker(report['overall'], no_color)} {report['overall']}")
    print()
    rows = [{"id": x.get("id"), "image": x.get("image"), "names": x.get("names"), "ports": x.get("ports")} for x in report["containers"]]
    print(format_table(rows, ["id", "image", "names", "ports"]) if rows else "  no running containers found")
    print()
    print("Findings")
    print_findings(report["findings"], no_color)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit local Docker or Podman containers.")
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
