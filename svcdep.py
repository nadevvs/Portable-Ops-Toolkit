#!/usr/bin/env python3
"""Diagnose one systemd service without changing the host."""

import argparse
import json
import os
import pwd
import re
import stat
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from common.cmd import run_cmd
from common.output import bad, emit_json, info, ok, warn
from common.redact import redact_data, redact_text
from common.state import resolve_state_dir
from common.warnings import command_warning


SHOW_FIELDS = [
    "Id",
    "LoadState",
    "ActiveState",
    "SubState",
    "UnitFileState",
    "MainPID",
    "ExecMainPID",
    "ExecMainStatus",
    "Restart",
    "NRestarts",
    "FragmentPath",
    "DropInPaths",
    "Description",
    "After",
    "Before",
    "Requires",
    "Wants",
]

NOTABLE_PATTERNS = [
    "failed",
    "error",
    "denied",
    "refused",
    "timeout",
    "killed",
    "oom",
    "permission",
    "traceback",
    "exception",
]

DEEP_DIRECTIVES = {
    "ExecStart",
    "User",
    "Group",
    "EnvironmentFile",
    "WorkingDirectory",
    "Restart",
}


def normalize_service_name(name: str) -> str:
    if "." in name:
        return name
    return f"{name}.service"


def parse_systemctl_show(text: str) -> Dict[str, str]:
    parsed: Dict[str, str] = {}
    for raw_line in text.splitlines():
        if "=" not in raw_line:
            continue
        key, value = raw_line.split("=", 1)
        if key in SHOW_FIELDS:
            parsed[key] = value
    return parsed


def split_units(value: str) -> List[str]:
    return [item for item in value.split() if item]


def parse_pid(value: Optional[str]) -> Optional[int]:
    if not value:
        return None
    try:
        pid = int(value)
    except ValueError:
        return None
    return pid if pid > 0 else None


def parse_ps_output(text: str) -> List[Dict[str, Any]]:
    processes: List[Dict[str, Any]] = []
    for index, raw_line in enumerate(text.splitlines()):
        line = raw_line.strip()
        if not line:
            continue
        if index == 0 and line.upper().startswith("PID "):
            continue
        parts = line.split(None, 4)
        if len(parts) < 5:
            continue
        pid, ppid, user, comm, args = parts
        try:
            parsed_pid = int(pid)
            parsed_ppid = int(ppid)
        except ValueError:
            continue
        processes.append(
            {
                "pid": parsed_pid,
                "ppid": parsed_ppid,
                "user": user,
                "comm": comm,
                "args": redact_text(args),
            }
        )
    return processes


def parse_ss_output(text: str) -> List[Dict[str, Any]]:
    ports: List[Dict[str, Any]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("Netid ") or line.startswith("State "):
            continue
        parts = line.split()
        if len(parts) < 5:
            continue

        proto = parts[0].lower()
        if proto not in {"tcp", "udp", "tcp6", "udp6"}:
            continue

        state = ""
        local_index = 4
        if len(parts) > 1:
            state = parts[1]

        if len(parts) <= local_index:
            continue

        local_address = parts[local_index]
        process_text = " ".join(parts[local_index + 2 :])
        process = None
        pid = None

        match = re.search(r'users:\(\("([^"]+)",pid=(\d+)', process_text)
        if match:
            process = match.group(1)
            pid = int(match.group(2))

        address, port = split_address_port(local_address)
        ports.append(
            {
                "proto": proto,
                "state": state,
                "local": local_address,
                "address": address,
                "port": port,
                "process": process,
                "pid": pid,
            }
        )
    return ports


def split_address_port(value: str) -> Sequence[Optional[str]]:
    if value.startswith("[") and "]:" in value:
        address, port = value.rsplit("]:", 1)
        return address.lstrip("["), port
    if ":" in value:
        address, port = value.rsplit(":", 1)
        return address, port
    return value, None


def extract_notable_logs(lines: Iterable[str]) -> List[Dict[str, str]]:
    notable = []
    for line in lines:
        lowered = line.lower()
        matched = next((word for word in NOTABLE_PATTERNS if word in lowered), None)
        if matched:
            notable.append({"level": "WARN", "match": matched, "line": redact_text(line)})
    return notable


def read_proc_process(pid: int) -> Dict[str, Any]:
    base = Path("/proc") / str(pid)
    data: Dict[str, Any] = {"pid": pid}
    try:
        status = base.joinpath("status").read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        data["warning"] = str(exc)
        return data

    uid = None
    for line in status.splitlines():
        if line.startswith("Name:"):
            data["name"] = line.split(":", 1)[1].strip()
        elif line.startswith("Uid:"):
            parts = line.split()
            if len(parts) > 1:
                try:
                    uid = int(parts[1])
                except ValueError:
                    uid = None
        elif line.startswith("VmRSS:"):
            data["rss"] = line.split(":", 1)[1].strip()

    if uid is not None:
        try:
            data["user"] = pwd.getpwuid(uid).pw_name
        except KeyError:
            data["user"] = str(uid)

    try:
        raw_cmd = base.joinpath("cmdline").read_bytes()
        data["command"] = redact_text(raw_cmd.replace(b"\x00", b" ").decode("utf-8", "replace").strip())
    except OSError:
        data["command"] = ""

    for key, path in (("exe", base / "exe"), ("cwd", base / "cwd")):
        try:
            data[key] = str(path.resolve())
        except OSError:
            data[key] = None

    return data


def collect_child_processes(main_pid: Optional[int]) -> List[Dict[str, Any]]:
    if main_pid is None:
        return []
    result = run_cmd(["ps", "-eo", "pid,ppid,user,comm,args"], timeout=5)
    if not result.ok:
        return []

    processes = parse_ps_output(result.stdout)
    by_parent: Dict[int, List[Dict[str, Any]]] = {}
    for process in processes:
        by_parent.setdefault(process["ppid"], []).append(process)

    collected: List[Dict[str, Any]] = []
    stack = list(by_parent.get(main_pid, []))
    seen = {main_pid}
    while stack:
        process = stack.pop(0)
        pid = process["pid"]
        if pid in seen:
            continue
        seen.add(pid)
        collected.append(process)
        stack.extend(by_parent.get(pid, []))
    return collected


def filter_ports(
    ports: Iterable[Dict[str, Any]],
    service_name: str,
    main_pid: Optional[int],
    processes: Iterable[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    pids = {process.get("pid") for process in processes}
    if main_pid is not None:
        pids.add(main_pid)
    name_hint = service_name.split(".", 1)[0].split("@", 1)[0]

    matched = []
    for port in ports:
        process_name = port.get("process") or ""
        if port.get("pid") in pids or (name_hint and name_hint in process_name):
            matched.append(port)
    return matched


def file_metadata(path_text: str) -> Dict[str, Any]:
    path = Path(path_text)
    result: Dict[str, Any] = {"path": path_text, "exists": path.exists()}
    if not path.exists():
        return result
    try:
        st = path.stat()
    except OSError as exc:
        result["error"] = str(exc)
        return result
    result["mode"] = oct(stat.S_IMODE(st.st_mode))[2:]
    result["owner_uid"] = st.st_uid
    result["mtime"] = datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds")
    try:
        result["owner"] = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        result["owner"] = str(st.st_uid)
    return result


def parse_dropin_paths(value: str) -> List[str]:
    if not value:
        return []
    return [item for item in value.split() if item]


def read_deep_directives(paths: Iterable[str]) -> Dict[str, List[Dict[str, str]]]:
    found: Dict[str, List[Dict[str, str]]] = {}
    for path_text in paths:
        path = Path(path_text)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            if key in DEEP_DIRECTIVES:
                found.setdefault(key, []).append({"path": path_text, "value": redact_text(value)})
    return found


def check_dependencies(units: Iterable[str]) -> List[Dict[str, str]]:
    results = []
    for unit in list(units)[:20]:
        active = run_cmd(["systemctl", "is-active", unit], timeout=3)
        enabled = run_cmd(["systemctl", "is-enabled", unit], timeout=3)
        results.append(
            {
                "unit": unit,
                "active": active.stdout.strip() if active.stdout.strip() else "unknown",
                "enabled": enabled.stdout.strip() if enabled.stdout.strip() else "unknown",
            }
        )
    return results


def collect_service(service_arg: str, logs: int, deep: bool, state: Optional[str]) -> Dict[str, Any]:
    service = normalize_service_name(service_arg)
    warnings: List[str] = []
    state_dir = resolve_state_dir(state)

    show_result = run_cmd(["systemctl", "show", service, "--no-pager"], timeout=5)
    show_warning = command_warning("systemctl show", show_result)
    if show_warning:
        warnings.append(show_warning)
    status = parse_systemctl_show(show_result.stdout) if show_result.stdout else {}

    status_result = run_cmd(["systemctl", "status", service, "--no-pager"], timeout=5)
    status_warning = command_warning("systemctl status", status_result)
    if status_warning and not status_warning.startswith("systemctl status: command failed with exit 3"):
        warnings.append(status_warning)

    main_pid = parse_pid(status.get("MainPID")) or parse_pid(status.get("ExecMainPID"))
    processes = []
    if main_pid is not None:
        main_process = read_proc_process(main_pid)
        processes.append(main_process)
    processes.extend(collect_child_processes(main_pid))

    ss_result = run_cmd(["ss", "-tulpn"], timeout=5)
    ss_warning = command_warning("ss", ss_result)
    if ss_warning:
        warnings.append(ss_warning)
    all_ports = parse_ss_output(ss_result.stdout) if ss_result.stdout else []
    ports = filter_ports(all_ports, service, main_pid, processes)
    if ss_result.returncode != 0 and ss_result.stderr:
        warnings.append("ss may require higher permissions to show process names")

    journal_result = run_cmd(["journalctl", "-u", service, "-n", str(logs), "--no-pager"], timeout=8)
    journal_warning = command_warning("journalctl", journal_result)
    if journal_warning:
        warnings.append(journal_warning)
    log_lines = journal_result.stdout.splitlines() if journal_result.stdout else []
    notable_logs = extract_notable_logs(log_lines)

    requires = split_units(status.get("Requires", ""))
    wants = split_units(status.get("Wants", ""))
    dependencies = {
        "requires": requires,
        "wants": wants,
        "after": split_units(status.get("After", "")),
        "before": split_units(status.get("Before", "")),
        "checked": check_dependencies(requires + wants) if show_result.ok else [],
    }

    unit_paths = []
    fragment_path = status.get("FragmentPath", "")
    if fragment_path:
        unit_paths.append(fragment_path)
    unit_paths.extend(parse_dropin_paths(status.get("DropInPaths", "")))
    unit_files = [file_metadata(path) for path in unit_paths]

    if status.get("LoadState") == "not-found":
        warnings.append(f"{service}: service not found")

    report: Dict[str, Any] = {
        "service": status.get("Id") or service,
        "state_dir": str(state_dir),
        "status": status,
        "processes": processes,
        "ports": ports,
        "unit_files": unit_files,
        "dependencies": dependencies,
        "logs": notable_logs,
        "warnings": dedupe(warnings),
    }

    if deep:
        report["deep"] = {"unit_directives": read_deep_directives(unit_paths)}

    return redact_data(report)


def dedupe(values: Iterable[str]) -> List[str]:
    seen = set()
    result = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def print_human(report: Dict[str, Any], no_color: bool = False) -> None:
    status = report["status"]
    print(f"svcdep: {report['service']}")
    print()
    print("Status")
    print(f"  State: {format_state(status, no_color)}")
    print(f"  Enabled: {status.get('UnitFileState') or 'unknown'}")
    print(f"  PID: {status.get('MainPID') or status.get('ExecMainPID') or 'unknown'}")
    print(f"  Restarts: {status.get('NRestarts') or 'unknown'}")
    if status.get("Description"):
        print(f"  Description: {status['Description']}")

    print()
    print("Processes")
    if report["processes"]:
        for process in report["processes"]:
            print(format_process(process))
    else:
        print("  none found")

    print()
    print("Listening ports")
    if report["ports"]:
        for port in report["ports"]:
            process = f" pid={port['pid']} {port['process']}" if port.get("pid") else ""
            print(f"  {port['proto']} {port['local']}{process}")
    else:
        print("  none matched")

    print()
    print("Unit files")
    if report["unit_files"]:
        for unit in report["unit_files"]:
            if unit.get("exists"):
                print(f"  {unit['path']} owner={unit.get('owner')} mode={unit.get('mode')}")
            else:
                print(f"  {unit['path']} missing")
    else:
        print("  none reported")

    print()
    print("Dependencies")
    dependencies = report["dependencies"]
    print(f"  Requires: {', '.join(dependencies['requires']) or 'none'}")
    print(f"  Wants: {', '.join(dependencies['wants']) or 'none'}")
    checked = dependencies.get("checked") or []
    for dependency in checked[:10]:
        print(
            "  "
            f"{dependency['unit']}: active={dependency['active']} "
            f"enabled={dependency['enabled']}"
        )

    print()
    print("Recent notable logs")
    if report["logs"]:
        for entry in report["logs"][:20]:
            print(f"  {warn('[WARN]', no_color)} {entry['line']}")
    else:
        print("  none found")

    if report.get("deep"):
        print()
        print("Deep unit directives")
        directives = report["deep"].get("unit_directives", {})
        if directives:
            for key, entries in directives.items():
                for entry in entries:
                    print(f"  {key}={entry['value']} ({entry['path']})")
        else:
            print("  none readable")

    if report["warnings"]:
        print()
        print("Warnings")
        for warning in report["warnings"]:
            print(f"  {warn('[WARN]', no_color)} {warning}")


def format_state(status: Dict[str, str], no_color: bool = False) -> str:
    active = status.get("ActiveState") or "unknown"
    sub = status.get("SubState") or "unknown"
    value = f"{active}/{sub}"
    if active == "active":
        return ok(value, no_color)
    if active in {"failed", "inactive"}:
        return bad(value, no_color)
    return info(value, no_color)


def format_process(process: Dict[str, Any]) -> str:
    pid = process.get("pid", "?")
    user = process.get("user", "?")
    command = process.get("command") or process.get("args") or process.get("name") or process.get("comm") or ""
    rss = f" rss={process['rss']}" if process.get("rss") else ""
    return f"  {pid} {user} {command}{rss}"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Diagnose one systemd service and related local evidence."
    )
    parser.add_argument("service", help="service name, for example nginx or ssh.service")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI color")
    parser.add_argument("--state", help="state directory path", default=None)
    parser.add_argument("--logs", type=int, default=30, help="recent journal lines to inspect")
    parser.add_argument("--deep", action="store_true", help="read extra unit directives when possible")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    report = collect_service(args.service, args.logs, args.deep, args.state)
    if args.json:
        emit_json(report)
    else:
        print_human(report, args.no_color)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
