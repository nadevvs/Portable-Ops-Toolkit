#!/usr/bin/env python3
"""Inventory cron jobs and systemd timers."""

import argparse
import os
import pwd
import stat
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from common.cmd import run_cmd
from common.output import emit_json, warn
from common.state import resolve_state_dir
from common.systemd import parse_systemd_timers
from common.warnings import command_warning


SPECIAL_SCHEDULES = {
    "@reboot",
    "@daily",
    "@hourly",
    "@weekly",
    "@monthly",
    "@yearly",
    "@annually",
}


def parse_crontab(text: str, source: str, has_user_field: bool = True) -> List[Dict[str, str]]:
    jobs = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or is_env_assignment(line):
            continue
        parts = line.split()
        if not parts:
            continue
        if parts[0] in SPECIAL_SCHEDULES:
            needed = 3 if has_user_field else 2
            if len(parts) < needed:
                continue
            schedule = parts[0]
            user = parts[1] if has_user_field else ""
            command = " ".join(parts[2 if has_user_field else 1 :])
        else:
            needed = 7 if has_user_field else 6
            if len(parts) < needed:
                continue
            schedule = " ".join(parts[:5])
            user = parts[5] if has_user_field else ""
            command = " ".join(parts[6 if has_user_field else 5 :])
        jobs.append({"schedule": schedule, "user": user, "command": command, "source": source})
    return jobs


def is_env_assignment(line: str) -> bool:
    key, sep, _ = line.partition("=")
    return bool(sep and key.replace("_", "").isalnum() and " " not in key)


def parse_unit_files(text: str) -> Dict[str, str]:
    states = {}
    for raw_line in text.splitlines():
        parts = raw_line.split()
        if len(parts) >= 2 and parts[0].endswith(".timer"):
            states[parts[0]] = parts[1]
    return states


def check_suspicious(job: Dict[str, str]) -> List[str]:
    command = job.get("command", "")
    lowered = command.lower()
    reasons = []
    if any(path in lowered for path in ("/tmp/", "/var/tmp/", "/dev/shm/")):
        reasons.append("runs from a world-writable location")
    if ("curl" in lowered or "wget" in lowered) and "| sh" in lowered:
        reasons.append("pipes downloaded content to shell")
    if "base64" in lowered and ("-d" in lowered or "--decode" in lowered):
        reasons.append("uses base64 decoding")
    if job.get("user") == "root" and "/home/" in lowered:
        reasons.append("root job executes from a user home directory")
    if ">/dev/null 2>&1" in lowered or "> /dev/null 2>&1" in lowered:
        reasons.append("hides all output")
    if any(f" {tool} " in f" {lowered} " for tool in ("nc", "ncat", "socat")):
        reasons.append("uses an unusual network tool")
    return reasons


def file_metadata(path: Path, period: str = "") -> Dict[str, Any]:
    try:
        st = path.stat()
    except OSError as exc:
        return {"path": str(path), "period": period, "error": str(exc)}
    try:
        owner = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        owner = str(st.st_uid)
    return {
        "period": period,
        "path": str(path),
        "owner": owner,
        "mode": oct(stat.S_IMODE(st.st_mode))[2:],
        "modified": datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds"),
        "executable": os.access(path, os.X_OK),
    }


def read_file(path: Path, errors: List[str]) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        errors.append(f"{path}: {exc}")
        return ""


def collect(include_users: bool = False, suspicious_only: bool = False, state: Optional[str] = None) -> Dict[str, Any]:
    errors: List[str] = []
    cron_jobs: List[Dict[str, str]] = []
    periodic_jobs: List[Dict[str, Any]] = []
    warnings: List[Dict[str, str]] = []

    etc_crontab = Path("/etc/crontab")
    if etc_crontab.exists():
        cron_jobs.extend(parse_crontab(read_file(etc_crontab, errors), str(etc_crontab), True))

    cron_d = Path("/etc/cron.d")
    if cron_d.exists():
        for path in sorted(cron_d.iterdir()):
            if path.is_file():
                cron_jobs.extend(parse_crontab(read_file(path, errors), str(path), True))

    for period in ("hourly", "daily", "weekly", "monthly"):
        directory = Path(f"/etc/cron.{period}")
        if directory.exists():
            for path in sorted(directory.iterdir()):
                if path.name.startswith("."):
                    continue
                periodic_jobs.append(file_metadata(path, period))

    if include_users:
        result = run_cmd(["crontab", "-l"], timeout=5)
        if result.ok:
            cron_jobs.extend(parse_crontab(result.stdout, "current-user crontab", False))
        else:
            errors.append("current-user crontab not readable or crontab command missing")

    timer_result = run_cmd(["systemctl", "list-timers", "--all", "--no-pager", "--no-legend"], timeout=5)
    timer_warning = command_warning("systemctl list-timers", timer_result)
    if timer_warning:
        errors.append(timer_warning)
    timers = parse_systemd_timers(timer_result.stdout) if timer_result.stdout else []
    unit_result = run_cmd(["systemctl", "list-unit-files", "--type=timer", "--no-pager"], timeout=5)
    unit_warning = command_warning("systemctl list-unit-files", unit_result)
    if unit_warning:
        errors.append(unit_warning)
    states = parse_unit_files(unit_result.stdout) if unit_result.stdout else {}
    for timer in timers:
        timer["state"] = states.get(timer["unit"], "unknown")

    for job in cron_jobs:
        for reason in check_suspicious(job):
            warnings.append({"source": job["source"], "command": job["command"], "reason": reason})

    if suspicious_only:
        suspicious_commands = {warning["command"] for warning in warnings}
        cron_jobs = [job for job in cron_jobs if job["command"] in suspicious_commands]

    return {
        "state_dir": str(resolve_state_dir(state)),
        "cron_jobs": cron_jobs,
        "periodic_jobs": periodic_jobs,
        "systemd_timers": timers,
        "warnings": warnings,
        "errors": errors,
    }


def print_human(report: Dict[str, Any], no_color: bool = False) -> None:
    print("croninv: scheduled job inventory")
    print()
    print("Cron jobs")
    for job in report["cron_jobs"] or []:
        user = f" {job['user']}" if job.get("user") else ""
        print(f"  {job['source']}: {job['schedule']}{user} {job['command']}")
    if not report["cron_jobs"]:
        print("  none found")
    print()
    print("Periodic directories")
    for job in report["periodic_jobs"] or []:
        print(f"  {job.get('period')}: {job['path']} owner={job.get('owner')} mode={job.get('mode')}")
    if not report["periodic_jobs"]:
        print("  none found")
    print()
    print("Systemd timers")
    for timer in report["systemd_timers"] or []:
        print(f"  {timer['unit']} {timer.get('state')} next={timer.get('next')} activates={timer.get('activates')}")
    if not report["systemd_timers"]:
        print("  none found")
    if report["warnings"] or report["errors"]:
        print()
        print("Warnings")
        for item in report["warnings"]:
            print(f"  {warn('[WARN]', no_color)} {item['source']}: {item['reason']}")
        for item in report["errors"]:
            print(f"  {warn('[WARN]', no_color)} {item}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Inventory cron jobs and systemd timers.")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--state")
    parser.add_argument("--include-users", action="store_true")
    parser.add_argument("--suspicious", action="store_true")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    report = collect(args.include_users, args.suspicious, args.state)
    emit_json(report) if args.json else print_human(report, args.no_color)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
