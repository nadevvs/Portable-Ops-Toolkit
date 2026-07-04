#!/usr/bin/env python3
"""Audit mount and fstab security options."""

import argparse
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from common.output import emit_json, format_table
from common.sec import marker, overall, print_findings
from common.state import resolve_state_dir


SENSITIVE_MOUNTS = {"/tmp", "/var/tmp", "/dev/shm", "/home"}


def parse_mountinfo(text: str) -> List[Dict[str, Any]]:
    rows = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 10 or " - " not in line:
            continue
        sep = parts.index("-")
        rows.append({"mount": parts[4].replace("\\040", " "), "options": parts[5].split(","), "fstype": parts[sep + 1], "source": parts[sep + 2] if len(parts) > sep + 2 else ""})
    return rows


def parse_fstab(text: str) -> List[Dict[str, Any]]:
    rows = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 4:
            rows.append({"source": parts[0], "mount": parts[1], "fstype": parts[2], "options": parts[3].split(",")})
    return rows


def classify_findings(mounts: List[Dict[str, Any]], fstab: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    findings = []
    by_mount = {item["mount"]: item for item in mounts}
    for path in SENSITIVE_MOUNTS:
        item = by_mount.get(path)
        if not item:
            continue
        options = set(item.get("options", []))
        if "nosuid" not in options:
            findings.append({"severity": "WARN", "message": f"{path} is mounted without nosuid"})
        if path in {"/tmp", "/var/tmp", "/dev/shm"} and "noexec" not in options:
            findings.append({"severity": "INFO", "message": f"{path} is mounted without noexec"})
    for item in fstab:
        options = set(item.get("options", []))
        if "user" in options and "nosuid" not in options:
            findings.append({"severity": "WARN", "message": f"fstab user mount lacks nosuid: {item['mount']}"})
    return findings


def collect(state: Optional[str] = None) -> Dict[str, Any]:
    try:
        mount_text = Path("/proc/self/mountinfo").read_text(encoding="utf-8", errors="replace")
    except OSError:
        mount_text = ""
    try:
        fstab_text = Path("/etc/fstab").read_text(encoding="utf-8", errors="replace")
    except OSError:
        fstab_text = ""
    mounts = parse_mountinfo(mount_text)
    fstab = parse_fstab(fstab_text)
    findings = classify_findings(mounts, fstab)
    return {"tool": "mountaudit", "state_dir": str(resolve_state_dir(state)), "mounts": mounts, "fstab": fstab, "findings": findings, "overall": overall(findings), "warnings": []}


def print_human(report: Dict[str, Any], no_color: bool = False) -> None:
    print("mountaudit: mount option posture")
    print(f"overall: {marker(report['overall'], no_color)} {report['overall']}")
    rows = [{"mount": x.get("mount"), "fstype": x.get("fstype"), "options": ",".join(x.get("options", [])[:6])} for x in report["mounts"][:30]]
    print()
    print(format_table(rows, ["mount", "fstype", "options"]) if rows else "  no mounts parsed")
    print()
    print("Findings")
    print_findings(report["findings"], no_color)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit mount and fstab security options.")
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
