#!/usr/bin/env python3
"""Record compact server state snapshots."""

import argparse
import json
import os
import socket
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from common.cmd import run_cmd
from common.output import emit_json
from common.redact import redact_text
from common.state import ensure_state_dir, resolve_state_dir
from common.systemd import parse_failed_units
from common.warnings import command_warning


def parse_loadavg(text: str) -> Dict[str, Any]:
    parts = text.split()
    data: Dict[str, Any] = {}
    try:
        if text.strip() and len(parts) < 3:
            raise ValueError
        if len(parts) >= 3:
            data.update({"load1": float(parts[0]), "load5": float(parts[1]), "load15": float(parts[2])})
        if len(parts) >= 4 and "/" in parts[3]:
            running, total = parts[3].split("/", 1)
            data.update({"running_processes": int(running), "total_processes": int(total)})
    except ValueError:
        data["parse_error"] = "invalid /proc/loadavg format"
    return data


def parse_meminfo(text: str) -> Dict[str, Any]:
    values: Dict[str, int] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, rest = line.split(":", 1)
        parts = rest.split()
        if parts and parts[0].isdigit():
            values[key] = int(parts[0])
    total = values.get("MemTotal", 0)
    available = values.get("MemAvailable", values.get("MemFree", 0))
    swap_total = values.get("SwapTotal", 0)
    swap_free = values.get("SwapFree", 0)
    values["MemUsedPercent"] = round(((total - available) / total) * 100, 1) if total else 0
    values["SwapUsedPercent"] = round(((swap_total - swap_free) / swap_total) * 100, 1) if swap_total else 0
    return values


def parse_df(text: str) -> List[Dict[str, Any]]:
    disks = []
    pseudo_filesystems = {"devfs", "devtmpfs", "tmpfs", "proc", "sysfs", "cgroup", "cgroup2", "map"}
    for index, line in enumerate(text.splitlines()):
        if index == 0 or not line.strip():
            continue
        parts = line.split()
        if len(parts) < 6:
            continue
        if parts[0] in pseudo_filesystems or not parts[4].endswith("%"):
            continue
        disks.append(
            {
                "filesystem": parts[0],
                "size": int(parts[1]) if parts[1].isdigit() else parts[1],
                "used": int(parts[2]) if parts[2].isdigit() else parts[2],
                "available": int(parts[3]) if parts[3].isdigit() else parts[3],
                "used_percent": int(parts[4].rstrip("%")) if parts[4].rstrip("%").isdigit() else 0,
                "mount": parts[5],
            }
        )
    return disks


def parse_ps(text: str) -> Dict[str, List[Dict[str, Any]]]:
    rows = []
    for index, line in enumerate(text.splitlines()):
        if index == 0 or not line.strip():
            continue
        parts = line.split(None, 7)
        if len(parts) < 8:
            continue
        rows.append(
            {
                "pid": parts[0],
                "ppid": parts[1],
                "user": parts[2],
                "comm": parts[3],
                "cpu": float_or_zero(parts[4]),
                "mem": float_or_zero(parts[5]),
                "rss": int(parts[6]) if parts[6].isdigit() else 0,
                "args": redact_text(parts[7][:160]),
            }
        )
    return {
        "top_cpu": sorted(rows, key=lambda item: item["cpu"], reverse=True)[:5],
        "top_mem": sorted(rows, key=lambda item: item["mem"], reverse=True)[:5],
    }


def float_or_zero(value: str) -> float:
    try:
        return float(value)
    except ValueError:
        return 0.0


def parse_ss_summary(text: str) -> Dict[str, Any]:
    summary = {"tcp_listen": 0, "tcp_established": 0, "udp": 0, "top_remote_ips": []}
    remotes: Dict[str, int] = {}
    for line in text.splitlines():
        parts = line.split()
        if not parts or parts[0] in {"Netid", "State"}:
            continue
        proto = parts[0].lower()
        if proto.startswith("udp"):
            summary["udp"] += 1
        if proto.startswith("tcp"):
            state = parts[1] if len(parts) > 1 else ""
            if state == "LISTEN":
                summary["tcp_listen"] += 1
            if state == "ESTAB":
                summary["tcp_established"] += 1
                remote = parts[5] if len(parts) > 5 else ""
                ip = remote.rsplit(":", 1)[0]
                if ip:
                    remotes[ip] = remotes.get(ip, 0) + 1
    summary["top_remote_ips"] = sorted(remotes.items(), key=lambda item: item[1], reverse=True)[:5]
    return summary


def notable_kernel(lines: Iterable[str]) -> List[str]:
    needles = ("oom", "killed process", "i/o error", "thermal", "segfault", "blocked for more than", "filesystem error")
    return [redact_text(line) for line in lines if any(needle in line.lower() for needle in needles)][:5]


def read_text(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def collect_snapshot() -> Dict[str, Any]:
    uptime_text = read_text("/proc/uptime")
    warnings = []
    load = parse_loadavg(read_text("/proc/loadavg"))
    mem = parse_meminfo(read_text("/proc/meminfo"))
    df = run_cmd(["df", "-P"], timeout=5)
    ps = run_cmd(["ps", "-eo", "pid,ppid,user,comm,%cpu,%mem,rss,args", "--sort=-%cpu"], timeout=5)
    failed = run_cmd(["systemctl", "--failed", "--no-pager"], timeout=5)
    ss = run_cmd(["ss", "-tuna"], timeout=5)
    journal = run_cmd(["journalctl", "-k", "-n", "30", "--no-pager"], timeout=5)
    for label, result in (
        ("df", df),
        ("ps", ps),
        ("systemctl --failed", failed),
        ("ss", ss),
        ("journalctl -k", journal),
    ):
        warning = command_warning(label, result)
        if warning:
            warnings.append(warning)
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "hostname": socket.gethostname(),
        "uptime_seconds": float_or_zero(uptime_text.split()[0]) if uptime_text else 0,
        "boot_id": read_text("/proc/sys/kernel/random/boot_id").strip(),
        "load": load,
        "memory": mem,
        "disk": parse_df(df.stdout) if df.stdout else [],
        "processes": parse_ps(ps.stdout) if ps.stdout else {"top_cpu": [], "top_mem": []},
        "services": {"failed_units": parse_failed_units(failed.stdout) if failed.stdout else []},
        "network": parse_ss_summary(ss.stdout) if ss.stdout else {"tcp_listen": 0, "tcp_established": 0, "udp": 0, "top_remote_ips": []},
        "kernel": {"notable": notable_kernel(journal.stdout.splitlines() if journal.stdout else [])},
        "warnings": warnings,
    }


def paths(state: Optional[str], create: bool = False) -> Dict[str, Path]:
    base = (ensure_state_dir(state) if create else resolve_state_dir(state)) / "blackbox"
    if create:
        base.mkdir(parents=True, exist_ok=True)
    return {"dir": base, "snapshots": base / "snapshots.jsonl", "metadata": base / "metadata.json"}


def record(state: Optional[str]) -> Dict[str, Any]:
    snapshot = collect_snapshot()
    p = paths(state, create=True)
    with p["snapshots"].open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(snapshot, sort_keys=True) + "\n")
    p["metadata"].write_text(json.dumps({"last_record": snapshot["timestamp"]}, indent=2), encoding="utf-8")
    return snapshot


def read_snapshots(state: Optional[str]) -> List[Dict[str, Any]]:
    path = paths(state, create=False)["snapshots"]
    snapshots = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return snapshots
    for line in lines:
        try:
            snapshots.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return snapshots


def summarize(snapshots: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not snapshots:
        return {"count": 0, "time_range": [], "reboots": 0, "failed_services": {}, "notable_events": []}
    max_load = max(snapshots, key=lambda item: item.get("load", {}).get("load1", 0))
    max_mem = max(snapshots, key=lambda item: item.get("memory", {}).get("MemUsedPercent", 0))
    boot_ids = [item.get("boot_id") for item in snapshots if item.get("boot_id")]
    failed: Dict[str, Dict[str, str]] = {}
    notable = []
    for item in snapshots:
        ts = item.get("timestamp", "")
        for unit in item.get("services", {}).get("failed_units", []):
            failed.setdefault(unit, {"first_seen": ts, "last_seen": ts})["last_seen"] = ts
        for line in item.get("kernel", {}).get("notable", []):
            notable.append({"timestamp": ts, "line": line})
    return {
        "count": len(snapshots),
        "time_range": [snapshots[0].get("timestamp"), snapshots[-1].get("timestamp")],
        "max_load1": {"value": max_load.get("load", {}).get("load1", 0), "timestamp": max_load.get("timestamp")},
        "max_memory_used": {"value": max_mem.get("memory", {}).get("MemUsedPercent", 0), "timestamp": max_mem.get("timestamp")},
        "reboots": max(0, len(set(boot_ids)) - 1),
        "failed_services": failed,
        "notable_events": notable[:20],
    }


def prune(state: Optional[str], days: int) -> Dict[str, Any]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    kept = []
    removed = 0
    for item in read_snapshots(state):
        try:
            ts = datetime.fromisoformat(item["timestamp"])
        except (KeyError, ValueError):
            removed += 1
            continue
        if ts >= cutoff:
            kept.append(item)
        else:
            removed += 1
    path = paths(state, create=False)["snapshots"]
    if not path.exists():
        return {"kept": 0, "removed": 0, "message": f"snapshot not found: {path}"}
    tmp = path.with_suffix(".jsonl.tmp")
    tmp.write_text("".join(json.dumps(item, sort_keys=True) + "\n" for item in kept), encoding="utf-8")
    tmp.replace(path)
    return {"kept": len(kept), "removed": removed}


def print_record(snapshot: Dict[str, Any]) -> None:
    root_disk = next((disk for disk in snapshot["disk"] if disk.get("mount") == "/"), {})
    print("blackbox: snapshot recorded")
    print(f"time: {snapshot['timestamp']}")
    print(f"load: {snapshot['load'].get('load1', 0)} {snapshot['load'].get('load5', 0)} {snapshot['load'].get('load15', 0)}")
    print(f"memory: {snapshot['memory'].get('MemUsedPercent', 0)}% used")
    print(f"disk: / {root_disk.get('used_percent', 0)}% used")
    print(f"failed services: {len(snapshot['services']['failed_units'])}")
    print(f"notable kernel lines: {len(snapshot['kernel']['notable'])}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Record compact server snapshots.")
    add_common_flags(parser)
    sub = parser.add_subparsers(dest="command", required=True)
    add_common_flags(sub.add_parser("record"), suppress=True)
    add_common_flags(sub.add_parser("summary"), suppress=True)
    add_common_flags(sub.add_parser("tail"), suppress=True)
    prune_parser = sub.add_parser("prune")
    add_common_flags(prune_parser, suppress=True)
    prune_parser.add_argument("--days", type=positive_int, required=True)
    return parser


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def add_common_flags(parser: argparse.ArgumentParser, suppress: bool = False) -> None:
    default = argparse.SUPPRESS if suppress else None
    parser.add_argument("--json", action="store_true", default=default)
    parser.add_argument("--no-color", action="store_true", default=default)
    parser.add_argument("--state", default=argparse.SUPPRESS if suppress else "ops_state")


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "record":
        output = record(args.state)
        emit_json(output) if args.json else print_record(output)
    elif args.command == "summary":
        output = summarize(read_snapshots(args.state))
        emit_json(output) if args.json else print(json.dumps(output, indent=2, sort_keys=True))
    elif args.command == "tail":
        output = read_snapshots(args.state)[-5:]
        emit_json(output) if args.json else print(json.dumps(output, indent=2, sort_keys=True))
    else:
        output = prune(args.state, args.days)
        emit_json(output) if args.json else print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
