#!/usr/bin/env python3
"""One-command practical server overview."""

import argparse
import grp
import os
import platform
import pwd
import socket
import stat
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from blackbox import parse_df, parse_meminfo
from common.cmd import run_cmd
from common.detect import read_os_release
from common.output import bad, emit_json, ok, warn
from common.redact import redact_text
from common.state import resolve_state_dir
from common.systemd import parse_failed_units
from common.warnings import command_warning
from sshexpose import get_setting, load_sshd_config, parse_auth_log, parse_sshd_T
from svcdep import parse_ss_output


RISKY_PORTS = {
    "5432": "PostgreSQL",
    "3306": "MySQL",
    "6379": "Redis",
    "27017": "MongoDB",
    "2375": "Docker API",
    "9200": "Elasticsearch",
}


def collect_system_info() -> Dict[str, Any]:
    os_release = read_os_release()
    uptime_text = read_file("/proc/uptime")
    uptime_seconds = 0.0
    if uptime_text:
        try:
            uptime_seconds = float(uptime_text.split()[0])
        except (ValueError, IndexError):
            uptime_seconds = 0.0
    load = os.getloadavg() if hasattr(os, "getloadavg") else (0, 0, 0)
    return {
        "hostname": socket.gethostname(),
        "os": os_release.get("PRETTY_NAME", ""),
        "kernel": platform.release(),
        "uptime_seconds": uptime_seconds,
        "boot_id": read_file("/proc/sys/kernel/random/boot_id").strip(),
        "load": list(load),
    }


def collect_memory() -> Dict[str, Any]:
    return parse_meminfo(read_file("/proc/meminfo"))


def collect_disk() -> List[Dict[str, Any]]:
    result = run_cmd(["df", "-P"], timeout=5)
    return parse_df(result.stdout) if result.stdout else []


def collect_failed_services() -> Dict[str, Any]:
    result = run_cmd(["systemctl", "--failed", "--no-pager"], timeout=5)
    warning = command_warning("systemctl --failed", result)
    return {
        "failed_units": parse_failed_units(result.stdout) if result.stdout else [],
        "available": not result.missing,
        "warning": warning or "",
    }


def classify_listener(port: Dict[str, Any]) -> str:
    address = port.get("address") or ""
    if address in {"127.0.0.1", "::1", "localhost"}:
        return "local-only"
    if address in {"0.0.0.0", "::", "*"}:
        return "all-interfaces"
    return "specific-interface"


def collect_listeners() -> List[Dict[str, Any]]:
    result = run_cmd(["ss", "-tulpn"], timeout=5)
    listeners = []
    for port in parse_ss_output(result.stdout) if result.stdout else []:
        if port.get("state") in {"LISTEN", "UNCONN", ""}:
            port["exposure"] = classify_listener(port)
            listeners.append(port)
    return listeners


def collect_recent_log_summary() -> Dict[str, Any]:
    result = run_cmd(["journalctl", "-p", "warning..alert", "-n", "50", "--no-pager"], timeout=5)
    lines = [redact_text(line) for line in result.stdout.splitlines()] if result.stdout else []
    lowered = "\n".join(lines).lower()
    return {
        "recent_warnings": len(lines),
        "oom_kills": lowered.count("oom") + lowered.count("killed process"),
        "io_errors": lowered.count("i/o error"),
        "auth_failures": lowered.count("failed password"),
        "notable": lines[:10],
    }


def collect_ssh_quick(listeners: List[Dict[str, Any]]) -> Dict[str, Any]:
    active = run_cmd(["systemctl", "is-active", "ssh.service"], timeout=3)
    if not active.stdout.strip():
        active = run_cmd(["systemctl", "is-active", "sshd.service"], timeout=3)
    sshd_t = run_cmd(["sshd", "-T"], timeout=5)
    if sshd_t.ok:
        config = parse_sshd_T(sshd_t.stdout)
    else:
        config = load_sshd_config()
    auth_lines = []
    for path in (Path("/var/log/auth.log"), Path("/var/log/secure")):
        try:
            auth_lines.extend(path.read_text(encoding="utf-8", errors="replace").splitlines()[-100:])
        except OSError:
            pass
    return {
        "active": active.stdout.strip() or "unknown",
        "listeners": [item for item in listeners if (item.get("process") or "").lower() == "sshd" or item.get("port") == "22"],
        "password_auth": get_setting(config, "passwordauthentication", "PasswordAuthentication") or "unknown",
        "root_login": get_setting(config, "permitrootlogin", "PermitRootLogin") or "unknown",
        "auth_log_summary": parse_auth_log(auth_lines),
    }


def parse_config(path: Optional[str]) -> Dict[str, List[str]]:
    config = {"paths": [], "services": [], "urls": []}
    if not path:
        return config
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError:
        return config
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or ":" not in stripped:
            continue
        kind, value = stripped.split(":", 1)
        kind = kind.strip()
        value = value.strip()
        if kind == "path":
            config["paths"].append(value)
        elif kind == "service":
            config["services"].append(value)
        elif kind == "url":
            config["urls"].append(value)
    return config


def path_metadata(path_text: str) -> Dict[str, Any]:
    path = Path(path_text)
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return {"path": path_text, "exists": False}
    except OSError as exc:
        return {"path": path_text, "exists": False, "error": str(exc)}
    try:
        owner = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        owner = str(st.st_uid)
    try:
        group = grp.getgrgid(st.st_gid).gr_name
    except KeyError:
        group = str(st.st_gid)
    return {
        "path": path_text,
        "exists": True,
        "mode": oct(stat.S_IMODE(st.st_mode))[2:],
        "owner": owner,
        "group": group,
    }


def collect_config_checks(config: Dict[str, List[str]]) -> Dict[str, Any]:
    services = []
    for service in config.get("services", []):
        active = run_cmd(["systemctl", "is-active", service], timeout=3)
        services.append(
            {
                "service": service,
                "active": active.stdout.strip() or "unknown",
                "warning": command_warning(f"systemctl is-active {service}", active) or "",
            }
        )
    return {
        "paths": [path_metadata(path) for path in config.get("paths", [])],
        "services": services,
        "urls": [
            {"url": url, "checked": False, "reason": "network URL checks are disabled by design"}
            for url in config.get("urls", [])
        ],
    }


def collect_network_basics() -> Dict[str, Any]:
    route = run_cmd(["ip", "route"], timeout=5)
    addr = run_cmd(["ip", "addr"], timeout=5)
    resolv = read_file("/etc/resolv.conf")
    default_route = next((line for line in route.stdout.splitlines() if line.startswith("default ")), "")
    dns = [line.split()[1] for line in resolv.splitlines() if line.startswith("nameserver ")]
    return {"default_route": default_route, "addresses": addr.stdout.splitlines()[:30], "dns": dns}


def classify_findings(data: Dict[str, Any]) -> List[Dict[str, str]]:
    findings = []
    memory = data.get("memory", {})
    if memory.get("MemUsedPercent", 0) >= 90:
        findings.append({"severity": "WARN", "message": "memory available below recommended level"})
    if memory.get("SwapUsedPercent", 0) >= 50:
        findings.append({"severity": "WARN", "message": "swap usage is high"})
    for disk in data.get("disk", []):
        used = disk.get("used_percent", 0)
        if used >= 95:
            findings.append({"severity": "CRITICAL", "message": f"{disk['mount']} disk usage {used}%"})
        elif used >= 85:
            findings.append({"severity": "WARN", "message": f"{disk['mount']} disk usage {used}%"})
    for unit in data.get("services", {}).get("failed_units", []):
        findings.append({"severity": "WARN", "message": f"{unit} is failed"})
    for item in data.get("config_checks", {}).get("paths", []):
        if not item.get("exists"):
            findings.append({"severity": "WARN", "message": f"configured path missing: {item['path']}"})
    for item in data.get("config_checks", {}).get("services", []):
        if item.get("active") not in {"active", "unknown"}:
            findings.append({"severity": "WARN", "message": f"configured service inactive: {item['service']} ({item['active']})"})
    for listener in data.get("listeners", []):
        if listener.get("exposure") == "all-interfaces" and listener.get("port") in RISKY_PORTS:
            findings.append({"severity": "CRITICAL", "message": f"{RISKY_PORTS[listener['port']]} listens on all interfaces"})
        elif listener.get("exposure") == "all-interfaces" and listener.get("port") == "22":
            findings.append({"severity": "INFO", "message": "SSH listens on all interfaces"})
    if data.get("logs", {}).get("oom_kills", 0):
        findings.append({"severity": "WARN", "message": "recent OOM/kernel kill indicators found"})
    return findings


def overall_status(findings: List[Dict[str, str]]) -> str:
    if any(item["severity"] == "CRITICAL" for item in findings):
        return "CRITICAL"
    if any(item["severity"] == "WARN" for item in findings):
        return "WARN"
    return "OK"


def recommend_next_checks(findings: List[Dict[str, str]]) -> List[str]:
    commands = ["python3 sshexpose.py", "python3 croninv.py"]
    if any("failed" in item["message"] for item in findings):
        commands.insert(0, "python3 svcdep.py SERVICE")
    if any("disk" in item["message"] or "memory" in item["message"] for item in findings):
        commands.append("python3 blackbox.py summary --state ops_state")
    return commands


def read_file(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def collect(config_path: Optional[str] = None, checks: Optional[str] = None, deep: bool = False, state: Optional[str] = None) -> Dict[str, Any]:
    wanted = set(checks.split(",")) if checks else {"system", "disk", "memory", "network", "security", "logs"}
    data: Dict[str, Any] = {"state_dir": str(resolve_state_dir(state))}
    if "system" in wanted:
        data["system"] = collect_system_info()
    if "memory" in wanted:
        data["memory"] = collect_memory()
    if "disk" in wanted:
        data["disk"] = collect_disk()
    if "system" in wanted:
        data["services"] = collect_failed_services()
    listeners = collect_listeners() if "network" in wanted or "security" in wanted else []
    data["listeners"] = listeners
    if "logs" in wanted:
        data["logs"] = collect_recent_log_summary()
    if "security" in wanted:
        data["ssh"] = collect_ssh_quick(listeners)
    if "network" in wanted:
        data["network"] = collect_network_basics()
    data["config"] = parse_config(config_path)
    data["config_checks"] = collect_config_checks(data["config"])
    findings = classify_findings(data)
    data["findings"] = findings
    data["overall"] = overall_status(findings)
    data["next_checks"] = recommend_next_checks(findings)
    return data


def print_human(report: Dict[str, Any], no_color: bool = False) -> None:
    print("serverdoctor: quick health overview")
    if "system" in report:
        sysinfo = report["system"]
        print()
        print("System")
        print(f"  Hostname: {sysinfo.get('hostname')}")
        print(f"  OS: {sysinfo.get('os') or 'unknown'}")
        print(f"  Kernel: {sysinfo.get('kernel')}")
        print(f"  Load: {' '.join(str(x) for x in sysinfo.get('load', []))}")
    if "memory" in report:
        print()
        print("Memory")
        print(f"  Used: {report['memory'].get('MemUsedPercent', 0)}%")
        print(f"  Swap: {report['memory'].get('SwapUsedPercent', 0)}%")
    if "disk" in report:
        print()
        print("Disk")
        for disk in report["disk"]:
            print(f"  {disk['mount']} {disk['used_percent']}%")
    print()
    print("Services")
    failed = report.get("services", {}).get("failed_units", [])
    print(f"  failed units: {len(failed)}")
    for unit in failed:
        print(f"  {unit}")
    print()
    print("Network listeners")
    for listener in report.get("listeners", [])[:20]:
        print(f"  {listener.get('local')} {listener.get('process') or ''} [{listener.get('exposure')}]")
    print()
    marker = ok("[OK]", no_color) if report["overall"] == "OK" else warn("[WARN]", no_color)
    if report["overall"] == "CRITICAL":
        marker = bad("[CRITICAL]", no_color)
    print(f"Overall: {marker} {report['overall']}")
    print()
    print("Next checks:")
    for command in report["next_checks"]:
        print(f"  {command}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Show a quick server health overview.")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--state")
    parser.add_argument("--deep", action="store_true")
    parser.add_argument("--checks")
    parser.add_argument("--config")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    report = collect(args.config, args.checks, args.deep, args.state)
    emit_json(report) if args.json else print_human(report, args.no_color)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
