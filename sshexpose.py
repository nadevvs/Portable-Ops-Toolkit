#!/usr/bin/env python3
"""Audit local OpenSSH exposure indicators."""

import argparse
import grp
import os
import pwd
import re
import shlex
import stat
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from common.cmd import run_cmd
from common.output import bad, emit_json, ok, warn
from common.state import resolve_state_dir
from svcdep import parse_ss_output


CONFIG_KEYS = {
    "Port",
    "ListenAddress",
    "PermitRootLogin",
    "PasswordAuthentication",
    "PubkeyAuthentication",
    "KbdInteractiveAuthentication",
    "ChallengeResponseAuthentication",
    "AllowUsers",
    "AllowGroups",
    "DenyUsers",
    "DenyGroups",
    "MaxAuthTries",
    "PermitEmptyPasswords",
    "X11Forwarding",
    "AllowTcpForwarding",
    "ClientAliveInterval",
    "UsePAM",
}


def parse_sshd_config(text: str) -> Dict[str, Any]:
    config: Dict[str, Any] = {}
    in_match = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            parts = shlex.split(line, comments=True)
        except ValueError:
            continue
        if not parts:
            continue
        key = parts[0]
        if key.lower() == "match":
            in_match = True
            config["_match_blocks_present"] = True
            continue
        if in_match:
            continue
        canonical = next((item for item in CONFIG_KEYS if item.lower() == key.lower()), key)
        if canonical in CONFIG_KEYS and len(parts) > 1:
            value = " ".join(parts[1:])
            if canonical in config:
                existing = config[canonical]
                config[canonical] = existing + [value] if isinstance(existing, list) else [existing, value]
            else:
                config[canonical] = value
    return config


def parse_sshd_T(text: str) -> Dict[str, str]:
    config = {}
    for raw_line in text.splitlines():
        parts = raw_line.strip().split(None, 1)
        if len(parts) == 2:
            key = parts[0].lower()
            config[key] = parts[1]
    return config


def parse_ss_listeners(text: str) -> List[Dict[str, Any]]:
    listeners = []
    for port in parse_ss_output(text):
        if (port.get("process") or "").lower() == "sshd":
            address = port.get("address") or ""
            port["exposure"] = classify_listener(address)
            listeners.append(port)
    return listeners


def classify_listener(address: str) -> str:
    if address in {"127.0.0.1", "::1", "localhost"}:
        return "loopback-only"
    if address in {"0.0.0.0", "::", "*"}:
        return "all-interfaces"
    return "specific-interface"


def inspect_authorized_keys(path: Path, username: str = "") -> Dict[str, Any]:
    data: Dict[str, Any] = {"user": username, "path": str(path), "exists": path.exists()}
    if not path.exists():
        return data
    try:
        st = path.stat()
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        data["error"] = str(exc)
        return data
    try:
        owner = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        owner = str(st.st_uid)
    try:
        group = grp.getgrgid(st.st_gid).gr_name
    except KeyError:
        group = str(st.st_gid)
    key_types = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            key_types.append(stripped.split()[0])
    data.update(
        {
            "keys": len(key_types),
            "key_types": sorted(set(key_types)),
            "mode": oct(stat.S_IMODE(st.st_mode))[2:],
            "owner": owner,
            "group": group,
            "writable_by_group_or_other": bool(st.st_mode & 0o022),
        }
    )
    return data


def parse_auth_log(lines: Iterable[str]) -> Dict[str, Any]:
    failed_ips: Counter[str] = Counter()
    failed_users: Counter[str] = Counter()
    accepted = 0
    failed = 0
    invalid = 0
    disconnected = 0
    for line in lines:
        if "Failed password" in line:
            failed += 1
            user = extract_after(line, "for ")
            ip = extract_ip(line)
            if user:
                failed_users[user.split()[0]] += 1
            if ip:
                failed_ips[ip] += 1
        if "Accepted " in line:
            accepted += 1
        if "Invalid user" in line or "invalid user" in line:
            invalid += 1
        if "Disconnected from" in line or "disconnect" in line.lower():
            disconnected += 1
    return {
        "failed_logins": failed,
        "accepted_logins": accepted,
        "invalid_users": invalid,
        "disconnects": disconnected,
        "top_failed_ips": failed_ips.most_common(5),
        "top_failed_users": failed_users.most_common(5),
    }


def extract_ip(line: str) -> str:
    match = re.search(r"from ([0-9a-fA-F:.]+)", line)
    return match.group(1) if match else ""


def extract_after(line: str, marker: str) -> str:
    if marker not in line:
        return ""
    return line.split(marker, 1)[1]


def classify_findings(config: Dict[str, Any], listeners: List[Dict[str, Any]], keys: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    findings = []
    root_login = get_setting(config, "permitrootlogin", "PermitRootLogin")
    password_auth = get_setting(config, "passwordauthentication", "PasswordAuthentication")
    empty_passwords = get_setting(config, "permitemptypasswords", "PermitEmptyPasswords")
    max_auth = get_setting(config, "maxauthtries", "MaxAuthTries")
    exposed = any(item.get("exposure") == "all-interfaces" for item in listeners)
    if root_login == "yes":
        findings.append({"severity": "CRITICAL", "message": "PermitRootLogin yes"})
    if empty_passwords == "yes":
        findings.append({"severity": "CRITICAL", "message": "PermitEmptyPasswords yes"})
    if exposed and password_auth == "yes":
        findings.append({"severity": "CRITICAL", "message": "SSH listens on all interfaces with password authentication enabled"})
    elif password_auth == "yes":
        findings.append({"severity": "WARN", "message": "PasswordAuthentication yes"})
    if exposed and not (get_setting(config, "allowusers", "AllowUsers") or get_setting(config, "allowgroups", "AllowGroups")):
        findings.append({"severity": "WARN", "message": "No AllowUsers or AllowGroups on exposed SSH listener"})
    try:
        if max_auth and int(str(max_auth)) > 6:
            findings.append({"severity": "WARN", "message": "MaxAuthTries above 6"})
    except ValueError:
        pass
    for item in keys:
        if item.get("writable_by_group_or_other"):
            findings.append({"severity": "CRITICAL", "message": f"{item['path']} writable by group/others"})
        if item.get("user") == "root" and item.get("keys", 0):
            findings.append({"severity": "WARN", "message": "root has authorized SSH keys"})
    if config.get("_match_blocks_present"):
        findings.append({"severity": "INFO", "message": "Match blocks present; simple parser did not evaluate conditional config"})
    return findings


def get_setting(config: Dict[str, Any], lower_key: str, mixed_key: str) -> Any:
    value = config.get(lower_key, config.get(mixed_key, ""))
    return value.lower() if isinstance(value, str) else value


def score_findings(findings: List[Dict[str, str]]) -> str:
    score = sum(3 if item["severity"] == "CRITICAL" else 1 if item["severity"] == "WARN" else 0 for item in findings)
    if score >= 3:
        return "HIGH"
    if score:
        return "MEDIUM"
    return "LOW"


def find_ssh_service() -> Dict[str, str]:
    for unit in ("ssh.service", "sshd.service"):
        active = run_cmd(["systemctl", "is-active", unit], timeout=3)
        enabled = run_cmd(["systemctl", "is-enabled", unit], timeout=3)
        if active.stdout.strip() or enabled.stdout.strip():
            return {"unit": unit, "active": active.stdout.strip(), "enabled": enabled.stdout.strip()}
    return {"unit": "", "active": "unknown", "enabled": "unknown"}


def collect_users() -> List[Dict[str, Any]]:
    entries = []
    try:
        passwd_lines = Path("/etc/passwd").read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return entries
    for line in passwd_lines:
        parts = line.split(":")
        if len(parts) < 6:
            continue
        username, home = parts[0], parts[5]
        if home and home not in {"/", "/nonexistent"}:
            entries.append(inspect_authorized_keys(Path(home) / ".ssh" / "authorized_keys", username))
    return [entry for entry in entries if entry.get("exists")]


def collect(logs: int = 100, include_users: bool = False, deep: bool = False, state: Optional[str] = None) -> Dict[str, Any]:
    warnings: List[str] = []
    sshd_t = run_cmd(["sshd", "-T"], timeout=5)
    if sshd_t.ok:
        config = parse_sshd_T(sshd_t.stdout)
        config_source = "sshd -T"
    else:
        config = {}
        config_source = "files"
        for path in [Path("/etc/ssh/sshd_config")] + sorted(Path("/etc/ssh/sshd_config.d").glob("*.conf") if Path("/etc/ssh/sshd_config.d").exists() else []):
            try:
                config.update(parse_sshd_config(path.read_text(encoding="utf-8", errors="replace")))
            except OSError as exc:
                warnings.append(f"{path}: {exc}")
    ss_result = run_cmd(["ss", "-tulpn"], timeout=5)
    listeners = parse_ss_listeners(ss_result.stdout) if ss_result.stdout else []
    key_entries = collect_users() if include_users else []
    auth_lines: List[str] = []
    for unit in ("ssh", "sshd"):
        journal = run_cmd(["journalctl", "-u", unit, "-n", str(logs), "--no-pager"], timeout=5)
        if journal.stdout:
            auth_lines.extend(journal.stdout.splitlines())
    if not auth_lines:
        for path in (Path("/var/log/auth.log"), Path("/var/log/secure")):
            try:
                auth_lines.extend(path.read_text(encoding="utf-8", errors="replace").splitlines()[-logs:])
            except OSError:
                pass
    fail2ban = run_cmd(["fail2ban-client", "status", "sshd"], timeout=5)
    fail2ban_data = {"available": fail2ban.returncode != 127, "sshd": fail2ban.stdout.strip() if fail2ban.ok else ""}
    findings = classify_findings(config, listeners, key_entries)
    return {
        "state_dir": str(resolve_state_dir(state)),
        "service": find_ssh_service(),
        "listeners": listeners,
        "config_source": config_source,
        "config": config,
        "authorized_keys": key_entries,
        "auth_log_summary": parse_auth_log(auth_lines),
        "fail2ban": fail2ban_data,
        "findings": findings,
        "risk": score_findings(findings),
        "warnings": warnings,
    }


def print_human(report: Dict[str, Any], no_color: bool = False) -> None:
    print("sshexpose: SSH exposure audit")
    print()
    print("Service")
    print(f"  unit: {report['service'].get('unit') or 'unknown'}")
    print(f"  active: {report['service'].get('active') or 'unknown'}")
    print(f"  enabled: {report['service'].get('enabled') or 'unknown'}")
    print()
    print("Listening")
    for listener in report["listeners"] or []:
        print(f"  {listener['local']} [{listener['exposure']}]")
    if not report["listeners"]:
        print("  none found")
    print()
    print("Effective config")
    for key in ("permitrootlogin", "PermitRootLogin", "passwordauthentication", "PasswordAuthentication", "pubkeyauthentication", "PubkeyAuthentication", "maxauthtries", "MaxAuthTries"):
        if key in report["config"]:
            print(f"  {key}: {report['config'][key]}")
    print()
    print("Recent auth")
    auth = report["auth_log_summary"]
    print(f"  failed logins: {auth['failed_logins']}")
    print(f"  accepted logins: {auth['accepted_logins']}")
    print()
    print("Findings")
    for finding in report["findings"] or []:
        marker = bad("[CRITICAL]", no_color) if finding["severity"] == "CRITICAL" else warn("[WARN]", no_color) if finding["severity"] == "WARN" else ok("[INFO]", no_color)
        print(f"  {marker} {finding['message']}")
    if not report["findings"]:
        print("  none")
    print()
    print(f"Risk: {report['risk']}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit local SSH exposure.")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--state")
    parser.add_argument("--logs", type=int, default=100)
    parser.add_argument("--users", action="store_true")
    parser.add_argument("--deep", action="store_true")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    report = collect(args.logs, args.users, args.deep, args.state)
    emit_json(report) if args.json else print_human(report, args.no_color)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
