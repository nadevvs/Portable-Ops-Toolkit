#!/usr/bin/env python3
"""Check file permission drift against a simple baseline."""

import argparse
import grp
import json
import os
import pwd
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from common.output import bad, emit_json, ok, warn
from common.state import ensure_state_dir, resolve_state_dir


EXAMPLE_CONFIG = """# path | mode | owner | group | type | note | optional
/etc/ssh/sshd_config | 600 | root | root | file | SSH daemon config
/etc/sudoers | 440 | root | root | file | sudoers
/etc/passwd | 644 | root | root | file | user database
/etc/shadow | 640 | root | shadow | file | password hashes; adjust group per distro
"""


@dataclass
class ExpectedPath:
    path: str
    mode: str
    owner: str
    group: str
    type: str
    note: str = ""
    optional: bool = False


def parse_config(text: str) -> List[ExpectedPath]:
    entries = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [part.strip() for part in line.split("|")]
        if len(parts) < 5:
            raise ValueError(f"malformed config line: {raw_line}")
        entries.append(
            ExpectedPath(
                path=parts[0],
                mode=parts[1],
                owner=parts[2],
                group=parts[3],
                type=parts[4],
                note=parts[5] if len(parts) > 5 else "",
                optional=any(part.lower() == "optional" for part in parts[6:]),
            )
        )
    return entries


def mode_text(mode: int) -> str:
    return oct(mode & 0o7777)[2:]


def normalize_mode_text(value: Any) -> str:
    try:
        return oct(int(str(value), 8) & 0o7777)[2:]
    except (TypeError, ValueError):
        return str(value)


def type_text(mode: int) -> str:
    if stat.S_ISREG(mode):
        return "file"
    if stat.S_ISDIR(mode):
        return "dir"
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
        return "device"
    return "other"


def get_file_metadata(path_text: str) -> Dict[str, Any]:
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
    data = {
        "path": path_text,
        "exists": True,
        "type": type_text(st.st_mode),
        "mode": mode_text(st.st_mode),
        "owner": owner,
        "group": group,
        "world_writable": bool(st.st_mode & stat.S_IWOTH),
        "setuid": bool(st.st_mode & stat.S_ISUID),
        "setgid": bool(st.st_mode & stat.S_ISGID),
        "mtime": int(st.st_mtime),
    }
    if stat.S_ISLNK(st.st_mode):
        try:
            data["target"] = os.readlink(path)
        except OSError:
            data["target"] = None
    return data


def compare_expected_actual(expected: ExpectedPath, actual: Dict[str, Any]) -> Dict[str, Any]:
    reasons = []
    severity = "OK"
    if not actual.get("exists"):
        severity = "WARN" if expected.optional else "CRITICAL"
        reasons.append("file missing" + (", marked optional" if expected.optional else ""))
        return result(expected, actual, severity, reasons)
    for key in ("type", "mode", "owner", "group"):
        expected_value = normalize_mode_text(getattr(expected, key)) if key == "mode" else str(getattr(expected, key))
        actual_value = normalize_mode_text(actual.get(key)) if key == "mode" else str(actual.get(key))
        if actual_value != expected_value:
            reasons.append(f"{key} expected={expected_value} actual={actual_value}")
            severity = "WARN"
    critical_reason = classify_issue(expected, actual)
    if critical_reason:
        severity = "CRITICAL"
        reasons.append(critical_reason)
    return result(expected, actual, severity, reasons or ["matches expected baseline"])


def classify_issue(expected: ExpectedPath, actual: Dict[str, Any]) -> str:
    path = expected.path.lower()
    try:
        mode = int(str(actual.get("mode", "0")), 8)
        expected_mode = int(str(expected.mode), 8)
    except ValueError:
        return "invalid mode value"
    if actual.get("world_writable") and not (expected_mode & 0o002):
        return "world-writable path"
    if actual.get("setuid") and not (expected_mode & stat.S_ISUID):
        return "unexpected setuid bit"
    if expected.type == "file" and actual.get("type") == "symlink":
        return "file type changed from file to symlink"
    if "sudoers" in path and actual.get("owner") != "root":
        return "sudoers is not owned by root"
    if "sshd_config" in path and actual.get("owner") != "root":
        return "SSH config is not owned by root"
    if is_sensitive_path(path) and mode & 0o077:
        return "sensitive-looking file is readable or writable by group/others"
    return ""


def is_sensitive_path(path: str) -> bool:
    return any(token in path for token in ("id_rsa", ".env", "authorized_keys", "shadow"))


def result(expected: ExpectedPath, actual: Dict[str, Any], severity: str, reasons: List[str]) -> Dict[str, Any]:
    return {
        "path": expected.path,
        "severity": severity,
        "expected": expected.__dict__,
        "actual": actual,
        "reasons": reasons,
    }


def load_entries(config: str) -> List[ExpectedPath]:
    return parse_config(Path(config).read_text(encoding="utf-8"))


def check_config(config: str) -> Dict[str, Any]:
    entries = load_entries(config)
    results = [compare_expected_actual(entry, get_file_metadata(entry.path)) for entry in entries]
    return summarize(results)


def summarize(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "checked": len(results),
        "ok": sum(1 for item in results if item["severity"] == "OK"),
        "warnings": sum(1 for item in results if item["severity"] == "WARN"),
        "critical": sum(1 for item in results if item["severity"] == "CRITICAL"),
        "results": results,
    }


def snapshot(config: str, state: Optional[str]) -> Dict[str, Any]:
    entries = load_entries(config)
    data = {"paths": [get_file_metadata(entry.path) for entry in entries]}
    state_dir = ensure_state_dir(state) / "permdrift"
    state_dir.mkdir(parents=True, exist_ok=True)
    path = state_dir / "snapshot.json"
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    return {"snapshot": str(path), "count": len(data["paths"])}


def diff_snapshot(config: str, state: Optional[str]) -> Dict[str, Any]:
    state_dir = resolve_state_dir(state) / "permdrift"
    path = state_dir / "snapshot.json"
    try:
        previous = json.loads(path.read_text(encoding="utf-8"))
    except OSError:
        return {"error": f"snapshot not found: {path}", "changes": []}
    old = {item["path"]: item for item in previous.get("paths", [])}
    changes = []
    for entry in load_entries(config):
        current = get_file_metadata(entry.path)
        previous = old.get(entry.path)
        if permission_identity(current) != permission_identity(previous):
            changes.append({"path": entry.path, "before": previous, "after": current})
    return {"snapshot": str(path), "changes": changes}


def permission_identity(item: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not item:
        return {}
    keys = ("exists", "type", "mode", "owner", "group", "target", "world_writable", "setuid", "setgid")
    return {key: item.get(key) for key in keys if key in item}


def print_check(report: Dict[str, Any], no_color: bool = False) -> None:
    print(f"permdrift: checking {report['checked']} paths")
    for item in report["results"]:
        marker = item["severity"]
        label = ok("[OK]", no_color) if marker == "OK" else warn("[WARN]", no_color)
        if marker == "CRITICAL":
            label = bad("[CRITICAL]", no_color)
        print()
        print(f"{label} {item['path']}")
        print(f"     reason: {'; '.join(item['reasons'])}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Check file permission drift.")
    add_common_flags(parser)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("check", "init", "snapshot", "diff"):
        child = sub.add_parser(name)
        add_common_flags(child, suppress=True)
        child.add_argument("config")
    return parser


def add_common_flags(parser: argparse.ArgumentParser, suppress: bool = False) -> None:
    default = argparse.SUPPRESS if suppress else None
    parser.add_argument("--json", action="store_true", default=default)
    parser.add_argument("--no-color", action="store_true", default=default)
    parser.add_argument("--state", default=argparse.SUPPRESS if suppress else None)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "init":
        path = Path(args.config)
        if path.exists():
            output = {"created": False, "path": str(path), "message": "config already exists"}
        else:
            path.write_text(EXAMPLE_CONFIG, encoding="utf-8")
            output = {"created": True, "path": str(path)}
    elif args.command == "check":
        output = check_config(args.config)
    elif args.command == "snapshot":
        output = snapshot(args.config, args.state)
    else:
        output = diff_snapshot(args.config, args.state)
    if args.json:
        emit_json(output)
    elif args.command == "check":
        print_check(output, args.no_color)
    else:
        print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
