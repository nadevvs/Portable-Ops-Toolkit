"""Shared helpers for security and DFIR-oriented tools."""

import hashlib
import os
import stat
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional

from common.output import bad, format_table, info, ok, warn


SEVERITY_ORDER = {"CRITICAL": 3, "WARN": 2, "INFO": 1, "OK": 0}


def marker(severity: str, no_color: bool = False) -> str:
    severity = severity.upper()
    text = f"[{severity}]"
    if severity == "CRITICAL":
        return bad(text, no_color)
    if severity == "WARN":
        return warn(text, no_color)
    if severity == "INFO":
        return info(text, no_color)
    return ok(text, no_color)


def overall(findings: Iterable[Mapping[str, Any]]) -> str:
    highest = "OK"
    for finding in findings:
        severity = str(finding.get("severity", "OK")).upper()
        if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER[highest]:
            highest = severity
    return highest


def print_findings(findings: List[Dict[str, Any]], no_color: bool = False) -> None:
    if not findings:
        print(f"  {marker('OK', no_color)} no findings")
        return
    for finding in findings:
        print(f"  {marker(str(finding.get('severity', 'INFO')), no_color)} {finding.get('message', '')}")


def print_section(title: str) -> None:
    print()
    print(title)


def print_rows(rows: List[Dict[str, Any]], columns: List[str], empty: str = "none") -> None:
    if rows:
        print(format_table(rows, columns))
    else:
        print(f"  {empty}")


def file_sha256(path: Path, limit_bytes: Optional[int] = None) -> Dict[str, Any]:
    data: Dict[str, Any] = {"path": str(path)}
    h = hashlib.sha256()
    total = 0
    try:
        with path.open("rb") as handle:
            while True:
                remaining = None if limit_bytes is None else max(0, limit_bytes - total)
                if remaining == 0:
                    data["truncated"] = True
                    break
                chunk_size = 1024 * 1024 if remaining is None else min(1024 * 1024, remaining)
                chunk = handle.read(chunk_size)
                if not chunk:
                    break
                h.update(chunk)
                total += len(chunk)
    except OSError as exc:
        data["error"] = str(exc)
        return data
    data.update({"sha256": h.hexdigest(), "bytes_hashed": total})
    return data


def stat_metadata(path: Path) -> Dict[str, Any]:
    data: Dict[str, Any] = {"path": str(path), "exists": path.exists()}
    try:
        st = os.lstat(path)
    except OSError as exc:
        data["error"] = str(exc)
        return data
    data.update(
        {
            "mode": oct(stat.S_IMODE(st.st_mode))[2:],
            "uid": st.st_uid,
            "gid": st.st_gid,
            "size": st.st_size,
            "mtime": int(st.st_mtime),
            "type": file_type(st.st_mode),
            "setuid": bool(st.st_mode & stat.S_ISUID),
            "setgid": bool(st.st_mode & stat.S_ISGID),
            "sticky": bool(st.st_mode & stat.S_ISVTX),
            "world_writable": bool(st.st_mode & stat.S_IWOTH),
        }
    )
    return data


def file_type(mode: int) -> str:
    if stat.S_ISREG(mode):
        return "file"
    if stat.S_ISDIR(mode):
        return "dir"
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISCHR(mode):
        return "char"
    if stat.S_ISBLK(mode):
        return "block"
    return "other"


def parse_simple_config(text: str) -> Dict[str, List[str]]:
    config: Dict[str, List[str]] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        config.setdefault(key.strip(), []).append(value.strip())
    return config
