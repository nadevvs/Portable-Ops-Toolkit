"""Shared warning helpers for best-effort collectors."""

from typing import Optional

from common.cmd import CommandResult


def command_warning(label: str, result: CommandResult) -> Optional[str]:
    if result.missing:
        return f"{label}: command not available"
    if result.timed_out:
        return f"{label}: command timed out"
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip().splitlines()
        suffix = f": {detail[0]}" if detail else ""
        return f"{label}: command failed with exit {result.returncode}{suffix}"
    return None
