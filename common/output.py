"""Terminal and JSON output helpers."""

import json
import sys
from typing import Any, Iterable, Mapping, Sequence


COLORS = {
    "ok": "\033[32m",
    "warn": "\033[33m",
    "bad": "\033[31m",
    "info": "\033[36m",
    "reset": "\033[0m",
}


def use_color(no_color: bool = False) -> bool:
    return not no_color and sys.stdout.isatty()


def colorize(text: str, level: str, no_color: bool = False) -> str:
    if not use_color(no_color):
        return text
    return f"{COLORS.get(level, '')}{text}{COLORS['reset']}"


def ok(text: str, no_color: bool = False) -> str:
    return colorize(text, "ok", no_color)


def warn(text: str, no_color: bool = False) -> str:
    return colorize(text, "warn", no_color)


def bad(text: str, no_color: bool = False) -> str:
    return colorize(text, "bad", no_color)


def info(text: str, no_color: bool = False) -> str:
    return colorize(text, "info", no_color)


def emit_json(data: Any) -> None:
    print(json.dumps(data, indent=2, sort_keys=True))


def format_table(rows: Iterable[Mapping[str, Any]], columns: Sequence[str]) -> str:
    materialized = [{column: str(row.get(column, "")) for column in columns} for row in rows]
    widths = {
        column: max([len(column)] + [len(row[column]) for row in materialized])
        for column in columns
    }
    header = "  ".join(column.ljust(widths[column]) for column in columns)
    divider = "  ".join("-" * widths[column] for column in columns)
    lines = [header, divider]
    lines.extend(
        "  ".join(row[column].ljust(widths[column]) for column in columns)
        for row in materialized
    )
    return "\n".join(lines)
