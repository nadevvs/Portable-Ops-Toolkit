"""Parsers for stable parts of common systemd command output."""

import re
from typing import Dict, List, Sequence, Tuple


WEEKDAYS = {"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"}
DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
TIME_RE = re.compile(r"\d{2}:\d{2}(?::\d{2})?")
UNIT_SUFFIXES = (
    ".service",
    ".timer",
    ".socket",
    ".mount",
    ".target",
    ".path",
    ".slice",
    ".scope",
    ".device",
    ".swap",
)


def parse_failed_units(text: str) -> List[str]:
    units = []
    seen = set()
    for line in text.splitlines():
        parts = line.split()
        unit = next((part.lstrip("●*") for part in parts if _looks_like_unit(part.lstrip("●*"))), "")
        if unit and unit not in seen:
            seen.add(unit)
            units.append(unit)
    return units


def _looks_like_unit(value: str) -> bool:
    return value.endswith(UNIT_SUFFIXES) and not value.startswith("UNIT")


def parse_systemd_timers(text: str) -> List[Dict[str, str]]:
    timers = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("NEXT ") or line.startswith("- ") or " timers listed" in line.lower():
            continue
        parts = line.split()
        timer_index = next((i for i, part in enumerate(parts) if part.endswith(".timer")), None)
        if timer_index is None:
            continue
        prefix = parts[:timer_index]
        unit = parts[timer_index]
        activates = parts[timer_index + 1] if len(parts) > timer_index + 1 else ""
        next_value, rest = _take_timestamp(prefix)
        left_value, rest = _take_until_timestamp(rest)
        last_value, rest = _take_timestamp(rest)
        passed_value = " ".join(rest)
        timers.append(
            {
                "unit": unit,
                "next": next_value,
                "left": left_value,
                "last": last_value,
                "passed": passed_value,
                "activates": activates,
            }
        )
    return timers


def _take_timestamp(tokens: Sequence[str]) -> Tuple[str, Sequence[str]]:
    if not tokens:
        return "", []
    if tokens[0] == "n/a":
        return "n/a", tokens[1:]
    if len(tokens) >= 4 and tokens[0] in WEEKDAYS and DATE_RE.fullmatch(tokens[1]) and TIME_RE.fullmatch(tokens[2]):
        return " ".join(tokens[:4]), tokens[4:]
    if len(tokens) >= 3 and DATE_RE.fullmatch(tokens[0]) and TIME_RE.fullmatch(tokens[1]):
        return " ".join(tokens[:3]), tokens[3:]
    return tokens[0], tokens[1:]


def _take_until_timestamp(tokens: Sequence[str]) -> Tuple[str, Sequence[str]]:
    collected = []
    for index, token in enumerate(tokens):
        if index > 0 and _is_timestamp_start(token):
            return " ".join(collected), tokens[index:]
        collected.append(token)
    return " ".join(collected), []


def _is_timestamp_start(token: str) -> bool:
    return token == "n/a" or token in WEEKDAYS or bool(DATE_RE.fullmatch(token))
