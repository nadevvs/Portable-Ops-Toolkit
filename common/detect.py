"""Small host detection helpers shared by tools."""

from pathlib import Path
from typing import Dict


def parse_key_value_file(text: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key.strip()] = value.strip().strip('"')
    return result


def read_os_release(path: str = "/etc/os-release") -> Dict[str, str]:
    try:
        return parse_key_value_file(Path(path).read_text(encoding="utf-8"))
    except OSError:
        return {}
