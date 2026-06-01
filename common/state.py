"""State directory helpers."""

from pathlib import Path
from typing import Union


DEFAULT_STATE_DIR = "ops_state"


def resolve_state_dir(path: Union[str, Path, None]) -> Path:
    return Path(path or DEFAULT_STATE_DIR).expanduser()


def ensure_state_dir(path: Union[str, Path, None]) -> Path:
    state_dir = resolve_state_dir(path)
    state_dir.mkdir(parents=True, exist_ok=True)
    return state_dir
