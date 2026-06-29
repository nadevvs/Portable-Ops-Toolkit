"""State directory helpers."""

from pathlib import Path
from typing import Union


DEFAULT_STATE_DIR = "ops_state"
TOOLKIT_ROOT = Path(__file__).resolve().parents[1]


def resolve_state_dir(path: Union[str, Path, None]) -> Path:
    if path is None:
        return TOOLKIT_ROOT / DEFAULT_STATE_DIR
    return Path(path).expanduser()


def ensure_state_dir(path: Union[str, Path, None]) -> Path:
    state_dir = resolve_state_dir(path)
    state_dir.mkdir(parents=True, exist_ok=True)
    return state_dir
