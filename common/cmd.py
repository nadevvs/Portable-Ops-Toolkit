"""Safe external command execution helpers."""

import os
import subprocess
from dataclasses import dataclass
from typing import Mapping, Optional, Sequence


@dataclass
class CommandResult:
    args: Sequence[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    missing: bool = False
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.missing


def run_cmd(
    args: Sequence[str],
    timeout: float = 5,
    env: Optional[Mapping[str, str]] = None,
) -> CommandResult:
    """Run a command without a shell and return a non-throwing result."""
    merged_env = os.environ.copy()
    merged_env.setdefault("LC_ALL", "C")
    if env:
        merged_env.update(env)

    try:
        completed = subprocess.run(
            list(args),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
            env=merged_env,
        )
    except FileNotFoundError as exc:
        return CommandResult(
            args=args,
            returncode=127,
            stdout="",
            stderr="",
            missing=True,
            error=str(exc),
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            args=args,
            returncode=124,
            stdout=exc.stdout or "",
            stderr=exc.stderr or "",
            timed_out=True,
            error="command timed out",
        )
    except OSError as exc:
        return CommandResult(
            args=args,
            returncode=1,
            stdout="",
            stderr="",
            error=str(exc),
        )

    return CommandResult(
        args=args,
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )
