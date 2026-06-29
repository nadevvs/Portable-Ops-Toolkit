"""Small redaction helpers for terminal and JSON output."""

import re
from typing import Any


SENSITIVE_WORD = (
    r"password|passwd|passphrase|secret|token|"
    r"api[_-]?key|secret[_-]?key|access[_-]?key|private[_-]?key|"
    r"aws[_-]?secret[_-]?access[_-]?key"
)

KEY_VALUE_RE = re.compile(
    rf"(?i)\b([A-Z0-9_./-]*(?:{SENSITIVE_WORD})[A-Z0-9_./-]*)(\s*=\s*|\s+)([^\s;]+)"
)
LONG_FLAG_RE = re.compile(
    rf"(?i)(--(?:{SENSITIVE_WORD})(?:[-_][a-z0-9]+)?)(=|\s+)([^\s;]+)"
)
URL_CREDS_RE = re.compile(r"([a-z][a-z0-9+.-]*://)([^/\s:@]+):([^@\s/]+)@", re.IGNORECASE)


def redact_text(value: str) -> str:
    """Redact common secret-looking values while preserving surrounding context."""
    redacted = URL_CREDS_RE.sub(r"\1<redacted>@", value)
    redacted = LONG_FLAG_RE.sub(r"\1\2<redacted>", redacted)
    redacted = KEY_VALUE_RE.sub(r"\1\2<redacted>", redacted)
    return redacted


def redact_data(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact_data(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_data(item) for item in value)
    if isinstance(value, dict):
        return {key: redact_data(item) for key, item in value.items()}
    return value
