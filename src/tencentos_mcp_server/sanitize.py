"""Input sanitization — prevent shell command injection.

All user-supplied parameters that are interpolated into shell commands
MUST pass through a validator here before use.  Each validator raises
ValueError with a clear message if the input is rejected.
"""

from __future__ import annotations

import re

# ── Precompiled patterns ──────────────────────────────────────────

_SAFE_NAME = re.compile(r"^[a-zA-Z0-9_.@:-]+$")
_SAFE_SORT = {"cpu", "mem"}
_SAFE_PRIORITY = {"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug", ""}
_SAFE_PROTOCOL = {"tcp", "udp", "all"}
_SAFE_SERVICE_STATE = {"running", "failed", "inactive", "active", "dead", ""}
_TIME_LIKE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}([ T]\d{2}:\d{2}(:\d{2})?)?|"  # ISO date/datetime
    r"\d+\s+(second|minute|hour|day|week|month)s?\s+ago|"  # relative: "2 hours ago"
    r"today|yesterday|now)$",
    re.IGNORECASE,
)


# ── Validators ────────────────────────────────────────────────────

def safe_name(value: str, field: str = "name") -> str:
    """Validate a service/unit/package name.

    Allows: letters, digits, underscore, dot, @, colon, hyphen.
    Blocks: spaces, semicolons, pipes, backticks, $, etc.
    """
    value = value.strip()
    if not value:
        raise ValueError(f"{field} cannot be empty")
    if len(value) > 256:
        raise ValueError(f"{field} too long (max 256 chars)")
    if not _SAFE_NAME.match(value):
        raise ValueError(
            f"Invalid {field}: '{value}'. "
            f"Only letters, digits, underscore, dot, @, colon, and hyphen are allowed."
        )
    return value


def safe_sort_by(value: str) -> str:
    """Validate sort_by parameter (cpu / mem)."""
    value = value.strip().lower()
    if value not in _SAFE_SORT:
        raise ValueError(f"Invalid sort_by: '{value}'. Must be one of: {_SAFE_SORT}")
    return value


def safe_priority(value: str) -> str:
    """Validate journalctl priority level."""
    value = value.strip().lower()
    if value not in _SAFE_PRIORITY:
        raise ValueError(f"Invalid priority: '{value}'. Must be one of: {_SAFE_PRIORITY}")
    return value


def safe_protocol(value: str) -> str:
    """Validate network protocol filter."""
    value = value.strip().lower()
    if value not in _SAFE_PROTOCOL:
        raise ValueError(f"Invalid protocol: '{value}'. Must be one of: {_SAFE_PROTOCOL}")
    return value


def safe_service_state(value: str) -> str:
    """Validate systemd service state filter."""
    value = value.strip().lower()
    if value not in _SAFE_SERVICE_STATE:
        raise ValueError(f"Invalid state: '{value}'. Must be one of: {_SAFE_SERVICE_STATE}")
    return value


def safe_time_expr(value: str, field: str = "time") -> str:
    """Validate a time expression for journalctl --since / --until.

    Accepts: ISO dates, relative expressions ("2 hours ago"), "today", "yesterday".
    Blocks: shell metacharacters that could be used for injection.
    """
    value = value.strip()
    if not value:
        return value
    if len(value) > 64:
        raise ValueError(f"{field} too long (max 64 chars)")
    if _TIME_LIKE.match(value):
        return value
    # Extra safety: reject any shell-dangerous characters
    dangerous = set(";|&`$(){}[]!#\\'\">")
    found = dangerous & set(value)
    if found:
        raise ValueError(
            f"Invalid {field}: '{value}' contains forbidden characters: {found}"
        )
    return value


def safe_positive_int(value: int, field: str = "number", max_val: int = 10000) -> int:
    """Validate a positive integer within bounds."""
    if not isinstance(value, int) or value < 1:
        raise ValueError(f"{field} must be a positive integer, got: {value}")
    if value > max_val:
        raise ValueError(f"{field} too large (max {max_val}), got: {value}")
    return value
