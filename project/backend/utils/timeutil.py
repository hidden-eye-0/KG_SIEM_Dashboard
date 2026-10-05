from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional, Union


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def to_iso(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def parse_dt(value: Union[str, datetime, None]) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    s = str(value).strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def clamp_window(start: datetime, end: datetime, max_seconds: int) -> tuple[datetime, datetime, bool]:
    """Clamp [start, end] to at most max_seconds, anchored at the start. Returns (s, e, clamped)."""
    if end < start:
        start, end = end, start
    if (end - start).total_seconds() > max_seconds:
        return start, start + timedelta(seconds=max_seconds), True
    return start, end, False
