"""Shared helpers for route modules: JSON-safe conversion, pagination, time parsing."""
from __future__ import annotations

import datetime as _dt
import math
from typing import Any, Optional

from fastapi import HTTPException

from backend.utils.timeutil import parse_dt, to_iso


def jsonable(obj: Any) -> Any:
    """Convert Mongo/BSON documents into JSON-serialisable structures."""
    if isinstance(obj, dict):
        return {str(k): jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [jsonable(v) for v in obj]
    if isinstance(obj, _dt.datetime):
        return to_iso(obj)
    if isinstance(obj, float):
        if math.isnan(obj) or math.isinf(obj):
            return None
        return obj
    if hasattr(obj, "item"):  # numpy scalars
        try:
            return obj.item()
        except Exception:
            return str(obj)
    if obj.__class__.__name__ == "ObjectId":
        return str(obj)
    return obj


def parse_time(value: Optional[str], name: str = "time") -> Optional[_dt.datetime]:
    if value in (None, ""):
        return None
    try:
        return parse_dt(value)
    except Exception:
        raise HTTPException(400, f"invalid {name}: {value!r} (use ISO-8601)")


def page_args(page: int, page_size: int, max_page_size: int = 500) -> tuple[int, int]:
    if page < 1:
        raise HTTPException(400, "page must be >= 1")
    page_size = max(1, min(page_size, max_page_size))
    return (page - 1) * page_size, page_size
