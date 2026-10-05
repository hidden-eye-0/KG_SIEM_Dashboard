"""Portable, sortable string identifiers shared by MongoDB, Neo4j and the UI."""
from __future__ import annotations

import hashlib
import json
from typing import Any

from ulid import ULID
import uuid


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def digest(obj: Any, length: int = 16) -> str:
    """Stable content digest for tool arguments / query provenance."""
    raw = json.dumps(obj, sort_keys=True, default=str).encode()
    return hashlib.sha256(raw).hexdigest()[:length]
