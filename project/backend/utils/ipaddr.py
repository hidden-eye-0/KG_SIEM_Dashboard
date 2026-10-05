"""IP address helpers used by entity extraction and threat-intelligence gating."""
from __future__ import annotations

import ipaddress
from typing import Optional

DOCUMENTATION_RANGES = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]


def classify_ip(value: str) -> dict:
    """Return {valid, version, is_private, is_reserved_documentation, is_public}."""
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return {"valid": False, "version": None, "is_private": False,
                "is_reserved_documentation": False, "is_public": False}
    is_doc = any(ip in n for n in DOCUMENTATION_RANGES)
    is_private = ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved
    return {
        "valid": True,
        "version": ip.version,
        "is_private": bool(is_private),
        "is_reserved_documentation": is_doc,
        "is_public": not is_private and not is_doc and ip.is_global,
    }


def is_lookup_worthy(value: str) -> bool:
    """Only globally routable, non-documentation addresses are sent to external TI providers."""
    return classify_ip(value)["is_public"]


def safe_ip(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None
