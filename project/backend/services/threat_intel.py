"""Passive threat-intelligence lookups (VirusTotal v3, AlienVault OTX) with caching.

Rules (brief §10, §27, §34):
* passive lookups only (GET by indicator) — nothing is ever submitted
* keys optional: without a key the provider returns status "not_configured"
* private / documentation-range addresses are short-circuited ("private_address") and never sent out
* raw provider payload (trimmed) and the normalised summary are stored separately; any AI
  interpretation lives in its own field so the UI can distinguish "Actual API result" from
  "AI interpretation"
* results are cached in the `threat_intelligence` collection with a TTL
"""
from __future__ import annotations

import logging
import re
import time
from datetime import timedelta
from typing import Any, Dict, Optional

import httpx

from backend.config import Settings
from backend.services.mongo import DocumentStore
from backend.utils.ids import new_id
from backend.utils.ipaddr import classify_ip
from backend.utils.timeutil import utcnow

log = logging.getLogger(__name__)

VT_BASE = "https://www.virustotal.com/api/v3"
OTX_BASE = "https://otx.alienvault.com/api/v1"
HASH_RE = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}$")


def indicator_type(value: str) -> str:
    v = value.strip()
    if classify_ip(v)["valid"]:
        return "ip"
    if HASH_RE.match(v):
        return "hash"
    if DOMAIN_RE.match(v):
        return "domain"
    return "unknown"


def _trim(obj: Any, depth: int = 0) -> Any:
    """Drop nulls/empties and cap nesting so cached raw payloads stay small."""
    if depth > 6:
        return "…"
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if v in (None, "", [], {}):
                continue
            if k in ("last_analysis_results", "crowdsourced_context", "popularity_ranks"):
                continue
            out[k] = _trim(v, depth + 1)
        return out
    if isinstance(obj, list):
        return [_trim(v, depth + 1) for v in obj[:25]]
    if isinstance(obj, str) and len(obj) > 500:
        return obj[:500] + "…"
    return obj


class ThreatIntelService:
    def __init__(self, settings: Settings, store: DocumentStore):
        self.settings = settings
        self.store = store
        self.coll = store["threat_intelligence"]
        self._last_vt_call = 0.0

    # ------------------------------------------------------------------ cache
    def _cached(self, indicator: str, provider: str) -> Optional[dict]:
        doc = self.coll.find_one({"indicator": indicator, "provider": provider})
        if doc and doc.get("expires_at") and doc["expires_at"] > utcnow():
            doc["cache_hit"] = True
            return doc
        return None

    def _save(self, doc: dict) -> dict:
        doc.setdefault("_id", new_id("ti"))
        doc["fetched_at"] = utcnow()
        doc["expires_at"] = utcnow() + timedelta(seconds=self.settings.ti_cache_ttl_seconds)
        self.coll.replace_one({"indicator": doc["indicator"], "provider": doc["provider"]}, doc, upsert=True)
        doc["cache_hit"] = False
        return doc

    def _skeleton(self, indicator: str, itype: str, provider: str, status: str, note: str = "") -> dict:
        return {"indicator": indicator, "type": itype, "provider": provider, "status": status, "note": note,
                "raw": None, "normalized": {}, "ai_interpretation": None}

    # ------------------------------------------------------------------ gating
    def _gate(self, indicator: str, itype: str, provider: str) -> Optional[dict]:
        if itype == "ip":
            c = classify_ip(indicator)
            if c["is_reserved_documentation"]:
                return self._skeleton(indicator, itype, provider, "private_address",
                                      "RFC 5737 documentation address (synthesized attacker context) — not sent to external providers")
            if c["is_private"]:
                return self._skeleton(indicator, itype, provider, "private_address",
                                      "private/reserved address — not sent to external providers")
        if itype == "unknown":
            return self._skeleton(indicator, itype, provider, "unsupported_indicator", "unrecognised indicator format")
        return None

    # ------------------------------------------------------------------ VirusTotal
    def check_virustotal(self, indicator: str, itype: Optional[str] = None) -> dict:
        itype = itype or indicator_type(indicator)
        gated = self._gate(indicator, itype, "virustotal")
        if gated:
            return gated
        cached = self._cached(indicator, "virustotal")
        if cached:
            return cached
        if not self.settings.virustotal_api_key:
            return self._skeleton(indicator, itype, "virustotal", "not_configured", "VIRUSTOTAL_API_KEY not set")
        path = {"ip": f"/ip_addresses/{indicator}", "domain": f"/domains/{indicator}", "hash": f"/files/{indicator}"}[itype]
        # free tier: 4 req/min -> simple spacing
        wait = 15.5 - (time.time() - self._last_vt_call)
        if wait > 0:
            time.sleep(min(wait, 16))
        doc = self._skeleton(indicator, itype, "virustotal", "ok")
        try:
            with httpx.Client(timeout=20) as client:
                r = client.get(VT_BASE + path, headers={"x-apikey": self.settings.virustotal_api_key})
            self._last_vt_call = time.time()
            if r.status_code == 404:
                doc["status"] = "not_found"
            elif r.status_code == 429:
                doc["status"] = "rate_limited"
            elif r.status_code >= 400:
                doc["status"] = "unavailable"
                doc["note"] = f"HTTP {r.status_code}"
            else:
                attrs = r.json().get("data", {}).get("attributes", {})
                doc["raw"] = _trim(attrs)
                stats = attrs.get("last_analysis_stats", {})
                doc["normalized"] = {
                    "malicious_votes": stats.get("malicious", 0), "suspicious_votes": stats.get("suspicious", 0),
                    "harmless_votes": stats.get("harmless", 0), "undetected_votes": stats.get("undetected", 0),
                    "reputation": attrs.get("reputation"), "country": attrs.get("country"), "as_owner": attrs.get("as_owner"),
                    "first_seen": attrs.get("first_submission_date") or attrs.get("creation_date"),
                    "last_seen": attrs.get("last_analysis_date") or attrs.get("last_modification_date"),
                    "tags": attrs.get("tags", [])[:20],
                    "related_domains": [], "related_hashes": [],
                    "verdict": "malicious" if stats.get("malicious", 0) > 0 else ("suspicious" if stats.get("suspicious", 0) > 0 else "clean_or_unknown"),
                }
        except Exception as exc:
            doc["status"] = "unavailable"
            doc["note"] = f"{type(exc).__name__}: {exc}"
        return self._save(doc)

    # ------------------------------------------------------------------ OTX
    def check_otx(self, indicator: str, itype: Optional[str] = None) -> dict:
        itype = itype or indicator_type(indicator)
        gated = self._gate(indicator, itype, "otx")
        if gated:
            return gated
        cached = self._cached(indicator, "otx")
        if cached:
            return cached
        if not self.settings.otx_api_key:
            return self._skeleton(indicator, itype, "otx", "not_configured", "OTX_API_KEY not set")
        section = {"ip": f"/indicators/IPv4/{indicator}/general", "domain": f"/indicators/domain/{indicator}/general",
                   "hash": f"/indicators/file/{indicator}/general"}[itype]
        doc = self._skeleton(indicator, itype, "otx", "ok")
        try:
            with httpx.Client(timeout=20) as client:
                r = client.get(OTX_BASE + section, headers={"X-OTX-API-KEY": self.settings.otx_api_key})
            if r.status_code == 404:
                doc["status"] = "not_found"
            elif r.status_code >= 400:
                doc["status"] = "unavailable"
                doc["note"] = f"HTTP {r.status_code}"
            else:
                data = r.json()
                doc["raw"] = _trim(data)
                pulses = data.get("pulse_info", {})
                plist = pulses.get("pulses", []) or []
                doc["normalized"] = {
                    "pulse_count": pulses.get("count", len(plist)),
                    "pulse_names": [p.get("name") for p in plist[:10]],
                    "tags": sorted({t for p in plist for t in (p.get("tags") or [])})[:25],
                    "malware_families": sorted({m.get("display_name") for p in plist for m in (p.get("malware_families") or []) if isinstance(m, dict)})[:10],
                    "attack_ids": sorted({a.get("id") for p in plist for a in (p.get("attack_ids") or []) if isinstance(a, dict)})[:15],
                    "first_seen": min((p.get("created") for p in plist if p.get("created")), default=None),
                    "last_seen": max((p.get("modified") for p in plist if p.get("modified")), default=None),
                    "reputation": data.get("reputation"), "country": data.get("country_name"), "asn": data.get("asn"),
                    "verdict": "reported_in_pulses" if plist else "no_pulses",
                }
        except Exception as exc:
            doc["status"] = "unavailable"
            doc["note"] = f"{type(exc).__name__}: {exc}"
        return self._save(doc)

    # ------------------------------------------------------------------ combined
    def lookup(self, indicator: str) -> dict:
        itype = indicator_type(indicator)
        return {"indicator": indicator, "type": itype,
                "virustotal": self.check_virustotal(indicator, itype), "otx": self.check_otx(indicator, itype)}

    def list_cached(self, limit: int = 200) -> list:
        return list(self.coll.find({}).sort([("fetched_at", -1)]).limit(limit))
