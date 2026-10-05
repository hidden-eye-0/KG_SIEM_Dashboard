"""Gemini LLM client (google-genai SDK).

* model name comes from GEMINI_MODEL — never hard-coded
* availability is verified once at startup via models.list() (result cached for /api/health)
* every call has a JSON-schema-constrained response (structured output) where possible
* per-investigation LLM budget is enforced by the caller; this module only counts
* when no key is configured the client reports `available=False` and agents fall back
  to deterministic/heuristic behaviour — the investigation never depends on the LLM
"""
from __future__ import annotations

import json
import logging
import re
import time
from typing import Any, Dict, List, Optional

from backend.config import Settings

log = logging.getLogger(__name__)


class GeminiClient:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.model = settings.gemini_model
        self.enabled = settings.gemini_configured
        self._client = None
        self.availability: Dict[str, Any] = {"checked": False, "available": False, "model": self.model, "note": None}
        self.calls = 0
        self.total_latency_ms = 0.0
        if self.enabled:
            try:
                from google import genai

                self._client = genai.Client(api_key=settings.gemini_api_key)
            except Exception as exc:  # pragma: no cover
                log.error("google-genai init failed: %s", exc)
                self.enabled = False

    # ------------------------------------------------------------------ model check
    def verify_model(self) -> Dict[str, Any]:
        if not self.enabled:
            self.availability = {"checked": True, "available": False, "model": self.model, "note": "GEMINI_API_KEY not set"}
            return self.availability
        try:
            names = []
            for m in self._client.models.list():
                n = getattr(m, "name", "") or ""
                names.append(n.split("/")[-1])
            ok = self.model in names or f"models/{self.model}" in names
            self.availability = {"checked": True, "available": ok, "model": self.model,
                                 "note": None if ok else f"model '{self.model}' not in models.list()",
                                 "candidates": [n for n in names if n.startswith("gemini")][:25]}
        except Exception as exc:
            self.availability = {"checked": True, "available": False, "model": self.model, "note": f"{type(exc).__name__}: {exc}"}
        return self.availability

    @property
    def available(self) -> bool:
        return self.enabled and (self.availability.get("available") or not self.availability.get("checked"))

    # ------------------------------------------------------------------ calls
    def generate_json(self, system: str, prompt: str, schema: Optional[Dict[str, Any]] = None,
                      temperature: float = 0.2, max_output_tokens: int = 2048) -> Optional[Dict[str, Any]]:
        """Return parsed JSON or None on failure (never raises into the agent loop)."""
        if not self.available:
            return None
        from google.genai import types

        t0 = time.perf_counter()
        try:
            cfg = types.GenerateContentConfig(
                system_instruction=system, temperature=temperature, max_output_tokens=max_output_tokens,
                response_mime_type="application/json", **({"response_schema": schema} if schema else {}),
            )
            resp = self._client.models.generate_content(model=self.model, contents=prompt, config=cfg)
            text = resp.text or ""
            self.calls += 1
            self.total_latency_ms += (time.perf_counter() - t0) * 1000
            return _parse_json(text)
        except Exception as exc:
            log.warning("Gemini call failed: %s", exc)
            self.calls += 1
            return None

    def generate_text(self, system: str, prompt: str, temperature: float = 0.3, max_output_tokens: int = 2048) -> Optional[str]:
        if not self.available:
            return None
        from google.genai import types

        t0 = time.perf_counter()
        try:
            cfg = types.GenerateContentConfig(system_instruction=system, temperature=temperature, max_output_tokens=max_output_tokens)
            resp = self._client.models.generate_content(model=self.model, contents=prompt, config=cfg)
            self.calls += 1
            self.total_latency_ms += (time.perf_counter() - t0) * 1000
            return resp.text
        except Exception as exc:
            log.warning("Gemini call failed: %s", exc)
            self.calls += 1
            return None


def _parse_json(text: str) -> Optional[Dict[str, Any]]:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.S)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", text, flags=re.S)
        if m:
            try:
                return json.loads(m.group(0))
            except json.JSONDecodeError:
                return None
    return None


_client: Optional[GeminiClient] = None


def get_gemini() -> GeminiClient:
    global _client
    if _client is None:
        from backend.config import get_settings

        _client = GeminiClient(get_settings())
    return _client
