"""Document store access.

* `MONGODB_URI` set  -> real MongoDB (Atlas or local) via pymongo.
* `MONGODB_URI` empty -> in-process `mongomock` database with the *same* API, so the
  whole application (tools, agents, API) runs without any external service.

The synchronous pymongo API is used deliberately: all investigation work runs in a
worker thread (see services/runner.py) and FastAPI handlers call the store through
`run_in_threadpool`-safe short operations.  This keeps one code path for both backends.
"""
from __future__ import annotations

import logging
from typing import Optional

from backend.config import Settings

log = logging.getLogger(__name__)

COLLECTIONS = [
    "security_events",
    "alerts",
    "investigations",
    "threat_intelligence",
    "behavior_profiles",
    "reports",
    "models",
    "dataset_stats",
    "evaluation_runs",
    "ingestion_runs",
    "scenarios",
]

# Only the indexes that queries actually use (brief §14: do not index everything).
INDEXES = {
    "security_events": [
        ([("timestamp", 1)], {}),
        ([("source_ip", 1), ("timestamp", 1)], {}),
        ([("destination_ip", 1), ("timestamp", 1)], {}),
        ([("device_id", 1), ("timestamp", 1)], {}),
        ([("protocol", 1)], {}),
        ([("prediction.attack_type", 1), ("timestamp", 1)], {}),
        ([("ground_truth.scenario_id", 1)], {}),
    ],
    "alerts": [
        ([("created_at", -1)], {}),
        ([("severity", 1), ("status", 1)], {}),
        ([("source_ip", 1), ("first_seen", 1)], {}),
        ([("category", 1)], {}),
    ],
    "investigations": [
        ([("alert_id", 1)], {}),
        ([("status", 1), ("started_at", -1)], {}),
    ],
    "threat_intelligence": [
        ([("indicator", 1), ("provider", 1)], {"unique": True}),
    ],
    "reports": [([("investigation_id", 1)], {})],
    "behavior_profiles": [([("attack_type", 1)], {})],
}


class DocumentStore:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.backend = "mongodb" if settings.mongo_configured else "mongomock"
        self._client = None
        self.db = None

    # ------------------------------------------------------------------ lifecycle
    def connect(self) -> "DocumentStore":
        if self.backend == "mongodb":
            from pymongo import MongoClient

            self._client = MongoClient(self.settings.mongodb_uri, serverSelectionTimeoutMS=8000)
            try:
                self._client.admin.command("ping")
                log.info("Connected to MongoDB (%s)", self.settings.mongodb_db)
            except Exception as exc:  # fall back rather than crash the demo
                log.error("MongoDB unreachable (%s); falling back to in-process store", exc)
                self.backend = "mongomock"
        if self.backend == "mongomock":
            import mongomock

            self._client = mongomock.MongoClient()
            log.warning("Using in-process mongomock store (set MONGODB_URI for persistence)")
        self.db = self._client[self.settings.mongodb_db]
        self.ensure_indexes()
        return self

    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            except Exception:  # pragma: no cover
                pass

    def ensure_indexes(self) -> None:
        for coll, specs in INDEXES.items():
            for keys, kwargs in specs:
                try:
                    self.db[coll].create_index(keys, **kwargs)
                except Exception as exc:  # pragma: no cover
                    log.warning("index creation failed on %s %s: %s", coll, keys, exc)

    # ------------------------------------------------------------------ helpers
    def ping(self) -> dict:
        try:
            if self.backend == "mongodb":
                self._client.admin.command("ping")
            return {"status": "ok", "backend": self.backend, "database": self.settings.mongodb_db}
        except Exception as exc:
            return {"status": "error", "backend": self.backend, "error": str(exc)}

    def counts(self) -> dict:
        out = {}
        for c in COLLECTIONS:
            try:
                out[c] = self.db[c].estimated_document_count()
            except Exception:
                out[c] = self.db[c].count_documents({})
        return out

    def drop_all(self) -> None:
        for c in COLLECTIONS:
            self.db[c].delete_many({})

    def __getitem__(self, name: str):
        return self.db[name]


_store: Optional[DocumentStore] = None


def get_store() -> DocumentStore:
    global _store
    if _store is None:
        from backend.config import get_settings

        _store = DocumentStore(get_settings()).connect()
    return _store


def set_store(store: DocumentStore) -> None:
    global _store
    _store = store
