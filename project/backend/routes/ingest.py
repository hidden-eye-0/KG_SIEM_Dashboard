"""Controlled live-ingestion bridge.

The final trained detector is intentionally kept in the separate model repository.
This API accepts the canonical *post-inference* event contract so that the SIEM can
be integrated with that detector later without changing alerting/investigation code.

Security properties:
* request models reject unknown fields (including ground_truth)
* batches are hard-capped at 500 events
* prediction confidence is bounded to [0, 1]
* alert generation reuses the existing evidence/alert rules
* ingested events are marked provenance='ingested'
"""
from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator

from backend.deps import Container, current_user, get_container
from backend.routes.common import jsonable
from backend.services.alerting import generate_alerts
from backend.utils.ids import new_id

router = APIRouter()


class Prediction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: str = Field(min_length=1, max_length=128)
    attack_type: str = Field(min_length=1, max_length=128)
    category: str = Field(min_length=1, max_length=64)
    confidence: float = Field(ge=0.0, le=1.0)
    model_version: Optional[str] = Field(default=None, min_length=1, max_length=128)
    model: Optional[str] = Field(default=None, min_length=1, max_length=64)

    @field_validator("confidence")
    @classmethod
    def finite_confidence(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("confidence must be finite")
        return value


class IngestEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp: datetime
    source_ip: str = Field(min_length=1, max_length=64)
    destination_ip: str = Field(min_length=1, max_length=64)
    device_id: Optional[str] = Field(default=None, max_length=128)
    device_type: Optional[str] = Field(default=None, max_length=128)
    protocol: Optional[str] = Field(default=None, max_length=32)
    log_source: str = Field(default="live_ingest", min_length=1, max_length=128)
    features: Dict[str, float] = Field(default_factory=dict, max_length=64)
    prediction: Prediction
    external_id: Optional[str] = Field(default=None, max_length=256)

    @field_validator("timestamp")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @field_validator("features")
    @classmethod
    def validate_features(cls, value: Dict[str, float]) -> Dict[str, float]:
        for name, number in value.items():
            if not name.strip():
                raise ValueError("feature names must be non-empty")
            if not math.isfinite(float(number)):
                raise ValueError(f"feature '{name}' must be finite")
        return {str(k): float(v) for k, v in value.items()}


class IngestBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: List[IngestEvent] = Field(min_length=1, max_length=500)
    model_version: str = Field(min_length=1, max_length=128)
    source: str = Field(default="live_ingest", min_length=1, max_length=128)


@router.post("/ingest", status_code=202)
def ingest_batch(body: IngestBatch, c: Container = Depends(get_container), user: dict = Depends(current_user)):
    """Ingest post-inference security events and run the existing alert generator.

    The endpoint is intentionally model-agnostic. The separate final detector can
    POST its predictions here later; the investigation stack then sees the same
    event/alert contract used by the current dataset pipeline.
    """
    run_id = new_id("ing")
    docs = []
    for item in body.events:
        pred = item.prediction.model_dump()
        if pred.get("model_version") and pred["model_version"] != body.model_version:
            raise HTTPException(400, "event prediction.model_version must match batch model_version")
        pred["model_version"] = body.model_version

        doc = {
            "_id": new_id("evt"),
            "external_id": item.external_id,
            "timestamp": item.timestamp,
            "source_ip": item.source_ip,
            "destination_ip": item.destination_ip,
            "device_id": item.device_id,
            "device_type": item.device_type,
            "protocol": item.protocol,
            "log_source": item.log_source,
            "features": item.features,
            "prediction": pred,
            "context": {
                "provenance": "ingested",
                "ingestion_run_id": run_id,
                "source": body.source,
            },
            "dataset": {"source": body.source},
            "ingestion_run_id": run_id,
        }
        docs.append(doc)

    run_doc = {
        "_id": run_id,
        "status": "running",
        "created_at": datetime.now(timezone.utc),
        "created_by": user.get("username"),
        "source": body.source,
        "model_version": body.model_version,
        "event_count": len(docs),
        "alert_count": 0,
    }
    c.store["ingestion_runs"].insert_one(run_doc)

    try:
        c.store["security_events"].insert_many(docs, ordered=True)

        profiles_by_label = {
            p.get("raw_label"): p
            for p in c.store["behavior_profiles"].find({"kind": {"$ne": "global"}})
            if p.get("raw_label")
        }
        alerts = generate_alerts(docs, profiles_by_label, body.model_version)
        if alerts:
            c.store["alerts"].insert_many(alerts, ordered=True)

        c.store["ingestion_runs"].update_one(
            {"_id": run_id},
            {"$set": {"status": "completed", "alert_count": len(alerts), "finished_at": datetime.now(timezone.utc)}},
        )
    except Exception as exc:
        c.store["ingestion_runs"].update_one(
            {"_id": run_id},
            {"$set": {"status": "failed", "error_type": type(exc).__name__, "finished_at": datetime.now(timezone.utc)}},
        )
        raise HTTPException(500, "ingestion failed; check backend logs") from exc

    return jsonable({
        "status": "accepted",
        "ingestion_run_id": run_id,
        "events_ingested": len(docs),
        "alerts_created": len(alerts),
        "model_version": body.model_version,
        "provenance": "ingested",
    })
