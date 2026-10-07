"""Smoke test for the post-inference live ingestion bridge.

Usage:
    python scripts/ingest_smoke.py
    python scripts/ingest_smoke.py --base http://localhost:8000

This does not execute attacks. It posts one controlled, already-classified
synthetic security event to validate the ingestion -> alert path.
"""
from __future__ import annotations

import argparse
import json
import urllib.request
from datetime import datetime, timezone


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://localhost:8000")
    args = ap.parse_args()

    payload = {
        "model_version": "integration-smoke",
        "source": "controlled_smoke_test",
        "events": [
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source_ip": "203.0.113.10",
                "destination_ip": "192.0.2.10",
                "device_id": "device-smoke-01",
                "device_type": "iot",
                "protocol": "ICMP",
                "log_source": "smoke_test",
                "features": {
                    "Rate": 100.0,
                    "Srate": 80.0,
                    "Drate": 0.0,
                    "Number": 10.0,
                    "ICMP": 1.0,
                },
                "prediction": {
                    "label": "DDoS-ICMP_Flood",
                    "attack_type": "DDoS ICMP Flood",
                    "category": "DDoS",
                    "confidence": 0.99,
                    "model": "integration-smoke",
                },
            }
        ],
    }

    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        args.base.rstrip("/") + "/api/ingest",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read().decode())
    except Exception as exc:
        print(f"ERROR: {exc}")
        return 1

    print(json.dumps(result, indent=2))
    assert result["status"] == "accepted"
    assert result["events_ingested"] == 1
    print("OK: ingestion bridge accepted the controlled event.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
