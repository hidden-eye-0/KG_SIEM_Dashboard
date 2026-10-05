"""MITRE ATT&CK mapping.

Two layers, both offline (no API key):

1. A **curated mapping table** from CICIoT2023 attack classes to ATT&CK technique ids.
   Each entry carries a confidence and a rationale.  These mappings are *analyst-curated
   associations between the labelled attack class and ATT&CK behaviour*, not conclusions
   drawn from any individual flow.
2. **Verification against the official ATT&CK STIX bundle** when it is available locally
   (`data/mitre/enterprise-attack.json`, downloadable with `python -m backend.services.mitre
   download`).  Verified entries get `verified: true` and the official name/URL; otherwise
   the curated name is used and `verified: false` is shown in the UI.
"""
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Dict, List, Optional

log = logging.getLogger(__name__)

ATTACK_STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
LOCAL_BUNDLE = Path(__file__).resolve().parents[2] / "data" / "mitre" / "enterprise-attack.json"

# attack_type -> list of mappings
CURATED: Dict[str, List[dict]] = {
    # DDoS / DoS
    "DDoS ICMP Flood": [{"technique_id": "T1498.001", "name": "Network Denial of Service: Direct Network Flood", "tactic": "Impact", "confidence": "high"}],
    "DDoS UDP Flood": [{"technique_id": "T1498.001", "name": "Network Denial of Service: Direct Network Flood", "tactic": "Impact", "confidence": "high"}],
    "DDoS TCP Flood": [{"technique_id": "T1498.001", "name": "Network Denial of Service: Direct Network Flood", "tactic": "Impact", "confidence": "high"}],
    "DDoS SYN Flood": [{"technique_id": "T1498.001", "name": "Network Denial of Service: Direct Network Flood", "tactic": "Impact", "confidence": "high"}],
    "DDoS HTTP Flood": [{"technique_id": "T1499.002", "name": "Endpoint Denial of Service: Service Exhaustion Flood", "tactic": "Impact", "confidence": "high"}],
    "DoS TCP Flood": [{"technique_id": "T1498.001", "name": "Network Denial of Service: Direct Network Flood", "tactic": "Impact", "confidence": "high"}],
    "DoS UDP Flood": [{"technique_id": "T1498.001", "name": "Network Denial of Service: Direct Network Flood", "tactic": "Impact", "confidence": "high"}],
    "DoS SYN Flood": [{"technique_id": "T1498.001", "name": "Network Denial of Service: Direct Network Flood", "tactic": "Impact", "confidence": "high"}],
    "DoS HTTP Flood": [{"technique_id": "T1499.002", "name": "Endpoint Denial of Service: Service Exhaustion Flood", "tactic": "Impact", "confidence": "high"}],
    # Reconnaissance
    "Ping Sweep": [{"technique_id": "T1018", "name": "Remote System Discovery", "tactic": "Discovery", "confidence": "medium"},
                   {"technique_id": "T1595.001", "name": "Active Scanning: Scanning IP Blocks", "tactic": "Reconnaissance", "confidence": "medium"}],
    "Host Discovery": [{"technique_id": "T1018", "name": "Remote System Discovery", "tactic": "Discovery", "confidence": "medium"},
                       {"technique_id": "T1595.001", "name": "Active Scanning: Scanning IP Blocks", "tactic": "Reconnaissance", "confidence": "medium"}],
    "Port Scan": [{"technique_id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery", "confidence": "high"}],
    "OS Scan": [{"technique_id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery", "confidence": "medium"},
                {"technique_id": "T1592.002", "name": "Gather Victim Host Information: Software", "tactic": "Reconnaissance", "confidence": "low"}],
    "Vulnerability Scan": [{"technique_id": "T1595.002", "name": "Active Scanning: Vulnerability Scanning", "tactic": "Reconnaissance", "confidence": "high"}],
    # Web-based
    "SQL Injection": [{"technique_id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access", "confidence": "medium"}],
    "Command Injection": [{"technique_id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access", "confidence": "medium"},
                          {"technique_id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution", "confidence": "low"}],
    "XSS": [{"technique_id": "T1189", "name": "Drive-by Compromise", "tactic": "Initial Access", "confidence": "low"},
            {"technique_id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access", "confidence": "low"}],
    "Uploading Attack": [{"technique_id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control", "confidence": "low"},
                         {"technique_id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access", "confidence": "low"}],
    "Backdoor Malware": [{"technique_id": "T1071.001", "name": "Application Layer Protocol: Web Protocols", "tactic": "Command and Control", "confidence": "low"},
                         {"technique_id": "T1505.003", "name": "Server Software Component: Web Shell", "tactic": "Persistence", "confidence": "low"}],
    "Browser Hijacking": [{"technique_id": "T1176", "name": "Browser Extensions", "tactic": "Persistence", "confidence": "low"}],
    # Brute force
    "Dictionary Brute Force": [{"technique_id": "T1110.001", "name": "Brute Force: Password Guessing", "tactic": "Credential Access", "confidence": "high"}],
    # Spoofing
    "ARP Spoofing": [{"technique_id": "T1557.002", "name": "Adversary-in-the-Middle: ARP Cache Poisoning", "tactic": "Credential Access / Collection", "confidence": "high"}],
    "DNS Spoofing": [{"technique_id": "T1557", "name": "Adversary-in-the-Middle", "tactic": "Credential Access / Collection", "confidence": "medium"},
                     {"technique_id": "T1584.002", "name": "Compromise Infrastructure: DNS Server", "tactic": "Resource Development", "confidence": "low"}],
}

RATIONALE = ("Curated association between the labelled {attack} class and ATT&CK technique {tid}; "
             "the network-flow evidence supports the class label, not the technique's internal actions.")


class MitreService:
    def __init__(self, bundle_path: Path = LOCAL_BUNDLE):
        self.bundle_path = bundle_path
        self.techniques: Dict[str, dict] = {}
        self.attack_version: Optional[str] = None
        self._load_bundle()

    def _load_bundle(self) -> None:
        if not self.bundle_path.exists():
            log.info("ATT&CK STIX bundle not present at %s (curated names will be used; run `python -m backend.services.mitre download`)", self.bundle_path)
            return
        try:
            data = json.loads(self.bundle_path.read_text())
            for obj in data.get("objects", []):
                if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
                    continue
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                        self.techniques[ref["external_id"]] = {
                            "technique_id": ref["external_id"], "name": obj.get("name"), "url": ref.get("url"),
                            "tactics": [p.get("phase_name") for p in obj.get("kill_chain_phases", [])],
                            "description": (obj.get("description") or "")[:600],
                        }
                if obj.get("type") == "x-mitre-collection":
                    self.attack_version = obj.get("x_mitre_version")
            for obj in data.get("objects", []):
                if obj.get("type") == "x-mitre-collection":
                    self.attack_version = obj.get("x_mitre_version")
            log.info("loaded %d ATT&CK techniques (version %s)", len(self.techniques), self.attack_version)
        except Exception as exc:  # pragma: no cover
            log.warning("failed to load ATT&CK bundle: %s", exc)

    @property
    def bundle_loaded(self) -> bool:
        return bool(self.techniques)

    def map_attack_type(self, attack_type: str) -> List[dict]:
        out = []
        for m in CURATED.get(attack_type, []):
            official = self.techniques.get(m["technique_id"])
            out.append({
                "attack_type": attack_type,
                "technique_id": m["technique_id"],
                "name": official["name"] if official else m["name"],
                "tactic": m["tactic"],
                "tactics_official": official["tactics"] if official else None,
                "url": official["url"] if official else f"https://attack.mitre.org/techniques/{m['technique_id'].replace('.', '/')}/",
                "confidence": m["confidence"],
                "verified_against_bundle": bool(official),
                "source": "curated_mapping" + ("+attack_stix" if official else ""),
                "rationale": RATIONALE.format(attack=attack_type, tid=m["technique_id"]),
            })
        return out

    def get_technique(self, technique_id: str) -> Optional[dict]:
        t = self.techniques.get(technique_id)
        if t:
            return {**t, "verified_against_bundle": True}
        for maps in CURATED.values():
            for m in maps:
                if m["technique_id"] == technique_id:
                    return {"technique_id": technique_id, "name": m["name"], "tactics": [m["tactic"]],
                            "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
                            "verified_against_bundle": False}
        return None


def download_bundle(dest: Path = LOCAL_BUNDLE) -> Path:
    import httpx

    dest.parent.mkdir(parents=True, exist_ok=True)
    with httpx.stream("GET", ATTACK_STIX_URL, timeout=120, follow_redirects=True) as r:
        r.raise_for_status()
        with open(dest, "wb") as fh:
            for chunk in r.iter_bytes():
                fh.write(chunk)
    return dest


_svc: Optional[MitreService] = None


def get_mitre() -> MitreService:
    global _svc
    if _svc is None:
        _svc = MitreService()
    return _svc


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "download":
        p = download_bundle()
        print("downloaded", p, p.stat().st_size, "bytes")
