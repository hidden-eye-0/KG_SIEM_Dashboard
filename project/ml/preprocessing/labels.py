"""Label scope mapping for CICIoT2023 (Phase 1).

IMPORTANT: this module encodes the *expected* raw label strings of the public
CICIoT2023 CSV release together with the conceptual attack type, category and
project scope defined in the project brief.  It does NOT assert that any of these
labels exist in the files provided by the user.  The inspector
(`ml.preprocessing.inspect`) reads the actual files, looks every observed label up
here, and reports:

* observed labels that are expected and in scope,
* observed labels that are expected but excluded (Mirai, out-of-scope DDoS variants,
  optional Browser Hijacking),
* observed labels that are unknown (not in this table),
* expected in-scope labels that are missing from the provided files.

Scope rules (project brief §4 + decision D5):
    DDoS        : ICMP / UDP / TCP / SYN / HTTP floods only
    DoS         : TCP / UDP / SYN / HTTP floods (all four)
    Recon       : Ping Sweep, OS Scan, Host Discovery, Vulnerability Scan, Port Scan
    Web-Based   : SQL Injection, Command Injection, Backdoor Malware, Uploading Attack, XSS
                  (Browser Hijacking optional -> excluded by decision D5)
    Brute Force : Dictionary Brute Force
    Spoofing    : ARP Spoofing, DNS Spoofing
    Mirai       : ALL excluded
    Benign      : required negative class
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

CATEGORY_BENIGN = "Benign"
CATEGORY_DDOS = "DDoS"
CATEGORY_DOS = "DoS"
CATEGORY_RECON = "Reconnaissance"
CATEGORY_WEB = "Web-Based"
CATEGORY_BRUTE = "Brute Force"
CATEGORY_SPOOF = "Spoofing"
CATEGORY_MIRAI = "Mirai"

CATEGORIES: List[str] = [
    CATEGORY_BENIGN,
    CATEGORY_DDOS,
    CATEGORY_DOS,
    CATEGORY_RECON,
    CATEGORY_WEB,
    CATEGORY_BRUTE,
    CATEGORY_SPOOF,
    CATEGORY_MIRAI,
]

# Exclusion reason codes (machine readable, used in reports)
EXCL_MIRAI = "mirai_excluded"
EXCL_NOT_IN_SCOPE = "not_in_project_scope"
EXCL_OPTIONAL = "optional_excluded_decision_D5"


@dataclass(frozen=True)
class LabelInfo:
    raw_label: str
    attack_type: str
    category: str
    in_scope: bool
    exclusion_reason: Optional[str] = None


EXPECTED_LABELS: List[LabelInfo] = [
    # Benign
    LabelInfo("BenignTraffic", "Benign", CATEGORY_BENIGN, True),
    # DDoS - in scope
    LabelInfo("DDoS-ICMP_Flood", "DDoS ICMP Flood", CATEGORY_DDOS, True),
    LabelInfo("DDoS-UDP_Flood", "DDoS UDP Flood", CATEGORY_DDOS, True),
    LabelInfo("DDoS-TCP_Flood", "DDoS TCP Flood", CATEGORY_DDOS, True),
    LabelInfo("DDoS-SYN_Flood", "DDoS SYN Flood", CATEGORY_DDOS, True),
    LabelInfo("DDoS-HTTP_Flood", "DDoS HTTP Flood", CATEGORY_DDOS, True),
    # DDoS - present in the public release but outside the project scope
    LabelInfo("DDoS-ACK_Fragmentation", "DDoS ACK Fragmentation", CATEGORY_DDOS, False, EXCL_NOT_IN_SCOPE),
    LabelInfo("DDoS-ICMP_Fragmentation", "DDoS ICMP Fragmentation", CATEGORY_DDOS, False, EXCL_NOT_IN_SCOPE),
    LabelInfo("DDoS-UDP_Fragmentation", "DDoS UDP Fragmentation", CATEGORY_DDOS, False, EXCL_NOT_IN_SCOPE),
    LabelInfo("DDoS-PSHACK_Flood", "DDoS PSH-ACK Flood", CATEGORY_DDOS, False, EXCL_NOT_IN_SCOPE),
    LabelInfo("DDoS-RSTFINFlood", "DDoS RST-FIN Flood", CATEGORY_DDOS, False, EXCL_NOT_IN_SCOPE),
    LabelInfo("DDoS-SlowLoris", "DDoS SlowLoris", CATEGORY_DDOS, False, EXCL_NOT_IN_SCOPE),
    LabelInfo("DDoS-SynonymousIP_Flood", "DDoS Synonymous IP Flood", CATEGORY_DDOS, False, EXCL_NOT_IN_SCOPE),
    # DoS - all four in scope
    LabelInfo("DoS-TCP_Flood", "DoS TCP Flood", CATEGORY_DOS, True),
    LabelInfo("DoS-UDP_Flood", "DoS UDP Flood", CATEGORY_DOS, True),
    LabelInfo("DoS-SYN_Flood", "DoS SYN Flood", CATEGORY_DOS, True),
    LabelInfo("DoS-HTTP_Flood", "DoS HTTP Flood", CATEGORY_DOS, True),
    # Reconnaissance
    LabelInfo("Recon-PingSweep", "Ping Sweep", CATEGORY_RECON, True),
    LabelInfo("Recon-OSScan", "OS Scan", CATEGORY_RECON, True),
    LabelInfo("Recon-HostDiscovery", "Host Discovery", CATEGORY_RECON, True),
    LabelInfo("VulnerabilityScan", "Vulnerability Scan", CATEGORY_RECON, True),
    LabelInfo("Recon-PortScan", "Port Scan", CATEGORY_RECON, True),
    # Web-based
    LabelInfo("SqlInjection", "SQL Injection", CATEGORY_WEB, True),
    LabelInfo("CommandInjection", "Command Injection", CATEGORY_WEB, True),
    LabelInfo("Backdoor_Malware", "Backdoor Malware", CATEGORY_WEB, True),
    LabelInfo("Uploading_Attack", "Uploading Attack", CATEGORY_WEB, True),
    LabelInfo("XSS", "XSS", CATEGORY_WEB, True),
    LabelInfo("BrowserHijacking", "Browser Hijacking", CATEGORY_WEB, False, EXCL_OPTIONAL),
    # Brute force
    LabelInfo("DictionaryBruteForce", "Dictionary Brute Force", CATEGORY_BRUTE, True),
    # Spoofing
    LabelInfo("MITM-ArpSpoofing", "ARP Spoofing", CATEGORY_SPOOF, True),
    LabelInfo("DNS_Spoofing", "DNS Spoofing", CATEGORY_SPOOF, True),
    # Mirai - all excluded
    LabelInfo("Mirai-greeth_flood", "Mirai GRE-ETH Flood", CATEGORY_MIRAI, False, EXCL_MIRAI),
    LabelInfo("Mirai-greip_flood", "Mirai GRE-IP Flood", CATEGORY_MIRAI, False, EXCL_MIRAI),
    LabelInfo("Mirai-udpplain", "Mirai UDP Plain", CATEGORY_MIRAI, False, EXCL_MIRAI),
]

_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def normalize_key(label: str) -> str:
    """Case/punctuation-insensitive key used to tolerate label spelling variants."""
    return _NON_ALNUM.sub("", str(label).strip().lower())


_EXACT: Dict[str, LabelInfo] = {li.raw_label: li for li in EXPECTED_LABELS}
_NORMALIZED: Dict[str, LabelInfo] = {normalize_key(li.raw_label): li for li in EXPECTED_LABELS}

assert len(_NORMALIZED) == len(EXPECTED_LABELS), "normalized label keys must be unique"


def classify_label(raw: str) -> Tuple[Optional[LabelInfo], str]:
    """Look an observed label up.

    Returns (LabelInfo | None, matched_via) where matched_via is
    'exact' | 'normalized' | 'unknown'.
    """
    if raw is None:
        return None, "unknown"
    s = str(raw).strip()
    if s in _EXACT:
        return _EXACT[s], "exact"
    li = _NORMALIZED.get(normalize_key(s))
    if li is not None:
        return li, "normalized"
    return None, "unknown"


def in_scope_labels() -> List[LabelInfo]:
    return [li for li in EXPECTED_LABELS if li.in_scope]


def mirai_labels() -> List[LabelInfo]:
    return [li for li in EXPECTED_LABELS if li.category == CATEGORY_MIRAI]


def is_mirai(raw: str) -> bool:
    li, _ = classify_label(raw)
    if li is not None:
        return li.category == CATEGORY_MIRAI
    return normalize_key(raw).startswith("mirai")
