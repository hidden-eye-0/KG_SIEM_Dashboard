"""Feature manifest for the CICIoT2023 flow representation.

The 46 feature names below are the *expected* CSV columns (verified against the actual
files by `ml.preprocessing.inspect`).  Feature *groups* are used for behavioural
profiling summaries; membership is structural (what the column measures), not a claim
about importance — importance is measured experimentally (Phase 4).
"""
from __future__ import annotations

from typing import Dict, List

TARGET = "label"

FEATURES: List[str] = [
    "flow_duration", "Header_Length", "Protocol Type", "Duration", "Rate", "Srate", "Drate",
    "fin_flag_number", "syn_flag_number", "rst_flag_number", "psh_flag_number", "ack_flag_number",
    "ece_flag_number", "cwr_flag_number", "ack_count", "syn_count", "fin_count", "urg_count",
    "rst_count", "HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC", "TCP", "UDP", "DHCP",
    "ARP", "ICMP", "IPv", "LLC", "Tot sum", "Min", "Max", "AVG", "Std", "Tot size", "IAT",
    "Number", "Magnitue", "Radius", "Covariance", "Variance", "Weight",
]

FEATURE_GROUPS: Dict[str, List[str]] = {
    "traffic": ["Rate", "Srate", "Drate", "Number"],
    "temporal": ["flow_duration", "Duration", "IAT"],
    "tcp_flags": ["fin_flag_number", "syn_flag_number", "rst_flag_number", "psh_flag_number",
                  "ack_flag_number", "ece_flag_number", "cwr_flag_number"],
    "flag_counts": ["ack_count", "syn_count", "fin_count", "urg_count", "rst_count"],
    "protocol_indicators": ["HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC", "TCP", "UDP",
                            "DHCP", "ARP", "ICMP", "IPv", "LLC"],
    "packet_statistics": ["Header_Length", "Protocol Type", "Tot sum", "Min", "Max", "AVG", "Std",
                          "Tot size", "Magnitue", "Radius", "Covariance", "Variance", "Weight"],
}

PROTOCOL_INDICATORS = FEATURE_GROUPS["protocol_indicators"]
BINARY_FEATURES = FEATURE_GROUPS["tcp_flags"] + PROTOCOL_INDICATORS

# Human-readable notes (structural descriptions only; never used as evidence semantics)
FEATURE_NOTES: Dict[str, str] = {
    "Magnitue": "spelled 'Magnitue' in the public CSV header (kept verbatim)",
    "Protocol Type": "numeric IP protocol identifier as exported by the dataset tooling",
    "IPv": "IP-layer indicator",
    "LLC": "logical-link-control indicator",
}


def group_of(feature: str) -> str:
    for g, cols in FEATURE_GROUPS.items():
        if feature in cols:
            return g
    return "other"


assert len(FEATURES) == 46, "expected 46 features"
assert sorted(sum(FEATURE_GROUPS.values(), [])) == sorted(FEATURES), "groups must partition the features"
