"""SYNTHETIC demonstration flows in the CICIoT2023 *shape* (46 features + label).

Purpose
-------
The application must run end to end before the CICIoT2023 files are placed in
``DATASET_DIR``.  This module generates clearly-labelled synthetic flows so that every
downstream component (preprocessing, models, behavioural profiles, ingestion, alerts,
investigation, graph, report, dashboard) can be exercised.

Every artefact derived from these flows carries ``data_source = "synthetic_demo"`` and
the UI shows a provenance banner.  **Nothing produced from this module is a
statistic of CICIoT2023.**  The per-class parameters below are hand-written design
choices that make the classes distinguishable in a plausible way (e.g. SYN floods have
SYN flags set and high rates); they are not measured from the dataset.

When real files are present, ``ml.pipeline`` uses them instead and this module is not
called.
"""
from __future__ import annotations

from typing import Dict, Tuple

import numpy as np
import pandas as pd

from ml.features import FEATURES, TARGET
from ml.preprocessing.labels import in_scope_labels

DATA_SOURCE = "synthetic_demo"


def _lognormal(rng, mean, sigma, n):
    return rng.lognormal(mean=np.log(max(mean, 1e-9)), sigma=sigma, size=n)


def _bern(rng, p, n):
    return (rng.random(n) < p).astype(np.float32)


# Per-class overrides. Values are (kind, params). kind: 'b' Bernoulli p, 'ln' lognormal(mean, sigma),
# 'c' constant, 'u' uniform(lo, hi).  Anything not overridden falls back to BASE (benign-like).
BASE: Dict[str, Tuple] = {
    "flow_duration": ("ln", 2.0, 1.5), "Header_Length": ("ln", 8000, 1.6), "Protocol Type": ("choice", [6, 17, 1], [0.7, 0.25, 0.05]),
    "Duration": ("ln", 64, 0.3), "Rate": ("ln", 40, 1.3), "Srate": ("ln", 40, 1.3), "Drate": ("c", 0.0),
    "fin_flag_number": ("b", 0.15), "syn_flag_number": ("b", 0.2), "rst_flag_number": ("b", 0.1), "psh_flag_number": ("b", 0.35),
    "ack_flag_number": ("b", 0.6), "ece_flag_number": ("b", 0.01), "cwr_flag_number": ("b", 0.01),
    "ack_count": ("ln", 1.0, 0.8), "syn_count": ("ln", 0.6, 0.8), "fin_count": ("ln", 0.4, 0.8), "urg_count": ("ln", 0.5, 1.0), "rst_count": ("ln", 0.5, 1.2),
    "HTTP": ("b", 0.2), "HTTPS": ("b", 0.35), "DNS": ("b", 0.15), "Telnet": ("b", 0.01), "SMTP": ("b", 0.01), "SSH": ("b", 0.03), "IRC": ("b", 0.005),
    "TCP": ("b", 0.7), "UDP": ("b", 0.25), "DHCP": ("b", 0.02), "ARP": ("b", 0.02), "ICMP": ("b", 0.05), "IPv": ("b", 0.97), "LLC": ("b", 0.97),
    "Tot sum": ("ln", 5000, 1.0), "Min": ("ln", 54, 0.3), "Max": ("ln", 900, 0.8), "AVG": ("ln", 300, 0.7), "Std": ("ln", 250, 0.9),
    "Tot size": ("ln", 300, 0.7), "IAT": ("ln", 8.0e7, 0.4), "Number": ("ln", 9.5, 0.3), "Magnitue": ("ln", 22, 0.4), "Radius": ("ln", 350, 0.9),
    "Covariance": ("ln", 90000, 1.2), "Variance": ("u", 0.05, 1.0), "Weight": ("ln", 141, 0.3),
}

CLASS_OVERRIDES: Dict[str, Dict[str, Tuple]] = {
    "BenignTraffic": {},
    # ---------------- DDoS (many sources -> very high aggregate rate, low variance flows)
    "DDoS-ICMP_Flood": {"ICMP": ("b", 0.99), "TCP": ("b", 0.01), "UDP": ("b", 0.01), "Protocol Type": ("c", 1), "Rate": ("ln", 9000, 0.6), "Srate": ("ln", 9000, 0.6),
                        "syn_flag_number": ("b", 0.0), "ack_flag_number": ("b", 0.0), "psh_flag_number": ("b", 0.0), "HTTP": ("b", 0), "HTTPS": ("b", 0), "DNS": ("b", 0),
                        "Header_Length": ("ln", 60, 0.3), "Tot size": ("ln", 42, 0.05), "Min": ("ln", 42, 0.05), "Max": ("ln", 42, 0.05), "AVG": ("ln", 42, 0.05),
                        "Std": ("ln", 0.5, 1.0), "IAT": ("ln", 1.5e8, 0.05), "Variance": ("u", 0.0, 0.05), "Tot sum": ("ln", 400, 0.2), "Radius": ("ln", 0.7, 1.0)},
    "DDoS-UDP_Flood": {"UDP": ("b", 0.99), "TCP": ("b", 0.01), "Protocol Type": ("c", 17), "Rate": ("ln", 7000, 0.6), "Srate": ("ln", 7000, 0.6),
                       "syn_flag_number": ("b", 0.0), "ack_flag_number": ("b", 0.0), "HTTP": ("b", 0), "HTTPS": ("b", 0), "DNS": ("b", 0.02),
                       "Tot size": ("ln", 50, 0.1), "Min": ("ln", 50, 0.1), "Max": ("ln", 50, 0.1), "AVG": ("ln", 50, 0.1), "Std": ("ln", 0.5, 1.0),
                       "IAT": ("ln", 1.5e8, 0.05), "Variance": ("u", 0.0, 0.05), "Header_Length": ("ln", 40, 0.4)},
    "DDoS-TCP_Flood": {"TCP": ("b", 0.99), "UDP": ("b", 0.0), "Protocol Type": ("c", 6), "Rate": ("ln", 6000, 0.6), "Srate": ("ln", 6000, 0.6),
                       "ack_flag_number": ("b", 0.5), "syn_flag_number": ("b", 0.3), "rst_flag_number": ("b", 0.3), "psh_flag_number": ("b", 0.2), "ack_count": ("ln", 2.5, 0.5),
                       "HTTP": ("b", 0), "HTTPS": ("b", 0), "Tot size": ("ln", 54, 0.05), "Min": ("ln", 54, 0.05), "Max": ("ln", 54, 0.05), "AVG": ("ln", 54, 0.05),
                       "Std": ("ln", 0.3, 1.0), "IAT": ("ln", 1.5e8, 0.05), "Variance": ("u", 0.0, 0.05)},
    "DDoS-SYN_Flood": {"TCP": ("b", 0.99), "UDP": ("b", 0.0), "Protocol Type": ("c", 6), "Rate": ("ln", 6500, 0.6), "Srate": ("ln", 6500, 0.6),
                       "syn_flag_number": ("b", 0.98), "ack_flag_number": ("b", 0.02), "psh_flag_number": ("b", 0.0), "fin_flag_number": ("b", 0.0),
                       "syn_count": ("ln", 3.0, 0.4), "ack_count": ("ln", 0.05, 1.0), "HTTP": ("b", 0), "HTTPS": ("b", 0),
                       "Tot size": ("ln", 54, 0.05), "Min": ("ln", 54, 0.05), "Max": ("ln", 54, 0.05), "AVG": ("ln", 54, 0.05), "Std": ("ln", 0.2, 1.0),
                       "IAT": ("ln", 1.5e8, 0.05), "Variance": ("u", 0.0, 0.05)},
    "DDoS-HTTP_Flood": {"TCP": ("b", 0.99), "Protocol Type": ("c", 6), "HTTP": ("b", 0.97), "HTTPS": ("b", 0.02), "Rate": ("ln", 1200, 0.7), "Srate": ("ln", 1200, 0.7),
                        "psh_flag_number": ("b", 0.9), "ack_flag_number": ("b", 0.95), "syn_flag_number": ("b", 0.1), "ack_count": ("ln", 3.0, 0.4),
                        "Tot size": ("ln", 420, 0.3), "AVG": ("ln", 420, 0.3), "Max": ("ln", 900, 0.4), "Header_Length": ("ln", 60000, 0.8), "Tot sum": ("ln", 12000, 0.5)},
    # ---------------- DoS (single source -> lower aggregate rate, otherwise similar signature)
    "DoS-TCP_Flood": {"TCP": ("b", 0.99), "UDP": ("b", 0.0), "Protocol Type": ("c", 6), "Rate": ("ln", 1500, 0.7), "Srate": ("ln", 1500, 0.7),
                      "ack_flag_number": ("b", 0.5), "syn_flag_number": ("b", 0.3), "rst_flag_number": ("b", 0.35), "ack_count": ("ln", 2.0, 0.5),
                      "HTTP": ("b", 0), "HTTPS": ("b", 0), "Tot size": ("ln", 54, 0.08), "Min": ("ln", 54, 0.08), "Max": ("ln", 54, 0.08), "AVG": ("ln", 54, 0.08),
                      "Std": ("ln", 0.4, 1.0), "IAT": ("ln", 1.5e8, 0.08), "Variance": ("u", 0.0, 0.08), "Weight": ("ln", 38, 0.3), "Number": ("ln", 5.5, 0.3)},
    "DoS-UDP_Flood": {"UDP": ("b", 0.99), "TCP": ("b", 0.01), "Protocol Type": ("c", 17), "Rate": ("ln", 1800, 0.7), "Srate": ("ln", 1800, 0.7),
                      "syn_flag_number": ("b", 0.0), "ack_flag_number": ("b", 0.0), "HTTP": ("b", 0), "HTTPS": ("b", 0),
                      "Tot size": ("ln", 50, 0.12), "Min": ("ln", 50, 0.12), "Max": ("ln", 50, 0.12), "AVG": ("ln", 50, 0.12), "Std": ("ln", 0.6, 1.0),
                      "IAT": ("ln", 1.5e8, 0.08), "Variance": ("u", 0.0, 0.08), "Weight": ("ln", 38, 0.3), "Number": ("ln", 5.5, 0.3), "Header_Length": ("ln", 40, 0.4)},
    "DoS-SYN_Flood": {"TCP": ("b", 0.99), "UDP": ("b", 0.0), "Protocol Type": ("c", 6), "Rate": ("ln", 1700, 0.7), "Srate": ("ln", 1700, 0.7),
                      "syn_flag_number": ("b", 0.97), "ack_flag_number": ("b", 0.03), "psh_flag_number": ("b", 0.0), "syn_count": ("ln", 2.5, 0.4), "ack_count": ("ln", 0.08, 1.0),
                      "HTTP": ("b", 0), "HTTPS": ("b", 0), "Tot size": ("ln", 54, 0.08), "Min": ("ln", 54, 0.08), "Max": ("ln", 54, 0.08), "AVG": ("ln", 54, 0.08),
                      "Std": ("ln", 0.3, 1.0), "IAT": ("ln", 1.5e8, 0.08), "Variance": ("u", 0.0, 0.08), "Weight": ("ln", 38, 0.3), "Number": ("ln", 5.5, 0.3)},
    "DoS-HTTP_Flood": {"TCP": ("b", 0.99), "Protocol Type": ("c", 6), "HTTP": ("b", 0.96), "HTTPS": ("b", 0.02), "Rate": ("ln", 350, 0.7), "Srate": ("ln", 350, 0.7),
                       "psh_flag_number": ("b", 0.9), "ack_flag_number": ("b", 0.95), "ack_count": ("ln", 2.5, 0.4), "Tot size": ("ln", 400, 0.3), "AVG": ("ln", 400, 0.3),
                       "Header_Length": ("ln", 30000, 0.8), "Tot sum": ("ln", 9000, 0.5), "Weight": ("ln", 38, 0.3), "Number": ("ln", 5.5, 0.3)},
    # ---------------- Reconnaissance (low rate, probing patterns)
    "Recon-PingSweep": {"ICMP": ("b", 0.95), "TCP": ("b", 0.05), "UDP": ("b", 0.0), "Protocol Type": ("c", 1), "Rate": ("ln", 12, 0.8), "Srate": ("ln", 12, 0.8),
                        "syn_flag_number": ("b", 0.0), "ack_flag_number": ("b", 0.0), "HTTP": ("b", 0), "HTTPS": ("b", 0), "DNS": ("b", 0),
                        "Tot size": ("ln", 60, 0.2), "AVG": ("ln", 60, 0.2), "Max": ("ln", 98, 0.2), "Header_Length": ("ln", 120, 0.5), "flow_duration": ("ln", 0.3, 1.0), "Duration": ("ln", 64, 0.1)},
    "Recon-OSScan": {"TCP": ("b", 0.97), "Protocol Type": ("c", 6), "Rate": ("ln", 90, 0.9), "Srate": ("ln", 90, 0.9), "syn_flag_number": ("b", 0.45), "fin_flag_number": ("b", 0.3),
                     "psh_flag_number": ("b", 0.3), "rst_flag_number": ("b", 0.4), "ack_flag_number": ("b", 0.35), "urg_count": ("ln", 1.5, 0.6), "rst_count": ("ln", 1.8, 0.6),
                     "HTTP": ("b", 0.02), "HTTPS": ("b", 0.02), "Tot size": ("ln", 58, 0.15), "AVG": ("ln", 58, 0.15), "Header_Length": ("ln", 200, 0.6), "flow_duration": ("ln", 0.6, 1.0)},
    "Recon-HostDiscovery": {"ARP": ("b", 0.55), "ICMP": ("b", 0.4), "TCP": ("b", 0.1), "UDP": ("b", 0.05), "Protocol Type": ("choice", [1, 6, 0], [0.5, 0.2, 0.3]),
                            "Rate": ("ln", 25, 0.9), "Srate": ("ln", 25, 0.9), "syn_flag_number": ("b", 0.05), "ack_flag_number": ("b", 0.02), "HTTP": ("b", 0), "HTTPS": ("b", 0),
                            "Tot size": ("ln", 50, 0.25), "AVG": ("ln", 50, 0.25), "Header_Length": ("ln", 80, 0.6), "IPv": ("b", 0.6), "LLC": ("b", 0.98), "flow_duration": ("ln", 0.4, 1.0)},
    "VulnerabilityScan": {"TCP": ("b", 0.98), "Protocol Type": ("c", 6), "HTTP": ("b", 0.55), "HTTPS": ("b", 0.15), "Rate": ("ln", 220, 0.8), "Srate": ("ln", 220, 0.8),
                          "syn_flag_number": ("b", 0.35), "psh_flag_number": ("b", 0.5), "ack_flag_number": ("b", 0.7), "rst_flag_number": ("b", 0.2), "rst_count": ("ln", 1.2, 0.6),
                          "Header_Length": ("ln", 50000, 0.9), "Tot sum": ("ln", 15000, 0.7), "flow_duration": ("ln", 25, 1.0), "Tot size": ("ln", 350, 0.5), "Std": ("ln", 400, 0.6)},
    "Recon-PortScan": {"TCP": ("b", 0.99), "Protocol Type": ("c", 6), "Rate": ("ln", 150, 0.9), "Srate": ("ln", 150, 0.9), "syn_flag_number": ("b", 0.9), "ack_flag_number": ("b", 0.08),
                       "rst_flag_number": ("b", 0.55), "rst_count": ("ln", 3.0, 0.5), "syn_count": ("ln", 1.5, 0.5), "HTTP": ("b", 0.01), "HTTPS": ("b", 0.01),
                       "Tot size": ("ln", 54, 0.05), "AVG": ("ln", 54, 0.05), "Max": ("ln", 60, 0.1), "Header_Length": ("ln", 160, 0.5), "flow_duration": ("ln", 0.2, 1.0), "IAT": ("ln", 1.2e8, 0.3)},
    # ---------------- Web-based (HTTP payload-carrying flows, low rate)
    "SqlInjection": {"TCP": ("b", 0.99), "Protocol Type": ("c", 6), "HTTP": ("b", 0.95), "HTTPS": ("b", 0.03), "Rate": ("ln", 15, 0.9), "Srate": ("ln", 15, 0.9),
                     "psh_flag_number": ("b", 0.92), "ack_flag_number": ("b", 0.97), "syn_flag_number": ("b", 0.08), "Tot size": ("ln", 700, 0.4), "AVG": ("ln", 700, 0.4),
                     "Max": ("ln", 1400, 0.3), "Tot sum": ("ln", 9000, 0.6), "Header_Length": ("ln", 25000, 0.9), "flow_duration": ("ln", 6, 1.0), "Std": ("ln", 480, 0.5)},
    "CommandInjection": {"TCP": ("b", 0.99), "Protocol Type": ("c", 6), "HTTP": ("b", 0.94), "HTTPS": ("b", 0.03), "Rate": ("ln", 18, 0.9), "Srate": ("ln", 18, 0.9),
                         "psh_flag_number": ("b", 0.9), "ack_flag_number": ("b", 0.97), "Tot size": ("ln", 520, 0.45), "AVG": ("ln", 520, 0.45), "Max": ("ln", 1300, 0.35),
                         "Tot sum": ("ln", 7000, 0.6), "Header_Length": ("ln", 20000, 0.9), "flow_duration": ("ln", 9, 1.0), "Std": ("ln", 560, 0.5), "Radius": ("ln", 800, 0.6)},
    "Backdoor_Malware": {"TCP": ("b", 0.98), "Protocol Type": ("c", 6), "HTTP": ("b", 0.35), "HTTPS": ("b", 0.4), "IRC": ("b", 0.08), "Rate": ("ln", 6, 1.0), "Srate": ("ln", 6, 1.0),
                         "psh_flag_number": ("b", 0.75), "ack_flag_number": ("b", 0.95), "flow_duration": ("ln", 120, 1.0), "Tot size": ("ln", 260, 0.6), "AVG": ("ln", 260, 0.6),
                         "IAT": ("ln", 1.0e8, 0.5), "Number": ("ln", 12, 0.3), "Covariance": ("ln", 40000, 1.2)},
    "Uploading_Attack": {"TCP": ("b", 0.99), "Protocol Type": ("c", 6), "HTTP": ("b", 0.96), "Rate": ("ln", 40, 0.9), "Srate": ("ln", 40, 0.9), "psh_flag_number": ("b", 0.95),
                         "ack_flag_number": ("b", 0.98), "Tot size": ("ln", 1200, 0.3), "AVG": ("ln", 1200, 0.3), "Max": ("ln", 1500, 0.1), "Min": ("ln", 60, 0.3),
                         "Tot sum": ("ln", 60000, 0.6), "Header_Length": ("ln", 150000, 0.8), "flow_duration": ("ln", 14, 1.0), "Std": ("ln", 300, 0.5)},
    "XSS": {"TCP": ("b", 0.99), "Protocol Type": ("c", 6), "HTTP": ("b", 0.95), "HTTPS": ("b", 0.03), "Rate": ("ln", 22, 0.9), "Srate": ("ln", 22, 0.9),
            "psh_flag_number": ("b", 0.9), "ack_flag_number": ("b", 0.97), "Tot size": ("ln", 600, 0.4), "AVG": ("ln", 600, 0.4), "Max": ("ln", 1350, 0.3),
            "Tot sum": ("ln", 8000, 0.6), "Header_Length": ("ln", 22000, 0.9), "flow_duration": ("ln", 5, 1.0), "Std": ("ln", 420, 0.5), "Variance": ("u", 0.3, 1.0)},
    # ---------------- Brute force (auth protocols, many short connections)
    "DictionaryBruteForce": {"TCP": ("b", 0.99), "Protocol Type": ("c", 6), "SSH": ("b", 0.6), "Telnet": ("b", 0.38), "HTTP": ("b", 0.02), "HTTPS": ("b", 0.0),
                             "Rate": ("ln", 70, 0.8), "Srate": ("ln", 70, 0.8), "syn_flag_number": ("b", 0.4), "psh_flag_number": ("b", 0.6), "ack_flag_number": ("b", 0.8),
                             "fin_flag_number": ("b", 0.35), "fin_count": ("ln", 1.4, 0.5), "syn_count": ("ln", 1.3, 0.5), "flow_duration": ("ln", 1.5, 0.8),
                             "Tot size": ("ln", 120, 0.4), "AVG": ("ln", 120, 0.4), "IAT": ("ln", 6.0e7, 0.5), "Number": ("ln", 13, 0.3)},
    # ---------------- Spoofing (link-layer / DNS)
    "MITM-ArpSpoofing": {"ARP": ("b", 0.97), "LLC": ("b", 0.99), "IPv": ("b", 0.1), "TCP": ("b", 0.03), "UDP": ("b", 0.02), "ICMP": ("b", 0.0), "Protocol Type": ("c", 0),
                         "Rate": ("ln", 30, 0.8), "Srate": ("ln", 30, 0.8), "syn_flag_number": ("b", 0.0), "ack_flag_number": ("b", 0.0), "HTTP": ("b", 0), "HTTPS": ("b", 0), "DNS": ("b", 0),
                         "Header_Length": ("ln", 42, 0.2), "Tot size": ("ln", 42, 0.05), "AVG": ("ln", 42, 0.05), "Max": ("ln", 42, 0.05), "Min": ("ln", 42, 0.05), "Std": ("ln", 0.1, 1.0),
                         "Variance": ("u", 0.0, 0.05), "flow_duration": ("ln", 0.05, 1.0)},
    "DNS_Spoofing": {"DNS": ("b", 0.96), "UDP": ("b", 0.97), "TCP": ("b", 0.03), "Protocol Type": ("c", 17), "Rate": ("ln", 45, 0.8), "Srate": ("ln", 45, 0.8),
                     "syn_flag_number": ("b", 0.0), "ack_flag_number": ("b", 0.0), "HTTP": ("b", 0), "HTTPS": ("b", 0), "Tot size": ("ln", 95, 0.3), "AVG": ("ln", 95, 0.3),
                     "Max": ("ln", 160, 0.3), "Min": ("ln", 60, 0.2), "Header_Length": ("ln", 300, 0.6), "flow_duration": ("ln", 0.4, 1.0)},
}


def _sample(rng: np.random.Generator, spec: Tuple, n: int) -> np.ndarray:
    kind = spec[0]
    if kind == "b":
        return _bern(rng, spec[1], n)
    if kind == "ln":
        return _lognormal(rng, spec[1], spec[2], n).astype(np.float32)
    if kind == "c":
        return np.full(n, spec[1], dtype=np.float32)
    if kind == "u":
        return rng.uniform(spec[1], spec[2], n).astype(np.float32)
    if kind == "choice":
        return rng.choice(spec[1], size=n, p=spec[2]).astype(np.float32)
    raise ValueError(kind)


def generate_demo_flows(n_per_class: int = 600, seed: int = 42, benign_multiplier: float = 3.0) -> pd.DataFrame:
    """Generate synthetic flows for all in-scope classes (+ a larger benign class)."""
    rng = np.random.default_rng(seed)
    frames = []
    for li in in_scope_labels():
        if li.raw_label not in CLASS_OVERRIDES:
            continue
        n = int(n_per_class * benign_multiplier) if li.raw_label == "BenignTraffic" else n_per_class
        spec = {**BASE, **CLASS_OVERRIDES[li.raw_label]}
        cols = {f: _sample(rng, spec[f], n) for f in FEATURES}
        df = pd.DataFrame(cols)
        # derived consistency: Srate == Rate for the dataset representation, Drate stays 0
        df["Srate"] = df["Rate"].to_numpy()
        df[TARGET] = li.raw_label
        frames.append(df)
    out = pd.concat(frames, ignore_index=True)
    out = out.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    out.attrs["data_source"] = DATA_SOURCE
    return out


if __name__ == "__main__":  # quick smoke
    d = generate_demo_flows(50)
    print(d.shape, d[TARGET].value_counts().to_dict())
