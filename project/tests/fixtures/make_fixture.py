"""Builds a tiny SYNTHETIC fixture that mimics the *shape* of a CICIoT2023 part file.

It exists only to unit-test the inspector's edge-case handling (NaN, inf, duplicates,
malformed lines, whitespace in headers, Mirai + out-of-scope labels, a second file with
the same header, and a gzip file).  Its numbers are random and MUST NEVER be reported
as dataset statistics.
"""
from __future__ import annotations

import gzip
import random
from pathlib import Path
from typing import List

# Header as it appears in the public release (note the leading spaces on some names —
# the inspector must strip them).
HEADER = (
    "flow_duration, Header_Length, Protocol Type,Duration,Rate, Srate, Drate, fin_flag_number, "
    "syn_flag_number, rst_flag_number, psh_flag_number, ack_flag_number, ece_flag_number, "
    "cwr_flag_number, ack_count, syn_count, fin_count, urg_count, rst_count, HTTP, HTTPS, DNS, "
    "Telnet, SMTP, SSH, IRC, TCP, UDP, DHCP, ARP, ICMP, IPv, LLC, Tot sum, Min, Max, AVG, Std, "
    "Tot size, IAT, Number, Magnitue, Radius, Covariance, Variance, Weight, label"
)
FEATURES = [c.strip() for c in HEADER.split(",")][:-1]
BINARY_COLS = {
    "fin_flag_number", "syn_flag_number", "rst_flag_number", "psh_flag_number", "ack_flag_number",
    "ece_flag_number", "cwr_flag_number", "HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC",
    "TCP", "UDP", "DHCP", "ARP", "ICMP", "IPv", "LLC",
}

LABELS_A = ["BenignTraffic", "DDoS-SYN_Flood", "DoS-UDP_Flood", "Recon-PortScan", "SqlInjection",
            "DictionaryBruteForce", "MITM-ArpSpoofing", "Mirai-udpplain", "DDoS-SlowLoris"]
LABELS_B = ["BenignTraffic", "DNS_Spoofing", "XSS", "Recon-OSScan", "DDoS-ICMP_Flood",
            "Mirai-greeth_flood", "BrowserHijacking", "TotallyUnknownLabel"]


def _row(rng: random.Random, label: str) -> List[str]:
    vals = []
    for c in FEATURES:
        if c in BINARY_COLS:
            vals.append(str(rng.choice([0, 1])))
        elif c == "Protocol Type":
            vals.append(str(rng.choice([1, 6, 17])))
        else:
            vals.append(f"{rng.uniform(0, 1000):.6f}")
    vals.append(label)
    return vals


def build(out_dir: Path, seed: int = 7) -> dict:
    rng = random.Random(seed)
    out_dir.mkdir(parents=True, exist_ok=True)
    expected = {"rows_a": 0, "rows_b": 0, "dupes": 0, "nan_cells": 0, "inf_cells": 0,
                "malformed": 0, "coerced": 0}

    # ---- file A: plain CSV with edge cases
    lines = [HEADER]
    rows_a: List[List[str]] = []
    for i in range(300):
        rows_a.append(_row(rng, LABELS_A[i % len(LABELS_A)]))
    # inject NaN (empty cells) and inf
    for i in (5, 17, 42):
        rows_a[i][0] = ""             # flow_duration empty -> NaN
        expected["nan_cells"] += 1
    for i in (9, 33):
        rows_a[i][4] = "inf"          # Rate = inf
        expected["inf_cells"] += 1
    rows_a[60][39] = "-inf"           # IAT = -inf
    expected["inf_cells"] += 1
    rows_a[70][1] = "notanumber"      # Header_Length non-numeric -> coerced
    expected["coerced"] += 1
    # exact duplicates: repeat 10 rows twice more
    for i in range(10):
        rows_a.append(list(rows_a[i]))
        rows_a.append(list(rows_a[i]))
        expected["dupes"] += 2
    lines += [",".join(r) for r in rows_a]
    expected["rows_a"] = len(rows_a)
    # malformed lines (too many fields) -> skipped by parser
    lines.append(",".join(["1"] * 60))
    lines.append(",".join(["2"] * 55))
    expected["malformed"] = 2
    (out_dir / "part-00000-fixture.csv").write_text("\n".join(lines) + "\n")

    # ---- file B: gzip, same header, no edge cases, rows counted separately
    lines_b = [HEADER]
    rows_b = [_row(rng, LABELS_B[i % len(LABELS_B)]) for i in range(160)]
    lines_b += [",".join(r) for r in rows_b]
    expected["rows_b"] = len(rows_b)
    with gzip.open(out_dir / "part-00001-fixture.csv.gz", "wt") as fh:
        fh.write("\n".join(lines_b) + "\n")

    expected["rows_total"] = expected["rows_a"] + expected["rows_b"]
    expected["labels"] = sorted(set(LABELS_A) | set(LABELS_B))
    return expected


if __name__ == "__main__":
    import json
    import sys

    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("tests/fixtures/mini_dataset")
    print(json.dumps(build(target), indent=2))
