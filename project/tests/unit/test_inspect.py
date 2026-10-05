"""Unit tests for Phase 1 (label scope table + streaming inspector).

They run against a small SYNTHETIC fixture (tests/fixtures/make_fixture.py) so they
exercise NaN / inf / duplicate / malformed-line / gzip / multi-file handling without
needing the real dataset.  None of the numbers here describe CICIoT2023.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from ml.preprocessing import labels as L
from ml.preprocessing.inspect import (
    detect_target_column,
    inspect_dataset,
    read_header,
    render_markdown,
)
from tests.fixtures.make_fixture import FEATURES, build


@pytest.fixture(scope="module")
def fixture_dir(tmp_path_factory) -> tuple[Path, dict]:
    d = tmp_path_factory.mktemp("mini_dataset")
    expected = build(d)
    return d, expected


# ------------------------------------------------------------------ labels table
def test_label_table_is_consistent():
    raws = [li.raw_label for li in L.EXPECTED_LABELS]
    assert len(raws) == len(set(raws))
    assert all(li.category in L.CATEGORIES for li in L.EXPECTED_LABELS)
    # 22 attack classes + Benign in scope (Browser Hijacking excluded by D5)
    assert len(L.in_scope_labels()) == 23
    assert all(li.in_scope is False for li in L.mirai_labels())
    assert len(L.mirai_labels()) == 3


@pytest.mark.parametrize(
    "raw,expected_type,expected_scope",
    [
        ("DDoS-SYN_Flood", "DDoS SYN Flood", True),
        ("  DDoS-SYN_Flood ", "DDoS SYN Flood", True),        # whitespace tolerated
        ("ddos_syn_flood", "DDoS SYN Flood", True),           # spelling variant via normalisation
        ("Mirai-udpplain", "Mirai UDP Plain", False),
        ("DDoS-SlowLoris", "DDoS SlowLoris", False),
        ("BrowserHijacking", "Browser Hijacking", False),
        ("BenignTraffic", "Benign", True),
    ],
)
def test_classify_label(raw, expected_type, expected_scope):
    li, how = L.classify_label(raw)
    assert li is not None, raw
    assert li.attack_type == expected_type
    assert li.in_scope is expected_scope
    assert how in ("exact", "normalized")


def test_unknown_label_and_mirai_prefix():
    li, how = L.classify_label("SomethingNew")
    assert li is None and how == "unknown"
    assert L.is_mirai("Mirai-newvariant") is True
    assert L.is_mirai("DoS-TCP_Flood") is False


# ------------------------------------------------------------------ header/target
def test_header_is_stripped(fixture_dir):
    d, _ = fixture_dir
    hdr = read_header(d / "part-00000-fixture.csv")
    assert hdr[:3] == ["flow_duration", "Header_Length", "Protocol Type"]
    assert hdr[-1] == "label"
    assert len(hdr) == 47


def test_detect_target_column():
    assert detect_target_column(["a", "b", "label"]) == ("label", "exact")
    assert detect_target_column(["a", "Label"]) == ("Label", "case_insensitive")
    assert detect_target_column(["a", "b"]) == ("b", "last_column_guess")
    assert detect_target_column([]) == (None, "none")


# ------------------------------------------------------------------ inspector
@pytest.fixture(scope="module")
def report(fixture_dir):
    d, _ = fixture_dir
    # tiny chunksize forces multi-chunk paths (duplicates across chunks, stats merging)
    return inspect_dataset(d, chunksize=64, detect_duplicates=True)


def test_files_and_schema(report, fixture_dir):
    _, exp = fixture_dir
    assert report["files"]["count"] == 2
    assert report["files"]["split_across_multiple_files"] is True
    assert report["files"]["schema_consistent"] is True
    names = [pf["file"] for pf in report["files"]["per_file"]]
    assert "part-00000-fixture.csv" in names and "part-00001-fixture.csv.gz" in names


def test_row_counts_and_malformed(report, fixture_dir):
    _, exp = fixture_dir
    assert report["rows"]["parsed_rows_total"] == exp["rows_total"]
    assert report["rows"]["malformed_lines_skipped_total"] == exp["malformed"]
    per = {pf["file"]: pf for pf in report["files"]["per_file"]}
    assert per["part-00000-fixture.csv"]["parsed_rows"] == exp["rows_a"]
    assert per["part-00001-fixture.csv.gz"]["parsed_rows"] == exp["rows_b"]
    # physical lines = header + rows + malformed
    assert per["part-00000-fixture.csv"]["physical_lines"] == 1 + exp["rows_a"] + exp["malformed"]


def test_columns_and_target(report):
    cols = report["columns"]
    assert cols["count"] == 47 and cols["feature_count"] == 46
    assert cols["target_column"] == "label" and cols["target_verified_as_label"] is True
    assert cols["names"][:-1] == FEATURES
    assert "Header_Length" in cols["columns_with_coerced_non_numeric"]


def test_missing_inf_and_coerced(report, fixture_dir):
    _, exp = fixture_dir
    mv = report["missing_values"]
    # the duplicated rows replicate rows 0-9 only; injected NaN/inf/coerced rows are >= 5,
    # row 5 (NaN) is duplicated twice -> +2 NaN cells
    assert mv["total_nan_cells"] == exp["nan_cells"] + 2
    assert mv["total_inf_cells"] == exp["inf_cells"] + 2       # row 9 (inf) duplicated twice
    assert mv["total_coerced_cells"] == exp["coerced"]
    assert report["feature_statistics"]["flow_duration"]["nan_count"] == 5   # 3 injected + row 5 duplicated twice
    assert report["feature_statistics"]["Rate"]["pos_inf_count"] == 4
    assert report["feature_statistics"]["IAT"]["neg_inf_count"] == 1


def test_duplicates(report, fixture_dir):
    _, exp = fixture_dir
    dup = report["duplicates"]
    assert dup["duplicate_rows"] == exp["dupes"]
    assert dup["max_multiplicity"] == 3
    assert dup["total_rows_hashed"] == exp["rows_total"]


def test_label_distribution_and_scope(report, fixture_dir):
    _, exp = fixture_dir
    dist = report["labels"]["distribution"]
    assert set(dist) == set(exp["labels"])
    assert sum(dist.values()) == exp["rows_total"]
    sc = report["scope"]
    statuses = {e["raw_label"]: e["status"] for e in sc["observed"]}
    assert statuses["Mirai-udpplain"] == "excluded"
    assert statuses["DDoS-SlowLoris"] == "excluded"
    assert statuses["BrowserHijacking"] == "excluded"
    assert statuses["TotallyUnknownLabel"] == "unknown_label"
    assert statuses["DDoS-SYN_Flood"] == "in_scope"
    assert sc["coverage_complete"] is False                 # fixture covers only a few classes
    missing = {m["raw_label"] for m in sc["missing_in_scope_labels"]}
    assert "DoS-TCP_Flood" in missing and "DDoS-SYN_Flood" not in missing
    assert sorted(sc["mirai_labels_observed"]) == ["Mirai-greeth_flood", "Mirai-udpplain"]
    assert sc["in_scope_rows"] + sc["excluded_rows"] + sc["unknown_label_rows"] == exp["rows_total"]
    assert sc["per_category_rows"]["Benign"] == sc["benign_rows"] > 0


def test_binary_indicator_detection(report):
    binary = set(report["columns"]["binary_indicator_columns"])
    assert {"HTTP", "TCP", "syn_flag_number"} <= binary
    assert "Rate" not in binary
    assert report["feature_statistics"]["Protocol Type"]["recommended_dtype"] == "uint8"


def test_report_is_json_serialisable_and_markdown_renders(report, tmp_path):
    txt = json.dumps(report, default=str)
    assert "ground_truth" not in txt
    md = render_markdown(report)
    assert "# CICIoT2023 — Dataset Inspection Report" in md
    assert "DDoS-SYN_Flood" in md
    (tmp_path / "r.md").write_text(md)


def test_empty_directory_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        inspect_dataset(tmp_path)
