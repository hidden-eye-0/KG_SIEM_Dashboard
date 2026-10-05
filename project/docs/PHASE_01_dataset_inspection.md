# Phase 1 — Dataset Inspection

**Status:** tool implemented and tested on synthetic fixtures · **waiting for the real CICIoT2023 files** (decision D1: you upload a subset of `part-*.csv` files).

## 1. What is being built

A streaming inspector (`ml/preprocessing/inspect.py`) plus the label-scope table (`ml/preprocessing/labels.py`). It reads every `*.csv` / `*.csv.gz` under `data/raw/` chunk by chunk and writes `data/reports/dataset_inspection.json` + `.md` containing **only measured facts**:

| Required by the brief (§3) | Where it appears in the report |
|---|---|
| number of files, sizes, split across files | `files.count`, `files.total_size_*`, `files.split_across_multiple_files`, `files.per_file[]` |
| number of rows | `rows.parsed_rows_total` (cross-checked against a byte-level newline/field scan → `row_count_discrepancy_total` must be 0) |
| number of columns, column names, data types | `columns.count`, `columns.names`, `feature_statistics.<col>.recommended_dtype`, `columns.binary_indicator_columns` |
| missing values | `missing_values.*`, `columns.columns_with_missing_values`, `columns_with_infinite_values`, `columns_with_coerced_non_numeric` |
| duplicate records | `duplicates.*` (64-bit row hash over features + label across *all* files) |
| unique attack labels, class distribution | `labels.unique_count`, `labels.distribution`, per-file spread |
| target column = `label` — verified | `columns.target_column`, `columns.target_detection`, `columns.target_verified_as_label` |
| mapping to project scope (Mirai excluded etc.) | `scope.observed[]` (in_scope / excluded + reason / unknown_label), `scope.missing_in_scope_labels`, `scope.coverage_complete` |
| feature statistics | `feature_statistics.<col>` (finite count, NaN, ±inf, zero %, min, max, mean, std, integral-valued, low-cardinality value set) |

Malformed lines are detected **independently of pandas** (NumPy scan of comma counts per physical line). If a file has any, that file is re-parsed through a strict line filter, because pandas 2.2.3's `on_bad_lines="skip"` was observed to mis-handle bad lines at chunk boundaries (it produced 322 rows for a 320-row file at chunksize 64). This was found and fixed by the fixture tests.

## 2. Why it exists

Rule §3/§38 of the brief: *never fabricate dataset statistics*. Everything downstream (label mapping, class caps, split strategy, dtype plan, imputation plan, the "46 features" claim) is derived from this report, not from external descriptions.

## 3. File structure (after Phase 1)

```
project/
├── ml/preprocessing/labels.py        # expected raw label → attack type / category / scope (+ exclusion reasons)
├── ml/preprocessing/inspect.py       # streaming inspector + Markdown renderer + CLI
├── tests/fixtures/make_fixture.py    # synthetic 2-file fixture (NaN, inf, dupes, malformed, gzip, CRLF-safe)
├── tests/unit/test_inspect.py        # 20 tests
├── data/raw/                         # ← put part-*.csv here (git-ignored)
├── data/reports/                     # ← dataset_inspection.json / .md are written here
├── docs/00_ARCHITECTURE_REVIEW.md
├── .env.example  .gitignore  pytest.ini  requirements.txt  requirements/phase1.txt
```

## 4. Installation

```bash
cd project
python -m venv .venv && source .venv/bin/activate      # optional
pip install -r requirements/phase1.txt
```

## 5. Run

```bash
# place the dataset files first:  project/data/raw/part-*.csv  (gzip .csv.gz also accepted)
python -m ml.preprocessing.inspect --data-dir data/raw --out data/reports/dataset_inspection.json
# options: --chunksize 100000 (default; ~300–400 MB peak RSS) · --no-dupes (skip duplicate detection, saves 8 B/row) · --max-files N (debug)
```

## 6. Test

```bash
python -m pytest tests/unit -q          # expected: 20 passed
```

## 7. Measured performance (synthetic 1.2 M-row, 366 MB file, this sandbox: 2 vCPU / 1.9 GiB)

- 10.4 s end to end → **~116 k rows/s**, peak RSS 602 MB at chunksize 200 k (default lowered to 100 k).
- Extrapolation only (not a measurement of the real dataset): ~46.7 M rows ≈ 7 min CPU plus disk I/O; the duplicate-hash array for 46.7 M rows is ~374 MB, which is why `--no-dupes` exists for very low-memory machines.

## 8. Expected output

Console summary like:

```
=== Dataset inspection summary ===
files: N   rows: R   columns: C   target: label (exact)
labels: L   in-scope classes: k/23   coverage complete: True|False
NaN cells: …   inf cells: …   duplicate rows: …
report: data/reports/dataset_inspection.json  |  markdown: data/reports/dataset_inspection.md
```

The Markdown report has 8 sections: files · rows · columns · missing/non-finite · duplicates · labels & distribution · scope coverage · per-feature statistics.

## 9. Verification checklist (to tick against the real files)

- [ ] `rows.row_count_discrepancy_total == 0` (every physical data line accounted for)
- [ ] `files.schema_consistent == true` (or the header variants are listed and explained)
- [ ] `columns.target_verified_as_label == true`
- [ ] `scope.unknown_label_rows == 0` (otherwise: new labels to classify in `labels.py`)
- [ ] `scope.coverage_complete == true` — if false, the missing in-scope classes are listed; either upload files containing them or the scope is narrowed *explicitly* in the model card
- [ ] Mirai labels appear under `excluded (mirai_excluded)` and nowhere in `per_attack_type_rows`
- [ ] NaN/inf columns identified → drives the Phase 2 imputation plan
- [ ] duplicate fraction known → Phase 2 dedupe decision is recorded with the measured number

## 10. Known limitations

- The byte-level scan assumes no quoted fields containing commas (true for the CICIoT2023 CSV format, where all cells except `label` are numeric). If a quoted-field file is ever supplied, the parsed-vs-scanned discrepancy counter will reveal it.
- Duplicate detection keys on float32-rounded features + label; two rows differing only beyond float32 precision would be counted as duplicates (this is the intended equivalence for later ML use).
- Statistics are computed over finite values only; NaN/±inf are counted separately, not imputed here.
- The report is ~45 KB of JSON for 47 columns; per-file label tables are included, so with 169 files it will be larger but still small.
