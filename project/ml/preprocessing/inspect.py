"""Phase 1 — streaming CICIoT2023 dataset inspector.

Reads every CSV file under a directory in fixed-size chunks and produces a JSON
report (plus a Markdown summary) containing ONLY measured facts:

* files, sizes, per-file row counts (parsed rows *and* physical line counts)
* header consistency across files, column names, inferred dtypes
* missing values (NaN), non-finite values (+/-inf), non-numeric cells that had to be
  coerced, malformed lines skipped by the parser
* exact duplicate rows (64-bit row hashing, whole dataset)
* target column detection (expects ``label`` but verifies it)
* unique labels, class distribution, per-label file spread
* scope mapping of the observed labels (in-scope / excluded / unknown / missing)
* per-column streaming statistics (count, mean, std, min, max, zero-rate,
  integral-valued flag, low-cardinality value sets)
* a recommended compact dtype per column for later phases

Memory: one chunk at a time (default 200k rows) plus 8 bytes per row for the
duplicate-detection hashes.  Nothing else is retained.

Usage
-----
    python -m ml.preprocessing.inspect --data-dir data/raw \
        --out data/reports/dataset_inspection.json [--chunksize 100000] [--no-dupes]
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import logging
import math
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import numpy as np
import pandas as pd

from ml.preprocessing.labels import (
    CATEGORY_MIRAI,
    EXPECTED_LABELS,
    classify_label,
    in_scope_labels,
)

log = logging.getLogger("inspect")

EXPECTED_TARGET = "label"
DEFAULT_CHUNKSIZE = 100_000   # ~300-400 MB peak RSS incl. interpreter; raise on machines with more RAM
LOW_CARD_TRACK_LIMIT = 24          # keep the distinct-value set for a column until it exceeds this
SUPPORTED_SUFFIXES = (".csv", ".csv.gz")


# --------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------
def _human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024.0:
            return f"{n:,.1f} {unit}"
        n /= 1024.0
    return f"{n:,.1f} PB"


def _is_gz(path: Path) -> bool:
    return path.name.lower().endswith(".gz")


def list_dataset_files(data_dir: Path) -> List[Path]:
    files: List[Path] = []
    for p in sorted(data_dir.rglob("*")):
        if p.is_file() and p.name.lower().endswith(SUPPORTED_SUFFIXES) and not p.name.startswith("."):
            files.append(p)
    return files


class _FilteredLineReader(io.RawIOBase):
    """Binary file-like object that yields only lines with the expected field count.

    Used as a *strict* fallback for files in which the byte-level scan found malformed
    lines: pandas' C parser can mis-handle ``on_bad_lines="skip"`` at chunk boundaries
    (observed with pandas 2.2.3), and it silently NaN-pads short lines.  Filtering the
    lines before parsing makes both cases exact.  The header (first line) always passes.
    Pure-Python per line, so it is only used when actually needed.
    """

    def __init__(self, path: Path, expected_commas: int, block: int = 8 * 1024 * 1024):
        super().__init__()
        self._fh = (gzip.open if _is_gz(path) else open)(path, "rb")  # type: ignore[operator]
        self._expected = expected_commas
        self._block = block
        self._buf = memoryview(b"")
        self._carry = b""
        self._eof = False
        self._first = True
        self.dropped_long = 0
        self.dropped_short = 0
        self.blank = 0

    def readable(self) -> bool:  # pragma: no cover - trivial
        return True

    def _emit(self, lines: List[bytes]) -> None:
        out: List[bytes] = []
        for ln in lines:
            if self._first:
                self._first = False
                out.append(ln)
                continue
            c = ln.count(b",")
            if c == self._expected:
                out.append(ln)
            elif ln.strip() == b"":
                self.blank += 1
            elif c > self._expected:
                self.dropped_long += 1
            else:
                self.dropped_short += 1
        if out:
            self._buf = memoryview(bytes(self._buf) + b"\n".join(out) + b"\n")

    def readinto(self, b) -> int:  # type: ignore[override]
        while len(self._buf) == 0 and not self._eof:
            data = self._fh.read(self._block)
            if not data:
                self._eof = True
                if self._carry:
                    self._emit([self._carry])
                    self._carry = b""
                break
            data = self._carry + data
            lines = data.split(b"\n")
            self._carry = lines.pop()
            self._emit(lines)
        n = min(len(b), len(self._buf))
        if n:
            b[:n] = self._buf[:n]
            self._buf = self._buf[n:]
        return n

    def close(self) -> None:
        try:
            self._fh.close()
        finally:
            super().close()


def scan_file_lines(path: Path, expected_fields: int) -> dict:
    """Vectorised byte-level scan: newline count and per-line field counts.

    Counts commas per physical line with NumPy (no parsing), so malformed lines
    (field count != expected) are known exactly and independently of pandas.
    Limitation: assumes no quoted fields containing commas (true for CICIoT2023,
    whose cells are all numeric except the label)."""
    opener = gzip.open if _is_gz(path) else open
    expected_commas = expected_fields - 1
    n_lines = 0
    long_lines = 0
    short_lines = 0
    blank_lines = 0
    carry_commas = 0
    carry_len = 0
    last = b"\n"
    first_line_seen = False
    with opener(path, "rb") as fh:  # type: ignore[arg-type]
        while True:
            buf = fh.read(16 * 1024 * 1024)
            if not buf:
                break
            last = buf[-1:]
            arr = np.frombuffer(buf, dtype=np.uint8)
            nl_pos = np.flatnonzero(arr == 10)
            comma_pos = np.flatnonzero(arr == 44)
            if nl_pos.size == 0:
                carry_commas += int(comma_pos.size)
                carry_len += arr.size
                continue
            bins = np.searchsorted(nl_pos, comma_pos, side="right")
            counts = np.bincount(bins, minlength=nl_pos.size + 1)
            counts[0] += carry_commas
            line_commas = counts[: nl_pos.size]
            starts = np.concatenate(([0], nl_pos[:-1] + 1))
            line_len = nl_pos - starts
            line_len[0] += carry_len
            carry_commas = int(counts[nl_pos.size])
            carry_len = int(arr.size - (nl_pos[-1] + 1))
            if not first_line_seen:           # header line is judged by the caller
                first_line_seen = True
                line_commas = line_commas[1:]
                line_len = line_len[1:]
            blank = (line_commas == 0) & (line_len <= 1)
            long_lines += int((line_commas > expected_commas).sum())
            short_lines += int(((line_commas < expected_commas) & ~blank).sum())
            blank_lines += int(blank.sum())
            n_lines += int(nl_pos.size)
    ends_with_newline = last == b"\n"
    if not ends_with_newline and (carry_len > 0):
        # final line without trailing newline
        n_lines += 1
        if first_line_seen or n_lines > 1:
            if carry_commas > expected_commas:
                long_lines += 1
            elif carry_commas < expected_commas:
                short_lines += 1
    return {
        "physical_lines": n_lines,
        "ends_with_newline": ends_with_newline,
        "blank_lines": blank_lines,
        "long_lines": long_lines,
        "short_lines": short_lines,
        "malformed_lines": long_lines + short_lines,
    }


def read_header(path: Path) -> List[str]:
    opener = gzip.open if _is_gz(path) else open
    with opener(path, "rt", encoding="utf-8", errors="replace", newline="") as fh:  # type: ignore[arg-type]
        first = fh.readline()
    return [c.strip() for c in first.rstrip("\r\n").split(",")]


def sha256_head(path: Path, nbytes: int = 4 * 1024 * 1024) -> str:
    """Hash of the first ``nbytes`` of the file — cheap provenance fingerprint."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        h.update(fh.read(nbytes))
    return h.hexdigest()[:16]


def detect_target_column(columns: List[str]) -> Tuple[Optional[str], str]:
    """Return (column_name, how) where how in {exact, case_insensitive, last_column_guess, none}."""
    if EXPECTED_TARGET in columns:
        return EXPECTED_TARGET, "exact"
    lowered = {c.lower(): c for c in columns}
    if EXPECTED_TARGET in lowered:
        return lowered[EXPECTED_TARGET], "case_insensitive"
    for cand in ("Label", "attack", "Attack", "class", "Class", "category"):
        if cand in columns:
            return cand, "alias"
    if columns:
        return columns[-1], "last_column_guess"
    return None, "none"


# --------------------------------------------------------------------------------------
# streaming accumulators
# --------------------------------------------------------------------------------------
class ColumnStats:
    """Streaming numeric statistics for a fixed list of columns (vectorised per chunk)."""

    def __init__(self, columns: List[str]):
        self.columns = columns
        k = len(columns)
        self.count = np.zeros(k, dtype=np.int64)      # finite values
        self.nan = np.zeros(k, dtype=np.int64)        # NaN in the source (empty cells / NaN literals)
        self.posinf = np.zeros(k, dtype=np.int64)
        self.neginf = np.zeros(k, dtype=np.int64)
        self.coerced = np.zeros(k, dtype=np.int64)    # non-numeric strings coerced to NaN
        self.zeros = np.zeros(k, dtype=np.int64)
        self.negatives = np.zeros(k, dtype=np.int64)
        self.sum = np.zeros(k, dtype=np.float64)
        self.sumsq = np.zeros(k, dtype=np.float64)
        self.min = np.full(k, np.inf, dtype=np.float64)
        self.max = np.full(k, -np.inf, dtype=np.float64)
        self.integral = np.ones(k, dtype=bool)        # all finite values are whole numbers
        self.low_card: List[Optional[set]] = [set() for _ in columns]

    def update(self, values: np.ndarray, coerced_counts: np.ndarray) -> None:
        """values: 2-D float64 array (rows x columns) possibly containing NaN/inf."""
        isnan = np.isnan(values)
        isposinf = np.isposinf(values)
        isneginf = np.isneginf(values)
        finite = ~(isnan | isposinf | isneginf)

        self.nan += isnan.sum(axis=0) - coerced_counts
        self.coerced += coerced_counts
        self.posinf += isposinf.sum(axis=0)
        self.neginf += isneginf.sum(axis=0)
        self.count += finite.sum(axis=0)

        clean = np.where(finite, values, 0.0)
        self.sum += clean.sum(axis=0)
        self.sumsq += (clean * clean).sum(axis=0)
        self.zeros += ((values == 0.0) & finite).sum(axis=0)
        self.negatives += ((values < 0.0) & finite).sum(axis=0)

        with np.errstate(invalid="ignore"):
            colmin = np.where(finite, values, np.inf).min(axis=0)
            colmax = np.where(finite, values, -np.inf).max(axis=0)
        self.min = np.minimum(self.min, colmin)
        self.max = np.maximum(self.max, colmax)

        with np.errstate(invalid="ignore"):
            frac = np.where(finite, np.mod(np.where(finite, values, 0.0), 1.0), 0.0)
        self.integral &= ~(np.abs(frac) > 0).any(axis=0)

        for j in range(values.shape[1]):
            s = self.low_card[j]
            if s is None:
                continue
            col = values[:, j]
            u = np.unique(col[finite[:, j]])
            if len(u) + len(s) > LOW_CARD_TRACK_LIMIT * 4:
                self.low_card[j] = None
                continue
            s.update(float(x) for x in u)
            if len(s) > LOW_CARD_TRACK_LIMIT:
                self.low_card[j] = None

    def recommend_dtype(self, j: int) -> str:
        if self.count[j] == 0:
            return "float32"
        if self.integral[j] and self.posinf[j] == 0 and self.neginf[j] == 0:
            lo, hi = self.min[j], self.max[j]
            vals = self.low_card[j]
            if vals is not None and vals <= {0.0, 1.0}:
                return "uint8 (binary indicator)"
            if lo >= 0 and hi <= 255:
                return "uint8"
            if lo >= -32768 and hi <= 32767:
                return "int16"
            if lo >= -2147483648 and hi <= 2147483647:
                return "int32"
            return "int64"
        return "float32"

    def to_dict(self) -> Dict[str, dict]:
        out: Dict[str, dict] = {}
        for j, c in enumerate(self.columns):
            n = int(self.count[j])
            mean = self.sum[j] / n if n else None
            var = (self.sumsq[j] / n - mean * mean) if n and mean is not None else None
            std = math.sqrt(var) if var is not None and var > 0 else (0.0 if var is not None else None)
            vals = self.low_card[j]
            out[c] = {
                "finite_count": n,
                "nan_count": int(self.nan[j]),
                "non_numeric_coerced_count": int(self.coerced[j]),
                "pos_inf_count": int(self.posinf[j]),
                "neg_inf_count": int(self.neginf[j]),
                "zero_count": int(self.zeros[j]),
                "negative_count": int(self.negatives[j]),
                "min": None if n == 0 else float(self.min[j]),
                "max": None if n == 0 else float(self.max[j]),
                "mean": None if mean is None else float(mean),
                "std": None if std is None else float(std),
                "integral_valued": bool(self.integral[j]) if n else None,
                "distinct_values_if_low_cardinality": (sorted(vals) if vals is not None else None),
                "recommended_dtype": self.recommend_dtype(j),
            }
        return out


@dataclass
class FileReport:
    file: str
    size_bytes: int
    header: List[str]
    header_matches_reference: bool
    fingerprint_sha256_head: str
    physical_lines: int = 0
    ends_with_newline: bool = True
    blank_lines: int = 0
    long_lines: int = 0
    short_lines: int = 0
    malformed_lines_skipped: int = 0
    strict_parse: bool = False
    parsed_rows: int = 0
    row_count_discrepancy: int = 0
    label_counts: Dict[str, int] = field(default_factory=dict)
    chunks: int = 0
    seconds: float = 0.0
    error: Optional[str] = None


# --------------------------------------------------------------------------------------
# core inspection
# --------------------------------------------------------------------------------------
def _read_chunks(
    path: Path, expected_fields: int, chunksize: int, strict: bool = False
) -> Iterable[pd.DataFrame]:
    """Yield chunks with stripped column names.

    Fast path (``strict=False``): pandas C parser straight from the file.
    Strict path: lines are pre-filtered by field count (see _FilteredLineReader);
    used when the byte-level scan found malformed lines in this file."""
    kwargs = dict(
        chunksize=chunksize,
        skipinitialspace=True,
        on_bad_lines="skip",
        low_memory=True,
        encoding="utf-8",
        encoding_errors="replace",
    )
    if strict:
        raw = _FilteredLineReader(path, expected_fields - 1)
        source = io.BufferedReader(raw, buffer_size=1024 * 1024)
    else:
        source = path  # type: ignore[assignment]
    reader = pd.read_csv(source, **kwargs)
    for chunk in reader:
        chunk.columns = [str(c).strip() for c in chunk.columns]
        yield chunk


def _numeric_matrix(chunk: pd.DataFrame, feature_cols: List[str]) -> Tuple[np.ndarray, np.ndarray]:
    """Return (float64 matrix, per-column count of non-numeric strings coerced to NaN)."""
    mat = np.empty((len(chunk), len(feature_cols)), dtype=np.float64)
    coerced = np.zeros(len(feature_cols), dtype=np.int64)
    for j, c in enumerate(feature_cols):
        if c not in chunk.columns:
            mat[:, j] = np.nan
            continue
        s = chunk[c]
        if pd.api.types.is_numeric_dtype(s):
            mat[:, j] = s.to_numpy(dtype=np.float64, na_value=np.nan)
        else:
            raw_na = s.isna().to_numpy()
            num = pd.to_numeric(s, errors="coerce")
            coerced[j] = int((num.isna().to_numpy() & ~raw_na).sum())
            mat[:, j] = num.to_numpy(dtype=np.float64, na_value=np.nan)
    return mat, coerced


def inspect_dataset(
    data_dir: Path,
    chunksize: int = DEFAULT_CHUNKSIZE,
    detect_duplicates: bool = True,
    max_files: Optional[int] = None,
) -> dict:
    t0 = time.time()
    data_dir = Path(data_dir)
    files = list_dataset_files(data_dir)
    if max_files:
        files = files[:max_files]
    if not files:
        raise FileNotFoundError(
            f"No CSV files found under {data_dir.resolve()} (looked for {SUPPORTED_SUFFIXES})."
        )

    # ---- headers / schema consistency
    headers = {f: read_header(f) for f in files}
    reference = headers[files[0]]
    ref_set = set(reference)
    header_variants: Dict[str, List[str]] = {}
    for f, h in headers.items():
        key = json.dumps(h)
        header_variants.setdefault(key, []).append(str(f.relative_to(data_dir)))
    union_cols: List[str] = list(reference)
    for h in headers.values():
        for c in h:
            if c not in union_cols:
                union_cols.append(c)

    target, target_how = detect_target_column(reference)
    feature_cols = [c for c in union_cols if c != target]
    stats = ColumnStats(feature_cols)

    label_counts: Dict[str, int] = {}
    label_files: Dict[str, set] = {}
    label_raw_variants: Dict[str, set] = {}   # normalized -> raw spellings seen
    hash_blocks: List[np.ndarray] = []
    file_reports: List[FileReport] = []
    total_rows = 0
    total_bytes = 0
    object_columns_seen: Dict[str, int] = {}

    for idx, f in enumerate(files, start=1):
        fr = FileReport(
            file=str(f.relative_to(data_dir)),
            size_bytes=f.stat().st_size,
            header=headers[f],
            header_matches_reference=(set(headers[f]) == ref_set),
            fingerprint_sha256_head=sha256_head(f),
        )
        total_bytes += fr.size_bytes
        ft = time.time()
        log.info("[%d/%d] %s (%s)", idx, len(files), fr.file, _human(fr.size_bytes))
        try:
            scan = scan_file_lines(f, expected_fields=len(headers[f]))
            fr.physical_lines = scan["physical_lines"]
            fr.ends_with_newline = scan["ends_with_newline"]
            fr.blank_lines = scan["blank_lines"]
            fr.long_lines = scan["long_lines"]
            fr.short_lines = scan["short_lines"]
            fr.malformed_lines_skipped = scan["malformed_lines"]
            fr.strict_parse = scan["malformed_lines"] > 0
            if fr.strict_parse:
                log.warning("%s: %d malformed line(s) detected -> strict line-filtered parsing",
                            fr.file, scan["malformed_lines"])
            for chunk in _read_chunks(f, len(headers[f]), chunksize, strict=fr.strict_parse):
                fr.chunks += 1
                n = len(chunk)
                fr.parsed_rows += n
                total_rows += n
                for c in chunk.columns:
                    if chunk[c].dtype == object and c != target:
                        object_columns_seen[c] = object_columns_seen.get(c, 0) + 1

                # labels
                if target in chunk.columns:
                    lab = chunk[target].astype("string").str.strip()
                    vc = lab.value_counts(dropna=False)
                    for k, v in vc.items():
                        key = "<missing>" if pd.isna(k) else str(k)
                        label_counts[key] = label_counts.get(key, 0) + int(v)
                        fr.label_counts[key] = fr.label_counts.get(key, 0) + int(v)
                        label_files.setdefault(key, set()).add(fr.file)
                else:
                    label_counts["<no target column in file>"] = (
                        label_counts.get("<no target column in file>", 0) + n
                    )

                # numeric stats
                mat, coerced = _numeric_matrix(chunk, feature_cols)
                stats.update(mat, coerced)

                # duplicate hashing (float32 view + label string -> deterministic across chunks)
                if detect_duplicates:
                    hdf = pd.DataFrame(mat.astype(np.float32), columns=feature_cols)
                    if target in chunk.columns:
                        hdf[target] = chunk[target].astype("string").str.strip().to_numpy()
                    hash_blocks.append(pd.util.hash_pandas_object(hdf, index=False).to_numpy())
                del mat
            expected_rows = max(fr.physical_lines - 1 - fr.blank_lines - fr.malformed_lines_skipped, 0)
            fr.row_count_discrepancy = fr.parsed_rows - expected_rows
            if fr.row_count_discrepancy:
                log.warning("%s: parsed %d rows but expected %d from the byte scan",
                            fr.file, fr.parsed_rows, expected_rows)
        except Exception as exc:  # keep going; report the failure
            fr.error = f"{type(exc).__name__}: {exc}"
            log.exception("failed on %s", fr.file)
        fr.seconds = round(time.time() - ft, 2)
        file_reports.append(fr)

    # ---- duplicates
    dup_info: dict
    if detect_duplicates and hash_blocks:
        all_hashes = np.concatenate(hash_blocks)
        del hash_blocks
        uniq, counts = np.unique(all_hashes, return_counts=True)
        dup_rows = int((counts - 1).sum())
        dup_info = {
            "method": "64-bit row hash (features as float32 + label), exact match across all files",
            "total_rows_hashed": int(all_hashes.size),
            "unique_rows": int(uniq.size),
            "duplicate_rows": dup_rows,
            "duplicate_row_fraction": (dup_rows / all_hashes.size) if all_hashes.size else 0.0,
            "rows_duplicated_more_than_10x": int((counts > 10).sum()),
            "max_multiplicity": int(counts.max()) if counts.size else 0,
            "hash_memory_bytes": int(all_hashes.nbytes),
        }
        del all_hashes, uniq, counts
    else:
        dup_info = {"method": "disabled", "duplicate_rows": None}

    # ---- label scope mapping
    observed_scope: List[dict] = []
    in_scope_total = 0
    excluded_total = 0
    unknown_total = 0
    benign_total = 0
    per_category: Dict[str, int] = {}
    per_attack_type: Dict[str, int] = {}
    for raw, cnt in sorted(label_counts.items(), key=lambda kv: -kv[1]):
        li, how = classify_label(raw)
        entry = {
            "raw_label": raw,
            "rows": cnt,
            "fraction": cnt / total_rows if total_rows else None,
            "files": len(label_files.get(raw, [])),
            "matched": how,
        }
        if li is None:
            entry.update({"status": "unknown_label", "attack_type": None, "category": None})
            unknown_total += cnt
        else:
            entry.update(
                {
                    "status": "in_scope" if li.in_scope else "excluded",
                    "attack_type": li.attack_type,
                    "category": li.category,
                    "exclusion_reason": li.exclusion_reason,
                }
            )
            if li.in_scope:
                in_scope_total += cnt
                per_category[li.category] = per_category.get(li.category, 0) + cnt
                per_attack_type[li.attack_type] = per_attack_type.get(li.attack_type, 0) + cnt
                if li.category == "Benign":
                    benign_total += cnt
            else:
                excluded_total += cnt
        observed_scope.append(entry)

    observed_keys = set(label_counts)
    missing_in_scope = [
        {"raw_label": li.raw_label, "attack_type": li.attack_type, "category": li.category}
        for li in in_scope_labels()
        if li.raw_label not in observed_keys
        and not any(classify_label(k)[0] is li for k in observed_keys)
    ]
    mirai_observed = [
        k for k in observed_keys if (classify_label(k)[0] or None) and classify_label(k)[0].category == CATEGORY_MIRAI
    ]

    # ---- assemble
    col_stats = stats.to_dict()
    report = {
        "meta": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "data_dir": str(data_dir.resolve()),
            "chunksize": chunksize,
            "duplicate_detection": detect_duplicates,
            "pandas_version": pd.__version__,
            "numpy_version": np.__version__,
            "python_version": sys.version.split()[0],
            "elapsed_seconds": round(time.time() - t0, 2),
            "note": "All values are measured from the files listed below. Nothing is assumed from external descriptions of CICIoT2023.",
        },
        "files": {
            "count": len(files),
            "total_size_bytes": total_bytes,
            "total_size_human": _human(total_bytes),
            "split_across_multiple_files": len(files) > 1,
            "schema_consistent": len(header_variants) == 1,
            "header_variants": [
                {"columns": json.loads(k), "files": v} for k, v in header_variants.items()
            ],
            "per_file": [fr.__dict__ for fr in file_reports],
        },
        "rows": {
            "parsed_rows_total": total_rows,
            "physical_data_lines_total": int(sum(max(fr.physical_lines - 1, 0) for fr in file_reports)),
            "malformed_lines_skipped_total": int(sum(fr.malformed_lines_skipped for fr in file_reports)),
            "blank_lines_total": int(sum(fr.blank_lines for fr in file_reports)),
            "row_count_discrepancy_total": int(sum(fr.row_count_discrepancy for fr in file_reports)),
            "files_parsed_in_strict_mode": [fr.file for fr in file_reports if fr.strict_parse],
            "files_with_errors": [fr.file for fr in file_reports if fr.error],
        },
        "columns": {
            "count": len(union_cols),
            "feature_count": len(feature_cols),
            "names": union_cols,
            "target_column": target,
            "target_detection": target_how,
            "target_verified_as_label": target == EXPECTED_TARGET,
            "reference_header_raw": reference,
            "non_numeric_feature_columns_seen": sorted(object_columns_seen),
            "columns_with_missing_values": {
                c: v["nan_count"] for c, v in col_stats.items() if v["nan_count"] > 0
            },
            "columns_with_infinite_values": {
                c: v["pos_inf_count"] + v["neg_inf_count"]
                for c, v in col_stats.items()
                if (v["pos_inf_count"] + v["neg_inf_count"]) > 0
            },
            "columns_with_coerced_non_numeric": {
                c: v["non_numeric_coerced_count"] for c, v in col_stats.items() if v["non_numeric_coerced_count"] > 0
            },
            "binary_indicator_columns": [
                c for c, v in col_stats.items() if v["recommended_dtype"] == "uint8 (binary indicator)"
            ],
            "constant_columns": [
                c for c, v in col_stats.items()
                if v["finite_count"] > 0 and v["min"] == v["max"]
            ],
        },
        "missing_values": {
            "total_nan_cells": int(sum(v["nan_count"] for v in col_stats.values())),
            "total_inf_cells": int(sum(v["pos_inf_count"] + v["neg_inf_count"] for v in col_stats.values())),
            "total_coerced_cells": int(sum(v["non_numeric_coerced_count"] for v in col_stats.values())),
            "label_missing_rows": label_counts.get("<missing>", 0),
        },
        "duplicates": dup_info,
        "labels": {
            "unique_count": len([k for k in label_counts if not k.startswith("<")]),
            "distribution": label_counts,
            "per_label_file_spread": {k: len(v) for k, v in label_files.items()},
            "labels_per_file_max": max((len(fr.label_counts) for fr in file_reports), default=0),
            "labels_per_file_min": min((len(fr.label_counts) for fr in file_reports), default=0),
        },
        "scope": {
            "observed": observed_scope,
            "in_scope_rows": in_scope_total,
            "in_scope_attack_rows": in_scope_total - benign_total,
            "benign_rows": benign_total,
            "excluded_rows": excluded_total,
            "unknown_label_rows": unknown_total,
            "in_scope_class_count": len(per_attack_type),
            "expected_in_scope_class_count": len(in_scope_labels()),
            "per_category_rows": per_category,
            "per_attack_type_rows": per_attack_type,
            "missing_in_scope_labels": missing_in_scope,
            "mirai_labels_observed": sorted(mirai_observed),
            "coverage_complete": len(missing_in_scope) == 0,
            "expected_label_table_size": len(EXPECTED_LABELS),
        },
        "feature_statistics": col_stats,
    }
    return report


# --------------------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------------------
def render_markdown(r: dict) -> str:
    L: List[str] = []
    f, rows, cols, lab, sc, dup, mv = (
        r["files"], r["rows"], r["columns"], r["labels"], r["scope"], r["duplicates"], r["missing_values"],
    )
    L.append("# CICIoT2023 — Dataset Inspection Report (Phase 1)\n")
    L.append(f"Generated: {r['meta']['generated_at']}  ·  data dir: `{r['meta']['data_dir']}`  ·  "
             f"elapsed: {r['meta']['elapsed_seconds']} s\n")
    L.append("> Every number below was measured from the listed files in streaming mode "
             "(chunksize {:,}). No external dataset descriptions were used.\n".format(r["meta"]["chunksize"]))

    L.append("## 1. Files\n")
    L.append(f"- Files: **{f['count']}**  ·  total size: **{f['total_size_human']}**  ·  "
             f"split across multiple files: **{f['split_across_multiple_files']}**  ·  "
             f"schema consistent: **{f['schema_consistent']}**")
    L.append("\n| File | Size | Physical data lines | Parsed rows | Malformed skipped | Labels in file | Header OK | Time (s) |")
    L.append("|---|---:|---:|---:|---:|---:|:-:|---:|")
    for pf in f["per_file"]:
        L.append(
            f"| `{pf['file']}` | {_human(pf['size_bytes'])} | {max(pf['physical_lines']-1,0):,} | {pf['parsed_rows']:,} | "
            f"{pf['malformed_lines_skipped']:,} | {len(pf['label_counts'])} | "
            f"{'yes' if pf['header_matches_reference'] else 'NO'} | {pf['seconds']} |"
        )
        if pf.get("error"):
            L.append(f"|  | ERROR: {pf['error']} | | | | | | |")

    L.append("\n## 2. Rows\n")
    L.append(f"- Parsed rows: **{rows['parsed_rows_total']:,}**")
    L.append(f"- Physical data lines (newline count minus headers): **{rows['physical_data_lines_total']:,}**")
    L.append(f"- Malformed lines (field count != header) dropped: **{rows['malformed_lines_skipped_total']:,}**  ·  "
             f"blank lines: {rows['blank_lines_total']:,}  ·  files parsed in strict mode: {len(rows['files_parsed_in_strict_mode'])}")
    L.append(f"- Parsed-vs-scanned row discrepancy: **{rows['row_count_discrepancy_total']:,}** (0 = every physical data line accounted for)")
    if rows["files_with_errors"]:
        L.append(f"- Files with read errors: {rows['files_with_errors']}")

    L.append("\n## 3. Columns\n")
    L.append(f"- Columns: **{cols['count']}** ({cols['feature_count']} features + target)")
    L.append(f"- Target column: **`{cols['target_column']}`** (detected via `{cols['target_detection']}`; "
             f"equals expected `label`: **{cols['target_verified_as_label']}**)")
    L.append(f"- Binary indicator columns (only 0/1 observed): {len(cols['binary_indicator_columns'])} → "
             f"{', '.join('`'+c+'`' for c in cols['binary_indicator_columns']) or 'none'}")
    L.append(f"- Constant columns: {cols['constant_columns'] or 'none'}")
    L.append(f"- Feature columns parsed as non-numeric in ≥1 chunk: {cols['non_numeric_feature_columns_seen'] or 'none'}")
    L.append("\nColumn names (stripped): " + ", ".join(f"`{c}`" for c in cols["names"]))

    L.append("\n## 4. Missing / non-finite values\n")
    L.append(f"- NaN cells: **{mv['total_nan_cells']:,}**  ·  ±inf cells: **{mv['total_inf_cells']:,}**  ·  "
             f"non-numeric cells coerced: **{mv['total_coerced_cells']:,}**  ·  rows with missing label: **{mv['label_missing_rows']:,}**")
    if cols["columns_with_missing_values"]:
        L.append("- Columns with NaN: " + ", ".join(f"`{c}` ({n:,})" for c, n in cols["columns_with_missing_values"].items()))
    if cols["columns_with_infinite_values"]:
        L.append("- Columns with ±inf: " + ", ".join(f"`{c}` ({n:,})" for c, n in cols["columns_with_infinite_values"].items()))
    if cols["columns_with_coerced_non_numeric"]:
        L.append("- Columns with coerced non-numeric cells: " + ", ".join(f"`{c}` ({n:,})" for c, n in cols["columns_with_coerced_non_numeric"].items()))

    L.append("\n## 5. Duplicates\n")
    if dup.get("duplicate_rows") is None:
        L.append("- Duplicate detection disabled.")
    else:
        L.append(f"- Method: {dup['method']}")
        L.append(f"- Rows hashed: {dup['total_rows_hashed']:,}  ·  unique rows: {dup['unique_rows']:,}  ·  "
                 f"**duplicate rows: {dup['duplicate_rows']:,} ({dup['duplicate_row_fraction']*100:.2f} %)**  ·  "
                 f"max multiplicity: {dup['max_multiplicity']:,}")

    L.append("\n## 6. Labels and class distribution\n")
    L.append(f"- Unique labels observed: **{lab['unique_count']}**  ·  labels per file: min {lab['labels_per_file_min']}, max {lab['labels_per_file_max']}")
    L.append("\n| Raw label | Rows | % | Files | Status | Attack type | Category | Match |")
    L.append("|---|---:|---:|---:|---|---|---|---|")
    for e in sc["observed"]:
        status = e["status"] + (f" ({e.get('exclusion_reason')})" if e.get("exclusion_reason") else "")
        L.append(f"| `{e['raw_label']}` | {e['rows']:,} | {(e['fraction'] or 0)*100:.3f} | {e['files']} | {status} | "
                 f"{e['attack_type'] or '—'} | {e['category'] or '—'} | {e['matched']} |")

    L.append("\n## 7. Project scope coverage\n")
    L.append(f"- In-scope rows: **{sc['in_scope_rows']:,}** (attack {sc['in_scope_attack_rows']:,} + benign {sc['benign_rows']:,})")
    L.append(f"- Excluded rows (Mirai / out-of-scope variants / optional): **{sc['excluded_rows']:,}**")
    L.append(f"- Unknown-label rows: **{sc['unknown_label_rows']:,}**")
    L.append(f"- In-scope classes observed: **{sc['in_scope_class_count']} / {sc['expected_in_scope_class_count']}**  ·  "
             f"coverage complete: **{sc['coverage_complete']}**")
    if sc["missing_in_scope_labels"]:
        L.append("- Missing in-scope labels: " + ", ".join(f"`{m['raw_label']}`" for m in sc["missing_in_scope_labels"]))
    if sc["mirai_labels_observed"]:
        L.append("- Mirai labels observed (will be excluded): " + ", ".join(f"`{m}`" for m in sc["mirai_labels_observed"]))
    L.append("\n| Category | In-scope rows |")
    L.append("|---|---:|")
    for c, n in sorted(sc["per_category_rows"].items(), key=lambda kv: -kv[1]):
        L.append(f"| {c} | {n:,} |")

    L.append("\n## 8. Feature statistics (streaming; finite values only)\n")
    L.append("| Feature | Finite | NaN | ±inf | Zero % | Min | Max | Mean | Std | Integral | Recommended dtype |")
    L.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|:-:|---|")
    for c, v in r["feature_statistics"].items():
        n = v["finite_count"]
        zero_pct = (v["zero_count"] / n * 100) if n else 0.0
        fmt = lambda x: "—" if x is None else (f"{x:.4g}")
        L.append(f"| `{c}` | {n:,} | {v['nan_count']:,} | {v['pos_inf_count']+v['neg_inf_count']:,} | {zero_pct:.1f} | "
                 f"{fmt(v['min'])} | {fmt(v['max'])} | {fmt(v['mean'])} | {fmt(v['std'])} | "
                 f"{'yes' if v['integral_valued'] else ('no' if v['integral_valued'] is not None else '—')} | {v['recommended_dtype']} |")
    L.append("")
    return "\n".join(L)


# --------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------
def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Streaming CICIoT2023 dataset inspector (Phase 1)")
    ap.add_argument("--data-dir", default=os.environ.get("DATASET_DIR", "data/raw"))
    ap.add_argument("--out", default="data/reports/dataset_inspection.json")
    ap.add_argument("--chunksize", type=int, default=int(os.environ.get("INSPECT_CHUNKSIZE", DEFAULT_CHUNKSIZE)))
    ap.add_argument("--no-dupes", action="store_true", help="skip exact-duplicate detection (saves 8 bytes/row)")
    ap.add_argument("--max-files", type=int, default=None, help="inspect only the first N files (debug)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    report = inspect_dataset(
        Path(args.data_dir),
        chunksize=args.chunksize,
        detect_duplicates=not args.no_dupes,
        max_files=args.max_files,
    )
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, default=str))
    md = out.with_suffix(".md")
    md.write_text(render_markdown(report))
    log.info("wrote %s and %s", out, md)

    # short console summary
    sc = report["scope"]
    print("\n=== Dataset inspection summary ===")
    print(f"files: {report['files']['count']}   rows: {report['rows']['parsed_rows_total']:,}   "
          f"columns: {report['columns']['count']}   target: {report['columns']['target_column']} "
          f"({report['columns']['target_detection']})")
    print(f"labels: {report['labels']['unique_count']}   in-scope classes: {sc['in_scope_class_count']}/"
          f"{sc['expected_in_scope_class_count']}   coverage complete: {sc['coverage_complete']}")
    print(f"NaN cells: {report['missing_values']['total_nan_cells']:,}   inf cells: "
          f"{report['missing_values']['total_inf_cells']:,}   duplicate rows: {report['duplicates'].get('duplicate_rows')}")
    if sc["missing_in_scope_labels"]:
        print("missing in-scope labels:", [m["raw_label"] for m in sc["missing_in_scope_labels"]])
    print(f"report: {out}  |  markdown: {md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
