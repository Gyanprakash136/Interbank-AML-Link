"""HI-Small dataset validation, normalization and profiling (evaluation-side).

The public HI-Small transaction file has TWO columns named ``Account``. Columns are
therefore read positionally and renamed, after the raw header is checked.

Normalization rules (every rejected row gets exactly one reason, in this priority):
  1. bad_timestamp      - not ``YYYY/MM/DD HH:MM`` (or ISO ``YYYY-MM-DDTHH:MM:SSZ``)
  2. bad_amount         - not a finite number > 0 (the graph builder aborts on these)
  3. missing_currency   - empty payment currency
  4. missing_identifier - empty bank or account on either side
  5. bad_label          - ``Is Laundering`` not 0/1
Nothing is silently coerced. Timestamps carry no timezone in the source; they are
treated as UTC (documented assumption) and emitted as ISO-8601 with a ``Z`` suffix.
"""

import argparse
import csv
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterator, Optional, Tuple

import numpy as np
import pandas as pd

from app.evaluation.artifacts import sha256_file, write_json

RAW_HEADER = [
    "Timestamp", "From Bank", "Account", "To Bank", "Account",
    "Amount Received", "Receiving Currency", "Amount Paid",
    "Payment Currency", "Payment Format", "Is Laundering",
]
INTERNAL_COLUMNS = [
    "timestamp", "from_bank", "from_account", "to_bank", "to_account",
    "amount_received", "receiving_currency", "amount_paid",
    "payment_currency", "payment_format", "is_laundering",
]

# Display name -> ISO-style code. Compiled from recollection of the public dataset:
# VERIFY against the profile's currency list. Unmapped names are passed through
# upper-cased (never guessed) and reported, so downstream coverage warnings fire.
DEFAULT_CURRENCY_MAP: Dict[str, str] = {
    "US Dollar": "USD", "Euro": "EUR", "Yuan": "CNY", "Rupee": "INR", "Yen": "JPY",
    "Ruble": "RUB", "Swiss Franc": "CHF", "Canadian Dollar": "CAD",
    "Australian Dollar": "AUD", "Mexican Peso": "MXN", "Brazilian Real": "BRL",
    "Saudi Riyal": "SAR", "UK Pound": "GBP", "Shekel": "ILS", "Bitcoin": "BTC",
}

REJECT_ORDER = ["bad_timestamp", "bad_amount", "missing_currency", "missing_identifier", "bad_label"]


class DatasetSchemaError(ValueError):
    """Raised when the CSV header does not match the expected HI-Small schema."""


def check_header(path: Path) -> None:
    with open(path, "r", encoding="utf-8", newline="") as f:
        header = next(csv.reader(f), None)
    if header is None:
        raise DatasetSchemaError(f"{path} is empty")
    header = [h.strip() for h in header]
    if header != RAW_HEADER:
        raise DatasetSchemaError(
            f"Unexpected header.\n  expected: {RAW_HEADER}\n  found:    {header}"
        )


def read_chunks(path: Path, chunksize: int = 500_000) -> Iterator[pd.DataFrame]:
    """Yields string-typed chunks with internal column names. Header is validated first."""
    check_header(Path(path))
    reader = pd.read_csv(
        path, header=0, names=INTERNAL_COLUMNS, dtype=str,
        keep_default_na=False, na_values=[""], chunksize=chunksize,
    )
    for chunk in reader:
        yield chunk


def _parse_timestamps(s: pd.Series) -> pd.Series:
    s = s.str.strip()
    parsed = pd.to_datetime(s, format="%Y/%m/%d %H:%M", errors="coerce")
    missing = parsed.isna() & s.notna()
    if missing.any():
        alt = pd.to_datetime(s[missing], format="%Y-%m-%dT%H:%M:%SZ", errors="coerce")
        parsed = parsed.copy()
        parsed[missing] = alt
    return parsed


def normalize_chunk(
    df: pd.DataFrame,
    row_offset: int = 0,
    currency_map: Optional[Dict[str, str]] = None,
) -> Tuple[pd.DataFrame, pd.DataFrame, set]:
    """Returns (clean, rejected, unmapped_currency_names).

    ``clean`` has: row_number, timestamp_iso, ts (datetime), from_bank, from_account,
    to_bank, to_account, amount, currency, tx_type, is_laundering (int).
    ``rejected`` has: row_number, reject_reason (+ the raw columns).
    """
    cmap = DEFAULT_CURRENCY_MAP if currency_map is None else currency_map
    df = df.copy()
    df["row_number"] = np.arange(row_offset, row_offset + len(df), dtype=np.int64)

    ts = _parse_timestamps(df["timestamp"])
    amount = pd.to_numeric(df["amount_paid"], errors="coerce")
    bad_amount = ~np.isfinite(amount.to_numpy(dtype=float)) | (amount.to_numpy(dtype=float) <= 0)

    ids = df[["from_bank", "from_account", "to_bank", "to_account"]].apply(lambda c: c.str.strip())
    missing_id = ids.isna().any(axis=1) | (ids == "").any(axis=1)
    cur_raw = df["payment_currency"].str.strip()
    missing_cur = cur_raw.isna() | (cur_raw == "")
    label = df["is_laundering"].str.strip()
    bad_label = ~label.isin(["0", "1"])

    conditions = [ts.isna().to_numpy(), bad_amount, missing_cur.to_numpy(),
                  missing_id.to_numpy(), bad_label.to_numpy()]
    reason = np.select(conditions, REJECT_ORDER, default="")
    ok = reason == ""

    rejected = df.loc[~ok].copy()
    rejected["reject_reason"] = reason[~ok]

    clean = df.loc[ok].copy()
    clean["ts"] = ts[ok]
    clean["timestamp_iso"] = clean["ts"].dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    for col in ["from_bank", "from_account", "to_bank", "to_account"]:
        clean[col] = ids.loc[ok, col]
    clean["amount"] = amount[ok].astype(float)
    names = cur_raw[ok]
    clean["currency"] = names.map(cmap).fillna(names.str.upper())
    unmapped = set(names[~names.isin(cmap.keys())].unique().tolist())
    clean["tx_type"] = (
        clean["payment_format"].fillna("UNKNOWN").str.strip().str.upper().str.replace(" ", "_")
    )
    clean["is_laundering"] = label[ok].astype(int)
    keep = ["row_number", "timestamp_iso", "ts", "from_bank", "from_account", "to_bank",
            "to_account", "amount", "currency", "tx_type", "is_laundering"]
    return clean[keep].reset_index(drop=True), rejected.reset_index(drop=True), unmapped


def profile_csv(path: Path, chunksize: int = 500_000, top_banks: int = 10) -> Dict[str, Any]:
    """Streams the file once and returns a JSON-serializable data profile."""
    path = Path(path)
    check_header(path)

    rows = 0
    null_counts: Counter = Counter()
    pay_cur: Counter = Counter()
    recv_cur: Counter = Counter()
    formats: Counter = Counter()
    labels: Counter = Counter()
    bank_activity: Counter = Counter()
    rejects: Counter = Counter()
    row_hashes: set = set()
    min_ts = max_ts = None
    unmapped: set = set()

    for chunk in read_chunks(path, chunksize):
        for col in INTERNAL_COLUMNS:
            null_counts[col] += int(chunk[col].isna().sum())
        pay_cur.update(chunk["payment_currency"].dropna().value_counts().to_dict())
        recv_cur.update(chunk["receiving_currency"].dropna().value_counts().to_dict())
        formats.update(chunk["payment_format"].dropna().value_counts().to_dict())
        labels.update(chunk["is_laundering"].dropna().value_counts().to_dict())
        bank_activity.update(chunk["from_bank"].dropna().value_counts().to_dict())
        bank_activity.update(chunk["to_bank"].dropna().value_counts().to_dict())
        row_hashes.update(pd.util.hash_pandas_object(chunk[INTERNAL_COLUMNS], index=False).tolist())

        clean, rejected, unm = normalize_chunk(chunk, row_offset=rows)
        unmapped |= unm
        rejects.update(rejected["reject_reason"].value_counts().to_dict())
        if len(clean):
            lo, hi = clean["ts"].min(), clean["ts"].max()
            min_ts = lo if min_ts is None else min(min_ts, lo)
            max_ts = hi if max_ts is None else max(max_ts, hi)
        rows += len(chunk)

    dup_rows = rows - len(row_hashes)
    return {
        "source_file": str(path),
        "sha256": sha256_file(path),
        "size_bytes": path.stat().st_size,
        "row_count": rows,
        "columns": RAW_HEADER,
        "null_counts": dict(null_counts),
        "payment_currency_counts": dict(pay_cur),
        "receiving_currency_counts": dict(recv_cur),
        "unmapped_currency_names": sorted(unmapped),
        "payment_format_counts": dict(formats),
        "label_counts": dict(labels),
        "laundering_rate": (labels.get("1", 0) / rows) if rows else None,
        "distinct_banks": len(bank_activity),
        "top_banks_by_activity": bank_activity.most_common(top_banks),
        "timestamp_min": None if min_ts is None else min_ts.isoformat(),
        "timestamp_max": None if max_ts is None else max_ts.isoformat(),
        "timestamp_assumed_timezone": "UTC (source has no timezone)",
        "exact_duplicate_rows": dup_rows,
        "duplicate_rate": (dup_rows / rows) if rows else None,
        "reject_counts": dict(rejects),
        "rejected_rows_total": int(sum(rejects.values())),
    }


def main() -> None:
    p = argparse.ArgumentParser(description="Profile a HI-Small transaction CSV.")
    p.add_argument("csv_path", type=Path)
    p.add_argument("--out", type=Path, default=Path("hi_small_profile.json"))
    p.add_argument("--chunksize", type=int, default=500_000)
    args = p.parse_args()
    profile = profile_csv(args.csv_path, chunksize=args.chunksize)
    write_json(args.out, profile)
    print(f"Profile written to {args.out}")
    for k in ("row_count", "sha256", "distinct_banks", "laundering_rate",
              "exact_duplicate_rows", "rejected_rows_total", "unmapped_currency_names"):
        print(f"  {k}: {profile[k]}")


if __name__ == "__main__":
    main()
