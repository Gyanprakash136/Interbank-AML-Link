"""Deterministic HI-Small -> bank-local partitioning (streaming, label-safe).

Produces, under ``out_dir``:
  bank_a|bank_b|bank_c/transactions.csv     operational; NO labels
  bank_a|bank_b|bank_c/local_entities.csv   owned accounts + opaque tokens
  evaluation/hi_small_ground_truth.csv      tx-level labels            (evaluation only)
  evaluation/hi_small_entity_labels.csv     account-level labels       (evaluation only)
  evaluation/hi_small_rejected_rows.csv     quarantined rows (capped)  (evaluation only)
  manifest.json                             hashes, params, counts, versions

Naming matches what the graph builder and agent already assume:
  owned account    -> ``ACC_<A|B|C>_<account>``   (builder: local iff prefix matches)
  other-bank account -> ``ACC_<other letter>_<account>`` if that bank is selected,
                        else ``EXT_<rawbank>_<account>``

Ownership rule (unchanged from the original adapter): a transaction is visible to a
bank iff that bank is the sender's or the receiver's institution. A transaction
between two banks outside the selection is dropped and counted.

Tokens are derived from the account node id with the project's existing scheme
(``app.core.tokens``). Two banks therefore derive the SAME token for the same
account, but only the owning bank lists it in ``local_entities.csv``. Whether
counterparty accounts may become PSI candidates is a separate design decision and is
NOT made here.

Account-level label: an owned account is ``touched_by_laundering_tx = 1`` iff it is
the sender or receiver of any retained transaction labelled ``Is Laundering = 1``.
"""

from collections import Counter
from pathlib import Path
from typing import Any, Dict, Optional, Set

import pandas as pd

from app.core.security import FORBIDDEN_GROUND_TRUTH_COLUMNS
from app.core.tokens import derive_canonical_token
from app.evaluation.artifacts import sha256_file, write_manifest
from app.evaluation.dataset_validation import (
    DEFAULT_CURRENCY_MAP,
    check_header,
    normalize_chunk,
    read_chunks,
)

ALLOWED_BANK_IDS = ("bank_a", "bank_b", "bank_c")
OPERATIONAL_COLUMNS = [
    "transaction_id", "timestamp", "from_account_id", "to_account_id",
    "amount", "currency", "tx_type",
]
ENTITY_COLUMNS = ["local_account_id", "canonical_token", "entity_type",
                  "account_opened_date", "kyc_risk_score"]
REJECT_SAMPLE_CAP = 10_000


def _validate_mapping(bank_raw_ids: Dict[str, str]) -> None:
    if not bank_raw_ids:
        raise ValueError("bank_raw_ids must map at least one raw bank id to a bank id")
    for raw, bank in bank_raw_ids.items():
        if bank not in ALLOWED_BANK_IDS:
            raise ValueError(f"'{bank}' is not one of {ALLOWED_BANK_IDS}")
    if len(set(bank_raw_ids.values())) != len(bank_raw_ids):
        raise ValueError("Two raw bank ids map to the same bank id")


def _append(df: pd.DataFrame, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(path, mode="a", header=not path.exists(), index=False)


def partition_hi_small(
    csv_path: Path,
    out_dir: Path,
    bank_raw_ids: Dict[str, str],
    *,
    max_rows: Optional[int] = None,
    ts_from: Optional[str] = None,
    ts_to: Optional[str] = None,
    chunksize: int = 500_000,
    currency_map: Optional[Dict[str, str]] = None,
    overwrite: bool = False,
) -> Dict[str, Any]:
    """Partitions the CSV; returns (and writes) the manifest."""
    csv_path, out_dir = Path(csv_path), Path(out_dir)
    _validate_mapping(bank_raw_ids)
    check_header(csv_path)

    eval_dir = out_dir / "evaluation"
    banks = sorted(set(bank_raw_ids.values()))
    outputs = (
        [out_dir / b / n for b in banks for n in ("transactions.csv", "local_entities.csv")]
        + [eval_dir / n for n in ("hi_small_ground_truth.csv", "hi_small_entity_labels.csv",
                                  "hi_small_rejected_rows.csv")]
    )
    existing = [p for p in outputs if p.exists()]
    if existing and not overwrite:
        raise FileExistsError(f"Refusing to overwrite existing outputs (use overwrite=True): {existing[:3]}")
    for p in existing:
        p.unlink()

    letter = {b: b[-1].upper() for b in banks}
    tf = pd.Timestamp(ts_from) if ts_from else None
    tt = pd.Timestamp(ts_to) if ts_to else None
    cmap = DEFAULT_CURRENCY_MAP if currency_map is None else currency_map

    owned: Dict[str, Set[str]] = {b: set() for b in banks}
    laundering_nodes: Set[str] = set()
    counts: Counter = Counter()
    reject_counts: Counter = Counter()
    unmapped: Set[str] = set()
    flows: Counter = Counter()
    per_bank_rows: Counter = Counter()
    rejects_written = 0
    offset = 0

    for chunk in read_chunks(csv_path, chunksize):
        if max_rows is not None and offset >= max_rows:
            break
        if max_rows is not None:
            chunk = chunk.iloc[: max(0, max_rows - offset)]
        clean, rejected, unm = normalize_chunk(chunk, row_offset=offset, currency_map=cmap)
        offset += len(chunk)
        counts["rows_read"] += len(chunk)
        unmapped |= unm

        if len(rejected):
            reject_counts.update(rejected["reject_reason"].value_counts().to_dict())
            room = REJECT_SAMPLE_CAP - rejects_written
            if room > 0:
                sample = rejected.head(room)
                _append(sample, eval_dir / "hi_small_rejected_rows.csv")
                rejects_written += len(sample)

        if tf is not None or tt is not None:
            keep = pd.Series(True, index=clean.index)
            if tf is not None:
                keep &= clean["ts"] >= tf
            if tt is not None:
                keep &= clean["ts"] <= tt
            counts["excluded_by_time_window"] += int((~keep).sum())
            clean = clean[keep].reset_index(drop=True)
        if clean.empty:
            continue

        fb = clean["from_bank"].map(bank_raw_ids)
        tb = clean["to_bank"].map(bank_raw_ids)
        in_scope = fb.notna() | tb.notna()
        counts["dropped_outside_selected_banks"] += int((~in_scope).sum())
        clean, fb, tb = clean[in_scope], fb[in_scope], tb[in_scope]
        if clean.empty:
            continue

        fl = fb.map(letter)
        tl = tb.map(letter)
        from_node = ("ACC_" + fl + "_" + clean["from_account"]).where(
            fb.notna(), "EXT_" + clean["from_bank"] + "_" + clean["from_account"])
        to_node = ("ACC_" + tl + "_" + clean["to_account"]).where(
            tb.notna(), "EXT_" + clean["to_bank"] + "_" + clean["to_account"])

        tx_id = "TX_HI_" + clean["row_number"].astype(str).str.zfill(8)
        operational = pd.DataFrame({
            "transaction_id": tx_id,
            "timestamp": clean["timestamp_iso"],
            "from_account_id": from_node,
            "to_account_id": to_node,
            "amount": clean["amount"],
            "currency": clean["currency"],
            "tx_type": clean["tx_type"],
        })[OPERATIONAL_COLUMNS]
        leaked = FORBIDDEN_GROUND_TRUTH_COLUMNS.intersection(operational.columns)
        if leaked:  # defensive: real exception, not assert
            raise RuntimeError(f"Operational output would contain label columns: {leaked}")

        for b in banks:
            mask = (fb == b) | (tb == b)
            if mask.any():
                _append(operational[mask], out_dir / b / "transactions.csv")
                per_bank_rows[b] += int(mask.sum())
            owned[b].update(from_node[fb == b].tolist())
            owned[b].update(to_node[tb == b].tolist())

        truth = pd.DataFrame({
            "transaction_id": tx_id,
            "is_laundering": clean["is_laundering"],
            "from_bank_raw": clean["from_bank"],
            "to_bank_raw": clean["to_bank"],
            "from_node": from_node,
            "to_node": to_node,
        })
        _append(truth, eval_dir / "hi_small_ground_truth.csv")
        pos = truth[truth["is_laundering"] == 1]
        laundering_nodes.update(pos["from_node"].tolist())
        laundering_nodes.update(pos["to_node"].tolist())

        flows.update((fb.fillna("OUTSIDE") + "->" + tb.fillna("OUTSIDE")).value_counts().to_dict())
        counts["rows_retained"] += len(clean)
        counts["laundering_rows_retained"] += int(clean["is_laundering"].sum())

    label_rows = []
    for b in banks:
        accounts = sorted(owned[b])
        entities = pd.DataFrame({
            "local_account_id": accounts,
            "canonical_token": [derive_canonical_token(a) for a in accounts],
            "entity_type": "UNKNOWN",
            "account_opened_date": "",
            "kyc_risk_score": 0.0,
        })[ENTITY_COLUMNS]
        (out_dir / b).mkdir(parents=True, exist_ok=True)
        entities.to_csv(out_dir / b / "local_entities.csv", index=False)
        label_rows.append(pd.DataFrame({
            "bank_id": b,
            "node_id": accounts,
            "canonical_token": entities["canonical_token"],
            "touched_by_laundering_tx": [int(a in laundering_nodes) for a in accounts],
        }))
    labels = pd.concat(label_rows, ignore_index=True) if label_rows else pd.DataFrame()
    eval_dir.mkdir(parents=True, exist_ok=True)
    labels.to_csv(eval_dir / "hi_small_entity_labels.csv", index=False)

    manifest = {
        "stage": "hi_small_partitioning",
        "source_file": str(csv_path),
        "source_sha256": sha256_file(csv_path),
        "source_size_bytes": csv_path.stat().st_size,
        "parameters": {
            "bank_raw_ids": dict(sorted(bank_raw_ids.items())),
            "max_rows": max_rows,
            "ts_from": ts_from,
            "ts_to": ts_to,
            "currency_map": dict(sorted(cmap.items())),
            "timestamp_assumed_timezone": "UTC",
        },
        "subset_note": ("Full file" if max_rows is None and not (ts_from or ts_to)
                        else "SUBSET: results must not be reported as full-dataset results"),
        "counts": dict(counts),
        "rows_per_bank_file": dict(per_bank_rows),
        "owned_accounts_per_bank": {b: len(owned[b]) for b in banks},
        "laundering_touched_owned_accounts": int(labels["touched_by_laundering_tx"].sum()) if len(labels) else 0,
        "reject_counts": dict(reject_counts),
        "rejected_rows_sample_written": rejects_written,
        "unmapped_currency_names": sorted(unmapped),
        "cross_bank_flow_counts": dict(sorted(flows.items())),
    }
    return write_manifest(out_dir / "manifest.json", manifest)
