import json
from pathlib import Path

import pandas as pd
import pytest

from app.core.tokens import derive_canonical_token
from app.evaluation.artifacts import sha256_file
from app.evaluation.partitioning import partition_hi_small

HEADER = ("Timestamp,From Bank,Account,To Bank,Account,Amount Received,Receiving Currency,"
          "Amount Paid,Payment Currency,Payment Format,Is Laundering")
ROWS = [
    "2022/09/01 00:20,010,A1,020,B1,5000.00,US Dollar,5000.00,US Dollar,Wire,1",      # 0 A->B laundering
    "2022/09/01 01:15,020,B1,030,C1,4800.00,US Dollar,4800.00,US Dollar,Wire,1",      # 1 B->C laundering
    "2022/09/01 02:40,010,A2,010,A3,9500.00,US Dollar,9500.00,US Dollar,Cash,0",      # 2 within A
    "2022/09/02 04:00,030,C2,999,X1,150.00,US Dollar,150.00,US Dollar,ACH,0",         # 3 C -> outside bank
    "2022/09/02 05:30,999,X2,888,X3,10.00,US Dollar,10.00,US Dollar,ACH,0",           # 4 outside both: dropped
    "2022/09/03 06:10,020,B2,010,A1,80.00,Euro,80.00,Euro,Credit Card,0",             # 5 B -> A (euro)
]
MAPPING = {"010": "bank_a", "020": "bank_b", "030": "bank_c"}
BAD_ROW = "garbage,010,A1,020,B1,5,US Dollar,5,US Dollar,Wire,0"


def make_csv(tmp_path, rows=ROWS):
    p = tmp_path / "hs.csv"
    p.write_text(HEADER + "\n" + "\n".join(rows) + "\n")
    return p


def tx(out, bank):
    return pd.read_csv(out / bank / "transactions.csv", dtype=str)


def test_ownership_and_naming(tmp_path):
    out = tmp_path / "out"
    partition_hi_small(make_csv(tmp_path), out, MAPPING)
    a, b, c = tx(out, "bank_a"), tx(out, "bank_b"), tx(out, "bank_c")
    assert list(a["transaction_id"]) == ["TX_HI_00000000", "TX_HI_00000002", "TX_HI_00000005"]
    assert list(b["transaction_id"]) == ["TX_HI_00000000", "TX_HI_00000001", "TX_HI_00000005"]
    assert list(c["transaction_id"]) == ["TX_HI_00000001", "TX_HI_00000003"]
    row0 = a.iloc[0]
    assert (row0["from_account_id"], row0["to_account_id"]) == ("ACC_A_A1", "ACC_B_B1")
    row3 = c[c["transaction_id"] == "TX_HI_00000003"].iloc[0]
    assert row3["to_account_id"] == "EXT_999_X1"
    assert list(a["timestamp"])[0] == "2022-09-01T00:20:00Z"
    assert set(a["currency"]) == {"USD", "EUR"}
    assert list(a.columns) == ["transaction_id", "timestamp", "from_account_id",
                               "to_account_id", "amount", "currency", "tx_type"]


def test_no_labels_in_operational_files_but_present_in_evaluation(tmp_path):
    out = tmp_path / "out"
    partition_hi_small(make_csv(tmp_path), out, MAPPING)
    for bank in MAPPING.values():
        for name in ("transactions.csv", "local_entities.csv"):
            cols = {c.lower() for c in pd.read_csv(out / bank / name, nrows=1).columns}
            assert not any("launder" in c or "label" in c or "typology" in c for c in cols)
    truth = pd.read_csv(out / "evaluation" / "hi_small_ground_truth.csv", dtype={"transaction_id": str})
    assert truth["is_laundering"].sum() == 2


def test_entities_tokens_and_ownership(tmp_path):
    out = tmp_path / "out"
    partition_hi_small(make_csv(tmp_path), out, MAPPING)
    ent_a = pd.read_csv(out / "bank_a" / "local_entities.csv")
    ent_b = pd.read_csv(out / "bank_b" / "local_entities.csv")
    assert set(ent_a["local_account_id"]) == {"ACC_A_A1", "ACC_A_A2", "ACC_A_A3"}
    assert "ACC_B_B1" not in set(ent_a["local_account_id"])  # counterparty not listed as owned
    tok = ent_b.set_index("local_account_id").loc["ACC_B_B1", "canonical_token"]
    assert tok == derive_canonical_token("ACC_B_B1")
    assert (ent_a["kyc_risk_score"] == 0.0).all()


def test_entity_labels(tmp_path):
    out = tmp_path / "out"
    partition_hi_small(make_csv(tmp_path), out, MAPPING)
    lab = pd.read_csv(out / "evaluation" / "hi_small_entity_labels.csv").set_index("node_id")
    assert lab.loc["ACC_A_A1", "touched_by_laundering_tx"] == 1
    assert lab.loc["ACC_B_B1", "touched_by_laundering_tx"] == 1
    assert lab.loc["ACC_C_C1", "touched_by_laundering_tx"] == 1
    assert lab.loc["ACC_A_A2", "touched_by_laundering_tx"] == 0


def test_manifest_contents(tmp_path):
    csv_path = make_csv(tmp_path)
    out = tmp_path / "out"
    m = partition_hi_small(csv_path, out, MAPPING)
    on_disk = json.loads((out / "manifest.json").read_text())
    assert on_disk["source_sha256"] == sha256_file(csv_path) == m["source_sha256"]
    assert on_disk["counts"]["rows_read"] == 6
    assert on_disk["counts"]["dropped_outside_selected_banks"] == 1
    assert on_disk["counts"]["rows_retained"] == 5
    assert on_disk["counts"]["laundering_rows_retained"] == 2
    assert on_disk["cross_bank_flow_counts"]["bank_a->bank_b"] == 1
    assert on_disk["cross_bank_flow_counts"]["bank_c->OUTSIDE"] == 1
    assert on_disk["subset_note"] == "Full file"
    assert "created_at_utc" in on_disk and "environment" in on_disk


def test_chunk_size_does_not_change_output(tmp_path):
    csv_path = make_csv(tmp_path)
    big, small = tmp_path / "big", tmp_path / "small"
    partition_hi_small(csv_path, big, MAPPING, chunksize=100)
    partition_hi_small(csv_path, small, MAPPING, chunksize=2)
    for rel in ["bank_a/transactions.csv", "bank_b/transactions.csv", "bank_c/transactions.csv",
                "bank_a/local_entities.csv", "bank_b/local_entities.csv", "bank_c/local_entities.csv",
                "evaluation/hi_small_ground_truth.csv", "evaluation/hi_small_entity_labels.csv"]:
        assert (big / rel).read_bytes() == (small / rel).read_bytes(), rel


def test_repeat_runs_are_identical_and_overwrite_is_guarded(tmp_path):
    csv_path = make_csv(tmp_path)
    one, two = tmp_path / "one", tmp_path / "two"
    partition_hi_small(csv_path, one, MAPPING)
    partition_hi_small(csv_path, two, MAPPING)
    assert (one / "bank_a" / "transactions.csv").read_bytes() == (two / "bank_a" / "transactions.csv").read_bytes()
    with pytest.raises(FileExistsError):
        partition_hi_small(csv_path, one, MAPPING)
    partition_hi_small(csv_path, one, MAPPING, overwrite=True)
    assert len(tx(one, "bank_a")) == 3  # not doubled by appending


def test_subset_options_are_recorded(tmp_path):
    csv_path = make_csv(tmp_path)
    out = tmp_path / "out"
    m = partition_hi_small(csv_path, out, MAPPING, max_rows=2)
    assert m["counts"]["rows_read"] == 2
    assert m["subset_note"].startswith("SUBSET")
    out2 = tmp_path / "out2"
    m2 = partition_hi_small(csv_path, out2, MAPPING, ts_from="2022-09-02", ts_to="2022-09-02 23:59")
    assert m2["counts"]["excluded_by_time_window"] == 4
    assert m2["counts"]["rows_retained"] == 1  # row 3 kept, row 4 dropped as outside banks


def test_rejected_rows_are_quarantined_not_loaded(tmp_path):
    csv_path = make_csv(tmp_path, ROWS + [BAD_ROW])
    out = tmp_path / "out"
    m = partition_hi_small(csv_path, out, MAPPING)
    assert m["reject_counts"] == {"bad_timestamp": 1}
    q = pd.read_csv(out / "evaluation" / "hi_small_rejected_rows.csv")
    assert list(q["reject_reason"]) == ["bad_timestamp"]
    assert "TX_HI_00000006" not in set(tx(out, "bank_a")["transaction_id"])


def test_mapping_validation(tmp_path):
    csv_path = make_csv(tmp_path)
    with pytest.raises(ValueError):
        partition_hi_small(csv_path, tmp_path / "o1", {"010": "bank_z"})
    with pytest.raises(ValueError):
        partition_hi_small(csv_path, tmp_path / "o2", {"010": "bank_a", "020": "bank_a"})
    with pytest.raises(ValueError):
        partition_hi_small(csv_path, tmp_path / "o3", {})
