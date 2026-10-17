"""Unit tests for the Public HI-Small Dataset Adapter.

Validates:
1. Handling of duplicate 'Account' headers from IBM AMLSim/HI-Small schema.
2. Non-random partitioning based strictly on bank ownership ('From Bank' / 'To Bank').
3. Cross-bank transactions visible ONLY to the two counterparty banks, not uninvolved banks.
4. 'Is Laundering' label extraction into isolated evaluation ground truth.
5. Error handling for malformed or missing headers.
"""

import io
import json
from pathlib import Path
import pytest
import pandas as pd

from app.banks.hi_small_adapter import HISmallAdapter, SAMPLE_HI_SMALL_CSV


def test_hi_small_adapter_parses_sample_fixture():
    """Confirms the adapter loads and resolves duplicate Account columns in the fixture."""
    adapter = HISmallAdapter()
    df = adapter.load_and_validate_dataframe(io.StringIO(SAMPLE_HI_SMALL_CSV))

    assert "From Account" in df.columns
    assert "To Account" in df.columns
    assert len(df) == 6


def test_hi_small_adapter_partitions_by_account_ownership(tmp_path):
    """Confirms transactions are partitioned by bank ownership without data leakage."""
    adapter = HISmallAdapter()
    df = adapter.load_and_validate_dataframe(io.StringIO(SAMPLE_HI_SMALL_CSV))
    result = adapter.partition_to_bank_local_views(df, output_dir=tmp_path)

    assert result["status"] == "success"

    # In SAMPLE_HI_SMALL_CSV:
    # Row 0: 010 -> 020 (Bank A, Bank B)
    # Row 1: 010 -> 020 (Bank A, Bank B)
    # Row 2: 020 -> 030 (Bank B, Bank C)
    # Row 3: 010 -> 010 (Bank A only)
    # Row 4: 030 -> 020 (Bank B, Bank C)
    # Row 5: 020 -> 020 (Bank B only)

    # Bank A count: rows 0, 1, 3 = 3 rows
    # Bank B count: rows 0, 1, 2, 4, 5 = 5 rows
    # Bank C count: rows 2, 4 = 2 rows
    assert result["partitioned_rows"]["bank_a"] == 3
    assert result["partitioned_rows"]["bank_b"] == 5
    assert result["partitioned_rows"]["bank_c"] == 2

    # Verify 'is_laundering' is NOT in bank-local files
    for bank_id in ("bank_a", "bank_b", "bank_c"):
        tx_file = tmp_path / bank_id / "hi_small_transactions.csv"
        assert tx_file.exists()
        bank_df = pd.read_csv(tx_file)
        assert "is_laundering" not in bank_df.columns
        assert "Is Laundering" not in bank_df.columns

    # Verify ground truth file contains the labels
    gt_file = tmp_path / "evaluation" / "hi_small_ground_truth.json"
    assert gt_file.exists()
    with open(gt_file, "r") as f:
        gt_data = json.load(f)
    assert len(gt_data) == 6
    assert gt_data["TX_HI_000000"]["is_laundering"] is True
    assert gt_data["TX_HI_000003"]["is_laundering"] is False


def test_hi_small_adapter_rejects_missing_columns():
    """Confirms adapter rejects CSVs missing critical fields."""
    adapter = HISmallAdapter()
    bad_csv = "Timestamp,From Bank,Account\n2022/09/01,010,1001\n"
    with pytest.raises(ValueError, match="missing required columns"):
        adapter.load_and_validate_dataframe(io.StringIO(bad_csv))
