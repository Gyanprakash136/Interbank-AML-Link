"""Unit tests for the Deterministic Synthetic AML Generator.

Validates:
1. Exact repeatability and byte-level determinism with fixed seeds.
2. Partitioning into three distinct banks (Bank A, Bank B, Bank C).
3. Intentionally linked entities vs non-linked entities across banks.
4. Distinguishability between PSI overlap and ground-truth laundering labels
   (e.g. benign commercial entity present in both banks with is_laundering=False).
5. Ground-truth isolation: operational files contain no ground-truth columns.
6. Execution of real OpenMined PSI on generated bank-local tokens.
"""

import hashlib
import json
from pathlib import Path
import pytest
import pandas as pd

from scripts.generate_synthetic_data import generate_synthetic_aml_data
from app.psi.protocol import PSIBidirectionalSession


def _compute_file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


def test_generator_determinism(tmp_path):
    """Confirms running the generator with seed=42 produces byte-identical outputs."""
    dir_run1 = tmp_path / "run1"
    dir_run2 = tmp_path / "run2"

    res1 = generate_synthetic_aml_data(dir_run1, seed=42)
    res2 = generate_synthetic_aml_data(dir_run2, seed=42)

    assert res1["status"] == "success"
    assert res2["status"] == "success"
    assert res1["pairwise_overlap_counts"] == res2["pairwise_overlap_counts"]

    # Verify identical hashes across all generated files
    files_to_check = [
        "bank_a/transactions.csv",
        "bank_a/local_entities.csv",
        "bank_b/transactions.csv",
        "bank_b/local_entities.csv",
        "bank_c/transactions.csv",
        "bank_c/local_entities.csv",
        "evaluation/ground_truth_entities.json",
        "evaluation/ground_truth_transactions.json",
    ]

    for rel_path in files_to_check:
        f1 = dir_run1 / rel_path
        f2 = dir_run2 / rel_path
        assert f1.exists(), f"Missing file {f1}"
        assert f2.exists(), f"Missing file {f2}"
        assert _compute_file_sha256(f1) == _compute_file_sha256(f2), f"Non-deterministic file: {rel_path}"


def test_ground_truth_isolation(tmp_path):
    """Confirms operational bank CSVs contain NO ground-truth labels."""
    output_dir = tmp_path / "dataset"
    generate_synthetic_aml_data(output_dir, seed=42)

    forbidden_cols = {"is_laundering", "is_laundering_label", "ground_truth_entity_id", "global_entity_id"}

    for bank_id in ("bank_a", "bank_b", "bank_c"):
        tx_df = pd.read_csv(output_dir / bank_id / "transactions.csv")
        ent_df = pd.read_csv(output_dir / bank_id / "local_entities.csv")

        assert len(forbidden_cols.intersection(tx_df.columns)) == 0, f"Leaked cols in {bank_id}/transactions.csv"
        assert len(forbidden_cols.intersection(ent_df.columns)) == 0, f"Leaked cols in {bank_id}/local_entities.csv"

        # Check expected operational columns
        assert "transaction_id" in tx_df.columns
        assert "amount" in tx_df.columns
        assert "canonical_token" in ent_df.columns
        assert "local_account_id" in ent_df.columns


def test_linked_vs_non_linked_entities_and_benign_control(tmp_path):
    """Confirms linked entities have matching canonical tokens and distinguishes benign overlap."""
    output_dir = tmp_path / "dataset"
    generate_synthetic_aml_data(output_dir, seed=42)

    with open(output_dir / "evaluation" / "ground_truth_entities.json", "r") as f:
        gt = json.load(f)

    meta = gt["metadata"]["expected_pairwise_psi_overlaps"]
    assert len(meta["bank_a_and_bank_b"]) == 3
    assert len(meta["bank_b_and_bank_c"]) == 2
    assert len(meta["bank_a_and_bank_c"]) == 2
    assert len(meta["all_three"]) == 1

    # Verify benign control entity: present in both A and B, but NOT laundering!
    entities = gt["entities"]
    benign_matches = [
        e for e in entities
        if e["global_entity_id"] == "GT_ENT_005_BENIGN_CORP_AB"
    ]
    assert len(benign_matches) == 1
    benign_ent = benign_matches[0]
    assert benign_ent["is_laundering"] is False
    assert benign_ent["typology"] == "BENIGN_COMMERCIAL"
    assert "bank_a" in benign_ent["accounts"] and "bank_b" in benign_ent["accounts"]
    # Its canonical token MUST be in the A & B overlap
    assert benign_ent["canonical_token"] in meta["bank_a_and_bank_b"]


def test_real_psi_on_generated_bank_datasets(tmp_path):
    """Executes real OpenMined PSI on the generated bank datasets and compares with ground truth."""
    output_dir = tmp_path / "dataset"
    generate_synthetic_aml_data(output_dir, seed=42)

    # Load tokens from Bank A and Bank B local files
    df_a = pd.read_csv(output_dir / "bank_a" / "local_entities.csv")
    df_b = pd.read_csv(output_dir / "bank_b" / "local_entities.csv")

    tokens_a = sorted(df_a["canonical_token"].tolist())
    tokens_b = sorted(df_b["canonical_token"].tolist())

    # Load ground truth expectation
    with open(output_dir / "evaluation" / "ground_truth_entities.json", "r") as f:
        gt = json.load(f)
    expected_overlap = sorted(gt["metadata"]["expected_pairwise_psi_overlaps"]["bank_a_and_bank_b"])

    # Run real two-way PSI protocol
    session = PSIBidirectionalSession("bank_a", "bank_b", fpr=0.001)
    result = session.execute(tokens_a, tokens_b)

    assert result.bank_a_matched_tokens == expected_overlap
    assert result.bank_b_matched_tokens == expected_overlap
    assert result.matched_count == 3
