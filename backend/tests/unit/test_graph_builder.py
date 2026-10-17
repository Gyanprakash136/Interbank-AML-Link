"""Unit tests for SignalMesh Local Graph Builder.

Validates:
1. Deterministic graph construction with correct node and edge counts on known fixtures.
2. Correct classification of locally-owned accounts vs external counterparties.
3. Proper directed edge representation (inbound vs outbound) without double counting.
4. Input validation (missing IDs, non-positive amounts, malformed timestamps, duplicates).
5. Ground-truth contamination rejection (is_laundering raises DataBoundaryViolationError).
"""

import pandas as pd
import pytest

from app.core.config import DataBoundaryViolationError
from app.graph.graph_builder import GraphValidationError, LocalGraphBuilder


@pytest.fixture
def sample_valid_tx_df():
    return pd.DataFrame([
        {
            "transaction_id": "TX_A_001",
            "timestamp": "2026-03-01T09:00:00Z",
            "from_account_id": "EXT_CASH_01",
            "to_account_id": "ACC_A_1001",
            "amount": 9500.0,
            "currency": "USD",
            "tx_type": "CASH_DEPOSIT",
        },
        {
            "transaction_id": "TX_A_002",
            "timestamp": "2026-03-01T10:00:00Z",
            "from_account_id": "ACC_A_1001",
            "to_account_id": "EXT_WIRE_B",
            "amount": 9400.0,
            "currency": "USD",
            "tx_type": "WIRE",
        },
        {
            "transaction_id": "TX_A_003",
            "timestamp": "2026-03-01T11:00:00Z",
            "from_account_id": "ACC_A_1002",
            "to_account_id": "ACC_A_1001",
            "amount": 2500.0,
            "currency": "USD",
            "tx_type": "INTERNAL_TRANSFER",
        },
    ])


@pytest.fixture
def sample_entities_df():
    return pd.DataFrame([
        {
            "local_account_id": "ACC_A_1001",
            "canonical_token": "TOK_0123456789abcdef",
            "entity_type": "CORPORATION",
            "account_opened_date": "2023-01-01",
            "kyc_risk_score": 0.75,
        },
        {
            "local_account_id": "ACC_A_1002",
            "canonical_token": "TOK_fedcba9876543210",
            "entity_type": "INDIVIDUAL",
            "account_opened_date": "2023-02-01",
            "kyc_risk_score": 0.20,
        },
    ])


def test_graph_builder_node_and_edge_counts(sample_valid_tx_df, sample_entities_df):
    """Confirms graph correctly populates 4 nodes and 3 edges from fixture."""
    builder = LocalGraphBuilder("bank_a", sample_valid_tx_df, sample_entities_df)
    G = builder.build()

    assert G.number_of_nodes() == 4  # ACC_A_1001, ACC_A_1002, EXT_CASH_01, EXT_WIRE_B
    assert G.number_of_edges() == 3

    # Check local vs external
    assert G.nodes["ACC_A_1001"]["is_local"] is True
    assert G.nodes["ACC_A_1001"]["canonical_token"] == "TOK_0123456789abcdef"
    assert G.nodes["ACC_A_1001"]["entity_type"] == "CORPORATION"

    assert G.nodes["ACC_A_1002"]["is_local"] is True

    assert G.nodes["EXT_CASH_01"]["is_local"] is False
    assert G.nodes["EXT_CASH_01"]["canonical_token"] is None
    assert G.nodes["EXT_WIRE_B"]["is_local"] is False


def test_graph_builder_directionality_and_attributes(sample_valid_tx_df, sample_entities_df):
    """Confirms edge direction and transaction metadata preservation."""
    builder = LocalGraphBuilder("bank_a", sample_valid_tx_df, sample_entities_df)
    G = builder.build()

    # ACC_A_1001 should have in_degree=2 (from EXT_CASH_01 and ACC_A_1002)
    in_edges = list(G.in_edges("ACC_A_1001", data=True))
    assert len(in_edges) == 2

    # ACC_A_1001 should have out_degree=1 (to EXT_WIRE_B)
    out_edges = list(G.out_edges("ACC_A_1001", data=True))
    assert len(out_edges) == 1
    u, v, data = out_edges[0]
    assert v == "EXT_WIRE_B"
    assert data["amount"] == 9400.0
    assert data["tx_type"] == "WIRE"
    assert data["transaction_id"] == "TX_A_002"


def test_graph_builder_deduplication(sample_valid_tx_df):
    """Confirms duplicate transaction rows do not cause double counting."""
    dup_df = pd.concat([sample_valid_tx_df, sample_valid_tx_df.iloc[[0]]], ignore_index=True)
    assert len(dup_df) == 4

    builder = LocalGraphBuilder("bank_a", dup_df)
    G = builder.build()
    # Deduplication keeps only 3 unique transactions
    assert G.number_of_edges() == 3


def test_graph_builder_rejects_missing_identifiers(sample_valid_tx_df):
    """Confirms missing account or transaction IDs raise GraphValidationError."""
    bad_df = sample_valid_tx_df.copy()
    bad_df.loc[0, "from_account_id"] = None
    builder = LocalGraphBuilder("bank_a", bad_df)
    with pytest.raises(GraphValidationError, match="null values"):
        builder.build()


def test_graph_builder_rejects_non_positive_amounts(sample_valid_tx_df):
    """Confirms negative or zero amounts are rejected."""
    bad_df = sample_valid_tx_df.copy()
    bad_df.loc[0, "amount"] = -100.0
    builder = LocalGraphBuilder("bank_a", bad_df)
    with pytest.raises(GraphValidationError, match="non-positive"):
        builder.build()


def test_graph_builder_rejects_malformed_timestamps(sample_valid_tx_df):
    """Confirms malformed timestamps raise GraphValidationError."""
    bad_df = sample_valid_tx_df.copy()
    bad_df.loc[0, "timestamp"] = "not-a-valid-timestamp"
    builder = LocalGraphBuilder("bank_a", bad_df)
    with pytest.raises(GraphValidationError, match="Malformed ISO-8601"):
        builder.build()


def test_graph_builder_rejects_ground_truth_labels(sample_valid_tx_df):
    """Confirms ground-truth columns are strictly barred from graph construction."""
    leaked_df = sample_valid_tx_df.copy()
    leaked_df["is_laundering"] = 1
    with pytest.raises(DataBoundaryViolationError, match="Ground truth contamination"):
        LocalGraphBuilder("bank_a", leaked_df)


def test_graph_builder_determinism(sample_valid_tx_df, sample_entities_df):
    """Confirms graph construction produces identical node and edge orders across runs."""
    builder1 = LocalGraphBuilder("bank_a", sample_valid_tx_df, sample_entities_df)
    builder2 = LocalGraphBuilder("bank_a", sample_valid_tx_df, sample_entities_df)

    G1 = builder1.build()
    G2 = builder2.build()

    assert list(G1.nodes) == list(G2.nodes)
    assert list(G1.edges(keys=True)) == list(G2.edges(keys=True))
