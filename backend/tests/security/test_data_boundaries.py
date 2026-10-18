"""Security & Data Boundary Verification Tests.

Validates:
1. Operational bank agents cannot access files from another bank's directory.
2. Operational bank agents cannot access the evaluation ground-truth directory.
3. Operational transaction and entity loaders reject files containing ground-truth labels.
4. PSI protocol inputs strictly reject non-token data structures (DataFrames, dicts, row strings).
5. Bidirectional PSI session confines revelation strictly to authorized mutual intersections.
6. Raw transaction records and local graph structures are never exposed to PSI.
"""

from pathlib import Path
import pytest
import pandas as pd

from app.banks.local_agent import OperationalBankAgent
from app.core.config import DataBoundaryViolationError, settings
from app.psi.protocol import (
    PSI_AVAILABLE,
    PSIClient,
    PSIServer,
    PSIBidirectionalSession,
    PSIBoundaryError,
    _validate_token_inputs,
)
from scripts.generate_synthetic_data import generate_synthetic_aml_data


@pytest.fixture(scope="module")
def synthetic_data_dir(tmp_path_factory):
    out = tmp_path_factory.mktemp("sec_test_data")
    generate_synthetic_aml_data(out, seed=42)
    return out


def test_agent_cannot_access_other_bank_directory(synthetic_data_dir):
    """Verifies Bank A agent cannot traverse or read Bank B's local directory."""
    agent_a = OperationalBankAgent(bank_id="bank_a", data_dir=synthetic_data_dir)

    # Attempt to access Bank B transactions
    target_b_file = synthetic_data_dir / "bank_b" / "transactions.csv"
    with pytest.raises(DataBoundaryViolationError, match="unauthorized bank directory"):
        agent_a._verify_boundary(target_b_file)

    # Attempt directory traversal (e.g. ../bank_b)
    traversal_path = agent_a.bank_dir / ".." / "bank_b" / "transactions.csv"
    with pytest.raises(DataBoundaryViolationError):
        agent_a._verify_boundary(traversal_path)


def test_agent_cannot_access_evaluation_ground_truth(synthetic_data_dir):
    """Verifies operational bank agent cannot read evaluation ground truth."""
    agent_a = OperationalBankAgent(bank_id="bank_a", data_dir=synthetic_data_dir)

    gt_file = synthetic_data_dir / "evaluation" / "ground_truth_entities.json"
    with pytest.raises(DataBoundaryViolationError, match="evaluation ground-truth"):
        agent_a._verify_boundary(gt_file)


def test_operational_loader_rejects_leaked_ground_truth_labels(tmp_path):
    """Verifies bank agent rejects transaction files contaminated with ground truth labels."""
    bad_bank_dir = tmp_path / "bank_a"
    bad_bank_dir.mkdir(parents=True, exist_ok=True)

    # Write a contaminated transactions CSV with 'is_laundering'
    bad_tx_file = bad_bank_dir / "transactions.csv"
    bad_df = pd.DataFrame([
        {
            "transaction_id": "TX_CONTAMINATED_01",
            "timestamp": "2026-03-01T12:00:00Z",
            "from_account_id": "ACC_1",
            "to_account_id": "ACC_2",
            "amount": 5000.0,
            "currency": "USD",
            "tx_type": "WIRE",
            "is_laundering": 1,  # LEAKED LABEL
        }
    ])
    bad_df.to_csv(bad_tx_file, index=False)

    agent = OperationalBankAgent(bank_id="bank_a", data_dir=tmp_path)
    with pytest.raises(DataBoundaryViolationError, match="forbidden ground-truth columns detected"):
        agent.load_local_transactions()


def test_psi_rejects_raw_transaction_data():
    """Verifies PSI protocol wrapper rejects raw transaction records and DataFrames."""
    # Test validation boundary directly (platform-independent)
    with pytest.raises(PSIBoundaryError):
        _validate_token_inputs([{"account": "ACC_1001", "amount": 9500.0, "type": "WIRE"}])

    with pytest.raises(PSIBoundaryError):
        _validate_token_inputs(["account=ACC_A_1001, amount=9800.00, tx=WIRE"])

    # If OpenMined PSI is available, also verify end-to-end through PSIClient
    if PSI_AVAILABLE:
        client = PSIClient(reveal_intersection=True)
        with pytest.raises(PSIBoundaryError):
            client.create_request([{"account": "ACC_1001", "amount": 9500.0, "type": "WIRE"}])

        with pytest.raises(PSIBoundaryError):
            client.create_request(["account=ACC_A_1001, amount=9800.00, tx=WIRE"])


@pytest.mark.skipif(
    not PSI_AVAILABLE,
    reason="OpenMined PSI native dependency is unavailable on this platform",
)
def test_bidirectional_session_authorization_isolation():
    """Verifies that in a two-way PSI session, each bank receives ONLY its authorized matches."""
    tokens_a = ["MATCH_ALPHA_BETA", "EXCLUSIVE_A_1", "EXCLUSIVE_A_2"]
    tokens_b = ["MATCH_ALPHA_BETA", "EXCLUSIVE_B_1", "EXCLUSIVE_B_2"]

    session = PSIBidirectionalSession(bank_a_id="bank_a", bank_b_id="bank_b", fpr=0.001)
    res = session.execute(tokens_a, tokens_b)

    # Bank A receives ONLY its own matched token
    assert res.bank_a_matched_tokens == ["MATCH_ALPHA_BETA"]
    assert "EXCLUSIVE_B_1" not in res.bank_a_matched_tokens
    assert "EXCLUSIVE_B_2" not in res.bank_a_matched_tokens

    # Bank B receives ONLY its own matched token
    assert res.bank_b_matched_tokens == ["MATCH_ALPHA_BETA"]
    assert "EXCLUSIVE_A_1" not in res.bank_b_matched_tokens
    assert "EXCLUSIVE_A_2" not in res.bank_b_matched_tokens


def test_ground_truth_never_in_operational_agent_tokens(synthetic_data_dir):
    """Verifies that canonical tokens extracted by operational agents contain no entity metadata, semantic names, or labels."""
    from app.core.security import assert_opaque_tokens

    agent_a = OperationalBankAgent(bank_id="bank_a", data_dir=synthetic_data_dir)
    tokens = agent_a.get_canonical_tokens()

    assert len(tokens) > 0
    # Verifies format matches ^TOK_[0-9a-f]{16}$ and contains no semantic prefixes
    assert_opaque_tokens(tokens)
    for tok in tokens:
        assert isinstance(tok, str)
        assert tok.startswith("TOK_")
        assert "is_laundering" not in tok
        assert "true" not in tok.lower()
        assert "false" not in tok.lower()
        assert "gt_ent" not in tok.lower()
        assert "syndicate" not in tok.lower()
        assert "smurf" not in tok.lower()
        assert "corp" not in tok.lower()
        assert "shell" not in tok.lower()

