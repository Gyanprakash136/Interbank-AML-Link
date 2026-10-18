"""Unit tests for SignalMesh PSI Collaboration Coordinator.

Validates:
1. Rejection of central dictionaries of bank graphs and token sets.
2. Rejection of complete OperationalBankAgent instances (demanding narrow BankMessageEndpoint).
3. Two-bank bidirectional execution with agent ownership and zero coordinator data retention.
4. Accurate matching in GCS and exact RAW modes.
5. Disjoint token sets produce zero matches without false positives.
6. Three-bank pairwise orchestration (A-B, A-C, B-C across 6 directional sessions).
7. Non-matching tokens of one bank are never revealed to other banks or coordinator.
8. Coordinator outputs contain zero member-level tokens or graph structures.
9. Pairwise intersection cardinalities are accurately attributed to their actual recipients.
10. Replay prevention: duplicate round IDs are rejected and do not produce duplicate leads.
11. Rejection of non-opaque or semantic tokens.
"""

import networkx as nx
import pytest

from app.banks.local_agent import OperationalBankAgent
from app.core.config import DataBoundaryViolationError
from app.psi.coordinator import (
    PairwiseSessionSummary,
    PSICollaborationCoordinator,
)
from app.psi.leakage_ledger import PrivacyLeakageLedger
from app.psi.protocol import PSI_AVAILABLE
from app.psi.transport import BankMessageEndpoint, InProcessBankMessageEndpoint

if PSI_AVAILABLE:
    import private_set_intersection.python as psi
else:
    psi = None

requires_psi = pytest.mark.skipif(
    not PSI_AVAILABLE,
    reason="OpenMined PSI is unavailable on this platform",
)


@pytest.fixture
def test_coordinator():
    ledger = PrivacyLeakageLedger()
    return PSICollaborationCoordinator(leakage_ledger=ledger, default_fpr=0.001)


def test_coordinator_rejects_central_dictionaries_of_graphs_or_tokens(test_coordinator):
    """Verifies that the coordinator strictly refuses to accept central dictionaries of tokens or graphs."""
    raw_tokens_map = {
        "bank_a": ["TOK_0000000000000001", "TOK_0000000000000002"],
        "bank_b": ["TOK_0000000000000002", "TOK_0000000000000003"],
    }
    raw_graphs_map = {
        "bank_a": nx.MultiDiGraph(),
        "bank_b": nx.MultiDiGraph(),
    }

    # 1. Reject dictionary passed directly as endpoints
    with pytest.raises(DataBoundaryViolationError, match="strictly prohibited"):
        test_coordinator.execute_collaboration_round(raw_tokens_map)

    # 2. Reject legacy kwargs bank_tokens_map
    with pytest.raises(DataBoundaryViolationError, match="strictly prohibited"):
        test_coordinator.execute_collaboration_round(
            bank_tokens_map=raw_tokens_map,
            round_id="ROUND_ILLEGAL_MAP",
        )

    # 3. Reject legacy kwargs bank_graphs_map
    with pytest.raises(DataBoundaryViolationError, match="strictly prohibited"):
        test_coordinator.execute_collaboration_round(
            bank_graphs_map=raw_graphs_map,
            round_id="ROUND_ILLEGAL_GRAPHS",
        )

    # 4. Reject dictionaries passed to execute_pairwise_round
    with pytest.raises(DataBoundaryViolationError, match="strictly prohibited"):
        test_coordinator.execute_pairwise_round(
            round_id="ROUND_ILLEGAL_PAIR",
            endpoint_a={"tokens": ["TOK_0000000000000001"]},
            endpoint_b={"tokens": ["TOK_0000000000000002"]},
        )


def test_coordinator_rejects_complete_bank_agent_instances(test_coordinator):
    """Confirms coordinator rejects complete OperationalBankAgent objects, requiring narrow BankMessageEndpoints."""
    agent_a = OperationalBankAgent("bank_a")
    agent_b = OperationalBankAgent("bank_b")

    # In collaboration round
    with pytest.raises(DataBoundaryViolationError, match="implement BankMessageEndpoint"):
        test_coordinator.execute_collaboration_round([agent_a, agent_b])

    # In pairwise round
    with pytest.raises(DataBoundaryViolationError, match="implement BankMessageEndpoint"):
        test_coordinator.execute_pairwise_round(
            round_id="ROUND_REJECT_RAW_AGENT",
            endpoint_a=agent_a,
            endpoint_b=agent_b,
        )


@requires_psi
def test_coordinator_two_bank_overlap_gcs_and_raw(test_coordinator):
    """Confirms known overlap is detected in both GCS and exact RAW modes with agent data ownership."""
    tokens_a = ["TOK_0000000000000001", "TOK_0000000000000002", "TOK_0000000000000003"]
    tokens_b = ["TOK_0000000000000002", "TOK_0000000000000003", "TOK_0000000000000004"]
    expected_overlap = ["TOK_0000000000000002", "TOK_0000000000000003"]

    agent_a = OperationalBankAgent("bank_a")
    agent_b = OperationalBankAgent("bank_b")
    agent_a.prepare_candidate_tokens(custom_candidate_tokens=tokens_a)
    agent_b.prepare_candidate_tokens(custom_candidate_tokens=tokens_b)

    ep_a = agent_a.get_message_endpoint()
    ep_b = agent_b.get_message_endpoint()

    # 1. GCS Mode
    res_gcs = test_coordinator.execute_pairwise_round(
        round_id="ROUND_PAIR_GCS",
        endpoint_a=ep_a,
        endpoint_b=ep_b,
        data_structure=psi.DataStructure.GCS,
    )
    assert res_gcs.bank_a_revealed_matches == 2
    assert res_gcs.bank_b_revealed_matches == 2
    assert res_gcs.session_a_to_b.status == "SUCCESS"
    assert res_gcs.session_b_to_a.status == "SUCCESS"
    # Matches are held locally within each agent
    assert agent_a.get_matched_tokens() == expected_overlap
    assert agent_b.get_matched_tokens() == expected_overlap

    # Clear leads and matched tokens for next run
    agent_a.clear_local_investigation_leads()
    agent_b.clear_local_investigation_leads()

    # 2. RAW Mode (Exact)
    res_raw = test_coordinator.execute_pairwise_round(
        round_id="ROUND_PAIR_RAW",
        endpoint_a=ep_a,
        endpoint_b=ep_b,
        data_structure=psi.DataStructure.RAW,
    )
    assert res_raw.bank_a_revealed_matches == 2
    assert res_raw.bank_b_revealed_matches == 2
    assert res_raw.session_a_to_b.data_structure == "RAW"
    assert res_raw.session_a_to_b.fpr_parameter == 0.0
    assert agent_a.get_matched_tokens() == expected_overlap
    assert agent_b.get_matched_tokens() == expected_overlap


@requires_psi
def test_coordinator_two_bank_no_overlap(test_coordinator):
    """Confirms disjoint token sets produce zero matches without leaking tokens."""
    tokens_a = ["TOK_0000000000000001", "TOK_0000000000000002"]
    tokens_b = ["TOK_0000000000000008", "TOK_0000000000000009"]

    agent_a = OperationalBankAgent("bank_a")
    agent_b = OperationalBankAgent("bank_b")
    agent_a.prepare_candidate_tokens(custom_candidate_tokens=tokens_a)
    agent_b.prepare_candidate_tokens(custom_candidate_tokens=tokens_b)

    ep_a = agent_a.get_message_endpoint()
    ep_b = agent_b.get_message_endpoint()

    res = test_coordinator.execute_pairwise_round(
        round_id="ROUND_DISJOINT",
        endpoint_a=ep_a,
        endpoint_b=ep_b,
        data_structure=psi.DataStructure.RAW,
    )
    assert res.bank_a_revealed_matches == 0
    assert res.bank_b_revealed_matches == 0
    assert len(agent_a.get_matched_tokens()) == 0
    assert len(agent_b.get_matched_tokens()) == 0
    assert res.session_a_to_b.client_revealed_cardinality == 0
    assert res.session_b_to_a.client_revealed_cardinality == 0


@requires_psi
def test_non_matching_tokens_never_disclosed_to_counterparty(test_coordinator):
    """Verifies that non-matching candidate tokens are never returned or revealed to other participants."""
    exclusive_token_a = "TOK_00000000000000aa"
    exclusive_token_b = "TOK_00000000000000bb"
    shared_token = "TOK_00000000000000ab"

    agent_a = OperationalBankAgent("bank_a")
    agent_b = OperationalBankAgent("bank_b")
    agent_a.prepare_candidate_tokens(custom_candidate_tokens=[shared_token, exclusive_token_a])
    agent_b.prepare_candidate_tokens(custom_candidate_tokens=[shared_token, exclusive_token_b])

    test_coordinator.execute_pairwise_round(
        round_id="ROUND_NON_MATCH_CONFINE",
        endpoint_a=agent_a.get_message_endpoint(),
        endpoint_b=agent_b.get_message_endpoint(),
        data_structure=psi.DataStructure.RAW,
    )

    # Bank A learns ONLY shared_token; NEVER exclusive_token_b
    assert agent_a.get_matched_tokens() == [shared_token]
    assert exclusive_token_b not in agent_a.get_matched_tokens()

    # Bank B learns ONLY shared_token; NEVER exclusive_token_a
    assert agent_b.get_matched_tokens() == [shared_token]
    assert exclusive_token_a not in agent_b.get_matched_tokens()


@requires_psi
def test_coordinator_outputs_contain_no_member_level_tokens(test_coordinator):
    """Verifies that coordinator output structures contain zero member-level tokens or graph objects."""
    tokens_a = ["TOK_0000000000000001", "TOK_0000000000000002"]
    tokens_b = ["TOK_0000000000000002", "TOK_0000000000000003"]
    tokens_c = ["TOK_0000000000000002", "TOK_0000000000000004"]

    agent_a = OperationalBankAgent("bank_a")
    agent_b = OperationalBankAgent("bank_b")
    agent_c = OperationalBankAgent("bank_c")
    agent_a.prepare_candidate_tokens(custom_candidate_tokens=tokens_a)
    agent_b.prepare_candidate_tokens(custom_candidate_tokens=tokens_b)
    agent_c.prepare_candidate_tokens(custom_candidate_tokens=tokens_c)

    endpoints = [
        agent_a.get_message_endpoint(),
        agent_b.get_message_endpoint(),
        agent_c.get_message_endpoint(),
    ]

    summary = test_coordinator.execute_collaboration_round(
        endpoints=endpoints,
        round_id="ROUND_ZERO_TOKEN_CHECK",
        data_structure=psi.DataStructure.RAW,
    )

    # Inspect summary dictionary representation
    summary_dict = summary.to_dict()
    summary_str = str(summary_dict)

    # Confirm NO member-level tokens appear anywhere in coordinator summary or events
    all_tokens = set(tokens_a + tokens_b + tokens_c)
    for tok in all_tokens:
        assert tok not in summary_str, f"Token {tok} leaked into coordinator summary output!"

    # Confirm zero graph objects or lists of nodes/edges exist in coordinator summary
    assert "MultiDiGraph" not in summary_str
    assert "local_account_id" not in summary_str
    assert "neighbor_accounts" not in summary_str


@requires_psi
def test_pairwise_cardinality_attributed_to_actual_recipients(test_coordinator):
    """Verifies that pairwise intersection cardinalities are accurately attributed to their actual recipients."""
    tokens_a = ["TOK_0000000000000001", "TOK_0000000000000002"]
    tokens_b = ["TOK_0000000000000002", "TOK_0000000000000003"]

    agent_a = OperationalBankAgent("bank_a")
    agent_b = OperationalBankAgent("bank_b")
    agent_a.prepare_candidate_tokens(custom_candidate_tokens=tokens_a)
    agent_b.prepare_candidate_tokens(custom_candidate_tokens=tokens_b)

    summary = test_coordinator.execute_pairwise_round(
        round_id="ROUND_RECIPIENT_CHECK",
        endpoint_a=agent_a.get_message_endpoint(),
        endpoint_b=agent_b.get_message_endpoint(),
        data_structure=psi.DataStructure.RAW,
    )

    # Leg 1: A is Server, B is Client -> Output recipient is Bank B
    assert summary.session_a_to_b.server_bank_id == "bank_a"
    assert summary.session_a_to_b.client_bank_id == "bank_b"
    assert summary.session_a_to_b.recipient_of_output == "bank_b"
    assert summary.session_a_to_b.client_revealed_cardinality == 1

    # Leg 2: B is Server, A is Client -> Output recipient is Bank A
    assert summary.session_b_to_a.server_bank_id == "bank_b"
    assert summary.session_b_to_a.client_bank_id == "bank_a"
    assert summary.session_b_to_a.recipient_of_output == "bank_a"
    assert summary.session_b_to_a.client_revealed_cardinality == 1


@requires_psi
def test_coordinator_three_bank_pairwise_orchestration(test_coordinator):
    """Confirms three-bank collaboration executes 3 pairs (6 directional sessions) and logs to ledger."""
    tokens_a = ["TOK_0000000000000001", "TOK_0000000000000002"]
    tokens_b = ["TOK_0000000000000001", "TOK_0000000000000002", "TOK_0000000000000003"]
    tokens_c = ["TOK_0000000000000002", "TOK_0000000000000003", "TOK_0000000000000009"]

    agent_a = OperationalBankAgent("bank_a")
    agent_b = OperationalBankAgent("bank_b")
    agent_c = OperationalBankAgent("bank_c")
    agent_a.prepare_candidate_tokens(custom_candidate_tokens=tokens_a)
    agent_b.prepare_candidate_tokens(custom_candidate_tokens=tokens_b)
    agent_c.prepare_candidate_tokens(custom_candidate_tokens=tokens_c)

    endpoints = [
        agent_a.get_message_endpoint(),
        agent_b.get_message_endpoint(),
        agent_c.get_message_endpoint(),
    ]

    summary = test_coordinator.execute_collaboration_round(
        endpoints=endpoints,
        round_id="ROUND_3BANK_UNIT_01",
        data_structure=psi.DataStructure.RAW,
    )

    assert summary.round_id == "ROUND_3BANK_UNIT_01"
    assert summary.session_count == 6
    assert summary.participating_banks == ["bank_a", "bank_b", "bank_c"]
    assert summary.status == "COMPLETED"

    # Agent A matches: token 1 (with B), token 2 (with B and C)
    assert agent_a.get_matched_tokens() == ["TOK_0000000000000001", "TOK_0000000000000002"]

    # Agent B matches: token 1 (with A), token 2 (with A and C), token 3 (with C)
    assert agent_b.get_matched_tokens() == ["TOK_0000000000000001", "TOK_0000000000000002", "TOK_0000000000000003"]

    # Agent C matches: token 2 (with A and B), token 3 (with B)
    assert agent_c.get_matched_tokens() == ["TOK_0000000000000002", "TOK_0000000000000003"]

    # Ledger must contain exactly 6 directional sessions
    ledger_events = test_coordinator.ledger.get_events_for_round("ROUND_3BANK_UNIT_01")
    assert len(ledger_events) == 6
    for ev in ledger_events:
        assert ev.status == "SUCCESS"
        assert ev.total_wire_bytes > 0


@requires_psi
def test_coordinator_duplicate_round_id_rejected(test_coordinator):
    """Confirms reusing an identical round ID raises ValueError to prevent replay."""
    tokens_a = ["TOK_0000000000000001"]
    tokens_b = ["TOK_0000000000000001"]

    agent_a = OperationalBankAgent("bank_a")
    agent_b = OperationalBankAgent("bank_b")
    agent_a.prepare_candidate_tokens(custom_candidate_tokens=tokens_a)
    agent_b.prepare_candidate_tokens(custom_candidate_tokens=tokens_b)

    endpoints = [agent_a.get_message_endpoint(), agent_b.get_message_endpoint()]

    test_coordinator.execute_collaboration_round(endpoints, round_id="ROUND_UNIQUE_ID")
    with pytest.raises(ValueError, match="already been processed"):
        test_coordinator.execute_collaboration_round(endpoints, round_id="ROUND_UNIQUE_ID")


def test_coordinator_rejects_non_opaque_tokens():
    """Confirms bank agent and security boundary reject non-opaque tokens."""
    bad_tokens_a = ["CANON_SYNDICATE_LEAK"]  # Semantic name
    agent_a = OperationalBankAgent("bank_a")

    with pytest.raises(DataBoundaryViolationError, match="opaque token format"):
        agent_a.prepare_candidate_tokens(custom_candidate_tokens=bad_tokens_a)
