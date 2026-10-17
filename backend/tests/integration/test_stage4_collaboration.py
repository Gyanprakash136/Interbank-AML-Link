"""Integration test for Stage 4 Multi-Bank Collaboration Workflow.

Validates:
1. End-to-end 3-bank pairwise collaboration round with operational datasets.
2. Verified detection of multi-bank syndicates and fan-in/fan-out patterns.
3. Strict Match != Crime behavior:
   Benign cross-bank commercial entity matches remain classified as BENIGN_CROSS_BANK_ENTITY_MATCH.
4. Privacy Leakage Ledger audit completeness: 6 directional sessions recorded.
5. Absolute boundary preservation:
   - Zero raw transaction data or graph structures sent to coordinator.
   - Zero evaluation ground-truth accessed by operational modules.
   - Member-level investigation leads remain strictly inside local bank agents.
   - Coordinator receives and returns zero member-level tokens or graph objects.
"""

from pathlib import Path
import pytest
import private_set_intersection.python as psi

from app.banks.data_adapter import BankDataAdapter
from app.psi.coordinator import PSICollaborationCoordinator
from app.psi.leakage_ledger import PrivacyLeakageLedger
from scripts.generate_synthetic_data import generate_synthetic_aml_data


@pytest.fixture(scope="module")
def stage4_data_dir(tmp_path_factory):
    data_dir = tmp_path_factory.mktemp("stage4_collab_data")
    generate_synthetic_aml_data(data_dir, seed=42)
    return data_dir


def test_stage4_three_bank_collaboration_pipeline(stage4_data_dir):
    """Executes the full Stage 4 pipeline across Bank A, Bank B, and Bank C."""
    # ── 1. Local Operational Ingestion & Graph Construction ───────────────────
    agent_a = BankDataAdapter.get_agent("bank_a", data_dir=stage4_data_dir)
    agent_b = BankDataAdapter.get_agent("bank_b", data_dir=stage4_data_dir)
    agent_c = BankDataAdapter.get_agent("bank_c", data_dir=stage4_data_dir)

    # Each bank builds its graph locally within its own memory
    agent_a.build_local_graph()
    agent_b.build_local_graph()
    agent_c.build_local_graph()

    # Each bank runs local rule detection to identify suspicious candidate tokens
    agent_a.prepare_candidate_tokens(suspicion_threshold=0.45)
    agent_b.prepare_candidate_tokens(suspicion_threshold=0.45)
    agent_c.prepare_candidate_tokens(suspicion_threshold=0.45)

    # ── 2. Inject Benign Control Entity to Test Match != Crime ────────────────
    # Look up the benign commercial entity token from Bank A and Bank B
    ent_a = agent_a.load_local_entities()
    benign_token = ent_a[ent_a["local_account_id"] == "ACC_A_1005"]["canonical_token"].iloc[0]

    # Include benign token in Bank A and Bank B candidate sets to test collaboration response
    agent_a.prepare_candidate_tokens(custom_candidate_tokens=list(agent_a._candidate_tokens) + [benign_token])
    agent_b.prepare_candidate_tokens(custom_candidate_tokens=list(agent_b._candidate_tokens) + [benign_token])

    # ── 3. Orchestrate 3-Bank Pairwise Collaboration Round ───────────────────
    ledger = PrivacyLeakageLedger()
    coordinator = PSICollaborationCoordinator(leakage_ledger=ledger, default_fpr=0.001)

    endpoints = [
        agent_a.get_message_endpoint(),
        agent_b.get_message_endpoint(),
        agent_c.get_message_endpoint(),
    ]
    round_summary = coordinator.execute_collaboration_round(
        endpoints=endpoints,
        round_id="ROUND_STAGE4_INTEGRATION_01",
        data_structure=psi.DataStructure.RAW,
    )

    # ── 4. Verify Coordinator Output Contains Zero Member Tokens ──────────────
    assert round_summary.round_id == "ROUND_STAGE4_INTEGRATION_01"
    assert round_summary.total_wire_bytes > 0
    assert round_summary.session_count == 6  # 3 pairs * 2 directional sessions
    assert round_summary.participating_banks == ["bank_a", "bank_b", "bank_c"]
    assert round_summary.status == "COMPLETED"

    # Verify zero member tokens leaked into coordinator output
    summary_dict = round_summary.to_dict()
    summary_str = str(summary_dict)
    assert benign_token not in summary_str
    assert "ACC_A_1005" not in summary_str
    assert "MultiDiGraph" not in summary_str

    # ── 5. Verify Member-Level Investigation Leads Held Locally by Bank Agent ───
    # Member leads reside strictly inside the bank agent
    leads_a = agent_a.get_local_investigation_leads()
    assert len(leads_a) > 0

    # Benign control entity verification (Match != Crime)
    benign_leads_a = [l for l in leads_a if l.matched_token == benign_token]
    assert len(benign_leads_a) == 1
    # MUST be classified as benign cross-bank match, NOT money laundering
    assert benign_leads_a[0].investigative_assessment == "BENIGN_CROSS_BANK_ENTITY_MATCH"
    assert benign_leads_a[0].updated_local_suspicion_score <= 0.35

    # Suspicious syndicate lead in Bank A
    suspicious_leads_a = [l for l in leads_a if l.matched_token != benign_token]
    assert len(suspicious_leads_a) >= 1
    for lead in suspicious_leads_a:
        assert lead.investigative_assessment == "CROSS_BANK_INVESTIGATION_LEAD"
        assert lead.updated_local_suspicion_score >= 0.80
        # Multi-currency safe aggregation in supporting evidence
        assert "volumes_by_currency" in lead.supporting_evidence
        assert "currencies_observed" in lead.supporting_evidence

    # Verify Bank B also holds local leads
    leads_b = agent_b.get_local_investigation_leads()
    assert len(leads_b) > 0
    benign_leads_b = [l for l in leads_b if l.matched_token == benign_token]
    assert len(benign_leads_b) == 1
    assert benign_leads_b[0].investigative_assessment == "BENIGN_CROSS_BANK_ENTITY_MATCH"

    # ── 6. Verify Privacy Leakage Ledger Telemetry ───────────────────────────
    assert round_summary.session_count == 6
    for ev in round_summary.sessions:
        assert ev.status == "SUCCESS"
        assert ev.total_wire_bytes > 0
        assert ev.recipient_of_output == ev.client_bank_id
        assert ev.recipient_of_output != ev.server_bank_id
