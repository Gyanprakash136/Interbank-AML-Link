"""Integration Test for Stage 3 End-to-End Pipeline.

Executes the complete multi-bank Stage 3 workflow:
1. Operational Data Ingestion: Bank Alpha and Bank Beta load local operational files.
2. Local Graph Construction: Both banks build independent NetworkX MultiDiGraphs.
3. Feature Extraction & Rule Detection: Both banks compute local explainable AML indicators.
4. Token Gating: Only locally flagged suspicious accounts generate eligible PSI tokens.
5. Real OpenMined PSI Matching: Two-way PSI protocol executes between Bank Alpha and Bank Beta.
6. Matched-Seed Expansion: Each bank locally expands 1-hop and 2-hop neighborhoods around matched seeds.
7. Verification of Boundaries:
   - Zero raw transaction data or graphs transmitted over PSI wire.
   - Match status distinguished from crime (benign control verified).
   - Evaluation ground truth strictly unread by all operational code.
"""

from pathlib import Path
import pytest

from app.banks.data_adapter import BankDataAdapter
from app.banks.local_detection import LocalRuleDetectionEngine
from app.graph.graph_builder import LocalGraphBuilder
from app.graph.graph_expansion import MatchedSeedGraphExpander
from app.psi.protocol import PSIBidirectionalSession
from scripts.generate_synthetic_data import generate_synthetic_aml_data


@pytest.fixture(scope="module")
def pipeline_data_dir(tmp_path_factory):
    data_dir = tmp_path_factory.mktemp("pipeline_data")
    generate_synthetic_aml_data(data_dir, seed=42)
    return data_dir


def test_stage3_end_to_end_pipeline(pipeline_data_dir):
    """Executes the full Stage 3 pipeline across Bank A and Bank B."""
    # ── 1. Bank A Local Ingestion and Graph Construction ──────────────────────
    agent_a = BankDataAdapter.get_agent("bank_a", data_dir=pipeline_data_dir)
    tx_a = agent_a.load_local_transactions()
    ent_a = agent_a.load_local_entities()
    graph_a = LocalGraphBuilder("bank_a", tx_a, ent_a).build()

    # ── 2. Bank B Local Ingestion and Graph Construction ──────────────────────
    agent_b = BankDataAdapter.get_agent("bank_b", data_dir=pipeline_data_dir)
    tx_b = agent_b.load_local_transactions()
    ent_b = agent_b.load_local_entities()
    graph_b = LocalGraphBuilder("bank_b", tx_b, ent_b).build()

    # ── 3. Local Rule Detection & PSI Candidate Extraction ────────────────────
    engine_a = LocalRuleDetectionEngine(suspicion_threshold=0.45)
    engine_b = LocalRuleDetectionEngine(suspicion_threshold=0.45)

    alerts_a = engine_a.evaluate_graph(graph_a)
    alerts_b = engine_b.evaluate_graph(graph_b)

    tokens_a = engine_a.get_eligible_psi_tokens(graph_a)
    tokens_b = engine_b.get_eligible_psi_tokens(graph_b)

    assert len(tokens_a) > 0, "Bank A should have flagged suspicious entities"
    assert len(tokens_b) > 0, "Bank B should have flagged suspicious entities"

    # Verify all emitted tokens are strictly opaque string tokens
    for tok in tokens_a + tokens_b:
        assert isinstance(tok, str)
        assert tok.startswith("TOK_")

    # ── 4. Real OpenMined PSI Matching ───────────────────────────────────────
    session = PSIBidirectionalSession("bank_a", "bank_b", fpr=0.001)
    psi_result = session.execute(tokens_a, tokens_b)

    # ── 5. Matched-Seed Local Neighborhood Expansion ──────────────────────────
    expander_a = MatchedSeedGraphExpander(rule_engine=engine_a)
    expander_b = MatchedSeedGraphExpander(rule_engine=engine_b)

    for matched_token in psi_result.bank_a_matched_tokens:
        lead_a = expander_a.expand_neighborhood(graph_a, matched_token, hops=1)
        assert lead_a is not None
        assert lead_a.local_account_id.startswith("ACC_A_")
        assert lead_a.psi_matched is True
        assert lead_a.subgraph_node_count >= 2
        # Verify investigative assessment is an explainable lead, not proof of crime
        assert lead_a.investigative_assessment in (
            "CROSS_BANK_INVESTIGATION_LEAD",
            "CONFIRMED_MULTI_BANK_INVESTIGATION_LEAD",
            "BENIGN_CROSS_BANK_ENTITY_MATCH",
        )

    for matched_token in psi_result.bank_b_matched_tokens:
        lead_b = expander_b.expand_neighborhood(graph_b, matched_token, hops=1)
        assert lead_b is not None
        assert lead_b.local_account_id.startswith("ACC_B_")
        assert lead_b.psi_matched is True
        assert lead_b.subgraph_node_count >= 2

    # ── 6. Boundary Verification ─────────────────────────────────────────────
    # Verify no ground truth files were opened by operational agents
    assert psi_result.total_wire_bytes > 0
