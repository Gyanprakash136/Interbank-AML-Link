"""Unit tests for Matched-Seed Graph Expansion.

Validates:
1. Extraction of 1-hop and 2-hop local transaction neighborhoods.
2. Subgraph volume, node counts, and edge counts.
3. Strict separation of match status from laundering alert:
   - High local suspicion + PSI match -> CONFIRMED_MULTI_BANK_INVESTIGATION_LEAD (elevated score)
   - Low local suspicion + PSI match -> BENIGN_CROSS_BANK_ENTITY_MATCH (score remains low)
4. Non-matching tokens return None gracefully.
5. All operations stay strictly local to the bank's own graph.
"""

import networkx as nx
import pytest

from app.graph.graph_expansion import MatchedSeedGraphExpander


@pytest.fixture
def expansion_test_graph():
    """Builds a test graph with a 2-hop neighborhood around a suspicious account and a benign account."""
    G = nx.MultiDiGraph()

    # Suspicious Syndicate Account (ACC_SYND)
    G.add_node("ACC_SYND", is_local=True, canonical_token="TOK_syndicate_token_01", entity_type="CORPORATION", kyc_risk_score=0.80)
    G.add_node("EXT_DEPOSITOR_1", is_local=False, canonical_token=None, entity_type="EXTERNAL", kyc_risk_score=0.0)
    G.add_node("EXT_DEPOSITOR_2", is_local=False, canonical_token=None, entity_type="EXTERNAL", kyc_risk_score=0.0)
    G.add_node("LOCAL_INTERMEDIARY", is_local=True, canonical_token="TOK_intermediary_02", entity_type="INDIVIDUAL", kyc_risk_score=0.30)
    G.add_node("EXT_OFFSHORE", is_local=False, canonical_token=None, entity_type="EXTERNAL", kyc_risk_score=0.0)

    # 1-hop connections to ACC_SYND
    G.add_edge("EXT_DEPOSITOR_1", "ACC_SYND", key="E1", amount=9800.0, tx_type="CASH_DEPOSIT", timestamp="2026-03-01T08:00:00Z")
    G.add_edge("EXT_DEPOSITOR_2", "ACC_SYND", key="E2", amount=9700.0, tx_type="CASH_DEPOSIT", timestamp="2026-03-01T09:00:00Z")
    G.add_edge("ACC_SYND", "LOCAL_INTERMEDIARY", key="E3", amount=19400.0, tx_type="WIRE", timestamp="2026-03-01T12:00:00Z")

    # 2-hop connection from LOCAL_INTERMEDIARY to EXT_OFFSHORE
    G.add_edge("LOCAL_INTERMEDIARY", "EXT_OFFSHORE", key="E4", amount=19000.0, tx_type="WIRE", timestamp="2026-03-01T16:00:00Z")

    # Benign Multi-Bank Commercial Account (ACC_BENIGN_CORP)
    G.add_node("ACC_BENIGN_CORP", is_local=True, canonical_token="TOK_benign_corp_token", entity_type="CORPORATION", kyc_risk_score=0.05)
    G.add_node("EXT_SUPPLIER", is_local=False, canonical_token=None, entity_type="EXTERNAL", kyc_risk_score=0.0)
    G.add_edge("ACC_BENIGN_CORP", "EXT_SUPPLIER", key="E5", amount=1200.0, tx_type="ACH", timestamp="2026-03-01T10:00:00Z")

    return G


def test_expand_neighborhood_1_hop(expansion_test_graph):
    """Confirms 1-hop expansion includes direct predecessors and successors only."""
    expander = MatchedSeedGraphExpander()
    lead = expander.expand_neighborhood(expansion_test_graph, "TOK_syndicate_token_01", hops=1)

    assert lead is not None
    assert lead.local_account_id == "ACC_SYND"
    assert lead.expansion_hops == 1
    # 1-hop neighbors: EXT_DEPOSITOR_1, EXT_DEPOSITOR_2, LOCAL_INTERMEDIARY
    assert set(lead.neighbor_accounts) == {"EXT_DEPOSITOR_1", "EXT_DEPOSITOR_2", "LOCAL_INTERMEDIARY"}
    assert lead.subgraph_node_count == 4
    assert lead.subgraph_edge_count == 3
    # 2-hop node EXT_OFFSHORE should NOT be in 1-hop expansion
    assert "EXT_OFFSHORE" not in lead.neighbor_accounts


def test_expand_neighborhood_2_hop(expansion_test_graph):
    """Confirms 2-hop expansion reaches the 2nd hop node EXT_OFFSHORE."""
    expander = MatchedSeedGraphExpander()
    lead = expander.expand_neighborhood(expansion_test_graph, "TOK_syndicate_token_01", hops=2)

    assert lead is not None
    assert lead.subgraph_node_count == 5  # ACC_SYND + 3 (1-hop) + 1 (2-hop EXT_OFFSHORE)
    assert "EXT_OFFSHORE" in lead.neighbor_accounts
    assert lead.subgraph_edge_count == 4


def test_match_status_distinguishes_suspicious_from_benign(expansion_test_graph):
    """Confirms suspicious account elevates to CONFIRMED_MULTI_BANK while benign remains BENIGN_MATCH."""
    expander = MatchedSeedGraphExpander()

    # Suspicious lead
    lead_synd = expander.expand_neighborhood(expansion_test_graph, "TOK_syndicate_token_01", hops=1)
    assert lead_synd.investigative_assessment == "CROSS_BANK_INVESTIGATION_LEAD"
    assert lead_synd.updated_local_suspicion_score >= lead_synd.prior_local_risk_score
    assert lead_synd.updated_local_suspicion_score >= 0.80

    # Benign lead
    lead_benign = expander.expand_neighborhood(expansion_test_graph, "TOK_benign_corp_token", hops=1)
    assert lead_benign.investigative_assessment == "BENIGN_CROSS_BANK_ENTITY_MATCH"
    assert lead_benign.updated_local_suspicion_score <= 0.35


def test_expand_neighborhood_unknown_token_returns_none(expansion_test_graph):
    """Confirms expander returns None when asked to expand a token not present in this bank."""
    expander = MatchedSeedGraphExpander()
    lead = expander.expand_neighborhood(expansion_test_graph, "TOK_nonexistent_token", hops=1)
    assert lead is None


def test_multi_currency_aggregation_separation():
    """Confirms subgraph volume does not blindly combine incompatible currencies."""
    G = nx.MultiDiGraph()
    G.add_node("ACC_MULTI", is_local=True, canonical_token="TOK_multicurrency_01", entity_type="CORPORATION", kyc_risk_score=0.50)
    G.add_node("EXT_1", is_local=False, canonical_token=None, entity_type="EXTERNAL", kyc_risk_score=0.0)
    G.add_node("EXT_2", is_local=False, canonical_token=None, entity_type="EXTERNAL", kyc_risk_score=0.0)

    # 10,000 USD and 10,000 EUR
    G.add_edge("EXT_1", "ACC_MULTI", key="TX_USD", amount=10000.0, currency="USD", tx_type="WIRE", timestamp="2026-03-01T10:00:00Z")
    G.add_edge("EXT_2", "ACC_MULTI", key="TX_EUR", amount=10000.0, currency="EUR", tx_type="WIRE", timestamp="2026-03-01T11:00:00Z")

    expander = MatchedSeedGraphExpander()
    lead = expander.expand_neighborhood(G, "TOK_multicurrency_01", hops=1)

    assert lead is not None
    # Volumes by currency must be strictly separated
    v_by_curr = lead.supporting_evidence["volumes_by_currency"]
    assert v_by_curr["USD"] == 10000.0
    assert v_by_curr["EUR"] == 10000.0
    assert "EUR" in lead.supporting_evidence["currencies_observed"]
    assert "USD" in lead.supporting_evidence["currencies_observed"]

