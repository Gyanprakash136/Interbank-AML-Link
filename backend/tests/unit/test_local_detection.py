"""Unit tests for Local Rule-Based Detection Engine.

Validates:
1. Expected rule firing on known AML typologies:
   - Structuring / Smurfing
   - Rapid pass-through layering
   - Fan-in aggregation
   - Fan-out dispersion
   - High-value conduit
2. Negative control: Benign retail accounts do NOT trigger suspicion.
3. PSI eligibility gating: Only flagged accounts with canonical tokens are emitted.
4. Token opacity: Emitted tokens are strictly opaque and contain no metadata.
"""

import networkx as nx
import pytest

from app.banks.local_detection import LocalRuleDetectionEngine
from app.core.security import assert_opaque_tokens
from app.graph.features import LocalGraphFeatureExtractor


@pytest.fixture
def multi_typology_graph():
    """Builds a test graph with 4 distinct account behaviors:
    1. ACC_SMURF: structuring cash deposits + rapid pass through.
    2. ACC_FAN_IN: multiple incoming senders aggregating funds.
    3. ACC_FAN_OUT: dispersing funds to multiple beneficiaries.
    4. ACC_BENIGN: normal low-value retail transfers.
    """
    G = nx.MultiDiGraph()

    # Accounts
    G.add_node("ACC_SMURF", is_local=True, canonical_token="TOK_1111222233334444", entity_type="INDIVIDUAL", kyc_risk_score=0.60)
    G.add_node("ACC_FAN_IN", is_local=True, canonical_token="TOK_5555666677778888", entity_type="CORPORATION", kyc_risk_score=0.50)
    G.add_node("ACC_FAN_OUT", is_local=True, canonical_token="TOK_9999aaaabbbbcccc", entity_type="CORPORATION", kyc_risk_score=0.50)
    G.add_node("ACC_BENIGN", is_local=True, canonical_token="TOK_ddddeeeeffff0000", entity_type="INDIVIDUAL", kyc_risk_score=0.10)

    # External counterparties
    for i in range(1, 6):
        G.add_node(f"EXT_SRC_{i}", is_local=False, canonical_token=None, entity_type="EXTERNAL", kyc_risk_score=0.0)
        G.add_node(f"EXT_DST_{i}", is_local=False, canonical_token=None, entity_type="EXTERNAL", kyc_risk_score=0.0)

    # 1. Smurf flows: 2 structured cash deposits + outbound wire
    G.add_edge("EXT_SRC_1", "ACC_SMURF", key="T1", amount=9500.0, tx_type="CASH_DEPOSIT", timestamp="2026-03-01T08:00:00Z")
    G.add_edge("EXT_SRC_2", "ACC_SMURF", key="T2", amount=9600.0, tx_type="CASH_DEPOSIT", timestamp="2026-03-01T09:00:00Z")
    G.add_edge("ACC_SMURF", "EXT_DST_1", key="T3", amount=19000.0, tx_type="WIRE", timestamp="2026-03-01T12:00:00Z")

    # 2. Fan-In flows: 3 senders send 6000 each to ACC_FAN_IN
    G.add_edge("EXT_SRC_1", "ACC_FAN_IN", key="T4", amount=6000.0, tx_type="WIRE", timestamp="2026-03-01T10:00:00Z")
    G.add_edge("EXT_SRC_2", "ACC_FAN_IN", key="T5", amount=6000.0, tx_type="WIRE", timestamp="2026-03-01T10:30:00Z")
    G.add_edge("EXT_SRC_3", "ACC_FAN_IN", key="T6", amount=6000.0, tx_type="WIRE", timestamp="2026-03-01T11:00:00Z")
    G.add_edge("ACC_FAN_IN", "EXT_DST_2", key="T7", amount=17500.0, tx_type="WIRE", timestamp="2026-03-02T10:00:00Z")

    # 3. Fan-Out flows: ACC_FAN_OUT receives 25000 and disperses to 3 beneficiaries
    G.add_edge("EXT_SRC_4", "ACC_FAN_OUT", key="T8", amount=25000.0, tx_type="WIRE", timestamp="2026-03-01T08:00:00Z")
    G.add_edge("ACC_FAN_OUT", "EXT_DST_3", key="T9", amount=8000.0, tx_type="WIRE", timestamp="2026-03-01T12:00:00Z")
    G.add_edge("ACC_FAN_OUT", "EXT_DST_4", key="T10", amount=8000.0, tx_type="WIRE", timestamp="2026-03-01T12:30:00Z")
    G.add_edge("ACC_FAN_OUT", "EXT_DST_5", key="T11", amount=8000.0, tx_type="WIRE", timestamp="2026-03-01T13:00:00Z")

    # 4. Benign flows
    G.add_edge("ACC_BENIGN", "EXT_DST_1", key="T12", amount=45.0, tx_type="POS", timestamp="2026-03-01T15:00:00Z")
    G.add_edge("ACC_BENIGN", "EXT_DST_2", key="T13", amount=120.0, tx_type="ACH", timestamp="2026-03-02T09:00:00Z")

    return G


def test_rule_detection_on_smurf_account(multi_typology_graph):
    """Confirms smurf account triggers RULE_STRUCTURING_SMURFING and RULE_RAPID_PASS_THROUGH."""
    extractor = LocalGraphFeatureExtractor()
    feat = extractor.extract_for_account(multi_typology_graph, "ACC_SMURF")

    engine = LocalRuleDetectionEngine(suspicion_threshold=0.50)
    alert = engine.evaluate_account(feat)

    assert alert.is_suspicious is True
    assert alert.is_eligible_for_psi is True
    assert "RULE_STRUCTURING_SMURFING" in alert.triggered_rules
    assert "RULE_RAPID_PASS_THROUGH" in alert.triggered_rules
    assert alert.local_risk_score >= 0.70


def test_rule_detection_on_fan_in_and_fan_out(multi_typology_graph):
    """Confirms fan-in and fan-out rules trigger on aggregating and dispersing accounts."""
    extractor = LocalGraphFeatureExtractor()
    engine = LocalRuleDetectionEngine(suspicion_threshold=0.50)

    # Fan-in
    feat_in = extractor.extract_for_account(multi_typology_graph, "ACC_FAN_IN")
    alert_in = engine.evaluate_account(feat_in)
    assert alert_in.is_suspicious is True
    assert "RULE_HIGH_FAN_IN" in alert_in.triggered_rules

    # Fan-out
    feat_out = extractor.extract_for_account(multi_typology_graph, "ACC_FAN_OUT")
    alert_out = engine.evaluate_account(feat_out)
    assert alert_out.is_suspicious is True
    assert "RULE_HIGH_FAN_OUT" in alert_out.triggered_rules


def test_rule_detection_negative_control_benign(multi_typology_graph):
    """Confirms benign low-volume account triggers zero rules and is NOT eligible for PSI."""
    extractor = LocalGraphFeatureExtractor()
    feat = extractor.extract_for_account(multi_typology_graph, "ACC_BENIGN")

    engine = LocalRuleDetectionEngine(suspicion_threshold=0.50)
    alert = engine.evaluate_account(feat)

    assert alert.is_suspicious is False
    assert alert.is_eligible_for_psi is False
    assert len(alert.triggered_rules) == 0
    assert alert.local_risk_score < 0.20


def test_get_eligible_psi_tokens(multi_typology_graph):
    """Confirms get_eligible_psi_tokens returns only opaque tokens for suspicious accounts."""
    engine = LocalRuleDetectionEngine(suspicion_threshold=0.50)
    tokens = engine.get_eligible_psi_tokens(multi_typology_graph)

    # Should contain tokens for ACC_SMURF, ACC_FAN_IN, ACC_FAN_OUT, but NOT ACC_BENIGN
    assert len(tokens) == 3
    assert "TOK_1111222233334444" in tokens
    assert "TOK_5555666677778888" in tokens
    assert "TOK_9999aaaabbbbcccc" in tokens
    assert "TOK_ddddeeeeffff0000" not in tokens

    # Verify strict token opacity
    assert_opaque_tokens(tokens)


def test_incomplete_currency_coverage_detection_rule_and_warning():
    """Confirms unmapped foreign currency transactions trigger RULE_INCOMPLETE_CURRENCY_COVERAGE and audit warning."""
    G = nx.MultiDiGraph()
    G.add_node("ACC_FX_PARTIAL", is_local=True, canonical_token="TOK_fx11223344556677", entity_type="CORPORATION", kyc_risk_score=0.40)
    G.add_node("EXT_USD", is_local=False, canonical_token=None, entity_type="EXTERNAL", kyc_risk_score=0.0)
    G.add_node("EXT_EUR", is_local=False, canonical_token=None, entity_type="EXTERNAL", kyc_risk_score=0.0)

    # 1 USD wire (5,000) and 1 EUR wire (50,000)
    G.add_edge("EXT_USD", "ACC_FX_PARTIAL", key="TX1", amount=5000.0, currency="USD", tx_type="WIRE", timestamp="2026-03-01T10:00:00Z")
    G.add_edge("EXT_EUR", "ACC_FX_PARTIAL", key="TX2", amount=50000.0, currency="EUR", tx_type="WIRE", timestamp="2026-03-01T11:00:00Z")

    extractor = LocalGraphFeatureExtractor(base_currency="USD")
    feat = extractor.extract_for_account(G, "ACC_FX_PARTIAL")

    assert feat.currency_coverage_complete is False
    assert feat.excluded_currencies == ["EUR"]
    assert feat.excluded_currency_tx_count == 1
    assert feat.total_in_amount == 5000.0  # Only USD counted

    engine = LocalRuleDetectionEngine()
    alert = engine.evaluate_account(feat)

    # 1. Warning & Rule assertions
    assert "RULE_INCOMPLETE_CURRENCY_COVERAGE" in alert.triggered_rules
    assert any("Financial totals reflect partial activity" in exp for exp in alert.rule_explanations)

    # 2. Risk Score Policy assertion: Missing FX mapping is a data warning, NOT an illicit behavior indicator
    # Expected score: KYC component only (0.40 * 0.20 = 0.08), zero artificial inflation (+0.20 omitted)
    assert alert.local_risk_score == 0.08
    assert alert.is_suspicious is False
    assert alert.is_eligible_for_psi is False

    # 3. Supporting Evidence assertions
    assert alert.supporting_evidence["currency_coverage_complete"] is False
    assert alert.supporting_evidence["excluded_currencies"] == ["EUR"]
    assert alert.supporting_evidence["excluded_currency_tx_count"] == 1
    assert "EUR" in alert.supporting_evidence["coverage_warning"]


def test_incomplete_currency_coverage_with_actual_suspicious_typology():
    """Confirms data completeness warning coexists with genuine AML typologies without score interference."""
    G = nx.MultiDiGraph()
    G.add_node("ACC_FX_SMURF", is_local=True, canonical_token="TOK_fx_smurf_9999", entity_type="INDIVIDUAL", kyc_risk_score=0.50)
    G.add_node("EXT_USD", is_local=False, canonical_token=None, entity_type="EXTERNAL", kyc_risk_score=0.0)
    G.add_node("EXT_EUR", is_local=False, canonical_token=None, entity_type="EXTERNAL", kyc_risk_score=0.0)

    # Structured USD deposits (triggering RULE_STRUCTURING_SMURFING: +0.40) + 1 foreign EUR transaction
    G.add_edge("EXT_USD", "ACC_FX_SMURF", key="T1", amount=9500.0, currency="USD", tx_type="CASH_DEPOSIT", timestamp="2026-03-01T08:00:00Z")
    G.add_edge("EXT_USD", "ACC_FX_SMURF", key="T2", amount=9600.0, currency="USD", tx_type="CASH_DEPOSIT", timestamp="2026-03-01T09:00:00Z")
    G.add_edge("EXT_EUR", "ACC_FX_SMURF", key="T3", amount=40000.0, currency="EUR", tx_type="WIRE", timestamp="2026-03-01T10:00:00Z")

    extractor = LocalGraphFeatureExtractor(base_currency="USD")
    feat = extractor.extract_for_account(G, "ACC_FX_SMURF")

    engine = LocalRuleDetectionEngine(suspicion_threshold=0.50)
    alert = engine.evaluate_account(feat)

    # Both the genuine typologies and data completeness warning are present
    assert "RULE_STRUCTURING_SMURFING" in alert.triggered_rules
    assert "RULE_HIGH_FAN_IN" in alert.triggered_rules
    assert "RULE_INCOMPLETE_CURRENCY_COVERAGE" in alert.triggered_rules

    # Score: Structuring (0.40) + Fan-In (0.35) + KYC (0.50 * 0.20 = 0.10) = 0.85
    # Confirms currency completeness warning added 0.00 to the score
    assert alert.local_risk_score == 0.85
    assert alert.is_suspicious is True
    assert alert.is_eligible_for_psi is True
    assert alert.supporting_evidence["currency_coverage_complete"] is False
    assert alert.supporting_evidence["excluded_currencies"] == ["EUR"]
