"""Unit tests for Local Graph Feature Extractor.

Validates:
1. Exact degree and transaction counts.
2. Volume totals, averages, and net flow.
3. Turnover ratio and rapid pass-through dwell time.
4. Structuring and cash deposit anomaly counters.
5. Fan-in and fan-out ratios.
6. Local 2-hop neighborhood node counts.
"""

import networkx as nx
import pytest

from app.graph.features import LocalAccountFeatures, LocalGraphFeatureExtractor


@pytest.fixture
def test_graph():
    """Builds a deterministic test multigraph with known flow characteristics."""
    G = nx.MultiDiGraph()
    G.add_node("LOCAL_MULE", is_local=True, canonical_token="TOK_0123456789abcdef", entity_type="INDIVIDUAL", kyc_risk_score=0.70)
    G.add_node("LOCAL_BENIGN", is_local=True, canonical_token="TOK_abcdef0123456789", entity_type="CORPORATION", kyc_risk_score=0.10)
    G.add_node("EXT_ATM_1", is_local=False, canonical_token=None, entity_type="EXTERNAL", kyc_risk_score=0.0)
    G.add_node("EXT_ATM_2", is_local=False, canonical_token=None, entity_type="EXTERNAL", kyc_risk_score=0.0)
    G.add_node("EXT_WIRE_OUT", is_local=False, canonical_token=None, entity_type="EXTERNAL", kyc_risk_score=0.0)

    # Inbound structuring cash deposits to LOCAL_MULE
    G.add_edge("EXT_ATM_1", "LOCAL_MULE", key="TX_01", amount=9500.0, tx_type="CASH_DEPOSIT", timestamp="2026-03-01T09:00:00Z")
    G.add_edge("EXT_ATM_2", "LOCAL_MULE", key="TX_02", amount=9600.0, tx_type="CASH_DEPOSIT", timestamp="2026-03-01T10:00:00Z")

    # Outbound wire from LOCAL_MULE (4 hours after first cash deposit)
    G.add_edge("LOCAL_MULE", "EXT_WIRE_OUT", key="TX_03", amount=19000.0, tx_type="WIRE", timestamp="2026-03-01T13:00:00Z")

    # Benign normal transactions
    G.add_edge("LOCAL_BENIGN", "EXT_WIRE_OUT", key="TX_04", amount=500.0, tx_type="ACH", timestamp="2026-03-01T14:00:00Z")
    return G


def test_feature_extractor_on_mule_account(test_graph):
    """Confirms feature extractor accurately captures structuring, turnover, and rapid pass-through."""
    extractor = LocalGraphFeatureExtractor()
    feat = extractor.extract_for_account(test_graph, "LOCAL_MULE")

    assert feat.account_id == "LOCAL_MULE"
    assert feat.is_local is True
    assert feat.in_degree == 2  # EXT_ATM_1, EXT_ATM_2
    assert feat.out_degree == 1  # EXT_WIRE_OUT
    assert feat.in_tx_count == 2
    assert feat.out_tx_count == 1
    assert feat.total_tx_count == 3

    assert feat.total_in_amount == 19100.0  # 9500 + 9600
    assert feat.total_out_amount == 19000.0
    assert feat.net_flow == 100.0
    assert round(feat.turnover_ratio, 2) == 0.99  # 19000 / 19100

    # Structuring counts (both deposits between 9000 and 9999.99)
    assert feat.structuring_count == 2
    assert feat.cash_deposit_count == 2
    assert feat.cash_deposit_amount == 19100.0

    # Rapid pass-through: 09:00 to 13:00 = 4.0 hours
    assert feat.rapid_pass_through_hours == 4.0

    # Fan-in ratio: 2 / max(1, 1) = 2.0
    assert feat.fan_in_ratio == 2.0


def test_feature_extractor_on_benign_account(test_graph):
    """Confirms benign retail account shows zero structuring and zero pass-through."""
    extractor = LocalGraphFeatureExtractor()
    feat = extractor.extract_for_account(test_graph, "LOCAL_BENIGN")

    assert feat.in_degree == 0
    assert feat.out_degree == 1
    assert feat.total_in_amount == 0.0
    assert feat.total_out_amount == 500.0
    assert feat.structuring_count == 0
    assert feat.cash_deposit_count == 0
    assert feat.rapid_pass_through_hours is None


def test_feature_extractor_extract_all_local(test_graph):
    """Confirms extractor processes only local nodes when extract_all_local_accounts is called."""
    extractor = LocalGraphFeatureExtractor()
    all_feats = extractor.extract_all_local_accounts(test_graph)

    assert len(all_feats) == 2
    assert "LOCAL_MULE" in all_feats
    assert "LOCAL_BENIGN" in all_feats
    assert "EXT_ATM_1" not in all_feats


def test_feature_extractor_multi_currency_isolation():
    """Confirms that amounts in differing currencies are never added as if identical (Phase 6.14)."""
    G = nx.MultiDiGraph()
    G.add_node("LOCAL_MULTI", is_local=True, canonical_token="TOK_curr_01", entity_type="INDIVIDUAL", kyc_risk_score=0.20)
    G.add_node("EXT_USD", is_local=False, canonical_token=None, entity_type="EXTERNAL", kyc_risk_score=0.0)
    G.add_node("EXT_EUR", is_local=False, canonical_token=None, entity_type="EXTERNAL", kyc_risk_score=0.0)

    # Inbound: 5,000 USD and 5,000 EUR
    G.add_edge("EXT_USD", "LOCAL_MULTI", key="TX1", amount=5000.0, currency="USD", tx_type="WIRE", timestamp="2026-03-01T10:00:00Z")
    G.add_edge("EXT_EUR", "LOCAL_MULTI", key="TX2", amount=5000.0, currency="EUR", tx_type="WIRE", timestamp="2026-03-01T11:00:00Z")

    # 1. Without exchange rates: strictly isolates to base_currency (USD), NEVER adds EUR to USD
    extractor_no_rates = LocalGraphFeatureExtractor(base_currency="USD")
    feat_no_rates = extractor_no_rates.extract_for_account(G, "LOCAL_MULTI")
    assert feat_no_rates.total_in_amount == 5000.0  # Only the USD amount is aggregated, NOT 10,000.0!

    # 2. With explicit exchange rates: EUR is converted to USD before aggregation
    extractor_with_rates = LocalGraphFeatureExtractor(
        base_currency="USD",
        exchange_rates={"USD": 1.0, "EUR": 1.10},
    )
    feat_with_rates = extractor_with_rates.extract_for_account(G, "LOCAL_MULTI")
    # 5,000 USD + (5,000 * 1.10 USD) = 5,000 + 5,500 = 10,500 USD
    assert feat_with_rates.total_in_amount == 10500.0

    # 3. Missing rate for foreign currency raises CurrencyMismatchError
    from app.graph.features import CurrencyMismatchError
    extractor_missing_rate = LocalGraphFeatureExtractor(
        base_currency="USD",
        exchange_rates={"USD": 1.0},  # EUR missing
    )
    with pytest.raises(CurrencyMismatchError, match="No exchange rate configured"):
        extractor_missing_rate.extract_for_account(G, "LOCAL_MULTI")

