"""SignalMesh Rules-Based Suspicious-Entity Detection Engine.

Executes deterministic, explainable rule-based AML suspicion scoring on bank-local graph features.

CORE AML RULES:
1. RULE_STRUCTURING_SMURFING:
   Multiple deposits just below the $10,000 CTR reporting threshold (e.g. $9,000–$9,999) or high cash deposit counts.
2. RULE_RAPID_PASS_THROUGH:
   Funds pass through the account rapidly (< 24 hours dwell time) with turnover ratio near 1.0 (85%–115%).
3. RULE_HIGH_FAN_IN:
   Multiple distinct counterparties funnel funds into a single aggregating account.
4. RULE_HIGH_FAN_OUT:
   A single account rapidly disperses funds out to multiple distinct counterparties.
5. RULE_HIGH_VALUE_CONDUIT:
   Substantial single transaction exceeding high-value monitoring thresholds (>= $40,000).

LEGAL & COMPLIANCE NOTICE:
Triggered rules and calculated risk indicators represent anomalous investigative leads
only and DO NOT constitute proof of criminal activity.
"""

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional
import networkx as nx

from app.core.security import assert_opaque_tokens
from app.graph.features import LocalAccountFeatures, LocalGraphFeatureExtractor


@dataclass(frozen=True)
class LocalDetectionAlert:
    """Structured detection result for a single bank-local account."""
    account_id: str
    canonical_token: Optional[str]
    is_suspicious: bool
    is_eligible_for_psi: bool
    local_risk_score: float
    triggered_rules: List[str]
    rule_explanations: List[str]
    supporting_evidence: Dict[str, Any]
    detection_timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class LocalRuleDetectionEngine:
    """Configurable, deterministic AML rule engine operating exclusively on local graph features."""

    def __init__(
        self,
        suspicion_threshold: float = 0.50,
        structuring_threshold_count: int = 2,
        high_value_conduit_amount: float = 40000.0,
        rapid_pass_through_max_hours: float = 24.0,
    ):
        self.suspicion_threshold = suspicion_threshold
        self.structuring_threshold_count = structuring_threshold_count
        self.high_value_conduit_amount = high_value_conduit_amount
        self.rapid_pass_through_max_hours = rapid_pass_through_max_hours

    def evaluate_account(self, feat: LocalAccountFeatures) -> LocalDetectionAlert:
        """Evaluates rules for a single account based on local graph features."""
        triggered_rules: List[str] = []
        rule_explanations: List[str] = []
        score_components: float = 0.0

        # Rule 1: Structuring / Smurfing
        if feat.structuring_count >= self.structuring_threshold_count or (feat.cash_deposit_count >= 2 and feat.total_in_amount >= 15000.0):
            triggered_rules.append("RULE_STRUCTURING_SMURFING")
            rule_explanations.append(
                f"Observed {feat.structuring_count} transactions near reporting threshold and "
                f"{feat.cash_deposit_count} cash deposits totaling ${feat.cash_deposit_amount:,.2f}."
            )
            score_components += 0.40

        # Rule 2: Rapid Pass-Through Layering
        if (
            feat.rapid_pass_through_hours is not None
            and feat.rapid_pass_through_hours <= self.rapid_pass_through_max_hours
            and 0.85 <= feat.turnover_ratio <= 1.15
            and feat.total_out_amount >= 10000.0
        ):
            triggered_rules.append("RULE_RAPID_PASS_THROUGH")
            rule_explanations.append(
                f"Rapid funds disbursement within {feat.rapid_pass_through_hours:.1f} hours of receipt "
                f"with turnover ratio of {feat.turnover_ratio:.2f}."
            )
            score_components += 0.35

        # Rule 3: High Fan-In (Aggregation)
        if feat.in_degree >= 2 and feat.fan_in_ratio >= 1.5 and feat.total_in_amount >= 15000.0:
            triggered_rules.append("RULE_HIGH_FAN_IN")
            rule_explanations.append(
                f"Fan-in aggregation from {feat.in_degree} distinct source counterparties "
                f"with in/out ratio of {feat.fan_in_ratio:.1f}."
            )
            score_components += 0.35

        # Rule 4: High Fan-Out (Dispersion)
        if feat.out_degree >= 2 and feat.fan_out_ratio >= 1.5 and feat.total_out_amount >= 15000.0:
            triggered_rules.append("RULE_HIGH_FAN_OUT")
            rule_explanations.append(
                f"Fan-out dispersion to {feat.out_degree} distinct beneficiary counterparties "
                f"with out/in ratio of {feat.fan_out_ratio:.1f}."
            )
            score_components += 0.35

        # Rule 5: High-Value Conduit
        if feat.max_out_amount >= self.high_value_conduit_amount or feat.max_in_amount >= self.high_value_conduit_amount:
            triggered_rules.append("RULE_HIGH_VALUE_CONDUIT")
            max_val = max(feat.max_in_amount, feat.max_out_amount)
            rule_explanations.append(
                f"Single transaction value of ${max_val:,.2f} exceeds threshold (${self.high_value_conduit_amount:,.2f})."
            )
            score_components += 0.30

        # Currency Coverage Data-Completeness Warning
        if not feat.currency_coverage_complete:
            triggered_rules.append("RULE_INCOMPLETE_CURRENCY_COVERAGE")
            rule_explanations.append(
                f"AUDIT WARNING: Financial totals reflect partial activity. {feat.coverage_warning}"
            )
            # Note: Missing currency mappings are treated strictly as a data-completeness warning,
            # not an illicit behavior risk indicator. No artificial risk score adjustment is applied,
            # ensuring AML risk scores reflect genuine observed transactional typologies.

        # Add KYC local risk component (scaled at 20%)
        score_components += feat.kyc_risk_score * 0.20

        final_risk_score = min(1.0, round(score_components, 3))
        is_suspicious = final_risk_score >= self.suspicion_threshold
        # Eligible for PSI only if suspicious and has a valid canonical token
        is_eligible_for_psi = is_suspicious and bool(feat.canonical_token)

        supporting_evidence = {
            "total_in_amount": feat.total_in_amount,
            "total_out_amount": feat.total_out_amount,
            "turnover_ratio": feat.turnover_ratio,
            "structuring_count": feat.structuring_count,
            "in_degree": feat.in_degree,
            "out_degree": feat.out_degree,
            "rapid_pass_through_hours": feat.rapid_pass_through_hours,
            "kyc_risk_score": feat.kyc_risk_score,
            "currency_coverage_complete": feat.currency_coverage_complete,
            "excluded_currencies": feat.excluded_currencies,
            "excluded_currency_tx_count": feat.excluded_currency_tx_count,
            "coverage_warning": feat.coverage_warning,
        }

        return LocalDetectionAlert(
            account_id=feat.account_id,
            canonical_token=feat.canonical_token,
            is_suspicious=is_suspicious,
            is_eligible_for_psi=is_eligible_for_psi,
            local_risk_score=final_risk_score,
            triggered_rules=triggered_rules,
            rule_explanations=rule_explanations,
            supporting_evidence=supporting_evidence,
            detection_timestamp=datetime.utcnow().isoformat(),
        )

    def evaluate_graph(self, G: nx.MultiDiGraph) -> List[LocalDetectionAlert]:
        """Evaluates all locally-owned accounts in the graph."""
        extractor = LocalGraphFeatureExtractor()
        all_features = extractor.extract_all_local_accounts(G)
        alerts = [self.evaluate_account(feat) for feat in all_features.values()]
        # Sort deterministically by risk score descending, then account_id
        return sorted(alerts, key=lambda a: (-a.local_risk_score, a.account_id))

    def get_eligible_psi_tokens(self, G: nx.MultiDiGraph) -> List[str]:
        """Extracts approved, deduplicated canonical entity tokens eligible for PSI collaborative matching.

        Privacy Boundary Guarantees:
        - Only pure string tokens ('TOK_<16_hex>') are returned.
        - Verified by assert_opaque_tokens before emission.
        - Zero transaction records, amounts, or account numbers are included.
        """
        alerts = self.evaluate_graph(G)
        eligible_tokens = [
            a.canonical_token
            for a in alerts
            if a.is_eligible_for_psi and a.canonical_token is not None
        ]
        unique_sorted_tokens = sorted(set(eligible_tokens))
        assert_opaque_tokens(unique_sorted_tokens)
        return unique_sorted_tokens
