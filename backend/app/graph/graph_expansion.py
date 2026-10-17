"""SignalMesh Matched-Seed Graph Expansion.

Expands local k-hop neighborhoods for authorized matched entity seeds following a PSI round.

CRITICAL PRIVACY & ANALYTICAL SAFEGUARDS:
1. Local Investigation Only:
   The expanded subgraph and derived metrics stay strictly within the local bank's
   investigation service. Subgraphs are NEVER transmitted to other banks or the central matching service.
2. Match Status != Laundering Alert:
   A Private Set Intersection (PSI) match confirms only that an entity exists across institutions.
   A PSI match alone DOES NOT classify an entity as a money launderer.
   Local transactional evidence (structuring, velocity, pass-through) is strictly required to confirm
   an investigative lead. Benign multi-bank commercial entities remain classified as benign.
"""

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Set
import networkx as nx

from app.banks.local_detection import LocalDetectionAlert, LocalRuleDetectionEngine
from app.graph.features import LocalGraphFeatureExtractor


@dataclass(frozen=True)
class LocalInvestigationLead:
    """Structured result of local neighborhood expansion for an authorized PSI match."""
    matched_token: str
    local_account_id: str
    expansion_hops: int
    neighbor_accounts: List[str]
    subgraph_node_count: int
    subgraph_edge_count: int
    subgraph_total_volume: float
    prior_local_risk_score: float
    updated_local_suspicion_score: float
    psi_matched: bool
    investigative_assessment: str
    supporting_evidence: Dict[str, Any]
    investigation_timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class MatchedSeedGraphExpander:
    """Expands local subgraphs around PSI-matched seeds within a bank's local graph."""

    def __init__(self, rule_engine: Optional[LocalRuleDetectionEngine] = None):
        self.rule_engine = rule_engine or LocalRuleDetectionEngine()
        self.feature_extractor = LocalGraphFeatureExtractor()

    def expand_neighborhood(
        self,
        G: nx.MultiDiGraph,
        matched_token: str,
        hops: int = 1,
    ) -> Optional[LocalInvestigationLead]:
        """Expands a 1-hop or 2-hop local neighborhood around the account corresponding to matched_token.

        Returns None if the token does not match any local account in G.
        """
        # 1. Resolve token to local account ID in G
        target_account: Optional[str] = None
        for node_id, data in G.nodes(data=True):
            if data.get("canonical_token") == matched_token:
                target_account = node_id
                break

        if target_account is None:
            return None

        # 2. Extract k-hop neighborhood nodes in local graph
        neighborhood_nodes: Set[str] = {target_account}
        frontier: Set[str] = {target_account}

        for _ in range(max(1, hops)):
            next_frontier: Set[str] = set()
            for node in frontier:
                # Add all successors and predecessors
                succs = set(G.successors(node))
                preds = set(G.predecessors(node))
                next_frontier.update(succs | preds)
            frontier = next_frontier - neighborhood_nodes
            neighborhood_nodes.update(frontier)

        # 3. Build local subgraph and calculate volume by currency
        subgraph = G.subgraph(neighborhood_nodes).copy()
        subgraph_nodes = sorted(neighborhood_nodes)
        subgraph_edges = list(subgraph.edges(data=True))

        # Safely aggregate volume grouped by currency (NEVER combine incompatible currencies)
        volumes_by_currency: Dict[str, float] = {}
        for u, v, d in subgraph_edges:
            curr = str(d.get("currency", "USD")).upper()
            amt = float(d.get("amount", 0.0))
            volumes_by_currency[curr] = round(volumes_by_currency.get(curr, 0.0) + amt, 2)

        # Primary volume reported in USD if present, otherwise largest currency or 0.0
        total_volume = volumes_by_currency.get("USD", sum(volumes_by_currency.values()) if len(volumes_by_currency) == 1 else 0.0)

        # 4. Evaluate local transactional suspicion on the target account
        feat = self.feature_extractor.extract_for_account(G, target_account)
        alert = self.rule_engine.evaluate_account(feat)
        prior_score = alert.local_risk_score

        # 5. Assess investigative priority based on COMBINATION of local evidence and PSI match
        # Match != Crime: A match alone is never proof of crime.
        # Use CROSS_BANK_INVESTIGATION_LEAD to avoid implying crime confirmation.
        if prior_score >= 0.40:
            # High or moderate local suspicion + confirmed cross-bank presence = investigation lead
            updated_score = min(1.0, round(prior_score + 0.20, 3))
            assessment = "CROSS_BANK_INVESTIGATION_LEAD"
        else:
            # Low local suspicion (< 0.40) + PSI match = benign multi-bank customer
            updated_score = min(0.35, prior_score)
            assessment = "BENIGN_CROSS_BANK_ENTITY_MATCH"

        evidence = {
            "target_account": target_account,
            "target_entity_type": feat.entity_type,
            "local_rules_triggered": alert.triggered_rules,
            "rule_explanations": alert.rule_explanations,
            "structuring_count": feat.structuring_count,
            "turnover_ratio": feat.turnover_ratio,
            "rapid_pass_through_hours": feat.rapid_pass_through_hours,
            "subgraph_nodes": subgraph_nodes,
            "subgraph_edge_count": len(subgraph_edges),
            "subgraph_total_volume": round(total_volume, 2),
            "volumes_by_currency": volumes_by_currency,
            "currencies_observed": sorted(volumes_by_currency.keys()),
        }

        neighbor_accounts = [n for n in subgraph_nodes if n != target_account]

        return LocalInvestigationLead(
            matched_token=matched_token,
            local_account_id=target_account,
            expansion_hops=hops,
            neighbor_accounts=neighbor_accounts,
            subgraph_node_count=len(subgraph_nodes),
            subgraph_edge_count=len(subgraph_edges),
            subgraph_total_volume=round(total_volume, 2),
            prior_local_risk_score=prior_score,
            updated_local_suspicion_score=updated_score,
            psi_matched=True,
            investigative_assessment=assessment,
            supporting_evidence=evidence,
            investigation_timestamp=datetime.utcnow().isoformat(),
        )
