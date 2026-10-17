"""SignalMesh Explainable Local Graph Feature Extraction.

Extracts explainable, audit-ready graph and transactional features for individual accounts
from a bank's local transaction graph.

FEATURE DEFINITIONS & EXPLANATIONS:
1. Degree & Count Metrics:
   - in_degree: Number of unique sender counterparties. High in_degree indicates aggregation / fan-in.
   - out_degree: Number of unique beneficiary counterparties. High out_degree indicates dispersion / fan-out.
   - in_tx_count / out_tx_count: Frequency of transfers into and out of the account.
2. Volume & Flow Metrics:
   - total_in_amount / total_out_amount: Gross aggregate funds received and disbursed.
   - turnover_ratio (total_out / total_in): Ratio of disbursed funds to received funds.
     A ratio close to 1.0 (e.g. 0.90 to 1.05) with short dwell time indicates a pass-through conduit.
   - net_flow (total_in - total_out): Net balance impact from observed local transactions.
3. AML Anomaly Indicators:
   - structuring_count: Count of transactions within $9,000 to $9,999.99 (just below the $10,000 CTR threshold).
   - cash_deposit_count / cash_deposit_amount: Volume of physical cash deposited.
   - rapid_pass_through_hours: Elapsed time between incoming funds and subsequent outgoing disbursement.
     Short delays (< 24 hours) signify rapid layering.
   - fan_in_ratio / fan_out_ratio: Imbalance between incoming counterparties and outgoing counterparties.
   - two_hop_neighbor_count: Breadth of the local 2-hop transaction neighborhood.

LIMITATIONS:
- Features reflect ONLY transactions recorded at the local bank.
- Inter-bank movements outside the local bank are invisible at this stage.
"""

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional
import networkx as nx


@dataclass(frozen=True)
class LocalAccountFeatures:
    """Structured feature vector for a single account in the local graph."""
    account_id: str
    is_local: bool
    canonical_token: Optional[str]
    entity_type: str
    kyc_risk_score: float

    # Degrees and Counts
    in_degree: int
    out_degree: int
    in_tx_count: int
    out_tx_count: int
    total_tx_count: int

    # Volume metrics
    total_in_amount: float
    total_out_amount: float
    avg_in_amount: float
    avg_out_amount: float
    max_in_amount: float
    max_out_amount: float
    net_flow: float
    turnover_ratio: float

    # AML Typology Indicators
    structuring_count: int
    cash_deposit_count: int
    cash_deposit_amount: float
    rapid_pass_through_hours: Optional[float]
    fan_in_ratio: float
    fan_out_ratio: float
    two_hop_neighbor_count: int
    participates_in_local_cycle: bool

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class CurrencyMismatchError(ValueError):
    """Raised when transactions have multiple incompatible currencies without exchange rates."""
    pass


class LocalGraphFeatureExtractor:
    """Extracts explainable features from a bank's local NetworkX graph."""

    def __init__(
        self,
        structuring_min: float = 9000.0,
        structuring_max: float = 9999.99,
        base_currency: str = "USD",
        exchange_rates: Optional[Dict[str, float]] = None,
    ):
        self.structuring_min = structuring_min
        self.structuring_max = structuring_max
        self.base_currency = base_currency.upper()
        self.exchange_rates = exchange_rates

    def extract_for_account(self, G: nx.MultiDiGraph, account_id: str) -> LocalAccountFeatures:
        """Extracts explainable feature metrics for a single node in G."""
        if account_id not in G:
            raise KeyError(f"Account '{account_id}' not found in transaction graph.")

        node_data = G.nodes[account_id]
        is_local = bool(node_data.get("is_local", False))
        canonical_token = node_data.get("canonical_token")
        entity_type = str(node_data.get("entity_type", "UNKNOWN"))
        kyc_risk_score = float(node_data.get("kyc_risk_score", 0.0))

        # Inbound transactions
        in_edges = list(G.in_edges(account_id, data=True))
        in_tx_count = len(in_edges)
        in_senders = {u for u, v, d in in_edges}
        in_degree = len(in_senders)

        # Collect inbound amounts by currency
        in_by_curr: Dict[str, List[float]] = {}
        for u, v, d in in_edges:
            c = str(d.get("currency", self.base_currency)).upper()
            amt = float(d.get("amount", 0.0))
            in_by_curr.setdefault(c, []).append(amt)

        # Outbound transactions
        out_edges = list(G.out_edges(account_id, data=True))
        out_tx_count = len(out_edges)
        out_receivers = {v for u, v, d in out_edges}
        out_degree = len(out_receivers)

        # Collect outbound amounts by currency
        out_by_curr: Dict[str, List[float]] = {}
        for u, v, d in out_edges:
            c = str(d.get("currency", self.base_currency)).upper()
            amt = float(d.get("amount", 0.0))
            out_by_curr.setdefault(c, []).append(amt)

        # Multi-currency handling: amounts in different currencies must NEVER be added as if identical
        all_currencies = set(in_by_curr.keys()) | set(out_by_curr.keys())
        if self.exchange_rates is not None:
            # Convert all amounts to base_currency using explicit exchange rate mapping
            in_amounts = []
            for c, amls in in_by_curr.items():
                rate = self.exchange_rates.get(c, 1.0 if c == self.base_currency else None)
                if rate is None:
                    raise CurrencyMismatchError(f"No exchange rate configured for currency '{c}'")
                in_amounts.extend([a * rate for a in amls])

            out_amounts = []
            for c, amls in out_by_curr.items():
                rate = self.exchange_rates.get(c, 1.0 if c == self.base_currency else None)
                if rate is None:
                    raise CurrencyMismatchError(f"No exchange rate configured for currency '{c}'")
                out_amounts.extend([a * rate for a in amls])
        elif len(all_currencies) <= 1:
            # Single uniform currency observed
            in_amounts = [amt for amls in in_by_curr.values() for amt in amls]
            out_amounts = [amt for amls in out_by_curr.values() for amt in amls]
        else:
            # Multi-currency present without exchange rates:
            # Strictly isolate to base_currency transactions, never adding differing currencies
            in_amounts = in_by_curr.get(self.base_currency, [])
            out_amounts = out_by_curr.get(self.base_currency, [])

        total_in = sum(in_amounts)
        avg_in = (total_in / in_tx_count) if in_tx_count > 0 else 0.0
        max_in = max(in_amounts) if in_amounts else 0.0

        total_out = sum(out_amounts)
        avg_out = (total_out / out_tx_count) if out_tx_count > 0 else 0.0
        max_out = max(out_amounts) if out_amounts else 0.0

        net_flow = total_in - total_out
        turnover_ratio = (total_out / total_in) if total_in > 0 else 0.0

        # Structuring and cash analysis
        structuring_count = 0
        cash_count = 0
        cash_amount = 0.0

        for u, v, d in in_edges + out_edges:
            c = str(d.get("currency", self.base_currency)).upper()
            raw_amt = float(d.get("amount", 0.0))
            tx_type = str(d.get("tx_type", "")).upper()

            # Normalize amount to base currency for threshold evaluations
            if self.exchange_rates is not None:
                rate = self.exchange_rates.get(c, 1.0 if c == self.base_currency else None)
                if rate is None:
                    continue
                amt = raw_amt * rate
            elif c == self.base_currency or len(all_currencies) <= 1:
                amt = raw_amt
            else:
                # Omit incompatible currency amounts from USD structuring rules
                continue

            if self.structuring_min <= amt <= self.structuring_max:
                structuring_count += 1
            if "CASH" in tx_type:
                cash_count += 1
                cash_amount += amt

        # Fan-in and Fan-out ratios
        fan_in_ratio = (in_degree / max(1, out_degree))
        fan_out_ratio = (out_degree / max(1, in_degree))

        # Rapid pass-through calculation (time between earliest in and earliest out afterwards)
        rapid_pass_through_hours: Optional[float] = None
        if in_edges and out_edges:
            in_times = []
            for u, v, d in in_edges:
                try:
                    in_times.append(datetime.fromisoformat(str(d.get("timestamp")).replace("Z", "+00:00")))
                except Exception:
                    pass
            out_times = []
            for u, v, d in out_edges:
                try:
                    out_times.append(datetime.fromisoformat(str(d.get("timestamp")).replace("Z", "+00:00")))
                except Exception:
                    pass

            if in_times and out_times:
                min_in = min(in_times)
                subsequent_outs = [t for t in out_times if t >= min_in]
                if subsequent_outs:
                    first_subsequent_out = min(subsequent_outs)
                    delta_secs = (first_subsequent_out - min_in).total_seconds()
                    rapid_pass_through_hours = round(max(0.0, delta_secs / 3600.0), 2)

        # 2-Hop Local Neighborhood Count
        two_hop_nodes = set()
        for succ in G.successors(account_id):
            two_hop_nodes.add(succ)
            for s2 in G.successors(succ):
                two_hop_nodes.add(s2)
        for pred in G.predecessors(account_id):
            two_hop_nodes.add(pred)
            for p2 in G.predecessors(pred):
                two_hop_nodes.add(p2)
        two_hop_nodes.discard(account_id)
        two_hop_count = len(two_hop_nodes)

        # Local Cycle Participation
        participates_cycle = False
        try:
            # Check if account is in a directed cycle
            participates_cycle = any(account_id in c for c in nx.simple_cycles(G))
        except Exception:
            participates_cycle = False

        return LocalAccountFeatures(
            account_id=account_id,
            is_local=is_local,
            canonical_token=canonical_token,
            entity_type=entity_type,
            kyc_risk_score=round(kyc_risk_score, 3),
            in_degree=in_degree,
            out_degree=out_degree,
            in_tx_count=in_tx_count,
            out_tx_count=out_tx_count,
            total_tx_count=in_tx_count + out_tx_count,
            total_in_amount=round(total_in, 2),
            total_out_amount=round(total_out, 2),
            avg_in_amount=round(avg_in, 2),
            avg_out_amount=round(avg_out, 2),
            max_in_amount=round(max_in, 2),
            max_out_amount=round(max_out, 2),
            net_flow=round(net_flow, 2),
            turnover_ratio=round(turnover_ratio, 3),
            structuring_count=structuring_count,
            cash_deposit_count=cash_count,
            cash_deposit_amount=round(cash_amount, 2),
            rapid_pass_through_hours=rapid_pass_through_hours,
            fan_in_ratio=round(fan_in_ratio, 2),
            fan_out_ratio=round(fan_out_ratio, 2),
            two_hop_neighbor_count=two_hop_count,
            participates_in_local_cycle=participates_cycle,
        )

    def extract_all_local_accounts(self, G: nx.MultiDiGraph) -> Dict[str, LocalAccountFeatures]:
        """Extracts features for all locally-owned accounts in the graph."""
        results = {}
        for node_id, data in G.nodes(data=True):
            if data.get("is_local", False):
                results[node_id] = self.extract_for_account(G, node_id)
        return results
