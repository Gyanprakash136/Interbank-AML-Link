"""SignalMesh Local Transaction Graph Builder.

Constructs a directed NetworkX multigraph from validated bank-local operational transactions.

CORE DESIGN PRINCIPLES:
1. Operational Data Only:
   Constructed strictly from bank-local transaction CSVs. Ground-truth labels
   ('is_laundering', 'global_entity_id') are strictly forbidden and trigger DataBoundaryViolationError.
2. Ownership Distinctions:
   Nodes are partitioned into locally-owned accounts (is_local=True) and external counterparties (is_local=False).
   External counterparties reflect ONLY the local bank's direct interactions; external complete histories
   are never inferred or populated.
3. Robust Data Validation:
   Validates missing IDs, non-positive amounts, malformed timestamps, and duplicate transaction IDs.
4. Determinism:
   Graph construction is deterministic across repeated runs on identical inputs.
"""

from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
import networkx as nx
import pandas as pd

from app.core.config import DataBoundaryViolationError
from app.core.security import assert_no_ground_truth_contamination


class GraphValidationError(ValueError):
    """Raised when operational transaction data violates data integrity constraints."""
    pass


class LocalGraphBuilder:
    """Builds a deterministic directed transaction graph for a single bank."""

    REQUIRED_TX_COLUMNS = {"transaction_id", "timestamp", "from_account_id", "to_account_id", "amount"}

    def __init__(
        self,
        bank_id: str,
        transactions_df: pd.DataFrame,
        local_entities_df: Optional[pd.DataFrame] = None,
    ):
        self.bank_id = bank_id.lower().strip()
        self.transactions_df = transactions_df.copy()
        self.local_entities_df = local_entities_df.copy() if local_entities_df is not None else None

        # 1. Enforce strict boundary against ground truth leakage
        assert_no_ground_truth_contamination(self.transactions_df.columns, f"{self.bank_id} transactions")
        if self.local_entities_df is not None:
            assert_no_ground_truth_contamination(self.local_entities_df.columns, f"{self.bank_id} entities")

    def _validate_and_clean_data(self) -> pd.DataFrame:
        """Validates transactions schema, amounts, timestamps, and deduplicates records."""
        missing = self.REQUIRED_TX_COLUMNS - set(self.transactions_df.columns)
        if missing:
            raise GraphValidationError(f"Transactions missing required columns: {missing}")

        df = self.transactions_df.copy()

        # Check for missing account or transaction IDs
        null_counts = df[["transaction_id", "from_account_id", "to_account_id"]].isnull().sum()
        if null_counts.any():
            raise GraphValidationError(f"Found null values in critical identifiers:\n{null_counts}")

        # Check for non-numeric or non-positive amounts
        try:
            df["amount"] = pd.to_numeric(df["amount"], errors="raise")
        except Exception as e:
            raise GraphValidationError(f"Invalid non-numeric transaction amount detected: {e}")

        invalid_amounts = df[df["amount"] <= 0]
        if not invalid_amounts.empty:
            raise GraphValidationError(f"Found {len(invalid_amounts)} non-positive transaction amounts.")

        # Validate timestamps
        for ts_val in df["timestamp"]:
            try:
                datetime.fromisoformat(str(ts_val).replace("Z", "+00:00"))
            except Exception:
                raise GraphValidationError(f"Malformed ISO-8601 timestamp: '{ts_val}'")

        # Deduplicate transaction IDs to prevent double counting
        initial_len = len(df)
        df = df.drop_duplicates(subset=["transaction_id"], keep="first")
        # Ensure deterministic ordering: sort by timestamp, then transaction_id
        df = df.sort_values(by=["timestamp", "transaction_id"]).reset_index(drop=True)

        return df

    def build(self) -> nx.MultiDiGraph:
        """Builds and returns the deterministic directed multigraph."""
        df = self._validate_and_clean_data()
        G = nx.MultiDiGraph(bank_id=self.bank_id, created_at=datetime.utcnow().isoformat())

        # Build local account lookup from local_entities_df if provided
        local_lookup: Dict[str, Dict] = {}
        if self.local_entities_df is not None and not self.local_entities_df.empty:
            for _, row in self.local_entities_df.iterrows():
                acc = str(row["local_account_id"]).strip()
                local_lookup[acc] = {
                    "is_local": True,
                    "canonical_token": str(row.get("canonical_token", "")).strip() or None,
                    "entity_type": str(row.get("entity_type", "UNKNOWN")),
                    "kyc_risk_score": float(row.get("kyc_risk_score", 0.0)),
                }

        # Add all nodes observed in transactions
        all_accounts = set(df["from_account_id"]).union(set(df["to_account_id"]))
        for acc in sorted(all_accounts):
            if acc in local_lookup:
                attrs = local_lookup[acc]
                G.add_node(acc, **attrs)
            else:
                # External counterparty or untracked local account
                # By convention in our synthetic schema, accounts starting with ACC_<BANK_LETTER> are local
                is_local = acc.startswith(f"ACC_{self.bank_id[-1].upper()}_")
                G.add_node(
                    acc,
                    is_local=is_local,
                    canonical_token=None,
                    entity_type="EXTERNAL" if not is_local else "UNINDEXED_LOCAL",
                    kyc_risk_score=0.0,
                )

        # Add directed edges for each transaction
        for _, row in df.iterrows():
            tx_id = str(row["transaction_id"]).strip()
            u = str(row["from_account_id"]).strip()
            v = str(row["to_account_id"]).strip()
            amount = float(row["amount"])
            currency = str(row.get("currency", "USD")).strip()
            tx_type = str(row.get("tx_type", "WIRE")).strip()
            timestamp = str(row["timestamp"]).strip()

            G.add_edge(
                u,
                v,
                key=tx_id,
                transaction_id=tx_id,
                amount=amount,
                currency=currency,
                tx_type=tx_type,
                timestamp=timestamp,
            )

        return G
