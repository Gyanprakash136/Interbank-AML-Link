"""SignalMesh Public HI-Small Dataset Adapter.

Provides an optional, clearly separated adapter for integrating the public
IBM / Elliptic AML HI-Small transaction CSV.

HI-SMALL SCHEMA SPECIFICATION:
The standard public HI-Small transaction file (HI-Small_Trans.csv) uses the schema:
    Timestamp,From Bank,Account,To Bank,Account,Amount Received,Receiving Currency,Amount Paid,Payment Currency,Payment Format,Is Laundering

CRITICAL PARTITIONING PRINCIPLES (Non-Random):
1. A transaction belongs to a bank's local ledger IF AND ONLY IF that bank is either the
   originating institution ('From Bank') or the beneficiary institution ('To Bank').
2. Transactions between Bank X and Bank Y are never visible to Bank Z.
3. The ground-truth label 'Is Laundering' is extracted into an isolated evaluation map
   and is NEVER included in bank-local transaction files.
4. Local accounts are partitioned strictly by bank ownership.
"""

import csv
import io
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import pandas as pd

from app.core.config import DataBoundaryViolationError


EXPECTED_HI_SMALL_HEADERS = [
    "Timestamp",
    "From Bank",
    "Account",
    "To Bank",
    "Account.1",  # Pandas or deduplication resolves second Account column to Account.1
    "Amount Received",
    "Receiving Currency",
    "Amount Paid",
    "Payment Currency",
    "Payment Format",
    "Is Laundering",
]


# Minimal deterministic fixture for unit testing the adapter without downloading the full dataset
SAMPLE_HI_SMALL_CSV = """Timestamp,From Bank,Account,To Bank,Account,Amount Received,Receiving Currency,Amount Paid,Payment Currency,Payment Format,Is Laundering
2022/09/01 00:20,010,10001,020,20001,5000.00,US Dollar,5000.00,US Dollar,Wire,1
2022/09/01 01:15,010,10001,020,20001,4800.00,US Dollar,4800.00,US Dollar,Wire,1
2022/09/01 02:40,020,20001,030,30001,9500.00,US Dollar,9500.00,US Dollar,Wire,1
2022/09/01 04:00,010,10002,010,10003,150.00,US Dollar,150.00,US Dollar,ACH,0
2022/09/01 05:30,030,30002,020,20002,2500.00,US Dollar,2500.00,US Dollar,Cheque,0
2022/09/01 06:10,020,20003,020,20004,80.00,US Dollar,80.00,US Dollar,Cash,0
"""


class HISmallAdapter:
    """Adapter for processing public HI-Small AML dataset."""

    def __init__(self, bank_mapping: Optional[Dict[str, str]] = None):
        """Initializes adapter with a mapping from HI-Small bank IDs to SignalMesh bank IDs.

        Default mapping:
            '010' -> 'bank_a'
            '020' -> 'bank_b'
            '030' -> 'bank_c'
        """
        self.bank_mapping = bank_mapping or {
            "010": "bank_a",
            "10": "bank_a",
            "020": "bank_b",
            "20": "bank_b",
            "030": "bank_c",
            "30": "bank_c",
        }

    def load_and_validate_dataframe(self, source: Path | io.StringIO) -> pd.DataFrame:
        """Loads and normalizes the HI-Small CSV, handling duplicate 'Account' column names."""
        if isinstance(source, Path):
            if not source.exists():
                raise FileNotFoundError(f"HI-Small source file not found at {source}")
            df = pd.read_csv(source)
        else:
            df = pd.read_csv(source)

        # Standardize column names (pandas renames 2nd Account to Account.1)
        rename_map = {}
        cols = list(df.columns)
        if cols.count("Account") > 1:
            # First Account is From Account, second is To Account
            seen = False
            new_cols = []
            for c in cols:
                if c == "Account":
                    if not seen:
                        new_cols.append("From Account")
                        seen = True
                    else:
                        new_cols.append("To Account")
                else:
                    new_cols.append(c)
            df.columns = new_cols
        elif "Account.1" in df.columns:
            df = df.rename(columns={"Account": "From Account", "Account.1": "To Account"})

        required = {"Timestamp", "From Bank", "From Account", "To Bank", "To Account", "Amount Paid", "Is Laundering"}
        missing = required - set(df.columns)
        if missing:
            raise ValueError(f"HI-Small dataset missing required columns: {missing}")

        return df

    def partition_to_bank_local_views(
        self,
        df: pd.DataFrame,
        output_dir: Path,
    ) -> Dict[str, Any]:
        """Partitions HI-Small transactions into isolated bank-local views and ground truth.

        Strict Separation Enforced:
        - Bank A gets rows where From Bank == Bank A or To Bank == Bank A.
        - 'Is Laundering' is STRIPPED from bank-local CSVs.
        - Ground truth is saved separately in output_dir / 'evaluation' / 'hi_small_ground_truth.json'.
        """
        output_dir = Path(output_dir).resolve()
        eval_dir = output_dir / "evaluation"
        eval_dir.mkdir(parents=True, exist_ok=True)

        bank_rows: Dict[str, List[Dict[str, Any]]] = {
            "bank_a": [],
            "bank_b": [],
            "bank_c": [],
        }
        eval_ground_truth: Dict[str, Dict[str, Any]] = {}

        for idx, row in df.iterrows():
            from_bank_raw = str(row["From Bank"]).strip()
            to_bank_raw = str(row["To Bank"]).strip()

            from_bank = self.bank_mapping.get(from_bank_raw)
            to_bank = self.bank_mapping.get(to_bank_raw)

            tx_id = f"TX_HI_{idx:06d}"
            is_laundering = bool(int(row["Is Laundering"]))

            # Store ground truth label in isolated evaluation dictionary
            eval_ground_truth[tx_id] = {
                "is_laundering": is_laundering,
                "from_bank_raw": from_bank_raw,
                "to_bank_raw": to_bank_raw,
                "amount": float(row["Amount Paid"]),
            }

            # Prepare operational transaction dictionary (NO 'Is Laundering' label!)
            operational_tx = {
                "transaction_id": tx_id,
                "timestamp": str(row["Timestamp"]),
                "from_account_id": f"ACC_{from_bank_raw}_{row['From Account']}",
                "to_account_id": f"ACC_{to_bank_raw}_{row['To Account']}",
                "amount": float(row["Amount Paid"]),
                "currency": str(row.get("Payment Currency", "USD")),
                "tx_type": str(row.get("Payment Format", "WIRE")),
            }

            # Distribute based on account ownership
            if from_bank in bank_rows:
                bank_rows[from_bank].append(operational_tx)
            if to_bank in bank_rows and to_bank != from_bank:
                bank_rows[to_bank].append(operational_tx)

        # Write partitioned bank files (operational only)
        counts = {}
        for b_id, rows in bank_rows.items():
            b_dir = output_dir / b_id
            b_dir.mkdir(parents=True, exist_ok=True)
            out_file = b_dir / "hi_small_transactions.csv"
            out_df = pd.DataFrame(rows)
            # Ensure 'is_laundering' is NOT present
            assert "is_laundering" not in out_df.columns
            out_df.to_csv(out_file, index=False)
            counts[b_id] = len(rows)

        # Write evaluation ground truth file
        with open(eval_dir / "hi_small_ground_truth.json", "w", encoding="utf-8") as f:
            json.dump(eval_ground_truth, f, indent=2)

        return {
            "status": "success",
            "partitioned_rows": counts,
            "ground_truth_entries": len(eval_ground_truth),
        }
