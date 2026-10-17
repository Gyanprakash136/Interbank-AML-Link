"""SignalMesh Bank Data Adapter.

Provides standardized loading and partitioning interfaces for operational bank agents
and optional external datasets like HI-Small.
"""

from pathlib import Path
from typing import Dict, List, Optional
import pandas as pd

from app.banks.hi_small_adapter import HISmallAdapter
from app.banks.local_agent import OperationalBankAgent
from app.core.config import DataBoundaryViolationError, settings


class BankDataAdapter:
    """Standardized loader for bank-local operational files."""

    @staticmethod
    def get_agent(bank_id: str, data_dir: Optional[Path] = None) -> OperationalBankAgent:
        """Instantiates an operational bank agent bound to the given bank_id."""
        return OperationalBankAgent(bank_id=bank_id, data_dir=data_dir)

    @staticmethod
    def load_transactions(bank_id: str, data_dir: Optional[Path] = None) -> pd.DataFrame:
        """Loads operational transactions for a specific bank."""
        agent = OperationalBankAgent(bank_id=bank_id, data_dir=data_dir)
        return agent.load_local_transactions()

    @staticmethod
    def load_canonical_tokens(bank_id: str, data_dir: Optional[Path] = None) -> List[str]:
        """Loads canonical entity tokens for a specific bank."""
        agent = OperationalBankAgent(bank_id=bank_id, data_dir=data_dir)
        return agent.get_canonical_tokens()
