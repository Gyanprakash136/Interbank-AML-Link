"""SignalMesh Core Configuration & Settings.

Enforces data directory locations, PSI parameters, and data boundary rules.
"""

import os
from pathlib import Path
from pydantic import BaseModel, Field


class DataBoundaryViolationError(PermissionError):
    """Raised when an operational component attempts to access unauthorized data.

    Examples:
    - An operational bank agent attempting to access another bank's local data.
    - An operational component attempting to access evaluation ground-truth.
    - An operational model attempting to ingest the 'is_laundering' ground truth label.
    """
    pass


class Settings(BaseModel):
    """SignalMesh project settings."""

    # Project paths
    backend_root: Path = Field(
        default_factory=lambda: Path(__file__).resolve().parent.parent.parent
    )
    data_dir_override: Path | None = Field(
        default_factory=lambda: Path(os.getenv("SIGNALMESH_DATA_DIR")).resolve()
        if os.getenv("SIGNALMESH_DATA_DIR")
        else None
    )
    env: str = Field(default_factory=lambda: os.getenv("SIGNALMESH_ENV", "development"))
    log_level: str = Field(default_factory=lambda: os.getenv("SIGNALMESH_LOG_LEVEL", "INFO"))

    # PSI Protocol Parameters
    psi_fpr: float = Field(
        default_factory=lambda: float(os.getenv("PSI_FALSE_POSITIVE_RATE", "0.001"))
    )

    # API / Service configuration (future stages)
    api_host: str = Field(default_factory=lambda: os.getenv("API_HOST", "127.0.0.1"))
    api_port: int = Field(default_factory=lambda: int(os.getenv("API_PORT", "8000")))

    @property
    def data_dir(self) -> Path:
        """Root data directory."""
        if self.data_dir_override:
            return self.data_dir_override
        return self.backend_root / "data"

    @property
    def bank_a_dir(self) -> Path:
        return self.data_dir / "bank_a"

    @property
    def bank_b_dir(self) -> Path:
        return self.data_dir / "bank_b"

    @property
    def bank_c_dir(self) -> Path:
        return self.data_dir / "bank_c"

    @property
    def evaluation_dir(self) -> Path:
        return self.data_dir / "evaluation"

    @property
    def synthetic_dir(self) -> Path:
        return self.data_dir / "synthetic"

    def get_bank_dir(self, bank_id: str) -> Path:
        """Returns the isolated local directory for a given bank ID."""
        normalized = bank_id.lower().strip()
        bank_map = {
            "bank_a": self.bank_a_dir,
            "bank_b": self.bank_b_dir,
            "bank_c": self.bank_c_dir,
            "bank_alpha": self.bank_a_dir,
            "bank_beta": self.bank_b_dir,
            "bank_gamma": self.bank_c_dir,
        }
        if normalized not in bank_map:
            raise ValueError(f"Unknown bank_id: {bank_id}. Must be one of {list(bank_map.keys())}")
        return bank_map[normalized]


settings = Settings()
