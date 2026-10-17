"""SignalMesh Security & Isolation Boundaries.

Defines boundary validation routines and explicitly documents application-level
vs operating-system level isolation guarantees.

ISOLATION ARCHITECTURE & DEPLOYMENT NOTICE:
1. Application-Level Guardrails:
   The checks provided in this module and throughout OperationalBankAgent are
   application-level guardrails. They prevent accidental cross-bank access,
   evaluation ground-truth leakage, and non-token data transfer into the PSI wire
   during simulation and local integration.
2. Operating-System / Container Isolation:
   Application-level checks DO NOT provide OS-level or cryptographic isolation when
   all banks execute under the same OS process or filesystem user. In a production
   or multi-tenant deployment, each bank agent must run in an independent process,
   container, or confidential computing enclave (e.g. separate Kubernetes pods,
   distinct Unix UIDs/GIDs, and dedicated filesystems), communicating exclusively
   via mutual TLS (mTLS) and serialized PSI protobufs.
3. No Automatic Laundering Inference:
   A PSI match indicates ONLY entity identity intersection. A PSI match alone
   MUST NEVER be treated as proof of laundering or criminal activity.
"""

from pathlib import Path
import re
from typing import List, Sequence
from app.core.config import DataBoundaryViolationError


OPAQUE_TOKEN_REGEX = re.compile(r"^TOK_[0-9a-f]{16}$")
FORBIDDEN_GROUND_TRUTH_COLUMNS = {
    "is_laundering",
    "is_laundering_label",
    "ground_truth_entity_id",
    "global_entity_id",
    "typology",
    "laundering_typology",
}

FORBIDDEN_SEMANTIC_KEYWORDS = {
    "syndicate",
    "smurf",
    "launder",
    "benign",
    "cartel",
    "shell",
    "mule",
    "churn",
    "layering",
    "structuring",
}


def assert_opaque_tokens(tokens: Sequence[str]) -> None:
    """Verifies that all tokens in the sequence are strictly opaque and contain no semantic labels."""
    for idx, token in enumerate(tokens):
        if not isinstance(token, str):
            raise TypeError(f"Token at index {idx} is not a string: {type(token).__name__}")
        if not OPAQUE_TOKEN_REGEX.match(token):
            raise DataBoundaryViolationError(
                f"Token at index {idx} ('{token}') does not follow the opaque token format 'TOK_<16_hex>'. "
                "Tokens must never embed semantic names, typologies, or labels."
            )
        lower_token = token.lower()
        for kw in FORBIDDEN_SEMANTIC_KEYWORDS:
            if kw in lower_token:
                raise DataBoundaryViolationError(
                    f"Token at index {idx} contains forbidden semantic keyword '{kw}'. "
                    "Tokens must be completely opaque."
                )


def assert_no_ground_truth_contamination(columns: Sequence[str], source_name: str = "operational data") -> None:
    """Verifies that a list of column names does not contain ground truth labels."""
    leaked = FORBIDDEN_GROUND_TRUTH_COLUMNS.intersection(set(columns))
    if leaked:
        raise DataBoundaryViolationError(
            f"Ground truth contamination detected in {source_name}. Leaked columns: {leaked}. "
            "forbidden ground-truth columns detected. Operational modules must never ingest or process ground-truth labels."
        )


def verify_path_within_bank_boundary(target_path: Path, authorized_bank_dir: Path, bank_id: str) -> Path:
    """Ensures a path resides strictly within the authorized bank directory."""
    resolved = target_path.resolve()
    authorized = authorized_bank_dir.resolve()

    if "evaluation" in resolved.parts or "ground_truth" in resolved.name.lower():
        raise DataBoundaryViolationError(
            f"Bank '{bank_id}' attempted to access isolated evaluation data: {resolved}."
        )

    for other_bank in ("bank_a", "bank_b", "bank_c"):
        if other_bank != bank_id and other_bank in resolved.parts:
            raise DataBoundaryViolationError(
                f"Bank '{bank_id}' attempted cross-bank directory access to '{other_bank}': {resolved}."
            )

    try:
        resolved.relative_to(authorized)
    except ValueError:
        raise DataBoundaryViolationError(
            f"Path {resolved} is outside authorized directory {authorized} for bank '{bank_id}'."
        )

    return resolved
