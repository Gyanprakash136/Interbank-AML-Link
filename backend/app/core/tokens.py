"""SignalMesh canonical token derivation (single source of truth).

Token format: ``TOK_<16 lowercase hex>`` where the hex is the first 16 characters of
``sha256("SIGNALMESH_CANONICAL_TOKEN_SALT_V1:" + entity_key)``.

This reproduces the scheme used by ``scripts/generate_synthetic_data.py``. Golden
vectors in ``tests/unit/test_tokens.py`` pin it: NEVER change the salt prefix,
hash, or truncation without fixtures and a compatibility note.

The token must not encode bank, typology, or risk. ``entity_key`` is an
operational identifier (e.g. an account node id), never a label.
"""

import hashlib

TOKEN_SALT_PREFIX = "SIGNALMESH_CANONICAL_TOKEN_SALT_V1:"


def derive_canonical_token(entity_key: str) -> str:
    if not isinstance(entity_key, str) or not entity_key:
        raise ValueError("entity_key must be a non-empty string")
    digest = hashlib.sha256(f"{TOKEN_SALT_PREFIX}{entity_key}".encode("utf-8")).hexdigest()
    return f"TOK_{digest[:16]}"
