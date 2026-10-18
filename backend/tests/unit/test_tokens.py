import re

import pytest

from app.core.tokens import derive_canonical_token

# Golden vectors taken from the committed synthetic fixtures (backend/data/*/local_entities.csv
# and data/evaluation/ground_truth_entities.json). Changing these is a breaking change.
GOLDEN = {
    "ENT_GLOBAL_SYNDICATE_01": "TOK_d3de48ba1c9f1337",
    "ENT_GLOBAL_SMURF_02": "TOK_cfc9afe60a6306d0",
    "ENT_GLOBAL_FAN_03": "TOK_cf30f5dddce79c99",
    "ENT_GLOBAL_SHELL_04": "TOK_a891160d185e175a",
    "ENT_GLOBAL_BENIGN_05": "TOK_fcc90d38c0240418",
}


@pytest.mark.parametrize("key,token", sorted(GOLDEN.items()))
def test_golden_vectors(key, token):
    assert derive_canonical_token(key) == token


def test_format_and_determinism():
    t = derive_canonical_token("ACC_A_12345")
    assert re.fullmatch(r"TOK_[0-9a-f]{16}", t)
    assert t == derive_canonical_token("ACC_A_12345")
    assert t != derive_canonical_token("ACC_B_12345")


@pytest.mark.parametrize("bad", ["", None, 123])
def test_rejects_invalid_keys(bad):
    with pytest.raises(ValueError):
        derive_canonical_token(bad)
