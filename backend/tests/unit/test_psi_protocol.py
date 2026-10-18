"""Unit tests for SignalMesh OpenMined PSI Wrapper and Protocol Semantics.

Validates:
1. Exact matching on overlapping sets (indices and token string mapping).
2. Empty intersection on disjoint sets (no-overlap).
3. Cardinality-only mode (reveal_intersection=False).
4. Bidirectional exchange session between Bank A and Bank B.
5. Strict token validation preventing raw transaction dicts or rows from entering PSI.
6. Protobuf serialization and wire format integrity.
7. Asymmetric revelation semantics: only client learns intersection.
"""

import pytest

pytest.importorskip("private_set_intersection.python", reason="OpenMined PSI is unavailable on this platform")
import private_set_intersection.python as psi
from app.psi.protocol import (
    PSIClient,
    PSIServer,
    PSIBidirectionalSession,
    PSIProtocolError,
    PSIBoundaryError,
)


def test_psi_overlap_exact_indices_and_items():
    """Confirms OpenMined PSI returns indices and maps back to expected tokens."""
    server_tokens = ["CANON_ENT_1", "CANON_ENT_2", "CANON_ENT_3"]
    client_tokens = ["CANON_ENT_2", "CANON_ENT_3", "CANON_ENT_4"]
    expected = {"CANON_ENT_2", "CANON_ENT_3"}

    server = PSIServer(reveal_intersection=True)
    client = PSIClient(reveal_intersection=True)

    setup = server.create_setup_message(
        inputs=server_tokens,
        fpr=0.001,
        num_client_inputs=len(client_tokens),
    )
    request = client.create_request(client_tokens)
    response = server.process_request(request)

    # 1. Verify raw indices into client set
    # client_tokens[0] == "CANON_ENT_2", client_tokens[1] == "CANON_ENT_3"
    indices = client.get_intersection_indices(setup, response)
    assert indices == [0, 1]

    # 2. Verify mapping back to client tokens
    items = client.get_intersection_items(setup, response, client_tokens)
    assert set(items) == expected

    # 3. Verify server learns zero info (has no intersection getter)
    assert not hasattr(server, "get_intersection_indices")
    assert not hasattr(server, "get_intersection_items")


def test_psi_no_overlap():
    """Confirms empty intersection when sets have no common tokens."""
    server_tokens = ["CANON_ALPHA_01", "CANON_ALPHA_02"]
    client_tokens = ["CANON_BETA_01", "CANON_BETA_02", "CANON_BETA_03"]

    server = PSIServer(reveal_intersection=True)
    client = PSIClient(reveal_intersection=True)

    setup = server.create_setup_message(server_tokens, fpr=0.001, num_client_inputs=len(client_tokens))
    request = client.create_request(client_tokens)
    response = server.process_request(request)

    indices = client.get_intersection_indices(setup, response)
    assert len(indices) == 0

    items = client.get_intersection_items(setup, response, client_tokens)
    assert len(items) == 0


def test_psi_cardinality_only_mode():
    """Confirms reveal_intersection=False yields only count and blocks index revelation."""
    server_tokens = ["ENT_1", "ENT_2", "ENT_3"]
    client_tokens = ["ENT_2", "ENT_3", "ENT_4"]

    server = PSIServer(reveal_intersection=False)
    client = PSIClient(reveal_intersection=False)

    setup = server.create_setup_message(server_tokens, fpr=0.001, num_client_inputs=len(client_tokens))
    request = client.create_request(client_tokens)
    response = server.process_request(request)

    # Size should be 2
    count = client.get_intersection_size(setup, response)
    assert count == 2

    # Attempting to get indices or items must raise PSIProtocolError
    with pytest.raises(PSIProtocolError):
        client.get_intersection_indices(setup, response)


def test_psi_bidirectional_session():
    """Confirms authorized two-way PSI between Bank A and Bank B."""
    bank_a_tokens = ["TOKEN_COMMON_1", "TOKEN_COMMON_2", "TOKEN_ONLY_A"]
    bank_b_tokens = ["TOKEN_COMMON_1", "TOKEN_COMMON_2", "TOKEN_ONLY_B"]

    session = PSIBidirectionalSession(bank_a_id="bank_a", bank_b_id="bank_b", fpr=0.001)
    result = session.execute(bank_a_tokens, bank_b_tokens)

    # Both banks learn the mutual common tokens
    assert result.bank_a_matched_tokens == ["TOKEN_COMMON_1", "TOKEN_COMMON_2"]
    assert result.bank_b_matched_tokens == ["TOKEN_COMMON_1", "TOKEN_COMMON_2"]
    assert result.matched_count == 2

    # Neither bank learns the non-matching tokens
    assert "TOKEN_ONLY_B" not in result.bank_a_matched_tokens
    assert "TOKEN_ONLY_A" not in result.bank_b_matched_tokens

    # Wire bytes must reflect the protobuf messages
    assert result.total_wire_bytes > 0


def test_psi_wire_serialization_roundtrip():
    """Confirms protobuf messages can be serialized to bytes and restored across network."""
    server = PSIServer(reveal_intersection=True)
    client = PSIClient(reveal_intersection=True)

    setup = server.create_setup_message(["T1", "T2"], fpr=0.001, num_client_inputs=2)
    request = client.create_request(["T2", "T3"])
    response = server.process_request(request)

    # Serialize to bytes
    setup_bytes = setup.SerializeToString()
    req_bytes = request.SerializeToString()
    resp_bytes = response.SerializeToString()

    assert isinstance(setup_bytes, bytes) and len(setup_bytes) > 0
    assert isinstance(req_bytes, bytes) and len(req_bytes) > 0
    assert isinstance(resp_bytes, bytes) and len(resp_bytes) > 0

    # Deserialize from bytes
    setup_restored = psi.ServerSetup()
    setup_restored.ParseFromString(setup_bytes)

    req_restored = psi.Request()
    req_restored.ParseFromString(req_bytes)

    resp_restored = psi.Response()
    resp_restored.ParseFromString(resp_bytes)

    # Execute match using restored protobufs
    indices = client.get_intersection_indices(setup_restored, resp_restored)
    assert indices == [0]  # T2 matched at index 0 of client


def test_psi_boundary_rejects_non_tokens():
    """Confirms PSI wrapper rejects raw transaction records, dicts, or stringified rows."""
    client = PSIClient(reveal_intersection=True)

    # Non-string object
    with pytest.raises(PSIBoundaryError):
        client.create_request([{"account": "ACC_1", "amount": 1000}])

    # Raw stringified JSON row
    with pytest.raises(PSIBoundaryError):
        client.create_request(['{"transaction_id": "TX_01", "amount": 500.0}'])

    # String containing account and amount keywords
    with pytest.raises(PSIBoundaryError):
        client.create_request(["account: ACC_1001, amount: 9800.00"])


def test_psi_false_positive_measurement_and_raw_mode_comparison():
    """Measures false-positive rate on GCS across non-matching items and verifies RAW mode has zero false positives.

    Addresses audit requirement:
    - GCS has a theoretical FPR bounded by fpr parameter.
    - RAW mode provides exact matching with 0 false matches.
    """
    server_items = [f"SERVER_EXCLUSIVE_TOK_{i:04d}" for i in range(50)]
    client_non_matching = [f"CLIENT_NONMATCH_TOK_{j:04d}" for j in range(1000)]

    # --- Mode 1: GCS with fpr=0.001 ---
    server_gcs = PSIServer(reveal_intersection=True)
    client_gcs = PSIClient(reveal_intersection=True)

    setup_gcs = server_gcs.create_setup_message(
        inputs=server_items,
        fpr=0.001,
        num_client_inputs=len(client_non_matching),
        data_structure=psi.DataStructure.GCS,
    )
    req_gcs = client_gcs.create_request(client_non_matching)
    resp_gcs = server_gcs.process_request(req_gcs)
    matches_gcs = client_gcs.get_intersection_indices(setup_gcs, resp_gcs)

    # Measured FPR on 1,000 non-matching queries against 50 server items
    empirical_gcs_fpr = len(matches_gcs) / len(client_non_matching)
    assert empirical_gcs_fpr <= 0.01, f"GCS FPR ({empirical_gcs_fpr}) exceeded safety bound"

    # --- Mode 2: RAW mode (Exact, Zero False Positives) ---
    server_raw = PSIServer(reveal_intersection=True)
    client_raw = PSIClient(reveal_intersection=True)

    setup_raw = server_raw.create_setup_message(
        inputs=server_items,
        fpr=0.001,
        num_client_inputs=len(client_non_matching),
        data_structure=psi.DataStructure.RAW,
    )
    req_raw = client_raw.create_request(client_non_matching)
    resp_raw = server_raw.process_request(req_raw)
    matches_raw = client_raw.get_intersection_indices(setup_raw, resp_raw)

    # RAW mode must have EXACTLY 0 false positives
    assert len(matches_raw) == 0, f"RAW mode produced false positives: {matches_raw}"

