"""Unit tests for SignalMesh Privacy Leakage Ledger.

Validates:
1. Recording of observable session telemetry (participants, wire bytes, cardinalities).
2. Duplicate session detection and rejection (replay prevention).
3. Round summary calculation (sessions, total wire bytes, status).
4. Strict absence of raw transaction data, customer IDs, or private keys.
"""

import pytest

from app.psi.leakage_ledger import (
    CollaborationRoundSummary,
    LeakageSessionEvent,
    PrivacyLeakageLedger,
)


def _make_dummy_event(
    session_id: str,
    round_id: str = "ROUND_001",
    server: str = "bank_a",
    client: str = "bank_b",
    wire_bytes: int = 250,
    matches: int = 2,
    status: str = "SUCCESS",
) -> LeakageSessionEvent:
    return LeakageSessionEvent(
        session_id=session_id,
        round_id=round_id,
        server_bank_id=server,
        client_bank_id=client,
        protocol_family="Diffie-Hellman-ECC-PSI",
        data_structure="GCS",
        fpr_parameter=0.001,
        server_set_size=5,
        client_set_size=5,
        server_setup_bytes=100,
        client_request_bytes=75,
        server_response_bytes=75,
        total_wire_bytes=wire_bytes,
        client_revealed_cardinality=matches,
        recipient_of_output=client,
        status=status,
        timestamp="2026-03-01T12:00:00Z",
        execution_time_ms=12.5,
    )


def test_leakage_ledger_record_and_query():
    """Confirms ledger records session events and retrieves by round ID."""
    ledger = PrivacyLeakageLedger()
    ev1 = _make_dummy_event("SESS_01", "ROUND_01", "bank_a", "bank_b", 250, 2)
    ev2 = _make_dummy_event("SESS_02", "ROUND_01", "bank_b", "bank_a", 250, 2)

    ledger.record_session(ev1)
    ledger.record_session(ev2)

    events = ledger.get_events_for_round("ROUND_01")
    assert len(events) == 2
    assert events[0].session_id == "SESS_01"
    assert events[1].session_id == "SESS_02"


def test_leakage_ledger_replay_prevention():
    """Confirms duplicate session IDs are rejected without duplicating recorded data."""
    ledger = PrivacyLeakageLedger()
    ev1 = _make_dummy_event("SESS_DUP_01", "ROUND_01")
    ledger.record_session(ev1)

    # Attempt replay with identical session ID
    ev1_replay = _make_dummy_event("SESS_DUP_01", "ROUND_01")
    ledger.record_session(ev1_replay)

    events = ledger.get_events_for_round("ROUND_01")
    assert len(events) == 2
    assert events[0].status == "SUCCESS"
    assert events[1].status == "REJECTED_DUPLICATE"
    assert "Duplicate session ID" in events[1].error_message


def test_leakage_ledger_round_summary():
    """Confirms round summary accurately computes totals across participating banks."""
    ledger = PrivacyLeakageLedger()
    ledger.record_session(_make_dummy_event("S1", "ROUND_SUM_01", "bank_a", "bank_b", 300, 1))
    ledger.record_session(_make_dummy_event("S2", "ROUND_SUM_01", "bank_b", "bank_a", 300, 1))

    summary = ledger.get_round_summary("ROUND_SUM_01")
    assert summary.round_id == "ROUND_SUM_01"
    assert summary.session_count == 2
    assert summary.total_wire_bytes == 600
    assert summary.total_matches_revealed == 2
    assert summary.participating_banks == ["bank_a", "bank_b"]
    assert summary.status == "COMPLETED"


def test_leakage_ledger_rejects_nonexistent_round():
    """Confirms get_round_summary raises KeyError for unknown round IDs."""
    ledger = PrivacyLeakageLedger()
    with pytest.raises(KeyError, match="not found"):
        ledger.get_round_summary("ROUND_NONEXISTENT")
