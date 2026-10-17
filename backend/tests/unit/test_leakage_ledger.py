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


def test_audit_chain_clean_verification(tmp_path):
    """Confirms unbroken audit chain verifies cleanly (Phase 6.1)."""
    db_file = tmp_path / "clean_ledger.db"
    ledger = PrivacyLeakageLedger(db_path=db_file)

    for i in range(1, 6):
        ev = _make_dummy_event(f"SESS_CLEAN_{i}", round_id="ROUND_CLEAN", wire_bytes=200 + i)
        ledger.record_session(ev)

    is_valid, err = ledger.verify_chain()
    assert is_valid is True
    assert err is None

    # Check chain integrity fields
    events = ledger.get_all_events()
    assert len(events) == 5
    assert events[0].prev_hash == "GENESIS"
    for i in range(1, 5):
        assert events[i].prev_hash == events[i - 1].event_hash
        assert events[i].sequence_number == i + 1

    ledger.close()


def test_audit_chain_detects_modified_record(tmp_path):
    """Confirms tampering with a recorded event is detected by chain verification (Phase 6.2)."""
    import sqlite3
    db_file = tmp_path / "tamper_ledger.db"
    ledger = PrivacyLeakageLedger(db_path=db_file)

    for i in range(1, 4):
        ledger.record_session(_make_dummy_event(f"SESS_T_{i}", round_id="ROUND_T", wire_bytes=100 * i))

    is_valid, err = ledger.verify_chain()
    assert is_valid is True
    ledger.close()

    # Tamper with row 2 directly in SQLite (simulating unauthorized modification)
    conn = sqlite3.connect(str(db_file))
    conn.execute("UPDATE leakage_events SET client_revealed_cardinality = 999 WHERE sequence_number = 2")
    conn.commit()
    conn.close()

    # Reopen ledger and verify
    tampered_ledger = PrivacyLeakageLedger(db_path=db_file)
    is_valid_after, err_after = tampered_ledger.verify_chain()
    assert is_valid_after is False
    assert "Tampered record detected at sequence 2" in err_after
    tampered_ledger.close()


def test_audit_chain_detects_deleted_record(tmp_path):
    """Confirms deleting a record breaks sequence continuity and hash chain (Phase 6.3)."""
    import sqlite3
    db_file = tmp_path / "delete_ledger.db"
    ledger = PrivacyLeakageLedger(db_path=db_file)

    for i in range(1, 4):
        ledger.record_session(_make_dummy_event(f"SESS_DEL_{i}", round_id="ROUND_DEL"))

    assert ledger.verify_chain()[0] is True
    ledger.close()

    # Delete row 2 directly
    conn = sqlite3.connect(str(db_file))
    conn.execute("DELETE FROM leakage_events WHERE sequence_number = 2")
    conn.commit()
    conn.close()

    # Reopen ledger and verify
    tampered_ledger = PrivacyLeakageLedger(db_path=db_file)
    is_valid_after, err_after = tampered_ledger.verify_chain()
    assert is_valid_after is False
    assert "Sequence gap" in err_after or "Broken chain" in err_after
    tampered_ledger.close()


def test_audit_chain_detects_reordered_record(tmp_path):
    """Confirms reordering records breaks the cryptographic hash linkage (Phase 6.3)."""
    import sqlite3
    db_file = tmp_path / "reorder_ledger.db"
    ledger = PrivacyLeakageLedger(db_path=db_file)

    for i in range(1, 4):
        ledger.record_session(_make_dummy_event(f"SESS_REORD_{i}", round_id="ROUND_REORD"))

    assert ledger.verify_chain()[0] is True
    ledger.close()

    # Swap sequence_number between rows 1 and 2
    conn = sqlite3.connect(str(db_file))
    conn.execute("UPDATE leakage_events SET sequence_number = 99 WHERE sequence_number = 1")
    conn.execute("UPDATE leakage_events SET sequence_number = 1 WHERE sequence_number = 2")
    conn.execute("UPDATE leakage_events SET sequence_number = 2 WHERE sequence_number = 99")
    conn.commit()
    conn.close()

    tampered_ledger = PrivacyLeakageLedger(db_path=db_file)
    is_valid_after, err_after = tampered_ledger.verify_chain()
    assert is_valid_after is False
    assert err_after is not None
    tampered_ledger.close()


def test_ledger_persistence_across_restarts(tmp_path):
    """Confirms records and hash chains survive simulated application restart (Phase 6.4)."""
    db_file = tmp_path / "persist_ledger.db"

    # Process 1 creates ledger and records sessions
    ledger1 = PrivacyLeakageLedger(db_path=db_file)
    ledger1.record_session(_make_dummy_event("SESS_P1", round_id="ROUND_P", wire_bytes=300))
    ledger1.record_session(_make_dummy_event("SESS_P2", round_id="ROUND_P", wire_bytes=350))
    is_valid1, _ = ledger1.verify_chain()
    assert is_valid1 is True
    ledger1.close()

    # Process 2 starts up, reopens existing DB file
    ledger2 = PrivacyLeakageLedger(db_path=db_file)
    events = ledger2.get_events_for_round("ROUND_P")
    assert len(events) == 2
    assert events[0].session_id == "SESS_P1"
    assert events[1].session_id == "SESS_P2"
    assert events[0].total_serialized_protocol_bytes == 300
    assert events[1].total_serialized_protocol_bytes == 350
    assert ledger2.verify_chain()[0] is True

    # Append new session after restart
    ledger2.record_session(_make_dummy_event("SESS_P3", round_id="ROUND_P", wire_bytes=400))
    all_events = ledger2.get_all_events()
    assert len(all_events) == 3
    assert all_events[2].sequence_number == 3
    assert all_events[2].prev_hash == all_events[1].event_hash
    assert ledger2.verify_chain()[0] is True
    ledger2.close()


def test_duplicate_session_rejection_after_restart(tmp_path):
    """Confirms duplicate session IDs are rejected across restarts via SQLite constraint (Phase 6.5)."""
    db_file = tmp_path / "replay_persist_ledger.db"

    # Initial session
    ledger1 = PrivacyLeakageLedger(db_path=db_file)
    ledger1.record_session(_make_dummy_event("SESS_REPLAY_TEST", round_id="ROUND_R1"))
    ledger1.close()

    # Restarted application
    ledger2 = PrivacyLeakageLedger(db_path=db_file)
    # Attempt replay with identical session ID in a new round
    ledger2.record_session(_make_dummy_event("SESS_REPLAY_TEST", round_id="ROUND_R2"))

    r1_events = ledger2.get_events_for_round("ROUND_R1")
    r2_events = ledger2.get_events_for_round("ROUND_R2")
    assert len(r1_events) == 1
    assert r1_events[0].status == "SUCCESS"

    assert len(r2_events) == 1
    assert r2_events[0].status == "REJECTED_DUPLICATE"
    assert "Duplicate session ID detected" in r2_events[0].error_message
    assert ledger2.verify_chain()[0] is True
    ledger2.close()


def test_concurrent_audit_writes(tmp_path):
    """Confirms thread-safe concurrent writes maintain continuous sequence and valid chain (Phase 6.6)."""
    import threading
    db_file = tmp_path / "concurrent_ledger.db"
    ledger = PrivacyLeakageLedger(db_path=db_file)

    num_threads = 8
    threads = []

    def writer_worker(idx: int):
        ev = _make_dummy_event(f"SESS_CONC_{idx}", round_id="ROUND_CONC", wire_bytes=100 + idx)
        ledger.record_session(ev)

    for i in range(num_threads):
        t = threading.Thread(target=writer_worker, args=(i,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    events = ledger.get_events_for_round("ROUND_CONC")
    assert len(events) == num_threads

    # Verify no sequence gaps and cryptographic chain is 100% valid
    is_valid, err = ledger.verify_chain()
    assert is_valid is True
    assert err is None
    ledger.close()


def test_ledger_contains_no_raw_data_or_keys(tmp_path):
    """Confirms central ledger schema and stored rows contain zero raw tx data or keys (Phase 6.10)."""
    db_file = tmp_path / "privacy_audit_ledger.db"
    ledger = PrivacyLeakageLedger(db_path=db_file)
    ledger.record_session(_make_dummy_event("SESS_AUDIT_1"))

    import sqlite3
    conn = sqlite3.connect(str(db_file))
    cur = conn.execute("PRAGMA table_info(leakage_events)")
    col_names = [row[1].lower() for row in cur.fetchall()]
    conn.close()
    ledger.close()

    # Verify no sensitive columns exist
    forbidden_substrings = ["raw", "account", "key", "tx_id", "graph", "transaction", "token_list"]
    for col in col_names:
        assert not any(f in col for f in forbidden_substrings), f"Forbidden column found in ledger: {col}"

