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
    canonical_json_dumps,
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


def test_audit_chain_deleting_last_record_requires_checkpoint(tmp_path):
    """Confirms that deleting the last record leaves a locally valid prefix, but is detected via checkpoint."""
    import sqlite3
    db_file = tmp_path / "tail_delete_ledger.db"
    ledger = PrivacyLeakageLedger(db_path=db_file)

    for i in range(1, 5):
        ledger.record_session(_make_dummy_event(f"SESS_TAIL_{i}", round_id="ROUND_TAIL"))

    # Record the true expected head hash and count before tampering
    checkpoint_head_hash = ledger.get_latest_event_hash()
    assert checkpoint_head_hash is not None
    assert ledger.verify_chain(expected_head_hash=checkpoint_head_hash, expected_sequence_count=4)[0] is True
    ledger.close()

    # Adversary deletes the final record (row 4)
    conn = sqlite3.connect(str(db_file))
    conn.execute("DELETE FROM leakage_events WHERE sequence_number = 4")
    conn.commit()
    conn.close()

    # Reopen ledger
    reopened_ledger = PrivacyLeakageLedger(db_path=db_file)

    # 1. Internal-only check sees rows 1-3 as an unbroken valid prefix
    is_valid_internal, err_internal = reopened_ledger.verify_chain()
    assert is_valid_internal is True, "Autonomous local check without checkpoint sees valid prefix"
    assert err_internal is None

    # 2. External checkpoint by sequence count reliably catches the deletion
    is_valid_cnt, err_cnt = reopened_ledger.verify_chain(expected_sequence_count=4)
    assert is_valid_cnt is False
    assert "expected 4 events, found 3" in err_cnt

    # 3. External checkpoint by head hash reliably catches the deletion
    is_valid_hash, err_hash = reopened_ledger.verify_chain(expected_head_hash=checkpoint_head_hash)
    assert is_valid_hash is False
    assert "Chain tail truncation or head mismatch detected" in err_hash

    reopened_ledger.close()


def test_audit_chain_truncating_multiple_final_records(tmp_path):
    """Confirms rollback/truncation of multiple trailing records is detected with checkpoints."""
    import sqlite3
    db_file = tmp_path / "truncation_ledger.db"
    ledger = PrivacyLeakageLedger(db_path=db_file)

    for i in range(1, 6):
        ledger.record_session(_make_dummy_event(f"SESS_TRUNC_{i}", round_id="ROUND_TRUNC"))

    checkpoint_head_hash = ledger.get_latest_event_hash()
    ledger.close()

    # Adversary rolls back to sequence 2 by deleting rows 3, 4, 5
    conn = sqlite3.connect(str(db_file))
    conn.execute("DELETE FROM leakage_events WHERE sequence_number >= 3")
    conn.commit()
    conn.close()

    reopened = PrivacyLeakageLedger(db_path=db_file)
    # Internal check: valid 2-event prefix
    assert reopened.verify_chain()[0] is True

    # Checkpoint checks: both detect truncation
    is_valid_cnt, err_cnt = reopened.verify_chain(expected_sequence_count=5)
    assert is_valid_cnt is False
    assert "expected 5 events, found 2" in err_cnt

    is_valid_hash, err_hash = reopened.verify_chain(expected_head_hash=checkpoint_head_hash)
    assert is_valid_hash is False
    assert "Chain tail truncation" in err_hash

    reopened.close()


def _multiprocess_same_session_worker(
    db_path_str: str,
    session_id: str,
    round_id: str,
    barrier,
    result_queue,
):
    """Worker executed in an independent OS process attempting to record the same session."""
    from app.psi.leakage_ledger import PrivacyLeakageLedger
    ledger = PrivacyLeakageLedger(db_path=db_path_str)
    ev = _make_dummy_event(session_id, round_id=round_id)
    # Synchronize both processes at barrier so they execute record_session simultaneously
    barrier.wait()
    try:
        recorded = ledger.record_session(ev)
        result_queue.put((
            recorded.status,
            recorded.session_id,
            recorded.event_id,
            recorded.sequence_number,
            recorded.error_message,
        ))
    except Exception as exc:
        result_queue.put(("EXCEPTION", session_id, "", -1, str(exc)))
    finally:
        ledger.close()


def test_concurrent_multiprocess_same_session_race(tmp_path):
    """Confirms two separate OS processes racing to record the same session are cleanly handled.

    One process succeeds (SUCCESS), the other is rejected as duplicate (REJECTED_DUPLICATE),
    both retain the exact original session_id, receive distinct event_ids,
    accepted_sessions contains exactly 1 row, and the hash chain remains unbroken.
    """
    import multiprocessing
    import sqlite3

    db_file = tmp_path / "multiprocess_race_ledger.db"

    # Pre-initialize database schema
    init_ledger = PrivacyLeakageLedger(db_path=db_file)
    init_ledger.close()

    ctx = multiprocessing.get_context("spawn")
    barrier = ctx.Barrier(2)
    result_queue = ctx.Queue()

    race_session_id = "SESS_CONCURRENT_RACE"
    p1 = ctx.Process(
        target=_multiprocess_same_session_worker,
        args=(str(db_file), race_session_id, "ROUND_RACE", barrier, result_queue),
    )
    p2 = ctx.Process(
        target=_multiprocess_same_session_worker,
        args=(str(db_file), race_session_id, "ROUND_RACE", barrier, result_queue),
    )

    p1.start()
    p2.start()

    p1.join(timeout=10.0)
    p2.join(timeout=10.0)

    assert not p1.is_alive()
    assert not p2.is_alive()

    results = [result_queue.get(timeout=2.0), result_queue.get(timeout=2.0)]
    statuses = {r[0] for r in results}
    assert statuses == {"SUCCESS", "REJECTED_DUPLICATE"}, f"Expected one SUCCESS and one REJECTED_DUPLICATE, got {statuses}"

    # Confirm both results retain the exact original submitted session ID
    assert results[0][1] == race_session_id
    assert results[1][1] == race_session_id

    # Confirm distinct event IDs
    assert results[0][2] != results[1][2]

    # Verify ledger state directly
    ledger = PrivacyLeakageLedger(db_path=db_file)
    events = ledger.get_events_for_round("ROUND_RACE")
    assert len(events) == 2
    assert {e.status for e in events} == {"SUCCESS", "REJECTED_DUPLICATE"}
    assert events[0].session_id == race_session_id
    assert events[1].session_id == race_session_id
    assert events[0].event_id != events[1].event_id
    assert events[1].prev_hash == events[0].event_hash

    # Verify chain integrity
    is_valid, err = ledger.verify_chain()
    assert is_valid is True
    assert err is None

    # Verify accepted_sessions registry in SQLite
    conn = sqlite3.connect(str(db_file))
    cur = conn.cursor()
    cur.execute("SELECT session_id, event_id FROM accepted_sessions")
    rows = cur.fetchall()
    conn.close()

    assert len(rows) == 1
    assert rows[0][0] == race_session_id
    # The accepted event_id must match the event that got SUCCESS
    success_event = next(e for e in events if e.status == "SUCCESS")
    assert rows[0][1] == success_event.event_id

    ledger.close()


def test_duplicate_replay_attempts_remain_auditable_across_multiple_restarts(tmp_path):
    """Confirms repeated replay attempts across multiple restarts are chained and auditable."""
    db_file = tmp_path / "multi_restart_replay.db"

    # Step 1: Initial successful session
    l1 = PrivacyLeakageLedger(db_path=db_file)
    l1.record_session(_make_dummy_event("SESS_ORIGINAL", round_id="R1"))
    l1.close()

    # Step 2: Restart 1 - First replay attempt
    l2 = PrivacyLeakageLedger(db_path=db_file)
    l2.record_session(_make_dummy_event("SESS_ORIGINAL", round_id="R2"))
    r2_events = l2.get_events_for_round("R2")
    assert len(r2_events) == 1
    assert r2_events[0].status == "REJECTED_DUPLICATE"
    assert r2_events[0].session_id == "SESS_ORIGINAL"
    assert r2_events[0].event_id == "EVT_000002"
    assert l2.verify_chain()[0] is True
    l2.close()

    # Step 3: Restart 2 - Second replay attempt of the same original session ID
    l3 = PrivacyLeakageLedger(db_path=db_file)
    l3.record_session(_make_dummy_event("SESS_ORIGINAL", round_id="R3"))
    r3_events = l3.get_events_for_round("R3")
    assert len(r3_events) == 1
    assert r3_events[0].status == "REJECTED_DUPLICATE"
    assert r3_events[0].session_id == "SESS_ORIGINAL"
    assert r3_events[0].event_id == "EVT_000003"

    # Verify all 3 events are ordered and cryptographically chained
    all_events = l3.get_all_events()
    assert len(all_events) == 3
    assert all_events[0].status == "SUCCESS"
    assert all_events[1].status == "REJECTED_DUPLICATE"
    assert all_events[2].status == "REJECTED_DUPLICATE"
    assert all_events[0].session_id == "SESS_ORIGINAL"
    assert all_events[1].session_id == "SESS_ORIGINAL"
    assert all_events[2].session_id == "SESS_ORIGINAL"
    assert all_events[0].event_id == "EVT_000001"
    assert all_events[1].event_id == "EVT_000002"
    assert all_events[2].event_id == "EVT_000003"
    assert all_events[1].prev_hash == all_events[0].event_hash
    assert all_events[2].prev_hash == all_events[1].event_hash
    assert l3.verify_chain()[0] is True
    l3.close()


def test_audit_chain_detects_small_numerical_tampering(tmp_path):
    """Confirms canonical hash protects exact float precision against minute tampering."""
    import sqlite3
    db_file = tmp_path / "precision_tamper.db"
    ledger = PrivacyLeakageLedger(db_path=db_file)
    ledger.record_session(_make_dummy_event("SESS_PRECISION", round_id="R_PREC", wire_bytes=100))
    assert ledger.verify_chain()[0] is True
    ledger.close()

    # 1a. Tamper with fpr_parameter by exactly 1e-9 (0.001 -> 0.001000001, delta = 10^-9)
    conn = sqlite3.connect(str(db_file))
    conn.execute("UPDATE leakage_events SET fpr_parameter = 0.001000001 WHERE sequence_number = 1")
    conn.commit()
    conn.close()

    tampered_fpr_1e9 = PrivacyLeakageLedger(db_path=db_file)
    is_valid_fpr, err_fpr = tampered_fpr_1e9.verify_chain()
    assert is_valid_fpr is False
    assert "Tampered record detected" in err_fpr
    tampered_fpr_1e9.close()

    # 1b. Tamper with fpr_parameter by exactly 1e-11 (0.001 -> 0.00100000001, delta = 10^-11)
    conn = sqlite3.connect(str(db_file))
    conn.execute("UPDATE leakage_events SET fpr_parameter = 0.00100000001 WHERE sequence_number = 1")
    conn.commit()
    conn.close()

    tampered_fpr_1e11 = PrivacyLeakageLedger(db_path=db_file)
    is_valid_fpr_11, err_fpr_11 = tampered_fpr_1e11.verify_chain()
    assert is_valid_fpr_11 is False
    assert "Tampered record detected" in err_fpr_11
    tampered_fpr_1e11.close()

    # 2. Restore fpr_parameter and tamper with execution_time_ms by 1e-6 (12.5 -> 12.500001)
    conn = sqlite3.connect(str(db_file))
    conn.execute("UPDATE leakage_events SET fpr_parameter = 0.001, execution_time_ms = 12.500001 WHERE sequence_number = 1")
    conn.commit()
    conn.close()

    tampered_time_ledger = PrivacyLeakageLedger(db_path=db_file)
    is_valid_time, err_time = tampered_time_ledger.verify_chain()
    assert is_valid_time is False
    assert "Tampered record detected" in err_time
    tampered_time_ledger.close()


def test_audit_chain_detects_tampered_event_id(tmp_path):
    """Confirms modifying event_id directly in SQLite is detected by chain verification."""
    import sqlite3
    db_file = tmp_path / "tamper_event_id.db"
    ledger = PrivacyLeakageLedger(db_path=db_file)
    ledger.record_session(_make_dummy_event("SESS_EV_TAMPER", round_id="R_EV"))
    assert ledger.verify_chain()[0] is True
    ledger.close()

    # Tamper with event_id directly in SQLite
    conn = sqlite3.connect(str(db_file))
    conn.execute("UPDATE leakage_events SET event_id = 'EVT_FORGED_9999' WHERE sequence_number = 1")
    conn.commit()
    conn.close()

    reopened = PrivacyLeakageLedger(db_path=db_file)
    is_valid, err = reopened.verify_chain()
    assert is_valid is False
    assert "Tampered record detected at sequence 1" in err
    reopened.close()


def test_canonical_json_scheme_conformance():
    """Conformance tests for SignalMesh Canonical JSON (SMCJ) serialization."""
    # 1. Floating-point formatting: preserves exact float values without decimal truncation
    data_floats = {"a": 0.001, "b": 0.001000001, "c": 12.5, "d": 100.25}
    out_floats = canonical_json_dumps(data_floats)
    assert out_floats == '{"a":0.001,"b":0.001000001,"c":12.5,"d":100.25}'

    # 2. Negative zero: -0.0 is normalized to 0.0, avoiding dual zero representations
    pos_zero = canonical_json_dumps({"rate": 0.0})
    neg_zero = canonical_json_dumps({"rate": -0.0})
    assert pos_zero == '{"rate":0.0}'
    assert neg_zero == '{"rate":0.0}'
    assert pos_zero == neg_zero

    # 3. Exponent notation: verify standard representation for tiny and large floats
    data_exp = {"small": 1e-05, "tiny": 1e-09, "large": 1e+20}
    out_exp = canonical_json_dumps(data_exp)
    assert '"small":1e-05' in out_exp
    assert '"tiny":1e-09' in out_exp
    assert '"large":1e+20' in out_exp

    # 4. Unicode keys and values: sorted by Unicode code point, unescaped UTF-8 output
    data_unicode = {"β_key": "val2", "α_key": "café", "a_ascii": "normal"}
    out_unicode = canonical_json_dumps(data_unicode)
    # Lexicographical order: ASCII 'a_ascii' (U+0061) < 'α_key' (U+03B1) < 'β_key' (U+03B2)
    assert out_unicode == '{"a_ascii":"normal","α_key":"café","β_key":"val2"}'

    # 5. Nested normalization: negative zero inside lists/dicts
    nested = {"list": [-0.0, 1.5, {"inner": -0.0}]}
    out_nested = canonical_json_dumps(nested)
    assert out_nested == '{"list":[0.0,1.5,{"inner":0.0}]}'
