"""SignalMesh Privacy Leakage Ledger.

Records observable cryptographic protocol events, wire message sizes, and disclosure metrics
for Private Set Intersection (PSI) collaborative rounds.

PRIVACY & SECURITY GUARANTEES:
1. Observable Telemetry Only:
   Records only observable protocol metadata: participant roles, set sizes, serialized message
   byte counts, and intersection cardinalities.
2. Zero Raw Data Ingestion:
   NEVER stores raw transaction rows, customer account numbers, private keys, candidate token sets,
   or local graph structures.
3. Durable Persistence & Atomicity:
   Backed by SQLite with ACID transactions and unique constraints. Session records persist
   across application restarts.
4. Cryptographic Hash Chain:
   Every session event incorporates a SHA-256 cryptographic hash over its canonical fields,
   linked directly to the preceding event's hash in an unbroken audit chain.
5. Tamper & Checkpoint Verification:
   Includes verify_chain() to detect modified, deleted, inserted, or reordered records.
   Supports external checkpoints (expected head hash / expected sequence count) to detect
   silent tail truncation.
6. Session Registry & Replay Protection:
   Maintains a dedicated accepted_sessions registry enforcing UNIQUE(session_id) for accepted
   sessions. Every audit event receives a distinct unique event_id while preserving the caller's
   original submitted session_id unchanged in duplicate rejection audit records.

AUDIT-INTEGRITY GUARANTEES & THREAT MODEL LIMITATIONS:
The local cryptographic hash chain provides verifiable detection against accidental corruption,
record tampering, row deletion, or history reordering when checked against a recorded chain
or external checkpoint.
HONEST LIMITATION: A local hash chain is NOT immutable or fully tamper-proof against a privileged
adversary with operating-system or root-level write access to the SQLite database file, as such
an attacker could rewrite all rows and recompute the entire hash chain from genesis without detection.
External checkpoints, digital signatures, or external write-once storage would be required to
defend against root-level database administrators.
"""

from dataclasses import asdict, dataclass
from datetime import datetime
import hashlib
import json
from pathlib import Path
import sqlite3
import threading
from typing import Any, Dict, List, Optional, Set, Tuple, Union


@dataclass(frozen=True)
class LeakageSessionEvent:
    """Audit record for a single unidirectional PSI session between two participants."""
    session_id: str
    round_id: str
    server_bank_id: str
    client_bank_id: str
    protocol_family: str
    data_structure: str
    fpr_parameter: float
    server_set_size: int
    client_set_size: int
    server_setup_bytes: int
    client_request_bytes: int
    server_response_bytes: int
    total_wire_bytes: int  # Measured serialized protocol-message bytes (excluding TLS/network framing)
    client_revealed_cardinality: int
    recipient_of_output: str
    status: str  # "SUCCESS", "REJECTED_DUPLICATE", "FAILED"
    timestamp: str
    execution_time_ms: float
    error_message: Optional[str] = None
    sequence_number: int = 0
    prev_hash: str = "GENESIS"
    event_hash: str = ""
    event_id: str = ""  # Unique audit record identifier

    @property
    def total_serialized_protocol_bytes(self) -> int:
        """Alias for total_wire_bytes adhering to precise measurement terminology."""
        return self.total_wire_bytes

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CollaborationRoundSummary:
    """Aggregated disclosure and execution summary for a multi-party collaboration round."""
    round_id: str
    created_at: str
    participating_banks: List[str]
    session_count: int
    total_wire_bytes: int  # Measured serialized protocol-message bytes (excluding TLS/network framing)
    total_matches_revealed: int
    status: str
    sessions: List[LeakageSessionEvent]

    @property
    def total_serialized_protocol_bytes(self) -> int:
        """Alias for total_wire_bytes adhering to precise measurement terminology."""
        return self.total_wire_bytes

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def canonical_json_dumps(obj: Any) -> str:
    """Serializes a Python data structure into SignalMesh Canonical JSON (SMCJ).

    CANONICAL SPECIFICATION (SignalMesh Canonical JSON):
    1. Lexicographical Key Ordering:
       Dictionary keys are sorted in ascending order by Unicode code points (sort_keys=True).
    2. Zero Structural Whitespace:
       Separators are emitted strictly without whitespace: ',' between items and ':' between key/value.
    3. Direct UTF-8 Representation:
       Characters are emitted directly as UTF-8 without escaping non-ASCII code points (ensure_ascii=False).
    4. Numeric Normalization:
       - Negative zero (-0.0) is normalized to positive zero (0.0) to avoid dual zero representations.
       - Floating-point numbers preserve full IEEE 754 precision without truncation.
       - Integers are rendered as decimal tokens without decimal points.

    HONEST SPECIFICATION BOUNDARY:
    SMCJ is a well-defined project-specific canonicalization scheme. It does NOT claim full RFC 8785 (JCS)
    compliance because Python's standard json engine formats certain exponents differently from ECMAScript 6
    (e.g., Python outputs '1e-05' with a two-digit exponent rather than ECMAScript's '1e-5').
    Within the SignalMesh network, all participating nodes share this exact SMCJ specification.
    """
    def _normalize(item: Any) -> Any:
        if isinstance(item, dict):
            return {str(k): _normalize(v) for k, v in item.items()}
        if isinstance(item, (list, tuple)):
            return [_normalize(x) for x in item]
        if isinstance(item, float):
            # Normalize negative zero (-0.0) to positive zero (0.0)
            if item == 0.0:
                return 0.0
            return item
        return item

    normalized = _normalize(obj)
    return json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_canonical_event_hash(
    sequence_number: int,
    event_id: str,
    prev_hash: str,
    session_id: str,
    round_id: str,
    server_bank_id: str,
    client_bank_id: str,
    protocol_family: str,
    data_structure: str,
    fpr_parameter: float,
    server_set_size: int,
    client_set_size: int,
    server_setup_bytes: int,
    client_request_bytes: int,
    server_response_bytes: int,
    total_wire_bytes: int,
    client_revealed_cardinality: int,
    recipient_of_output: str,
    status: str,
    timestamp: str,
    execution_time_ms: float,
    error_message: Optional[str] = None,
) -> str:
    """Computes a deterministic SHA-256 hash over canonical audit fields at exact stored precision."""
    canonical_dict = {
        "sequence_number": int(sequence_number),
        "event_id": str(event_id),
        "prev_hash": str(prev_hash),
        "session_id": str(session_id),
        "round_id": str(round_id),
        "server_bank_id": str(server_bank_id),
        "client_bank_id": str(client_bank_id),
        "protocol_family": str(protocol_family),
        "data_structure": str(data_structure),
        "fpr_parameter": float(fpr_parameter),
        "server_set_size": int(server_set_size),
        "client_set_size": int(client_set_size),
        "server_setup_bytes": int(server_setup_bytes),
        "client_request_bytes": int(client_request_bytes),
        "server_response_bytes": int(server_response_bytes),
        "total_wire_bytes": int(total_wire_bytes),
        "client_revealed_cardinality": int(client_revealed_cardinality),
        "recipient_of_output": str(recipient_of_output),
        "status": str(status),
        "timestamp": str(timestamp),
        "execution_time_ms": float(execution_time_ms),
        "error_message": str(error_message or ""),
    }
    canonical_json = canonical_json_dumps(canonical_dict)
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


class PrivacyLeakageLedger:
    """Durable, verifiable, append-only ledger for tracking observable PSI disclosure events."""

    def __init__(self, db_path: Optional[Union[str, Path]] = None):
        self._lock = threading.Lock()
        self.db_path = str(db_path) if db_path is not None else ":memory:"
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        self._conn = sqlite3.connect(
            self.db_path,
            timeout=30.0,
            check_same_thread=False,
            isolation_level=None,  # Explicit transaction control
        )
        self._conn.row_factory = sqlite3.Row

        with self._lock:
            if self.db_path != ":memory:":
                self._conn.execute("PRAGMA journal_mode=WAL;")
                self._conn.execute("PRAGMA synchronous=NORMAL;")
            self._init_db()

    def _init_db(self) -> None:
        """Initializes tables and indexes if they do not exist."""
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS leakage_events (
                sequence_number INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                session_id TEXT NOT NULL,
                round_id TEXT NOT NULL,
                server_bank_id TEXT NOT NULL,
                client_bank_id TEXT NOT NULL,
                protocol_family TEXT NOT NULL,
                data_structure TEXT NOT NULL,
                fpr_parameter REAL NOT NULL,
                server_set_size INTEGER NOT NULL,
                client_set_size INTEGER NOT NULL,
                server_setup_bytes INTEGER NOT NULL,
                client_request_bytes INTEGER NOT NULL,
                server_response_bytes INTEGER NOT NULL,
                total_wire_bytes INTEGER NOT NULL,
                client_revealed_cardinality INTEGER NOT NULL,
                recipient_of_output TEXT NOT NULL,
                status TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                execution_time_ms REAL NOT NULL,
                error_message TEXT,
                prev_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL
            );
        """)
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS accepted_sessions (
                session_id TEXT PRIMARY KEY,
                event_id TEXT NOT NULL,
                round_id TEXT NOT NULL,
                accepted_at TEXT NOT NULL
            );
        """)
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_leakage_round_id ON leakage_events(round_id);
        """)
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_leakage_session_id ON leakage_events(session_id);
        """)

    def _row_to_event(self, row: sqlite3.Row) -> LeakageSessionEvent:
        """Constructs a LeakageSessionEvent from a database row."""
        return LeakageSessionEvent(
            session_id=row["session_id"],
            round_id=row["round_id"],
            server_bank_id=row["server_bank_id"],
            client_bank_id=row["client_bank_id"],
            protocol_family=row["protocol_family"],
            data_structure=row["data_structure"],
            fpr_parameter=float(row["fpr_parameter"]),
            server_set_size=int(row["server_set_size"]),
            client_set_size=int(row["client_set_size"]),
            server_setup_bytes=int(row["server_setup_bytes"]),
            client_request_bytes=int(row["client_request_bytes"]),
            server_response_bytes=int(row["server_response_bytes"]),
            total_wire_bytes=int(row["total_wire_bytes"]),
            client_revealed_cardinality=int(row["client_revealed_cardinality"]),
            recipient_of_output=row["recipient_of_output"],
            status=row["status"],
            timestamp=row["timestamp"],
            execution_time_ms=float(row["execution_time_ms"]),
            error_message=row["error_message"],
            sequence_number=int(row["sequence_number"]),
            prev_hash=row["prev_hash"],
            event_hash=row["event_hash"],
            event_id=row["event_id"],
        )

    def record_session(self, event: LeakageSessionEvent) -> LeakageSessionEvent:
        """Records a session event into the ledger with ACID transaction, replay prevention, and hash chaining."""
        with self._lock:
            # Check if this session ID was already accepted in the registry
            cursor = self._conn.execute(
                "SELECT 1 FROM accepted_sessions WHERE session_id = ?",
                (event.session_id,),
            )
            if cursor.fetchone() is not None:
                # Duplicate replay detected! Construct REJECTED_DUPLICATE event.
                # Original session_id remains completely unchanged (un-suffixed).
                # event_id will be uniquely generated in _insert_event_atomic.
                rej_event = LeakageSessionEvent(
                    session_id=event.session_id,
                    round_id=event.round_id,
                    server_bank_id=event.server_bank_id,
                    client_bank_id=event.client_bank_id,
                    protocol_family=event.protocol_family,
                    data_structure=event.data_structure,
                    fpr_parameter=event.fpr_parameter,
                    server_set_size=event.server_set_size,
                    client_set_size=event.client_set_size,
                    server_setup_bytes=0,
                    client_request_bytes=0,
                    server_response_bytes=0,
                    total_wire_bytes=0,
                    client_revealed_cardinality=0,
                    recipient_of_output="NONE",
                    status="REJECTED_DUPLICATE",
                    timestamp=datetime.utcnow().isoformat(),
                    execution_time_ms=0.0,
                    error_message=f"Duplicate session ID detected: {event.session_id}",
                )
                return self._insert_event_atomic(rej_event, register_accepted=False)

            # Not yet seen in accepted_sessions. Attempt atomic insert.
            register_accepted = (event.status == "SUCCESS")
            try:
                return self._insert_event_atomic(event, register_accepted=register_accepted)
            except sqlite3.IntegrityError as ie:
                if "accepted_sessions" in str(ie) or "UNIQUE constraint failed" in str(ie):
                    # Concurrent duplicate race caught by SQLite UNIQUE constraint: handle as duplicate rejection
                    rej_event = LeakageSessionEvent(
                        session_id=event.session_id,
                        round_id=event.round_id,
                        server_bank_id=event.server_bank_id,
                        client_bank_id=event.client_bank_id,
                        protocol_family=event.protocol_family,
                        data_structure=event.data_structure,
                        fpr_parameter=event.fpr_parameter,
                        server_set_size=event.server_set_size,
                        client_set_size=event.client_set_size,
                        server_setup_bytes=0,
                        client_request_bytes=0,
                        server_response_bytes=0,
                        total_wire_bytes=0,
                        client_revealed_cardinality=0,
                        recipient_of_output="NONE",
                        status="REJECTED_DUPLICATE",
                        timestamp=datetime.utcnow().isoformat(),
                        execution_time_ms=0.0,
                        error_message=f"Duplicate session ID detected (concurrent race): {event.session_id}",
                    )
                    return self._insert_event_atomic(rej_event, register_accepted=False)
                raise

    def _insert_event_atomic(
        self,
        event: LeakageSessionEvent,
        register_accepted: bool = False,
    ) -> LeakageSessionEvent:
        """Atomically computes sequence, prev_hash, and event_hash, then inserts row in a transaction."""
        self._conn.execute("BEGIN IMMEDIATE;")
        try:
            # Get last recorded event to chain against
            last_cur = self._conn.execute(
                "SELECT sequence_number, event_hash FROM leakage_events ORDER BY sequence_number DESC LIMIT 1"
            )
            last_row = last_cur.fetchone()
            if last_row is None:
                seq_num = 1
                prev_h = "GENESIS"
            else:
                seq_num = last_row["sequence_number"] + 1
                prev_h = last_row["event_hash"]

            # Distinct unique event ID for every audit record
            ev_id = event.event_id or f"EVT_{seq_num:06d}"

            ev_hash = compute_canonical_event_hash(
                sequence_number=seq_num,
                event_id=ev_id,
                prev_hash=prev_h,
                session_id=event.session_id,
                round_id=event.round_id,
                server_bank_id=event.server_bank_id,
                client_bank_id=event.client_bank_id,
                protocol_family=event.protocol_family,
                data_structure=event.data_structure,
                fpr_parameter=event.fpr_parameter,
                server_set_size=event.server_set_size,
                client_set_size=event.client_set_size,
                server_setup_bytes=event.server_setup_bytes,
                client_request_bytes=event.client_request_bytes,
                server_response_bytes=event.server_response_bytes,
                total_wire_bytes=event.total_wire_bytes,
                client_revealed_cardinality=event.client_revealed_cardinality,
                recipient_of_output=event.recipient_of_output,
                status=event.status,
                timestamp=event.timestamp,
                execution_time_ms=event.execution_time_ms,
                error_message=event.error_message,
            )

            self._conn.execute("""
                INSERT INTO leakage_events (
                    sequence_number, event_id, session_id, round_id, server_bank_id, client_bank_id,
                    protocol_family, data_structure, fpr_parameter, server_set_size, client_set_size,
                    server_setup_bytes, client_request_bytes, server_response_bytes, total_wire_bytes,
                    client_revealed_cardinality, recipient_of_output, status, timestamp,
                    execution_time_ms, error_message, prev_hash, event_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                seq_num, ev_id, event.session_id, event.round_id, event.server_bank_id, event.client_bank_id,
                event.protocol_family, event.data_structure, event.fpr_parameter, event.server_set_size, event.client_set_size,
                event.server_setup_bytes, event.client_request_bytes, event.server_response_bytes, event.total_wire_bytes,
                event.client_revealed_cardinality, event.recipient_of_output, event.status, event.timestamp,
                event.execution_time_ms, event.error_message, prev_h, ev_hash,
            ))

            if register_accepted:
                self._conn.execute("""
                    INSERT INTO accepted_sessions (session_id, event_id, round_id, accepted_at)
                    VALUES (?, ?, ?, ?);
                """, (event.session_id, ev_id, event.round_id, event.timestamp))

            self._conn.execute("COMMIT;")

            return LeakageSessionEvent(
                session_id=event.session_id,
                round_id=event.round_id,
                server_bank_id=event.server_bank_id,
                client_bank_id=event.client_bank_id,
                protocol_family=event.protocol_family,
                data_structure=event.data_structure,
                fpr_parameter=event.fpr_parameter,
                server_set_size=event.server_set_size,
                client_set_size=event.client_set_size,
                server_setup_bytes=event.server_setup_bytes,
                client_request_bytes=event.client_request_bytes,
                server_response_bytes=event.server_response_bytes,
                total_wire_bytes=event.total_wire_bytes,
                client_revealed_cardinality=event.client_revealed_cardinality,
                recipient_of_output=event.recipient_of_output,
                status=event.status,
                timestamp=event.timestamp,
                execution_time_ms=event.execution_time_ms,
                error_message=event.error_message,
                sequence_number=seq_num,
                prev_hash=prev_h,
                event_hash=ev_hash,
                event_id=ev_id,
            )
        except Exception:
            try:
                self._conn.execute("ROLLBACK;")
            except sqlite3.Error:
                pass
            raise

    def get_events_for_round(self, round_id: str) -> List[LeakageSessionEvent]:
        """Returns all recorded events for a specific round ID ordered by sequence."""
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM leakage_events WHERE round_id = ? ORDER BY sequence_number ASC",
                (round_id,),
            )
            return [self._row_to_event(r) for r in cur.fetchall()]

    def get_round_summary(self, round_id: str) -> CollaborationRoundSummary:
        """Computes a summary of disclosures and serialized protocol traffic for a collaboration round."""
        round_events = self.get_events_for_round(round_id)
        if not round_events:
            raise KeyError(f"Round '{round_id}' not found in leakage ledger.")

        banks: Set[str] = set()
        total_wire = 0
        total_matches = 0
        failed = False

        for ev in round_events:
            banks.add(ev.server_bank_id)
            banks.add(ev.client_bank_id)
            total_wire += ev.total_wire_bytes
            total_matches += ev.client_revealed_cardinality
            if ev.status != "SUCCESS":
                failed = True

        status = "COMPLETED" if not failed else "PARTIAL_OR_FAILED"

        return CollaborationRoundSummary(
            round_id=round_id,
            created_at=round_events[0].timestamp,
            participating_banks=sorted(banks),
            session_count=len(round_events),
            total_wire_bytes=total_wire,
            total_matches_revealed=total_matches,
            status=status,
            sessions=round_events,
        )

    def get_all_events(self) -> List[LeakageSessionEvent]:
        """Returns all events recorded in the ledger ordered by sequence."""
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM leakage_events ORDER BY sequence_number ASC"
            )
            return [self._row_to_event(r) for r in cur.fetchall()]

    def get_latest_event_hash(self) -> Optional[str]:
        """Returns the event_hash of the most recently recorded event, or None if ledger is empty."""
        with self._lock:
            cur = self._conn.execute(
                "SELECT event_hash FROM leakage_events ORDER BY sequence_number DESC LIMIT 1"
            )
            row = cur.fetchone()
            return row["event_hash"] if row else None

    def verify_chain(
        self,
        expected_head_hash: Optional[str] = None,
        expected_sequence_count: Optional[int] = None,
    ) -> Tuple[bool, Optional[str]]:
        """Verifies the integrity of the cryptographic audit hash chain.

        INTERNAL DETECTION VS. TAIL TRUNCATION:
        1. Internal Detection (Autonomous):
           - Can detect any modification to canonical fields (at exact float/int precision).
           - Can detect any internal record deletion (e.g. middle records, genesis deletion).
           - Can detect any record reordering or swapping.
        2. Tail Truncation (Requires External Checkpoint):
           - Deleting the final record or rolling back multiple trailing records leaves a
             self-consistent prefix of the chain (valid sequence numbers and unbroken hashes).
           - Internal chain inspection alone CANNOT detect silent tail truncation without an
             external checkpoint.
           - Passing 'expected_head_hash' or 'expected_sequence_count' verifies the ledger against
             an external receipt/checkpoint, immediately detecting any tail truncation.

        Returns:
            (True, None) if completely verified against all internal rules and external checkpoints.
            (False, error_description) if modified, deleted, truncated, or reordered.
        """
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM leakage_events ORDER BY sequence_number ASC"
            )
            rows = cur.fetchall()

            # External checkpoint validations
            if expected_sequence_count is not None and len(rows) != expected_sequence_count:
                return (
                    False,
                    f"Chain truncation detected: expected {expected_sequence_count} events, found {len(rows)}",
                )

            if expected_head_hash is not None:
                if not rows:
                    return (
                        False,
                        f"Chain truncation detected: expected head hash '{expected_head_hash}', but ledger is empty",
                    )
                actual_head_hash = rows[-1]["event_hash"]
                if actual_head_hash != expected_head_hash:
                    return (
                        False,
                        f"Chain tail truncation or head mismatch detected: expected head hash '{expected_head_hash}', got '{actual_head_hash}'",
                    )

            if not rows:
                return (True, None)

            expected_seq = 1
            expected_prev_hash = "GENESIS"

            for row in rows:
                actual_seq = row["sequence_number"]
                if actual_seq != expected_seq:
                    return (
                        False,
                        f"Sequence gap or reordering detected: expected sequence {expected_seq}, found {actual_seq}",
                    )

                actual_prev_hash = row["prev_hash"]
                if actual_prev_hash != expected_prev_hash:
                    return (
                        False,
                        f"Broken chain link at sequence {actual_seq}: expected prev_hash '{expected_prev_hash}', got '{actual_prev_hash}'",
                    )

                computed_hash = compute_canonical_event_hash(
                    sequence_number=actual_seq,
                    event_id=row["event_id"],
                    prev_hash=actual_prev_hash,
                    session_id=row["session_id"],
                    round_id=row["round_id"],
                    server_bank_id=row["server_bank_id"],
                    client_bank_id=row["client_bank_id"],
                    protocol_family=row["protocol_family"],
                    data_structure=row["data_structure"],
                    fpr_parameter=row["fpr_parameter"],
                    server_set_size=row["server_set_size"],
                    client_set_size=row["client_set_size"],
                    server_setup_bytes=row["server_setup_bytes"],
                    client_request_bytes=row["client_request_bytes"],
                    server_response_bytes=row["server_response_bytes"],
                    total_wire_bytes=row["total_wire_bytes"],
                    client_revealed_cardinality=row["client_revealed_cardinality"],
                    recipient_of_output=row["recipient_of_output"],
                    status=row["status"],
                    timestamp=row["timestamp"],
                    execution_time_ms=row["execution_time_ms"],
                    error_message=row["error_message"],
                )

                if computed_hash != row["event_hash"]:
                    return (
                        False,
                        f"Tampered record detected at sequence {actual_seq} (session '{row['session_id']}'): computed hash {computed_hash} != stored {row['event_hash']}",
                    )

                expected_prev_hash = row["event_hash"]
                expected_seq += 1

            return (True, None)

    def verify_integrity(
        self,
        expected_head_hash: Optional[str] = None,
        expected_sequence_count: Optional[int] = None,
    ) -> Tuple[bool, Optional[str]]:
        """Convenience alias for verify_chain."""
        return self.verify_chain(
            expected_head_hash=expected_head_hash,
            expected_sequence_count=expected_sequence_count,
        )

    def close(self) -> None:
        """Closes the underlying database connection."""
        with self._lock:
            try:
                self._conn.close()
            except Exception:
                pass
