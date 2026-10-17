"""SignalMesh PSI Collaboration Coordinator.

Orchestrates multi-bank collaborative Private Set Intersection (PSI) rounds,
manages bidirectional discovery sessions, logs observable telemetry to the
Privacy Leakage Ledger, and coordinates protocol message routing between
autonomous bank agents via narrow BankMessageEndpoint transport interfaces.

SECURITY & ARCHITECTURAL BOUNDARIES:
1. Zero Complete Agent Passing:
   The coordinator NEVER accepts complete OperationalBankAgent instances, local graphs,
   or raw local token sets. It communicates strictly with narrow BankMessageEndpoint
   interfaces exchanging serialized protobuf bytes and scalar parameters.
2. Message Router Only:
   The coordinator functions strictly as a message router relaying opaque protobuf bytes
   (ServerSetup, Request, Response) between participant endpoints.
3. Decentralized Graph Expansion:
   Matched-seed graph expansion is executed locally and privately by each bank agent
   in its own local memory/process. Subgraphs and member-level investigation leads NEVER
   leave the bank agent.
4. Asymmetric Revelation Accounting:
   OpenMined PSI reveals matching indices ONLY to the client. A bidirectional round
   consists of two explicit directional sessions:
     - Leg 1: Bank A is Server, Bank B is Client. Bank B computes matches; Bank A learns nothing.
     - Leg 2: Bank B is Server, Bank A is Client. Bank A computes matches; Bank B learns nothing.
5. Observable Telemetry & Leakage Ledger:
   Observable wire metadata (wire lengths, set sizes, revealed cardinalities, and timings)
   are explicitly logged to the Privacy Leakage Ledger for compliance and auditability.
   Zero member-level tokens or graph objects are recorded or returned.
6. Replay & Duplicate Prevention:
   Replayed round IDs or duplicate sessions are rejected and audited in the Privacy Leakage Ledger.
"""

from dataclasses import asdict, dataclass
from datetime import datetime
import time
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple
import uuid

import private_set_intersection.python as psi

from app.core.config import DataBoundaryViolationError
from app.psi.leakage_ledger import (
    CollaborationRoundSummary,
    LeakageSessionEvent,
    PrivacyLeakageLedger,
)
from app.psi.transport import BankMessageEndpoint


@dataclass(frozen=True)
class PairwiseSessionSummary:
    """Summary of observable metadata for a bidirectional pairwise PSI exchange between two banks."""
    pair_id: str
    bank_a_id: str
    bank_b_id: str
    session_a_to_b: LeakageSessionEvent
    session_b_to_a: LeakageSessionEvent
    bank_a_revealed_matches: int
    bank_b_revealed_matches: int
    total_wire_bytes: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class PSICollaborationCoordinator:
    """Coordinates privacy-preserving collaborative rounds across financial institutions."""

    def __init__(
        self,
        leakage_ledger: Optional[PrivacyLeakageLedger] = None,
        default_fpr: float = 0.001,
        default_data_structure: psi.DataStructure = psi.DataStructure.RAW,
    ):
        self.ledger = leakage_ledger or PrivacyLeakageLedger()
        self.default_fpr = default_fpr
        self.default_data_structure = default_data_structure
        self._seen_round_ids: Set[str] = set()

    def execute_directional_session(
        self,
        round_id: str,
        session_id: str,
        server_endpoint: BankMessageEndpoint,
        client_endpoint: BankMessageEndpoint,
        fpr: Optional[float] = None,
        data_structure: Optional[psi.DataStructure] = None,
        expansion_hops: int = 1,
    ) -> LeakageSessionEvent:
        """Executes a single directional PSI session by relaying opaque protobuf messages between endpoints.

        Notice: The coordinator inspects only message byte lengths, participant IDs, and the
        match count reported by the client for audit telemetry. Member-level tokens and graphs
        are never handled by the coordinator.
        """
        if not isinstance(server_endpoint, BankMessageEndpoint) or not isinstance(client_endpoint, BankMessageEndpoint):
            raise DataBoundaryViolationError(
                "Participants must implement BankMessageEndpoint (e.g. agent.get_message_endpoint() or IPCBankMessageEndpoint). "
                "Passing complete OperationalBankAgent instances, graph objects, or raw token dictionaries is strictly prohibited."
            )

        t_start = time.perf_counter()
        ds = data_structure or self.default_data_structure
        ds_name = "RAW" if ds == psi.DataStructure.RAW else "GCS"
        fpr_val = fpr if fpr is not None else self.default_fpr

        server_id = server_endpoint.bank_id
        client_id = client_endpoint.bank_id

        try:
            # 1. Ask Server Endpoint to create ServerSetup bytes from its own local tokens
            client_count = client_endpoint.get_candidate_token_count()
            setup_bytes = server_endpoint.generate_server_setup(
                session_id=session_id,
                client_token_count=client_count,
                fpr=fpr_val,
                data_structure=ds,
            )

            # 2. Ask Client Endpoint to create Request bytes from its own local tokens
            req_bytes = client_endpoint.generate_client_request(session_id=session_id)

            # 3. Relay Request bytes to Server Endpoint to get Response bytes
            resp_bytes = server_endpoint.process_client_request(
                session_id=session_id,
                request_bytes=req_bytes,
            )

            # 4. Relay (Setup bytes, Response bytes) to Client Endpoint
            # Client agent decrypts indices, resolves to tokens in local memory,
            # and performs local graph expansion privately.
            match_count = client_endpoint.process_server_response(
                session_id=session_id,
                setup_bytes=setup_bytes,
                response_bytes=resp_bytes,
                hops=expansion_hops,
            )

            setup_len = len(setup_bytes)
            req_len = len(req_bytes)
            resp_len = len(resp_bytes)
            total_wire = setup_len + req_len + resp_len
            t_ms = round((time.perf_counter() - t_start) * 1000.0, 2)

            event = LeakageSessionEvent(
                session_id=session_id,
                round_id=round_id,
                server_bank_id=server_id,
                client_bank_id=client_id,
                protocol_family="Diffie-Hellman-ECC-PSI",
                data_structure=ds_name,
                fpr_parameter=fpr_val if ds_name == "GCS" else 0.0,
                server_set_size=server_endpoint.get_candidate_token_count(),
                client_set_size=client_endpoint.get_candidate_token_count(),
                server_setup_bytes=setup_len,
                client_request_bytes=req_len,
                server_response_bytes=resp_len,
                total_wire_bytes=total_wire,
                client_revealed_cardinality=match_count,
                recipient_of_output=client_id,
                status="SUCCESS",
                timestamp=datetime.utcnow().isoformat(),
                execution_time_ms=t_ms,
            )
            self.ledger.record_session(event)
            return event

        except Exception as e:
            t_ms = round((time.perf_counter() - t_start) * 1000.0, 2)
            event = LeakageSessionEvent(
                session_id=session_id,
                round_id=round_id,
                server_bank_id=server_id,
                client_bank_id=client_id,
                protocol_family="Diffie-Hellman-ECC-PSI",
                data_structure=ds_name,
                fpr_parameter=fpr_val,
                server_set_size=0,
                client_set_size=0,
                server_setup_bytes=0,
                client_request_bytes=0,
                server_response_bytes=0,
                total_wire_bytes=0,
                client_revealed_cardinality=0,
                recipient_of_output="NONE",
                status="FAILED",
                timestamp=datetime.utcnow().isoformat(),
                execution_time_ms=t_ms,
                error_message=str(e),
            )
            self.ledger.record_session(event)
            raise e

    def execute_pairwise_round(
        self,
        round_id: str,
        endpoint_a: BankMessageEndpoint,
        endpoint_b: BankMessageEndpoint,
        fpr: Optional[float] = None,
        data_structure: Optional[psi.DataStructure] = None,
        expansion_hops: int = 1,
        **kwargs,
    ) -> PairwiseSessionSummary:
        """Executes an authorized bidirectional PSI exchange between two participant endpoints."""
        if (
            isinstance(endpoint_a, dict)
            or isinstance(endpoint_b, dict)
            or not isinstance(endpoint_a, BankMessageEndpoint)
            or not isinstance(endpoint_b, BankMessageEndpoint)
            or "bank_a_tokens" in kwargs
            or "bank_b_tokens" in kwargs
            or "bank_a_graph" in kwargs
            or "bank_b_graph" in kwargs
        ):
            raise DataBoundaryViolationError(
                "Participants must implement BankMessageEndpoint (e.g. agent.get_message_endpoint() or IPCBankMessageEndpoint). "
                "Passing complete OperationalBankAgent instances, graph objects, or raw token dictionaries is strictly prohibited."
            )

        pair_id = f"{endpoint_a.bank_id}_{endpoint_b.bank_id}"

        # Leg 1: Endpoint A is Server, Endpoint B is Client. Endpoint B learns matches.
        session_id_1 = f"{round_id}_{endpoint_a.bank_id}_to_{endpoint_b.bank_id}"
        event_1 = self.execute_directional_session(
            round_id=round_id,
            session_id=session_id_1,
            server_endpoint=endpoint_a,
            client_endpoint=endpoint_b,
            fpr=fpr,
            data_structure=data_structure,
            expansion_hops=expansion_hops,
        )

        # Leg 2: Endpoint B is Server, Endpoint A is Client. Endpoint A learns matches.
        session_id_2 = f"{round_id}_{endpoint_b.bank_id}_to_{endpoint_a.bank_id}"
        event_2 = self.execute_directional_session(
            round_id=round_id,
            session_id=session_id_2,
            server_endpoint=endpoint_b,
            client_endpoint=endpoint_a,
            fpr=fpr,
            data_structure=data_structure,
            expansion_hops=expansion_hops,
        )

        total_wire = event_1.total_wire_bytes + event_2.total_wire_bytes

        return PairwiseSessionSummary(
            pair_id=pair_id,
            bank_a_id=endpoint_a.bank_id,
            bank_b_id=endpoint_b.bank_id,
            session_a_to_b=event_1,
            session_b_to_a=event_2,
            bank_a_revealed_matches=event_2.client_revealed_cardinality,
            bank_b_revealed_matches=event_1.client_revealed_cardinality,
            total_wire_bytes=total_wire,
        )

    def execute_collaboration_round(
        self,
        endpoints: Any = None,
        round_id: Optional[str] = None,
        fpr: Optional[float] = None,
        data_structure: Optional[psi.DataStructure] = None,
        expansion_hops: int = 1,
        **kwargs,
    ) -> CollaborationRoundSummary:
        """Orchestrates an authorized multi-bank collaboration round across all pairs of bank endpoints.

        Architectural Guardrails:
        - Rejects any central dictionaries of graphs or raw token sets.
        - Rejects complete OperationalBankAgent instances.
        - Relays messages exclusively between narrow BankMessageEndpoint implementations.
        - Returns observable aggregate metadata and ledger summary.
        - Member-level investigation leads remain inside each bank agent/process.
        """
        # Strict boundary check against centralized dictionaries
        if (
            isinstance(endpoints, dict)
            or "bank_tokens_map" in kwargs
            or "bank_graphs_map" in kwargs
        ):
            raise DataBoundaryViolationError(
                "Passing a dictionary of bank graphs or tokens into execute_collaboration_round is strictly prohibited. "
                "Pass a sequence of BankMessageEndpoint instances (e.g. agent.get_message_endpoint() or IPCBankMessageEndpoint)."
            )

        if not isinstance(endpoints, (list, tuple)) or len(endpoints) < 2:
            raise ValueError(f"Collaboration round requires a list of at least 2 bank message endpoints, got {endpoints}")

        for idx, ep in enumerate(endpoints):
            if not isinstance(ep, BankMessageEndpoint):
                raise DataBoundaryViolationError(
                    f"Element at index {idx} is of type '{type(ep).__name__}'. "
                    "Participants must implement BankMessageEndpoint (e.g. agent.get_message_endpoint() or IPCBankMessageEndpoint). "
                    "Passing complete OperationalBankAgent instances, graphs, or token collections into the coordinator is strictly prohibited."
                )

        r_id = round_id or f"ROUND_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex[:8]}"
        if r_id in self._seen_round_ids:
            raise ValueError(f"Round ID '{r_id}' has already been processed (duplicate round error).")
        self._seen_round_ids.add(r_id)

        # Generate all unique pairs of endpoints
        n = len(endpoints)
        for i in range(n):
            for j in range(i + 1, n):
                ep_a = endpoints[i]
                ep_b = endpoints[j]
                self.execute_pairwise_round(
                    round_id=r_id,
                    endpoint_a=ep_a,
                    endpoint_b=ep_b,
                    fpr=fpr,
                    data_structure=data_structure,
                    expansion_hops=expansion_hops,
                )

        # Retrieve observable audit summary from Privacy Leakage Ledger
        return self.ledger.get_round_summary(r_id)
