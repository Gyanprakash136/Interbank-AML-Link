"""SignalMesh PSI Collaboration Transport Interfaces.

Defines the narrow, serialized-message transport interfaces for inter-bank collaboration.

CRITICAL ARCHITECTURAL CONSTRAINTS:
1. Zero Complete Agent Passing:
   The coordinator NEVER accepts complete OperationalBankAgent instances, local graphs,
   or raw token collections.
2. Narrow Message Interface:
   Participants expose only primitive wire-message methods exchanging serialized bytes
   (ServerSetup, Request, Response protobufs) and scalar counts.
3. Logical Simulation vs OS Isolation:
   - InProcessBankMessageEndpoint: Used for fast single-process simulation. This is an
     application-level logical simulation, NOT an enforced security boundary.
   - IPCBankMessageEndpoint: Used for true multi-process isolation where agents run in
     independent OS processes (different PIDs) communicating via IPC message queues.
"""

from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, List, Optional
import multiprocessing as mp
import os

from app.core.config import DataBoundaryViolationError


class BankMessageEndpoint(ABC):
    """Abstract interface exposing strictly the wire-message transport for Private Set Intersection.

    The coordinator interacts exclusively with this interface. The coordinator does not receive
    local graphs, candidate tokens, or complete bank agent objects.
    """

    @property
    @abstractmethod
    def bank_id(self) -> str:
        """The identifier of the participating bank."""
        pass

    @abstractmethod
    def get_candidate_token_count(self) -> int:
        """Returns the number of candidate tokens prepared by this bank."""
        pass

    @abstractmethod
    def generate_server_setup(
        self,
        session_id: str,
        client_token_count: int,
        fpr: float = 0.001,
        data_structure: Any = None,
    ) -> bytes:
        """Generates the encrypted server setup message. Returns serialized wire bytes."""
        pass

    @abstractmethod
    def process_client_request(self, session_id: str, request_bytes: bytes) -> bytes:
        """Processes an encrypted client request. Returns serialized response wire bytes."""
        pass

    @abstractmethod
    def generate_client_request(self, session_id: str) -> bytes:
        """Generates an encrypted blinded client request. Returns serialized wire bytes."""
        pass

    @abstractmethod
    def process_server_response(
        self,
        session_id: str,
        setup_bytes: bytes,
        response_bytes: bytes,
        hops: int = 1,
    ) -> int:
        """Processes the server response inside the client agent's memory.

        Performs local match resolution and local graph expansion.
        Returns ONLY the match count (cardinality) to the caller.
        """
        pass


class InProcessBankMessageEndpoint(BankMessageEndpoint):
    """In-process simulation endpoint.

    SECURITY NOTICE:
    This endpoint is used for fast local testing and simulation within a single Python interpreter.
    It does NOT provide operating-system or hardware process isolation. It uses closures to
    expose only wire-protocol methods, preventing direct reference retention of bank-agent objects.
    """

    def __init__(
        self,
        bank_id: str,
        token_count_fn: Callable[[], int],
        setup_fn: Callable[[str, int, float, Any], bytes],
        process_req_fn: Callable[[str, bytes], bytes],
        request_fn: Callable[[str], bytes],
        process_resp_fn: Callable[[str, bytes, bytes, int], int],
    ):
        self._bank_id = bank_id
        self._token_count_fn = token_count_fn
        self._setup_fn = setup_fn
        self._process_req_fn = process_req_fn
        self._request_fn = request_fn
        self._process_resp_fn = process_resp_fn

    @property
    def bank_id(self) -> str:
        return self._bank_id

    def get_candidate_token_count(self) -> int:
        return self._token_count_fn()

    def generate_server_setup(
        self,
        session_id: str,
        client_token_count: int,
        fpr: float = 0.001,
        data_structure: Any = None,
    ) -> bytes:
        return self._setup_fn(session_id, client_token_count, fpr, data_structure)

    def process_client_request(self, session_id: str, request_bytes: bytes) -> bytes:
        return self._process_req_fn(session_id, request_bytes)

    def generate_client_request(self, session_id: str) -> bytes:
        return self._request_fn(session_id)

    def process_server_response(
        self,
        session_id: str,
        setup_bytes: bytes,
        response_bytes: bytes,
        hops: int = 1,
    ) -> int:
        return self._process_resp_fn(session_id, setup_bytes, response_bytes, hops)


class IPCBankMessageEndpoint(BankMessageEndpoint):
    """Operating-system process-isolated endpoint communicating via IPC queues.

    SECURITY NOTICE:
    This endpoint enforces true OS process isolation. The bank agent executes in a separate
    OS process (independent PID and memory address space). Only serialized protocol bytes
    and scalar parameters cross the inter-process boundary.
    """

    def __init__(
        self,
        bank_id: str,
        req_queue: mp.Queue,
        resp_queue: mp.Queue,
        timeout: float = 20.0,
    ):
        self._bank_id = bank_id
        self._req_queue = req_queue
        self._resp_queue = resp_queue
        self._timeout = timeout

    @property
    def bank_id(self) -> str:
        return self._bank_id

    def get_candidate_token_count(self) -> int:
        self._req_queue.put(("GET_TOKEN_COUNT",))
        tag, count = self._resp_queue.get(timeout=self._timeout)
        if tag == "ERROR":
            raise RuntimeError(f"Error in remote bank process {self._bank_id}: {count}")
        return count

    def generate_server_setup(
        self,
        session_id: str,
        client_token_count: int,
        fpr: float = 0.001,
        data_structure: Any = None,
    ) -> bytes:
        ds_raw = True
        if data_structure is not None:
            if isinstance(data_structure, str):
                ds_raw = (data_structure.upper() == "RAW")
            elif hasattr(data_structure, "name"):
                ds_raw = (data_structure.name == "RAW")
            else:
                from app.psi.protocol import require_psi
                _psi = require_psi("generate_server_setup")
                ds_raw = (data_structure == _psi.DataStructure.RAW)
        self._req_queue.put(("GENERATE_SERVER_SETUP", session_id, client_token_count, fpr, ds_raw))
        tag, data = self._resp_queue.get(timeout=self._timeout)
        if tag == "ERROR":
            raise RuntimeError(f"Error in remote bank process {self._bank_id}: {data}")
        return data

    def process_client_request(self, session_id: str, request_bytes: bytes) -> bytes:
        self._req_queue.put(("PROCESS_CLIENT_REQUEST", session_id, request_bytes))
        tag, data = self._resp_queue.get(timeout=self._timeout)
        if tag == "ERROR":
            raise RuntimeError(f"Error in remote bank process {self._bank_id}: {data}")
        return data

    def generate_client_request(self, session_id: str) -> bytes:
        self._req_queue.put(("GENERATE_CLIENT_REQUEST", session_id))
        tag, data = self._resp_queue.get(timeout=self._timeout)
        if tag == "ERROR":
            raise RuntimeError(f"Error in remote bank process {self._bank_id}: {data}")
        return data

    def process_server_response(
        self,
        session_id: str,
        setup_bytes: bytes,
        response_bytes: bytes,
        hops: int = 1,
    ) -> int:
        self._req_queue.put(("PROCESS_SERVER_RESPONSE", session_id, setup_bytes, response_bytes, hops))
        tag, match_count = self._resp_queue.get(timeout=self._timeout)
        if tag == "ERROR":
            raise RuntimeError(f"Error in remote bank process {self._bank_id}: {match_count}")
        return match_count


def run_ipc_bank_worker(
    agent_factory: Callable[[], Any],
    req_queue: mp.Queue,
    resp_queue: mp.Queue,
):
    """Worker loop for a bank agent running in a dedicated OS process.

    Instantiates and executes the bank agent in its own isolated memory space.
    Communicates strictly via IPC Queues.
    """
    try:
        agent = agent_factory()
    except Exception as e:
        resp_queue.put(("ERROR", f"Failed to initialize agent: {e}"))
        return

    while True:
        try:
            msg = req_queue.get()
            if msg is None or msg[0] == "STOP":
                break

            cmd = msg[0]
            if cmd == "GET_TOKEN_COUNT":
                cnt = agent.get_candidate_token_count()
                resp_queue.put(("COUNT", cnt))
            elif cmd == "GENERATE_SERVER_SETUP":
                _, session_id, client_token_count, fpr, ds_raw = msg
                from app.psi.protocol import require_psi
                _psi = require_psi("GENERATE_SERVER_SETUP")
                ds = _psi.DataStructure.RAW if ds_raw else _psi.DataStructure.GCS
                setup_bytes = agent.generate_server_setup(session_id, client_token_count, fpr, ds)
                resp_queue.put(("SETUP_BYTES", setup_bytes))
            elif cmd == "GENERATE_CLIENT_REQUEST":
                _, session_id = msg
                req_bytes = agent.generate_client_request(session_id)
                resp_queue.put(("REQUEST_BYTES", req_bytes))
            elif cmd == "PROCESS_CLIENT_REQUEST":
                _, session_id, req_bytes = msg
                resp_bytes = agent.process_client_request(session_id, req_bytes)
                resp_queue.put(("RESPONSE_BYTES", resp_bytes))
            elif cmd == "PROCESS_SERVER_RESPONSE":
                _, session_id, setup_bytes, resp_bytes, hops = msg
                match_count = agent.process_server_response(session_id, setup_bytes, resp_bytes, hops)
                resp_queue.put(("MATCH_COUNT", match_count))
            elif cmd == "GET_LEADS_COUNT":
                cnt = len(agent.get_local_investigation_leads())
                resp_queue.put(("LEADS_COUNT", cnt))
            elif cmd == "GET_LEADS":
                leads = [lead.to_dict() for lead in agent.get_local_investigation_leads()]
                resp_queue.put(("LEADS", leads))
            elif cmd == "GET_MATCHED_TOKENS":
                tokens = agent.get_matched_tokens()
                resp_queue.put(("MATCHED_TOKENS", tokens))
            elif cmd == "GET_PID":
                resp_queue.put(("PID", os.getpid()))
            else:
                resp_queue.put(("ERROR", f"Unknown command: {cmd}"))
        except Exception as e:
            resp_queue.put(("ERROR", str(e)))
