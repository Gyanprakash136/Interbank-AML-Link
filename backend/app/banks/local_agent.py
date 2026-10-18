"""SignalMesh Bank Operational Agent.

Encapsulates an isolated, single-institution agent representing Bank A, Bank B, or Bank C.

SECURITY & BOUNDARY ARCHITECTURE:
1. Local Data Ownership:
   The agent owns its local raw transactions, account graphs, rule detection engine,
   candidate tokens, and PSI cryptographic keys.
2. Local Graph Expansion:
   The bank agent performs matched-seed graph expansion strictly inside its own memory
   against its own local graph. Graph structures and member-level match results are
   NEVER sent to the coordinator or other banks.
3. Wire Protocol Interface:
   The agent communicates across the collaboration network strictly via serialized
   protobuf bytes (ServerSetup, Request, Response).
4. Simulation Notice:
   In this single-process simulation, separation is enforced by class-level encapsulation
   and boundary guards. In production deployment, each agent runs in an isolated container/process.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set
import networkx as nx
import pandas as pd

from app.core.config import DataBoundaryViolationError, settings
from app.core.security import assert_no_ground_truth_contamination, assert_opaque_tokens
from app.graph.graph_builder import LocalGraphBuilder
from app.graph.graph_expansion import LocalInvestigationLead, MatchedSeedGraphExpander
from app.banks.local_detection import LocalRuleDetectionEngine
from app.psi.protocol import PSIClient, PSIServer, require_psi
from app.psi.transport import InProcessBankMessageEndpoint


class OperationalBankAgent:
    """Represents an isolated operational agent for a single bank."""

    def __init__(self, bank_id: str, data_dir: Path | None = None):
        self.bank_id = bank_id.lower().strip()
        base_dir = data_dir or settings.data_dir
        self.bank_dir = (base_dir / self.bank_id).resolve()
        
        # Verify valid bank identity
        if self.bank_id not in ("bank_a", "bank_b", "bank_c"):
            raise ValueError(f"Invalid bank_id: '{self.bank_id}'. Must be 'bank_a', 'bank_b', or 'bank_c'.")

        # In-memory local state (CONFIDENTIAL TO THIS BANK)
        self._graph: Optional[nx.MultiDiGraph] = None
        self._candidate_tokens: List[str] = []
        self._matched_tokens: Set[str] = set()
        self._local_leads: List[LocalInvestigationLead] = []
        self._active_servers: Dict[str, PSIServer] = {}
        self._active_clients: Dict[str, PSIClient] = {}

    def _verify_boundary(self, target_path: Path) -> Path:
        """Ensures the target path is strictly within the agent's authorized bank directory."""
        resolved = target_path.resolve()
        
        # Explicit check against evaluation directory
        if "evaluation" in resolved.parts or "ground_truth" in resolved.name.lower():
            raise DataBoundaryViolationError(
                f"Bank agent '{self.bank_id}' attempted to access evaluation ground-truth: {resolved}. "
                "Ground truth is strictly isolated from operational agents."
            )

        # Explicit check against other banks' directories
        for other_bank in ("bank_a", "bank_b", "bank_c"):
            if other_bank != self.bank_id and other_bank in resolved.parts:
                raise DataBoundaryViolationError(
                    f"Bank agent '{self.bank_id}' attempted to access unauthorized bank directory: {resolved}. "
                    "Cross-bank direct data access is strictly prohibited."
                )

        # Must reside inside the bank's directory
        try:
            resolved.relative_to(self.bank_dir)
        except ValueError:
            raise DataBoundaryViolationError(
                f"Path {resolved} is outside the authorized directory for bank '{self.bank_id}' ({self.bank_dir})."
            )
        return resolved

    def load_local_transactions(self) -> pd.DataFrame:
        """Loads bank-local transactions and validates the absence of ground truth labels."""
        tx_path = self._verify_boundary(self.bank_dir / "transactions.csv")
        if not tx_path.exists():
            raise FileNotFoundError(f"Local transactions file not found at {tx_path}")

        df = pd.read_csv(tx_path)
        assert_no_ground_truth_contamination(df.columns, f"{self.bank_id} transactions")
        return df

    def load_local_entities(self) -> pd.DataFrame:
        """Loads local entity metadata (account to canonical token mapping)."""
        ent_path = self._verify_boundary(self.bank_dir / "local_entities.csv")
        if not ent_path.exists():
            raise FileNotFoundError(f"Local entities file not found at {ent_path}")

        df = pd.read_csv(ent_path)
        assert_no_ground_truth_contamination(df.columns, f"{self.bank_id} entities")
        return df

    def get_canonical_tokens(self) -> List[str]:
        """Extracts the unique list of canonical synthetic entity tokens for PSI matching."""
        df = self.load_local_entities()
        if "canonical_token" not in df.columns:
            raise ValueError(f"local_entities.csv for {self.bank_id} missing 'canonical_token' column.")
        tokens = sorted(df["canonical_token"].dropna().unique().tolist())
        assert_opaque_tokens(tokens)
        return tokens

    def get_account_for_token(self, canonical_token: str) -> Optional[str]:
        """Resolves a canonical token to a local bank account within the bank's internal memory."""
        df = self.load_local_entities()
        match = df[df["canonical_token"] == canonical_token]
        if match.empty:
            return None
        return str(match.iloc[0]["local_account_id"])

    # ─────────────────────────────────────────────────────────────────────────
    # LOCAL GRAPH & SUSPICIOUS CANDIDATE PREPARATION (BANK-LOCAL ONLY)
    # ─────────────────────────────────────────────────────────────────────────

    def build_local_graph(self) -> nx.MultiDiGraph:
        """Builds and caches the bank's local transaction graph in local memory."""
        tx_df = self.load_local_transactions()
        ent_df = self.load_local_entities()
        self._graph = LocalGraphBuilder(self.bank_id, tx_df, ent_df).build()
        return self._graph

    def set_local_graph(self, graph: nx.MultiDiGraph) -> None:
        """Sets the in-memory local graph directly (useful for tests or custom graph construction)."""
        self._graph = graph

    def get_local_graph(self) -> nx.MultiDiGraph:
        """Returns the in-memory local graph, building it if not yet loaded."""
        if self._graph is None:
            try:
                self.build_local_graph()
            except FileNotFoundError:
                self._graph = nx.MultiDiGraph()
        return self._graph

    def prepare_candidate_tokens(
        self,
        suspicion_threshold: float = 0.45,
        custom_candidate_tokens: Optional[Sequence[str]] = None,
    ) -> int:
        """Evaluates local rules and stores approved candidate tokens in local memory.

        Returns only the COUNT of candidate tokens for audit preparation.
        """
        if custom_candidate_tokens is not None:
            assert_opaque_tokens(custom_candidate_tokens)
            self._candidate_tokens = sorted(set(custom_candidate_tokens))
            return len(self._candidate_tokens)

        G = self.get_local_graph()
        engine = LocalRuleDetectionEngine(suspicion_threshold=suspicion_threshold)
        tokens = engine.get_eligible_psi_tokens(G)
        assert_opaque_tokens(tokens)
        self._candidate_tokens = tokens
        return len(self._candidate_tokens)

    def get_candidate_token_count(self) -> int:
        """Returns the count of prepared candidate tokens."""
        return len(self._candidate_tokens)

    # ─────────────────────────────────────────────────────────────────────────
    # PSI PROTOCOL WIRE MESSAGE HANDLERS (EXCHANGES OPAQUE PROTOBUFS ONLY)
    # ─────────────────────────────────────────────────────────────────────────

    def generate_server_setup(
        self,
        session_id: str,
        client_token_count: int,
        fpr: float = 0.001,
        data_structure: Any = None,
    ) -> bytes:
        """[SERVER ROLE] Creates setup message from local candidate tokens. Returns wire bytes."""
        _psi = require_psi("generate_server_setup")
        if not self._candidate_tokens:
            self.prepare_candidate_tokens()

        server = PSIServer(reveal_intersection=True)
        self._active_servers[session_id] = server

        ds = data_structure if data_structure is not None else _psi.DataStructure.RAW
        setup_msg = server.create_setup_message(
            inputs=self._candidate_tokens,
            fpr=fpr,
            num_client_inputs=max(1, client_token_count),
            data_structure=ds,
        )
        return setup_msg.SerializeToString()

    def process_client_request(self, session_id: str, request_bytes: bytes) -> bytes:
        """[SERVER ROLE] Processes encrypted client request. Returns response wire bytes."""
        _psi = require_psi("process_client_request")
        server = self._active_servers.get(session_id)
        if server is None:
            raise KeyError(f"No active server session for ID '{session_id}' in bank '{self.bank_id}'.")

        req = _psi.Request()
        req.ParseFromString(request_bytes)
        resp = server.process_request(req)
        return resp.SerializeToString()

    def generate_client_request(self, session_id: str) -> bytes:
        """[CLIENT ROLE] Creates encrypted blinded request from local candidate tokens. Returns wire bytes."""
        require_psi("generate_client_request")
        if not self._candidate_tokens:
            self.prepare_candidate_tokens()

        client = PSIClient(reveal_intersection=True)
        self._active_clients[session_id] = client

        req_msg = client.create_request(self._candidate_tokens)
        return req_msg.SerializeToString()

    def process_server_response(
        self,
        session_id: str,
        setup_bytes: bytes,
        response_bytes: bytes,
        hops: int = 1,
    ) -> int:
        """[CLIENT ROLE] Decrypts matched indices, resolves locally, and expands local graph.

        Privacy & Boundary Enforcement:
        - Decrypted indices are resolved to tokens strictly within the client agent's memory.
        - Graph expansion is performed locally on self.get_local_graph().
        - Results are stored in self._local_leads.
        - Returns ONLY the match count (cardinality) to the coordinator.
        """
        _psi = require_psi("process_server_response")
        client = self._active_clients.get(session_id)
        if client is None:
            raise KeyError(f"No active client session for ID '{session_id}' in bank '{self.bank_id}'.")

        setup_msg = _psi.ServerSetup()
        setup_msg.ParseFromString(setup_bytes)

        resp_msg = _psi.Response()
        resp_msg.ParseFromString(response_bytes)

        # Resolves matching indices back to tokens from local memory
        matched_tokens = client.get_intersection_items(setup_msg, resp_msg, self._candidate_tokens)
        self._matched_tokens.update(matched_tokens)

        # Perform local graph expansion strictly within this bank agent's own memory
        G = self.get_local_graph()
        expander = MatchedSeedGraphExpander()
        for token in matched_tokens:
            lead = expander.expand_neighborhood(G, token, hops=hops)
            if lead is not None:
                self._local_leads.append(lead)

        return len(matched_tokens)

    def get_matched_tokens(self) -> List[str]:
        """Returns the list of locally matched candidate tokens discovered across all client sessions."""
        return sorted(self._matched_tokens)

    def get_local_investigation_leads(self) -> List[LocalInvestigationLead]:
        """Returns the local investigation leads generated during collaboration rounds."""
        return list(self._local_leads)

    def clear_local_investigation_leads(self) -> None:
        """Clears local investigation leads and matched tokens."""
        self._local_leads.clear()
        self._matched_tokens.clear()

    def get_message_endpoint(self) -> InProcessBankMessageEndpoint:
        """Returns a narrow serialized-message transport endpoint for this bank agent.

        Exposes ONLY wire protocol methods (ServerSetup, Request, Response bytes)
        and candidate token count via callable closures. The returned endpoint
        does NOT retain direct references to local graph or token objects.
        """
        return InProcessBankMessageEndpoint(
            bank_id=self.bank_id,
            token_count_fn=self.get_candidate_token_count,
            setup_fn=self.generate_server_setup,
            process_req_fn=self.process_client_request,
            request_fn=self.generate_client_request,
            process_resp_fn=self.process_server_response,
        )
