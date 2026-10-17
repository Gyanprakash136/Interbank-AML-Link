"""SignalMesh Private Set Intersection (PSI) Protocol Wrapper.

Wraps OpenMined PSI (v2.0.6) with explicit semantics, boundary enforcement,
and bidirectional exchange orchestration.

Privacy Guarantees Enforced:
1. Pure Token Sets Only: Only canonical string tokens are permitted as inputs.
   Raw transaction rows, amounts, timestamps, and account graphs are strictly prohibited.
2. Asymmetric Revelation:
   - In a one-way PSI session, only the Client learns the intersection indices.
   - The Server learns zero information about which elements matched.
3. Bidirectional Exchange:
   - Conducted as two independent complementary PSI sessions.
   - Bank A learns strictly the subset of Bank A's tokens that exist in Bank B.
   - Bank B learns strictly the subset of Bank B's tokens that exist in Bank A.
   - Neither bank learns non-matching tokens of the counterparty.
"""

from dataclasses import dataclass
from typing import List, Sequence, Set, Any
import private_set_intersection.python as psi


class PSIProtocolError(Exception):
    """Raised when PSI protocol execution fails or constraints are violated."""
    pass


class PSIBoundaryError(TypeError):
    """Raised when non-token data (e.g. transaction rows or dicts) is passed to PSI."""
    pass


def _validate_token_inputs(items: Sequence[str]) -> List[str]:
    """Validates that inputs are strict string tokens and not complex data structures."""
    if not isinstance(items, (list, tuple, set)):
        raise PSIBoundaryError(f"Inputs must be a list of string tokens, got {type(items).__name__}")
    
    validated = []
    for idx, item in enumerate(items):
        if not isinstance(item, str):
            raise PSIBoundaryError(
                f"Element at index {idx} is of type {type(item).__name__}. "
                "PSI inputs must be pure string tokens."
            )
        # Check that caller didn't accidentally stringify a JSON or row dict
        s = item.strip()
        if (s.startswith("{") and s.endswith("}")) or ("amount" in s.lower() and "account" in s.lower()):
            raise PSIBoundaryError(
                f"Element at index {idx} appears to be a raw transaction or object dump, "
                "not a canonical entity token."
            )
        validated.append(s)
    return validated


class PSIServer:
    """Wraps the OpenMined PSI Server."""

    def __init__(self, reveal_intersection: bool = True, key_bytes: bytes | None = None):
        self.reveal_intersection = reveal_intersection
        if key_bytes is not None:
            self._server = psi.server.CreateFromKey(key_bytes, reveal_intersection)
        else:
            self._server = psi.server.CreateWithNewKey(reveal_intersection)

    def get_private_key_bytes(self) -> bytes:
        """Returns the serialized private key bytes."""
        return self._server.GetPrivateKeyBytes()

    def create_setup_message(
        self,
        inputs: Sequence[str],
        fpr: float = 0.001,
        num_client_inputs: int | None = None,
        data_structure: psi.DataStructure | None = None,
    ) -> psi.ServerSetup:
        """Creates the setup message containing the encrypted server dataset."""
        validated = _validate_token_inputs(inputs)
        client_count = num_client_inputs if num_client_inputs is not None else len(validated)
        ds = data_structure if data_structure is not None else psi.DataStructure.GCS
        return self._server.CreateSetupMessage(
            fpr=fpr,
            num_client_inputs=max(1, client_count),
            inputs=validated,
            ds=ds,
        )

    def process_request(self, request: psi.Request) -> psi.Response:
        """Processes an encrypted client request and returns the encrypted response."""
        if not isinstance(request, psi.Request):
            raise PSIProtocolError("Request must be a psi.Request protobuf message")
        return self._server.ProcessRequest(request)


class PSIClient:
    """Wraps the OpenMined PSI Client."""

    def __init__(self, reveal_intersection: bool = True, key_bytes: bytes | None = None):
        self.reveal_intersection = reveal_intersection
        if key_bytes is not None:
            self._client = psi.client.CreateFromKey(key_bytes, reveal_intersection)
        else:
            self._client = psi.client.CreateWithNewKey(reveal_intersection)
        self._last_inputs: List[str] = []

    def get_private_key_bytes(self) -> bytes:
        """Returns the serialized private key bytes."""
        return self._client.GetPrivateKeyBytes()

    def create_request(self, inputs: Sequence[str]) -> psi.Request:
        """Creates an encrypted client request for a list of tokens."""
        validated = _validate_token_inputs(inputs)
        self._last_inputs = list(validated)
        return self._client.CreateRequest(validated)

    def get_intersection_indices(
        self,
        setup: psi.ServerSetup,
        response: psi.Response,
    ) -> List[int]:
        """Returns the indices into client inputs that match the server dataset.

        NOTE: OpenMined PSI's GetIntersection returns integer indices into the client set,
        NOT string elements!
        """
        if not self.reveal_intersection:
            raise PSIProtocolError("Cannot call get_intersection_indices when reveal_intersection is False")
        indices = self._client.GetIntersection(setup, response)
        return sorted(indices)

    def get_intersection_items(
        self,
        setup: psi.ServerSetup,
        response: psi.Response,
        inputs: Sequence[str] | None = None,
    ) -> List[str]:
        """Resolves matched indices back to client tokens in client-local memory."""
        client_inputs = list(inputs) if inputs is not None else self._last_inputs
        if not client_inputs:
            raise PSIProtocolError("No client inputs provided or cached to resolve indices.")
        indices = self.get_intersection_indices(setup, response)
        return [client_inputs[i] for i in indices]

    def get_intersection_size(
        self,
        setup: psi.ServerSetup,
        response: psi.Response,
    ) -> int:
        """Returns only the cardinality (count) of matching items."""
        return self._client.GetIntersectionSize(setup, response)


@dataclass(frozen=True)
class PSIBidirectionalResult:
    """Result of a two-way PSI exchange between Bank A and Bank B."""
    bank_a_id: str
    bank_b_id: str
    bank_a_matched_tokens: List[str]
    bank_b_matched_tokens: List[str]
    total_wire_bytes: int

    @property
    def matched_count(self) -> int:
        return len(self.bank_a_matched_tokens)


class PSIBidirectionalSession:
    """Orchestrates an authorized bidirectional PSI exchange between two banks.

    Because 2-party PSI is fundamentally asymmetric (only the client learns the result),
    a bidirectional match requires two complementary sessions:
    - Session 1: Bank A is Server, Bank B is Client. Bank B computes matches.
    - Session 2: Bank B is Server, Bank A is Client. Bank A computes matches.

    Each party learns ONLY the subset of its OWN tokens that intersect with the counterparty.
    No party ever receives non-matching tokens or raw customer identifiers.
    """

    def __init__(
        self,
        bank_a_id: str,
        bank_b_id: str,
        fpr: float = 0.001,
        data_structure: psi.DataStructure | None = None,
    ):
        self.bank_a_id = bank_a_id
        self.bank_b_id = bank_b_id
        self.fpr = fpr
        self.data_structure = data_structure or psi.DataStructure.GCS

    def execute(
        self,
        bank_a_tokens: Sequence[str],
        bank_b_tokens: Sequence[str],
    ) -> PSIBidirectionalResult:
        """Executes the two-way PSI protocol between Bank A and Bank B."""
        tokens_a = _validate_token_inputs(bank_a_tokens)
        tokens_b = _validate_token_inputs(bank_b_tokens)

        wire_bytes = 0

        # --- Leg 1: Bank A is Server, Bank B is Client ---
        server_a = PSIServer(reveal_intersection=True)
        client_b = PSIClient(reveal_intersection=True)

        setup_a = server_a.create_setup_message(
            inputs=tokens_a,
            fpr=self.fpr,
            num_client_inputs=len(tokens_b),
            data_structure=self.data_structure,
        )
        req_b = client_b.create_request(tokens_b)
        resp_a = server_a.process_request(req_b)

        wire_bytes += len(setup_a.SerializeToString())
        wire_bytes += len(req_b.SerializeToString())
        wire_bytes += len(resp_a.SerializeToString())

        # Bank B resolves its own matched tokens
        matched_b = client_b.get_intersection_items(setup_a, resp_a, tokens_b)

        # --- Leg 2: Bank B is Server, Bank A is Client ---
        server_b = PSIServer(reveal_intersection=True)
        client_a = PSIClient(reveal_intersection=True)

        setup_b = server_b.create_setup_message(
            inputs=tokens_b,
            fpr=self.fpr,
            num_client_inputs=len(tokens_a),
            data_structure=self.data_structure,
        )
        req_a = client_a.create_request(tokens_a)
        resp_b = server_b.process_request(req_a)

        wire_bytes += len(setup_b.SerializeToString())
        wire_bytes += len(req_a.SerializeToString())
        wire_bytes += len(resp_b.SerializeToString())

        # Bank A resolves its own matched tokens
        matched_a = client_a.get_intersection_items(setup_b, resp_b, tokens_a)

        return PSIBidirectionalResult(
            bank_a_id=self.bank_a_id,
            bank_b_id=self.bank_b_id,
            bank_a_matched_tokens=sorted(matched_a),
            bank_b_matched_tokens=sorted(matched_b),
            total_wire_bytes=wire_bytes,
        )
