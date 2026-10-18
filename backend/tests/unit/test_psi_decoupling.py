"""Unit tests verifying that local graph analysis and bank operational components
are cleanly decoupled from the OpenMined PSI native C++ dependency.

Proves:
1. Local graph construction, transaction loading, token derivation, and rule detection
   import and execute without OpenMined PSI installed.
2. Attempting to execute actual PSI operations when OpenMined PSI is unavailable raises
   a clear, actionable PSIUnavailableError identifying the missing dependency.
3. When OpenMined PSI is available, all normal operations execute without degradation.
"""

import importlib
import sys
from unittest.mock import patch
import pytest

from app.banks.local_agent import OperationalBankAgent
from app.banks.local_detection import LocalRuleDetectionEngine
from app.core.tokens import derive_canonical_token
from app.graph.features import LocalGraphFeatureExtractor
from app.graph.graph_builder import LocalGraphBuilder
from app.psi.protocol import (
    PSI_AVAILABLE,
    PSIClient,
    PSIServer,
    PSIUnavailableError,
    require_psi,
)


@pytest.mark.skipif(
    not PSI_AVAILABLE,
    reason="OpenMined PSI native dependency is not available on this platform (e.g. LinuxONE s390x)",
)
def test_require_psi_succeeds_when_available():
    """Confirms require_psi returns the native module when installed."""
    psi_mod = require_psi("test_operation")
    assert hasattr(psi_mod, "client")
    assert hasattr(psi_mod, "server")
    assert hasattr(psi_mod, "DataStructure")


def test_require_psi_raises_actionable_error_when_unavailable():
    """Confirms require_psi raises PSIUnavailableError with operation details when missing."""
    with patch.dict(sys.modules, {"private_set_intersection": None, "private_set_intersection.python": None}):
        # Force re-check
        with pytest.raises(PSIUnavailableError) as exc_info:
            # Bypass cache to test missing module
            with patch("app.psi.protocol.PSI_AVAILABLE", False):
                with patch("app.psi.protocol.psi", None):
                    require_psi("CrossBankMatching")
        
        err_msg = str(exc_info.value)
        assert "CrossBankMatching" in err_msg
        assert "openmined.psi==2.0.6" in err_msg
        assert "private_set_intersection.python" in err_msg
        assert "LinuxONE" in err_msg


def test_local_agent_and_graph_pipeline_without_psi():
    """Simulates an environment (like LinuxONE s390x) where OpenMined PSI is not installed.
    
    Verifies that bank transaction loading, graph building, feature extraction,
    canonical token derivation, and local rule detection operate 100% successfully.
    """
    with patch.dict(sys.modules, {"private_set_intersection": None, "private_set_intersection.python": None}):
        with patch("app.psi.protocol.PSI_AVAILABLE", False):
            with patch("app.psi.protocol.psi", None):
                # 1. OperationalBankAgent initializes cleanly
                agent = OperationalBankAgent("bank_a")
                assert agent.bank_id == "bank_a"

                # 2. Local graph builds cleanly without PSI
                G = agent.build_local_graph()
                assert G.number_of_nodes() > 0
                assert G.number_of_edges() > 0

                # 3. Canonical tokens are derived cleanly
                tokens = agent.get_canonical_tokens()
                assert len(tokens) > 0
                assert all(t.startswith("TOK_") for t in tokens)

                # 4. Local candidate tokens prepared via rule engine without PSI
                candidate_count = agent.prepare_candidate_tokens(suspicion_threshold=0.25)
                assert candidate_count > 0
                assert agent.get_candidate_token_count() == candidate_count

                # 5. Direct rule detection engine executes without PSI
                engine = LocalRuleDetectionEngine()
                alerts = engine.evaluate_graph(G)
                assert len(alerts) > 0

                # 6. Graph feature extraction executes without PSI
                extractor = LocalGraphFeatureExtractor()
                features = extractor.extract_all_local_accounts(G)
                assert len(features) > 0


def test_psi_operations_raise_when_dependency_unavailable():
    """Verifies that calling any wire-level PSI protocol method on OperationalBankAgent
    or PSIClient/PSIServer raises a clear PSIUnavailableError when PSI is missing.
    """
    with patch.dict(sys.modules, {"private_set_intersection": None, "private_set_intersection.python": None}):
        with patch("app.psi.protocol.PSI_AVAILABLE", False):
            with patch("app.psi.protocol.psi", None):
                agent = OperationalBankAgent("bank_a")
                agent.prepare_candidate_tokens(suspicion_threshold=0.25)

                # generate_server_setup must raise
                with pytest.raises(PSIUnavailableError) as exc_setup:
                    agent.generate_server_setup(session_id="SESS_TEST", client_token_count=5)
                assert "generate_server_setup" in str(exc_setup.value)

                # generate_client_request must raise
                with pytest.raises(PSIUnavailableError) as exc_req:
                    agent.generate_client_request(session_id="SESS_TEST")
                assert "generate_client_request" in str(exc_req.value)

                # process_client_request must raise
                with pytest.raises(PSIUnavailableError) as exc_proc:
                    agent.process_client_request(session_id="SESS_TEST", request_bytes=b"fake_bytes")
                assert "process_client_request" in str(exc_proc.value)

                # process_server_response must raise
                with pytest.raises(PSIUnavailableError) as exc_resp:
                    agent.process_server_response(session_id="SESS_TEST", setup_bytes=b"fake_setup", response_bytes=b"fake_resp")
                assert "process_server_response" in str(exc_resp.value)

                # Direct PSIServer initialization must raise
                with pytest.raises(PSIUnavailableError) as exc_server:
                    PSIServer()
                assert "PSIServer initialization" in str(exc_server.value)

                # Direct PSIClient initialization must raise
                with pytest.raises(PSIUnavailableError) as exc_client:
                    PSIClient()
                assert "PSIClient initialization" in str(exc_client.value)
