"""Separate-Process Integration Tests for SignalMesh PSI Collaboration.

Demonstrates and verifies physical OS process isolation between Bank A and Bank B:
1. Bank A agent runs in OS Process 1 (PID 1).
2. Bank B agent runs in OS Process 2 (PID 2).
3. The Coordinator / Message Bus runs in Main Process (PID 0).
4. No shared memory or global objects are accessible between processes.
5. Communication occurs strictly via IPC Queues passing serialized protobuf bytes:
   - ServerSetup wire bytes
   - ClientRequest wire bytes
   - ServerResponse wire bytes
6. Proves that:
   - Server process never learns client items or matched indices.
   - Client process learns only intersection against its own tokens.
   - Subgraphs and candidate sets never cross the IPC wire or enter coordinator memory.
   - Investigation leads and expanded subgraphs are constructed and stored strictly
     within each bank's local process space.
"""

import multiprocessing as mp
import os
from typing import Dict, List, Tuple
import pytest
import networkx as nx

pytest.importorskip("private_set_intersection.python", reason="OpenMined PSI is unavailable on this platform")
import private_set_intersection.python as psi

from app.banks.local_agent import OperationalBankAgent
from app.psi.coordinator import PSICollaborationCoordinator
from app.psi.leakage_ledger import PrivacyLeakageLedger
from app.psi.transport import IPCBankMessageEndpoint, run_ipc_bank_worker


def _bank_server_worker(
    bank_id: str,
    candidate_tokens: List[str],
    in_queue: mp.Queue,
    out_queue: mp.Queue,
    result_queue: mp.Queue,
):
    """Runs a bank agent strictly in server role within an isolated OS process."""
    try:
        pid = os.getpid()
        agent = OperationalBankAgent(bank_id)
        agent.prepare_candidate_tokens(custom_candidate_tokens=candidate_tokens)

        # Step 1: Receive setup generation request with client token count
        msg_type, session_id, client_count = in_queue.get(timeout=10)
        assert msg_type == "GENERATE_SETUP"

        setup_bytes = agent.generate_server_setup(
            session_id=session_id,
            client_token_count=client_count,
            data_structure=psi.DataStructure.RAW,
        )
        out_queue.put(("SETUP_BYTES", setup_bytes))

        # Step 2: Receive client request bytes and compute response
        msg_type, req_bytes = in_queue.get(timeout=10)
        assert msg_type == "PROCESS_REQUEST"

        resp_bytes = agent.process_client_request(session_id=session_id, request_bytes=req_bytes)
        out_queue.put(("RESPONSE_BYTES", resp_bytes))

        # Report server-side state back to test harness
        result_queue.put({
            "pid": pid,
            "bank_id": bank_id,
            "matched_tokens": agent.get_matched_tokens(),
            "leads_count": len(agent.get_local_investigation_leads()),
            "status": "SUCCESS",
        })
    except Exception as e:
        result_queue.put({"status": "ERROR", "error": str(e), "pid": os.getpid()})


def _bank_client_worker(
    bank_id: str,
    candidate_tokens: List[str],
    in_queue: mp.Queue,
    out_queue: mp.Queue,
    result_queue: mp.Queue,
):
    """Runs a bank agent strictly in client role within an isolated OS process."""
    try:
        pid = os.getpid()
        agent = OperationalBankAgent(bank_id)
        agent.prepare_candidate_tokens(custom_candidate_tokens=candidate_tokens)

        # Step 1: Generate client request
        msg_type, session_id = in_queue.get(timeout=10)
        assert msg_type == "GENERATE_REQUEST"

        req_bytes = agent.generate_client_request(session_id=session_id)
        out_queue.put(("REQUEST_BYTES", req_bytes))

        # Step 2: Receive setup and response bytes to compute intersection locally
        msg_type, setup_bytes, resp_bytes = in_queue.get(timeout=10)
        assert msg_type == "PROCESS_RESPONSE"

        match_count = agent.process_server_response(
            session_id=session_id,
            setup_bytes=setup_bytes,
            response_bytes=resp_bytes,
        )

        # Report client-side state back to test harness
        result_queue.put({
            "pid": pid,
            "bank_id": bank_id,
            "matched_tokens": agent.get_matched_tokens(),
            "leads_count": len(agent.get_local_investigation_leads()),
            "match_count": match_count,
            "status": "SUCCESS",
        })
    except Exception as e:
        result_queue.put({"status": "ERROR", "error": str(e), "pid": os.getpid()})


def test_multiprocess_isolation_and_wire_exchange():
    """Verifies that two bank agents executing in separate OS processes can successfully collaborate

    via pure protobuf message passing over IPC queues with zero shared memory.
    """
    ctx = mp.get_context("spawn")

    # Candidate token sets
    tokens_server = ["TOK_0000000000000001", "TOK_0000000000000002", "TOK_0000000000000003"]
    tokens_client = ["TOK_0000000000000002", "TOK_0000000000000003", "TOK_0000000000000004"]
    expected_overlap = ["TOK_0000000000000002", "TOK_0000000000000003"]

    # IPC Queues
    server_in = ctx.Queue()
    server_out = ctx.Queue()
    client_in = ctx.Queue()
    client_out = ctx.Queue()
    server_res = ctx.Queue()
    client_res = ctx.Queue()

    # Launch separate processes
    p_server = ctx.Process(
        target=_bank_server_worker,
        args=("bank_a", tokens_server, server_in, server_out, server_res),
    )
    p_client = ctx.Process(
        target=_bank_client_worker,
        args=("bank_b", tokens_client, client_in, client_out, client_res),
    )

    p_server.start()
    p_client.start()

    session_id = "SESSION_IPC_TEST_001"

    try:
        # 1. Ask Server Process to generate Setup message bytes
        server_in.put(("GENERATE_SETUP", session_id, len(tokens_client)))
        tag, setup_bytes = server_out.get(timeout=10)
        assert tag == "SETUP_BYTES"
        assert isinstance(setup_bytes, bytes)
        assert len(setup_bytes) > 0

        # 2. Ask Client Process to generate Request message bytes
        client_in.put(("GENERATE_REQUEST", session_id))
        tag, req_bytes = client_out.get(timeout=10)
        assert tag == "REQUEST_BYTES"
        assert isinstance(req_bytes, bytes)
        assert len(req_bytes) > 0

        # 3. Relay Request bytes to Server Process
        server_in.put(("PROCESS_REQUEST", req_bytes))
        tag, resp_bytes = server_out.get(timeout=10)
        assert tag == "RESPONSE_BYTES"
        assert isinstance(resp_bytes, bytes)
        assert len(resp_bytes) > 0

        # 4. Relay (Setup bytes, Response bytes) to Client Process
        client_in.put(("PROCESS_RESPONSE", setup_bytes, resp_bytes))

        # Retrieve process states
        s_result = server_res.get(timeout=10)
        c_result = client_res.get(timeout=10)

        # Join processes cleanly
        p_server.join(timeout=5)
        p_client.join(timeout=5)

        # ── 5. Verify Process Isolation & Asymmetric Revelation ───────────────
        assert s_result["status"] == "SUCCESS"
        assert c_result["status"] == "SUCCESS"

        # Verify distinct OS process IDs
        main_pid = os.getpid()
        server_pid = s_result["pid"]
        client_pid = c_result["pid"]
        assert server_pid != main_pid
        assert client_pid != main_pid
        assert server_pid != client_pid

        # SERVER PROCESS: Asymmetric privacy guarantee - learned zero matched tokens
        assert s_result["matched_tokens"] == []

        # CLIENT PROCESS: Learned strictly the intersection against its own candidate tokens
        assert c_result["matched_tokens"] == expected_overlap
        assert c_result["match_count"] == 2

        # Non-matching token of server ("TOK_0000000000000001") is NOT in client results
        assert "TOK_0000000000000001" not in c_result["matched_tokens"]

    finally:
        if p_server.is_alive():
            p_server.terminate()
        if p_client.is_alive():
            p_client.terminate()


def _make_bank_a_agent():
    """Factory creating Bank A agent with a local graph and candidate tokens."""
    agent = OperationalBankAgent("bank_a")
    G = nx.MultiDiGraph()
    G.add_node("ACC_A_01", is_local=True, canonical_token="TOK_0000000000000002", entity_type="CORPORATION", kyc_risk_score=0.75)
    G.add_node("ACC_A_EXT", is_local=False, canonical_token=None, entity_type="EXTERNAL", kyc_risk_score=0.0)
    G.add_edge("ACC_A_EXT", "ACC_A_01", key="E1", amount=9900.0, tx_type="CASH_DEPOSIT", timestamp="2026-03-01T10:00:00Z")
    agent.set_local_graph(G)
    agent.prepare_candidate_tokens(custom_candidate_tokens=["TOK_0000000000000001", "TOK_0000000000000002"])
    return agent


def _make_bank_b_agent():
    """Factory creating Bank B agent with a local graph and candidate tokens."""
    agent = OperationalBankAgent("bank_b")
    G = nx.MultiDiGraph()
    G.add_node("ACC_B_01", is_local=True, canonical_token="TOK_0000000000000002", entity_type="INDIVIDUAL", kyc_risk_score=0.60)
    G.add_node("ACC_B_EXT", is_local=False, canonical_token=None, entity_type="EXTERNAL", kyc_risk_score=0.0)
    G.add_edge("ACC_B_EXT", "ACC_B_01", key="E2", amount=8500.0, tx_type="WIRE", timestamp="2026-03-01T11:00:00Z")
    agent.set_local_graph(G)
    agent.prepare_candidate_tokens(custom_candidate_tokens=["TOK_0000000000000002", "TOK_0000000000000003"])
    return agent


def test_multiprocess_end_to_end_collaboration_with_coordinator():
    """Verifies that the PSICollaborationCoordinator can orchestrate an end-to-end collaboration round

    where each bank agent executes in a completely separate OS process communicating strictly via
    IPCBankMessageEndpoint message queues.
    """
    ctx = mp.get_context("spawn")

    # Bank A IPC Queues
    req_q_a = ctx.Queue()
    resp_q_a = ctx.Queue()

    # Bank B IPC Queues
    req_q_b = ctx.Queue()
    resp_q_b = ctx.Queue()

    # Start Worker Processes
    p_a = ctx.Process(target=run_ipc_bank_worker, args=(_make_bank_a_agent, req_q_a, resp_q_a))
    p_b = ctx.Process(target=run_ipc_bank_worker, args=(_make_bank_b_agent, req_q_b, resp_q_b))

    p_a.start()
    p_b.start()

    try:
        # Create narrow IPC endpoints in the coordinator's main process
        ep_a = IPCBankMessageEndpoint("bank_a", req_q_a, resp_q_a)
        ep_b = IPCBankMessageEndpoint("bank_b", req_q_b, resp_q_b)

        # Confirm different process IDs
        req_q_a.put(("GET_PID",))
        _, pid_a = resp_q_a.get(timeout=10)
        req_q_b.put(("GET_PID",))
        _, pid_b = resp_q_b.get(timeout=10)

        main_pid = os.getpid()
        assert pid_a != main_pid
        assert pid_b != main_pid
        assert pid_a != pid_b

        # ── Execute Full Collaboration Round via Coordinator ──────────────────
        ledger = PrivacyLeakageLedger()
        coordinator = PSICollaborationCoordinator(leakage_ledger=ledger, default_fpr=0.001)

        round_summary = coordinator.execute_collaboration_round(
            endpoints=[ep_a, ep_b],
            round_id="ROUND_MULTIPROCESS_E2E",
            data_structure=psi.DataStructure.RAW,
        )

        # ── Verify Coordinator Observable Telemetry ───────────────────────────
        assert round_summary.round_id == "ROUND_MULTIPROCESS_E2E"
        assert round_summary.session_count == 2
        assert round_summary.status == "COMPLETED"
        assert round_summary.total_wire_bytes > 0
        assert round_summary.total_matches_revealed == 2  # 1 revealed to A, 1 revealed to B

        # Verify coordinator output contains zero member tokens or graphs
        summary_str = str(round_summary.to_dict())
        assert "TOK_0000000000000002" not in summary_str
        assert "MultiDiGraph" not in summary_str
        assert "ACC_A_01" not in summary_str
        assert "ACC_B_01" not in summary_str

        # ── Query Worker Process A State via IPC ──────────────────────────────
        req_q_a.put(("GET_MATCHED_TOKENS",))
        _, matched_a = resp_q_a.get(timeout=10)
        assert matched_a == ["TOK_0000000000000002"]

        req_q_a.put(("GET_LEADS",))
        _, leads_a = resp_q_a.get(timeout=10)
        assert len(leads_a) == 1
        assert leads_a[0]["matched_token"] == "TOK_0000000000000002"
        assert leads_a[0]["local_account_id"] == "ACC_A_01"
        assert leads_a[0]["subgraph_node_count"] == 2

        # ── Query Worker Process B State via IPC ──────────────────────────────
        req_q_b.put(("GET_MATCHED_TOKENS",))
        _, matched_b = resp_q_b.get(timeout=10)
        assert matched_b == ["TOK_0000000000000002"]

        req_q_b.put(("GET_LEADS",))
        _, leads_b = resp_q_b.get(timeout=10)
        assert len(leads_b) == 1
        assert leads_b[0]["matched_token"] == "TOK_0000000000000002"
        assert leads_b[0]["local_account_id"] == "ACC_B_01"
        assert leads_b[0]["subgraph_node_count"] == 2

        # ── Non-matching tokens confidentiality across processes ──────────────
        # Bank A's exclusive token is TOK_0000000000000001 -> NEVER learned by Bank B
        assert "TOK_0000000000000001" not in matched_b
        # Bank B's exclusive token is TOK_0000000000000003 -> NEVER learned by Bank A
        assert "TOK_0000000000000003" not in matched_a

    finally:
        req_q_a.put(("STOP",))
        req_q_b.put(("STOP",))
        p_a.join(timeout=5)
        p_b.join(timeout=5)
        if p_a.is_alive():
            p_a.terminate()
        if p_b.is_alive():
            p_b.terminate()


def _make_bank_c_agent():
    """Factory creating Bank C agent with a local graph and candidate tokens."""
    agent = OperationalBankAgent("bank_c")
    G = nx.MultiDiGraph()
    G.add_node("ACC_C_01", is_local=True, canonical_token="TOK_0000000000000002", entity_type="CORPORATION", kyc_risk_score=0.85)
    G.add_node("ACC_C_02", is_local=True, canonical_token="TOK_0000000000000003", entity_type="INDIVIDUAL", kyc_risk_score=0.70)
    G.add_node("ACC_C_EXT", is_local=False, canonical_token=None, entity_type="EXTERNAL", kyc_risk_score=0.0)
    G.add_edge("ACC_C_EXT", "ACC_C_01", key="E3", amount=12000.0, tx_type="WIRE", timestamp="2026-03-01T12:00:00Z")
    G.add_edge("ACC_C_EXT", "ACC_C_02", key="E4", amount=9500.0, tx_type="CASH_DEPOSIT", timestamp="2026-03-01T13:00:00Z")
    agent.set_local_graph(G)
    # Token 2 shared with A and B; Token 3 shared with B; Token 9 exclusive to C
    agent.prepare_candidate_tokens(custom_candidate_tokens=["TOK_0000000000000002", "TOK_0000000000000003", "TOK_0000000000000009"])
    return agent


def test_three_bank_multiprocess_collaboration_e2e():
    """Verifies full 3-bank pairwise collaboration round with Bank A, Bank B, and Bank C

    running in separate OS processes (4 distinct PIDs including coordinator main process).
    Verifies that all 6 directional sessions execute, all investigation leads remain inside
    their respective bank processes, and exclusive tokens are not leaked across process boundaries.
    """
    ctx = mp.get_context("spawn")

    # Bank A IPC Queues
    req_q_a = ctx.Queue()
    resp_q_a = ctx.Queue()

    # Bank B IPC Queues
    req_q_b = ctx.Queue()
    resp_q_b = ctx.Queue()

    # Bank C IPC Queues
    req_q_c = ctx.Queue()
    resp_q_c = ctx.Queue()

    # Launch 3 independent OS worker processes
    p_a = ctx.Process(target=run_ipc_bank_worker, args=(_make_bank_a_agent, req_q_a, resp_q_a))
    p_b = ctx.Process(target=run_ipc_bank_worker, args=(_make_bank_b_agent, req_q_b, resp_q_b))
    p_c = ctx.Process(target=run_ipc_bank_worker, args=(_make_bank_c_agent, req_q_c, resp_q_c))

    p_a.start()
    p_b.start()
    p_c.start()

    try:
        # Create narrow IPC endpoints in coordinator process
        ep_a = IPCBankMessageEndpoint("bank_a", req_q_a, resp_q_a)
        ep_b = IPCBankMessageEndpoint("bank_b", req_q_b, resp_q_b)
        ep_c = IPCBankMessageEndpoint("bank_c", req_q_c, resp_q_c)

        # Verify distinct PIDs across all 3 workers and main process
        req_q_a.put(("GET_PID",))
        _, pid_a = resp_q_a.get(timeout=10)
        req_q_b.put(("GET_PID",))
        _, pid_b = resp_q_b.get(timeout=10)
        req_q_c.put(("GET_PID",))
        _, pid_c = resp_q_c.get(timeout=10)

        main_pid = os.getpid()
        all_pids = {main_pid, pid_a, pid_b, pid_c}
        assert len(all_pids) == 4, f"Expected 4 distinct PIDs, got {all_pids}"

        # ── Execute 3-Bank Collaboration Round via Coordinator ────────────────
        ledger = PrivacyLeakageLedger()
        coordinator = PSICollaborationCoordinator(leakage_ledger=ledger, default_fpr=0.001)

        round_summary = coordinator.execute_collaboration_round(
            endpoints=[ep_a, ep_b, ep_c],
            round_id="ROUND_3BANK_MULTIPROCESS_E2E",
            data_structure=psi.DataStructure.RAW,
        )

        # ── Verify Coordinator Summary Telemetry ──────────────────────────────
        assert round_summary.round_id == "ROUND_3BANK_MULTIPROCESS_E2E"
        assert round_summary.session_count == 6  # 3 pairs * 2 directions
        assert round_summary.participating_banks == ["bank_a", "bank_b", "bank_c"]
        assert round_summary.status == "COMPLETED"
        assert round_summary.total_wire_bytes > 0

        # Verify zero member tokens or graph objects leaked into coordinator output
        summary_str = str(round_summary.to_dict())
        assert "TOK_0000000000000001" not in summary_str
        assert "TOK_0000000000000002" not in summary_str
        assert "TOK_0000000000000003" not in summary_str
        assert "TOK_0000000000000009" not in summary_str
        assert "MultiDiGraph" not in summary_str
        assert "ACC_A_01" not in summary_str
        assert "ACC_B_01" not in summary_str
        assert "ACC_C_01" not in summary_str

        # ── Verify In-Process State for Bank A ─────────────────────────────────
        req_q_a.put(("GET_MATCHED_TOKENS",))
        _, matched_a = resp_q_a.get(timeout=10)
        assert matched_a == ["TOK_0000000000000002"]

        req_q_a.put(("GET_LEADS",))
        _, leads_a = resp_q_a.get(timeout=10)
        assert len(leads_a) >= 1
        assert all(l["local_account_id"] == "ACC_A_01" for l in leads_a)

        # ── Verify In-Process State for Bank B ─────────────────────────────────
        req_q_b.put(("GET_MATCHED_TOKENS",))
        _, matched_b = resp_q_b.get(timeout=10)
        # Matches: token 2 (with A & C) and token 3 (with C)
        assert matched_b == ["TOK_0000000000000002", "TOK_0000000000000003"]

        req_q_b.put(("GET_LEADS",))
        _, leads_b = resp_q_b.get(timeout=10)
        assert len(leads_b) >= 1

        # ── Verify In-Process State for Bank C ─────────────────────────────────
        req_q_c.put(("GET_MATCHED_TOKENS",))
        _, matched_c = resp_q_c.get(timeout=10)
        # Matches: token 2 (with A & B) and token 3 (with B)
        assert matched_c == ["TOK_0000000000000002", "TOK_0000000000000003"]

        req_q_c.put(("GET_LEADS",))
        _, leads_c = resp_q_c.get(timeout=10)
        # Bank C has accounts for both token 2 (ACC_C_01) and token 3 (ACC_C_02)
        lead_accounts_c = {l["local_account_id"] for l in leads_c}
        assert "ACC_C_01" in lead_accounts_c
        assert "ACC_C_02" in lead_accounts_c

        # ── Cross-Process Confidentiality Verification ────────────────────────
        # Bank A exclusive token ("TOK_0000000000000001") never in B or C
        assert "TOK_0000000000000001" not in matched_b
        assert "TOK_0000000000000001" not in matched_c

        # Bank C exclusive token ("TOK_0000000000000009") never in A or B
        assert "TOK_0000000000000009" not in matched_a
        assert "TOK_0000000000000009" not in matched_b

    finally:
        req_q_a.put(("STOP",))
        req_q_b.put(("STOP",))
        req_q_c.put(("STOP",))
        p_a.join(timeout=5)
        p_b.join(timeout=5)
        p_c.join(timeout=5)
        if p_a.is_alive():
            p_a.terminate()
        if p_b.is_alive():
            p_b.terminate()
        if p_c.is_alive():
            p_c.terminate()

