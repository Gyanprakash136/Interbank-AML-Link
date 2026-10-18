"""Unit tests for the SignalMesh FastAPI endpoints.

Verifies that the dashboard summary, bank transaction querying, schema validation,
local rule-based detection, graph extraction, platform capability detection,
and evaluation endpoints return correct, uncorrupted, conforming payloads.
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.psi.protocol import PSI_AVAILABLE


@pytest.fixture
def client():
    return TestClient(app)


def test_health_endpoint(client):
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert "version" in data


def test_platform_endpoint(client):
    resp = client.get("/api/v1/platform")
    assert resp.status_code == 200
    data = resp.json()
    assert "os" in data
    assert "architecture" in data
    assert "psi_available" in data
    assert data["psi_available"] == PSI_AVAILABLE
    assert "environment_name" in data
    assert "supported_modes" in data


def test_dashboard_summary_endpoint(client):
    resp = client.get("/api/v1/dashboard/summary")
    assert resp.status_code == 200
    data = resp.json()
    assert data["simulated_participants_count"] == 3
    assert data["total_transactions_processed"] > 0
    assert data["total_accounts_monitored"] > 0
    assert data["audit_chain_status"] in ("VERIFIED", "TAMPERED")
    assert data["is_synthetic_demonstration"] is True


def test_banks_endpoint(client):
    resp = client.get("/api/v1/banks")
    assert resp.status_code == 200
    banks = resp.json()
    assert len(banks) == 3
    bank_ids = {b["bank_id"] for b in banks}
    assert bank_ids == {"BANK_A", "BANK_B", "BANK_C"}


def test_bank_transactions_endpoint(client):
    resp = client.get("/api/v1/banks/bank_a/transactions")
    assert resp.status_code == 200
    txs = resp.json()
    assert len(txs) > 0
    first = txs[0]
    assert "transaction_id" in first
    assert "amount" in first
    assert isinstance(first["amount"], float)
    assert first["amount"] > 0


def test_bank_validation_endpoint(client):
    resp = client.get("/api/v1/banks/bank_a/validation")
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_valid"] is True
    assert data["schema_status"] == "CONFORMING"
    assert data["quarantined_records"] == 0
    assert len(data["checks"]) >= 4


def test_bank_analyze_endpoint(client):
    resp = client.post("/api/v1/banks/bank_a/analyze?suspicion_threshold=0.45")
    assert resp.status_code == 200
    data = resp.json()
    assert data["bank_id"] == "BANK_A"
    assert data["total_accounts_analyzed"] > 0
    assert data["suspicious_count"] >= 1
    assert len(data["candidate_tokens"]) >= 1


def test_bank_graph_endpoint(client):
    resp = client.get("/api/v1/banks/bank_a/graph")
    assert resp.status_code == 200
    data = resp.json()
    assert "nodes" in data
    assert "edges" in data
    assert len(data["nodes"]) > 0
    assert len(data["edges"]) > 0


def test_audit_verify_endpoint(client):
    resp = client.get("/api/v1/audit/verify")
    assert resp.status_code == 200
    data = resp.json()
    assert "is_valid" in data
    assert "chain_head_hash" in data
    assert "threat_boundary_note" in data


def test_evaluation_metrics_endpoint(client):
    resp = client.get("/api/v1/evaluation/metrics")
    assert resp.status_code == 200
    data = resp.json()
    assert data["evaluation_available"] is True
    metrics = data["metrics"]
    assert "precision" in metrics
    assert "recall" in metrics
    assert "f1" in metrics
    assert "tp" in metrics
    assert "fp" in metrics
