# SignalMesh Frontend-Backend API Contract (v2)

**Document Status**: Proposed / Draft for Parallel Development  
**Inspection Date**: October 18, 2026  
**Backend Status**: Read-only inspection verified that `backend/app/main.py` and `backend/app/api/v1/*.py` are initial stub files with zero registered endpoints. FastAPI is specified in `requirements.txt` but no HTTP server or routes are currently active.  
**Frontend Mode**: Operating in `DATA_MODE = 'demo'` with deterministic sample fixtures via `DemoDataProvider`. `ApiDataProvider` is implemented with normalized response parsers and explicit error/loading/retry states ready for the endpoints specified below.

---

## 1. Architectural & Privacy Boundaries

SignalMesh is a privacy-preserving cross-bank AML collaboration prototype using Private Set Intersection (PSI). The API surface strictly enforces data minimization:

1. **Zero Raw Transaction Ingestion**: Endpoints must NEVER accept or return raw customer transactions, unmasked account numbers, or central transaction graphs.
2. **Opaque Entity Identifiers**: Entity leads are exposed solely as cryptographic hashes or opaque tokens (e.g., `TOK_0a91c73f81b2d604`).
3. **Decentralized Local Subgraphs**: Local bank transaction graphs remain inside bank-local agent memory. The central coordinator and dashboard API only receive observable session telemetry and client-reported match cardinalities.
4. **Transport Telemetry Terminology**: The ledger measures **Serialized Protocol Bytes** (the exact size of OpenMined PSI protobuf messages), not raw network wire packets, because the prototype currently communicates over IPC queues.
5. **Data-Completeness Warnings vs. Risk Scores**: Unmapped foreign currencies (`RULE_INCOMPLETE_CURRENCY_COVERAGE`) must be reported strictly as data-completeness warnings with **0.00 risk score inflation**, ensuring financial risk scores reflect observed transaction typologies rather than bank FX coverage gaps.

---

## 2. Normalized Data Models

The frontend consumes normalized TypeScript/JavaScript models defined below:

```typescript
// Summary Metrics
export interface DashboardSummary {
  simulated_participants_count: number;
  simulated_participants_list: string[];
  pairwise_overlaps_count: number;
  open_investigation_leads_count: number;
  audit_chain_status: "VERIFIED" | "CORRUPTED" | "TAMPERED" | "UNAVAILABLE";
  audit_chain_verified_events: number;
  last_activity_timestamp: string;
  source_environment: "DEMO_ENVIRONMENT" | "API_MODE";
}

// Bank Participant
export interface BankParticipant {
  bank_id: string; // e.g. "BANK_A", "BANK_B", "BANK_C"
  display_name: string; // e.g. "Bank A (Simulated Agent)"
  status: "ONLINE" | "OFFLINE" | "COLLABORATING" | "IDLE";
  local_candidate_token_count: number;
  pairwise_sessions_completed: number;
  last_activity_timestamp: string;
  local_rules_evaluated: string[];
}

// Pairwise PSI Session Summary
export interface PairwiseSession {
  pair_id: string; // e.g. "PAIR_A_B"
  server_bank_id: string;
  client_bank_id: string;
  data_structure: "RAW" | "GCS";
  fpr_parameter: number; // e.g. 0.001
  total_serialized_protocol_bytes: number;
  revealed_cardinality: number;
  status: "SUCCESS" | "REJECTED_DUPLICATE" | "FAILED";
  timestamp: string;
  duration_ms: number;
}

// Investigation Lead
export interface InvestigationLead {
  lead_id: string; // e.g. "LEAD-2026-001"
  canonical_token: string; // e.g. "TOK_0a91c73f81b2d604"
  matched_banks: string[]; // e.g. ["BANK_A", "BANK_B"]
  triggered_rules: string[]; // e.g. ["RULE_STRUCTURING_SMURFING", "RULE_HIGH_FAN_IN"]
  rule_explanations: string[];
  priority: "HIGH" | "MEDIUM" | "LOW";
  status: "OPEN" | "IN_REVIEW" | "ESCALATED" | "RESOLVED";
  local_risk_score: number; // 0.0 to 1.0
  currency_coverage_complete: boolean;
  excluded_currencies?: string[];
  excluded_currency_tx_count?: number;
  coverage_warning?: string;
  supporting_evidence: Record<string, any>;
  updated_at: string;
}

// Privacy Ledger Event
export interface LedgerEvent {
  sequence_number: number;
  event_id: string; // e.g. "EVT_000001"
  session_id: string; // Caller-submitted original session ID
  round_id: string;
  server_bank_id: string;
  client_bank_id: string;
  protocol_family: string; // e.g. "ECDH_OPRF_PSI"
  data_structure: "RAW" | "GCS";
  fpr_parameter: number;
  server_set_size: number;
  client_set_size: number;
  total_serialized_protocol_bytes: number;
  client_revealed_cardinality: number;
  status: "SUCCESS" | "REJECTED_DUPLICATE" | "FAILED";
  prev_hash: string;
  event_hash: string;
  timestamp: string;
  execution_time_ms: number;
  error_message?: string | null;
}

// Ledger Verification Result
export interface LedgerVerification {
  is_valid: boolean;
  total_events_checked: number;
  last_verified_sequence: number;
  chain_head_hash: string;
  verification_timestamp: string;
  checkpoint_status: "NOT_CONFIGURED" | "MATCHED" | "MISMATCH";
  threat_boundary_note: string;
}

// Rule Definition
export interface RuleDefinition {
  rule_id: string;
  name: string;
  category: "TYPOLOGY" | "DATA_COMPLETENESS";
  description: string;
  risk_weight: number;
  criteria: string;
  sample_evidence_keys: string[];
  is_data_completeness_warning: boolean;
}
```

---

## 3. Proposed Read-Only Endpoints

All endpoints are strictly read-only (`GET`). Write operations (initiating PSI sessions, publishing transactions) are out of scope for this dashboard.

### 3.1 `GET /api/v1/dashboard/summary`
**Purpose**: Retrieve high-level operational counts for metric cards and top banner.

**Request Query Parameters**: None.

**Response Example (200 OK)**:
```json
{
  "simulated_participants_count": 3,
  "simulated_participants_list": ["BANK_A", "BANK_B", "BANK_C"],
  "pairwise_overlaps_count": 12,
  "open_investigation_leads_count": 7,
  "audit_chain_status": "VERIFIED",
  "audit_chain_verified_events": 24,
  "last_activity_timestamp": "2026-10-18T12:45:00Z",
  "source_environment": "API_MODE"
}
```

---

### 3.2 `GET /api/v1/banks`
**Purpose**: Retrieve participating simulated bank agents and local status.

**Request Query Parameters**: None.

**Response Example (200 OK)**:
```json
[
  {
    "bank_id": "BANK_A",
    "display_name": "Bank A (Simulated Agent)",
    "status": "ONLINE",
    "local_candidate_token_count": 18,
    "pairwise_sessions_completed": 8,
    "last_activity_timestamp": "2026-10-18T12:45:00Z",
    "local_rules_evaluated": ["RULE_STRUCTURING_SMURFING", "RULE_HIGH_FAN_IN", "RULE_HIGH_FAN_OUT", "RULE_RAPID_PASS_THROUGH"]
  },
  {
    "bank_id": "BANK_B",
    "display_name": "Bank B (Simulated Agent)",
    "status": "ONLINE",
    "local_candidate_token_count": 15,
    "pairwise_sessions_completed": 8,
    "last_activity_timestamp": "2026-10-18T12:42:00Z",
    "local_rules_evaluated": ["RULE_STRUCTURING_SMURFING", "RULE_RAPID_PASS_THROUGH"]
  },
  {
    "bank_id": "BANK_C",
    "display_name": "Bank C (Simulated Agent)",
    "status": "ONLINE",
    "local_candidate_token_count": 12,
    "pairwise_sessions_completed": 8,
    "last_activity_timestamp": "2026-10-18T12:40:00Z",
    "local_rules_evaluated": ["RULE_STRUCTURING_SMURFING", "RULE_HIGH_VALUE_CONDUIT", "RULE_INCOMPLETE_CURRENCY_COVERAGE"]
  }
]
```

---

### 3.3 `GET /api/v1/psi/sessions`
**Purpose**: Retrieve pairwise bidirectional PSI collaboration session summaries.

**Request Query Parameters**:
- `pair_id` (optional string): Filter by bank pair (e.g. `PAIR_A_B`)
- `status` (optional string): Filter by `SUCCESS`, `REJECTED_DUPLICATE`, `FAILED`

**Response Example (200 OK)**:
```json
[
  {
    "pair_id": "PAIR_A_B",
    "server_bank_id": "BANK_A",
    "client_bank_id": "BANK_B",
    "data_structure": "RAW",
    "fpr_parameter": 0.001,
    "total_serialized_protocol_bytes": 14528,
    "revealed_cardinality": 5,
    "status": "SUCCESS",
    "timestamp": "2026-10-18T12:30:15Z",
    "duration_ms": 142.5
  },
  {
    "pair_id": "PAIR_B_A",
    "server_bank_id": "BANK_B",
    "client_bank_id": "BANK_A",
    "data_structure": "RAW",
    "fpr_parameter": 0.001,
    "total_serialized_protocol_bytes": 14412,
    "revealed_cardinality": 5,
    "status": "SUCCESS",
    "timestamp": "2026-10-18T12:30:18Z",
    "duration_ms": 138.2
  }
]
```

---

### 3.4 `GET /api/v1/investigation-leads`
**Purpose**: Retrieve detected cross-bank entity leads without leaking private account graphs.

**Request Query Parameters**:
- `bank_id` (optional string): Filter by bank participant (`BANK_A`, `BANK_B`, `BANK_C`)
- `priority` (optional string): Filter by `HIGH`, `MEDIUM`, `LOW`
- `status` (optional string): Filter by `OPEN`, `IN_REVIEW`, `ESCALATED`, `RESOLVED`
- `rule` (optional string): Filter by rule name
- `search` (optional string): Free-text search on token or lead ID

**Response Example (200 OK)**:
```json
[
  {
    "lead_id": "LEAD-2026-001",
    "canonical_token": "TOK_0a91c73f81b2d604",
    "matched_banks": ["BANK_A", "BANK_B"],
    "triggered_rules": ["RULE_STRUCTURING_SMURFING", "RULE_HIGH_FAN_IN"],
    "rule_explanations": [
      "Observed 3 cash deposits near reporting threshold totaling $28,800.00.",
      "Fan-in aggregation from 4 distinct source counterparties with in/out ratio of 3.2."
    ],
    "priority": "HIGH",
    "status": "OPEN",
    "local_risk_score": 0.85,
    "currency_coverage_complete": true,
    "supporting_evidence": {
      "total_in_amount": 28800.0,
      "total_out_amount": 4200.0,
      "turnover_ratio": 0.15,
      "structuring_count": 3,
      "in_degree": 4,
      "out_degree": 1
    },
    "updated_at": "2026-10-18T12:35:00Z"
  },
  {
    "lead_id": "LEAD-2026-004",
    "canonical_token": "TOK_e5f812d4a7b03c99",
    "matched_banks": ["BANK_A", "BANK_C"],
    "triggered_rules": ["RULE_HIGH_FAN_OUT", "RULE_INCOMPLETE_CURRENCY_COVERAGE"],
    "rule_explanations": [
      "Fan-out dispersion to 5 distinct beneficiary counterparties with out/in ratio of 2.8.",
      "AUDIT WARNING: Financial totals reflect partial activity. Excluded 2 transactions in unmapped currencies: GBP, EUR."
    ],
    "priority": "MEDIUM",
    "status": "OPEN",
    "local_risk_score": 0.55,
    "currency_coverage_complete": false,
    "excluded_currencies": ["GBP", "EUR"],
    "excluded_currency_tx_count": 2,
    "coverage_warning": "Excluded 2 transactions in unmapped currencies: GBP, EUR.",
    "supporting_evidence": {
      "total_in_amount": 12000.0,
      "total_out_amount": 33600.0,
      "fan_out_ratio": 2.8,
      "in_degree": 1,
      "out_degree": 5,
      "currency_coverage_complete": false
    },
    "updated_at": "2026-10-18T11:15:00Z"
  }
]
```

---

### 3.5 `GET /api/v1/investigation-leads/{lead_id}`
**Purpose**: Retrieve full details and explainable evidence for a single lead.

**Response Example (200 OK)**:
```json
{
  "lead_id": "LEAD-2026-001",
  "canonical_token": "TOK_0a91c73f81b2d604",
  "matched_banks": ["BANK_A", "BANK_B"],
  "triggered_rules": ["RULE_STRUCTURING_SMURFING", "RULE_HIGH_FAN_IN"],
  "rule_explanations": [
    "Observed 3 cash deposits near reporting threshold totaling $28,800.00.",
    "Fan-in aggregation from 4 distinct source counterparties with in/out ratio of 3.2."
  ],
  "priority": "HIGH",
  "status": "OPEN",
  "local_risk_score": 0.85,
  "currency_coverage_complete": true,
  "supporting_evidence": {
    "total_in_amount": 28800.0,
    "total_out_amount": 4200.0,
    "turnover_ratio": 0.15,
    "structuring_count": 3,
    "in_degree": 4,
    "out_degree": 1,
    "rapid_pass_through_hours": null,
    "kyc_risk_score": 0.35
  },
  "updated_at": "2026-10-18T12:35:00Z"
}
```

---

### 3.6 `GET /api/v1/privacy-ledger/events`
**Purpose**: Retrieve verifiable privacy leakage ledger records.

**Request Query Parameters**:
- `status` (optional string): `SUCCESS`, `REJECTED_DUPLICATE`, `FAILED`
- `pair` (optional string): e.g. `BANK_A:BANK_B`
- `data_structure` (optional string): `RAW` or `GCS`
- `limit` (optional integer, default 50)

**Response Example (200 OK)**:
```json
[
  {
    "sequence_number": 1,
    "event_id": "EVT_000001",
    "session_id": "SESS_20261018_A_B_01",
    "round_id": "RND_20261018_01",
    "server_bank_id": "BANK_A",
    "client_bank_id": "BANK_B",
    "protocol_family": "ECDH_OPRF_PSI",
    "data_structure": "RAW",
    "fpr_parameter": 0.001,
    "server_set_size": 18,
    "client_set_size": 15,
    "total_serialized_protocol_bytes": 14528,
    "client_revealed_cardinality": 5,
    "status": "SUCCESS",
    "prev_hash": "GENESIS",
    "event_hash": "7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b",
    "timestamp": "2026-10-18T12:30:15Z",
    "execution_time_ms": 142.5,
    "error_message": null
  }
]
```

---

### 3.7 `GET /api/v1/privacy-ledger/verification`
**Purpose**: Execute cryptographic verification of the SQLite ledger hash chain on the server.

**Response Example (200 OK)**:
```json
{
  "is_valid": true,
  "total_events_checked": 24,
  "last_verified_sequence": 24,
  "chain_head_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "verification_timestamp": "2026-10-18T12:45:00Z",
  "checkpoint_status": "NOT_CONFIGURED",
  "threat_boundary_note": "Local hash chaining detects modification/reordering/deletion. Tail truncation requires an independently retained checkpoint. Privileged database administrator write access is outside the local threat boundary."
}
```

---

### 3.8 `GET /api/v1/rules`
**Purpose**: Retrieve explainable AML rule definitions and data completeness policies.

**Response Example (200 OK)**:
```json
[
  {
    "rule_id": "RULE_STRUCTURING_SMURFING",
    "name": "Structuring / Smurfing",
    "category": "TYPOLOGY",
    "description": "Multiple deposits or withdrawals structured just below currency transaction reporting (CTR) thresholds.",
    "risk_weight": 0.40,
    "criteria": "structuring_count >= 2 OR (cash_deposit_count >= 2 AND total_in_amount >= $15,000)",
    "sample_evidence_keys": ["structuring_count", "cash_deposit_count", "cash_deposit_amount", "total_in_amount"],
    "is_data_completeness_warning": false
  },
  {
    "rule_id": "RULE_RAPID_PASS_THROUGH",
    "name": "Rapid Pass-Through Layering",
    "category": "TYPOLOGY",
    "description": "Funds rapidly disbursed within 24 hours of arrival with turnover ratio close to 1.0 (85% to 115%).",
    "risk_weight": 0.35,
    "criteria": "rapid_pass_through_hours <= 24.0 AND 0.85 <= turnover_ratio <= 1.15 AND total_out_amount >= $10,000",
    "sample_evidence_keys": ["rapid_pass_through_hours", "turnover_ratio", "total_out_amount"],
    "is_data_completeness_warning": false
  },
  {
    "rule_id": "RULE_HIGH_FAN_IN",
    "name": "High Fan-In Aggregation",
    "category": "TYPOLOGY",
    "description": "Funneling of funds from multiple distinct counterparties into a single destination account.",
    "risk_weight": 0.35,
    "criteria": "in_degree >= 2 AND fan_in_ratio >= 1.5 AND total_in_amount >= $15,000",
    "sample_evidence_keys": ["in_degree", "fan_in_ratio", "total_in_amount"],
    "is_data_completeness_warning": false
  },
  {
    "rule_id": "RULE_HIGH_FAN_OUT",
    "name": "High Fan-Out Dispersion",
    "category": "TYPOLOGY",
    "description": "Rapid dispersion of funds to multiple distinct beneficiary counterparties.",
    "risk_weight": 0.35,
    "criteria": "out_degree >= 2 AND fan_out_ratio >= 1.5 AND total_out_amount >= $15,000",
    "sample_evidence_keys": ["out_degree", "fan_out_ratio", "total_out_amount"],
    "is_data_completeness_warning": false
  },
  {
    "rule_id": "RULE_HIGH_VALUE_CONDUIT",
    "name": "High-Value Conduit",
    "category": "TYPOLOGY",
    "description": "Single transaction value exceeding the high-value monitoring threshold ($40,000).",
    "risk_weight": 0.30,
    "criteria": "max_in_amount >= $40,000 OR max_out_amount >= $40,000",
    "sample_evidence_keys": ["max_in_amount", "max_out_amount"],
    "is_data_completeness_warning": false
  },
  {
    "rule_id": "RULE_INCOMPLETE_CURRENCY_COVERAGE",
    "name": "Incomplete Currency Coverage Warning",
    "category": "DATA_COMPLETENESS",
    "description": "Operational currency conversion rate missing for one or more foreign-currency transactions. Treated strictly as a data-completeness warning with 0.00 risk score inflation.",
    "risk_weight": 0.00,
    "criteria": "currency_coverage_complete == False",
    "sample_evidence_keys": ["excluded_currencies", "excluded_currency_tx_count", "coverage_warning"],
    "is_data_completeness_warning": true
  }
]
```

---

## 4. Questions & Alignment for Backend Teammate

1. **CORS Development Origin**:
   When launching the FastAPI server, please configure `CORSMiddleware` with `allow_origins=["http://127.0.0.1:3000", "http://localhost:3000"]` to allow local browser testing.
2. **Server-Side Verify Chain Execution**:
   Will `GET /api/v1/privacy-ledger/verification` trigger `ledger.verify_chain()` on demand, or will it read from a cached verification status table? (On-demand is preferred for prototype evaluation).
3. **Session ID Formatting**:
   Are session IDs generated with timestamps or UUIDs? The frontend normalizer supports both string representations.
4. **Lead Updates / Status Transitions**:
   If an analyst toggles lead status (e.g. from `OPEN` to `IN_REVIEW`), is there a future `PATCH /api/v1/investigation-leads/{lead_id}` planned, or should this remain local to the client session for now?
