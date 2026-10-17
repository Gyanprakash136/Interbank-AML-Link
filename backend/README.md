# SignalMesh — Privacy-Preserving Collaborative AML Intelligence

SignalMesh is an enterprise privacy-preserving anti-money laundering (AML) collaborative intelligence prototype. It enables multiple participating financial institutions to detect multi-bank laundering schemes (such as smurfing, fan-out layering, and cartel syndicates) using **Private Set Intersection (PSI)** without pooling raw transactions, customer records, or account graphs.

---

## 1. Project Architecture & Stabilization Status

SignalMesh has completed its backend stabilization and security hardening pass.

| Stage / Component | Focus Area | Status |
| :--- | :--- | :--- |
| **Stage 1 Baseline** | OpenMined PSI 2.0.6 verification on Python 3.11.8 | **Complete & Verified** |
| **Stage 2 Data Boundary** | Deterministic synthetic AML data, opaque tokens, isolated ground truth | **Complete & Verified** |
| **Stage 3 Graph Engine** | Local NetworkX graph engine, explainable rule detection, multi-currency handling | **Complete & Verified** |
| **Stage 4 Collaboration** | Serialized-message transport, coordinator, 3-bank multiprocess workflow | **Complete & Verified** |
| **Stabilization & Hardening** | Durable SQLite audit ledger, SHA-256 hash chaining, replay rejection, tamper checks | **Complete & Verified (68/68 Tests)** |
| **Stage 5** | Suspicion propagation & multi-bank narrative generation | *Pending Review* |
| **Stage 6** | Local AML classifier (LightGBM/XGBoost) & ablation experiments | *Future* |
| **Stage 7** | Central matching API service & immutable audit ledger | *Future* |
| **Stage 8** | Interactive investigation web frontend | *Future* |

> [!IMPORTANT]
> **LinuxONE (s390x) Compatibility Status: UNVERIFIED**
> The cryptographic engine relies on OpenMined PSI 2.0.6. Precompiled wheels are verified on macOS Apple Silicon (`macosx_14_0_arm64`) with Python 3.11.8. On IBM LinuxONE (s390x), no prebuilt wheels exist on PyPI; building from source requires the Bazel / GCC s390x toolchain. Compatibility on LinuxONE remains explicitly marked **UNVERIFIED** until compiled, executed, and validated directly on the target s390x environment.

---

## 2. Threat Model & Security Boundaries

SignalMesh enforces strict physical and cryptographic boundaries across participating banks and the central coordinator.

```
┌────────────────────────────────────────────────────────────────────────┐
│ BANK ALPHA (Bank A) — Dedicated OS Worker Process                      │
│  ├── local_entities.csv (Account -> Opaque Token TOK_*) [CONFIDENTIAL] │
│  ├── transactions.csv   (Raw transactions)              [CONFIDENTIAL] │
│  ├── Local MultiDiGraph (In-memory NetworkX graph)      [CONFIDENTIAL] │
│  └── Local Investigation Leads & Expanded Subgraphs     [CONFIDENTIAL] │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ Serialized Protocol Bytes ONLY
                                   │ (Raw data / amounts / graphs NEVER sent)
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│ PSI COLLABORATION COORDINATOR & DURABLE LEAKAGE LEDGER                 │
│  - Pairwise Discovery Orchestration (A-B, A-C, B-C: 6 sessions)        │
│  - Observable Telemetry Log: serialized message lengths, cardinalities │
│  - Default Mode: RAW (exact zero false-positive matching)              │
│  - Experimental Mode: GCS (bandwidth optimization with empirical FPR) │
│  - Replay & duplicate round prevention via SQLite UNIQUE constraints   │
│  - Cryptographic SHA-256 event hash chain with tamper verification     │
└──────────────────────────────────▲─────────────────────────────────────┘
                                   │ Serialized Protocol Bytes ONLY
                                   │ (Raw data / amounts / graphs NEVER sent)
┌──────────────────────────────────┴─────────────────────────────────────┐
│ BANK BETA (Bank B) & BANK GAMMA (Bank C) — Dedicated OS Processes      │
│  ├── local_entities.csv (Account -> Opaque Token TOK_*) [CONFIDENTIAL] │
│  ├── transactions.csv   (Raw transactions)              [CONFIDENTIAL] │
│  ├── Local MultiDiGraph (In-memory NetworkX graph)      [CONFIDENTIAL] │
│  └── Local Investigation Leads & Expanded Subgraphs     [CONFIDENTIAL] │
└────────────────────────────────────────────────────────────────────────┘

[ISOLATED EVALUATION BENCHMARK — STRICT DATA BOUNDARY]
data/evaluation/ground_truth_entities.json
data/evaluation/ground_truth_transactions.json
(STRICTLY FORBIDDEN to be read by operational agents, detection models, or PSI coordinator)
```

### Threat Model & Process Isolation
1. **Execution Modes:**
   - **`IPCBankMessageEndpoint` (Production Model):** Each bank agent executes in an independent operating-system process with a separate virtual memory address space. Communication occurs strictly over OS IPC queues exchanging serialized protobuf byte buffers.
   - **`InProcessBankMessageEndpoint` (Simulation Model):** An in-process adapter using closures for rapid local testing. This is a logical software simulation, not physical process isolation.
2. **Host Administrator Limitation:**
   - Separate OS processes protect against cross-bank memory inspection in standard multi-tenant environments.
   - However, process isolation **does not defend against a privileged host administrator** (root / hypervisor) on the shared machine who can inspect OS memory pages or attach debuggers. In a distributed multi-bank production deployment, each bank agent must run inside its own institutional cloud/datacenter boundary connected via mutually authenticated TLS (mTLS).
3. **Data Boundary Guarantees:**
   - The coordinator never receives complete bank agent objects, NetworkX graph objects, raw transaction rows, or candidate token sets.
   - Only narrow `BankMessageEndpoint` instances exposing primitive message transmission methods are accepted.

---

## 3. Cryptographic Disclosures: What Each Entity Observes

| Entity | Information Observed | Information Concealed |
| :--- | :--- | :--- |
| **Client Bank in Session** | Which of its **own** candidate tokens matched the counterparty; intersection cardinality; local graph expansion around matches. | Non-matching counterparty tokens; counterparty candidate set elements; counterparty transactions or graphs. |
| **Server Bank in Session** | Blinded client request points; number of client inputs (`num_client_inputs`). | Which tokens matched (if any); intersection cardinality; client cleartext tokens; client transactions or graphs. |
| **Central Coordinator** | Session IDs, participant roles, data structure mode, serialized message lengths in bytes, scalar match count reported by client, session status and timing. | Raw transactions; customer identities; account numbers; candidate token strings; local graphs; investigative leads. |

*Pairwise Disclosure Trade-Off:* In a 3-bank network (A, B, C), running all 3 pairs (6 directional sessions) reveals pairwise overlaps ($A \cap B$, $A \cap C$, $B \cap C$). This reveals more metadata than a true 3-party intersection ($A \cap B \cap C$), which is a recognized architectural trade-off of pairwise PSI.

---

## 4. Durable & Verifiable Privacy Leakage Ledger (`app/psi/leakage_ledger.py`)

The Privacy Leakage Ledger records observable cryptographic protocol metadata in a durable, verifiable SQLite database:

### Ledger Design & Guarantees
- **Durable Persistence:** Backed by SQLite (WAL mode, synchronous normal). All recorded sessions persist across application restarts.
- **Atomic Operations:** Uses explicit ACID transactions (`BEGIN IMMEDIATE` / `COMMIT` / `ROLLBACK`). Failed operations leave zero partial records.
- **Replay & Duplicate Protection:** Durable `UNIQUE(session_id)` constraint prevents replay attacks. Replayed session IDs are detected and logged as `REJECTED_DUPLICATE` records even after system restarts.
- **Cryptographic Hash Chain:** Every session event computes a SHA-256 hash over canonical audit fields, linking directly to the prior record's hash (`prev_hash`). The first record links to `"GENESIS"`.
- **Tamper & Anomaly Detection:** `verify_chain()` scans the entire database sequentially, verifying sequence continuity (no gaps/reordering), hash linkage, and canonical field integrity.

### Audit Integrity Limitations
- The cryptographic hash chain reliably detects accidental corruption, unauthorized record modification, row deletion, and record reordering when checked against a recorded chain.
- **Honest Limitation:** The local hash chain is **not immutable or tamper-proof** against a privileged attacker with operating-system or root-level write access to the SQLite file. An attacker with full write access could rewrite all database rows and recompute the entire hash chain from genesis without detection. External checkpoints, digital signatures, or write-once media are required to defend against root-level database administrators.

---

## 5. PSI Protocol Correctness & Measurement Terminology

### Exact Matching vs Bandwidth Optimization
- **`RAW` Mode (Default):** Exact matching using Diffie-Hellman ECC PSI with zero false positives. This is the primary correctness mode for SignalMesh.
- **`GCS` Mode (Optional Experiment):** Bandwidth optimization using Golomb-Coded Sets. It provides reduced message sizes at the cost of a tunable false-positive probability ($FPR = 0.001$).
- **Empirical Measurement:** In 1,000 non-matching trials against 50 server items, GCS observed zero false positives ($FPR = 0.0$). This is reported strictly as an **empirical observation**, not mathematical proof that GCS can never produce a false positive.

### Precise Measurement Terminology
- Reported byte counts (e.g. `total_wire_bytes` / `total_serialized_protocol_bytes`) represent **serialized protocol-message bytes** exchanged across IPC queues.
- They **exclude** physical network wire overhead, TCP/IP framing, and TLS framing.

---

## 6. Graph Engine & Data Integrity

1. **Multi-Currency Safety (`app/graph/features.py`):**
   - Amounts in differing currencies are **never** added as if they were identical.
   - When multiple currencies exist without an explicit exchange rate mapping, `LocalGraphFeatureExtractor` strictly isolates calculations to the base currency (`USD`).
   - When an explicit `exchange_rates` dictionary is provided, foreign currencies are converted to base currency before aggregation. Missing exchange rates raise a `CurrencyMismatchError`.
2. **Subgraphs by Currency (`app/graph/graph_expansion.py`):**
   - Neighborhood subgraphs partition volume by currency (`volumes_by_currency = {"USD": 10000.0, "EUR": 5000.0}`).
3. **Match != Crime Distinction:**
   - A cryptographic PSI match alone **never** establishes money laundering.
   - An entity matching across banks is marked `CROSS_BANK_INVESTIGATION_LEAD` only if accompanied by local transactional suspicion (`prior_score >= 0.40`).
   - An entity matching across banks with normal retail transactional patterns (`prior_score < 0.40`) remains classified as `BENIGN_CROSS_BANK_ENTITY_MATCH` with risk capped at `<= 0.35`.
4. **Opaque Tokens:**
   - Canonical tokens follow the uniform opaque format `TOK_<16_hex>` (`assert_opaque_tokens`). They never encode syndicate names, typology labels, or laundering flags.

---

## 7. Running the Automated Test Suite

### Environment Activation
```bash
# Activate Python 3.11.8 virtual environment
source .venv311/bin/activate
```

### Running the Complete Test Suite (68 Tests)
```bash
pytest -v
```

All 68 tests run in approximately 3.8 seconds:
- 3 Integration / Multiprocess Isolation Tests (3-bank e2e, IPC queues, separate PIDs)
- 2 Pipeline Integration Tests (Stage 3 & Stage 4 workflows)
- 6 Security & Data Boundary Tests (ground truth isolation, directory traversal guards, opaque token enforcement)
- 8 Graph Builder Tests (node/edge attributes, deduplication, timestamp validation)
- 5 Graph Expansion Tests (1-hop, 2-hop, benign vs suspicious, multi-currency)
- 4 Graph Feature Tests (mule metrics, benign metrics, multi-currency isolation and conversion)
- 3 HI-Small Adapter Tests (schema parsing, account ownership partitioning)
- 12 Privacy Leakage Ledger Tests (replay rejection, summary, audit chain verification, tamper detection, deletion detection, reorder detection, restart persistence, concurrent writes, zero raw data)
- 4 Local Rule Detection Tests (smurfing, fan-in/fan-out, negative controls, PSI eligibility)
- 9 PSI Coordinator Tests (narrow message interfaces, two-bank overlap/no-overlap, non-matching concealment, three-bank orchestration, duplicate round rejection)
- 8 PSI Protocol Tests (exact indices, no-overlap, cardinality-only, serialization roundtrip, empirical GCS vs RAW)
- 4 Synthetic Data Generator Tests (determinism, ground truth isolation, real PSI on generated datasets)
