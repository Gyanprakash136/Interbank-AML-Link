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
| **Stabilization & Hardening** | Durable SQLite audit ledger, SHA-256 hash chaining, replay rejection, checkpoint audit | **Complete & Verified (74/74 Tests)** |
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
│  - Cryptographic SHA-256 event hash chain with checkpoint verification │
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

### Threat Model & Privacy Scope Distinctions
1. **Tested Output-Boundary Guarantees:**
   - Automated tests rigorously prove that the coordinator's outputs, round summaries, and audit logs contain zero member-level token strings (`TOK_*`), raw customer identifiers, account numbers, or graph objects.
   - Non-matching candidate tokens are proven never to be disclosed to the counterparty in any session.
2. **Local OS Process-Memory Isolation vs Simulation:**
   - In the production-intended model (`IPCBankMessageEndpoint`), each bank agent executes in an independent OS process with a distinct virtual memory address space.
   - In the fast testing model (`InProcessBankMessageEndpoint`), execution occurs within a single interpreter using closures. This is a logical software simulation, not enforced physical isolation.
3. **Privileged Host Administrator Limitation:**
   - OS-level process separation protects memory isolation between standard non-privileged processes on the host.
   - However, process isolation **does not defend against a privileged host administrator** (root, hypervisor, or kernel-level observer) on a shared host machine who can inspect OS memory pages (`/proc/<pid>/mem`, ptrace), read unencrypted SQLite files, or modify system libraries.
   - Production inter-bank collaboration requires distinct institutional clouds/datacenters for each participating bank.
4. **Network Transport Security Boundary:**
   - Current tests exchange serialized protobuf buffers over local multiprocessing IPC queues.
   - Physical network transport, TLS 1.3 encryption, mutual authentication (mTLS), certificate revocation, and network-level replay protection are transport-layer concerns not present in local IPC execution.

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
- **Separation of Event ID and Session ID:** Every audit event receives a unique, sequential audit identifier (`event_id`, e.g. `EVT_000001`). The original submitted `session_id` is preserved **strictly unchanged** in the audit record (no fabricated suffixes such as `_REJECTED_DUP`), eliminating collision risks with legitimate sessions and maintaining exact session traceability.
- **Audit Event Integrity:** `event_id` is incorporated into the canonical hash payload and re-verified on every call to `verify_chain()`. Modifying `event_id` directly in the database is detected immediately (`test_audit_chain_detects_tampered_event_id`).
- **Dedicated Accepted Session Registry:** Uniqueness is enforced on accepted sessions via a dedicated `accepted_sessions` table (`session_id TEXT PRIMARY KEY, event_id TEXT, round_id TEXT, accepted_at TEXT`). Replayed session IDs are recorded with status `REJECTED_DUPLICATE` and chained into the audit hash log without compromising uniqueness.
- **Concurrent Multiprocess Race Safety:** Verified via `test_concurrent_multiprocess_same_session_race` where two separate OS processes race simultaneously to record the same session ID. One succeeds (`SUCCESS`), the other is rejected as duplicate (`REJECTED_DUPLICATE`), both retain the exact original `session_id`, receive distinct `event_id`s, and maintain an unbroken hash chain.
- **Cryptographic Hash Chain:** Every session event computes a SHA-256 hash over canonical audit fields at exact stored precision (no rounding truncation on floats or timestamps), linking directly to the prior record's hash (`prev_hash`). The first record links to `"GENESIS"`.
- **Full Precision Protection:** Both `fpr_parameter` and `execution_time_ms` are hashed at their exact 64-bit IEEE 754 stored precision without rounding truncation. Tests verify that changes as small as $10^{-9}$ (`0.001000001 - 0.001`) or $10^{-11}$ (`0.00100000001 - 0.001`) to `fpr_parameter`, or $10^{-6}$ (`12.500001 - 12.5`) to `execution_time_ms`, are immediately detected by `verify_chain()`.
- **SignalMesh Canonical JSON (SMCJ) Scheme:** To guarantee deterministic hash compatibility across participating nodes, serialization follows the project-specific SMCJ specification (`canonical_json_dumps`):
  1. *Lexicographical Key Ordering:* Dictionary keys are sorted in ascending order by Unicode code points (`sort_keys=True`).
  2. *Zero Whitespace:* Structural separators omit all whitespace (`separators=(",", ":")`).
  3. *Direct UTF-8:* Non-ASCII characters are emitted directly as UTF-8 without escaping (`ensure_ascii=False`).
  4. *Negative Zero Normalization:* Floating-point `-0.0` is normalized to positive zero (`0.0`), preventing dual zero representations.
  5. *Honest Specification Boundary:* SMCJ is a project-specific scheme and does **not** claim full RFC 8785 (JCS) compliance because Python's standard `json` engine formats certain exponents differently from ECMAScript 6 (e.g. `1e-05` vs `1e-5`). Conformance is verified by `test_canonical_json_scheme_conformance`.

### Deletion Scenarios & Checkpoint Requirements
`verify_chain()` distinguishes two distinct classes of deletion:
1. **Internal Tampering / Middle Deletion (Autonomously Detected):**
   - Deleting a middle record (e.g., removing record 2 in a 3-record chain) creates an immediate sequence gap ($1 \to 3$) and breaks hash continuity ($H_3.prev\_hash \ne H_1.event\_hash$).
   - Swapping or reordering records breaks hash links.
   - Deleting the first record breaks genesis continuity ($H_2.prev\_hash \ne \text{"GENESIS"}$).
   - Any canonical field modification produces a hash mismatch.
   - All such internal modifications are autonomously detected by `verify_chain()`.
2. **Tail Truncation (Requires External Checkpoint):**
   - Deleting the final record (or rolling back multiple final records) leaves a self-consistent prefix of the chain (valid sequence numbers from 1 to $N-k$ and unbroken hash links).
   - Internal inspection alone **cannot** know that trailing records once existed without an external reference.
   - `verify_chain(expected_head_hash=..., expected_sequence_count=...)` verifies the ledger against an external checkpoint (e.g. published receipt or signed monitoring anchor), reliably detecting any tail truncation.

### Honest Threat Model Limitations
- The cryptographic hash chain reliably detects accidental corruption, unauthorized row tampering, record deletion, and history reordering when checked against a recorded chain or checkpoint.
- **Honest Limitation:** The local hash chain is **not immutable or tamper-proof** against a privileged attacker with operating-system or root-level write access to the SQLite file. An attacker with full write access could rewrite all database rows and recompute the entire hash chain from genesis without detection. External checkpoints, digital signatures, or write-once media (WORM) are required to defend against root-level database administrators.

---

## 5. PSI Protocol Correctness & Empirical Benchmark Experiments

SignalMesh separates exact PSI correctness from empirical bandwidth experiments.

### Benchmark Experiments
1. **Benchmark Experiment 1 — Single-Session GCS Empirical FPR (`test_psi_protocol.py`):**
   - **Configuration:** 50 server items vs. 1,000 non-matching client tokens, GCS data structure configured with theoretical parameter $FPR = 0.001$ (0.1%).
   - **Observed Empirical Result:** 0 false positives observed in this specific 1,000-query batch ($empirical\_FPR = 0 / 1,000 = 0.0$), satisfying the configured 0.001 bound.
   - **Essential Caveat:** Observing zero false positives in 1,000 queries does **not** prove that the true false-positive probability is zero. Over larger query volumes ($N \gg 1,000$), GCS will exhibit false positives bounded asymptotically by the configured $\epsilon = 0.001$.
2. **Benchmark Experiment 2 — Three-Bank Multiprocess Collaboration (`test_multiprocess_isolation.py`):**
   - **Configuration:** Bank A (15 items), Bank B (15 items), Bank C (15 items) across 6 directional sessions in `RAW` exact mode.
   - **Observed:** Exact matching; 0 false positives, 100% precision against synthetic ground truth.
   - **Exact-PSI Scope Specificity:** `RAW` mode provides mathematical zero-false-positive exact equality matching *at the cryptographic PSI protocol layer*, assuming correct protocol execution and consistent pre-protocol token normalization (uppercase formatting, stripped whitespace, canonical token encoding). This cryptographic exactness does **not** imply downstream AML rules are infallible: exact PSI matching only confirms that both banks flagged the identical entity token; it does not prove the entity is criminal (benign false positives) or that other laundering networks were not missed (false negatives). Local rules generate investigative leads for human compliance review.

### Precise Measurement Terminology
- Reported byte counts (e.g. `total_wire_bytes` / `total_serialized_protocol_bytes`) represent **serialized protocol-message bytes** exchanged across IPC queues.
- They **exclude** physical network wire overhead, TCP/IP framing, and TLS framing.

---

## 6. Graph Engine & Data Integrity

1. **Multi-Currency Safety & Incomplete Coverage Flagging (`app/graph/features.py`):**
   - Amounts in differing currencies are **never** added as if they were identical.
   - When multiple currencies exist without an explicit exchange rate mapping, `LocalGraphFeatureExtractor` strictly isolates volume metrics to the base currency (`USD`).
   - **Currency Coverage Indicator:** When non-base transactions are excluded due to missing rates, `currency_coverage_complete` is set to `False`, `excluded_currencies` and `excluded_currency_tx_count` are recorded, and an explicit `coverage_warning` is generated.
   - **Downstream AML Warning (`app/banks/local_detection.py`):** The local rule engine evaluates coverage, triggering `RULE_INCOMPLETE_CURRENCY_COVERAGE` and adding an audit warning to `rule_explanations`. Missing currency mappings are treated strictly as a **data-completeness warning**, not an illicit behavior risk indicator. No risk score adjustment (+0.00) is applied, ensuring AML risk scores reflect genuine observed transactional typologies rather than penalized for data gaps.
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
The virtual environment is located at `backend/.venv311`:
```bash
# Option A: From workspace root
source backend/.venv311/bin/activate
pytest backend/tests -v

# Option B: From backend directory
cd backend
source .venv311/bin/activate
pytest -v
```

### Complete Test Suite (77 Tests Passing)
All 77 tests execute in under 4 seconds:
- **Integration Tests (5):** Three-bank multiprocess OS isolation, IPC wire exchange, Stage 3 pipeline, Stage 4 collaboration pipeline.
- **Security & Data Boundaries (6):** Ground-truth isolation, directory traversal guards, operational loader label rejection, raw transaction rejection, bidirectional authorization, opaque token validation.
- **Privacy Leakage Ledger (19):** Telemetry recording, replay rejection, round summary, clean chain verification, modified record detection, deleted record detection, reordered record detection, restart persistence, restart duplicate rejection, concurrent writes, zero raw data/keys, last record deletion with checkpoint, tail truncation with checkpoint, concurrent multiprocess race test, multi-restart replay auditability, float precision protection ($10^{-9}$ and $10^{-11}$ tampering), direct `event_id` SQL tampering detection, SMCJ canonical JSON conformance.
- **Graph Engine & Feature Extraction (17):** Node/edge construction, deduplication, timestamp validation, 1-hop/2-hop expansion, benign vs. suspicious distinction, multi-currency volume partitioning, multi-currency feature isolation, currency coverage indicators, rate-based conversion.
- **Local AML Rule Detection (6):** Smurfing/structuring, fan-in/fan-out, negative control retail accounts, eligible PSI token extraction, incomplete currency coverage audit warning and score neutrality, coexistence of currency warning with genuine typologies.
- **PSI Coordinator & Transport (9):** Narrow message interfaces, two-bank overlap/no-overlap, non-matching token concealment, zero member tokens in coordinator output, correct recipient attribution, three-bank orchestration, duplicate round rejection.
- **PSI Protocol & Synthetic Data (15):** Exact indices, no-overlap, cardinality-only mode, bidirectional session, wire serialization roundtrip, empirical GCS vs. RAW comparison, generator determinism, real PSI on synthetic data.
