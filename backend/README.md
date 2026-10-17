# SignalMesh — Privacy-Preserving Collaborative AML Intelligence

SignalMesh is an enterprise privacy-preserving anti-money laundering (AML) collaborative intelligence network. It enables multiple participating financial institutions to detect sophisticated multi-bank laundering schemes (such as smurfing, fan-out layering, and cartel syndicates) using **Private Set Intersection (PSI)** without pooling raw transactions, customer records, or account graphs.

---

## 1. Project Architecture & Stage Status

SignalMesh follows a strict staged implementation roadmap.

| Stage | Focus Area | Status |
| :--- | :--- | :--- |
| **Stage 1** | Environment baseline, OpenMined PSI verification on Python 3.11.8 | **Complete & Verified** |
| **Stage 2** | Deterministic AML data generator, canonical tokens, PSI suite, data boundaries | **Complete & Verified** |
| **Stage 3** | Local AML graph engine, rule-based detection & matched-seed expansion | **Complete & Verified** |
| **Stage 4** | PSI protocol coordinator, 3-bank orchestration & Privacy Leakage Ledger | **Complete & Verified** |
| **Stage 5** | Suspicion propagation & multi-bank narrative generation | *Pending Review* |
| **Stage 6** | Local AML classifier (LightGBM/XGBoost) & ablation experiments | *Future* |
| **Stage 7** | Central matching API service & immutable audit ledger | *Future* |
| **Stage 8** | Interactive investigation web frontend | *Future* |

> [!IMPORTANT]
> **LinuxONE (s390x) Compatibility Status: UNVERIFIED**
> The cryptographic engine relies on OpenMined PSI 2.0.6. Precompiled wheels are verified on macOS Apple Silicon (`macosx_14_0_arm64`) with Python 3.11.8. On IBM LinuxONE (s390x), no prebuilt wheels exist on PyPI; building from source requires the Bazel / GCC s390x toolchain. Compatibility on LinuxONE remains explicitly marked **UNVERIFIED** until executed and validated on the assigned target environment.

---

## 2. Data Ownership & Trust Model

SignalMesh establishes strict security and data boundaries across all participating institutions:

```
┌────────────────────────────────────────────────────────────────────────┐
│ BANK ALPHA (Bank A)                                                    │
│  ├── local_entities.csv (Account -> Opaque Token TOK_*) [CONFIDENTIAL] │
│  ├── transactions.csv   (Raw transactions)              [CONFIDENTIAL] │
│  └── Local MultiDiGraph (In-memory NetworkX graph)      [CONFIDENTIAL] │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ Approved Opaque Tokens ONLY (TOK_*)
                                   │ (Raw data / amounts / graphs NEVER sent)
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│ PSI COLLABORATION COORDINATOR & PRIVACY LEAKAGE LEDGER                 │
│  - Pairwise Discovery Orchestration (A-B, A-C, B-C: 6 sessions)        │
│  - Observable Telemetry Log: wire bytes, cardinalities, session states │
│  - Data Structures: GCS (configurable FPR) & RAW (exact 0-FPR)         │
│  - Replay & duplicate round prevention                                 │
└──────────────────────────────────▲─────────────────────────────────────┘
                                   │ Approved Opaque Tokens ONLY (TOK_*)
                                   │ (Raw data / amounts / graphs NEVER sent)
┌──────────────────────────────────┴─────────────────────────────────────┐
│ BANK BETA (Bank B) & BANK GAMMA (Bank C)                               │
│  ├── local_entities.csv (Account -> Opaque Token TOK_*) [CONFIDENTIAL] │
│  ├── transactions.csv   (Raw transactions)              [CONFIDENTIAL] │
│  └── Local MultiDiGraph (In-memory NetworkX graph)      [CONFIDENTIAL] │
└────────────────────────────────────────────────────────────────────────┘

[ISOLATED EVALUATION BENCHMARK — STRICT DATA BOUNDARY]
data/evaluation/ground_truth_entities.json
data/evaluation/ground_truth_transactions.json
(STRICTLY FORBIDDEN to be read by operational agents, detection models, or PSI coordinator)
```

### Disclosure Analysis: What Each Participant Learns
- **Bank Client in Session:** Learns strictly which of its **own** submitted tokens matched the counterparty's set.
- **Bank Server in Session:** Receives only blinded, homomorphic client query points. Learns zero information about which elements matched or how many elements the client submitted beyond the `num_client_inputs` protocol parameter.
- **Pairwise Bidirectional Discovery:** In Bank A ↔ Bank B, two complementary sessions run:
  - Leg 1 (A=Server, B=Client): Bank B learns `Tokens(B) ∩ Tokens(A)`. Bank A learns nothing.
  - Leg 2 (B=Server, A=Client): Bank A learns `Tokens(A) ∩ Tokens(B)`. Bank B learns nothing.
- **Three-Bank Orchestration (A, B, C):**
  - Run across 3 pairs: (A, B), (A, C), and (B, C) requiring 6 total directional sessions.
  - Bank A learns mutual intersections with B and with C.
  - Bank B learns mutual intersections with A and with C.
  - Bank C learns mutual intersections with A and with B.
  - **Important Privacy Note:** Pairwise PSI is **not** equivalent to a single 3-party PSI protocol ($A \cap B \cap C$). Pairwise PSI reveals pairwise overlaps ($A \cap B$, $A \cap C$, $B \cap C$), which is strictly more information than revealing only items held by all three parties simultaneously.
- **Central Coordinator:** Observes only session metadata, total wire byte counts, and intersection sizes. The coordinator **never** learns raw customer names, account numbers, transaction histories, or local graph structures.

---

## 3. Privacy Leakage Ledger (`app/psi/leakage_ledger.py`)

The Privacy Leakage Ledger provides a tamper-evident audit record of observable protocol disclosures for every session:

| Field | Description | Example |
| :--- | :--- | :--- |
| `session_id` | Unique session identifier | `ROUND_01_bank_a_to_bank_b` |
| `round_id` | Collaboration round identifier | `ROUND_01` |
| `server_bank_id` | Institutional role serving encrypted setup | `bank_a` |
| `client_bank_id` | Institutional role learning intersection | `bank_b` |
| `protocol_family` | Underlying cryptographic construction | `Diffie-Hellman-ECC-PSI` |
| `data_structure` | Internal indexing mode | `GCS` or `RAW` |
| `fpr_parameter` | Theoretical false-positive rate | `0.001` (GCS) or `0.0` (RAW) |
| `server_set_size` / `client_set_size` | Number of tokens submitted | `15` / `15` |
| `total_wire_bytes` | Protocol messages transmitted | `155 bytes` |
| `client_revealed_cardinality` | Number of matches revealed to client | `2` |
| `recipient_of_output` | Authorized party receiving result | `bank_b` (Server receives `NONE`) |
| `status` | Execution outcome | `SUCCESS`, `REJECTED_DUPLICATE`, `FAILED` |

*Security Rule: Replayed sessions or duplicate round IDs are rejected with `REJECTED_DUPLICATE` to prevent replay attacks.*

---

## 4. Match-versus-Crime Distinction

SignalMesh strictly enforces that a cryptographic PSI match alone **does not constitute proof of money laundering or criminal activity**:
- **`CROSS_BANK_INVESTIGATION_LEAD`:** Assigned only when an entity matches across banks **and** exhibits local transactional suspicion (`prior_score >= 0.40`, such as structuring, cash churn, or rapid pass-through).
- **`BENIGN_CROSS_BANK_ENTITY_MATCH`:** Assigned when an entity matches across banks but exhibits normal, benign transactional patterns (`prior_score < 0.40`, such as normal commercial payroll/supplier payments). The suspicion score remains capped at `<= 0.35`.

---

## 5. Currency Handling in Graph Expansion

When expanding local transaction subgraphs around matched seeds, transaction volumes are grouped and reported **per currency** (e.g. `volumes_by_currency = {"USD": 10000.0, "EUR": 5000.0}`). Incompatible currencies are **never** combined into a single blended sum.

---

## 6. Reproducibility & Setup Instructions

### Environment Setup
```bash
# Ensure Python 3.11.8 is active
python3.11 -m venv .venv311
source .venv311/bin/activate

# Install pinned dependencies
pip install -r requirements.txt
```

### Running Complete Automated Test Suite (51 Tests)
```bash
pytest -v
```

---

## 7. Known Limitations & Next Steps

1. **Pairwise vs Multi-Party PSI:** The current implementation orchestrates $N(N-1)$ pairwise directional sessions. While computationally efficient, it leaks pairwise intersections rather than a single joint $N$-party intersection. True multi-party PSI (MP-PSI) without pairwise disclosure is a recognized cryptographic trade-off.
2. **Supervised ML Deferred:** Supervised ML models (XGBoost / LightGBM) remain deferred to Stage 6.
3. **LinuxONE s390x Status:** Retains open status until tested on the s390x target environment.
