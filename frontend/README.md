# SignalMesh Dashboard (Frontend v2)

A privacy-preserving, cross-bank AML investigation dashboard prototype built with pure vanilla HTML5, CSS3, inline SVG, and modern JavaScript. Preserves the institutional dark-fintech aesthetic inspired by modern financial infrastructure (black canvas `#070709`, crisp white typography, rounded pill controls, subtle glass surfaces, and a violet dot-matrix globe motif).

---

## 1. Quick Start / Running Locally

Because modern browser security policies (CORS) restrict `fetch()` requests and ES modules on `file://` URLs, run the dashboard via any local HTTP server:

### Option A: Using Python 3 (Recommended)
```bash
# From workspace root:
python3 -m http.server 3000 --directory frontend
```
Then open your browser at:  
👉 **`http://127.0.0.1:3000`**

### Option B: Using Node.js
```bash
npx -y serve frontend -l 3000
```

---

## 2. Configuration & Switching Modes (`demo` vs `api`)

The frontend features a unified provider abstraction (`DataProvider` interface) with two concrete implementations:
1. **`DemoDataProvider`**: Serves deterministic, realistic synthetic AML investigation fixtures from `DEMO_DATA`. All sample statuses, metrics, and entity tokens are tagged with `(demo)`.
2. **`ApiDataProvider`**: Executes real HTTP `fetch()` requests against confirmed read-only backend endpoints. Handles loading, error, timeout, and empty states without silently falling back to mock data.

### Switching Modes:
- **Interactive UI Switcher**: Click on the **Environment Chip** in the top header or the **Source Card** at the bottom of the sidebar to toggle instantly between `DEMO ENVIRONMENT` and `API MODE`.
- **Static Configuration**: Edit `CONFIG.DATA_MODE` at the top of the `<script>` tag in [`frontend/index.html`](file:///Users/gyanprakash09/Developer/Zdatathon/frontend/index.html):
  ```javascript
  const CONFIG = {
    DATA_MODE: 'demo', // Options: 'demo' | 'api'
    API_BASE_URL: 'http://127.0.0.1:8000',
    REQUEST_TIMEOUT_MS: 8000
  };
  ```

> [!NOTE]
> When `DATA_MODE = 'api'` is selected and no backend server is running on port 8000, each panel will cleanly display a structured error state with an explicit **Retry** button and diagnostic details. The dashboard **never** silently substitutes mock data upon API failures.

---

## 3. Implemented Views & Functional Capabilities

The dashboard implements a complete client-side view router across 5 views:

1. **Cross-Bank Overview (`#overview`)**:
   - High-level metric cards: Simulated Participants (3), Pairwise Overlaps (12), Open Investigation Leads (7), Audit Chain State (`Verified (demo)`).
   - Dynamic SVG network diagram showing pairwise Private Set Intersection (PSI) links between Bank A, Bank B, and Bank C.
   - Recent investigation leads table with inline status pills and detail drawer triggers.
   - Recent privacy ledger sessions table recording serialized protocol message bytes.
   - Designed for Data Minimization callout detailing architectural boundaries.
2. **Investigation Leads (`#leads`)**:
   - Filterable data table by token, bank, rule type, priority, and status.
   - Real-time search across opaque tokens, lead IDs, and rule explanations.
   - Export filtered rows to CSV with explicit provenance headers (`# SignalMesh Leads Export - Source: DEMO ENVIRONMENT`).
   - Accessible right-side detail drawer with rule breakdowns, financial evidence, and non-prosecution legal notices.
3. **Bank Network (`#network`)**:
   - Individual node cards for Bank A, Bank B, and Bank C showing active status, candidate token counts, and last session activity.
   - Detailed pairwise session exchange metrics (directional legs A→B, B→A) highlighting asymmetric revelation accounting.
   - Explicit reminders that raw transaction records and local graphs stay strictly inside bank-local environments.
4. **Privacy Ledger (`#ledger`)**:
   - Verifiable SHA-256 hash-chain event log explaining `sequence_number`, `event_id`, `prev_hash`, `event_hash`, and caller's `session_id`.
   - Threat boundary disclaimer: local hash chains detect modifications, insertions, reordering, and single-row deletions; tail truncation requires an external checkpoint (currently `Not configured` / illustrative); root database administrators are outside the local chain threat boundary.
   - Interactive client-side chain verification demonstration tool.
5. **Local Risk Signals (`#rules`)**:
   - Comprehensive explainable rule catalog:
     - `RULE_STRUCTURING_SMURFING`
     - `RULE_RAPID_PASS_THROUGH`
     - `RULE_HIGH_FAN_IN`
     - `RULE_HIGH_FAN_OUT`
     - `RULE_HIGH_VALUE_CONDUIT`
     - `RULE_INCOMPLETE_CURRENCY_COVERAGE`
   - Demonstrates the currency coverage policy: missing exchange rates trigger a **data-completeness warning** with **`+0.00` risk score adjustment**, preventing artificial inflation of financial suspicion scores.

---

## 4. Prototype Scope & Security Boundaries

SignalMesh is an experimental cross-bank collaboration prototype. To avoid misleading compliance personnel or security auditors:

| Feature / Dimension | Prototype Implementation Status | Production Requirement |
| :--- | :--- | :--- |
| **Cross-Host Transport** | Local IPC Queues / Single-Host Multiprocessing | Mutual TLS (mTLS 1.3) / Authenticated Network Gateway |
| **Audit Ledger Storage** | Local SQLite with SHA-256 Hash Chaining | Distributed Byzantine Fault Tolerant / WORM Hardware Ledger |
| **External Checkpoint Publishing** | **Not Configured** (Documented in UI) | Periodic root anchoring to independent transparency log |
| **Hardware Architecture** | Validated on x86_64 / Apple Silicon | **LinuxONE (s390x) compatibility unverified** |
| **Entity Token Discovery** | Pairwise OpenMined PSI (`ECDH_OPRF_PSI`) | Pairwise or Multi-party Cryptographic PSI |
| **Local Account Graphs** | Isolated in Bank Agent Memory (NetworkX) | Enterprise Core Banking Database / Graph Warehouse |

---

## 5. Backend Alignment & API Contract

Refer to [`frontend/API_CONTRACT.md`](file:///Users/gyanprakash09/Developer/Zdatathon/frontend/API_CONTRACT.md) for the complete endpoint specification, JSON schemas, query parameters, and coordination questions for the backend engineering team.
