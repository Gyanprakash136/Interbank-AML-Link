#!/usr/bin/env python3
"""SignalMesh Deterministic Synthetic AML Transaction Generator.

Generates:
1. Bank-local datasets for three simulated institutions:
   - Bank Alpha (Bank A): data/bank_a/transactions.csv, data/bank_a/local_entities.csv
   - Bank Beta (Bank B):  data/bank_b/transactions.csv, data/bank_b/local_entities.csv
   - Bank Gamma (Bank C): data/bank_c/transactions.csv, data/bank_c/local_entities.csv
2. Separate evaluation-only ground-truth mapping:
   - data/evaluation/ground_truth_entities.json
   - data/evaluation/ground_truth_transactions.json

CRITICAL SECURITY AND PRIVACY BOUNDARIES:
- Operational bank files contain ONLY local account IDs, transaction flows, and
  pre-derived canonical synthetic entity tokens.
- Operational bank files DO NOT contain global entity IDs or 'is_laundering' labels.
- OPAQUE TOKENS: Canonical tokens MUST NOT reveal entity category, typology, or laundering status.
  All tokens use the uniform opaque format 'TOK_<16_hex>'.
- The evaluation files are strictly isolated in data/evaluation/ and must NEVER be
  read by operational bank agents, detection modules, or PSI protocols.
- Application-level boundary checks provide simulation guardrails; container/OS isolation
  is a separate deployment concern.
"""

import argparse
import hashlib
import json
from pathlib import Path
import random
from typing import Any, Dict, List, Tuple


def _derive_canonical_token(entity_key: str) -> str:
    """Derives a completely opaque, deterministic canonical synthetic entity token.

    CRITICAL: The token string MUST NOT encode entity type, typology, bank of origin,
    or laundering status. All semantic attributes belong strictly in evaluation ground truth.
    Format: 'TOK_<16_hex_digits>'
    """
    h = hashlib.sha256(f"SIGNALMESH_CANONICAL_TOKEN_SALT_V1:{entity_key}".encode("utf-8")).hexdigest()[:16]
    return f"TOK_{h}"


def generate_synthetic_aml_data(
    output_dir: Path,
    seed: int = 42,
) -> Dict[str, Any]:
    """Generates deterministic synthetic AML transactions and isolated evaluation ground truth."""
    random.seed(seed)
    output_dir = Path(output_dir).resolve()

    dir_bank_a = output_dir / "bank_a"
    dir_bank_b = output_dir / "bank_b"
    dir_bank_c = output_dir / "bank_c"
    dir_eval = output_dir / "evaluation"

    for d in (dir_bank_a, dir_bank_b, dir_bank_c, dir_eval):
        d.mkdir(parents=True, exist_ok=True)

    # ─────────────────────────────────────────────────────────────────────────
    # 1. ENTITY DEFINITIONS & TOPOLOGY
    # ─────────────────────────────────────────────────────────────────────────
    entities: List[Dict[str, Any]] = []

    # --- Typology 1: Three-Way Syndicate (Linked across Bank A, Bank B, and Bank C) ---
    ent_syndicate = {
        "global_entity_id": "GT_ENT_001_SYNDICATE",
        "canonical_token": _derive_canonical_token("ENT_GLOBAL_SYNDICATE_01"),
        "is_laundering": True,
        "typology": "THREE_WAY_SYNDICATE",
        "entity_type": "CORPORATION",
        "accounts": {
            "bank_a": "ACC_A_1001",
            "bank_b": "ACC_B_2001",
            "bank_c": "ACC_C_3001",
        },
    }
    entities.append(ent_syndicate)

    # --- Typology 2: Structuring & Smurfing Layering (Linked across Bank A and Bank B) ---
    ent_smurf = {
        "global_entity_id": "GT_ENT_002_SMURF_AB",
        "canonical_token": _derive_canonical_token("ENT_GLOBAL_SMURF_02"),
        "is_laundering": True,
        "typology": "STRUCTURING_SMURFING",
        "entity_type": "INDIVIDUAL",
        "accounts": {
            "bank_a": "ACC_A_1002",
            "bank_b": "ACC_B_2002",
        },
    }
    entities.append(ent_smurf)

    # --- Typology 3: Fan-In / Fan-Out Rapid Layering (Linked across Bank B and Bank C) ---
    ent_fan = {
        "global_entity_id": "GT_ENT_003_FAN_BC",
        "canonical_token": _derive_canonical_token("ENT_GLOBAL_FAN_03"),
        "is_laundering": True,
        "typology": "FAN_IN_OUT_LAYERING",
        "entity_type": "CORPORATION",
        "accounts": {
            "bank_b": "ACC_B_2003",
            "bank_c": "ACC_C_3003",
        },
    }
    entities.append(ent_fan)

    # --- Typology 4: Shell Company Routing (Linked across Bank A and Bank C) ---
    ent_shell = {
        "global_entity_id": "GT_ENT_004_SHELL_AC",
        "canonical_token": _derive_canonical_token("ENT_GLOBAL_SHELL_04"),
        "is_laundering": True,
        "typology": "SHELL_ROUTING",
        "entity_type": "CORPORATION",
        "accounts": {
            "bank_a": "ACC_A_1004",
            "bank_c": "ACC_C_3004",
        },
    }
    entities.append(ent_shell)

    # --- Control Case: Benign Cross-Bank Commercial Entity (Bank A and Bank B, NOT LAUNDERING) ---
    ent_benign_ab = {
        "global_entity_id": "GT_ENT_005_BENIGN_CORP_AB",
        "canonical_token": _derive_canonical_token("ENT_GLOBAL_BENIGN_05"),
        "is_laundering": False,
        "typology": "BENIGN_COMMERCIAL",
        "entity_type": "CORPORATION",
        "accounts": {
            "bank_a": "ACC_A_1005",
            "bank_b": "ACC_B_2005",
        },
    }
    entities.append(ent_benign_ab)

    # --- Bank-Exclusive Entities (No Cross-Bank Linkage) ---
    for i in range(1, 11):
        # Bank A exclusive
        entities.append({
            "global_entity_id": f"GT_ENT_A_LOCAL_{i:02d}",
            "canonical_token": _derive_canonical_token(f"ENT_LOCAL_A_{i:02d}"),
            "is_laundering": False,
            "typology": "BENIGN_RETAIL",
            "entity_type": "INDIVIDUAL",
            "accounts": {"bank_a": f"ACC_A_{1100 + i}"},
        })
        # Bank B exclusive
        entities.append({
            "global_entity_id": f"GT_ENT_B_LOCAL_{i:02d}",
            "canonical_token": _derive_canonical_token(f"ENT_LOCAL_B_{i:02d}"),
            "is_laundering": False,
            "typology": "BENIGN_RETAIL",
            "entity_type": "INDIVIDUAL",
            "accounts": {"bank_b": f"ACC_B_{2100 + i}"},
        })
        # Bank C exclusive
        entities.append({
            "global_entity_id": f"GT_ENT_C_LOCAL_{i:02d}",
            "canonical_token": _derive_canonical_token(f"ENT_LOCAL_C_{i:02d}"),
            "is_laundering": False,
            "typology": "BENIGN_RETAIL",
            "entity_type": "INDIVIDUAL",
            "accounts": {"bank_c": f"ACC_C_{3100 + i}"},
        })

    # Add 1 local laundering entity per bank (detected solely locally)
    entities.append({
        "global_entity_id": "GT_ENT_A_LOCAL_LAUNDER",
        "canonical_token": _derive_canonical_token("ENT_LOCAL_A_LAUNDER"),
        "is_laundering": True,
        "typology": "LOCAL_STRUCTURING",
        "entity_type": "INDIVIDUAL",
        "accounts": {"bank_a": "ACC_A_1199"},
    })
    entities.append({
        "global_entity_id": "GT_ENT_B_LOCAL_LAUNDER",
        "canonical_token": _derive_canonical_token("ENT_LOCAL_B_LAUNDER"),
        "is_laundering": True,
        "typology": "LOCAL_VELOCITY_CHURN",
        "entity_type": "INDIVIDUAL",
        "accounts": {"bank_b": "ACC_B_2199"},
    })
    entities.append({
        "global_entity_id": "GT_ENT_C_LOCAL_LAUNDER",
        "canonical_token": _derive_canonical_token("ENT_LOCAL_C_LAUNDER"),
        "is_laundering": True,
        "typology": "LOCAL_DORMANT_SURGE",
        "entity_type": "INDIVIDUAL",
        "accounts": {"bank_c": "ACC_C_3199"},
    })

    # ─────────────────────────────────────────────────────────────────────────
    # 2. LOCAL ENTITIES CSV GENERATION (NO GROUND TRUTH LABELS)
    # ─────────────────────────────────────────────────────────────────────────
    bank_entities: Dict[str, List[Dict[str, str]]] = {
        "bank_a": [],
        "bank_b": [],
        "bank_c": [],
    }

    for ent in entities:
        for bank_key, acc_id in ent["accounts"].items():
            # Local operational KYC risk score (noisy local indicator, NOT ground truth)
            if ent["is_laundering"]:
                local_score = round(random.uniform(0.55, 0.92), 3)
            else:
                local_score = round(random.uniform(0.05, 0.40), 3)

            bank_entities[bank_key].append({
                "local_account_id": acc_id,
                "canonical_token": ent["canonical_token"],
                "entity_type": ent["entity_type"],
                "account_opened_date": "2023-04-12",
                "kyc_risk_score": str(local_score),
            })

    for bank_key, rows in bank_entities.items():
        bank_dir = output_dir / bank_key
        ent_file = bank_dir / "local_entities.csv"
        with open(ent_file, "w", encoding="utf-8") as f:
            f.write("local_account_id,canonical_token,entity_type,account_opened_date,kyc_risk_score\n")
            for r in rows:
                f.write(f"{r['local_account_id']},{r['canonical_token']},{r['entity_type']},{r['account_opened_date']},{r['kyc_risk_score']}\n")

    # ─────────────────────────────────────────────────────────────────────────
    # 3. TRANSACTIONS GENERATION (BANK-LOCAL CSVs & EVALUATION LABELS)
    # ─────────────────────────────────────────────────────────────────────────
    bank_txs: Dict[str, List[Dict[str, Any]]] = {
        "bank_a": [],
        "bank_b": [],
        "bank_c": [],
    }
    eval_tx_labels: Dict[str, Dict[str, Any]] = {}

    tx_counter = {"bank_a": 1, "bank_b": 1, "bank_c": 1}

    def add_tx(
        bank_key: str,
        from_acc: str,
        to_acc: str,
        amount: float,
        tx_type: str,
        timestamp: str,
        is_laundering: bool,
        typology: str,
        pattern_id: str,
    ):
        idx = tx_counter[bank_key]
        tx_counter[bank_key] += 1
        tx_id = f"TX_{bank_key.upper()}_{idx:05d}"

        # Bank local row (Operational: NO LABELS)
        bank_txs[bank_key].append({
            "transaction_id": tx_id,
            "timestamp": timestamp,
            "from_account_id": from_acc,
            "to_account_id": to_acc,
            "amount": f"{amount:.2f}",
            "currency": "USD",
            "tx_type": tx_type,
        })

        # Evaluation label (Isolated in ground truth)
        eval_tx_labels[tx_id] = {
            "is_laundering": is_laundering,
            "typology": typology,
            "pattern_id": pattern_id,
            "bank_id": bank_key,
        }

    # Flow A: Syndicate Layering across Banks A, B, and C
    # Cash structuring in A -> Wire to B -> Wire to C -> External cash-out
    add_tx("bank_a", "EXT_CASH_01", "ACC_A_1001", 9800.00, "CASH_DEPOSIT", "2026-03-01T09:15:00Z", True, "THREE_WAY_SYNDICATE", "PAT_SYNDICATE_01")
    add_tx("bank_a", "EXT_CASH_02", "ACC_A_1001", 9750.00, "CASH_DEPOSIT", "2026-03-01T11:30:00Z", True, "THREE_WAY_SYNDICATE", "PAT_SYNDICATE_01")
    add_tx("bank_a", "ACC_A_1001", "EXT_CORP_B_WIRE", 19500.00, "WIRE", "2026-03-01T14:00:00Z", True, "THREE_WAY_SYNDICATE", "PAT_SYNDICATE_01")

    add_tx("bank_b", "EXT_CORP_A_WIRE", "ACC_B_2001", 19500.00, "WIRE", "2026-03-01T14:05:00Z", True, "THREE_WAY_SYNDICATE", "PAT_SYNDICATE_01")
    add_tx("bank_b", "ACC_B_2001", "EXT_CORP_C_WIRE", 19200.00, "WIRE", "2026-03-01T16:20:00Z", True, "THREE_WAY_SYNDICATE", "PAT_SYNDICATE_01")

    add_tx("bank_c", "EXT_CORP_B_WIRE", "ACC_C_3001", 19200.00, "WIRE", "2026-03-01T16:25:00Z", True, "THREE_WAY_SYNDICATE", "PAT_SYNDICATE_01")
    add_tx("bank_c", "ACC_C_3001", "EXT_OFFSHORE_HAVEN", 18900.00, "WIRE", "2026-03-02T10:00:00Z", True, "THREE_WAY_SYNDICATE", "PAT_SYNDICATE_01")

    # Flow B: Smurf Structuring between Bank A and Bank B
    for i in range(3):
        ts = f"2026-03-02T{10+i}:00:00Z"
        add_tx("bank_a", f"EXT_SMURF_ATM_{i}", "ACC_A_1002", 9200.00, "CASH_DEPOSIT", ts, True, "STRUCTURING_SMURFING", "PAT_SMURF_02")
    add_tx("bank_a", "ACC_A_1002", "EXT_WIRE_B", 27000.00, "WIRE", "2026-03-02T15:30:00Z", True, "STRUCTURING_SMURFING", "PAT_SMURF_02")
    add_tx("bank_b", "EXT_WIRE_A", "ACC_B_2002", 27000.00, "WIRE", "2026-03-02T15:35:00Z", True, "STRUCTURING_SMURFING", "PAT_SMURF_02")

    # Flow C: Fan-In / Fan-Out between Bank B and Bank C
    add_tx("bank_b", "ACC_B_2101", "ACC_B_2003", 14500.00, "INTERNAL_TRANSFER", "2026-03-03T09:00:00Z", True, "FAN_IN_OUT_LAYERING", "PAT_FAN_03")
    add_tx("bank_b", "ACC_B_2102", "ACC_B_2003", 13200.00, "INTERNAL_TRANSFER", "2026-03-03T09:10:00Z", True, "FAN_IN_OUT_LAYERING", "PAT_FAN_03")
    add_tx("bank_b", "ACC_B_2003", "EXT_WIRE_C", 27500.00, "WIRE", "2026-03-03T11:00:00Z", True, "FAN_IN_OUT_LAYERING", "PAT_FAN_03")

    add_tx("bank_c", "EXT_WIRE_B", "ACC_C_3003", 27500.00, "WIRE", "2026-03-03T11:05:00Z", True, "FAN_IN_OUT_LAYERING", "PAT_FAN_03")
    add_tx("bank_c", "ACC_C_3003", "ACC_C_3101", 13500.00, "INTERNAL_TRANSFER", "2026-03-03T13:00:00Z", True, "FAN_IN_OUT_LAYERING", "PAT_FAN_03")
    add_tx("bank_c", "ACC_C_3003", "ACC_C_3102", 13800.00, "INTERNAL_TRANSFER", "2026-03-03T13:10:00Z", True, "FAN_IN_OUT_LAYERING", "PAT_FAN_03")

    # Flow D: Shell Routing between Bank A and Bank C
    add_tx("bank_a", "ACC_A_1004", "EXT_WIRE_C", 45000.00, "WIRE", "2026-03-04T08:30:00Z", True, "SHELL_ROUTING", "PAT_SHELL_04")
    add_tx("bank_c", "EXT_WIRE_A", "ACC_C_3004", 45000.00, "WIRE", "2026-03-04T08:35:00Z", True, "SHELL_ROUTING", "PAT_SHELL_04")

    # Control Flow E: Benign Commercial Settlement between Bank A and Bank B (NOT LAUNDERING)
    add_tx("bank_a", "ACC_A_1005", "EXT_SUPPLIER_PAY", 5420.50, "ACH", "2026-03-04T10:00:00Z", False, "BENIGN_COMMERCIAL", "PAT_BENIGN_05")
    add_tx("bank_b", "EXT_CUSTOMER_RECEIPT", "ACC_B_2005", 5420.50, "ACH", "2026-03-04T10:05:00Z", False, "BENIGN_COMMERCIAL", "PAT_BENIGN_05")

    # Local Benign Background Transactions
    for i in range(1, 11):
        add_tx("bank_a", f"ACC_A_{1100+i}", "EXT_MERCHANT", round(random.uniform(25.0, 450.0), 2), "POS", "2026-03-04T12:00:00Z", False, "BENIGN_RETAIL", f"PAT_RETAIL_A_{i}")
        add_tx("bank_b", f"ACC_B_{2100+i}", "EXT_MERCHANT", round(random.uniform(25.0, 450.0), 2), "POS", "2026-03-04T12:00:00Z", False, "BENIGN_RETAIL", f"PAT_RETAIL_B_{i}")
        add_tx("bank_c", f"ACC_C_{3100+i}", "EXT_MERCHANT", round(random.uniform(25.0, 450.0), 2), "POS", "2026-03-04T12:00:00Z", False, "BENIGN_RETAIL", f"PAT_RETAIL_C_{i}")

    # Local Laundering Transactions (1 per bank, purely local)
    add_tx("bank_a", "EXT_CASH", "ACC_A_1199", 9500.00, "CASH_DEPOSIT", "2026-03-05T09:00:00Z", True, "LOCAL_STRUCTURING", "PAT_LOCAL_A")
    add_tx("bank_b", "ACC_B_2199", "EXT_WIRE", 18500.00, "WIRE", "2026-03-05T10:00:00Z", True, "LOCAL_VELOCITY_CHURN", "PAT_LOCAL_B")
    add_tx("bank_c", "EXT_WIRE", "ACC_C_3199", 22000.00, "WIRE", "2026-03-05T11:00:00Z", True, "LOCAL_DORMANT_SURGE", "PAT_LOCAL_C")

    # Write Bank Transactions CSVs
    for bank_key, rows in bank_txs.items():
        bank_dir = output_dir / bank_key
        tx_file = bank_dir / "transactions.csv"
        with open(tx_file, "w", encoding="utf-8") as f:
            f.write("transaction_id,timestamp,from_account_id,to_account_id,amount,currency,tx_type\n")
            for r in rows:
                f.write(f"{r['transaction_id']},{r['timestamp']},{r['from_account_id']},{r['to_account_id']},{r['amount']},{r['currency']},{r['tx_type']}\n")

    # ─────────────────────────────────────────────────────────────────────────
    # 4. WRITE EVALUATION GROUND TRUTH (ISOLATED)
    # ─────────────────────────────────────────────────────────────────────────
    tokens_a = {r["canonical_token"] for r in bank_entities["bank_a"]}
    tokens_b = {r["canonical_token"] for r in bank_entities["bank_b"]}
    tokens_c = {r["canonical_token"] for r in bank_entities["bank_c"]}

    overlap_ab = sorted(tokens_a & tokens_b)
    overlap_bc = sorted(tokens_b & tokens_c)
    overlap_ac = sorted(tokens_a & tokens_c)
    overlap_abc = sorted(tokens_a & tokens_b & tokens_c)

    eval_entities_payload = {
        "metadata": {
            "description": "Evaluation-only ground-truth mapping. STRICTLY FORBIDDEN to be read by operational modules.",
            "seed": seed,
            "bank_token_counts": {
                "bank_a": len(tokens_a),
                "bank_b": len(tokens_b),
                "bank_c": len(tokens_c),
            },
            "expected_pairwise_psi_overlaps": {
                "bank_a_and_bank_b": overlap_ab,
                "bank_b_and_bank_c": overlap_bc,
                "bank_a_and_bank_c": overlap_ac,
                "all_three": overlap_abc,
            },
        },
        "entities": entities,
    }

    eval_ent_file = dir_eval / "ground_truth_entities.json"
    with open(eval_ent_file, "w", encoding="utf-8") as f:
        json.dump(eval_entities_payload, f, indent=2)

    eval_tx_file = dir_eval / "ground_truth_transactions.json"
    with open(eval_tx_file, "w", encoding="utf-8") as f:
        json.dump(eval_tx_labels, f, indent=2)

    summary = {
        "status": "success",
        "output_dir": str(output_dir),
        "seed": seed,
        "bank_counts": {
            "bank_a": {"entities": len(bank_entities["bank_a"]), "transactions": len(bank_txs["bank_a"])},
            "bank_b": {"entities": len(bank_entities["bank_b"]), "transactions": len(bank_txs["bank_b"])},
            "bank_c": {"entities": len(bank_entities["bank_c"]), "transactions": len(bank_txs["bank_c"])},
        },
        "pairwise_overlap_counts": {
            "bank_a_and_bank_b": len(overlap_ab),
            "bank_b_and_bank_c": len(overlap_bc),
            "bank_a_and_bank_c": len(overlap_ac),
            "all_three": len(overlap_abc),
        },
    }
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate synthetic AML multi-bank dataset")
    parser.add_argument("--output-dir", default="./data", help="Output directory (default: ./data)")
    parser.add_argument("--seed", type=int, default=42, help="Deterministic random seed (default: 42)")
    args = parser.parse_args()

    result = generate_synthetic_aml_data(Path(args.output_dir), seed=args.seed)
    print(json.dumps(result, indent=2))
