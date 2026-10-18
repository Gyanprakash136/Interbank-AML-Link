"""Profile and partition the public HI-Small CSV into bank-local data.

Run from the repo root with the project venv active, e.g.

  python backend/scripts/prepare_hi_small.py profile backend/data/raw/HI-Small_Trans.csv \
      --out backend/experiments/results/hi_small_profile.json

  python backend/scripts/prepare_hi_small.py partition backend/data/raw/HI-Small_Trans.csv \
      --out backend/data/hi_small_partitioned \
      --banks 010:bank_a,020:bank_b,030:bank_c --max-rows 200000

Bank ids in --banks are RAW HI-Small bank ids; choose them from the profile
(``top_banks_by_activity``), do not guess. Always keep --max-rows / time window in
mind: subset results must be labelled as subset results (the manifest records it).
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.evaluation.artifacts import write_json  # noqa: E402
from app.evaluation.dataset_validation import profile_csv  # noqa: E402
from app.evaluation.partitioning import partition_hi_small  # noqa: E402


def parse_banks(spec: str) -> dict:
    mapping = {}
    for pair in spec.split(","):
        raw, _, bank = pair.partition(":")
        if not raw or not bank:
            raise argparse.ArgumentTypeError(f"bad --banks entry '{pair}', expected RAW:bank_x")
        mapping[raw.strip()] = bank.strip()
    return mapping


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("profile", help="stream the CSV and write a data profile (JSON)")
    p1.add_argument("csv_path", type=Path)
    p1.add_argument("--out", type=Path, default=Path("hi_small_profile.json"))
    p1.add_argument("--chunksize", type=int, default=500_000)

    p2 = sub.add_parser("partition", help="write bank-local data + evaluation labels + manifest")
    p2.add_argument("csv_path", type=Path)
    p2.add_argument("--out", type=Path, required=True)
    p2.add_argument("--banks", type=parse_banks, required=True)
    p2.add_argument("--max-rows", type=int, default=None)
    p2.add_argument("--ts-from", default=None)
    p2.add_argument("--ts-to", default=None)
    p2.add_argument("--chunksize", type=int, default=500_000)
    p2.add_argument("--overwrite", action="store_true")

    args = ap.parse_args()
    if args.cmd == "profile":
        prof = profile_csv(args.csv_path, chunksize=args.chunksize)
        write_json(args.out, prof)
        print(f"profile -> {args.out}")
        for k in ("row_count", "sha256", "distinct_banks", "laundering_rate", "exact_duplicate_rows",
                  "rejected_rows_total", "unmapped_currency_names", "top_banks_by_activity"):
            print(f"  {k}: {prof[k]}")
    else:
        m = partition_hi_small(
            args.csv_path, args.out, args.banks, max_rows=args.max_rows, ts_from=args.ts_from,
            ts_to=args.ts_to, chunksize=args.chunksize, overwrite=args.overwrite,
        )
        print(f"partition -> {args.out}  ({m['subset_note']})")
        for k in ("counts", "rows_per_bank_file", "owned_accounts_per_bank",
                  "laundering_touched_owned_accounts", "reject_counts", "unmapped_currency_names",
                  "cross_bank_flow_counts"):
            print(f"  {k}: {m[k]}")


if __name__ == "__main__":
    main()
