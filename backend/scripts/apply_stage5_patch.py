"""Applies the small, reviewed edits to existing files. Run from the repo root:

    python backend/scripts/apply_stage5_patch.py          # apply
    python backend/scripts/apply_stage5_patch.py --check  # report only

Safety: every edit must match EXACTLY ONCE or nothing is written. Already-applied
edits are detected and skipped, so the script is idempotent.

Edits
  backend/app/graph/features.py
    - replace per-account ``nx.simple_cycles`` enumeration (exponential, once per
      account) with a linear-time SCC check computed once per graph.
      Behaviour is identical (tests/unit/test_cycles.py).
  backend/app/banks/local_agent.py
    - import ``Set`` (it was used in an annotation but never imported).
"""

import sys
from pathlib import Path

EDITS = {
    "backend/app/graph/features.py": [
        (
            "from typing import Any, Dict, List, Optional\nimport networkx as nx\n",
            "from typing import Any, Dict, List, Optional, Set\nimport networkx as nx\n\n"
            "from app.graph.cycles import nodes_on_directed_cycles\n",
        ),
        (
            "    def extract_for_account(self, G: nx.MultiDiGraph, account_id: str) -> LocalAccountFeatures:\n",
            "    def extract_for_account(\n"
            "        self,\n"
            "        G: nx.MultiDiGraph,\n"
            "        account_id: str,\n"
            "        cycle_nodes: Optional[Set[str]] = None,\n"
            "    ) -> LocalAccountFeatures:\n",
        ),
        (
            "        participates_cycle = False\n"
            "        try:\n"
            "            # Check if account is in a directed cycle\n"
            "            participates_cycle = any(account_id in c for c in nx.simple_cycles(G))\n"
            "        except Exception:\n"
            "            participates_cycle = False\n",
            "        # Linear-time SCC membership; pass cycle_nodes to avoid recomputing per account.\n"
            "        if cycle_nodes is None:\n"
            "            cycle_nodes = nodes_on_directed_cycles(G)\n"
            "        participates_cycle = account_id in cycle_nodes\n",
        ),
        (
            "        results = {}\n"
            "        for node_id, data in G.nodes(data=True):\n"
            "            if data.get(\"is_local\", False):\n"
            "                results[node_id] = self.extract_for_account(G, node_id)\n"
            "        return results",
            "        results = {}\n"
            "        cycle_nodes = nodes_on_directed_cycles(G)  # once per graph\n"
            "        for node_id, data in G.nodes(data=True):\n"
            "            if data.get(\"is_local\", False):\n"
            "                results[node_id] = self.extract_for_account(G, node_id, cycle_nodes=cycle_nodes)\n"
            "        return results",
        ),
    ],
    "backend/app/banks/local_agent.py": [
        (
            "from typing import Dict, List, Optional, Sequence\n",
            "from typing import Dict, List, Optional, Sequence, Set\n",
        ),
    ],
}


def main() -> int:
    check_only = "--check" in sys.argv
    pending = {}
    ok = True
    for rel, edits in EDITS.items():
        path = Path(rel)
        if not path.exists():
            print(f"MISSING  {rel} (run from the repo root)")
            return 2
        text = path.read_text(encoding="utf-8")
        for i, (old, new) in enumerate(edits, 1):
            if old in text and text.count(old) == 1:
                text = text.replace(old, new)
                print(f"WILL APPLY  {rel} edit {i}")
            elif new in text:
                print(f"ALREADY     {rel} edit {i}")
            else:
                print(f"NO MATCH    {rel} edit {i} (found {text.count(old)}x) - file differs from expected")
                ok = False
        pending[path] = text
    if not ok:
        print("\nNothing written. Send the output above and the relevant file section.")
        return 1
    if check_only:
        print("\n--check: nothing written.")
        return 0
    for path, text in pending.items():
        path.write_text(text, encoding="utf-8")
    print("\nPatch applied.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
