"""End-to-end: HI-Small CSV -> partition -> agent -> graph -> detection.

Guards against the failure modes found in the stage-5 audit: non-ISO timestamps
aborting the graph build, wrong filenames producing a silent empty graph, and
account naming that makes every node look external.
"""

import networkx as nx

from app.banks.local_agent import OperationalBankAgent
from app.banks.local_detection import LocalRuleDetectionEngine
from app.core.security import assert_opaque_tokens
from app.evaluation.partitioning import partition_hi_small

HEADER = ("Timestamp,From Bank,Account,To Bank,Account,Amount Received,Receiving Currency,"
          "Amount Paid,Payment Currency,Payment Format,Is Laundering")
ROWS = [
    "2022/09/01 00:20,010,A1,020,B1,9500.00,US Dollar,9500.00,US Dollar,Wire,1",
    "2022/09/01 00:50,010,A1,020,B1,9400.00,US Dollar,9400.00,US Dollar,Wire,1",
    "2022/09/01 01:15,020,B1,030,C1,9300.00,US Dollar,9300.00,US Dollar,Wire,1",
    "2022/09/01 02:40,010,A2,010,A3,150.00,US Dollar,150.00,US Dollar,Cash,0",
    "2022/09/02 04:00,030,C2,999,X1,80.00,Euro,80.00,Euro,ACH,0",
    "2022/09/03 06:10,020,B2,010,A1,80.00,Euro,80.00,Euro,Credit Card,0",
]
MAPPING = {"010": "bank_a", "020": "bank_b", "030": "bank_c"}


def test_partitioned_hi_small_flows_through_graph_and_detection(tmp_path):
    csv_path = tmp_path / "hs.csv"
    csv_path.write_text(HEADER + "\n" + "\n".join(ROWS) + "\n")
    out = tmp_path / "data"
    partition_hi_small(csv_path, out, MAPPING)

    for bank_id in MAPPING.values():
        agent = OperationalBankAgent(bank_id, data_dir=out)
        G = agent.build_local_graph()          # must not raise (ISO timestamps)
        assert isinstance(G, nx.MultiDiGraph)
        assert G.number_of_edges() > 0, f"{bank_id}: empty graph (silent file/naming failure)"
        local_nodes = [n for n, d in G.nodes(data=True) if d.get("is_local")]
        assert local_nodes, f"{bank_id}: no node recognised as local"
        assert all(n.startswith(f"ACC_{bank_id[-1].upper()}_") for n in local_nodes)

        tokens = agent.get_canonical_tokens()
        assert_opaque_tokens(tokens)

        alerts = LocalRuleDetectionEngine().evaluate_graph(G)
        assert len(alerts) == len(local_nodes)
