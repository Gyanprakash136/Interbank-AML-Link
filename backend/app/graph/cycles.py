"""Linear-time directed-cycle membership.

Replaces ``any(account_id in c for c in nx.simple_cycles(G))``, which enumerates every
cycle in the graph for every account (exponential in the worst case).

A node lies on a directed cycle iff its strongly connected component has more than
one node, or it has a self-loop. Equivalent to the brute-force definition; see
tests/unit/test_cycles.py.
"""

from typing import Set

import networkx as nx


def nodes_on_directed_cycles(G: nx.Graph) -> Set[str]:
    members: Set[str] = set()
    for component in nx.strongly_connected_components(G):
        if len(component) > 1:
            members.update(component)
    members.update(nx.nodes_with_selfloops(G))
    return members
