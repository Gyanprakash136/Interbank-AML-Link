import random

import networkx as nx

from app.graph.cycles import nodes_on_directed_cycles


def brute_force(G):
    return {n for cycle in nx.simple_cycles(G) for n in cycle}


def test_basic_shapes():
    G = nx.MultiDiGraph()
    G.add_edges_from([("a", "b"), ("b", "a"), ("b", "c"), ("c", "d"), ("d", "d")])
    G.add_node("lonely")
    assert nodes_on_directed_cycles(G) == {"a", "b", "d"}


def test_parallel_edges_are_not_a_cycle():
    G = nx.MultiDiGraph()
    G.add_edge("x", "y", key="t1")
    G.add_edge("x", "y", key="t2")
    assert nodes_on_directed_cycles(G) == set()


def test_longer_cycle_and_tail():
    G = nx.MultiDiGraph()
    G.add_edges_from([(1, 2), (2, 3), (3, 1), (3, 4), (0, 1)])
    assert nodes_on_directed_cycles(G) == {1, 2, 3}


def test_matches_brute_force_on_random_multigraphs():
    for seed in range(300):
        rng = random.Random(seed)
        G = nx.MultiDiGraph()
        G.add_nodes_from(range(rng.randint(1, 8)))
        n = G.number_of_nodes()
        for i in range(rng.randint(0, 20)):
            G.add_edge(rng.randrange(n), rng.randrange(n), key=f"t{i}")
        assert nodes_on_directed_cycles(G) == brute_force(G), f"seed {seed}"
