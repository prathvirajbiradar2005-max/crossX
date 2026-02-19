"""
cycles.py — Circular Fund Routing detection.

Detects directed cycles of length 3–5 in the transaction graph, which is
the most classic "Money Muling" signature: A → B → C → A.

In legitimate commerce, money rarely travels in a perfect circle back to
the originator within a short time window.
"""

from __future__ import annotations

import networkx as nx
from typing import Dict, List, Set, Tuple
from collections import defaultdict


# ── Public API ───────────────────────────────────────────────────────────────

def detect_cycles(
    simple_graph: nx.DiGraph,
    min_length: int = 3,
    max_length: int = 5,
) -> Dict[str, object]:
    """Find all simple directed cycles of length *min_length* to *max_length*.

    Parameters
    ----------
    simple_graph : nx.DiGraph
        The collapsed (simple) directed graph built by
        ``graph_builder.build_simple_digraph``.
    min_length, max_length : int
        Inclusive bounds on cycle length.

    Returns
    -------
    dict with keys:
        cycles : list[list[str]]
            Each inner list is an ordered sequence of account IDs forming the
            cycle (the last node connects back to the first).
        cycle_accounts : set[str]
            All accounts that participate in at least one cycle.
        account_cycle_count : dict[str, int]
            Number of distinct cycles each account belongs to.
        rings : list[dict]
            Pre-grouped fraud-ring descriptors (see ``_group_into_rings``).
    """
    raw_cycles = _find_bounded_cycles(simple_graph, min_length, max_length)

    cycle_accounts: Set[str] = set()
    account_cycle_count: Dict[str, int] = defaultdict(int)

    for cycle in raw_cycles:
        for node in cycle:
            cycle_accounts.add(node)
            account_cycle_count[node] += 1

    rings = _group_into_rings(raw_cycles, simple_graph)

    return {
        "cycles": raw_cycles,
        "cycle_accounts": cycle_accounts,
        "account_cycle_count": dict(account_cycle_count),
        "rings": rings,
    }


# ── Internal helpers ─────────────────────────────────────────────────────────

def _find_bounded_cycles(
    G: nx.DiGraph,
    min_len: int,
    max_len: int,
) -> List[List[str]]:
    """Return simple cycles whose length is in [min_len, max_len].

    Uses Johnson's algorithm via ``nx.simple_cycles`` with a length_bound
    (available in NetworkX ≥ 3.1) for efficiency.  Falls back to a manual
    filter on older versions.
    """
    found: List[List[str]] = []

    try:
        # NetworkX ≥ 3.1 supports length_bound kwarg
        for cycle in nx.simple_cycles(G, length_bound=max_len):
            if min_len <= len(cycle) <= max_len:
                found.append(list(cycle))
    except TypeError:
        # Fallback for older NetworkX without length_bound
        for cycle in nx.simple_cycles(G):
            clen = len(cycle)
            if min_len <= clen <= max_len:
                found.append(list(cycle))
            # Early exit heuristic: cycles above max_len are uninteresting
            # but Johnson's yields them all — we just skip.

    return found


def _group_into_rings(
    cycles: List[List[str]],
    G: nx.DiGraph,
) -> List[Dict]:
    """Merge overlapping cycles into fraud rings via Union-Find.

    Two cycles that share at least one account are merged into the same
    ring.  Each ring gets an auto-generated ``RING_xxx`` ID.

    Returns a list of ring descriptors:
        ring_id, member_accounts, cycle_lengths, pattern_type, risk_score
    """
    if not cycles:
        return []

    # ── Union-Find ────────────────────────────────────────────────────────
    parent: Dict[str, str] = {}

    def find(x: str) -> str:
        while parent.get(x, x) != x:
            parent[x] = parent.get(parent[x], parent[x])  # path compression
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    # Union all nodes within each cycle
    for cycle in cycles:
        for node in cycle[1:]:
            union(cycle[0], node)

    # Group accounts by root
    ring_groups: Dict[str, Set[str]] = defaultdict(set)
    all_cycle_nodes = {n for c in cycles for n in c}
    for node in all_cycle_nodes:
        ring_groups[find(node)].add(node)

    # Map each cycle to its ring root
    ring_cycle_lengths: Dict[str, List[int]] = defaultdict(list)
    for cycle in cycles:
        root = find(cycle[0])
        ring_cycle_lengths[root].append(len(cycle))

    # ── Build ring descriptors ────────────────────────────────────────────
    rings: List[Dict] = []
    for idx, (root, members) in enumerate(
        sorted(ring_groups.items(), key=lambda kv: -len(kv[1])), start=1
    ):
        ring_id = f"RING_{idx:03d}"
        cycle_lens = ring_cycle_lengths[root]

        # Risk heuristic: longer cycles & more cycles → higher risk
        base_risk = min(100.0, 50.0 + 10.0 * len(cycle_lens) + 5.0 * max(cycle_lens))

        # Boost if total amount flowing within the ring is high
        internal_amount = 0.0
        for u, v, edata in G.edges(data=True):
            if u in members and v in members:
                internal_amount += edata.get("total_amount", 0.0)
        amount_boost = min(20.0, internal_amount / 10_000.0)
        risk_score = round(min(100.0, base_risk + amount_boost), 1)

        rings.append(
            {
                "ring_id": ring_id,
                "member_accounts": sorted(members),
                "cycle_lengths": sorted(set(cycle_lens)),
                "pattern_type": "cycle",
                "risk_score": risk_score,
            }
        )

    return rings
