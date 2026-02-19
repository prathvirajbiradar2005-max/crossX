"""
shell_network.py — Layered Shell / Pass-Through Network detection.

Detects relay-chain patterns where intermediate "shell" accounts receive
funds and immediately forward them onward, retaining almost nothing.

Signature
---------
Node B receives $5 000 from A and sends $4 990 to C within 2 hours.
B has very few total connections (exists *only* to relay this money).

Detection approach
------------------
1. Identify *pass-through* nodes: nodes whose net-flow ≈ 0 (the money
   entering ≈ money leaving) and with low total degree.
2. Trace chains of ≥ 3 such pass-through hops.
3. Score chains by length, speed, and retention ratio.
"""

from __future__ import annotations

import networkx as nx
import pandas as pd
import numpy as np
from typing import Dict, List, Set, Tuple
from collections import defaultdict


# ── Configurable thresholds ──────────────────────────────────────────────────
PERSISTENCE_THRESHOLD: float = 0.05     # max |net_flow| / throughput ratio
MAX_DEGREE: int = 6                     # max total degree for a "shell" node
RELAY_HOURS: float = 24.0               # time window for pass-through (hours)
MIN_CHAIN_LENGTH: int = 3               # minimum hops in a shell chain


# ── Public API ───────────────────────────────────────────────────────────────

def detect_shell_networks(
    multi_graph: nx.MultiDiGraph,
    simple_graph: nx.DiGraph,
    df: pd.DataFrame,
    persistence_threshold: float = PERSISTENCE_THRESHOLD,
    max_degree: int = MAX_DEGREE,
    relay_hours: float = RELAY_HOURS,
    min_chain_length: int = MIN_CHAIN_LENGTH,
) -> Dict[str, object]:
    """Detect layered shell / pass-through networks.

    Parameters
    ----------
    multi_graph : nx.MultiDiGraph
        Full graph with per-transaction edge data.
    simple_graph : nx.DiGraph
        Collapsed directed graph.
    df : pd.DataFrame
        Cleaned transaction DataFrame.
    persistence_threshold : float
        Maximum |net_flow| / throughput ratio to qualify as pass-through.
    max_degree : int
        Maximum total degree for a pass-through node.
    relay_hours : float
        Maximum hours between inbound and outbound transactions for relay.
    min_chain_length : int
        Minimum number of hops to form a shell chain.

    Returns
    -------
    dict with keys:
        passthrough_nodes : set[str]
        chains : list[list[str]]
        shell_accounts : set[str]
        rings : list[dict]
    """
    passthrough_nodes = _identify_passthrough_nodes(
        multi_graph, simple_graph, df,
        persistence_threshold, max_degree, relay_hours,
    )

    chains = _trace_chains(simple_graph, passthrough_nodes, min_chain_length)

    shell_accounts: Set[str] = set()
    for chain in chains:
        shell_accounts.update(chain)

    rings = _build_shell_rings(chains, simple_graph)

    return {
        "passthrough_nodes": passthrough_nodes,
        "chains": chains,
        "shell_accounts": shell_accounts,
        "rings": rings,
    }


# ── Internal helpers ─────────────────────────────────────────────────────────

def _identify_passthrough_nodes(
    G: nx.MultiDiGraph,
    S: nx.DiGraph,
    df: pd.DataFrame,
    persistence_threshold: float,
    max_degree: int,
    relay_hours: float,
) -> Set[str]:
    """Find nodes that act as transparent relays."""
    passthrough: Set[str] = set()

    for node, ndata in G.nodes(data=True):
        total_sent = ndata.get("total_sent", 0.0)
        total_received = ndata.get("total_received", 0.0)
        throughput = total_sent + total_received

        if throughput == 0:
            continue

        # Persistence: how much money does the node "keep"?
        net_flow = abs(ndata.get("net_flow", 0.0))
        persistence = net_flow / throughput

        if persistence > persistence_threshold:
            continue

        # Degree check: shell accounts are low-profile
        total_degree = G.in_degree(node) + G.out_degree(node)
        if total_degree > max_degree:
            continue

        # Must have both inbound AND outbound
        if G.in_degree(node) == 0 or G.out_degree(node) == 0:
            continue

        # Timing check: money is relayed quickly
        if _has_quick_relay(df, node, relay_hours):
            passthrough.add(node)

    return passthrough


def _has_quick_relay(
    df: pd.DataFrame,
    node: str,
    relay_hours: float,
) -> bool:
    """Check if *node* has at least one fast receive-then-send pattern."""
    inbound = df.loc[df["receiver_id"] == node, "timestamp"].sort_values()
    outbound = df.loc[df["sender_id"] == node, "timestamp"].sort_values()

    if inbound.empty or outbound.empty:
        return False

    window = pd.Timedelta(hours=relay_hours)

    # For each inbound tx, see if any outbound tx follows within the window
    for in_ts in inbound:
        mask = (outbound >= in_ts) & (outbound <= in_ts + window)
        if mask.any():
            return True

    return False


def _trace_chains(
    S: nx.DiGraph,
    passthrough_nodes: Set[str],
    min_length: int,
) -> List[List[str]]:
    """Trace maximal directed chains through pass-through nodes.

    A chain is a path where every *intermediate* node is a pass-through
    node.  The first and last nodes in the chain may or may not be
    pass-through (they are the "source" and "sink" of the layered network).
    """
    chains: List[List[str]] = []

    # Start DFS from every pass-through node that has predecessors outside
    # the pass-through set (potential chain heads).
    visited_chains: Set[tuple] = set()

    for start in passthrough_nodes:
        for path in _dfs_chains(S, start, passthrough_nodes, min_length, max_depth=8):
            key = tuple(path)
            if key not in visited_chains:
                visited_chains.add(key)
                chains.append(path)

    # Also try starting from non-passthrough nodes that feed into passthrough
    for pt_node in passthrough_nodes:
        for pred in S.predecessors(pt_node):
            if pred not in passthrough_nodes:
                for path in _dfs_chains(S, pred, passthrough_nodes, min_length, max_depth=8, allow_non_pt_start=True):
                    key = tuple(path)
                    if key not in visited_chains:
                        visited_chains.add(key)
                        chains.append(path)

    return chains


def _dfs_chains(
    S: nx.DiGraph,
    start: str,
    passthrough_nodes: Set[str],
    min_length: int,
    max_depth: int = 8,
    allow_non_pt_start: bool = False,
) -> List[List[str]]:
    """Yield all chains starting from *start* that pass through pass-through nodes."""
    results: List[List[str]] = []

    stack: List[Tuple[str, List[str]]] = [(start, [start])]

    while stack:
        current, path = stack.pop()

        extended = False
        for successor in S.successors(current):
            if successor in path:
                continue  # no revisiting
            if len(path) >= max_depth:
                continue

            # Intermediate nodes must be pass-through; endpoint can be anything
            if successor in passthrough_nodes:
                stack.append((successor, path + [successor]))
                extended = True
            else:
                # End of chain (non-passthrough sink)
                candidate = path + [successor]
                if len(candidate) >= min_length:
                    results.append(candidate)

        # If we couldn't extend and current chain is long enough, record it
        if not extended and len(path) >= min_length:
            results.append(path)

    return results


def _build_shell_rings(
    chains: List[List[str]],
    S: nx.DiGraph,
) -> List[Dict]:
    """Group overlapping chains into shell-network ring descriptors."""
    if not chains:
        return []

    # Union-Find to merge overlapping chains
    parent: Dict[str, str] = {}

    def find(x: str) -> str:
        while parent.get(x, x) != x:
            parent[x] = parent.get(parent[x], parent[x])
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    for chain in chains:
        for node in chain[1:]:
            union(chain[0], node)

    groups: Dict[str, Set[str]] = defaultdict(set)
    all_nodes = {n for c in chains for n in c}
    for node in all_nodes:
        groups[find(node)].add(node)

    rings: List[Dict] = []
    for idx, (root, members) in enumerate(
        sorted(groups.items(), key=lambda kv: -len(kv[1])), start=1
    ):
        chain_lens = [len(c) for c in chains if set(c) & members]
        max_len = max(chain_lens) if chain_lens else 0
        risk = round(min(100.0, 40.0 + 8.0 * max_len + 5.0 * len(chain_lens)), 1)

        rings.append(
            {
                "ring_id": f"SHELL_{idx:03d}",
                "member_accounts": sorted(members),
                "pattern_type": "shell_network",
                "risk_score": risk,
                "max_chain_length": max_len,
            }
        )

    return rings
