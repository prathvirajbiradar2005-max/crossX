"""
community.py — Ring Networks / Community Detection + New Account Detection.

1. Community Detection (Louvain)
   Finds tightly connected clusters that may represent organized fraud rings.
   Uses Louvain community detection and Strongly Connected Components.

2. New Account Sudden Activity
   Flags accounts that are newly created (first seen recently) but
   suddenly have high transaction volume.
"""

from __future__ import annotations

import networkx as nx
import pandas as pd
import numpy as np
from typing import Dict, List, Set, Any
from collections import defaultdict
from datetime import timedelta


# ── Configurable thresholds ──────────────────────────────────────────────────
MIN_COMMUNITY_SIZE: int = 3             # minimum nodes in a suspicious community
MAX_COMMUNITY_SIZE: int = 30            # ignore huge "normal" communities
COMMUNITY_DENSITY_MIN: float = 0.3      # minimum internal edge density
SCC_MIN_SIZE: int = 3                   # min strongly connected component size

# New account thresholds
NEW_ACCOUNT_DAYS: float = 7.0           # account active < 7 days = "new"
NEW_ACCOUNT_MIN_TXN: int = 5            # minimum txns to flag as "sudden"
NEW_ACCOUNT_MIN_AMOUNT: float = 5000.0  # minimum total amount to flag


def detect_communities(
    G: nx.MultiDiGraph,
    simple_G: nx.DiGraph,
    df: pd.DataFrame,
    min_community: int = MIN_COMMUNITY_SIZE,
    max_community: int = MAX_COMMUNITY_SIZE,
    density_min: float = COMMUNITY_DENSITY_MIN,
    scc_min: int = SCC_MIN_SIZE,
) -> Dict[str, Any]:
    """Detect suspicious communities and strongly connected components.

    Parameters
    ----------
    G : nx.MultiDiGraph
        Full transaction multigraph.
    simple_G : nx.DiGraph
        Simple directed graph.
    df : pd.DataFrame
        Cleaned transaction DataFrame.

    Returns
    -------
    dict with keys:
        communities : list[dict]
            Suspicious communities with members, density, internal flow.
        scc_components : list[dict]
            Strongly connected components.
        community_accounts : set[str]
            All accounts in suspicious communities.
    """
    communities = _louvain_communities(G, simple_G, min_community, max_community, density_min)
    scc_components = _strongly_connected(simple_G, scc_min)

    community_accounts: Set[str] = set()
    for c in communities:
        community_accounts.update(c["members"])
    for c in scc_components:
        community_accounts.update(c["members"])

    return {
        "communities": communities,
        "scc_components": scc_components,
        "community_accounts": community_accounts,
    }


def detect_new_accounts(
    G: nx.MultiDiGraph,
    df: pd.DataFrame,
    max_age_days: float = NEW_ACCOUNT_DAYS,
    min_txn: int = NEW_ACCOUNT_MIN_TXN,
    min_amount: float = NEW_ACCOUNT_MIN_AMOUNT,
) -> Dict[str, Any]:
    """Detect newly created accounts with sudden high activity.

    Parameters
    ----------
    G : nx.MultiDiGraph
        Full transaction multigraph.
    df : pd.DataFrame
        Cleaned transaction DataFrame.
    max_age_days : float
        Maximum active days to count as "new".
    min_txn : int
        Minimum transaction count to flag.
    min_amount : float
        Minimum total amount to flag.

    Returns
    -------
    dict with keys:
        new_accounts : list[dict]
            Details per flagged new account.
        flagged_accounts : set[str]
    """
    flagged: List[Dict] = []
    flagged_accounts: Set[str] = set()

    for node, ndata in G.nodes(data=True):
        active_days = ndata.get("active_days", float("inf"))
        tx_count = ndata.get("tx_count", 0)
        total_sent = ndata.get("total_sent", 0)
        total_received = ndata.get("total_received", 0)
        total_volume = total_sent + total_received

        if active_days <= max_age_days and tx_count >= min_txn and total_volume >= min_amount:
            flagged.append({
                "account_id": node,
                "active_days": round(active_days, 1),
                "tx_count": tx_count,
                "total_volume": round(total_volume, 2),
                "total_sent": round(total_sent, 2),
                "total_received": round(total_received, 2),
            })
            flagged_accounts.add(node)

    # Sort by volume descending
    flagged.sort(key=lambda x: -x["total_volume"])

    return {
        "new_accounts": flagged,
        "flagged_accounts": flagged_accounts,
    }


# ── Internal helpers ─────────────────────────────────────────────────────────

def _louvain_communities(
    G: nx.MultiDiGraph,
    S: nx.DiGraph,
    min_size: int,
    max_size: int,
    density_min: float,
) -> List[Dict]:
    """Run Louvain community detection on the undirected projection."""
    # Convert to undirected for community detection
    U = G.to_undirected()

    try:
        # NetworkX >= 3.1 has community.louvain_communities
        communities_sets = nx.community.louvain_communities(U, seed=42)
    except AttributeError:
        # Fallback: use greedy modularity
        communities_sets = list(nx.community.greedy_modularity_communities(U))

    results = []
    for idx, members in enumerate(communities_sets, 1):
        members = set(members)
        if len(members) < min_size or len(members) > max_size:
            continue

        # Compute internal density
        subgraph = S.subgraph(members)
        n = len(members)
        max_edges = n * (n - 1)  # directed
        actual_edges = subgraph.number_of_edges()
        density = actual_edges / max_edges if max_edges > 0 else 0

        if density < density_min:
            continue

        # Compute internal flow
        internal_flow = sum(
            data.get("amount", 0)
            for u, v, data in G.edges(data=True)
            if u in members and v in members
        )

        results.append({
            "community_id": f"COMM_{idx:03d}",
            "members": sorted(members),
            "size": len(members),
            "density": round(density, 4),
            "internal_edges": actual_edges,
            "internal_flow": round(internal_flow, 2),
        })

    # Sort by density descending
    results.sort(key=lambda x: -x["density"])
    return results


def _strongly_connected(
    S: nx.DiGraph,
    min_size: int,
) -> List[Dict]:
    """Find strongly connected components (everyone can reach everyone)."""
    results = []
    for idx, component in enumerate(
        sorted(nx.strongly_connected_components(S), key=len, reverse=True), 1
    ):
        if len(component) < min_size:
            continue

        subgraph = S.subgraph(component)
        internal_flow = sum(
            data.get("total_amount", 0)
            for u, v, data in subgraph.edges(data=True)
        )

        results.append({
            "scc_id": f"SCC_{idx:03d}",
            "members": sorted(component),
            "size": len(component),
            "internal_edges": subgraph.number_of_edges(),
            "internal_flow": round(internal_flow, 2),
        })

    return results
