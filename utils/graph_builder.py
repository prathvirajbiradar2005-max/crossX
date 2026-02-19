"""
graph_builder.py — Construct a weighted, directed NetworkX graph from
cleaned transaction data.

Each node is an account (sender or receiver).
Each edge represents aggregated fund flow between two accounts, carrying
metadata about individual transactions for downstream detection.
"""

from __future__ import annotations

import networkx as nx
import pandas as pd
import numpy as np
from typing import Dict, Any


# ── Public API ───────────────────────────────────────────────────────────────

def build_transaction_graph(df: pd.DataFrame) -> nx.MultiDiGraph:
    """Build a directed multigraph from a cleaned transaction DataFrame.

    We use a *MultiDiGraph* so parallel edges (multiple transactions between
    the same pair) are preserved — this matters for smurfing and velocity
    analysis.

    Node attributes
    ----------------
    - total_sent : float — sum of all outgoing amounts
    - total_received : float — sum of all incoming amounts
    - net_flow : float — total_received − total_sent
    - tx_count : int — total transactions involving this account
    - first_seen : pd.Timestamp
    - last_seen : pd.Timestamp
    - active_days : float — span between first and last activity (days)

    Edge attributes (per edge)
    ---------------------------
    - transaction_id : str
    - amount : float
    - timestamp : pd.Timestamp
    """
    G = nx.MultiDiGraph()

    # ── Bulk-add edges with attributes ────────────────────────────────────
    for row in df.itertuples(index=False):
        G.add_edge(
            row.sender_id,
            row.receiver_id,
            transaction_id=row.transaction_id,
            amount=float(row.amount),
            timestamp=row.timestamp,
        )

    # ── Compute node-level aggregates using vectorized pandas ─────────────
    sent_agg = (
        df.groupby("sender_id")
        .agg(
            total_sent=("amount", "sum"),
            sent_count=("amount", "count"),
            first_sent=("timestamp", "min"),
            last_sent=("timestamp", "max"),
        )
    )

    recv_agg = (
        df.groupby("receiver_id")
        .agg(
            total_received=("amount", "sum"),
            recv_count=("amount", "count"),
            first_recv=("timestamp", "min"),
            last_recv=("timestamp", "max"),
        )
    )

    for node in G.nodes():
        s = sent_agg.loc[node] if node in sent_agg.index else None
        r = recv_agg.loc[node] if node in recv_agg.index else None

        total_sent = float(s["total_sent"]) if s is not None else 0.0
        total_received = float(r["total_received"]) if r is not None else 0.0
        sent_count = int(s["sent_count"]) if s is not None else 0
        recv_count = int(r["recv_count"]) if r is not None else 0

        timestamps = []
        if s is not None:
            timestamps += [s["first_sent"], s["last_sent"]]
        if r is not None:
            timestamps += [r["first_recv"], r["last_recv"]]

        first_seen = min(timestamps)
        last_seen = max(timestamps)
        active_days = (last_seen - first_seen).total_seconds() / 86400.0

        G.nodes[node].update(
            {
                "total_sent": total_sent,
                "total_received": total_received,
                "net_flow": total_received - total_sent,
                "tx_count": sent_count + recv_count,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "active_days": active_days,
            }
        )

    return G


def build_simple_digraph(G: nx.MultiDiGraph) -> nx.DiGraph:
    """Collapse parallel edges into a simple DiGraph for cycle detection.

    Edge attributes on the simple graph:
    - total_amount : float  — sum of all parallel tx amounts
    - tx_count     : int    — number of individual transactions
    - timestamps   : list   — all transaction timestamps (sorted)
    """
    S = nx.DiGraph()

    for u, v, data in G.edges(data=True):
        if S.has_edge(u, v):
            S[u][v]["total_amount"] += data["amount"]
            S[u][v]["tx_count"] += 1
            S[u][v]["timestamps"].append(data["timestamp"])
        else:
            S.add_edge(
                u,
                v,
                total_amount=data["amount"],
                tx_count=1,
                timestamps=[data["timestamp"]],
            )

    # Sort timestamp lists once
    for _, _, edata in S.edges(data=True):
        edata["timestamps"].sort()

    # Copy node attributes
    for node in S.nodes():
        if node in G.nodes:
            S.nodes[node].update(G.nodes[node])

    return S


def get_account_list(G: nx.MultiDiGraph) -> list[str]:
    """Return a sorted list of all account IDs in the graph."""
    return sorted(G.nodes())


def get_edge_summary(G: nx.MultiDiGraph) -> pd.DataFrame:
    """Return a DataFrame summarising edges (for the UI table)."""
    rows = []
    for u, v, data in G.edges(data=True):
        rows.append(
            {
                "sender": u,
                "receiver": v,
                "amount": data["amount"],
                "transaction_id": data["transaction_id"],
                "timestamp": data["timestamp"],
            }
        )
    return pd.DataFrame(rows)
