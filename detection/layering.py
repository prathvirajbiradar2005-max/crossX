"""
layering.py — Layering with Slightly Reduced Amounts detection.

Pattern: 50000 → 49500 → 49000 → 48500

Why Suspicious?
Criminals deduct small commissions while layering money through
intermediary accounts. The amounts decrease along the chain.

Detection:
Track decreasing chain amounts with consistent deduction percentage.
"""

from __future__ import annotations

import pandas as pd
import numpy as np
import networkx as nx
from typing import Dict, List, Set, Any, Tuple
from collections import defaultdict


# ── Configurable thresholds ──────────────────────────────────────────────────
MIN_CHAIN_LENGTH: int = 3               # minimum hops in a layering chain
MAX_DEDUCTION_PCT: float = 0.10         # max % deducted per hop (10%)
MIN_DEDUCTION_PCT: float = 0.001        # min % deducted per hop (0.1%)
DEDUCTION_CV_THRESHOLD: float = 0.5     # max CV of deduction % for consistency
TIME_WINDOW_HOURS: float = 48.0         # max hours between consecutive hops


def detect_layering(
    G: nx.MultiDiGraph,
    df: pd.DataFrame,
    min_chain_length: int = MIN_CHAIN_LENGTH,
    max_deduction_pct: float = MAX_DEDUCTION_PCT,
    min_deduction_pct: float = MIN_DEDUCTION_PCT,
    deduction_cv_threshold: float = DEDUCTION_CV_THRESHOLD,
    time_window_hours: float = TIME_WINDOW_HOURS,
) -> Dict[str, Any]:
    """Detect layering chains with decreasing amounts.

    Parameters
    ----------
    G : nx.MultiDiGraph
        Full transaction multigraph.
    df : pd.DataFrame
        Cleaned transaction DataFrame.
    min_chain_length : int
        Minimum number of hops to flag as layering.
    max_deduction_pct : float
        Maximum per-hop deduction percentage.
    min_deduction_pct : float
        Minimum per-hop deduction percentage.
    deduction_cv_threshold : float
        Maximum coefficient of variation for deduction percentages.
    time_window_hours : float
        Maximum hours between consecutive hops.

    Returns
    -------
    dict with keys:
        chains : list[dict]
            Each chain has: accounts, amounts, deductions, avg_deduction_pct.
        layering_accounts : set[str]
            All accounts participating in layering chains.
    """
    # Sort transactions by timestamp for chain building
    sorted_df = df.sort_values("timestamp").reset_index(drop=True)
    window = pd.Timedelta(hours=time_window_hours)

    # Build adjacency: for each tx, find next hops from receiver
    chains = []
    layering_accounts: Set[str] = set()

    # Index transactions by sender for efficient lookup
    sender_txns = defaultdict(list)
    for _, row in sorted_df.iterrows():
        sender_txns[row["sender_id"]].append(row)

    # Try extending chains from each transaction
    visited_chains: Set[tuple] = set()

    for _, start_row in sorted_df.iterrows():
        chain_result = _extend_chain(
            start_row, sender_txns, window,
            min_deduction_pct, max_deduction_pct,
            max_depth=8,
        )

        if chain_result and len(chain_result["accounts"]) >= min_chain_length:
            key = tuple(chain_result["accounts"])
            if key in visited_chains:
                continue
            visited_chains.add(key)

            # Check deduction consistency
            deductions = chain_result["deduction_pcts"]
            if len(deductions) >= 2:
                mean_d = np.mean(deductions)
                std_d = np.std(deductions)
                cv = std_d / mean_d if mean_d > 0 else float("inf")
                if cv <= deduction_cv_threshold:
                    chain_result["deduction_cv"] = round(cv, 4)
                    chain_result["avg_deduction_pct"] = round(mean_d * 100, 2)
                    chains.append(chain_result)
                    layering_accounts.update(chain_result["accounts"])

    return {
        "chains": chains,
        "layering_accounts": layering_accounts,
    }


def _extend_chain(
    start_row: pd.Series,
    sender_txns: Dict[str, List],
    window: pd.Timedelta,
    min_ded: float,
    max_ded: float,
    max_depth: int = 8,
) -> Dict[str, Any] | None:
    """Try to build a decreasing-amount chain starting from a transaction."""
    accounts = [start_row["sender_id"], start_row["receiver_id"]]
    amounts = [start_row["amount"]]
    deduction_pcts = []
    last_ts = start_row["timestamp"]
    last_amount = start_row["amount"]
    current_receiver = start_row["receiver_id"]
    visited = {start_row["sender_id"], start_row["receiver_id"]}

    for _ in range(max_depth):
        # Look for outgoing txns from current_receiver within time window
        candidates = sender_txns.get(current_receiver, [])
        best = None

        for tx in candidates:
            if tx["timestamp"] < last_ts:
                continue
            if tx["timestamp"] > last_ts + window:
                continue
            if tx["receiver_id"] in visited:
                continue

            # Check decreasing amount with valid deduction
            if tx["amount"] >= last_amount:
                continue

            deduction = (last_amount - tx["amount"]) / last_amount
            if min_ded <= deduction <= max_ded:
                if best is None or tx["amount"] > best["amount"]:
                    best = tx

        if best is None:
            break

        deduction = (last_amount - best["amount"]) / last_amount
        deduction_pcts.append(deduction)
        amounts.append(best["amount"])
        accounts.append(best["receiver_id"])
        visited.add(best["receiver_id"])
        last_ts = best["timestamp"]
        last_amount = best["amount"]
        current_receiver = best["receiver_id"]

    if len(accounts) < 3:
        return None

    return {
        "accounts": accounts,
        "amounts": [round(a, 2) for a in amounts],
        "deduction_pcts": deduction_pcts,
    }
