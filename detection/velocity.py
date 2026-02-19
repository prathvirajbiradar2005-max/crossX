"""
velocity.py — Rapid Pass-Through (Velocity Pattern) detection.

Pattern: A → B → C where money enters B and leaves within minutes.

Why Suspicious?
Money mule accounts don't hold money — they pass it immediately.

Detection:
For every account that both receives and sends, check the time gap
between incoming and outgoing transactions. If < threshold → suspicious.
"""

from __future__ import annotations

import pandas as pd
import numpy as np
import networkx as nx
from typing import Dict, List, Set, Any
from collections import defaultdict


# ── Configurable thresholds ──────────────────────────────────────────────────
RAPID_MINUTES: float = 30.0         # max minutes between in→out to flag
MIN_RAPID_PAIRS: int = 2            # minimum rapid pairs to flag account
AMOUNT_SIMILARITY: float = 0.15     # max % difference for similar amounts


def detect_velocity(
    G: nx.MultiDiGraph,
    df: pd.DataFrame,
    rapid_minutes: float = RAPID_MINUTES,
    min_rapid_pairs: int = MIN_RAPID_PAIRS,
    amount_similarity: float = AMOUNT_SIMILARITY,
) -> Dict[str, Any]:
    """Detect rapid pass-through velocity patterns.

    Parameters
    ----------
    G : nx.MultiDiGraph
        Full transaction multigraph.
    df : pd.DataFrame
        Cleaned transaction DataFrame with timestamp column.
    rapid_minutes : float
        Maximum minutes between an inbound and outbound tx to count as rapid.
    min_rapid_pairs : int
        Minimum number of rapid in→out pairs to flag an account.
    amount_similarity : float
        Maximum relative difference between in/out amounts for a matched pair.

    Returns
    -------
    dict with keys:
        rapid_accounts : dict[str, list[dict]]
            Account → list of rapid pass-through event details.
        flagged_accounts : set[str]
            Accounts flagged as rapid pass-through.
        chains : list[list[str]]
            Detected rapid A→B→C chains.
    """
    rapid_accounts: Dict[str, List[Dict]] = {}
    flagged_accounts: Set[str] = set()

    # Get all accounts that both send and receive
    senders = set(df["sender_id"].unique())
    receivers = set(df["receiver_id"].unique())
    intermediaries = senders & receivers

    window = pd.Timedelta(minutes=rapid_minutes)

    for account in intermediaries:
        inbound = df[df["receiver_id"] == account][["sender_id", "amount", "timestamp"]].copy()
        outbound = df[df["sender_id"] == account][["receiver_id", "amount", "timestamp"]].copy()

        if inbound.empty or outbound.empty:
            continue

        inbound = inbound.sort_values("timestamp")
        outbound = outbound.sort_values("timestamp")

        rapid_events = []

        for _, in_row in inbound.iterrows():
            # Find outbound txns within the rapid window after this inbound
            mask = (outbound["timestamp"] >= in_row["timestamp"]) & \
                   (outbound["timestamp"] <= in_row["timestamp"] + window)
            matches = outbound[mask]

            for _, out_row in matches.iterrows():
                gap_minutes = (out_row["timestamp"] - in_row["timestamp"]).total_seconds() / 60.0

                # Check amount similarity
                in_amt = in_row["amount"]
                out_amt = out_row["amount"]
                if in_amt > 0:
                    amt_diff = abs(in_amt - out_amt) / in_amt
                else:
                    amt_diff = 1.0

                rapid_events.append({
                    "from": in_row["sender_id"],
                    "to": out_row["receiver_id"],
                    "in_amount": round(in_amt, 2),
                    "out_amount": round(out_amt, 2),
                    "gap_minutes": round(gap_minutes, 1),
                    "amount_similar": amt_diff <= amount_similarity,
                })

        if len(rapid_events) >= min_rapid_pairs:
            rapid_accounts[account] = rapid_events
            flagged_accounts.add(account)

    # Build chains: find connected A→B→C where B is flagged
    chains = _build_velocity_chains(rapid_accounts)

    return {
        "rapid_accounts": rapid_accounts,
        "flagged_accounts": flagged_accounts,
        "chains": chains,
    }


def _build_velocity_chains(
    rapid_accounts: Dict[str, List[Dict]],
) -> List[List[str]]:
    """Build A→B→C chains from rapid events."""
    chains: List[List[str]] = []
    seen: Set[tuple] = set()

    for account, events in rapid_accounts.items():
        for ev in events:
            chain = (ev["from"], account, ev["to"])
            if chain not in seen:
                seen.add(chain)
                chains.append(list(chain))

    return chains
