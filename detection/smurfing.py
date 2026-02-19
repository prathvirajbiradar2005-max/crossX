"""
smurfing.py — Smurfing / Structuring pattern detection.

"Smurfing" involves breaking a large sum into many small transactions to
evade regulatory reporting thresholds.

Detection targets
-----------------
Fan-In  (Collection)  : ≥ 10 distinct senders → 1 receiver within a window.
Fan-Out (Distribution) : 1 sender → ≥ 10 distinct receivers within a window.

Additional signal:
- Low variance in transaction amounts (amounts suspiciously similar).
- Transactions clustered within a 72-hour window.
"""

from __future__ import annotations

import networkx as nx
import pandas as pd
import numpy as np
from typing import Dict, List, Set
from collections import defaultdict


# ── Configurable thresholds ──────────────────────────────────────────────────

FAN_DEGREE_THRESHOLD: int = 10          # min in/out-degree to flag
TIME_WINDOW_HOURS: float = 72.0         # suspicious clustering window
AMOUNT_CV_THRESHOLD: float = 0.15       # coefficient of variation cutoff


# ── Public API ───────────────────────────────────────────────────────────────

def detect_smurfing(
    multi_graph: nx.MultiDiGraph,
    df: pd.DataFrame,
    fan_threshold: int = FAN_DEGREE_THRESHOLD,
    window_hours: float = TIME_WINDOW_HOURS,
    cv_threshold: float = AMOUNT_CV_THRESHOLD,
) -> Dict[str, object]:
    """Identify fan-in and fan-out smurfing hubs.

    Parameters
    ----------
    multi_graph : nx.MultiDiGraph
        Full multigraph with edge-level transaction data.
    df : pd.DataFrame
        Cleaned transaction DataFrame (used for vectorized windowing).
    fan_threshold : int
        Minimum distinct counterparties to qualify as a hub.
    window_hours : float
        Time window (hours) for clustering analysis.
    cv_threshold : float
        Max coefficient of variation for "suspiciously uniform" amounts.

    Returns
    -------
    dict with keys:
        fan_in_hubs  : list[dict]  — details per fan-in hub
        fan_out_hubs : list[dict]  — details per fan-out hub
        smurfing_accounts : set[str] — union of all hub account IDs
        rings : list[dict] — ring descriptors for smurfing-based rings
    """
    fan_in_hubs = _detect_fan_in(df, fan_threshold, window_hours, cv_threshold)
    fan_out_hubs = _detect_fan_out(df, fan_threshold, window_hours, cv_threshold)

    smurfing_accounts: Set[str] = set()
    for hub in fan_in_hubs:
        smurfing_accounts.add(hub["hub_account"])
        smurfing_accounts.update(hub["counterparties"])
    for hub in fan_out_hubs:
        smurfing_accounts.add(hub["hub_account"])
        smurfing_accounts.update(hub["counterparties"])

    rings = _build_smurfing_rings(fan_in_hubs, fan_out_hubs)

    return {
        "fan_in_hubs": fan_in_hubs,
        "fan_out_hubs": fan_out_hubs,
        "smurfing_accounts": smurfing_accounts,
        "rings": rings,
    }


# ── Internal helpers ─────────────────────────────────────────────────────────

def _detect_fan_in(
    df: pd.DataFrame,
    fan_threshold: int,
    window_hours: float,
    cv_threshold: float,
) -> List[Dict]:
    """Find receivers with ≥ fan_threshold distinct senders."""
    hubs: List[Dict] = []

    recv_groups = df.groupby("receiver_id")
    for receiver, grp in recv_groups:
        unique_senders = grp["sender_id"].nunique()
        if unique_senders < fan_threshold:
            continue

        # Windowed clustering: check if most txns fall within window_hours
        window_ratio = _compute_window_ratio(grp["timestamp"], window_hours)

        # Amount uniformity
        amounts = grp["amount"].values
        cv = float(np.std(amounts) / np.mean(amounts)) if np.mean(amounts) > 0 else 0.0
        low_variance = cv < cv_threshold

        risk_boost = 0.0
        if window_ratio > 0.6:
            risk_boost += 15.0  # clustered in time
        if low_variance:
            risk_boost += 10.0  # suspiciously uniform amounts

        hubs.append(
            {
                "hub_account": receiver,
                "direction": "fan_in",
                "distinct_counterparties": unique_senders,
                "counterparties": sorted(grp["sender_id"].unique().tolist()),
                "total_amount": float(grp["amount"].sum()),
                "mean_amount": float(np.mean(amounts)),
                "amount_cv": round(cv, 4),
                "low_variance": low_variance,
                "window_ratio": round(window_ratio, 3),
                "risk_boost": risk_boost,
            }
        )

    return sorted(hubs, key=lambda h: -h["distinct_counterparties"])


def _detect_fan_out(
    df: pd.DataFrame,
    fan_threshold: int,
    window_hours: float,
    cv_threshold: float,
) -> List[Dict]:
    """Find senders with ≥ fan_threshold distinct receivers."""
    hubs: List[Dict] = []

    send_groups = df.groupby("sender_id")
    for sender, grp in send_groups:
        unique_receivers = grp["receiver_id"].nunique()
        if unique_receivers < fan_threshold:
            continue

        window_ratio = _compute_window_ratio(grp["timestamp"], window_hours)

        amounts = grp["amount"].values
        cv = float(np.std(amounts) / np.mean(amounts)) if np.mean(amounts) > 0 else 0.0
        low_variance = cv < cv_threshold

        risk_boost = 0.0
        if window_ratio > 0.6:
            risk_boost += 15.0
        if low_variance:
            risk_boost += 10.0

        hubs.append(
            {
                "hub_account": sender,
                "direction": "fan_out",
                "distinct_counterparties": unique_receivers,
                "counterparties": sorted(grp["receiver_id"].unique().tolist()),
                "total_amount": float(grp["amount"].sum()),
                "mean_amount": float(np.mean(amounts)),
                "amount_cv": round(cv, 4),
                "low_variance": low_variance,
                "window_ratio": round(window_ratio, 3),
                "risk_boost": risk_boost,
            }
        )

    return sorted(hubs, key=lambda h: -h["distinct_counterparties"])


def _compute_window_ratio(timestamps: pd.Series, window_hours: float) -> float:
    """Fraction of transactions falling within the densest window of *window_hours*.

    Uses a rolling-window approach: for each transaction, count how many
    others fall within the next ``window_hours`` hours, then take the max
    cluster.
    """
    if len(timestamps) <= 1:
        return 1.0

    ts_sorted = timestamps.sort_values().reset_index(drop=True)
    window_td = pd.Timedelta(hours=window_hours)
    best_count = 0

    # Vectorized: for each start, count how many fall within the window
    ts_arr = ts_sorted.values
    for i in range(len(ts_arr)):
        end_time = ts_arr[i] + np.timedelta64(int(window_hours * 3600), "s")
        count = int(np.sum((ts_arr >= ts_arr[i]) & (ts_arr <= end_time)))
        if count > best_count:
            best_count = count

    return best_count / len(ts_arr)


def _build_smurfing_rings(
    fan_in_hubs: List[Dict],
    fan_out_hubs: List[Dict],
) -> List[Dict]:
    """Create ring descriptors for significant smurfing clusters."""
    rings: List[Dict] = []
    ring_counter = 0

    for hub in fan_in_hubs:
        ring_counter += 1
        members = [hub["hub_account"]] + hub["counterparties"]
        risk = round(min(100.0, 50.0 + hub["risk_boost"] + hub["distinct_counterparties"] * 1.5), 1)
        rings.append(
            {
                "ring_id": f"SMURF_{ring_counter:03d}",
                "member_accounts": sorted(set(members)),
                "pattern_type": "fan_in_smurfing",
                "risk_score": risk,
            }
        )

    for hub in fan_out_hubs:
        ring_counter += 1
        members = [hub["hub_account"]] + hub["counterparties"]
        risk = round(min(100.0, 50.0 + hub["risk_boost"] + hub["distinct_counterparties"] * 1.5), 1)
        rings.append(
            {
                "ring_id": f"SMURF_{ring_counter:03d}",
                "member_accounts": sorted(set(members)),
                "pattern_type": "fan_out_smurfing",
                "risk_score": risk,
            }
        )

    return rings
