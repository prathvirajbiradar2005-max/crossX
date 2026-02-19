"""
structuring.py — Structuring / Threshold Avoidance detection.

Pattern: Multiple transactions just below a reporting threshold.
Example: If AML threshold = 10,000 → Criminal does 9900, 9800, 9950.

Why Suspicious?
Deliberately splitting transactions to avoid Currency Transaction
Reports (CTRs) or other AML threshold triggers.

Detection:
- Multiple outgoing transactions from the same account.
- Amounts cluster just below known thresholds.
- Low variance in those amounts.

Also detects Amount Consistency: identical or near-identical repeated
amounts (e.g., 5000, 5000, 5000, 5000).
"""

from __future__ import annotations

import pandas as pd
import numpy as np
import networkx as nx
from typing import Dict, List, Set, Any
from collections import defaultdict, Counter


# ── Configurable thresholds ──────────────────────────────────────────────────
AML_THRESHOLDS: List[float] = [10000.0, 5000.0, 3000.0, 15000.0]
BELOW_THRESHOLD_PCT: float = 0.10      # within 10% below threshold
MIN_STRUCTURING_TXN: int = 3           # minimum txns to flag
AMOUNT_REPEAT_MIN: int = 3             # minimum identical amounts to flag
AMOUNT_TOLERANCE: float = 0.02         # 2% tolerance for "identical"


def detect_structuring(
    G: nx.MultiDiGraph,
    df: pd.DataFrame,
    thresholds: List[float] | None = None,
    below_pct: float = BELOW_THRESHOLD_PCT,
    min_txn: int = MIN_STRUCTURING_TXN,
    repeat_min: int = AMOUNT_REPEAT_MIN,
    tolerance: float = AMOUNT_TOLERANCE,
) -> Dict[str, Any]:
    """Detect structuring / threshold avoidance and amount repetition.

    Parameters
    ----------
    G : nx.MultiDiGraph
        Full transaction multigraph.
    df : pd.DataFrame
        Cleaned transaction DataFrame.
    thresholds : list[float] or None
        AML reporting thresholds to check against.
    below_pct : float
        Percentage below a threshold to count as "just below".
    min_txn : int
        Minimum transactions just below a threshold to flag.
    repeat_min : int
        Minimum repeated identical amounts to flag.
    tolerance : float
        Tolerance for amount similarity.

    Returns
    -------
    dict with keys:
        structuring_accounts : dict[str, dict]
            Per-account structuring details.
        flagged_accounts : set[str]
            All accounts flagged for structuring.
        amount_repeat_accounts : dict[str, dict]
            Per-account details of repeated identical amounts.
        repeat_flagged : set[str]
            All accounts flagged for amount repetition.
    """
    if thresholds is None:
        thresholds = AML_THRESHOLDS

    structuring_accounts: Dict[str, Dict] = {}
    flagged_accounts: Set[str] = set()
    amount_repeat_accounts: Dict[str, Dict] = {}
    repeat_flagged: Set[str] = set()

    # Group outgoing transactions by sender
    for sender, grp in df.groupby("sender_id"):
        amounts = grp["amount"].values

        # ── 1. Threshold avoidance ─────────────────────────────────────
        for threshold in thresholds:
            lower_bound = threshold * (1 - below_pct)
            just_below = amounts[(amounts >= lower_bound) & (amounts < threshold)]

            if len(just_below) >= min_txn:
                structuring_accounts[sender] = {
                    "threshold": threshold,
                    "count_below": int(len(just_below)),
                    "amounts": sorted([round(a, 2) for a in just_below]),
                    "mean_amount": round(float(np.mean(just_below)), 2),
                    "total": round(float(np.sum(just_below)), 2),
                }
                flagged_accounts.add(sender)
                break  # Flag on first matching threshold

        # ── 2. Amount repetition / consistency ─────────────────────────
        if len(amounts) >= repeat_min:
            # Bucket amounts by tolerance
            rounded = np.round(amounts, 0)
            counter = Counter(rounded)

            for amt_bucket, count in counter.most_common():
                if count >= repeat_min:
                    # Get actual amounts in this bucket
                    mask = np.abs(amounts - amt_bucket) <= amt_bucket * tolerance
                    matched = amounts[mask]
                    if len(matched) >= repeat_min:
                        amount_repeat_accounts[sender] = {
                            "repeated_amount": round(float(amt_bucket), 2),
                            "count": int(len(matched)),
                            "total": round(float(np.sum(matched)), 2),
                            "variance": round(float(np.var(matched)), 4),
                        }
                        repeat_flagged.add(sender)
                        break

    return {
        "structuring_accounts": structuring_accounts,
        "flagged_accounts": flagged_accounts,
        "amount_repeat_accounts": amount_repeat_accounts,
        "repeat_flagged": repeat_flagged,
    }
