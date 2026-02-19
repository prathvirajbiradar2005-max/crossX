"""
scoring.py — Suspicion Scoring engine (the "Brain").

Aggregates all detection flags into a single 0–100 suspicion score per
account.  Includes false-positive control: high-degree nodes with stable
timing and zero cycles get a "Trust Multiplier" discount.

Scoring Weights (10 patterns)
-----------------------------
Factor                    | Weight | Reason
1. Cycle Participation    |  40 pts | Circular routing extremely rare in legal banking
2. Rapid Pass-Through     |  20 pts | Velocity: money in→out within minutes
3. Layering (Decreasing)  |  20 pts | Commission-deducting relay chains
4. Smurfing Hub (Fan-In)  |  30 pts | Collection / Distribution concentrator
5. Smurfing Hub (Fan-Out) |  30 pts | (merged with above, capped at 30)
6. Amount Consistency     |  10 pts | Money in ≈ money out
7. Low Entropy            |  10 pts | Predictable counterparty patterns
8. New Account Burst      |  15 pts | Newly created account suddenly very active
9. Community / SCC        |  12 pts | Tightly connected suspicious cluster
10. Structuring           |  18 pts | Threshold avoidance / repeated amounts
Shell Pass-Through        |  15 pts | Relay node with near-zero retention
"""

from __future__ import annotations

import math
import networkx as nx
import pandas as pd
import numpy as np
from typing import Dict, List, Set, Any
from collections import defaultdict, Counter


# ── Weight configuration ─────────────────────────────────────────────────────
WEIGHT_CYCLE: float = 40.0
WEIGHT_SMURFING: float = 30.0
WEIGHT_VELOCITY: float = 20.0
WEIGHT_SHELL: float = 15.0
WEIGHT_AMOUNT_CONSISTENCY: float = 10.0
WEIGHT_ENTROPY: float = 10.0
WEIGHT_LAYERING: float = 20.0
WEIGHT_NEW_ACCOUNT: float = 15.0
WEIGHT_COMMUNITY: float = 12.0
WEIGHT_STRUCTURING: float = 18.0

# False-positive control
TRUST_MULTIPLIER_DISCOUNT: float = 0.4   # reduce score by up to 40 %
STABLE_TIMING_CV: float = 0.3            # CV of inter-tx intervals
HIGH_DEGREE_THRESHOLD: int = 50          # "merchant-like" node


# ── Public API ───────────────────────────────────────────────────────────────

def compute_suspicion_scores(
    G: nx.MultiDiGraph,
    df: pd.DataFrame,
    cycle_results: Dict[str, Any],
    smurfing_results: Dict[str, Any],
    shell_results: Dict[str, Any],
    velocity_results: Dict[str, Any] | None = None,
    layering_results: Dict[str, Any] | None = None,
    structuring_results: Dict[str, Any] | None = None,
    community_results: Dict[str, Any] | None = None,
    new_account_results: Dict[str, Any] | None = None,
) -> List[Dict[str, Any]]:
    """Score every account in the graph.

    Parameters
    ----------
    G : nx.MultiDiGraph
        Full transaction graph.
    df : pd.DataFrame
        Cleaned transaction DataFrame.
    cycle_results : dict
        Output from ``cycles.detect_cycles``.
    smurfing_results : dict
        Output from ``smurfing.detect_smurfing``.
    shell_results : dict
        Output from ``shell_network.detect_shell_networks``.
    velocity_results : dict or None
        Output from ``velocity.detect_velocity``.
    layering_results : dict or None
        Output from ``layering.detect_layering``.
    structuring_results : dict or None
        Output from ``structuring.detect_structuring``.
    community_results : dict or None
        Output from ``community.detect_communities``.
    new_account_results : dict or None
        Output from ``community.detect_new_accounts``.

    Returns
    -------
    list[dict]
        One dict per account, sorted descending by ``suspicion_score``.
        Keys: account_id, suspicion_score, detected_patterns,
              breakdown, ring_id, is_false_positive_adjusted.
    """
    cycle_accounts: Set[str] = cycle_results.get("cycle_accounts", set())
    account_cycle_count: Dict[str, int] = cycle_results.get("account_cycle_count", {})

    smurfing_accounts: Set[str] = smurfing_results.get("smurfing_accounts", set())
    fan_in_hub_set = {h["hub_account"] for h in smurfing_results.get("fan_in_hubs", [])}
    fan_out_hub_set = {h["hub_account"] for h in smurfing_results.get("fan_out_hubs", [])}

    shell_accounts: Set[str] = shell_results.get("shell_accounts", set())
    passthrough_nodes: Set[str] = shell_results.get("passthrough_nodes", set())

    # New pattern data (optional inputs)
    velocity_flagged: Set[str] = set()
    velocity_rapid: Dict[str, list] = {}
    if velocity_results:
        velocity_flagged = velocity_results.get("flagged_accounts", set())
        velocity_rapid = velocity_results.get("rapid_accounts", {})

    layering_accounts: Set[str] = set()
    if layering_results:
        layering_accounts = layering_results.get("layering_accounts", set())

    structuring_flagged: Set[str] = set()
    repeat_flagged: Set[str] = set()
    structuring_details: Dict[str, dict] = {}
    repeat_details: Dict[str, dict] = {}
    if structuring_results:
        structuring_flagged = structuring_results.get("flagged_accounts", set())
        repeat_flagged = structuring_results.get("repeat_flagged", set())
        structuring_details = structuring_results.get("structuring_accounts", {})
        repeat_details = structuring_results.get("amount_repeat_accounts", {})

    community_accounts: Set[str] = set()
    if community_results:
        community_accounts = community_results.get("community_accounts", set())

    new_acc_flagged: Set[str] = set()
    if new_account_results:
        new_acc_flagged = new_account_results.get("flagged_accounts", set())

    # Pre-compute per-account velocity and entropy
    velocity_map = _compute_velocity(df)
    entropy_map = _compute_entropy(df)

    # Map accounts to ring IDs
    account_ring_map = _map_accounts_to_rings(
        cycle_results, smurfing_results, shell_results
    )

    scores: List[Dict[str, Any]] = []

    for node in G.nodes():
        breakdown: Dict[str, float] = {}
        patterns: List[str] = []
        raw_score = 0.0

        # ── 1. Cycle participation (up to 40 pts) ────────────────────────
        n_cycles = account_cycle_count.get(node, 0)
        if n_cycles > 0:
            # Diminishing returns: first cycle = 30 pts, extra cycles add less
            cycle_score = min(WEIGHT_CYCLE, 30.0 + 5.0 * min(n_cycles - 1, 2))
            raw_score += cycle_score
            breakdown["cycle"] = cycle_score
            patterns.append(f"cycle_participant_x{n_cycles}")

        # ── 2. Smurfing hub (up to 30 pts) ───────────────────────────────
        smurf_score = 0.0
        if node in fan_in_hub_set:
            hub_info = next(
                (h for h in smurfing_results["fan_in_hubs"]
                 if h["hub_account"] == node), None
            )
            smurf_score += 20.0
            if hub_info and hub_info.get("low_variance"):
                smurf_score += 5.0
            if hub_info and hub_info.get("window_ratio", 0) > 0.6:
                smurf_score += 5.0
            patterns.append("fan_in_hub")

        if node in fan_out_hub_set:
            hub_info = next(
                (h for h in smurfing_results["fan_out_hubs"]
                 if h["hub_account"] == node), None
            )
            smurf_score += 20.0
            if hub_info and hub_info.get("low_variance"):
                smurf_score += 5.0
            if hub_info and hub_info.get("window_ratio", 0) > 0.6:
                smurf_score += 5.0
            patterns.append("fan_out_hub")

        smurf_score = min(smurf_score, WEIGHT_SMURFING)
        if smurf_score > 0:
            raw_score += smurf_score
            breakdown["smurfing"] = smurf_score

        # Peripheral smurfing participant (not the hub)
        if node in smurfing_accounts and node not in fan_in_hub_set and node not in fan_out_hub_set:
            peripheral_score = 10.0
            raw_score += peripheral_score
            breakdown["smurfing_peripheral"] = peripheral_score
            patterns.append("smurfing_peripheral")

        # ── 3. High velocity (up to 20 pts) ──────────────────────────────
        vel = velocity_map.get(node, 0.0)
        if vel > 0:
            # Velocity = transactions per hour; > 2 tx/hr is suspicious
            velocity_score = min(WEIGHT_VELOCITY, vel * 5.0)
            if velocity_score >= 5.0:
                raw_score += velocity_score
                breakdown["high_velocity"] = velocity_score
                patterns.append("high_velocity")

        # ── 4. Shell pass-through (up to 15 pts) ─────────────────────────
        if node in passthrough_nodes:
            shell_score = WEIGHT_SHELL
            raw_score += shell_score
            breakdown["shell_passthrough"] = shell_score
            patterns.append("shell_passthrough")
        elif node in shell_accounts:
            shell_score = 8.0
            raw_score += shell_score
            breakdown["shell_network_member"] = shell_score
            patterns.append("shell_network_member")

        # ── 5. Amount consistency (up to 10 pts) ─────────────────────────
        ndata = G.nodes[node]
        total_in = ndata.get("total_received", 0.0)
        total_out = ndata.get("total_sent", 0.0)
        throughput = total_in + total_out
        if throughput > 0:
            retention = abs(total_in - total_out) / throughput
            if retention < 0.05:
                amount_score = WEIGHT_AMOUNT_CONSISTENCY
                raw_score += amount_score
                breakdown["amount_consistency"] = amount_score
                patterns.append("amount_consistency")

        # ── 6. Entropy score (up to 10 pts) ──────────────────────────────
        ent = entropy_map.get(node, None)
        if ent is not None and ent < 1.5:
            # Low entropy = predictable counterparty pattern
            ent_score = min(WEIGHT_ENTROPY, (1.5 - ent) * 8.0)
            if ent_score >= 2.0:
                raw_score += ent_score
                breakdown["low_entropy"] = round(ent_score, 2)
                patterns.append("low_entropy")

        # ── 7. Rapid pass-through / velocity (up to 20 pts) ─────────────
        if node in velocity_flagged:
            events = velocity_rapid.get(node, [])
            n_rapid = len(events)
            similar_count = sum(1 for e in events if e.get("amount_similar"))
            vel_score = min(WEIGHT_VELOCITY, 10.0 + 3.0 * min(n_rapid, 5))
            if similar_count > 0:
                vel_score = min(WEIGHT_VELOCITY, vel_score + 5.0)
            raw_score += vel_score
            breakdown["rapid_passthrough"] = vel_score
            patterns.append(f"rapid_passthrough_x{n_rapid}")

        # ── 8. Layering (decreasing amounts) (up to 20 pts) ─────────────
        if node in layering_accounts:
            lay_score = WEIGHT_LAYERING
            raw_score += lay_score
            breakdown["layering"] = lay_score
            patterns.append("layering_chain")

        # ── 9. Structuring / threshold avoidance (up to 18 pts) ──────────
        if node in structuring_flagged:
            detail = structuring_details.get(node, {})
            struct_score = min(WEIGHT_STRUCTURING, 12.0 + 2.0 * detail.get("count_below", 0))
            raw_score += struct_score
            breakdown["structuring"] = struct_score
            patterns.append(f"structuring_below_{int(detail.get('threshold', 0))}")

        if node in repeat_flagged and node not in structuring_flagged:
            rep_detail = repeat_details.get(node, {})
            rep_score = min(WEIGHT_STRUCTURING * 0.6, 4.0 * rep_detail.get("count", 0))
            raw_score += rep_score
            breakdown["amount_repetition"] = rep_score
            patterns.append(f"amount_repeat_x{rep_detail.get('count', 0)}")

        # ── 10. New account burst (up to 15 pts) ─────────────────────────
        if node in new_acc_flagged:
            new_score = WEIGHT_NEW_ACCOUNT
            raw_score += new_score
            breakdown["new_account_burst"] = new_score
            patterns.append("new_account_burst")

        # ── 11. Community / SCC membership (up to 12 pts) ────────────────
        if node in community_accounts:
            comm_score = WEIGHT_COMMUNITY
            raw_score += comm_score
            breakdown["community_cluster"] = comm_score
            patterns.append("tight_community")

        # ── 12. False-positive control ───────────────────────────────────
        fp_adjusted = False
        total_degree = G.in_degree(node) + G.out_degree(node)

        if total_degree >= HIGH_DEGREE_THRESHOLD and node not in cycle_accounts:
            timing_cv = _timing_regularity(df, node)
            if timing_cv is not None and timing_cv < STABLE_TIMING_CV:
                discount = TRUST_MULTIPLIER_DISCOUNT
                raw_score *= (1.0 - discount)
                fp_adjusted = True
                patterns.append("trust_adjusted")

        # ── Normalize to 0–100 ───────────────────────────────────────────
        # Use a calibrated ceiling: an account triggering 3-4 major patterns
        # should score near 100.  Raw scores above the ceiling cap at 100.
        SCORE_CEILING = 100.0
        normalized = min(100.0, (raw_score / SCORE_CEILING) * 100.0)
        normalized = round(normalized, 1)

        ring_ids = account_ring_map.get(node, [])

        scores.append(
            {
                "account_id": node,
                "suspicion_score": normalized,
                "detected_patterns": patterns,
                "breakdown": breakdown,
                "ring_id": ring_ids[0] if ring_ids else None,
                "all_ring_ids": ring_ids,
                "is_false_positive_adjusted": fp_adjusted,
            }
        )

    # Sort descending by score
    scores.sort(key=lambda s: -s["suspicion_score"])
    return scores


# ── Internal helpers ─────────────────────────────────────────────────────────

def _compute_velocity(df: pd.DataFrame) -> Dict[str, float]:
    """Transactions per hour for each account."""
    velocity: Dict[str, float] = {}

    for col in ("sender_id", "receiver_id"):
        for account, grp in df.groupby(col):
            ts = grp["timestamp"]
            span_hours = (ts.max() - ts.min()).total_seconds() / 3600.0
            if span_hours > 0:
                v = len(grp) / span_hours
            else:
                v = 0.0
            velocity[account] = velocity.get(account, 0.0) + v

    return velocity


def _compute_entropy(df: pd.DataFrame) -> Dict[str, float]:
    """Shannon entropy of counterparty distribution per account.

    For each account, we look at who they transact with and how the
    transaction volume is distributed.  Low entropy = concentrated /
    predictable pattern.
    """
    entropy: Dict[str, float] = {}

    # Outgoing counterparty distribution
    for sender, grp in df.groupby("sender_id"):
        counts = grp["receiver_id"].value_counts().values
        entropy[sender] = _shannon_entropy(counts)

    # Incoming counterparty distribution (merge with outgoing)
    for receiver, grp in df.groupby("receiver_id"):
        counts = grp["sender_id"].value_counts().values
        e = _shannon_entropy(counts)
        if receiver in entropy:
            entropy[receiver] = (entropy[receiver] + e) / 2.0
        else:
            entropy[receiver] = e

    return entropy


def _shannon_entropy(counts: np.ndarray) -> float:
    """Compute Shannon entropy from a frequency array."""
    total = counts.sum()
    if total == 0:
        return 0.0
    probs = counts / total
    # Filter out zero probabilities to avoid log(0)
    probs = probs[probs > 0]
    return float(-np.sum(probs * np.log2(probs)))


def _timing_regularity(df: pd.DataFrame, node: str) -> float | None:
    """Coefficient of variation of inter-transaction intervals for *node*.

    Returns None if the node has < 3 transactions (not enough data).
    """
    mask = (df["sender_id"] == node) | (df["receiver_id"] == node)
    ts = df.loc[mask, "timestamp"].sort_values()

    if len(ts) < 3:
        return None

    intervals = ts.diff().dropna().dt.total_seconds().values
    mean_interval = np.mean(intervals)
    if mean_interval == 0:
        return None

    return float(np.std(intervals) / mean_interval)


def _map_accounts_to_rings(
    cycle_results: Dict,
    smurfing_results: Dict,
    shell_results: Dict,
) -> Dict[str, List[str]]:
    """Create a mapping: account_id → list of ring IDs it belongs to."""
    mapping: Dict[str, List[str]] = defaultdict(list)

    for ring in cycle_results.get("rings", []):
        for acct in ring["member_accounts"]:
            mapping[acct].append(ring["ring_id"])

    for ring in smurfing_results.get("rings", []):
        for acct in ring["member_accounts"]:
            mapping[acct].append(ring["ring_id"])

    for ring in shell_results.get("rings", []):
        for acct in ring["member_accounts"]:
            mapping[acct].append(ring["ring_id"])

    return dict(mapping)
