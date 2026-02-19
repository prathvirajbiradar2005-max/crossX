"""
scoring.py — Suspicion Scoring engine (the "Brain").

Aggregates all detection flags into a single 0–100 suspicion score per
account.  Includes false-positive control: high-degree nodes with stable
timing and zero cycles get a "Trust Multiplier" discount.

Scoring Weights
---------------
Factor                  | Weight | Reason
Cycle Participation     |  40 pts | Extremely rare in legal personal banking
Smurfing Hub            |  30 pts | Concentrator / Distributor node
High Velocity           |  20 pts | Rapid movement = automated / forced muling
Shell Pass-Through      |  15 pts | Relay node with near-zero retention
Amount Consistency      |  10 pts | Money in ≈ money out
Entropy (low)           |  10 pts | Predictable counterparty patterns

Shannon Entropy
---------------
Low counterparty entropy → always sends/receives from same small set
→ predictable mule pattern → adds up to 10 pts.
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

        # ── 7. False-positive control ────────────────────────────────────
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
        max_possible = (
            WEIGHT_CYCLE + WEIGHT_SMURFING + WEIGHT_VELOCITY +
            WEIGHT_SHELL + WEIGHT_AMOUNT_CONSISTENCY + WEIGHT_ENTROPY
        )
        normalized = min(100.0, (raw_score / max_possible) * 100.0)
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
