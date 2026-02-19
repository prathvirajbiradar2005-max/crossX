"""
sample_data.py — Generate realistic synthetic transaction data that
contains money-muling patterns for demonstration and testing.

Patterns embedded:
 1. Circular routing (A→B→C→A)
 2. Rapid pass-through / velocity chains
 3. Layering (decreasing amounts through chain)
 4. Smurfing fan-in (12 mules → 1 collector)
 5. Smurfing fan-out (1 distributor → 11 recipients)
 6. Amount consistency (near-zero retention)
 7. Low-entropy counterparty patterns
 8. New-account burst (account active < 2 days, high volume)
 9. Community cluster (tight group with many internal txns)
10. Structuring / threshold avoidance (amounts just below $10 000)
11. Shell / pass-through relay chains
12. Normal legitimate traffic as background noise
"""

from __future__ import annotations

import random
import pandas as pd
import numpy as np
from datetime import datetime, timedelta


def generate_sample_csv(
    n_normal: int = 300,
    seed: int = 42,
) -> pd.DataFrame:
    """Generate a sample transaction DataFrame with embedded fraud patterns.

    Parameters
    ----------
    n_normal : int
        Number of normal (background) transactions.
    seed : int
        Random seed for reproducibility.

    Returns
    -------
    pd.DataFrame
        Ready-to-use DataFrame with columns:
        transaction_id, sender_id, receiver_id, amount, timestamp
    """
    rng = random.Random(seed)
    np_rng = np.random.RandomState(seed)

    rows: list[dict] = []
    tx_counter = 0
    base_time = datetime(2025, 6, 1, 8, 0, 0)

    def _add_tx(sender: str, receiver: str, amount: float, ts: datetime) -> None:
        nonlocal tx_counter
        tx_counter += 1
        rows.append({
            "transaction_id": f"TXN_{tx_counter:05d}",
            "sender_id": sender,
            "receiver_id": receiver,
            "amount": round(amount, 2),
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
        })

    # ── 1. Normal legitimate traffic ─────────────────────────────────────
    normal_accounts = [f"ACC_{i:04d}" for i in range(1, 81)]
    for _ in range(n_normal):
        s, r = rng.sample(normal_accounts, 2)
        amt = round(rng.uniform(10, 5000), 2)
        ts = base_time + timedelta(
            days=rng.randint(0, 60),
            hours=rng.randint(0, 23),
            minutes=rng.randint(0, 59),
        )
        _add_tx(s, r, amt, ts)

    # ── 2. Circular routing (3 rings) ────────────────────────────────────
    # Ring 1: length 3
    ring1 = ["MULE_A01", "MULE_A02", "MULE_A03"]
    t = base_time + timedelta(days=5, hours=2)
    for i in range(len(ring1)):
        _add_tx(ring1[i], ring1[(i + 1) % len(ring1)], 4500.0, t)
        t += timedelta(hours=1)
    # Second round through the same ring
    t += timedelta(hours=6)
    for i in range(len(ring1)):
        _add_tx(ring1[i], ring1[(i + 1) % len(ring1)], 4200.0, t)
        t += timedelta(hours=2)

    # Ring 2: length 4
    ring2 = ["MULE_B01", "MULE_B02", "MULE_B03", "MULE_B04"]
    t = base_time + timedelta(days=10, hours=14)
    for i in range(len(ring2)):
        _add_tx(ring2[i], ring2[(i + 1) % len(ring2)], 3800.0, t)
        t += timedelta(hours=3)

    # Ring 3: length 5
    ring3 = ["MULE_C01", "MULE_C02", "MULE_C03", "MULE_C04", "MULE_C05"]
    t = base_time + timedelta(days=20, hours=9)
    for i in range(len(ring3)):
        _add_tx(ring3[i], ring3[(i + 1) % len(ring3)], 6000.0, t)
        t += timedelta(hours=2)

    # ── 3. Smurfing — Fan-in (12 mules → 1 collector) ───────────────────
    collector = "SMURF_HUB_IN"
    smurf_senders = [f"SMURF_S{i:02d}" for i in range(1, 13)]
    t = base_time + timedelta(days=15, hours=10)
    for s in smurf_senders:
        amt = round(rng.uniform(480, 500), 2)  # low variance ≈ $490
        _add_tx(s, collector, amt, t)
        t += timedelta(minutes=rng.randint(10, 45))

    # ── 4. Smurfing — Fan-out (1 distributor → 11 recipients) ────────────
    distributor = "SMURF_HUB_OUT"
    smurf_receivers = [f"SMURF_R{i:02d}" for i in range(1, 12)]
    t = base_time + timedelta(days=18, hours=14)
    for r in smurf_receivers:
        amt = round(rng.uniform(290, 310), 2)  # low variance ≈ $300
        _add_tx(distributor, r, amt, t)
        t += timedelta(minutes=rng.randint(5, 30))

    # ── 5. Shell / pass-through relay chain ──────────────────────────────
    shell_chain = ["SHELL_SRC", "SHELL_P01", "SHELL_P02", "SHELL_P03", "SHELL_SINK"]
    t = base_time + timedelta(days=25, hours=11)
    amount = 8000.0
    for i in range(len(shell_chain) - 1):
        _add_tx(shell_chain[i], shell_chain[i + 1], amount, t)
        amount -= round(rng.uniform(5, 15), 2)  # tiny fee / retention
        t += timedelta(hours=rng.randint(1, 4))

    # Second relay pass
    t += timedelta(days=2)
    amount = 7500.0
    for i in range(len(shell_chain) - 1):
        _add_tx(shell_chain[i], shell_chain[i + 1], amount, t)
        amount -= round(rng.uniform(5, 15), 2)
        t += timedelta(hours=rng.randint(1, 3))

    # ── 6. High-volume legitimate merchant (false-positive candidate) ────
    merchant = "MERCHANT_PAYROLL"
    employees = [f"EMP_{i:03d}" for i in range(1, 55)]
    for month_offset in range(3):
        t = base_time + timedelta(days=30 * month_offset + 1, hours=9)
        for emp in employees:
            _add_tx(merchant, emp, round(rng.uniform(2800, 3200), 2), t)
            t += timedelta(seconds=rng.randint(1, 10))

    # ── 7. Rapid pass-through / velocity (Pattern #2) ───────────────────
    # Money hits VELOCITY_B and leaves within minutes to VELOCITY_C
    velocity_chain = ["VELOCITY_A", "VELOCITY_B", "VELOCITY_C"]
    t = base_time + timedelta(days=8, hours=15)
    for _ in range(4):   # 4 rapid in→out pairs
        amt = round(rng.uniform(3000, 3200), 2)
        _add_tx(velocity_chain[0], velocity_chain[1], amt, t)
        # Outbound within 5-15 min — highly suspicious
        _add_tx(velocity_chain[1], velocity_chain[2],
                round(amt * rng.uniform(0.94, 0.99), 2),
                t + timedelta(minutes=rng.randint(5, 15)))
        t += timedelta(hours=rng.randint(2, 6))

    # ── 8. Layering with decreasing amounts (Pattern #3) ────────────────
    layer_chain = ["LAYER_L01", "LAYER_L02", "LAYER_L03", "LAYER_L04", "LAYER_L05"]
    t = base_time + timedelta(days=12, hours=10)
    lay_amt = 12000.0
    for i in range(len(layer_chain) - 1):
        _add_tx(layer_chain[i], layer_chain[i + 1], round(lay_amt, 2), t)
        lay_amt *= (1 - rng.uniform(0.03, 0.06))    # 3-6 % commission deduction
        t += timedelta(hours=rng.randint(1, 4))
    # Second layering pass
    t += timedelta(days=3)
    lay_amt = 9500.0
    for i in range(len(layer_chain) - 1):
        _add_tx(layer_chain[i], layer_chain[i + 1], round(lay_amt, 2), t)
        lay_amt *= (1 - rng.uniform(0.03, 0.06))
        t += timedelta(hours=rng.randint(1, 3))

    # ── 9. Structuring / threshold avoidance (Pattern #10) ──────────────
    # Repeated amounts just below $10 000 AML threshold
    structurer = "STRUCT_SENDER"
    struct_receivers = [f"STRUCT_R{i:02d}" for i in range(1, 7)]
    t = base_time + timedelta(days=6, hours=9)
    for r in struct_receivers:
        amt = round(rng.uniform(9600, 9990), 2)    # conspicuously just under $10 000
        _add_tx(structurer, r, amt, t)
        t += timedelta(hours=rng.randint(4, 12))

    # ── 10. New account burst (Pattern #8) ───────────────────────────────
    # Account created on day 58, immediately processes huge volume
    burst_acct = "NEWBURST_01"
    t = base_time + timedelta(days=58, hours=8)
    for i in range(8):
        peer = f"BURST_PEER_{i:02d}"
        _add_tx(peer, burst_acct, round(rng.uniform(2000, 4000), 2), t)
        t += timedelta(minutes=rng.randint(20, 60))
    # Immediately distribute
    t += timedelta(hours=1)
    for i in range(6):
        _add_tx(burst_acct, f"BURST_OUT_{i:02d}",
                round(rng.uniform(1500, 3500), 2), t)
        t += timedelta(minutes=rng.randint(10, 40))

    # ── 11. Tight community cluster (Pattern #9) ────────────────────────
    # 5 accounts that ONLY transact among themselves — a suspicious cluster
    cluster = [f"CLUST_{i:02d}" for i in range(1, 6)]
    t = base_time + timedelta(days=30, hours=10)
    for _ in range(20):       # 20 internal transactions
        s, r = rng.sample(cluster, 2)
        _add_tx(s, r, round(rng.uniform(500, 2000), 2), t)
        t += timedelta(hours=rng.randint(1, 8))

    # ── Build DataFrame ──────────────────────────────────────────────────
    df = pd.DataFrame(rows)
    # Shuffle rows so patterns aren't visually obvious in the raw CSV
    df = df.sample(frac=1, random_state=seed).reset_index(drop=True)
    return df


def sample_csv_bytes() -> bytes:
    """Return sample CSV as UTF-8 bytes (for Streamlit download button)."""
    df = generate_sample_csv()
    return df.to_csv(index=False).encode("utf-8")
