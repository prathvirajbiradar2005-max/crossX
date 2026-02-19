"""
sample_data.py — Generate realistic synthetic transaction data that
contains money-muling patterns for demonstration and testing.

Patterns embedded:
- Circular routing (A→B→C→A)
- Smurfing fan-in / fan-out
- Shell / pass-through relay chains
- Normal legitimate traffic as background noise
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

    # ── Build DataFrame ──────────────────────────────────────────────────
    df = pd.DataFrame(rows)
    # Shuffle rows so patterns aren't visually obvious in the raw CSV
    df = df.sample(frac=1, random_state=seed).reset_index(drop=True)
    return df


def sample_csv_bytes() -> bytes:
    """Return sample CSV as UTF-8 bytes (for Streamlit download button)."""
    df = generate_sample_csv()
    return df.to_csv(index=False).encode("utf-8")
