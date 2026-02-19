"""
validation.py — CSV input validation for the Money Muling Detection Engine.

Validates uploaded CSV files against the required schema before any
graph construction or detection logic runs.
"""

from __future__ import annotations

import pandas as pd
import numpy as np
from typing import Tuple, List

# ── Required schema ──────────────────────────────────────────────────────────
REQUIRED_COLUMNS = {
    "transaction_id": "string",
    "sender_id": "string",
    "receiver_id": "string",
    "amount": "float",
    "timestamp": "datetime",
}

TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"


# ── Public API ───────────────────────────────────────────────────────────────

def validate_csv(df: pd.DataFrame) -> Tuple[bool, List[str], pd.DataFrame]:
    """Validate and clean an uploaded transaction DataFrame.

    Parameters
    ----------
    df : pd.DataFrame
        Raw DataFrame read from the user-uploaded CSV.

    Returns
    -------
    is_valid : bool
        ``True`` if the data passes all checks.
    errors : list[str]
        Human-readable error messages (empty when valid).
    cleaned_df : pd.DataFrame
        Cleaned / type-cast copy of the input (empty DataFrame on failure).
    """
    errors: List[str] = []

    # 1. Check required columns ------------------------------------------------
    missing = set(REQUIRED_COLUMNS.keys()) - set(df.columns)
    if missing:
        errors.append(f"Missing required columns: {', '.join(sorted(missing))}")
        return False, errors, pd.DataFrame()

    # Work on a copy so downstream mutations don't affect the original
    cleaned = df.copy()

    # 2. Strip whitespace from string columns ----------------------------------
    for col in ("transaction_id", "sender_id", "receiver_id"):
        cleaned[col] = cleaned[col].astype(str).str.strip()

    # 3. Check for empty IDs ---------------------------------------------------
    for col in ("transaction_id", "sender_id", "receiver_id"):
        n_empty = (cleaned[col] == "").sum() + cleaned[col].isna().sum()
        if n_empty > 0:
            errors.append(f"Column '{col}' has {n_empty} empty/null value(s).")

    # 4. Validate uniqueness of transaction_id ---------------------------------
    dup_count = cleaned["transaction_id"].duplicated().sum()
    if dup_count:
        errors.append(
            f"Column 'transaction_id' has {dup_count} duplicate value(s)."
        )

    # 5. Cast amount to float --------------------------------------------------
    cleaned["amount"] = pd.to_numeric(cleaned["amount"], errors="coerce")
    n_bad_amount = cleaned["amount"].isna().sum()
    if n_bad_amount:
        errors.append(
            f"Column 'amount' has {n_bad_amount} non-numeric value(s)."
        )

    # 6. Ensure positive amounts -----------------------------------------------
    if not cleaned["amount"].isna().all():
        n_neg = (cleaned["amount"] <= 0).sum()
        if n_neg:
            errors.append(
                f"Column 'amount' has {n_neg} non-positive value(s). "
                "All amounts must be > 0."
            )

    # 7. Parse timestamp -------------------------------------------------------
    cleaned["timestamp"] = pd.to_datetime(
        cleaned["timestamp"], format=TIMESTAMP_FORMAT, errors="coerce"
    )
    n_bad_ts = cleaned["timestamp"].isna().sum()
    if n_bad_ts:
        errors.append(
            f"Column 'timestamp' has {n_bad_ts} value(s) that don't match "
            f"format '{TIMESTAMP_FORMAT}'."
        )

    # 8. Self-transfers --------------------------------------------------------
    n_self = (cleaned["sender_id"] == cleaned["receiver_id"]).sum()
    if n_self:
        errors.append(
            f"Found {n_self} self-transfer(s) (sender == receiver). "
            "These will be dropped."
        )
        cleaned = cleaned[cleaned["sender_id"] != cleaned["receiver_id"]]

    # 9. Row count check -------------------------------------------------------
    if len(cleaned) == 0:
        errors.append("No valid transactions remain after cleaning.")
        return False, errors, pd.DataFrame()

    # 10. Performance guard (soft warning) -------------------------------------
    if len(cleaned) > 10_000:
        errors.append(
            f"Warning: {len(cleaned)} transactions detected. "
            "Performance may degrade above 10 000 rows."
        )
        # Not a hard failure — allow processing to continue

    is_valid = not any(
        e for e in errors
        if not e.startswith("Warning:") and "self-transfer" not in e.lower()
    )

    # Sort by timestamp for deterministic downstream processing
    if is_valid:
        cleaned = cleaned.sort_values("timestamp").reset_index(drop=True)

    return is_valid, errors, cleaned


def quick_stats(df: pd.DataFrame) -> dict:
    """Return a small summary dict for display in the Streamlit sidebar.

    Parameters
    ----------
    df : pd.DataFrame
        The *cleaned* DataFrame (post-validation).

    Returns
    -------
    dict
        Keys: total_transactions, unique_senders, unique_receivers,
              unique_accounts, min_amount, max_amount, date_range.
    """
    all_accounts = set(df["sender_id"].unique()) | set(df["receiver_id"].unique())
    return {
        "total_transactions": len(df),
        "unique_senders": df["sender_id"].nunique(),
        "unique_receivers": df["receiver_id"].nunique(),
        "unique_accounts": len(all_accounts),
        "min_amount": float(df["amount"].min()),
        "max_amount": float(df["amount"].max()),
        "date_range": (
            str(df["timestamp"].min()),
            str(df["timestamp"].max()),
        ),
    }
