"""
json_export.py — Generate the downloadable JSON output in the exact
required format.

Output Schema
-------------
{
  "suspicious_accounts": [ ... ],
  "fraud_rings": [ ... ],
  "summary": { ... }
}
"""

from __future__ import annotations

import json
from typing import Any, Dict, List


def generate_report(
    scores: List[Dict[str, Any]],
    cycle_results: Dict[str, Any],
    smurfing_results: Dict[str, Any],
    shell_results: Dict[str, Any],
    total_accounts: int,
    processing_time: float,
    score_threshold: float = 0.0,
) -> Dict[str, Any]:
    """Build the final JSON-serialisable report dictionary.

    Parameters
    ----------
    scores : list[dict]
        Per-account scores from ``scoring.compute_suspicion_scores``,
        already sorted descending by ``suspicion_score``.
    cycle_results, smurfing_results, shell_results : dict
        Raw outputs from each detector module.
    total_accounts : int
        Total unique accounts analysed.
    processing_time : float
        Wall-clock seconds for the full pipeline.
    score_threshold : float
        Minimum score to include in ``suspicious_accounts``.

    Returns
    -------
    dict
        The complete report matching the required JSON schema.
    """
    # ── 1. Suspicious accounts ────────────────────────────────────────────
    suspicious_accounts: List[Dict[str, Any]] = []
    for entry in scores:
        if entry["suspicion_score"] <= score_threshold:
            continue
        suspicious_accounts.append(
            {
                "account_id": entry["account_id"],
                "suspicion_score": entry["suspicion_score"],
                "detected_patterns": entry["detected_patterns"],
                "ring_id": entry["ring_id"],
            }
        )

    # ── 2. Fraud rings (merge all ring types) ─────────────────────────────
    all_rings: List[Dict[str, Any]] = []

    for ring in cycle_results.get("rings", []):
        all_rings.append(
            {
                "ring_id": ring["ring_id"],
                "member_accounts": ring["member_accounts"],
                "pattern_type": ring["pattern_type"],
                "risk_score": ring["risk_score"],
            }
        )

    for ring in smurfing_results.get("rings", []):
        all_rings.append(
            {
                "ring_id": ring["ring_id"],
                "member_accounts": ring["member_accounts"],
                "pattern_type": ring["pattern_type"],
                "risk_score": ring["risk_score"],
            }
        )

    for ring in shell_results.get("rings", []):
        all_rings.append(
            {
                "ring_id": ring["ring_id"],
                "member_accounts": ring["member_accounts"],
                "pattern_type": ring["pattern_type"],
                "risk_score": ring["risk_score"],
            }
        )

    # Sort rings by risk_score descending
    all_rings.sort(key=lambda r: -r["risk_score"])

    # ── 3. Summary ────────────────────────────────────────────────────────
    summary = {
        "total_accounts_analyzed": total_accounts,
        "suspicious_accounts_flagged": len(suspicious_accounts),
        "fraud_rings_detected": len(all_rings),
        "processing_time_seconds": round(processing_time, 1),
    }

    return {
        "suspicious_accounts": suspicious_accounts,
        "fraud_rings": all_rings,
        "summary": summary,
    }


def report_to_json_string(report: Dict[str, Any], indent: int = 2) -> str:
    """Serialise the report dict to a pretty-printed JSON string."""
    return json.dumps(report, indent=indent, default=str)


def build_ring_summary_table(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Build rows for the Fraud Ring Summary Table (Streamlit display).

    Columns: Ring ID, Pattern Type, Member Count, Risk Score,
             Member Account IDs
    """
    rows: List[Dict[str, Any]] = []
    for ring in report.get("fraud_rings", []):
        rows.append(
            {
                "Ring ID": ring["ring_id"],
                "Pattern Type": ring["pattern_type"],
                "Member Count": len(ring["member_accounts"]),
                "Risk Score": ring["risk_score"],
                "Member Account IDs": ", ".join(ring["member_accounts"]),
            }
        )
    return rows
