"""
run_local.py — Command-line interface for Money Muling Detection Engine.

Run with:  python run_local.py [csv_file]
           python run_local.py --sample    (use built-in sample data)
"""

import sys
import json
import time
import pandas as pd
from pathlib import Path

# Local imports
from utils.validation import validate_csv, quick_stats
from utils.graph_builder import build_transaction_graph, build_simple_digraph
from utils.sample_data import generate_sample_csv
from utils.json_export import generate_report, report_to_json_string
from detection.cycles import detect_cycles
from detection.smurfing import detect_smurfing
from detection.shell_network import detect_shell_networks
from detection.velocity import detect_velocity
from detection.layering import detect_layering
from detection.structuring import detect_structuring
from detection.community import detect_communities, detect_new_accounts
from detection.scoring import compute_suspicion_scores


def print_separator(title: str = "") -> None:
    """Print a visual separator."""
    if title:
        print(f"\n{'='*60}\n  {title}\n{'='*60}")
    else:
        print("-" * 60)


def run_detection(df: pd.DataFrame) -> dict:
    """Run all detection algorithms on the transaction data."""
    
    # Validate the data
    is_valid, errors, cleaned_df = validate_csv(df)
    if not is_valid:
        print("\n[ERROR] Invalid CSV data:")
        for err in errors:
            print(f"  - {err}")
        sys.exit(1)
    
    print(f"[OK] Loaded {len(cleaned_df)} transactions")
    
    # Build graphs
    print("[...] Building transaction graph...")
    G = build_transaction_graph(cleaned_df)
    simple_G = build_simple_digraph(G)
    print(f"[OK] Graph: {G.number_of_nodes()} accounts, {G.number_of_edges()} transactions")
    
    # Run detection algorithms
    print_separator("Running Detection Algorithms")
    
    print("[...] Detecting circular fund routing (cycles)...")
    cycle_results = detect_cycles(simple_G)
    print(f"[OK] Found {len(cycle_results['cycles'])} cycles, {len(cycle_results['cycle_accounts'])} accounts involved")
    
    print("[...] Detecting smurfing patterns...")
    smurfing_results = detect_smurfing(G, cleaned_df)
    fan_in = smurfing_results.get("fan_in_hubs", [])
    fan_out = smurfing_results.get("fan_out_hubs", [])
    print(f"[OK] Found {len(fan_in)} fan-in hubs, {len(fan_out)} fan-out hubs")
    
    print("[...] Detecting shell networks...")
    shell_results = detect_shell_networks(G, simple_G, cleaned_df)
    shell_accounts = shell_results.get("shell_accounts", set())
    print(f"[OK] Found {len(shell_accounts)} shell/relay accounts")

    print("[...] Detecting rapid pass-through (velocity)...")
    velocity_results = detect_velocity(G, cleaned_df)
    vel_flagged = velocity_results.get("flagged_accounts", set())
    print(f"[OK] Found {len(vel_flagged)} velocity-flagged accounts")

    print("[...] Detecting layering chains...")
    layering_results = detect_layering(G, cleaned_df)
    layer_chains = layering_results.get("chains", [])
    print(f"[OK] Found {len(layer_chains)} layering chains")

    print("[...] Detecting structuring / threshold avoidance...")
    structuring_results = detect_structuring(G, cleaned_df)
    struct_flagged = structuring_results.get("flagged_accounts", set())
    repeat_flagged = structuring_results.get("repeat_flagged", set())
    print(f"[OK] Found {len(struct_flagged)} structuring, {len(repeat_flagged)} repeat-amount accounts")

    print("[...] Detecting communities / SCCs...")
    community_results = detect_communities(G, simple_G, cleaned_df)
    comm_accts = community_results.get("community_accounts", set())
    print(f"[OK] Found {len(comm_accts)} accounts in suspicious communities")

    print("[...] Detecting new-account bursts...")
    new_account_results = detect_new_accounts(G, cleaned_df)
    new_flagged = new_account_results.get("flagged_accounts", set())
    print(f"[OK] Found {len(new_flagged)} new-account burst accounts")

    print("[...] Computing suspicion scores...")
    scores = compute_suspicion_scores(
        G, cleaned_df,
        cycle_results, smurfing_results, shell_results,
        velocity_results=velocity_results,
        layering_results=layering_results,
        structuring_results=structuring_results,
        community_results=community_results,
        new_account_results=new_account_results,
    )
    print(f"[OK] Scored {len(scores)} accounts")
    
    return {
        "graph": G,
        "simple_graph": simple_G,
        "cleaned_df": cleaned_df,
        "cycle_results": cycle_results,
        "smurfing_results": smurfing_results,
        "shell_results": shell_results,
        "velocity_results": velocity_results,
        "layering_results": layering_results,
        "structuring_results": structuring_results,
        "community_results": community_results,
        "new_account_results": new_account_results,
        "scores": scores,
    }


def print_results(results: dict) -> None:
    """Print detection results to console."""
    
    scores = results["scores"]
    cycle_results = results["cycle_results"]
    smurfing_results = results["smurfing_results"]
    shell_results = results["shell_results"]
    velocity_results = results.get("velocity_results", {})
    layering_results = results.get("layering_results", {})
    structuring_results = results.get("structuring_results", {})
    community_results = results.get("community_results", {})
    new_account_results = results.get("new_account_results", {})
    
    # ── High-risk accounts ───────────────────────────────────────────────
    print_separator("HIGH-RISK ACCOUNTS (Score >= 50)")
    high_risk = [s for s in scores if s["suspicion_score"] >= 50]
    
    if high_risk:
        print(f"{'Account':<20} {'Score':>8} {'Patterns':<40}")
        print("-" * 70)
        for acc in high_risk[:20]:  # Top 20
            patterns = ", ".join(acc.get("detected_patterns", []))
            print(f"{acc['account_id']:<20} {acc['suspicion_score']:>8.1f} {patterns:<40}")
    else:
        print("No high-risk accounts found.")
    
    # ── Detected cycles (fraud rings) ────────────────────────────────────
    print_separator("DETECTED FRAUD RINGS (Cycles)")
    rings = cycle_results.get("rings", [])
    
    if rings:
        for i, ring in enumerate(rings, 1):
            members = ring.get("member_accounts", [])
            risk_score = ring.get("risk_score", 0)
            pattern = ring.get("pattern_type", "unknown")
            print(f"\nRing #{i} [{ring.get('ring_id', '')}]: {len(members)} members, risk={risk_score}, type={pattern}")
            print(f"  Members: {', '.join(members)}")
    else:
        cycles = cycle_results.get("cycles", [])
        if cycles:
            for i, cycle in enumerate(cycles[:10], 1):  # Show first 10
                print(f"  Cycle #{i}: {' -> '.join(cycle)} -> {cycle[0]}")
        else:
            print("No circular routing detected.")
    
    # ── Smurfing hubs ────────────────────────────────────────────────────
    print_separator("SMURFING HUBS")
    
    fan_in = smurfing_results.get("fan_in_hubs", [])
    fan_out = smurfing_results.get("fan_out_hubs", [])
    
    if fan_in:
        print("\nFan-In Hubs (Collection Points):")
        for hub in fan_in[:5]:
            if isinstance(hub, dict):
                name = hub.get('hub_account', 'unknown')
                count = hub.get('distinct_counterparties', '?')
                amount = hub.get('total_amount', 0)
                print(f"  - {name}: {count} senders, ${amount:,.2f} total")
            else:
                print(f"  - {hub}")
    
    if fan_out:
        print("\nFan-Out Hubs (Distribution Points):")
        for hub in fan_out[:5]:
            if isinstance(hub, dict):
                name = hub.get('hub_account', 'unknown')
                count = hub.get('distinct_counterparties', '?')
                amount = hub.get('total_amount', 0)
                print(f"  - {name}: {count} receivers, ${amount:,.2f} total")
            else:
                print(f"  - {hub}")
    
    if not fan_in and not fan_out:
        print("No smurfing hubs detected.")
    
    # ── Shell/Relay accounts ─────────────────────────────────────────────
    print_separator("SHELL / RELAY ACCOUNTS")
    shell_accounts = shell_results.get("shell_accounts", set())
    
    if shell_accounts:
        print(f"Found {len(shell_accounts)} pass-through relay accounts:")
        for acc in list(shell_accounts)[:10]:
            print(f"  - {acc}")
    else:
        print("No shell accounts detected.")

    # ── Velocity (rapid pass-through) ────────────────────────────────────
    print_separator("RAPID PASS-THROUGH (Velocity)")
    vel_flagged = velocity_results.get("flagged_accounts", set())
    vel_rapid = velocity_results.get("rapid_accounts", {})
    if vel_flagged:
        for acc in list(vel_flagged)[:10]:
            events = vel_rapid.get(acc, [])
            similar = sum(1 for e in events if e.get("amount_similar"))
            print(f"  - {acc}: {len(events)} rapid pairs ({similar} amount-similar)")
    else:
        print("No rapid pass-through detected.")

    # ── Layering chains ──────────────────────────────────────────────────
    print_separator("LAYERING CHAINS (Decreasing Amounts)")
    lay_chains = layering_results.get("chains", [])
    if lay_chains:
        for i, c in enumerate(lay_chains[:5], 1):
            accts = " → ".join(c["accounts"])
            pct = c.get("avg_deduction_pct", 0)
            print(f"  Chain #{i}: {accts}  (avg deduction {pct:.1f}%)")
    else:
        print("No layering chains detected.")

    # ── Structuring ──────────────────────────────────────────────────────
    print_separator("STRUCTURING / THRESHOLD AVOIDANCE")
    struct_accts = structuring_results.get("structuring_accounts", {})
    if struct_accts:
        for acc, detail in list(struct_accts.items())[:10]:
            thr = detail.get("threshold", 0)
            cnt = detail.get("count_below", 0)
            mean_a = detail.get("mean_amount", 0)
            print(f"  - {acc}: {cnt} txns just below ${thr:,.0f}  (mean ${mean_a:,.2f})")
    else:
        print("No structuring detected.")

    rep_accts = structuring_results.get("amount_repeat_accounts", {})
    if rep_accts:
        print("\nAmount Repetition:")
        for acc, detail in list(rep_accts.items())[:10]:
            amt = detail.get("repeated_amount", 0)
            cnt = detail.get("count", 0)
            print(f"  - {acc}: amount ~${amt:,.2f} repeated {cnt} times")

    # ── Communities / SCCs ───────────────────────────────────────────────
    print_separator("SUSPICIOUS COMMUNITIES / SCCs")
    comms = community_results.get("communities", [])
    sccs = community_results.get("scc_components", [])
    if comms:
        for i, c in enumerate(comms[:5], 1):
            members = c.get("members", [])
            density = c.get("density", 0)
            print(f"  Community #{i}: {len(members)} members, density={density:.3f}")
            print(f"    Members: {', '.join(members[:8])}" + (" ..." if len(members) > 8 else ""))
    if sccs:
        for i, c in enumerate(sccs[:5], 1):
            members = c.get("members", [])
            print(f"  SCC #{i}: {len(members)} members — {', '.join(members[:8])}")
    if not comms and not sccs:
        print("No suspicious communities detected.")

    # ── New account bursts ───────────────────────────────────────────────
    print_separator("NEW ACCOUNT BURSTS")
    new_accts = new_account_results.get("new_accounts", [])
    if new_accts:
        for acc in new_accts[:10]:
            name = acc.get("account_id", "")
            days = acc.get("active_days", 0)
            vol = acc.get("total_volume", 0)
            txn = acc.get("tx_count", 0)
            print(f"  - {name}: {days:.0f} day(s) active, {txn} txns, ${vol:,.2f} volume")
    else:
        print("No new-account burst detected.")
    
    # ── Summary statistics ───────────────────────────────────────────────
    print_separator("SUMMARY")
    total_accounts = len(scores)
    high_risk_count = len([s for s in scores if s["suspicion_score"] >= 50])
    medium_risk_count = len([s for s in scores if 25 <= s["suspicion_score"] < 50])
    low_risk_count = total_accounts - high_risk_count - medium_risk_count
    
    print(f"  Total Accounts Analyzed: {total_accounts}")
    print(f"  High Risk (>=50):        {high_risk_count}")
    print(f"  Medium Risk (25-49):     {medium_risk_count}")
    print(f"  Low Risk (<25):          {low_risk_count}")


def main():
    print_separator("Money Muling Detection Engine")
    
    # Parse arguments
    if len(sys.argv) < 2 or sys.argv[1] == "--sample":
        print("[INFO] Using built-in sample data with embedded fraud patterns...")
        df = generate_sample_csv()
    else:
        csv_path = Path(sys.argv[1])
        if not csv_path.exists():
            print(f"[ERROR] File not found: {csv_path}")
            sys.exit(1)
        print(f"[INFO] Loading CSV: {csv_path}")
        df = pd.read_csv(csv_path)

        # Handle CSVs where every row is wrapped in quotes as a single field
        if len(df.columns) == 1 and "," in df.columns[0]:
            import io
            raw = csv_path.read_text()
            # Strip surrounding quotes from each line
            cleaned_lines = []
            for line in raw.splitlines():
                line = line.strip()
                if line.startswith('"') and line.endswith('"'):
                    line = line[1:-1]
                cleaned_lines.append(line)
            df = pd.read_csv(io.StringIO("\n".join(cleaned_lines)))
            print("[INFO] Re-parsed quoted CSV successfully")
    
    # Run detection
    start_time = time.time()
    results = run_detection(df)
    elapsed = time.time() - start_time
    
    # Print results
    print_results(results)
    
    # Optionally export to JSON
    if "--json" in sys.argv:
        report = generate_report(
            scores=results["scores"],
            cycle_results=results["cycle_results"],
            smurfing_results=results["smurfing_results"],
            shell_results=results["shell_results"],
            total_accounts=results["graph"].number_of_nodes(),
            processing_time=elapsed,
        )
        json_str = report_to_json_string(report)
        output_path = Path("detection_report.json")
        output_path.write_text(json_str)
        print(f"\n[OK] JSON report saved to: {output_path}")
    
    print("\n" + "=" * 60)
    print("  Detection complete!")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
