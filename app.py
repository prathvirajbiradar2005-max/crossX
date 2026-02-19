"""
app.py — Streamlit web application for the Money Muling Detection Engine.

Run with:  streamlit run app.py
"""

from __future__ import annotations

import time
import json
import tempfile
import os
from pathlib import Path

import streamlit as st
import pandas as pd
import networkx as nx
from pyvis.network import Network

# ── Local imports ─────────────────────────────────────────────────────────────
from utils.validation import validate_csv, quick_stats
from utils.graph_builder import (
    build_transaction_graph,
    build_simple_digraph,
    get_account_list,
)
from utils.json_export import (
    generate_report,
    report_to_json_string,
    build_ring_summary_table,
)
from utils.sample_data import sample_csv_bytes
from detection.cycles import detect_cycles
from detection.smurfing import detect_smurfing
from detection.shell_network import detect_shell_networks
from detection.scoring import compute_suspicion_scores

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Money Muling Detection Engine",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown(
    """
    <style>
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        border-radius: 12px;
        padding: 20px;
        color: white;
        text-align: center;
        margin: 5px;
    }
    .metric-card h2 { margin: 0; font-size: 2.2rem; }
    .metric-card p  { margin: 0; font-size: 0.9rem; opacity: 0.85; }
    .risk-high   { color: #ff4b4b; font-weight: bold; }
    .risk-medium { color: #ffa726; font-weight: bold; }
    .risk-low    { color: #66bb6a; }
    </style>
    """,
    unsafe_allow_html=True,
)


# ══════════════════════════════════════════════════════════════════════════════
#  SIDEBAR — File Upload & Controls
# ══════════════════════════════════════════════════════════════════════════════

st.sidebar.title("🔍 Muling Detection Engine")
st.sidebar.markdown("---")
st.sidebar.subheader("1 · Upload Transactions")

uploaded_file = st.sidebar.file_uploader(
    "Upload CSV file",
    type=["csv"],
    help=(
        "Required columns: transaction_id, sender_id, receiver_id, "
        "amount, timestamp (YYYY-MM-DD HH:MM:SS)"
    ),
)

score_threshold = st.sidebar.slider(
    "Suspicion score threshold",
    min_value=0.0,
    max_value=100.0,
    value=5.0,
    step=1.0,
    help="Only accounts scoring above this value appear in the report.",
)

st.sidebar.markdown("---")
st.sidebar.subheader("2 · Detection Parameters")
fan_threshold = st.sidebar.number_input(
    "Smurfing fan degree threshold", min_value=3, max_value=50, value=10
)
window_hours = st.sidebar.number_input(
    "Time window (hours) for clustering", min_value=1.0, max_value=720.0, value=72.0
)

# ══════════════════════════════════════════════════════════════════════════════
#  MAIN AREA
# ══════════════════════════════════════════════════════════════════════════════

st.title("💰 Money Muling Detection Engine")
st.caption("Graph-Theory-Based Fraud Detection  ·  Upload → Detect → Visualize → Export")

if uploaded_file is None:
    st.info(
        "👈 Upload a transaction CSV to get started.\n\n"
        "**Required columns:** `transaction_id`, `sender_id`, `receiver_id`, "
        "`amount`, `timestamp` (YYYY-MM-DD HH:MM:SS)"
    )

    st.markdown("---")
    st.subheader("📎 No CSV? Try the built-in sample data")
    st.markdown(
        "Download the sample CSV below — it contains **~500 transactions** "
        "with embedded fraud patterns (cycles, smurfing, shell networks, "
        "and normal traffic) so you can test the engine immediately."
    )
    st.download_button(
        label="⬇️ Download Sample CSV",
        data=sample_csv_bytes(),
        file_name="sample_transactions.csv",
        mime="text/csv",
    )
    st.stop()

# ── Read & Validate ──────────────────────────────────────────────────────────
import io

# Re-read with BOM-safe encoding to avoid invisible character issues
uploaded_file.seek(0)
raw_bytes = uploaded_file.read()
# Decode with utf-8-sig to strip BOM, then re-parse
text = raw_bytes.decode("utf-8-sig", errors="replace")
raw_df = pd.read_csv(io.StringIO(text))

# ── Debug: show raw columns & first rows so users can verify the upload ───
with st.expander("🐛 Debug — Raw CSV Preview", expanded=False):
    st.write("**Columns detected:**", raw_df.columns.tolist())
    st.dataframe(raw_df.head(2), use_container_width=True)

is_valid, errors, df = validate_csv(raw_df)

if errors:
    with st.expander("⚠️ Validation Messages", expanded=not is_valid):
        for e in errors:
            if e.startswith("Warning:"):
                st.warning(e)
            else:
                st.error(e)

if not is_valid:
    st.error("CSV validation failed. Fix the errors above and re-upload.")
    st.stop()

# ── Quick stats in sidebar ───────────────────────────────────────────────────
stats = quick_stats(df)
st.sidebar.markdown("---")
st.sidebar.subheader("📊 Data Summary")
st.sidebar.metric("Transactions", stats["total_transactions"])
st.sidebar.metric("Unique Accounts", stats["unique_accounts"])
st.sidebar.metric("Amount Range", f"${stats['min_amount']:,.2f} – ${stats['max_amount']:,.2f}")
st.sidebar.metric("Date Range", f"{stats['date_range'][0][:10]} → {stats['date_range'][1][:10]}")

# ══════════════════════════════════════════════════════════════════════════════
#  DETECTION PIPELINE
# ══════════════════════════════════════════════════════════════════════════════

with st.spinner("Building transaction graph and running detection pipeline…"):
    t_start = time.time()

    # Step 1: Build graphs
    multi_graph = build_transaction_graph(df)
    simple_graph = build_simple_digraph(multi_graph)

    # Step 2: Cycle detection
    cycle_results = detect_cycles(simple_graph, min_length=3, max_length=5)

    # Step 3: Smurfing detection
    smurfing_results = detect_smurfing(
        multi_graph, df,
        fan_threshold=int(fan_threshold),
        window_hours=float(window_hours),
    )

    # Step 4: Shell network detection
    shell_results = detect_shell_networks(multi_graph, simple_graph, df)

    # Step 5: Scoring
    scores = compute_suspicion_scores(
        multi_graph, df, cycle_results, smurfing_results, shell_results
    )

    # Step 6: Report
    total_accounts = stats["unique_accounts"]
    processing_time = time.time() - t_start

    report = generate_report(
        scores,
        cycle_results,
        smurfing_results,
        shell_results,
        total_accounts,
        processing_time,
        score_threshold=score_threshold,
    )

# ══════════════════════════════════════════════════════════════════════════════
#  SUMMARY METRICS
# ══════════════════════════════════════════════════════════════════════════════

st.markdown("---")
st.subheader("📈 Detection Summary")

col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("Accounts Analyzed", report["summary"]["total_accounts_analyzed"])
with col2:
    st.metric("Suspicious Flagged", report["summary"]["suspicious_accounts_flagged"])
with col3:
    st.metric("Fraud Rings", report["summary"]["fraud_rings_detected"])
with col4:
    st.metric("Processing Time", f"{report['summary']['processing_time_seconds']}s")

# ══════════════════════════════════════════════════════════════════════════════
#  INTERACTIVE GRAPH VISUALIZATION
# ══════════════════════════════════════════════════════════════════════════════

st.markdown("---")
st.subheader("🕸️ Interactive Transaction Graph")

suspicious_ids = {a["account_id"] for a in report["suspicious_accounts"]}
score_map = {s["account_id"]: s["suspicion_score"] for s in scores}
pattern_map = {s["account_id"]: s["detected_patterns"] for s in scores}

# Build ring membership lookup for colouring
ring_members: dict[str, str] = {}
for ring in report["fraud_rings"]:
    for acct in ring["member_accounts"]:
        ring_members[acct] = ring["ring_id"]

# Ring colours (cycle through a palette)
RING_COLORS = [
    "#ff4b4b", "#ff9800", "#e91e63", "#9c27b0",
    "#3f51b5", "#00bcd4", "#4caf50", "#ffeb3b",
]
ring_color_map: dict[str, str] = {}
ring_ids_ordered = list(dict.fromkeys(ring_members.values()))
for i, rid in enumerate(ring_ids_ordered):
    ring_color_map[rid] = RING_COLORS[i % len(RING_COLORS)]


def _build_pyvis_graph() -> str:
    """Create a PyVis HTML graph and return the path to the temp file."""
    net = Network(
        height="650px",
        width="100%",
        directed=True,
        bgcolor="#0e1117",
        font_color="white",
        notebook=False,
    )
    net.barnes_hut(
        gravity=-3000,
        central_gravity=0.3,
        spring_length=120,
        spring_strength=0.05,
    )

    # Add nodes
    for node in multi_graph.nodes():
        ndata = multi_graph.nodes[node]
        score = score_map.get(node, 0.0)
        patterns = pattern_map.get(node, [])

        # Determine colour
        if node in ring_members:
            color = ring_color_map[ring_members[node]]
        elif score >= 50:
            color = "#ff4b4b"
        elif score >= 20:
            color = "#ffa726"
        elif score > 0:
            color = "#ffeb3b"
        else:
            color = "#90caf9"

        # Size proportional to tx volume (clamped)
        size = max(10, min(50, 10 + ndata.get("tx_count", 1) * 2))

        # Tooltip
        title = (
            f"<b>{node}</b><br>"
            f"Suspicion Score: {score}<br>"
            f"Total Sent: ${ndata.get('total_sent', 0):,.2f}<br>"
            f"Total Received: ${ndata.get('total_received', 0):,.2f}<br>"
            f"Transactions: {ndata.get('tx_count', 0)}<br>"
            f"Patterns: {', '.join(patterns) if patterns else 'None'}<br>"
        )
        if node in ring_members:
            title += f"Ring: {ring_members[node]}<br>"

        # Border for suspicious nodes
        border_width = 3 if node in suspicious_ids else 1
        border_color = "#ffffff" if node in suspicious_ids else color

        net.add_node(
            node,
            label=node,
            color={
                "background": color,
                "border": border_color,
                "highlight": {"background": "#ffffff", "border": color},
            },
            size=size,
            title=title,
            borderWidth=border_width,
            font={"size": 10, "color": "white"},
        )

    # Add edges (use simple graph to avoid clutter from parallel edges)
    for u, v, edata in simple_graph.edges(data=True):
        total_amount = edata.get("total_amount", 0.0)
        tx_count = edata.get("tx_count", 1)

        # Edge colour: red if both endpoints are suspicious
        if u in suspicious_ids and v in suspicious_ids:
            edge_color = "#ff4b4b"
            width = 3
        elif u in suspicious_ids or v in suspicious_ids:
            edge_color = "#ffa726"
            width = 2
        else:
            edge_color = "#555555"
            width = 1

        edge_title = (
            f"{u} → {v}<br>"
            f"Total: ${total_amount:,.2f}<br>"
            f"Transactions: {tx_count}"
        )

        net.add_edge(
            u, v,
            value=width,
            title=edge_title,
            color=edge_color,
            arrows="to",
            smooth={"type": "curvedCW", "roundness": 0.15},
        )

    # Write to temp file
    tmp_path = os.path.join(tempfile.gettempdir(), "muling_graph.html")
    net.save_graph(tmp_path)
    return tmp_path


graph_path = _build_pyvis_graph()

with open(graph_path, "r", encoding="utf-8") as f:
    graph_html = f.read()

st.components.v1.html(graph_html, height=670, scrolling=False)

# Legend
with st.expander("🎨 Graph Legend"):
    lcol1, lcol2, lcol3, lcol4 = st.columns(4)
    lcol1.markdown("🔴 **High risk** (score ≥ 50)")
    lcol2.markdown("🟠 **Medium risk** (score 20–49)")
    lcol3.markdown("🟡 **Low risk** (score 1–19)")
    lcol4.markdown("🔵 **Clean** (score 0)")
    st.markdown("**Colored borders / nodes** indicate fraud ring membership. Hover over nodes for details.")

# ══════════════════════════════════════════════════════════════════════════════
#  SUSPICIOUS ACCOUNTS TABLE
# ══════════════════════════════════════════════════════════════════════════════

st.markdown("---")
st.subheader("🚨 Suspicious Accounts")

if report["suspicious_accounts"]:
    sus_df = pd.DataFrame(report["suspicious_accounts"])
    sus_df = sus_df.rename(columns={
        "account_id": "Account ID",
        "suspicion_score": "Suspicion Score",
        "detected_patterns": "Detected Patterns",
        "ring_id": "Ring ID",
    })
    sus_df["Detected Patterns"] = sus_df["Detected Patterns"].apply(
        lambda p: ", ".join(p) if isinstance(p, list) else str(p)
    )
    st.dataframe(
        sus_df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "Suspicion Score": st.column_config.ProgressColumn(
                min_value=0, max_value=100, format="%.1f"
            ),
        },
    )
else:
    st.success("No accounts exceed the suspicion threshold. 🎉")

# ══════════════════════════════════════════════════════════════════════════════
#  FRAUD RING SUMMARY TABLE
# ══════════════════════════════════════════════════════════════════════════════

st.markdown("---")
st.subheader("🔗 Fraud Ring Summary")

ring_rows = build_ring_summary_table(report)
if ring_rows:
    ring_df = pd.DataFrame(ring_rows)
    st.dataframe(
        ring_df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "Risk Score": st.column_config.ProgressColumn(
                min_value=0, max_value=100, format="%.1f"
            ),
        },
    )
else:
    st.info("No fraud rings detected.")

# ══════════════════════════════════════════════════════════════════════════════
#  DETECTION DETAILS (EXPANDABLE)
# ══════════════════════════════════════════════════════════════════════════════

st.markdown("---")
st.subheader("🔬 Detection Details")

tab_cycles, tab_smurf, tab_shell = st.tabs(
    ["♻️ Cycles", "🐿️ Smurfing", "🐚 Shell Networks"]
)

with tab_cycles:
    n_cycles = len(cycle_results.get("cycles", []))
    st.metric("Cycles Found", n_cycles)
    if n_cycles:
        for i, cycle in enumerate(cycle_results["cycles"][:20], 1):
            st.code(f"Cycle {i}: {' → '.join(cycle)} → {cycle[0]}")
    else:
        st.info("No directed cycles of length 3–5 detected.")

with tab_smurf:
    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown("**Fan-In Hubs** (many senders → 1 receiver)")
        fi = smurfing_results.get("fan_in_hubs", [])
        if fi:
            for h in fi[:10]:
                st.markdown(
                    f"- **{h['hub_account']}** ← {h['distinct_counterparties']} "
                    f"senders | Total ${h['total_amount']:,.2f} "
                    f"| CV={h['amount_cv']:.3f} | Window={h['window_ratio']:.1%}"
                )
        else:
            st.info("No fan-in hubs detected.")
    with col_b:
        st.markdown("**Fan-Out Hubs** (1 sender → many receivers)")
        fo = smurfing_results.get("fan_out_hubs", [])
        if fo:
            for h in fo[:10]:
                st.markdown(
                    f"- **{h['hub_account']}** → {h['distinct_counterparties']} "
                    f"receivers | Total ${h['total_amount']:,.2f} "
                    f"| CV={h['amount_cv']:.3f} | Window={h['window_ratio']:.1%}"
                )
        else:
            st.info("No fan-out hubs detected.")

with tab_shell:
    pt_nodes = shell_results.get("passthrough_nodes", set())
    chains = shell_results.get("chains", [])
    st.metric("Pass-Through Nodes", len(pt_nodes))
    st.metric("Shell Chains", len(chains))
    if chains:
        for i, chain in enumerate(chains[:15], 1):
            st.code(f"Chain {i} (len {len(chain)}): {' → '.join(chain)}")
    else:
        st.info("No shell/pass-through chains detected.")

# ══════════════════════════════════════════════════════════════════════════════
#  JSON DOWNLOAD
# ══════════════════════════════════════════════════════════════════════════════

st.markdown("---")
st.subheader("📥 Download Report")

json_str = report_to_json_string(report)

col_dl1, col_dl2 = st.columns([1, 3])
with col_dl1:
    st.download_button(
        label="⬇️ Download JSON Report",
        data=json_str,
        file_name="muling_detection_report.json",
        mime="application/json",
    )
with col_dl2:
    with st.expander("Preview JSON"):
        st.json(report)

# ── Footer ────────────────────────────────────────────────────────────────────
st.markdown("---")
st.caption(
    "Money Muling Detection Engine · Built with Streamlit, NetworkX & PyVis · "
    "Graph-Theory-Based Fraud Analytics"
)
