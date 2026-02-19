# 💰 Money Muling Detection Engine

A **graph-theory-based** web application that detects money muling patterns in financial transaction data using cycle detection, smurfing analysis, shell-network tracing, and entropy-based scoring.

---

## 🚀 Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Launch the Flask GUI (recommended)
python gui_app.py
```

Open your browser at **http://localhost:5000**.

- Click **⚡ Demo** to run with synthetic data, or upload your own CSV.
- Click **🛡️ Admin** in the header to open the Admin Panel.

---

## 🛡️ Admin Panel

Access at **http://localhost:5000/admin** — provides:

- **Account overview** — all accounts with AI scores, risk levels, detected patterns
- **Flag / Review / Clear** — override AI classification per account
- **Admin notes** — add free-text notes to any account
- **Transaction tracing** — click 🔍 Trace to see:
  - Every sent/received transaction with amounts and timestamps
  - Network graph of connected accounts
  - Stats: total sent, received, net balance, connected accounts
  - Chain-trace into any counterparty's transactions
- **Filters** — filter by flagged / under review / cleared / high-risk
- **Search** — search accounts by ID
- **Bulk actions** — flag all high-risk or review all medium-risk at once
- **CSV export** — download admin review as a CSV file

---

## 📂 Project Structure

```
money-muling-engine/
│
├── app.py                      # Streamlit web UI
├── gui_app.py                  # Flask-based GUI (recommended)
├── run_local.py                # CLI runner
├── detection/
│   ├── cycles.py               # Circular fund routing (DFS cycle detection)
│   ├── smurfing.py             # Fan-in / Fan-out structuring patterns
│   ├── shell_network.py        # Layered pass-through relay detection
│   ├── velocity.py             # Rapid pass-through detection
│   ├── layering.py             # Decreasing-amount chain detection
│   ├── structuring.py          # Threshold avoidance detection
│   ├── community.py            # Community clusters & new account bursts
│   └── scoring.py              # Suspicion scoring engine + entropy
│
├── utils/
│   ├── graph_builder.py        # NetworkX graph construction
│   ├── json_export.py          # JSON report generation
│   ├── sample_data.py          # Synthetic demo data generator
│   └── validation.py           # CSV schema validation & cleaning
│
├── templates/
│   ├── index.html              # Main dashboard UI
│   └── admin.html              # Admin panel UI
│
├── requirements.txt
└── README.md
```

---

## 📄 Input Format

Upload a **CSV** file with these exact columns:

| Column           | Type   | Example                   |
|------------------|--------|---------------------------|
| `transaction_id` | string | `TXN_00001`               |
| `sender_id`      | string | `ACC_00123`               |
| `receiver_id`    | string | `ACC_00456`               |
| `amount`         | float  | `1500.00`                 |
| `timestamp`      | string | `2025-01-15 14:30:00`     |

Timestamp format: **YYYY-MM-DD HH:MM:SS**

---

## 🔍 Detection Patterns

### 1. Circular Fund Routing (Cycles)
Detects directed cycles of length 3–5 using DFS. The classic mule signature:
**A → B → C → A**.

### 2. Smurfing / Structuring
- **Fan-In:** 10+ senders → 1 receiver (collection hub)
- **Fan-Out:** 1 sender → 10+ receivers (distribution hub)
- Time-window clustering and amount variance analysis

### 3. Layered Shell Networks
Traces relay chains where intermediate nodes:
- Have near-zero net balance (money in ≈ money out)
- Low total degree (exist only to relay funds)
- Rapid forwarding window (< 24 hours)

### 4. Suspicion Scoring (0–100 Scale)

This is a **deterministic, rule-based pattern-matching engine** — not a trained ML model. Each account receives a suspicion score by summing weighted points across 10 detection patterns:

| # | Factor                  | Max Weight | How It's Detected |
|---|------------------------|-----------|-------------------|
| 1 | Cycle Participation    | 40 pts    | Circular money flow (A→B→C→A). First cycle = 30 pts, each extra adds 5 |
| 2 | Smurfing Hub           | 30 pts    | Fan-in (many→one) or fan-out (one→many) concentration. +5 for low variance, +5 for timing |
| 3 | Rapid Pass-Through     | 20 pts    | Account in velocity chain — money in→out within minutes |
| 4 | Layering (Decreasing)  | 20 pts    | Decreasing-amount chains (A→B $10k, B→C $9.5k, C→D $9k) |
| 5 | Structuring            | 18 pts    | Transactions just below reporting thresholds (e.g. $9,900) |
| 6 | Shell Pass-Through     | 15 pts    | Near-zero retention — money in ≈ money out, no economic activity |
| 7 | New Account Burst      | 15 pts    | Freshly created account with sudden high transaction volume |
| 8 | Community / SCC        | 12 pts    | Tightly connected group with heavy internal transfers |
| 9 | Amount Consistency     | 10 pts    | Retention < 5% of throughput |
| 10| Low Entropy            | 10 pts    | Predictable counterparty patterns (Shannon entropy < 1.5) |

#### Score Calculation

```
raw_score = sum of all triggered pattern weights
final_score = min(100, raw_score)     # capped at 100
```

#### Risk Classification

| Risk Level | Score Range |
|-----------|-------------|
| 🔴 HIGH   | ≥ 50        |
| 🟡 MEDIUM | 25 – 49     |
| 🟢 LOW    | < 25        |

### 5. False Positive Control
High-degree nodes (≥ 50 connections) with stable timing regularity and no cycle participation receive a **Trust Multiplier** discount (up to 40% reduction).

---

## 📊 Output

### Interactive Graph
- Directed edges (sender → receiver)
- Color-coded by risk level (red/orange/yellow/blue)
- Fraud ring members share a ring colour
- Hover for account details (score, amounts, patterns)

### Downloadable JSON Report

```json
{
  "suspicious_accounts": [
    {
      "account_id": "ACC_00123",
      "suspicion_score": 87.5,
      "detected_patterns": ["cycle_participant_x1", "high_velocity"],
      "ring_id": "RING_001"
    }
  ],
  "fraud_rings": [
    {
      "ring_id": "RING_001",
      "member_accounts": ["ACC_00123", "ACC_00456"],
      "pattern_type": "cycle",
      "risk_score": 95.3
    }
  ],
  "summary": {
    "total_accounts_analyzed": 500,
    "suspicious_accounts_flagged": 15,
    "fraud_rings_detected": 4,
    "processing_time_seconds": 2.3
  }
}
```

### Fraud Ring Summary Table
| Ring ID   | Pattern Type | Member Count | Risk Score | Member Account IDs |
|-----------|-------------|--------------|------------|-------------------|
| RING_001  | cycle       | 3            | 95.3       | ACC_001, ACC_002  |

---

## ⚙️ Performance

- Handles up to **10 000 transactions**
- Typical processing time: **< 30 seconds**
- Efficient use of NetworkX algorithms and pandas vectorized operations

---

## 🛠️ Tech Stack

- **Python 3.10+**
- **Flask** — web application framework (GUI)
- **Streamlit** — alternative web UI
- **NetworkX** — graph construction & analysis
- **Pandas / NumPy** — data wrangling
- **vis.js** — interactive graph visualization
- **Tailwind CSS** — UI styling

---

## 📝 License

MIT
