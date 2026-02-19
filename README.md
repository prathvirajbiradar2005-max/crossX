# 💰 Money Muling Detection Engine

A **graph-theory-based** web application that detects money muling patterns in financial transaction data using cycle detection, smurfing analysis, shell-network tracing, and entropy-based scoring.

---

## 🚀 Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Launch the app
streamlit run app.py
```

Open your browser at **http://localhost:8501** and upload a CSV file.

---

## 📂 Project Structure

```
money-muling-engine/
│
├── app.py                      # Streamlit web UI
├── detection/
│   ├── cycles.py               # Circular fund routing (DFS cycle detection)
│   ├── smurfing.py             # Fan-in / Fan-out structuring patterns
│   ├── shell_network.py        # Layered pass-through relay detection
│   └── scoring.py              # Suspicion scoring engine + entropy
│
├── utils/
│   ├── graph_builder.py        # NetworkX graph construction
│   ├── json_export.py          # JSON report generation
│   └── validation.py           # CSV schema validation & cleaning
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

### 4. Suspicion Scoring

| Factor               | Weight   |
|----------------------|----------|
| Cycle Participation  | 40 pts   |
| Smurfing Hub         | 30 pts   |
| High Velocity        | 20 pts   |
| Shell Pass-Through   | 15 pts   |
| Amount Consistency   | 10 pts   |
| Low Entropy          | 10 pts   |

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
- **Streamlit** — web application framework
- **NetworkX** — graph construction & analysis
- **Pandas / NumPy** — data wrangling
- **PyVis** — interactive graph visualization

---

## 📝 License

MIT
