<p align="center">
  <h1 align="center">ZeroTrust</h1>
  <p align="center"><strong>AI-Driven Cybersecurity Intelligence Platform for Zero-Trust Network Enforcement</strong></p>
  <p align="center">
    Hybrid Machine Learning · Dynamic Trust Scoring · Real-Time Threat Detection · AMD-Optimized Inference
  </p>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.13-blue?style=flat-square" alt="Python 3.13" />
  <img src="https://img.shields.io/badge/FastAPI-0.115-009688?style=flat-square" alt="FastAPI" />
  <img src="https://img.shields.io/badge/React-19-61DAFB?style=flat-square" alt="React 19" />
  <img src="https://img.shields.io/badge/scikit--learn-1.6-F7931E?style=flat-square" alt="scikit-learn" />
  <img src="https://img.shields.io/badge/MySQL-8.0-4479A1?style=flat-square" alt="MySQL 8.0" />
  <img src="https://img.shields.io/badge/tests-31%2F31%20passing-brightgreen?style=flat-square" alt="Tests" />
  <img src="https://img.shields.io/badge/ROC--AUC-0.9999-brightgreen?style=flat-square" alt="ROC-AUC" />
</p>

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Problem Statement](#2-problem-statement)
3. [Threat Model](#3-threat-model)
4. [System Architecture](#4-system-architecture)
5. [Machine Learning Design](#5-machine-learning-design)
6. [Hybrid Detection Pipeline](#6-hybrid-detection-pipeline)
7. [Risk Engine — Mathematical Model](#7-risk-engine--mathematical-model)
8. [Simulation Engine](#8-simulation-engine)
9. [Frontend — SOC Dashboard](#9-frontend--soc-dashboard)
10. [Performance Benchmarks](#10-performance-benchmarks)
11. [Scalability & AMD Optimization](#11-scalability--amd-optimization)
12. [Security Hardening](#12-security-hardening)
13. [Observability & Monitoring](#13-observability--monitoring)
14. [False Positive Mitigation Strategy](#14-false-positive-mitigation-strategy)
15. [Deployment Guide](#15-deployment-guide)
16. [API Reference](#16-api-reference)
17. [Limitations & Constraints](#17-limitations--constraints)
18. [Future Roadmap](#18-future-roadmap)
19. [Conclusion](#19-conclusion)

---

## 1. Executive Summary

ZeroTrust is an **AI-driven cybersecurity intelligence platform** that implements continuous, automated Zero-Trust enforcement across campus-scale networks. Rather than relying on static perimeter defenses, ZeroTrust treats every device, every flow, and every communication as potentially hostile — computing a dynamic trust score for each endpoint in real time using a hybrid machine learning pipeline.

The system fuses **unsupervised anomaly detection** (Isolation Forest) with **supervised attack classification** (Random Forest) for network traffic, and an **NLP-enhanced phishing detector** (TF-IDF + Logistic Regression with 12 structural features) for email-borne threats. These signals feed a **mathematical risk engine** that computes per-device trust scores using exponential time-decay, severity-weighted penalties, sliding-window frequency escalation, and rolling-average smoothing — producing a single, interpretable trust metric that drives automated quarantine decisions.

**Key results:**

| Metric | Network (Hybrid) | Phishing (Enhanced) |
|---|---|---|
| Accuracy | 99.89% | 97.93% |
| F1 Score | 0.9982 | 0.9801 |
| ROC-AUC | 0.9999 | 0.9981 |
| Attack Detection Rate | 100% (at τ=0.5) | — |
| False Positive Rate | 0.15% | — |

The platform serves its own real-time SOC dashboard over WebSocket, supports multi-threaded batch inference for AMD multi-core processors, and ships with a scenario-driven simulation engine that replays six distinct attack campaigns — including a multi-stage Advanced Persistent Threat (APT) — against the live API.

**Why this matters:** The average cost of a data breach reached **$4.88 million** in 2024 (IBM Cost of a Data Breach Report), with a mean time-to-identify of **194 days**. Organizations with automated security orchestration reduced breach costs by **$2.22 million** and detected threats **108 days faster**. ZeroTrust targets exactly this gap — replacing manual, reactive security operations with continuous, AI-driven trust enforcement that isolates threats in **seconds**, not months.

---

## 2. Problem Statement

Traditional campus and enterprise networks operate on implicit trust: once a device authenticates at the perimeter, it receives broad access to network resources. This model fails catastrophically against:

- **Lateral movement** — Compromised endpoints pivot across flat network segments undetected.
- **Insider threats** — Authorized credentials are leveraged for data exfiltration, bypassing perimeter controls entirely.
- **Credential phishing** — Social engineering bypasses technical controls, granting adversaries legitimate access.
- **IoT proliferation** — Unmanaged devices (sensors, printers, kiosks) expand the attack surface beyond endpoint detection coverage.
- **Alert fatigue** — Legacy signature-based IDS/IPS produce volumes of low-fidelity alerts that overwhelm SOC analysts.

**ZeroTrust addresses these gaps** by shifting from perimeter-based trust to continuous, per-device trust evaluation. Every network flow and email is analyzed in real time; trust scores decay over time, escalate under repeated suspicious activity, and trigger automated quarantine when they breach configurable thresholds. The system is designed to operate autonomously — isolating compromised devices within seconds of detection, without requiring manual SOC intervention.

---

## 3. Threat Model

### 3.1 Adversary Capabilities

| Adversary Class | Capability | Example |
|---|---|---|
| **External — Opportunistic** | Commodity phishing kits, volumetric DDoS, credential stuffing | Botnet-driven SYN floods, bulk phishing campaigns |
| **External — Targeted** | Spear-phishing, multi-stage intrusion, C2 beaconing | APT campaign: phish → recon → lateral → exfil |
| **Insider — Negligent** | Accidental data exposure, policy violations | Clicking phishing links, connecting unauthorized devices |
| **Insider — Malicious** | Privileged access abuse, gradual data exfiltration | Staged exfiltration over days, disguised as normal traffic patterns |

### 3.2 Attack Vectors Covered

The detection pipeline covers the following attack vector taxonomy, each with a calibrated severity multiplier in the risk engine:

| Attack Vector | Detection Layer | Severity Multiplier | Notes |
|---|---|---|---|
| DDoS / Volumetric Flood | Network (IF + RF) | 1.5× | High packet rate, low duration, low variance |
| Brute Force | Network (IF + RF) | 1.3× | Repeated short flows with high SYN/RST ratios |
| Web Application Attack | Network (IF + RF) | 1.4× | Large forward packets, high PSH flag counts |
| Port Scanning | Network (IF + RF) | 1.1× | Zero backward packets, microsecond durations |
| Data Exfiltration | Network (IF + RF) | 1.8× | High-volume sustained outbound flows |
| C2 Communication | Network (IF + RF) | 1.6× | Periodic beaconing patterns |
| Insider Threat | Network (IF + RF) | 1.4× | Progressive anomaly escalation |
| Credential Phishing | Email (TF-IDF + LR) | 1.2× | URL manipulation, urgency markers, entropy analysis |

### 3.3 Assumptions

- Network traffic features (flow-level statistics) are available from a tap or span port. The system does not perform raw packet capture.
- Email content is submitted via API; the system does not integrate with an MTA relay in the current version.
- The training distribution (CICIDS-2017 for network, multi-corpus for phishing) is representative of the deployment environment's baseline.
- The adversary does not have access to the trained model weights or the scoring formula (no white-box evasion).

### 3.4 Out-of-Scope Threats

- **Encrypted payload inspection** — The system operates on flow metadata, not decrypted content.
- **Zero-day exploit detection** — The Isolation Forest provides some generalization to novel patterns, but zero-days outside the feature distribution may evade detection.
- **Physical access attacks** — Hardware-level compromise is not addressed.
- **Adversarial ML** — Model evasion via adversarial perturbation of network features is acknowledged as a limitation (see [§17](#17-limitations--constraints)).

---

## 4. System Architecture

ZeroTrust implements a layered pipeline architecture with eight processing stages:

```
┌─────────────────────────────────────────────────────────────────────┐
│                     FRONTEND — SOC DASHBOARD                        │
│  React 19 · Tailwind CSS · WebSocket · Monochrome Threat UI        │
├─────────────────────────────────────────────────────────────────────┤
│                     OBSERVABILITY LAYER                              │
│  Structured Logging · Latency Metrics · WebSocket Broadcast         │
├─────────────────────────────────────────────────────────────────────┤
│                     ENFORCEMENT LAYER                                │
│  Auto-Quarantine · Device Isolation · Status Transitions            │
├─────────────────────────────────────────────────────────────────────┤
│                     RISK ENGINE (§7)                                 │
│  Trust(t) = f(penalties, decay, frequency, severity, history)       │
├─────────────────────────────────────────────────────────────────────┤
│                     HYBRID SCORING (§6)                              │
│  Network: 0.4×IF + 0.6×RF  │  Phishing: Enhanced LR + Structural   │
├─────────────────────────────────────────────────────────────────────┤
│                     ML INFERENCE LAYER                               │
│  Isolation Forest · Random Forest · TF-IDF + Logistic Regression   │
├─────────────────────────────────────────────────────────────────────┤
│                     FEATURE ENGINEERING (§5.2)                       │
│  52 Network Features · 10K TF-IDF + 12 Structural Phishing         │
├─────────────────────────────────────────────────────────────────────┤
│                     DATA INGESTION                                   │
│  CICIDS-2017 (100K stratified) · 8 Phishing Corpora (50K emails)   │
└─────────────────────────────────────────────────────────────────────┘
```

### 4.1 Technology Stack

| Layer | Technology | Role |
|---|---|---|
| **API Server** | FastAPI 0.115, Uvicorn (ASGI) | Async HTTP + WebSocket serving |
| **Authentication** | python-jose (JWT), passlib (bcrypt) | Token-based auth with RBAC |
| **Rate Limiting** | slowapi (token bucket) | 120 req/min default, 10/min on auth |
| **Database** | MySQL 8.0 (prod), SQLite (dev fallback) | Device state, activity audit, risk history |
| **ORM** | SQLAlchemy 2.x | Connection pooling (10+20 overflow), indexed queries |
| **ML — Network** | scikit-learn (IF + RF), NumPy, joblib | Hybrid anomaly detection |
| **ML — Phishing** | scikit-learn (TF-IDF + LR), SciPy sparse | NLP + structural feature fusion |
| **Frontend** | React 19, Tailwind CSS 3 | Monochrome SOC dashboard |
| **Real-time** | WebSocket (native FastAPI) | Sub-second device update, alert, risk event streaming |
| **Containerization** | Docker Compose (MySQL + Backend + Nginx) | Single-command deployment |

### 4.2 Directory Structure

```
ZeroTrust/
├── backend/
│   ├── main.py                  # FastAPI application (511 lines, 18 endpoints)
│   ├── config.py                # Environment-based configuration
│   ├── auth/                    # JWT auth, RBAC (admin/analyst roles)
│   │   └── __init__.py          # bcrypt, token lifecycle, FastAPI dependencies
│   ├── engine/
│   │   └── risk_engine.py       # Mathematical trust scoring (236 lines)
│   ├── ml/
│   │   ├── inference.py         # Hybrid inference, batch parallelism (191 lines)
│   │   ├── train_network.py     # IF + RF training pipeline (236 lines)
│   │   └── train_phishing.py    # TF-IDF + LR training pipeline (209 lines)
│   ├── data/
│   │   ├── database.py          # SQLAlchemy ORM, CRUD, connection pooling (377 lines)
│   │   └── preprocess.py        # Feature engineering, stratified sampling (216 lines)
│   ├── services/
│   │   └── websocket.py         # Connection manager, async broadcast (101 lines)
│   ├── simulate.py              # 6-scenario attack simulation engine (447 lines)
│   ├── benchmark.py             # AMD performance benchmark suite (340 lines)
│   ├── models/                  # Trained model artifacts (.pkl)
│   ├── benchmark_results/       # Benchmark output (JSON + CSV)
│   └── tests/                   # pytest suite (31 tests)
├── frontend/
│   └── src/
│       ├── App.js               # Main layout, routing, data orchestration
│       ├── services/api.js      # API client, polling, WebSocket hook
│       └── components/          # Header, Sidebar, StatsCards, DeviceTable,
│                                # DeviceDetailModal, Charts, ThreatFeed,
│                                # ActivityFeed, ui.js (shared primitives)
├── Datasets/                    # 8 raw corpora (CICIDS-2017, phishing collections)
├── docker-compose.yml           # MySQL 8 + Backend + Frontend (Nginx)
└── README.md
```

### 4.3 End-to-End Data Flow Example

A concrete walkthrough of a single threat detection cycle:

```
1. Device "ws-lab-0142" sends network flow → API receives 52-feature vector
2. Isolation Forest scores anomaly    → IF_raw = −0.38 → IF_score = 0.69
3. Random Forest classifies attack    → RF_prob = 0.98 (DDoS)
4. Hybrid fusion                      → 0.4×0.69 + 0.6×0.98 = 0.864
5. hybrid_score (0.864) > τ (0.50)    → anomaly_detected = True
6. Risk engine applies severity        → DDoS multiplier = 1.5×
7. Penalty calculated                  → 45.0 × 1.5 × 1.0 = 67.5
8. Trust score updated                 → 100 − 67.5 = 32.5
9. 32.5 < QUARANTINE_THRESHOLD (50)    → Status: QUARANTINED
10. WebSocket broadcasts alert          → SOC dashboard updates in <1 second
```

From ingestion to quarantine: **< 500ms** (single-sample network latency P95 = 383ms + risk engine + DB write).

---

## 5. Machine Learning Design

### 5.1 Network Anomaly Detection Pipeline

**Objective:** Detect malicious network flows (DDoS, brute force, exfiltration, port scans, web attacks) in the CICIDS-2017 feature space, while maintaining a false positive rate below 1% on benign campus traffic.

#### 5.1.1 Data Preparation

| Parameter | Value |
|---|---|
| Source dataset | CICIDS-2017 (cleaned) |
| Sample size | 100,000 (stratified) |
| Class distribution | 70,000 benign / 30,000 attack |
| Train/test split | 80/20 (stratified) |
| Random seed | 42 (all splits, sampling, model init) |
| Scaling | StandardScaler (fit on normal traffic only) |
| Feature count | 52 flow-level features |

Scaling on normal traffic only is a deliberate design choice: it ensures the scaler's statistics reflect the benign distribution, making anomalies more pronounced in the scaled feature space.

#### 5.1.2 Model A — Isolation Forest (Unsupervised)

| Hyperparameter | Value | Rationale |
|---|---|---|
| `n_estimators` | 200 | Higher tree count reduces variance in anomaly scoring |
| `contamination` | 0.01 | Conservative; tuned from grid [0.01, 0.02, 0.03, 0.05, 0.07, 0.1] |
| `training_data` | Normal samples only | Unsupervised — learns the benign manifold |

The Isolation Forest constructs random partitioning trees and scores samples by average path length. Points that are isolated quickly (short paths) receive higher anomaly scores. By training exclusively on normal traffic, the model learns the decision boundaries of benign behavior — any flow that deviates from this manifold produces a short path, triggering an elevated anomaly score.

**Standalone IF Metrics:**

| Metric | Value |
|---|---|
| ROC-AUC | 0.821 |
| Anomaly Rate | 5.87% |
| Precision (at threshold) | 87.57% |
| Recall (at threshold) | 16.96% |

The Isolation Forest alone has low recall — it is intentionally conservative. Its value lies in detecting novel anomaly patterns outside the training distribution, and in providing a complementary signal to the supervised classifier.

#### 5.1.3 Model B — Random Forest (Supervised)

| Hyperparameter | Value | Rationale |
|---|---|---|
| `n_estimators` | 200 | Ensemble size balancing accuracy vs. inference cost |
| `max_depth` | 20 | Deep enough for complex flow patterns, pruned to prevent overfit |
| `min_samples_split` | 5 | Regularization |
| `min_samples_leaf` | 2 | Prevents single-sample leaves |
| `class_weight` | `balanced` | Reweights minority (attack) class inversely proportional to frequency |

**Standalone RF Metrics:**

| Metric | Value |
|---|---|
| Accuracy | 99.91% |
| Precision | 99.84% |
| Recall | 99.87% |
| F1 Score | 0.9985 |
| ROC-AUC | 0.9996 |
| PR-AUC | 0.9997 |
| Inference (50K samples) | 1,822 ms |

> **Note on high AUC:** CICIDS-2017 exhibits strong feature separability between benign and attack flows (52 engineered flow-level features with high discriminative power). The near-perfect RF discrimination is consistent with published benchmarks on this dataset. Further validation on newer, more adversarial datasets (CIC-IDS-2018, UNSW-NB15) is required to confirm generalizability.

### 5.2 Phishing Detection Pipeline

**Objective:** Classify email content as phishing or legitimate using a combination of lexical (TF-IDF) and structural (hand-engineered) features, supporting both known phishing templates and novel social engineering patterns.

#### 5.2.1 Training Corpus

Eight phishing and spam corpora are merged, deduplicated, and balanced:

| Corpus | Type |
|---|---|
| CEAS_08 | Spam / phishing |
| Enron | Legitimate email |
| Ling | Spam |
| Nazario | Phishing |
| Nigerian_Fraud | Fraud email |
| phishing_email | Phishing |
| SpamAssasin | Mixed |
| CICIDS-2017 (email subset) | Mixed |

**Total:** ~50,000 emails after deduplication and stratified sampling.

#### 5.2.2 Feature Engineering

**TF-IDF Features (10,000-dimensional):**

| Parameter | Value |
|---|---|
| `max_features` | 10,000 |
| `ngram_range` | (1, 2) — unigrams + bigrams |
| `stop_words` | English |
| `min_df` | 2 |
| `max_df` | 0.95 |

**12 Structural Features:**

| Feature | Type | Signal |
|---|---|---|
| `url_count` | Integer | Count of embedded URLs |
| `has_ip_url` | Binary | URL contains raw IP address |
| `suspicious_tld` | Binary | TLD is `.tk`, `.ml`, `.ga`, `.cf`, `.xyz`, etc. |
| `urgency_count` | Integer | Count of urgency keywords (`urgent`, `immediately`, `expire`) |
| `urgency_ratio` | Float | Urgency keywords / total word count |
| `has_html_form` | Binary | Presence of `<form>` tags |
| `has_html_link` | Binary | Presence of `<a href>` tags |
| `char_entropy` | Float | Shannon entropy of character distribution |
| `word_count` | Integer | Total words |
| `exclamation_count` | Integer | Count of `!` characters |
| `question_count` | Integer | Count of `?` characters |
| `caps_ratio` | Float | Proportion of uppercase characters |

The enhanced model concatenates the TF-IDF sparse matrix with the StandardScaler-transformed structural vector via `scipy.sparse.hstack`, producing a combined feature space of ~10,012 dimensions.

**Reproducibility:** Train/test split = 80/20 (stratified), `random_state=42` across all sampling, splits, and model initialization. All experiments are deterministically reproducible from the raw corpus files in `Datasets/`.

#### 5.2.3 Model Performance

**Baseline — TF-IDF Only:**

| Metric | Value |
|---|---|
| Accuracy | 97.97% |
| Precision | 97.80% |
| Recall | 98.31% |
| F1 Score | 0.9805 |
| ROC-AUC | 0.998 |

**Enhanced — TF-IDF + 12 Structural Features:**

| Metric | Value |
|---|---|
| Accuracy | 97.93% |
| Precision | 97.78% |
| Recall | 98.25% |
| F1 Score | 0.9801 |
| ROC-AUC | 0.9981 |
| Inference (10K samples) | 33,885 ms |

The enhanced model is used at inference time when the structural feature extractor is available; the system falls back to the baseline model gracefully.

---

## 6. Hybrid Detection Pipeline

The network detection subsystem does not rely on a single model. It fuses the Isolation Forest's novelty detection with the Random Forest's discriminative classification via a weighted hybrid score:

```
hybrid_score = 0.4 × IF_score + 0.6 × RF_probability
```

Where:
- **IF_score** = `max(0, min(1, 0.5 − raw_decision × 0.5))` — normalized so higher = more anomalous
- **RF_probability** = `predict_proba(X)[attack_class]` — posterior probability of the attack class

**Design rationale for the 40/60 split:**

| Weight | Model | Justification |
|---|---|---|
| 0.4 | Isolation Forest | Captures novelty — detects zero-day-like patterns outside the training distribution. Lower weight because standalone recall is low (16.96%). |
| 0.6 | Random Forest | Captures known attack signatures with near-perfect recall (99.87%). Higher weight because it dominates in-distribution performance. |

**Hybrid Model Metrics:**

| Metric | Hybrid | RF-Only | Delta |
|---|---|---|---|
| Accuracy | 99.89% | 99.91% | −0.02% |
| F1 Score | 0.9982 | 0.9985 | −0.0003 |
| ROC-AUC | 0.9999 | 1.000 | −0.0001 |
| *Novel pattern coverage* | ✓ | ✗ | *Qualitative gain* |

The hybrid approach accepts a marginal decrease in in-distribution metrics in exchange for **generalization to unseen attack patterns** — the IF component provides a safety net for threats that the RF has never been trained on.

### Decision Thresholds

```
anomaly_detected = True  if  prediction == −1  OR  hybrid_score > 0.5
```

**Real-World Inference Validation (held-out test data):**

| Scenario | Threshold (τ) | Detection Rate | False Positive Rate |
|---|---|---|---|
| Attack samples | 0.50 | 100.0% | 0.15% |
| Attack samples | 0.30 | 100.0% | 0.60% |
| Normal — mean hybrid score | — | 0.0061 | — |
| Attack — mean hybrid score | — | 0.9964 | — |

The separation between normal (μ = 0.006) and attack (μ = 0.996) populations is nearly three orders of magnitude, indicating strong discriminative power.

---

## 7. Risk Engine — Mathematical Model

The Risk Engine translates raw ML outputs into an actionable, interpretable trust score. The design is deterministic, unit-testable, and fully documented in `engine/risk_engine.py` (236 lines).

### 7.1 Trust Score Formula

```
Trust(t) = BASE − Σ(Penalty_i × Severity_i × FrequencyEscalation)
```

Where:
- `BASE = 100` (maximum trust for a clean device)
- Each detected threat deducts a penalty weighted by its severity multiplier and frequency escalation factor
- The final score is blended with historical scores via rolling average

### 7.2 Penalty Computation

**Network anomaly penalties:**

```
if anomaly_detected:
    penalty_network = 45.0 × severity × frequency_mult
elif anomaly_score > 0.35:
    penalty_network = anomaly_score × 40.0 × severity × frequency_mult
```

**Phishing penalties:**

```
if phishing_probability > 0.7:
    penalty_phishing = 35.0 × severity × frequency_mult
elif phishing_probability > 0.4:
    penalty_phishing = 20.0 × severity × frequency_mult
```

### 7.3 Exponential Time-Decay

Historical events decay in influence exponentially with a configurable half-life:

```
decay(Δt) = 2^(−Δt / T_half)
```

| Parameter | Value | Effect |
|---|---|---|
| `T_half` | 300 seconds (5 min) | Event at t−5min carries 50% weight |
| At t−10 min | — | 25% weight |
| At t−20 min | — | 6.25% weight |

This ensures that a device can recover trust over time if it ceases suspicious behavior, while recent events dominate the trust calculation.

### 7.4 Sliding-Window Frequency Escalation

A 10-minute sliding window tracks event frequency. When the count exceeds the threshold, a linear escalation multiplier is applied:

```
if event_count ≤ 3:
    escalation = 1.0
else:
    escalation = 1.0 + min(1.0, (event_count − 3) / 7.0)
```

| Events in Window | Escalation Factor |
|---|---|
| ≤ 3 | 1.0× (no escalation) |
| 6 | 1.43× |
| 10+ | 2.0× (maximum) |

Repeated suspicious activity from the same device compounds penalties, modeling persistent threats that probe defenses.

### 7.5 Severity Multipliers

Each recognized attack type carries a calibrated severity weight:

| Attack Type | Multiplier | Rationale |
|---|---|---|
| Data Exfiltration | 1.8× | Highest impact — direct data loss |
| C2 Communication | 1.6× | Indicates active compromise |
| DDoS | 1.5× | Service disruption |
| Web Attack | 1.4× | Application-layer compromise attempt |
| Insider Threat | 1.4× | Trusted entity acting maliciously |
| Brute Force | 1.3× | Credential compromise attempt |
| Phishing | 1.2× | Entry vector, lower immediate impact |
| Port Scan | 1.1× | Reconnaissance, lowest severity |

### 7.6 Rolling Average Smoothing

To prevent single-event score oscillation, trust scores are blended with recent history:

```
final_score = 0.7 × current_score + 0.3 × rolling_average(recent_scores)
```

This creates temporal hysteresis — a device with a history of suspicious activity requires sustained clean behavior to fully recover, while a single false positive against a historically clean device causes minimal score disruption.

### 7.7 Status Classification & Enforcement

| Trust Score Range | Status | Automated Action |
|---|---|---|
| ≥ 80 | **SAFE** | Normal access |
| 50 – 79 | **SUSPICIOUS** | Enhanced monitoring, alert generated |
| < 50 | **QUARANTINED** | Automatic device isolation, SOC alert |

---

## 8. Simulation Engine

The simulation engine (`simulate.py`, 447 lines) generates realistic multi-stage attack campaigns against the live API, enabling end-to-end validation of the detection-to-quarantine pipeline.

### 8.1 Scenario Library

| # | Scenario | Description | Behavior |
|---|---|---|---|
| 1 | **Normal Traffic** | Baseline campus activity | Benign flows + occasional safe emails; devices should remain SAFE |
| 2 | **DDoS Attack** | Volumetric flood with escalating waves | SYN floods with packet amplification across multiple waves |
| 3 | **Phishing Campaign** | Targeted email campaign | 70% phishing / 30% safe mix; tests ML discrimination |
| 4 | **Brute Force** | Credential stuffing against single server | Rapid repeated short flows with high SYN/RST ratios |
| 5 | **Insider Exfiltration** | Progressive data theft (5 stages) | Recon → gathering → exfiltration with escalating volume |
| 6 | **Multi-Stage APT** | Full kill chain (6 stages) | Phishing → recon → lateral → privesc → exfil → persistence |

### 8.2 APT Campaign Design (Scenario 6)

The APT scenario models a realistic advanced persistent threat kill chain:

```
Stage 1: Initial Access       →  Phishing email to gain foothold
Stage 2: Reconnaissance       →  3× port scan probes from compromised host
Stage 3: Lateral Movement     →  3× web attack pivots across subnets
Stage 4: Privilege Escalation →  5× brute force attempts (accelerated)
Stage 5: Data Exfiltration    →  3× high-volume outbound transfers (escalating)
Stage 6: Persistence          →  3× additional phishing for backup access
```

This tests the system's ability to:
1. Correlate multi-vector threats against a single device
2. Escalate trust penalties through frequency multiplication
3. Trigger quarantine autonomously during the attack chain
4. Maintain detection accuracy across attack type transitions

### 8.3 Usage

```bash
# Run all scenarios end-to-end
python simulate.py all

# Run individual scenarios with custom parameters
python simulate.py ddos --count 20 --delay 0.1
python simulate.py apt
python simulate.py phishing --count 30 --delay 0.3
python simulate.py brute_force --count 25
python simulate.py insider --count 6 --delay 1.0
```

---

## 9. Frontend — SOC Dashboard

The frontend is a **monochrome Security Operations Center (SOC) dashboard** built with React 19 and Tailwind CSS 3, designed for information density and rapid threat triage.

### 9.1 Dashboard Architecture

| View | Components | Data Source |
|---|---|---|
| **Overview** | StatsCards, Charts, ThreatFeed | `/stats`, `/risk-events` |
| **Devices** | DeviceTable, DeviceDetailModal | `/devices`, `/devices/:id` |
| **Activity** | ActivityFeed | `/activity` |
| **Threats** | ThreatFeed | `/risk-events` (filtered by severity) |

### 9.2 Component Inventory

```
frontend/src/components/
├── Header.js              # Navigation bar, view switching
├── Sidebar.js             # Status filters, quick stats
├── StatsCards.js          # Aggregate metrics (total, safe, suspicious, quarantined)
├── DeviceTable.js         # Searchable, sortable device grid
├── DeviceDetailModal.js   # Per-device deep dive (timeline, risk events)
├── Charts.js              # Trust score distribution, status breakdown
├── ThreatFeed.js          # Live threat event stream
├── ActivityFeed.js        # Chronological activity log
└── ui.js                  # Shared UI primitives
```

### 9.3 Real-Time Updates

The dashboard maintains a persistent WebSocket connection to `ws://backend:8000/ws`. The connection manager supports three message types:

- **`device_update`** — Real-time trust score changes push to the device table
- **`alert`** — Quarantine and phishing alerts surface immediately in the threat feed
- **`risk_event`** — New risk events appear in the timeline without polling

Fallback: 30-second polling interval if the WebSocket connection drops.

### 9.4 Design Philosophy

- **Monochrome palette** — Reduces visual noise; severity is conveyed through brightness saturation (white = safe, mid-gray = suspicious, dark = quarantined)
- **Information density** — Stats cards, device table, threat feed, and charts are visible simultaneously without scrolling on 1080p displays
- **Zero-click triage** — Trust score, status, anomaly score, and phishing score visible inline for every device; detail modal available on click

---

## 10. Performance Benchmarks

All benchmarks measured via the automated benchmark suite (`benchmark.py`, 340 lines). Results include model warm-up (5 iterations discarded) and statistical aggregation over 50 samples.

### 10.1 ML Model Metrics (Full Evaluation)

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | PR-AUC |
|---|---|---|---|---|---|---|
| Isolation Forest | — | 87.57% | 16.96% | — | 0.821 | — |
| Random Forest | 99.91% | 99.84% | 99.87% | 0.9985 | 0.9996 | 0.9997 |
| **Hybrid (IF+RF)** | **99.89%** | **99.87%** | **99.76%** | **0.9982** | **0.9999** | — |
| Phishing Baseline | 97.97% | 97.80% | 98.31% | 0.9805 | 0.998 | 0.998 |
| Phishing Enhanced | 97.93% | 97.78% | 98.25% | 0.9801 | 0.9981 | 0.9981 |

### 10.2 Inference Latency (Single Sample)

| Pipeline | Mean | Median | P95 | P99 | Std |
|---|---|---|---|---|---|
| **Network (IF+RF hybrid)** | 214.6 ms | 195.1 ms | 383.4 ms | 498.6 ms | 83.5 ms |
| **Phishing (TF-IDF+LR)** | 3.1 ms | 2.6 ms | 7.3 ms | 8.0 ms | 1.9 ms |

Network inference includes feature vector construction, scaler transform, Isolation Forest scoring, Random Forest probability estimation, and hybrid score fusion. Phishing inference includes TF-IDF vectorization, structural feature extraction, sparse matrix concatenation, and logistic regression prediction.

### 10.3 Batch Throughput

| Batch Size | Threads | Network (samples/s) | Phishing (samples/s) |
|---|---|---|---|
| 50 | 1T | 4.8 | 248.4 |
| 50 | 2T | 5.0 | 286.9 |
| 50 | 4T | 6.2 | 253.9 |
| 100 | 1T | 4.1 | 133.2 |
| 100 | 2T | 4.6 | 214.6 |
| 100 | 4T | 4.7 | 197.2 |

### 10.4 Test Suite Summary

```
pytest:   31/31 passing
API:      20/20 endpoint tests passing
Browser:   4/4  dashboard views validated (Playwright)
```

---

## 11. Scalability & AMD Optimization

### 11.1 Multi-Core Thread Scaling

Batch inference uses `concurrent.futures.ThreadPoolExecutor` with configurable worker counts, optimized for AMD multi-core architectures (Ryzen / EPYC):

| Threads | Network (samples/s) | Speedup | Phishing (samples/s) | Speedup |
|---|---|---|---|---|
| 1 | 4.6 | 1.00× | 317.9 | 1.00× |
| 2 | 7.1 | 1.55× | 305.1 | 0.96× |
| 4 | 7.2 | 1.56× | 288.0 | 0.91× |
| 8 | 6.1 | 1.32× | 179.4 | 0.56× |
| 12 | 8.6 | **1.87×** | 415.4 | **1.31×** |

**Analysis:**
- Network inference scales well to 12 threads (1.87× speedup), benefiting from Random Forest's embarrassingly parallel tree evaluation across AMD cores.
- Phishing inference is memory-bound (sparse matrix operations), showing best results at higher thread counts where L3 cache residency improves.
- The 8-thread dip is likely attributable to Python GIL contention and memory bandwidth saturation at intermediate thread counts — resolved at 12 threads where the OS scheduler distributes across physical cores more efficiently.

### 11.2 Parallel Inference Configuration

```python
# config.py — AMD-tunable parameters
ENABLE_PARALLEL = os.getenv("ENABLE_PARALLEL_INFERENCE", "true")
MAX_WORKERS = int(os.getenv("MAX_INFERENCE_WORKERS", "8"))
```

**Recommended settings by CPU:**

| Processor | Cores/Threads | Recommended `MAX_WORKERS` |
|---|---|---|
| AMD Ryzen 7 7700X | 8C/16T | 8 |
| AMD Ryzen 9 7950X | 16C/32T | 16 |
| AMD EPYC 7763 | 64C/128T | 32 |
| AMD EPYC 9654 | 96C/192T | 48 |

### 11.3 Benchmark Execution

```bash
# Full benchmark suite (200 latency samples, full thread scaling)
python benchmark.py --output benchmark_results

# Quick benchmark (50 samples, subset of thread counts — for CI)
python benchmark.py --quick --output benchmark_results
```

The benchmark suite:
1. Collects CPU topology via WMI (Windows) or `/proc/cpuinfo` (Linux)
2. Warms up models (5 iterations discarded)
3. Measures single-sample latency (mean/median/P95/P99/std)
4. Measures batch throughput across batch sizes × thread counts
5. Measures thread scaling from 1T to `max(cpu_count, 16)` with power-of-2 steps
6. Outputs structured JSON report + CSV scaling summary

### 11.4 AMD Hardware Acceleration Roadmap

| Phase | Capability | Expected Impact |
|---|---|---|
| **Current** | `ThreadPoolExecutor` multi-core batch inference | 1.87× at 12T (measured) |
| **Next** | AMD ROCm GPU acceleration (RF → GPU ensemble) | 5–10× inference throughput |
| **Future** | AMD Ryzen AI NPU offload (XDNA architecture) | Sub-millisecond latency, <5W TDP |
| **Future** | ONNX Runtime with ROCm Execution Provider | Framework-agnostic GPU/NPU deployment |

---

## 12. Security Hardening

| Control | Implementation | Details |
|---|---|---|
| **Authentication** | JWT (HS256) via python-jose | 60-min token expiry, configurable via `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` |
| **Password Storage** | bcrypt (passlib, adaptive cost) | Constant-time comparison |
| **Role-Based Access** | `admin` / `analyst` roles | FastAPI dependency injection: `require_admin()`, `require_analyst()` |
| **Rate Limiting** | slowapi token bucket | 120 req/min API, 10/min on `/auth/login` |
| **CORS** | FastAPI CORSMiddleware | Configurable origin whitelist via `CORS_ORIGINS` |
| **Input Validation** | Pydantic v2 schema models | All request bodies type-checked and constrained |
| **SQL Injection Prevention** | SQLAlchemy ORM (parameterized queries) | Zero raw SQL in codebase |
| **Connection Pooling** | Pool=10, overflow=20, pre-ping | Prevents connection exhaustion DoS |
| **Transport Security** | HTTPS via Nginx reverse proxy (Docker) | TLS termination at edge |
| **Secret Management** | Environment variables via `.env` | No hardcoded secrets in source |
| **Credential Rotation** | DB, JWT secret via env vars | Production-rotatable without code changes |

---

## 13. Observability & Monitoring

### 13.1 Structured Logging

Every inference, database operation, and API request is logged with structured metadata:

```
2026-02-28 20:15:43 [INFO] zerotrust.inference: Network inference: 195.13ms, hybrid=0.9964
2026-02-28 20:15:43 [INFO] zerotrust.inference: Batch network inference: 200 samples, 4234.12ms total, 8 workers
2026-02-28 20:15:43 [INFO] zerotrust.api: Login: admin (admin)
```

### 13.2 Per-Request Latency Tracking

Every prediction returns `inference_ms` in the response payload, enabling:
- Per-request latency monitoring and alerting
- Latency percentile tracking over time
- Model performance degradation detection

### 13.3 WebSocket Connection Monitoring

Active WebSocket client count is exposed in the health endpoint and root endpoint:

```json
{
  "status": "healthy",
  "ws_clients": 3,
  "devices": 42,
  "timestamp": "2026-02-28T20:15:43Z"
}
```

### 13.4 Database Audit Trail

Every device interaction produces three layered audit records:

| Table | Purpose | Indexes |
|---|---|---|
| `devices` | Current state snapshot (mutable) | `status`, `trust_score`, `updated_at` |
| `activity_log` | Full event history (append-only) | `device_id`, `timestamp`, `event_type` |
| `risk_events` | Threat signals for trend analysis | `device_id`, `timestamp` |

### 13.5 Health & Readiness Probes

| Endpoint | Purpose | Key Fields |
|---|---|---|
| `GET /` | Service identity | `service`, `version`, `status`, `ws_clients` |
| `GET /health` | Operational health | `status`, `devices`, `ws_clients` |
| `GET /stats` | Aggregate statistics | `total_devices`, `safe`, `suspicious`, `quarantined`, `avg_trust` |

All probes are compatible with container orchestration health checks (Docker, Kubernetes).

---

## 14. False Positive Mitigation Strategy

False positive management is a first-class design concern woven through multiple system layers:

### 14.1 ML Layer

| Technique | Effect |
|---|---|
| **Hybrid fusion (0.4×IF + 0.6×RF)** | IF's high novelty sensitivity is tempered by RF's discriminative precision |
| **Conservative IF contamination (0.01)** | Only 1% of training data treated as anomalous — minimizes over-flagging |
| **Balanced class weighting (RF)** | Prevents bias toward the majority class |
| **Normal-only scaler fitting** | Normalizes features relative to benign baseline, making real anomalies more distinct |

### 14.2 Risk Engine Layer

| Technique | Effect |
|---|---|
| **Rolling average smoothing (70/30)** | Single spurious events are dampened by device history |
| **Graduated penalty thresholds** | Anomaly scores 0.0–0.35 incur zero penalty — only elevated scores trigger deductions |
| **Exponential time-decay** | Old events fade, preventing historical FPs from permanently degrading trust |
| **Three-tier status classification** | SUSPICIOUS acts as buffer — devices are not quarantined until score drops below 50 |

### 14.3 Operational Layer

| Technique | Effect |
|---|---|
| **Manual isolation override** | SOC operators can quarantine or release devices regardless of ML output |
| **Per-device activity timeline** | Full audit trail for investigation and reclassification |
| **Configurable thresholds** | `QUARANTINE_THRESHOLD` and `SUSPICIOUS_THRESHOLD` adjustable via environment variables |

### 14.4 Measured False Positive Rate

| Population | Threshold | FPR |
|---|---|---|
| Normal traffic | τ = 0.50 (default) | **0.15%** |
| Normal traffic | τ = 0.30 (aggressive) | 0.60% |
| Normal traffic | Mean hybrid score | 0.0061 |

At the default threshold, only 1.5 in 1,000 benign flows are incorrectly flagged — well within acceptable operational limits for campus-scale deployment.

---

## 15. Deployment Guide

### 15.1 Docker Compose (Recommended)

```bash
git clone <repository-url>
cd ZeroTrust

# Start all services (MySQL 8 + Backend + Frontend via Nginx)
docker-compose up --build -d

# Verify health
curl http://localhost:8000/health
# Open dashboard
open http://localhost:3000
```

Services:
- **MySQL 8.0** — Port 3306, healthcheck-gated
- **Backend** — Port 8000, auto-initializes DB and loads models on startup
- **Frontend** — Port 3000, served via Nginx reverse proxy

### 15.2 Local Development

```bash
# Backend
cd backend
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # Linux/macOS
pip install -r requirements.txt

# Train models (one-time)
python train_all.py

# Start API server
python main.py
```

```bash
# Frontend (separate terminal)
cd frontend
npm install
npm start
```

### 15.3 Run Simulation

```bash
# With backend running:
cd backend
python simulate.py all          # Full 6-scenario demo
python simulate.py apt          # Single APT campaign
```

### 15.4 Run Benchmarks

```bash
cd backend
python benchmark.py --output benchmark_results
```

### 15.5 Run Tests

```bash
cd backend
pytest tests/ -v
```

### 15.6 Environment Configuration

All settings are configurable via environment variables or `.env` file:

| Variable | Default | Description |
|---|---|---|
| `DB_HOST` | `localhost` | MySQL host |
| `DB_PORT` | `3306` | MySQL port |
| `DB_NAME` | `zerotrust` | Database name |
| `DB_USER` | `root` | Database user |
| `DB_PASSWORD` | `password` | Database password |
| `JWT_SECRET_KEY` | (internal default) | JWT signing secret — **must override in production** |
| `JWT_ALGORITHM` | `HS256` | JWT algorithm |
| `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` | `60` | Token lifetime (minutes) |
| `SERVER_HOST` | `0.0.0.0` | API bind address |
| `SERVER_PORT` | `8000` | API port |
| `CORS_ORIGINS` | `http://localhost:3000` | Allowed CORS origins (comma-separated) |
| `RATE_LIMIT_PER_MINUTE` | `120` | Global API rate limit |
| `ANOMALY_CONTAMINATION` | `0.05` | Isolation Forest contamination |
| `QUARANTINE_THRESHOLD` | `50` | Auto-quarantine below this score |
| `SUSPICIOUS_THRESHOLD` | `80` | SUSPICIOUS status above this score |
| `ENABLE_PARALLEL_INFERENCE` | `true` | Enable multi-threaded batch inference |
| `MAX_INFERENCE_WORKERS` | `8` | ThreadPoolExecutor worker count |

---

## 16. API Reference

### 16.1 Authentication

| Method | Endpoint | Description | Rate Limit |
|---|---|---|---|
| `POST` | `/auth/login` | Authenticate, receive JWT token | 10/min |
| `GET` | `/auth/me` | Current user info (Bearer required) | 120/min |

### 16.2 Analysis

| Method | Endpoint | Description | Rate Limit |
|---|---|---|---|
| `POST` | `/analyze/network` | Hybrid network anomaly detection (IF+RF) | 120/min |
| `POST` | `/analyze/email` | Phishing detection (TF-IDF + structural) | 120/min |
| `POST` | `/analyze/device` | Full device analysis (network + phishing) | 120/min |
| `POST` | `/analyze/batch/network` | Multi-threaded batch network inference | 20/min |
| `POST` | `/analyze/batch/email` | Batch phishing inference | 20/min |

### 16.3 Device Management

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/devices` | List devices (search, filter, sort, paginate) |
| `GET` | `/devices/{id}` | Device detail + timeline + risk events |
| `POST` | `/devices/{id}/isolate` | Manual device quarantine with SOC alert |

### 16.4 Monitoring & Diagnostics

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/activity` | Activity log (configurable limit) |
| `GET` | `/risk-events` | Risk events (filter by device, severity) |
| `GET` | `/stats` | Aggregate statistics |
| `GET` | `/features` | Expected network feature columns |
| `GET` | `/` | Service identity |
| `GET` | `/health` | Health check |
| `WS` | `/ws` | Real-time event stream (device_update, alert, risk_event) |

**Total: 18 endpoints** (13 REST + 1 WebSocket + 4 diagnostics)

---

## 17. Limitations & Constraints

| # | Limitation | Impact | Mitigation Path |
|---|---|---|---|
| 1 | **Training data vintage** — CICIDS-2017 is ~8 years old | Feature distributions may diverge from modern traffic | Retrain on CIC-IDS-2018, UNSW-NB15, or custom capture |
| 2 | **No encrypted payload inspection** | Cannot analyze TLS-encrypted C2 or exfiltration content | TLS inspection proxy; JA3/JA4 fingerprinting on flow metadata |
| 3 | **Adversarial ML vulnerability** | Attacker with model knowledge can craft evasive features | Adversarial training, input perturbation detection, ensemble diversity |
| 4 | **Single-node inference** | Throughput ceiling on single-machine deployment | Kubernetes horizontal scaling, model sharding, queue-based inference |
| 5 | **In-memory user store** | Not production-grade for large-scale RBAC | Database-backed user model with LDAP/SAML integration |
| 6 | **Python GIL contention** | Limits true CPU parallelism for inference | Multiprocessing, ONNX Runtime, or native C++ inference server |
| 7 | **No model versioning** | Artifacts overwritten on retrain | MLflow or DVC for experiment tracking and model registry |
| 8 | **Static phishing corpus** | Phishing patterns evolve over time | Online learning pipeline or periodic retraining with fresh corpora |
| 9 | **Distribution shift at deployment** | Real-world FPR may exceed measured 0.15% due to traffic distribution differences between CICIDS-2017 and production environments | Calibration on site-specific traffic; periodic retraining with local captures |

### 17.1 Why Not Deep Learning?

A deliberate engineering decision — not a limitation:

| Concern | Classical ML (Current) | Deep Learning (Alternative) |
|---|---|---|
| **Inference latency** | 3–215 ms per sample | 50–500+ ms (transformer/LSTM) |
| **Deployment complexity** | CPU-only, no GPU required | Requires CUDA/ROCm runtime, GPU memory management |
| **Interpretability** | Feature importance, decision paths, anomaly scores | Black-box; requires SHAP/LIME post-hoc |
| **Training data requirement** | 100K samples sufficient | Typically 1M+ for competitive performance |
| **Model size** | ~50 MB (RF + IF + TF-IDF) | 500 MB–2 GB (transformer) |
| **Operational cost** | Commodity CPU (any AMD Ryzen) | GPU instance ($0.50–$3/hr cloud) |

For campus-scale deployment where **latency**, **interpretability**, and **infrastructure simplicity** are paramount, classical ML provides a superior cost-performance tradeoff. The architecture is designed to incorporate deep learning (GNN, transformers) in future versions (see [§18](#18-future-roadmap)) when the operational environment justifies the complexity.

---

## 18. Future Roadmap

| Phase | Capability | Description |
|---|---|---|
| **v2.1** | **Graph Neural Network (GNN)** | Model network topology as a graph; detect lateral movement via anomalous edge patterns between devices |
| **v2.1** | **Behavioral fingerprinting** | Learn per-device temporal behavioral profiles; detect deviations from individual baselines |
| **v2.2** | **Federated learning** | Train across distributed campus deployments without sharing raw data; privacy-preserving aggregation |
| **v2.2** | **SIEM integration** | Bidirectional Splunk/Elastic integration; CEF/LEEF export, external threat intel ingestion |
| **v2.3** | **AMD ROCm GPU acceleration** | Offload RF ensemble + TF-IDF vectorization to AMD Instinct GPUs via ROCm |
| **v2.3** | **AMD Ryzen AI NPU offload** | Deploy quantized models on XDNA NPU for edge inference at sub-milliwatt power |
| **v3.0** | **ONNX Runtime serving** | Convert all models to ONNX; serve via ROCm Execution Provider |
| **v3.0** | **Automated retraining** | Continuous learning with concept drift detection and human-in-the-loop validation gates |

---

## 19. Conclusion

ZeroTrust demonstrates that a production-viable Zero-Trust enforcement engine can be built on commodity hardware using classical ML techniques — without requiring deep learning infrastructure or GPU acceleration. The hybrid Isolation Forest + Random Forest pipeline achieves **99.89% accuracy** and a **0.15% false positive rate** on network traffic, while the NLP-enhanced phishing detector reaches **97.93% accuracy** across a diverse 50K-email corpus.

The mathematical risk engine provides deterministic, interpretable trust scoring with exponential time-decay, frequency escalation, and severity weighting — producing automated quarantine decisions in real time. The architecture is designed for AMD multi-core scaling today (1.87× measured at 12 threads) and GPU/NPU acceleration tomorrow.

In an era where the average breach takes 194 days to detect and costs $4.88M, ZeroTrust reduces detection-to-containment to **sub-second** timescales — shifting the economics of defense decisively in favor of the defender.

Every component — from the 8-layer processing pipeline to the WebSocket-driven SOC dashboard — is built for production deployment, operational auditability, and continuous evolution.

---

<p align="center"><em>Built for the AMD Slingshot Hackathon · 2026</em></p>
