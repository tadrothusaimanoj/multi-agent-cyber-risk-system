# CyberGuard AI — AI-Powered Continuous Cyber Risk Quantification & Investment Optimization Platform

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-1.4%2B-F7931E.svg)](https://scikit-learn.org/)
[![PuLP](https://img.shields.io/badge/PuLP-Knapsack%20Optimization-blueviolet.svg)](https://coin-or.github.io/pulp/)
[![Tests](https://img.shields.io/badge/pytest-26%20passed-brightgreen.svg)]()

CyberGuard AI is a continuous cyber-risk decision-support platform that ingests raw security signals (vulnerabilities, misconfigurations, and threat intelligence), normalizes them into canonical domain records, quantifies cyber risk in dollar terms (\$), prioritizes risks using machine learning exploit likelihood and business impact, and recommends optimal security investments using mathematical optimization (0/1 Knapsack via PuLP and Greedy ROI) under a fixed budget.

---

## 1. System Architecture & Conceptual Pipeline

```
Security Data Sources (NVD, EPSS, Cloud Misconfigs, Synthetic Generator)
                            ↓
                     Data Ingestion
                            ↓
               Canonical Data Normalization
                            ↓
                Asset Context Enrichment
  (Asset Value, Exposure, Business Unit, Criticality Multiplier)
                            ↓
             Continuous Risk Quantification
     Risk($) = Threat Likelihood × Vulnerability × Asset Value × Exposure
                            ↓
             AI/ML Risk Prioritization
      (Scikit-Learn Logistic Regression Exploit Probability)
                            ↓
             Investment Optimization Engine
        (PuLP 0/1 Knapsack & Greedy ROI: Risk$ / Cost$)
                            ↓
                    FastAPI REST APIs
  (GET /risk-summary, POST /optimize, GET /findings, POST /ingest)
                            ↓
               Executive & Operator Dashboard
               (React + Tailwind + Recharts)
```

---

## 2. Core Engines & Methodology

### 2.1 Continuous Risk Quantification Engine
Transforms technical security findings into dollar-denominated exposure:
$$\text{Risk}(\$) = \text{Threat Likelihood} \times \text{Vulnerability Severity Factor} \times \text{Exposure Multiplier} \times \text{Criticality Multiplier} \times \text{Asset Value}$$

- **Threat Likelihood ($TL$)**: Bounded probability $[0.01, 1.0]$ derived from empirical EPSS and Scikit-Learn exploit model.
- **Vulnerability Severity ($V$)**: CVSS base score normalized ($\text{CVSS} / 10.0$) $[0.05, 1.0]$.
- **Exposure Multiplier ($E$)**: `internet_facing: 1.0`, `dmz: 0.75`, `internal: 0.40`, `isolated: 0.15`.
- **Criticality Multiplier ($C$)**: `critical: 1.5`, `high: 1.25`, `medium: 1.0`, `low: 0.75`.
- **Asset Value ($AV$)**: Dollar replacement and downtime valuation.
- **FAIR Grounding**: Validated against Monte Carlo Beta-PERT simulation ($\text{Loss Event Frequency} \times \text{Loss Magnitude}$).

### 2.2 AI / ML Exploit Prioritization Engine
- **Algorithm**: `LogisticRegression` (Scikit-Learn) with feature scaling.
- **Features**: Normalized CVSS base score, EPSS probability, Internet-facing exposure flag, Severity level (1–4), and CVE record presence.
- **Output**: Calibrated probability $P(\text{exploited in the wild}) \in [0.01, 0.99]$.
- **Fallback**: Deterministic heuristic $0.65 \times \text{EPSS} + 0.35 \times (\text{CVSS} / 10)$ if model inference is unavailable.

### 2.3 Investment Optimization Engine (0/1 Knapsack)
Given a fixed security budget $B$ and $N$ candidate remediation actions:
$$\text{Maximize } Z = \sum_{i=1}^{N} x_i \cdot \text{RiskReduction}_i$$
$$\text{Subject to } \sum_{i=1}^{N} x_i \cdot \text{Cost}_i \le B, \quad x_i \in \{0, 1\}$$

- **Solvers**:
  1. **PuLP (CBC Branch-and-Cut)**: Guaranteed mathematically optimal 0/1 knapsack integer programming solution.
  2. **Greedy ROI Sort**: Heuristic ordering by $\text{ROI} = \frac{\text{Risk Reduction}}{\text{Cost}}$ with deterministic tie-breaking.
- **Constraints**: Cost strictly $\le B$, deterministic ordering, explainable selection.

---

## 3. Database Schema

The platform persists entities using SQLAlchemy:
- **`assets`**: `asset_id`, `asset_name`, `asset_category`, `business_unit`, `asset_value`, `exposure`, `criticality`, `owner`.
- **`findings`**: `finding_id`, `asset_id`, `finding_type`, `cve_id`, `title`, `severity`, `cvss_score`, `epss_score`, `exploit_likelihood`, `quantified_risk_usd`, `nist_csf_category`, `mitre_technique_id`.
- **`remediations`**: `action_id`, `finding_id`, `asset_id`, `title`, `remediation_type`, `cost`, `risk_reduction_usd`, `roi`, `effort_hours`, `nist_control_id`.
- **`optimization_runs`**: `run_id`, `budget`, `total_cost_allocated`, `total_risk_reduction`, `budget_utilization_pct`, `overall_roi`, `strategy`, `selected_action_ids`.
- **`reports`**: `report_date`, `total_assets`, `total_findings`, `total_quantified_risk`, `executive_summary`.

*Storage: SQLite (`cyberguard.db`) by default for zero-setup execution; automatically connects to PostgreSQL when `DATABASE_URL` is set.*

---

## 4. REST API Specification

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | System health and database connectivity check |
| `GET` | `/risk-summary` | Total quantified risk exposure, BU/Category breakdown, top 10 risks |
| `POST` | `/optimize` | 0/1 Knapsack optimization given budget and strategy |
| `GET` | `/findings` | Filterable list of canonical security findings |
| `GET` | `/assets` | List of monitored corporate assets |
| `GET` | `/remediations` | Catalog of remediation options with ROI and cost |
| `GET` | `/frameworks` | Compliance alignment (NIST CSF 2.0, MITRE ATT&CK, FAIR) |
| `GET` | `/executive-summary`| Board-ready plain-English executive decision briefing |
| `POST` | `/ingest` | Trigger ingestion pipeline or reseed synthetic dataset |

### Sample Optimization Request
```json
POST /optimize
{
  "budget": 50000.0,
  "strategy": "pulp",
  "min_roi_threshold": 1.0
}
```

### Sample Optimization Response
```json
{
  "budget": 50000.0,
  "total_cost_allocated": 48200.0,
  "total_risk_reduction": 492000.0,
  "budget_utilization_pct": 96.4,
  "overall_roi": 10.21,
  "strategy_used": "pulp_knapsack_0_1",
  "selected_actions": [...]
}
```

---

## 5. Quickstart & Execution Instructions

### Prerequisites
- Python 3.10+
- Pip / Virtual environment

### Installation
```bash
# Clone or navigate to the repository
cd multi-agent-cyber-risk-system

# Install Python dependencies
pip install -r python/requirements.txt
pip install fastapi uvicorn scikit-learn pulp pytest pydantic-settings
```

### Run the Application (Single Command)
```bash
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

- **Interactive Executive Dashboard**: Open [http://127.0.0.1:8000](http://127.0.0.1:8000) in your web browser.
- **Interactive Swagger API Docs**: Open [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs).

---

## 6. Testing & Quality Assurance

Run the automated test suite covering risk calculations, knapsack algorithms, ML prioritization, and REST endpoints:
```bash
python -m pytest tests/ -v
```

**Test Suite Coverage**:
- `tests/test_risk_engine.py`: Formula correctness, zero value boundaries, exposure multipliers, FAIR simulations, and aggregations.
- `tests/test_optimizer.py`: Zero budget, insufficient budget, exact budget matching, budget limit adherence ($\sum \text{Cost} \le \text{Budget}$), and PuLP vs Greedy determinism.
- `tests/test_ml_prioritization.py`: Scikit-learn model training, feature extraction, and bounded probability predictions $[0.01, 0.99]$.
- `tests/test_api.py`: FastAPI endpoints integration tests with `TestClient`.

---

## 7. Synthetic Data Generator

To ensure reproducibility across demonstrations and automated testing, the platform includes a deterministic synthetic generator:
- **Seed**: `42`
- **Scope**: 25 enterprise assets across 5 Business Units (`FinTech / Payments`, `Core Engineering`, `E-Commerce`, `Corporate IT`, `Data Science`).
- **Findings**: 82 enriched vulnerabilities, misconfigurations, and threat intelligence items.
- **Quantified Total Exposure**: Calibrated around ~$4.5M matching enterprise demonstration baselines.
- **Reseed Command**:
  ```bash
  curl -X POST http://127.0.0.1:8000/ingest -H "Content-Type: application/json" -d '{"reseed_synthetic": true}'
  ```

---

## 8. Requirements Traceability Matrix

| Requirement | Section | Implementation File | Test Module | Status |
|---|---|---|---|---|
| Ingestion & Normalization | §6, §7 | `backend/synthetic_generator.py` | `tests/test_api.py` | PASS |
| Canonical Domain Schemas | §8 | `backend/schemas.py` | `tests/test_api.py` | PASS |
| Asset Context Enrichment | §9 | `backend/risk_engine.py` | `tests/test_risk_engine.py` | PASS |
| Dollar-Risk Quantification | §10, §11 | `backend/risk_engine.py` | `tests/test_risk_engine.py` | PASS |
| ML Exploit Likelihood | §12, §13 | `backend/ml_prioritization.py` | `tests/test_ml_prioritization.py` | PASS |
| Security Framework Mappings | §14 | `backend/main.py` | `tests/test_api.py` | PASS |
| 0/1 Knapsack Optimization | §15, §16 | `backend/optimizer.py` | `tests/test_optimizer.py` | PASS |
| FastAPI REST Layer | §17, §18 | `backend/main.py` | `tests/test_api.py` | PASS |
| Executive Dashboard (React/Tailwind) | §21 | `backend/static/index.html` | Browser / UI Verified | PASS |
| Plain-English Executive Summary | §22 | `backend/executive_summary.py` | `tests/test_api.py` | PASS |
| Deterministic Synthetic Seed | §27 | `backend/synthetic_generator.py` | `tests/test_risk_engine.py` | PASS |
