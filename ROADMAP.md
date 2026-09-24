# CYBERGUARD AI GRC — Architectural Roadmap & Next Horizons

This roadmap specifies the forward engineering priorities for the **CyberGuard AI GRC Platform** following the successful implementation and verification of Phases 1–4 (Confidence-Banded FAIR Simulation, AI-Augmented Investment Optimizer, Natural Language Query Agent, and Reusable Slide-Over Drill-Down Panel).

---

## Strategic Capabilities Matrix

| Capability | Module Target | Architecture & Technologies | Primary Value & Outcome | Effort Est. |
| :--- | :--- | :--- | :--- | :---: |
| **1. Agentic Continuous Control Monitoring (CCM)** | Audit Trail & Compliance Gap | Event-driven webhook listeners, automated telemetry probes, telemetry threshold triggers | Replaces point-in-time audits with 24/7 automated control health verification. | 2–3 weeks |
| **2. Generative FAIR Scenario Synthesis** | Risk Calculator & Scenario Analysis | LLM prompt synthesis, parameter extraction, Beta-PERT prior calibration | Synthesizes realistic threat scenarios from raw CISA KEV / threat intel feeds. | 2 weeks |
| **3. Predictive Risk Trajectory Modeling** | Executive Dashboard | ARIMA / Holt-Winters time-series projection, Monte Carlo forward runs | Forecasts 30/60/90-day loss trajectories under varied remediation rates. | 2–3 weeks |
| **4. Advanced Policy-to-Control NLP Mapping** | Policy Mapper | Sentence-Transformers embeddings, cosine semantic matching, gap extraction | Maps unstructured governance policies directly into NIST CSF 2.0 / ISO 27001 clauses. | 1.5–2 weeks |
| **5. Global Command Palette (`Cmd+K`)** | App Shell (Global) | Headless UI / Fuse.js fuzzy index, shortcut keyboard dispatcher | Instant navigation across all 9 modules, findings, assets, and candidate controls. | 1 week |
| **6. Collaborative Annotation Layer** | Findings Explorer & Slide-Over | WebSockets / polling, optimistic updates, audit-linked commentary | Enables cross-functional review (SecOps, GRC, Finance) directly on finding drill-downs. | 1.5 weeks |
| **7. Adaptive Executive Summary Cards** | Executive Dashboard & Board Report | Persona-based rendering (CISO, CFO, Board), dynamic delta callouts | Automatically tailors loss metrics, ROI figures, and narratives to viewer persona. | 1 week |

---

## Deep-Dive Capability Specifications

### 1. Agentic Continuous Control Monitoring (CCM)
- **Objective**: Automate continuous verification of security controls without human polling.
- **Architecture**:
  - Background worker polling cloud APIs (AWS Security Hub, GitHub Advanced Security, Okta logs).
  - Evaluates actual telemetry against NIST CSF 2.0 control mandates (e.g., PR.AC-1 MFA enforcement, PR.DS-1 encryption).
  - Emits immutable `AuditLogModel` events (`action_type="CCM_TELEMETRY_ALERT"`) when drift or failure is detected.
  - Automatically raises or adjusts `FindingModel.quantified_risk_usd` in real-time.

### 2. Generative FAIR Scenario Synthesis
- **Objective**: Convert unstructured threat advisories (e.g., CISA Alert, Mandiant bulletin) into calibrated FAIR scenarios.
- **Architecture**:
  - Ingestion parser receives raw advisory markdown/text.
  - Extracts threat actor capabilities, targeted technologies, vulnerability IDs, and probable loss modes.
  - Maps parameters to OpenFAIR distributions: Threat Event Frequency (TEF), Vulnerability (V), Primary Loss ($PL$), Secondary Loss ($SL$).
  - Pre-populates the Risk Calculator for one-click Monte Carlo validation and what-if comparison.

### 3. Predictive Risk Trajectory Modeling
- **Objective**: Provide forward-looking risk visibility to executive leadership.
- **Architecture**:
  - Aggregates historical quantified risk snapshots across daily/weekly rollups.
  - Fits trend and seasonality models (incorporating new CVE arrival rates and mean-time-to-remediate MTTR).
  - Renders 30/60/90-day confidence cones on the Executive Dashboard showing:
    - *Status Quo Trajectory*: Risk growth if zero controls are funded.
    - *Optimized Allocation Trajectory*: Risk decay achieved via selected PuLP investment packages.

### 4. Advanced Policy-to-Control NLP Mapping
- **Objective**: Eliminate manual spreadsheet compliance audits between internal corporate policies and international standards.
- **Architecture**:
  - Chunks organization policy documents (PDF, DOCX, Markdown).
  - Uses vector similarity embeddings to match clauses against canonical NIST CSF 2.0 subcategories and ISO 27001:2022 Annex A controls.
  - Visualizes control coverage, policy ambiguities, and regulatory gaps with quantitative coverage percentages.

### 5. Global Command Palette (`Cmd+K` / `Ctrl+K`)
- **Objective**: Power-user keyboard navigation across enterprise risk assets.
- **Architecture**:
  - Client-side searchable inverted index over all 25+ assets, 65+ findings, remediations, and audit entries.
  - Quick action shortcuts: jump to module, filter by severity, trigger RAG question, or open drill-down panel.
  - Zero server load via local state caching.

### 6. Collaborative Annotation Layer
- **Objective**: Enable multi-stakeholder risk acceptance, exception approvals, and peer review.
- **Architecture**:
  - Extends `FindingModel` and `RemediationModel` with audit-backed comment threads.
  - Captures formal sign-offs (e.g., Risk Acceptance by Business Unit VP).
  - Automatically records formal justifications to `audit_logs` with cryptographic tamper-evident tagging.

### 7. Adaptive Executive Summary Cards
- **Objective**: Deliver contextual risk briefings tailored to specific executive audiences.
- **Architecture**:
  - **CISO View**: Focuses on exploit likelihoods, critical asset exposure, threat actors, and engineering effort.
  - **CFO View**: Focuses on annualized loss exposure (ALE), marginal ROI ($\Delta\text{ALE}/\text{Cost}$), and capital efficiency.
  - **Board View**: Focuses on regulatory compliance posture (NIST/ISO), risk appetite compliance, and fiduciary diligence.

---

## Verification & Compatibility Guarantees
- **Tech Stack Preservation**: Additive extensions only; retains FastAPI, SQLAlchemy, SQLite/PostgreSQL, Tailwind CSS, and Chart.js without heavyweight third-party runtime bloat.
- **9-Module Invariance**: All features strictly integrate into existing views (Executive Dashboard, Security Investment Optimizer, Findings Explorer, Board Executive Report, Risk Calculator, Compliance Gap Analyzer, Audit Trail, Policy Mapper, Scenario Analysis).
- **Test Integrity**: Maintained at 100% pass rate with zero deprecation warnings across Python 3.10–3.14.
