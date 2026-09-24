# Python Agent Specifications

## Overview

This document provides detailed specifications for each Python agent in the CyberRisk AI system.

---

## Agent 1: Data Ingestion Agent

**File:** `data_ingestion.py`

### Purpose
Fetch and normalize vulnerability data from NVD and EPSS APIs into a unified PostgreSQL schema.

### Dependencies
```python
numpy==1.26.4
requests==2.31.0
psycopg2-binary==2.9.9
python-dotenv==1.0.1
tenacity==8.2.3
loguru==0.7.2
```

### Classes

#### `NVDClient`
Interacts with National Vulnerability Database API.

**Methods:**
- `fetch_recent_cves(days_back: int) -> List[Dict]`
  - Fetches CVEs published in last N days
  - Handles pagination automatically
  - Implements rate limiting (6s between requests)
  - Retries with exponential backoff

- `parse_cve(cve_item: Dict) -> Optional[Dict]`
  - Extracts CVSS score (v3.1, v3.0, v2 fallback)
  - Determines severity (critical, high, medium, low)
  - Parses descriptions and metadata

**Rate Limits:**
- Without API key: 5 requests / 30 seconds
- With API key: 50 requests / 30 seconds

#### `EPSSClient`
Interacts with FIRST.org Exploit Prediction Scoring System API.

**Methods:**
- `get_epss_scores(cve_ids: List[str]) -> Dict[str, float]`
  - Batches CVE IDs (100 per request)
  - Returns exploitation probability (0.0 to 1.0)
  - Conservative 0.6s sleep between requests

**Rate Limits:**
- ~100 requests/minute (undocumented)

#### `DataIngestionAgent`
Orchestrates the full ingestion pipeline.

**Methods:**
- `ingest_vulnerabilities(asset_mapping: Dict, days_back: int) -> Tuple[int, int]`
  - Fetches CVEs from NVD
  - Enriches with EPSS scores
  - Bulk inserts to PostgreSQL
  - Returns (success_count, failed_count)

### Unified Schema Output
```python
{
  'asset_id': str,
  'vuln_id': str,      # CVE-XXXX-XXXXX
  'cvss_score': float, # 0.0 to 10.0
  'epss_score': float, # 0.0 to 1.0
  'discovery_date': datetime,
  'status': str,       # open, in_progress, remediated, accepted
  'severity': str,     # critical, high, medium, low
  'description': str,
  'raw_data': dict     # Full NVD response
}
```

### Error Handling
- API timeouts: Retry up to 3 times with exponential backoff
- Rate limit violations: Sleep and retry
- Parse failures: Log warning and skip CVE
- Database errors: Rollback transaction

### Standalone Usage
```bash
cd python
python3 data_ingestion.py
```

---

## Agent 2: FAIR Risk Engine

**File:** `fair_engine.py`

### Purpose
Implement Factor Analysis of Information Risk (FAIR) methodology using Monte Carlo simulation.

### Dependencies
```python
numpy==1.26.4
scipy==1.12.0
psycopg2-binary==2.9.9
loguru==0.7.2
```

### Classes

#### `FairInput`
Dataclass for FAIR input parameters using PERT distributions.

**Fields:**
```python
# Loss Event Frequency (LEF)
contact_frequency_min: float    # Threat events/year
contact_frequency_mode: float
contact_frequency_max: float

probability_of_action_min: float  # 0.0 to 1.0
probability_of_action_mode: float
probability_of_action_max: float

vulnerability_min: float  # 0.0 to 1.0
vulnerability_mode: float
vulnerability_max: float

# Loss Magnitude (LM)
primary_loss_min: float    # USD
primary_loss_mode: float
primary_loss_max: float

secondary_loss_min: float  # USD
secondary_loss_mode: float
secondary_loss_max: float
```

#### `FairOutput`
Dataclass for FAIR analysis results.

**Fields:**
```python
eal_min: float             # Minimum expected annual loss
eal_mode: float            # Most likely EAL
eal_mean: float            # Average EAL
eal_max: float             # Maximum EAL
eal_95th_percentile: float # 95% confidence upper bound
eal_std: float             # Standard deviation

loss_event_frequency_mean: float  # Events/year
loss_magnitude_mean: float        # USD/event

eal_distribution: np.ndarray  # Full distribution
simulation_runs: int              # Number of iterations
```

#### `FairRiskEngine`
Core Monte Carlo simulation engine.

**Methods:**
- `pert_distribution(min, mode, max, size) -> np.ndarray`
  - Generates PERT (Beta-based) distribution
  - Formula: Beta(α, β) scaled to [min, max]
  - Lambda parameter: 4 (gives weight to mode)

- `calculate_fair(inputs: FairInput) -> FairOutput`
  - Runs Monte Carlo simulation (default: 10,000 iterations)
  - Computes LEF = Contact_Freq × Prob_Action × Vulnerability
  - Computes LM = Primary_Loss + Secondary_Loss
  - Computes Risk = LEF × LM
  - Returns statistical distribution

- `cvss_to_fair_inputs(cvss, epss, asset_value, criticality) -> FairInput`
  - Heuristic mapping from CVSS/EPSS to FAIR parameters
  - CVSS → Vulnerability probability
  - EPSS → Threat Event Frequency
  - Asset criticality → Loss magnitude multiplier

#### `RiskAnalysisService`
Service layer for database persistence.

**Methods:**
- `analyze_vulnerability(vuln_id, asset_id, cvss_score, epss_score, ...) -> FairOutput`
  - End-to-end analysis pipeline
  - Converts CVSS/EPSS to FAIR inputs
  - Runs Monte Carlo simulation
  - Persists results to PostgreSQL

### FAIR Formula
```
Risk = LEF × LM

Where:
  LEF = Contact_Frequency × Probability_of_Action × Vulnerability
  LM = Primary_Loss + Secondary_Loss
```

### Monte Carlo Process
1. Generate random samples from each input distribution
2. Calculate LEF for each iteration
3. Calculate LM for each iteration
4. Multiply LEF × LM = Risk for each iteration
5. Aggregate: min, percentiles, mean, max

### Standalone Usage
```bash
cd python
python3 fair_engine.py
```

**Output:**
```
====================================================================
FAIR RISK ANALYSIS RESULTS
====================================================================
Expected Annual Loss (EAL):
  Minimum:        $12,450.23
  Most Likely:    $87,300.45
  Mean:           $94,125.67
  95th %ile:      $245,800.12
  Maximum:        $512,000.00

Interpretation:
  We are 95% confident the annual loss will not exceed $245,800.12
====================================================================
```

---

## Agent 3: Compliance RAG Agent

**File:** `compliance_rag.py`

### Purpose
Map vulnerabilities to compliance controls using Retrieval-Augmented Generation with strict hallucination guardrails.

### Dependencies
```python
sentence-transformers==2.5.1
chromadb==0.4.24
langchain==0.1.13
langchain-community==0.0.29
langgraph==0.0.26
langchain-ollama==0.0.1
langchain-anthropic==0.1.6
psycopg2-binary==2.9.9
loguru==0.7.2
```

### Classes

#### `ControlMapping`
Dataclass for compliance mapping results.

**Fields:**
```python
vuln_id: str
framework: str           # NIST_CSF_2.0 or ISO_27001
control_id: str          # e.g., "ID.RA-1", "A.8.8"
control_title: str
mapping_confidence: float  # 0.0 to 1.0
llm_citation: str        # Exact clause cited
reasoning: str           # LLM explanation
```

#### `ComplianceRAGPipeline`
RAG orchestration pipeline.

**Methods:**
- `__init__(use_ollama=True, ollama_model='llama3.1:8b', anthropic_api_key=None)`
  - Initializes embedding model (all-MiniLM-L6-v2)
  - Initializes ChromaDB vector store
  - Loads NIST CSF 2.0 and ISO 27001 controls
  - Configures LLM (Ollama or Claude)

- `retrieve_relevant_controls(query, framework, top_k=3) -> List[Dict]`
  - Embeds query with sentence-transformers
  - Performs semantic search in ChromaDB
  - Returns top-K most similar controls

- `map_vulnerability_to_controls(vuln_id, vuln_description, frameworks) -> List[ControlMapping]`
  - Retrieves relevant controls
  - Prompts LLM with strict citation requirements
  - Validates LLM output against retrieved controls
  - Rejects hallucinated control IDs
  - Returns mappings with confidence scores

#### `ComplianceService`
Database persistence layer.

**Methods:**
- `map_and_persist(vuln_id, vuln_description) -> List[ControlMapping]`
  - Calls RAG pipeline
  - Saves mappings to PostgreSQL
  - Returns results

### Knowledge Base

**NIST CSF 2.0 (7 controls in MVP):**
- ID.RA-1: Vulnerabilities identified
- ID.RA-2: Cyber threat intelligence
- PR.IP-12: Vulnerability management plan
- DE.CM-8: Vulnerability scans performed
- RS.MI-3: Vulnerabilities mitigated
- PR.DS-6: Integrity checking mechanisms
- PR.AC-5: Network integrity protected

**ISO 27001:2022 Annex A (6 controls in MVP):**
- A.5.1: Policies for information security
- A.8.8: Management of technical vulnerabilities
- A.8.7: Protection against malware
- A.5.23: Information security for cloud services
- A.8.9: Configuration management
- A.8.16: Monitoring activities

### Hallucination Guardrails

**Enforcement:**
```python
# Step 1: LLM generates mapping
llm_output = {
  "control_id": "ID.RA-1",
  "confidence": 0.95,
  "reasoning": "..."
}

# Step 2: Validate citation
if llm_output['control_id'] not in retrieved_control_ids:
    log_warning("HALLUCINATION DETECTED")
    reject_mapping()
    return None

# Step 3: Save only validated mappings
```

### Prompt Engineering
```
SYSTEM: You are a GRC analyst. Map vulnerabilities to controls.

CRITICAL REQUIREMENTS:
1. MUST cite exact control ID (e.g., "ID.RA-1")
2. ONLY map to controls in the provided context
3. If no match, respond "NO_MAPPING"
4. Provide confidence score (0.0-1.0)
5. Explain reasoning in 1-2 sentences

OUTPUT: JSON with control_id, confidence, reasoning
```

### Standalone Usage
```bash
# Requires Ollama running
ollama pull llama3.1:8b
ollama serve

cd python
python3 compliance_rag.py
```

---

## Agent 4: Optimization Agent

**File:** `optimization.py`

### Purpose
Solve 0/1 knapsack problem to maximize risk reduction within budget constraints using PuLP.

### Dependencies
```python
PuLP==2.8.0
psycopg2-binary==2.9.9
loguru==0.7.2
```

### Classes

#### `RemediationOption`
Dataclass for remediation options.

**Fields:**
```python
id: str
vuln_id: str
asset_id: str
remediation_type: str  # patch, configuration, compensating_control, accept_risk
cost: float            # USD
eal_reduction: float   # USD
effort_hours: float

@property
roi: float  # eal_reduction / cost
```

#### `OptimizationResult`
Dataclass for optimization output.

**Fields:**
```python
selected_remediations: List[str]  # Remediation IDs
total_cost: float
total_risk_reduction: float
budget_utilization: float  # Percentage
roi: float                 # Total reduction / total cost
solver_status: str         # Optimal, Infeasible, Unbounded
computation_time: float    # Seconds
```

#### `RemediationOptimizer`
Core optimization engine using PuLP.

**Methods:**
- `optimize(budget, remediations, min_roi_threshold=None) -> OptimizationResult`
  - Formulates 0/1 knapsack as integer program
  - Decision variables: x_i ∈ {0, 1}
  - Objective: Maximize Σ(x_i × eal_reduction_i)
  - Constraint: Σ(x_i × cost_i) ≤ budget
  - Solves with CBC (open-source)
  - Returns optimal remediation set

- `sensitivity_analysis(base_budget, remediations, budget_increments) -> Dict`
  - Runs optimization at multiple budget levels
  - Identifies diminishing returns threshold
  - Useful for budget justification

#### `OptimizationService`
Database integration layer.

**Methods:**
- `load_remediation_options() -> List[RemediationOption]`
  - Queries remediation_options table
  - Filters by cost > 0, eal_reduction > 0
  - Orders by EAL reduction (descending)

- `optimize_and_persist(budget, min_roi_threshold) -> OptimizationResult`
  - Loads options from database
  - Runs optimization
  - Saves results to optimization_runs table
  - Updates is_selected flag on remediation_options

### Mathematical Formulation

**Problem:**
```
Maximize: Z = Σ(x_i × r_i)

Subject to:
  Σ(x_i × c_i) ≤ B
  x_i ∈ {0, 1}

Where:
  x_i = 1 if remediation i is selected, 0 otherwise
  r_i = EAL reduction for remediation i
  c_i = Cost for remediation i
  B = Budget
```

### Solver Configuration

**MVP:** CBC (Coin-or Branch and Cut)
- Open source
- Good performance for 100s of variables
- No license required

**Phase 2:** Gurobi or CPLEX
- Commercial solvers
- 10-100x faster for large problems
- Required for 1000+ variables

### Standalone Usage
```bash
cd python
python3 optimization.py
```

**Output:**
```
======================================================================
REMEDIATION OPTIMIZATION RESULTS
======================================================================
Budget: $20,000.00
Status: Optimal

Selected Remediations:
  • CVE-2024-0001 (patch)
    Cost: $5,000.00 | Risk Reduction: $50,000.00 | ROI: 10.00x
  • CVE-2024-0003 (patch)
    Cost: $8,000.00 | Risk Reduction: $80,000.00 | ROI: 10.00x

Summary:
  Total Cost: $13,000.00 (65.0% of budget)
  Total Risk Reduction: $130,000.00
  Overall ROI: 10.00x
======================================================================
```

---

## Agent 5: Orchestrator

**File:** `orchestrator.py`

### Purpose
Coordinate all agents using LangGraph with shared state and feedback loops.

### Dependencies
```python
langgraph==0.0.26
langchain==0.1.13
psycopg2-binary==2.9.9
loguru==0.7.2
# + all dependencies from other agents
```

### State Definition

#### `RiskRegisterState` (TypedDict)
Shared state object passed between all agents.

**Fields:**
```python
# Inputs
asset_mapping: Dict[str, List[str]]
budget: float
days_back: int

# Agent outputs
ingestion_complete: bool
ingestion_count: int
vulnerabilities: List[Dict]

risk_analysis_complete: bool
risk_analyses: List[Dict]

compliance_complete: bool
compliance_mappings: List[Dict]

optimization_complete: bool
optimization_result: Dict

reporting_complete: bool
executive_summary: str

# Control flow
data_quality_check_passed: bool
re_ingestion_needed: bool
iteration_count: int

# Metadata
run_id: str
started_at: datetime
errors: List[str]
```

### Graph Nodes

Each node is a function that:
1. Receives state
2. Performs agent operation
3. Updates state
4. Returns state

**Nodes:**
```python
def data_ingestion_node(state: RiskRegisterState) -> RiskRegisterState
def quality_check_node(state: RiskRegisterState) -> RiskRegisterState
def risk_analysis_node(state: RiskRegisterState) -> RiskRegisterState
def compliance_mapping_node(state: RiskRegisterState) -> RiskRegisterState
def optimization_node(state: RiskRegisterState) -> RiskRegisterState
def reporting_node(state: RiskRegisterState) -> RiskRegisterState
```

### Graph Edges

**Linear edges:**
```python
ingestion → quality_check
risk_analysis → compliance
compliance → optimization
optimization → reporting
reporting → END
```

**Conditional edge (feedback loop):**
```python
quality_check → {
  "re_ingest": ingestion,   # If data insufficient
  "continue": risk_analysis  # If data sufficient
}
```

**Decision function:**
```python
def should_re_ingest(state: RiskRegisterState) -> Literal["re_ingest", "continue"]:
    if state.re_ingestion_needed and state.iteration_count < 3:
        return "re_ingest"
    else:
        return "continue"
```

### Workflow Execution

**Main function:**
```python
def execute_cyber_risk_workflow(
    asset_mapping: Dict[str, List[str]],
    budget: float,
    days_back: int = 30
) -> RiskRegisterState:
    # Initialize state
    initial_state = {...}
    
    # Build graph
    app = build_cyber_risk_graph()
    
    # Execute (blocks until complete)
    final_state = app.invoke(initial_state)
    
    return final_state
```

### Error Handling

All agent nodes wrapped in try/except:
```python
try:
    # Agent logic
    state['agent_complete'] = True
except Exception as e:
    logger.error(f"Agent failed: {e}")
    state['agent_complete'] = False
    state['errors'].append(str(e))
```

Workflow continues even if individual agents fail.

### Standalone Usage
```bash
cd python
python3 orchestrator.py
```

**Output:**
```
======================================================================
STARTING CYBER RISK QUANTIFICATION WORKFLOW
======================================================================
[AGENT 1/5] Data Ingestion (iteration 0)
✓ Ingested 45 vulnerabilities
[QUALITY CHECK] Validating data completeness
[AGENT 2/5] Risk Analysis (FAIR Monte Carlo)
✓ Analyzed 45 vulnerabilities | Total EAL: $1,234,567
[AGENT 3/5] Compliance Mapping (RAG)
✓ Mapped 38 compliance controls
[AGENT 4/5] Remediation Optimization (PuLP)
✓ Optimized remediation: 12 selected | $450,000 risk reduction
[AGENT 5/5] Executive Reporting
✓ Executive report generated
======================================================================
WORKFLOW COMPLETE
Run ID: run_20240115_143022
Vulnerabilities: 45
Errors: 0
======================================================================
```

---

## Utilities

**File:** `utils.py`

### Functions

**Logging:**
```python
setup_logging(level="INFO", log_file=None)
```

**Environment validation:**
```python
validate_environment() -> Dict[str, Any]
```

**Database utilities:**
```python
class DatabaseManager:
    def __init__(database_url, min_conn=1, max_conn=10)
    def get_connection()
    def put_connection(conn)
    def close_all()

test_database_connection(database_url) -> bool
```

**Data export:**
```python
export_risk_register_to_json(database_url, output_path)
```

**Performance monitoring:**
```python
class PerformanceTimer:
    with PerformanceTimer("Operation Name"):
        # ... code to time
```

**Data validation:**
```python
validate_cvss_score(score: float) -> bool  # 0.0 to 10.0
validate_epss_score(score: float) -> bool  # 0.0 to 1.0
validate_cve_format(cve_id: str) -> bool   # CVE-YYYY-NNNNN
```

---

## Setup & Validation

**File:** `setup.py`

### Purpose
Validate Python environment and dependencies.

### Usage
```bash
cd python
python3 setup.py --install
```

### Checks
1. ✓ Python 3.10+ version
2. ✓ Install dependencies from requirements.txt
3. ✓ Verify critical imports (numpy, scipy, langchain, etc.)
4. ✓ Check Ollama availability (optional)
5. ✓ Test database connection (optional)

### Output
```
============================================================
CyberRisk AI - Python Environment Setup
============================================================
✓ Python 3.10.12
📦 Installing Python dependencies...
✓ Dependencies installed
🔍 Verifying imports...
  ✓ NumPy
  ✓ SciPy
  ✓ Requests
  ✓ psycopg2
  ✓ Sentence Transformers
  ✓ ChromaDB
  ✓ LangChain
  ✓ LangGraph
  ✓ PuLP
🦙 Checking Ollama availability (optional)...
  ✓ Ollama is running
  Available models: ['llama3.1:8b']
🗄️  Checking database connection (optional)...
  ✓ PostgreSQL connected: PostgreSQL 16.1...
============================================================
✅ Setup complete! Python agents are ready.
============================================================
```

---

## Testing Agents Individually

Each agent can be tested standalone:

```bash
cd python

# Test data ingestion
python3 data_ingestion.py

# Test FAIR engine
python3 fair_engine.py

# Test compliance RAG (requires Ollama)
ollama serve
python3 compliance_rag.py

# Test optimization
python3 optimization.py

# Test full orchestration
python3 orchestrator.py

# Validate environment
python3 setup.py
```

---

## Common Patterns

### Database Connection
```python
from utils import DatabaseManager

db = DatabaseManager(os.getenv('DATABASE_URL'))
conn = db.get_connection()
try:
    # ... use connection
finally:
    db.put_connection(conn)
```

### Error Logging
```python
from loguru import logger

try:
    # ... operation
    logger.info("Operation succeeded")
except Exception as e:
    logger.error(f"Operation failed: {e}")
```

### Retry Logic
```python
from tenacity import retry, stop_after_attempt, wait_exponential

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=4, max=60)
)
def api_call():
    # ... API request
```

---

**Last Updated:** 2024  
**Version:** 1.0.0 (MVP)
