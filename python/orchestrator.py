"""
ORCHESTRATION & STATE MANAGEMENT: LangGraph Multi-Agent Workflow

Implements:
- Shared state object (risk register) across all agents
- Conditional edge routing based on data quality
- Feedback loop for data re-ingestion
- Graph visualization and execution tracking

Workflow:
1. Data Ingestion → 2. Risk Analysis → 3. Compliance Mapping → 
4. Optimization → 5. Reporting → [Feedback to step 1 if needed]

Author: Senior Cybersecurity Engineer
"""

import os
from typing import TypedDict, List, Dict, Annotated, Literal
from typing_extensions import NotRequired
import operator
from langgraph.graph import StateGraph, END
from loguru import logger
import psycopg2
from datetime import datetime

# Import our agents
from data_ingestion import DataIngestionAgent
from fair_engine import RiskAnalysisService
from compliance_rag import ComplianceRAGPipeline, ComplianceService
from optimization import OptimizationService


# ===== SHARED STATE DEFINITION =====

class RiskRegisterState(TypedDict):
    """
    Shared state object passed between all agents.
    This is the "risk register" that accumulates data through the pipeline.
    """
    # Input parameters
    asset_mapping: Dict[str, List[str]]  # {asset_id: [cve_ids]}
    budget: float
    days_back: int
    
    # Agent outputs
    ingestion_complete: bool
    ingestion_count: int
    vulnerabilities: List[Dict]  # Raw vulnerability data
    
    risk_analysis_complete: bool
    risk_analyses: List[Dict]  # FAIR outputs
    
    compliance_complete: bool
    compliance_mappings: List[Dict]
    
    optimization_complete: bool
    optimization_result: NotRequired[Dict]
    
    reporting_complete: bool
    executive_summary: NotRequired[str]
    
    # Feedback control
    data_quality_check_passed: bool
    re_ingestion_needed: bool
    iteration_count: int
    
    # Metadata
    run_id: str
    started_at: datetime
    errors: List[str]


# ===== AGENT NODES =====

def data_ingestion_node(state: RiskRegisterState) -> RiskRegisterState:
    """
    Node 1: Ingest CVE/EPSS data
    """
    logger.info(f"[AGENT 1/5] Data Ingestion (iteration {state['iteration_count']})")
    
    try:
        database_url = os.getenv('DATABASE_URL')
        nvd_api_key = os.getenv('NVD_API_KEY')
        
        agent = DataIngestionAgent(database_url, nvd_api_key)
        
        success, failed = agent.ingest_vulnerabilities(
            asset_mapping=state['asset_mapping'],
            days_back=state['days_back']
        )
        
        state['ingestion_complete'] = True
        state['ingestion_count'] = success
        state['errors'] = state.get('errors', [])
        
        if failed > 0:
            state['errors'].append(f"Data ingestion: {failed} failures")
        
        logger.info(f"✓ Ingested {success} vulnerabilities")
        
    except Exception as e:
        logger.error(f"✗ Data ingestion failed: {e}")
        state['ingestion_complete'] = False
        state['errors'].append(f"Data ingestion error: {str(e)}")
    
    return state


def risk_analysis_node(state: RiskRegisterState) -> RiskRegisterState:
    """
    Node 2: FAIR risk quantification
    """
    logger.info("[AGENT 2/5] Risk Analysis (FAIR Monte Carlo)")
    
    try:
        database_url = os.getenv('DATABASE_URL')
        service = RiskAnalysisService(database_url, simulation_runs=10000)
        
        # Fetch vulnerabilities from database
        conn = psycopg2.connect(database_url)
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT v.vuln_id, v.asset_id, v.cvss_score, v.epss_score
                FROM vulnerabilities v
                WHERE v.status = 'open'
                LIMIT 100  -- MVP: limit for performance
            """)
            vulns = cursor.fetchall()
        conn.close()
        
        risk_analyses = []
        
        for vuln_id, asset_id, cvss_score, epss_score in vulns:
            # Run FAIR analysis
            result = service.analyze_vulnerability(
                vuln_id=vuln_id,
                asset_id=asset_id,
                cvss_score=cvss_score,
                epss_score=epss_score,
                asset_value=100000.0,  # Default $100k
                asset_criticality='medium'
            )
            
            risk_analyses.append({
                'vuln_id': vuln_id,
                'asset_id': asset_id,
                'eal_mean': result.eal_mean,
                'eal_95th': result.eal_95th_percentile
            })
        
        state['risk_analysis_complete'] = True
        state['risk_analyses'] = risk_analyses
        
        total_eal = sum(r['eal_mean'] for r in risk_analyses)
        logger.info(f"✓ Analyzed {len(risk_analyses)} vulnerabilities | Total EAL: ${total_eal:,.2f}")
        
    except Exception as e:
        logger.error(f"✗ Risk analysis failed: {e}")
        state['risk_analysis_complete'] = False
        state['errors'].append(f"Risk analysis error: {str(e)}")
    
    return state


def compliance_mapping_node(state: RiskRegisterState) -> RiskRegisterState:
    """
    Node 3: RAG-based compliance control mapping
    """
    logger.info("[AGENT 3/5] Compliance Mapping (RAG)")
    
    try:
        database_url = os.getenv('DATABASE_URL')
        
        # Initialize RAG pipeline
        rag = ComplianceRAGPipeline(use_ollama=True)
        service = ComplianceService(database_url, rag)
        
        # Fetch vulnerabilities
        conn = psycopg2.connect(database_url)
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT vuln_id, description
                FROM vulnerabilities
                WHERE status = 'open'
                LIMIT 20  -- MVP: limit LLM calls
            """)
            vulns = cursor.fetchall()
        conn.close()
        
        all_mappings = []
        
        for vuln_id, description in vulns:
            mappings = service.map_and_persist(vuln_id, description or "Unknown vulnerability")
            all_mappings.extend(mappings)
        
        state['compliance_complete'] = True
        state['compliance_mappings'] = [
            {
                'vuln_id': m.vuln_id,
                'framework': m.framework,
                'control_id': m.control_id,
                'confidence': m.mapping_confidence
            }
            for m in all_mappings
        ]
        
        logger.info(f"✓ Mapped {len(all_mappings)} compliance controls")
        
    except Exception as e:
        logger.error(f"✗ Compliance mapping failed: {e}")
        state['compliance_complete'] = False
        state['errors'].append(f"Compliance mapping error: {str(e)}")
    
    return state


def optimization_node(state: RiskRegisterState) -> RiskRegisterState:
    """
    Node 4: Remediation optimization
    """
    logger.info("[AGENT 4/5] Remediation Optimization (PuLP)")
    
    try:
        database_url = os.getenv('DATABASE_URL')
        service = OptimizationService(database_url)
        
        result = service.optimize_and_persist(
            budget=state['budget'],
            min_roi_threshold=1.0  # Only consider remediations with ROI ≥ 1.0
        )
        
        state['optimization_complete'] = True
        state['optimization_result'] = {
            'selected_count': len(result.selected_remediations),
            'total_cost': result.total_cost,
            'total_risk_reduction': result.total_risk_reduction,
            'roi': result.roi,
            'budget_utilization': result.budget_utilization
        }
        
        logger.info(
            f"✓ Optimized remediation: {len(result.selected_remediations)} selected | "
            f"${result.total_risk_reduction:,.2f} risk reduction"
        )
        
    except Exception as e:
        logger.error(f"✗ Optimization failed: {e}")
        state['optimization_complete'] = False
        state['errors'].append(f"Optimization error: {str(e)}")
    
    return state


def reporting_node(state: RiskRegisterState) -> RiskRegisterState:
    """
    Node 5: Generate executive report
    """
    logger.info("[AGENT 5/5] Executive Reporting")
    
    try:
        database_url = os.getenv('DATABASE_URL')
        conn = psycopg2.connect(database_url)
        
        # Aggregate metrics
        with conn.cursor() as cursor:
            # Count assets and vulnerabilities
            cursor.execute("SELECT COUNT(DISTINCT asset_id) FROM vulnerabilities WHERE status = 'open'")
            total_assets = cursor.fetchone()[0] or 0
            
            cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE status = 'open'")
            total_vulns = cursor.fetchone()[0] or 0
            
            # Aggregate EAL
            cursor.execute("SELECT SUM(eal_mode) FROM risk_analysis")
            aggregate_eal = cursor.fetchone()[0] or 0.0
            
            # Top risks
            cursor.execute("""
                SELECT ra.vuln_id, ra.asset_id, ra.eal_95th_percentile
                FROM risk_analysis ra
                ORDER BY ra.eal_95th_percentile DESC
                LIMIT 10
            """)
            top_risks = [
                {'vuln_id': row[0], 'asset_id': row[1], 'eal_95th': float(row[2])}
                for row in cursor.fetchall()
            ]
            
            # Compliance score
            cursor.execute("""
                SELECT 
                    COUNT(DISTINCT vuln_id)::float / NULLIF((SELECT COUNT(*) FROM vulnerabilities WHERE status = 'open'), 0) * 100
                FROM compliance_mappings
            """)
            compliance_score = cursor.fetchone()[0] or 0.0
        
        # Generate 200-word executive summary
        opt_result = state.get('optimization_result', {})
        
        summary = f"""EXECUTIVE RISK SUMMARY
        
Risk Landscape: Our organization currently faces {total_vulns} active vulnerabilities across {total_assets} critical assets. 

Financial Exposure: Through rigorous Factor Analysis of Information Risk (FAIR) methodology with Monte Carlo simulation, we quantify our aggregate Expected Annual Loss at ${aggregate_eal:,.0f}. This represents the statistically-expected financial impact from cyber incidents over the next 12 months.

Top Risks: The highest-risk vulnerability carries a 95th percentile annual loss of ${top_risks[0]['eal_95th']:,.0f} if left unaddressed. Our top 10 risks account for {(sum(r['eal_95th'] for r in top_risks) / aggregate_eal * 100):.1f}% of total exposure.

Remediation Strategy: We have identified {opt_result.get('selected_count', 0)} priority remediations requiring ${opt_result.get('total_cost', 0):,.0f} investment. This targeted approach will reduce annual risk by ${opt_result.get('total_risk_reduction', 0):,.0f}, delivering a {opt_result.get('roi', 0):.1f}x return on security investment.

Compliance Posture: {compliance_score:.1f}% of vulnerabilities are mapped to NIST CSF 2.0 and ISO 27001 controls, demonstrating alignment with industry frameworks.

Recommendation: Immediate approval of the proposed remediation budget will achieve maximum risk reduction while maintaining operational efficiency."""
        
        # Persist report
        with conn.cursor() as cursor:
            from psycopg2.extras import Json
            cursor.execute("""
                INSERT INTO executive_reports (
                    total_assets, total_vulnerabilities, aggregate_eal,
                    top_risks, compliance_score, executive_summary, raw_data
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                total_assets, total_vulns, float(aggregate_eal),
                Json(top_risks), float(compliance_score), summary,
                Json(state)
            ))
            conn.commit()
        
        conn.close()
        
        state['reporting_complete'] = True
        state['executive_summary'] = summary
        
        logger.info("✓ Executive report generated")
        
    except Exception as e:
        logger.error(f"✗ Reporting failed: {e}")
        state['reporting_complete'] = False
        state['errors'].append(f"Reporting error: {str(e)}")
    
    return state


def data_quality_check_node(state: RiskRegisterState) -> RiskRegisterState:
    """
    Quality gate: Verify data completeness
    """
    logger.info("[QUALITY CHECK] Validating data completeness")
    
    # Check if we have sufficient data
    min_required_vulns = 1
    
    if state.get('ingestion_count', 0) < min_required_vulns:
        logger.warning(f"Insufficient data: {state.get('ingestion_count', 0)} vulnerabilities")
        state['data_quality_check_passed'] = False
        state['re_ingestion_needed'] = True
    else:
        state['data_quality_check_passed'] = True
        state['re_ingestion_needed'] = False
    
    return state


# ===== ROUTING LOGIC =====

def should_re_ingest(state: RiskRegisterState) -> Literal["re_ingest", "continue"]:
    """
    Conditional edge: Re-ingest data if quality check fails
    """
    max_iterations = 3
    
    if state.get('re_ingestion_needed') and state.get('iteration_count', 0) < max_iterations:
        logger.info("⟲ Data quality insufficient - triggering re-ingestion")
        state['iteration_count'] = state.get('iteration_count', 0) + 1
        return "re_ingest"
    else:
        return "continue"


# ===== GRAPH CONSTRUCTION =====

def build_cyber_risk_graph() -> StateGraph:
    """
    Construct the LangGraph workflow.
    
    Graph Structure:
    
    START → Ingestion → Quality Check → [PASS] → Risk Analysis → Compliance → Optimization → Reporting → END
                              ↓
                           [FAIL] → Re-ingestion (max 3 iterations)
    """
    workflow = StateGraph(RiskRegisterState)
    
    # Add nodes
    workflow.add_node("ingestion", data_ingestion_node)
    workflow.add_node("quality_check", data_quality_check_node)
    workflow.add_node("risk_analysis", risk_analysis_node)
    workflow.add_node("compliance", compliance_mapping_node)
    workflow.add_node("optimization", optimization_node)
    workflow.add_node("reporting", reporting_node)
    
    # Define edges
    workflow.set_entry_point("ingestion")
    workflow.add_edge("ingestion", "quality_check")
    
    # Conditional edge: re-ingest or continue
    workflow.add_conditional_edges(
        "quality_check",
        should_re_ingest,
        {
            "re_ingest": "ingestion",
            "continue": "risk_analysis"
        }
    )
    
    workflow.add_edge("risk_analysis", "compliance")
    workflow.add_edge("compliance", "optimization")
    workflow.add_edge("optimization", "reporting")
    workflow.add_edge("reporting", END)
    
    return workflow.compile()


# ===== EXECUTION =====

def execute_cyber_risk_workflow(
    asset_mapping: Dict[str, List[str]],
    budget: float,
    days_back: int = 30
) -> RiskRegisterState:
    """
    Execute the full multi-agent workflow.
    
    Args:
        asset_mapping: {asset_id: [cve_ids]}
        budget: Remediation budget (USD)
        days_back: Days of CVE history to fetch
        
    Returns:
        Final state with all analysis results
    """
    logger.info("="*70)
    logger.info("STARTING CYBER RISK QUANTIFICATION WORKFLOW")
    logger.info("="*70)
    
    # Initialize state
    initial_state: RiskRegisterState = {
        'asset_mapping': asset_mapping,
        'budget': budget,
        'days_back': days_back,
        'ingestion_complete': False,
        'ingestion_count': 0,
        'vulnerabilities': [],
        'risk_analysis_complete': False,
        'risk_analyses': [],
        'compliance_complete': False,
        'compliance_mappings': [],
        'optimization_complete': False,
        'reporting_complete': False,
        'data_quality_check_passed': False,
        're_ingestion_needed': False,
        'iteration_count': 0,
        'run_id': f"run_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
        'started_at': datetime.utcnow(),
        'errors': []
    }
    
    # Build and execute graph
    app = build_cyber_risk_graph()
    
    final_state = app.invoke(initial_state)
    
    logger.info("="*70)
    logger.info("WORKFLOW COMPLETE")
    logger.info(f"Run ID: {final_state['run_id']}")
    logger.info(f"Vulnerabilities: {final_state.get('ingestion_count', 0)}")
    logger.info(f"Errors: {len(final_state.get('errors', []))}")
    logger.info("="*70)
    
    return final_state


def main():
    """Standalone execution"""
    from dotenv import load_dotenv
    load_dotenv()
    
    # Example execution
    asset_mapping = {
        'asset-web-001': ['CVE-2024-0001', 'CVE-2024-0002'],
        'asset-db-001': ['CVE-2024-0003'],
    }
    
    final_state = execute_cyber_risk_workflow(
        asset_mapping=asset_mapping,
        budget=50000.0,
        days_back=30
    )
    
    # Print executive summary
    if final_state.get('executive_summary'):
        print("\n" + "="*70)
        print(final_state['executive_summary'])
        print("="*70 + "\n")


if __name__ == '__main__':
    main()
