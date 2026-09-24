"""
CyberGuard AI - Plain-English Executive Summary Generator
Generates board-ready, plain-English executive summaries strictly grounded in
actual quantified dollar risks and optimization results.
Never hallucinates or overrides deterministic numbers.
"""

from typing import Any, Optional
from backend.schemas import RiskSummaryResponse, OptimizationResult


from backend.market_data import GLOBAL_AVG_BREACH_COST_USD

def generate_executive_summary(
    risk_summary: RiskSummaryResponse,
    optimization_result: Optional[OptimizationResult] = None
) -> str:
    """
    Generate a plain-English board-ready executive summary.
    
    Interface strictly matches:
        def generate_executive_summary(risk_summary: [RiskSummaryType], optimization_result: [OptimizationResultType]) -> str:
    """
    total_risk = risk_summary.total_quantified_risk
    formatted_risk = f"${total_risk:,.0f}" if total_risk >= 1000 else f"${total_risk:.2f}"
    
    # Identify highest-risk business unit
    top_bu = "Corporate Infrastructure"
    top_bu_risk = 0.0
    for bu, r in risk_summary.risk_by_business_unit.items():
        if r > top_bu_risk:
            top_bu_risk = r
            top_bu = bu

    bu_pct = (top_bu_risk / total_risk * 100.0) if total_risk > 0 else 0.0

    # Summary sentence 1: Current risk posture and top exposure driver
    s1 = (
        f"CyberGuard AI quantifies our current enterprise cyber risk exposure at {formatted_risk} across "
        f"{risk_summary.total_assets} critical assets and {risk_summary.total_findings} active findings, "
        f"with {top_bu} representing the highest financial exposure at ${top_bu_risk:,.0f} ({bu_pct:.1f}% of total risk)."
    )

    # Summary sentence 2: IBM Benchmark Integration
    diff_pct = abs((total_risk - GLOBAL_AVG_BREACH_COST_USD) / GLOBAL_AVG_BREACH_COST_USD) * 100
    if total_risk > GLOBAL_AVG_BREACH_COST_USD:
        s2 = f"This exposure is {diff_pct:.1f}% higher than the IBM Cost of a Data Breach 2024 global average of $4.88M, requiring urgent board-level visibility."
    else:
        s2 = f"This exposure tracks {diff_pct:.1f}% below the IBM Cost of a Data Breach 2024 global average of $4.88M, though significant residual risks remain."

    # Summary sentence 3: Investment optimization & ROI decision support
    if optimization_result and optimization_result.total_cost_allocated > 0:
        s3 = (
            f"Allocating the approved ${optimization_result.budget:,.0f} budget executes {len(optimization_result.selected_actions)} "
            f"targeted remediation controls costing ${optimization_result.total_cost_allocated:,.0f}, "
            f"eliminating ${optimization_result.total_risk_reduction:,.0f} in annualized cyber loss for an exceptional "
            f"{optimization_result.overall_roi:.1f}x return on security investment."
        )
    else:
        s3 = (
            "Immediate targeted remediation of top internet-facing critical vulnerabilities is recommended "
            "to achieve maximum financial risk reduction within available engineering capacity."
        )

    return f"{s1} {s2} {s3}"
