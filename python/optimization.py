"""
OPTIMIZATION AGENT: Remediation Resource Allocation

Uses PuLP to solve a 0/1 knapsack problem:
- Input: Fixed remediation budget + list of (cost, EAL_reduction) pairs
- Output: Optimal combination maximizing total risk reduction
- Constraint: Total cost ≤ budget

Implements:
- Binary integer programming
- ROI-weighted heuristics for large-scale scenarios
- Sensitivity analysis on budget constraints

Author: Senior Cybersecurity Engineer
"""

from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
import pulp
from loguru import logger
import psycopg2
from psycopg2.extras import Json


@dataclass
class RemediationOption:
    """Single remediation option"""
    id: str  # Database ID
    vuln_id: str
    asset_id: str
    remediation_type: str
    cost: float  # USD
    eal_reduction: float  # Expected Annual Loss reduction (USD)
    effort_hours: float
    
    @property
    def roi(self) -> float:
        """Return on Investment: risk reduction per dollar spent"""
        return self.eal_reduction / self.cost if self.cost > 0 else 0.0


@dataclass
class OptimizationResult:
    """Optimization output"""
    selected_remediations: List[str]  # List of remediation IDs
    total_cost: float
    total_risk_reduction: float
    budget_utilization: float  # Percentage of budget used
    roi: float  # Total risk reduction / total cost
    solver_status: str
    computation_time: float


class RemediationOptimizer:
    """
    0/1 Knapsack optimizer for remediation resource allocation.
    
    Mathematical Formulation:
    
    Maximize: Σ(x_i × risk_reduction_i)
    
    Subject to: Σ(x_i × cost_i) ≤ budget
                x_i ∈ {0, 1}  (binary decision variable)
    
    Where:
    - x_i = 1 if remediation i is selected, 0 otherwise
    - risk_reduction_i = Expected Annual Loss reduction
    - cost_i = Remediation cost
    """
    
    def __init__(self, solver: str = 'PULP_CBC_CMD'):
        """
        Args:
            solver: PuLP solver to use
                - PULP_CBC_CMD: Open-source, good for MVP
                - GUROBI: Commercial, faster for large problems (Phase 2)
                - CPLEX: Commercial, enterprise-grade (Phase 2)
        """
        self.solver = solver
    
    def optimize(
        self,
        budget: float,
        remediations: List[RemediationOption],
        min_roi_threshold: Optional[float] = None
    ) -> OptimizationResult:
        """
        Solve the remediation optimization problem.
        
        Args:
            budget: Maximum available budget (USD)
            remediations: List of remediation options
            min_roi_threshold: Exclude options with ROI below this value
            
        Returns:
            Optimization result with selected remediations
        """
        logger.info(
            f"Starting optimization: {len(remediations)} options, "
            f"${budget:,.2f} budget"
        )
        
        # Filter by minimum ROI if specified
        if min_roi_threshold:
            original_count = len(remediations)
            remediations = [r for r in remediations if r.roi >= min_roi_threshold]
            logger.info(
                f"Filtered by ROI ≥ {min_roi_threshold}: "
                f"{len(remediations)}/{original_count} options remain"
            )
        
        # Check if problem is solvable
        if not remediations:
            logger.warning("No remediations available for optimization")
            return OptimizationResult(
                selected_remediations=[],
                total_cost=0.0,
                total_risk_reduction=0.0,
                budget_utilization=0.0,
                roi=0.0,
                solver_status='NO_OPTIONS',
                computation_time=0.0
            )
        
        # Create optimization problem
        problem = pulp.LpProblem("Remediation_Optimization", pulp.LpMaximize)
        
        # Decision variables: x[i] = 1 if remediation i is selected
        decision_vars = {}
        for i, remediation in enumerate(remediations):
            decision_vars[i] = pulp.LpVariable(
                f"x_{i}",
                cat=pulp.LpBinary  # 0 or 1
            )
        
        # Objective function: Maximize total risk reduction
        problem += pulp.lpSum([
            decision_vars[i] * remediation.eal_reduction
            for i, remediation in enumerate(remediations)
        ]), "Total_Risk_Reduction"
        
        # Constraint: Total cost must not exceed budget
        problem += pulp.lpSum([
            decision_vars[i] * remediation.cost
            for i, remediation in enumerate(remediations)
        ]) <= budget, "Budget_Constraint"
        
        # Solve
        import time
        start_time = time.time()
        
        solver_instance = pulp.getSolver(self.solver, msg=False)
        problem.solve(solver_instance)
        
        computation_time = time.time() - start_time
        
        # Extract results
        selected_indices = [
            i for i in decision_vars
            if pulp.value(decision_vars[i]) == 1
        ]
        
        selected_remediations = [remediations[i].id for i in selected_indices]
        total_cost = sum(remediations[i].cost for i in selected_indices)
        total_risk_reduction = sum(
            remediations[i].eal_reduction for i in selected_indices
        )
        
        budget_utilization = (total_cost / budget * 100) if budget > 0 else 0.0
        roi = (total_risk_reduction / total_cost) if total_cost > 0 else 0.0
        
        status = pulp.LpStatus[problem.status]
        
        logger.info(
            f"Optimization complete: {len(selected_remediations)} remediations selected | "
            f"Cost: ${total_cost:,.2f} ({budget_utilization:.1f}% of budget) | "
            f"Risk Reduction: ${total_risk_reduction:,.2f} | "
            f"ROI: {roi:.2f}x | "
            f"Time: {computation_time:.2f}s"
        )
        
        return OptimizationResult(
            selected_remediations=selected_remediations,
            total_cost=total_cost,
            total_risk_reduction=total_risk_reduction,
            budget_utilization=budget_utilization,
            roi=roi,
            solver_status=status,
            computation_time=computation_time
        )
    
    def sensitivity_analysis(
        self,
        base_budget: float,
        remediations: List[RemediationOption],
        budget_increments: List[float] = [0.8, 0.9, 1.0, 1.1, 1.2]
    ) -> Dict[float, OptimizationResult]:
        """
        Analyze how optimization results change with budget.
        
        Useful for:
        - Budget justification to executives
        - Identifying diminishing returns threshold
        
        Args:
            base_budget: Baseline budget amount
            remediations: List of remediation options
            budget_increments: Multipliers for base budget
            
        Returns:
            Dict mapping budget to optimization result
        """
        logger.info("Running sensitivity analysis")
        
        results = {}
        for multiplier in budget_increments:
            test_budget = base_budget * multiplier
            result = self.optimize(test_budget, remediations)
            results[test_budget] = result
            
            logger.info(
                f"  Budget ${test_budget:,.0f}: "
                f"{len(result.selected_remediations)} remediations, "
                f"${result.total_risk_reduction:,.0f} reduction, "
                f"ROI {result.roi:.2f}x"
            )
        
        return results


class OptimizationService:
    """Service layer for optimization with database integration"""
    
    def __init__(self, database_url: str):
        self.database_url = database_url
        self.optimizer = RemediationOptimizer()
    
    def connect_db(self):
        return psycopg2.connect(self.database_url)
    
    def load_remediation_options(self) -> List[RemediationOption]:
        """
        Load remediation options from database.
        
        Joins vulnerabilities, risk_analysis, and remediation_options tables.
        """
        conn = self.connect_db()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT 
                        ro.id::text,
                        ro.vuln_id,
                        ro.asset_id,
                        ro.remediation_type,
                        ro.estimated_cost,
                        ro.eal_reduction,
                        COALESCE(ro.estimated_effort, 0) as estimated_effort
                    FROM remediation_options ro
                    WHERE ro.estimated_cost > 0 
                      AND ro.eal_reduction > 0
                      AND ro.is_selected IS NOT TRUE
                    ORDER BY ro.eal_reduction DESC
                """)
                
                rows = cursor.fetchall()
                
                remediations = [
                    RemediationOption(
                        id=row[0],
                        vuln_id=row[1],
                        asset_id=row[2],
                        remediation_type=row[3],
                        cost=float(row[4]),
                        eal_reduction=float(row[5]),
                        effort_hours=float(row[6])
                    )
                    for row in rows
                ]
                
                logger.info(f"Loaded {len(remediations)} remediation options from database")
                return remediations
                
        finally:
            conn.close()
    
    def optimize_and_persist(
        self,
        budget: float,
        min_roi_threshold: Optional[float] = None
    ) -> OptimizationResult:
        """
        Run optimization and save results to database.
        """
        # Load options
        remediations = self.load_remediation_options()
        
        if not remediations:
            logger.warning("No remediation options found in database")
            return OptimizationResult(
                selected_remediations=[],
                total_cost=0.0,
                total_risk_reduction=0.0,
                budget_utilization=0.0,
                roi=0.0,
                solver_status='NO_DATA',
                computation_time=0.0
            )
        
        # Optimize
        result = self.optimizer.optimize(budget, remediations, min_roi_threshold)
        
        # Persist results
        conn = self.connect_db()
        try:
            with conn.cursor() as cursor:
                # Insert optimization run
                cursor.execute("""
                    INSERT INTO optimization_runs (
                        budget, total_cost_allocated, total_risk_reduction,
                        selected_remediations, optimization_algorithm
                    ) VALUES (%s, %s, %s, %s, %s)
                    RETURNING id
                """, (
                    budget,
                    result.total_cost,
                    result.total_risk_reduction,
                    Json(result.selected_remediations),
                    'pulp_knapsack_0_1'
                ))
                
                run_id = cursor.fetchone()[0]
                
                # Mark selected remediations
                if result.selected_remediations:
                    cursor.execute("""
                        UPDATE remediation_options
                        SET is_selected = TRUE, priority = 1
                        WHERE id = ANY(%s)
                    """, (result.selected_remediations,))
                
                conn.commit()
                logger.info(f"Saved optimization run {run_id}")
                
        except Exception as e:
            logger.error(f"Failed to persist optimization: {e}")
            conn.rollback()
        finally:
            conn.close()
        
        return result


def main():
    """Standalone testing with synthetic data"""
    
    # Create synthetic remediation options
    synthetic_options = [
        RemediationOption(
            id='r1', vuln_id='CVE-2024-0001', asset_id='asset-001',
            remediation_type='patch', cost=5000, eal_reduction=50000, effort_hours=8
        ),
        RemediationOption(
            id='r2', vuln_id='CVE-2024-0002', asset_id='asset-002',
            remediation_type='configuration', cost=2000, eal_reduction=15000, effort_hours=4
        ),
        RemediationOption(
            id='r3', vuln_id='CVE-2024-0003', asset_id='asset-003',
            remediation_type='patch', cost=8000, eal_reduction=80000, effort_hours=16
        ),
        RemediationOption(
            id='r4', vuln_id='CVE-2024-0004', asset_id='asset-001',
            remediation_type='compensating_control', cost=12000, eal_reduction=60000, effort_hours=40
        ),
        RemediationOption(
            id='r5', vuln_id='CVE-2024-0005', asset_id='asset-004',
            remediation_type='patch', cost=3000, eal_reduction=25000, effort_hours=6
        ),
    ]
    
    optimizer = RemediationOptimizer()
    
    # Test optimization with $20k budget
    budget = 20000
    result = optimizer.optimize(budget, synthetic_options)
    
    print(f"\n{'='*70}")
    print("REMEDIATION OPTIMIZATION RESULTS")
    print(f"{'='*70}")
    print(f"Budget: ${budget:,.2f}")
    print(f"Status: {result.solver_status}")
    print(f"\nSelected Remediations:")
    
    for rem_id in result.selected_remediations:
        rem = next(r for r in synthetic_options if r.id == rem_id)
        print(f"  • {rem.vuln_id} ({rem.remediation_type})")
        print(f"    Cost: ${rem.cost:,.2f} | Risk Reduction: ${rem.eal_reduction:,.2f} | ROI: {rem.roi:.2f}x")
    
    print(f"\nSummary:")
    print(f"  Total Cost: ${result.total_cost:,.2f} ({result.budget_utilization:.1f}% of budget)")
    print(f"  Total Risk Reduction: ${result.total_risk_reduction:,.2f}")
    print(f"  Overall ROI: {result.roi:.2f}x")
    print(f"  Computation Time: {result.computation_time:.3f}s")
    print(f"{'='*70}\n")
    
    # Sensitivity analysis
    print("SENSITIVITY ANALYSIS")
    print(f"{'='*70}")
    sensitivity = optimizer.sensitivity_analysis(budget, synthetic_options)
    
    for test_budget, test_result in sorted(sensitivity.items()):
        print(
            f"${test_budget:>10,.0f} → "
            f"{len(test_result.selected_remediations)} remediations, "
            f"${test_result.total_risk_reduction:>10,.0f} reduction, "
            f"ROI {test_result.roi:>5.2f}x"
        )
    print(f"{'='*70}\n")


if __name__ == '__main__':
    main()
