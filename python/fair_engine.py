"""
RISK ENGINE: FAIR Methodology with Monte Carlo Simulation

Implements Factor Analysis of Information Risk (FAIR) using:
- Monte Carlo simulation (10,000+ iterations)
- PERT (triangular) distributions for input parameters
- Statistical confidence intervals instead of point estimates

References:
- FAIR Institute: https://www.fairinstitute.org/
- PyFair: https://github.com/theonaunheim/pyfair

Author: Senior Cybersecurity Engineer & GRC Specialist
"""

import numpy as np
from scipy import stats
from typing import Dict, Tuple, Optional
from dataclasses import dataclass
import psycopg2
from psycopg2.extras import Json
from loguru import logger


@dataclass
class FairInput:
    """
    FAIR input parameters using PERT (triangular) distributions.
    All frequency values are annualized.
    All loss values are in USD.
    """
    # Loss Event Frequency (LEF) components
    contact_frequency_min: float  # Threat events contacting asset per year
    contact_frequency_mode: float
    contact_frequency_max: float
    
    probability_of_action_min: float  # 0.0 to 1.0
    probability_of_action_mode: float
    probability_of_action_max: float
    
    vulnerability_min: float  # 0.0 to 1.0 (probability control fails)
    vulnerability_mode: float
    vulnerability_max: float
    
    # Loss Magnitude (LM) components
    primary_loss_min: float  # Direct financial impact (USD)
    primary_loss_mode: float
    primary_loss_max: float
    
    secondary_loss_min: float  # Indirect costs: downtime, reputation (USD)
    secondary_loss_mode: float
    secondary_loss_max: float


@dataclass
class FairOutput:
    """FAIR analysis results with statistical confidence intervals"""
    # Expected Annual Loss (EAL) statistics
    eal_min: float
    eal_mode: float  # Most likely value
    eal_mean: float
    eal_max: float
    eal_95th_percentile: float  # 95% of scenarios result in loss <= this value
    eal_std: float
    
    # Supporting metrics
    loss_event_frequency_mean: float  # Events per year
    loss_magnitude_mean: float  # USD per event
    
    # Full distribution for visualization
    eal_distribution: np.ndarray
    simulation_runs: int


class FairRiskEngine:
    """
    FAIR-compliant Monte Carlo risk quantification engine.
    
    Key Principles:
    1. Use ranges (min/mode/max) instead of point estimates
    2. Model uncertainty explicitly through distributions
    3. Output confidence intervals, not false precision
    """
    
    def __init__(self, simulation_runs: int = 10000):
        """
        Args:
            simulation_runs: Number of Monte Carlo iterations (10k+ recommended)
        """
        self.simulation_runs = simulation_runs
        np.random.seed(42)  # Reproducibility for testing
    
    @staticmethod
    def pert_distribution(minimum: float, mode: float, maximum: float, size: int) -> np.ndarray:
        """
        Generate PERT (Program Evaluation and Review Technique) distribution.
        
        PERT is a modified Beta distribution commonly used in risk analysis.
        It's more realistic than uniform/triangular for modeling expert estimates.
        
        Args:
            minimum: Optimistic estimate
            mode: Most likely estimate
            maximum: Pessimistic estimate
            size: Number of samples to generate
            
        Returns:
            Array of samples from PERT distribution
        """
        # PERT uses Beta distribution with shape parameters derived from range
        # Standard PERT formula: lambda = 4 (gives more weight to mode)
        lambda_param = 4
        
        mean = (minimum + lambda_param * mode + maximum) / (lambda_param + 2)
        
        if maximum == minimum:
            return np.full(size, mode)
        
        # Beta distribution parameters
        alpha = 1 + lambda_param * (mode - minimum) / (maximum - minimum)
        beta = 1 + lambda_param * (maximum - mode) / (maximum - minimum)
        
        # Generate Beta samples and scale to [min, max]
        beta_samples = np.random.beta(alpha, beta, size)
        return minimum + beta_samples * (maximum - minimum)
    
    def calculate_fair(self, inputs: FairInput) -> FairOutput:
        """
        Execute FAIR Monte Carlo simulation.
        
        FAIR Formula:
        Risk = Loss Event Frequency (LEF) × Loss Magnitude (LM)
        
        Where:
        - LEF = Contact Frequency × Probability of Action × Vulnerability
        - LM = Primary Loss + Secondary Loss
        
        Args:
            inputs: FAIR input parameters
            
        Returns:
            Statistical analysis of Expected Annual Loss
        """
        logger.info(f"Starting FAIR analysis with {self.simulation_runs} simulations")
        
        # Generate distributions for each component
        contact_freq = self.pert_distribution(
            inputs.contact_frequency_min,
            inputs.contact_frequency_mode,
            inputs.contact_frequency_max,
            self.simulation_runs
        )
        
        prob_action = self.pert_distribution(
            inputs.probability_of_action_min,
            inputs.probability_of_action_mode,
            inputs.probability_of_action_max,
            self.simulation_runs
        )
        
        vulnerability = self.pert_distribution(
            inputs.vulnerability_min,
            inputs.vulnerability_mode,
            inputs.vulnerability_max,
            self.simulation_runs
        )
        
        # Loss Event Frequency (events per year)
        lef = contact_freq * prob_action * vulnerability
        
        # Loss Magnitude (USD per event)
        primary_loss = self.pert_distribution(
            inputs.primary_loss_min,
            inputs.primary_loss_mode,
            inputs.primary_loss_max,
            self.simulation_runs
        )
        
        secondary_loss = self.pert_distribution(
            inputs.secondary_loss_min,
            inputs.secondary_loss_mode,
            inputs.secondary_loss_max,
            self.simulation_runs
        )
        
        loss_magnitude = primary_loss + secondary_loss
        
        # Expected Annual Loss (USD per year)
        eal = lef * loss_magnitude
        
        # Statistical analysis
        percentiles = np.percentile(eal, [0, 50, 95, 100])
        
        output = FairOutput(
            eal_min=float(percentiles[0]),
            eal_mode=float(percentiles[1]),  # Median as "most likely"
            eal_mean=float(np.mean(eal)),
            eal_max=float(percentiles[3]),
            eal_95th_percentile=float(percentiles[2]),
            eal_std=float(np.std(eal)),
            loss_event_frequency_mean=float(np.mean(lef)),
            loss_magnitude_mean=float(np.mean(loss_magnitude)),
            eal_distribution=eal,
            simulation_runs=self.simulation_runs
        )
        
        logger.info(
            f"FAIR Analysis Complete | "
            f"EAL Mean: ${output.eal_mean:,.0f} | "
            f"95th Percentile: ${output.eal_95th_percentile:,.0f}"
        )
        
        return output
    
    def cvss_to_fair_inputs(
        self,
        cvss_score: float,
        epss_score: Optional[float],
        asset_value: float,
        asset_criticality: str
    ) -> FairInput:
        """
        Convert CVSS/EPSS scores to FAIR input parameters.
        
        This is a heuristic mapping based on industry best practices.
        Organizations should calibrate these mappings to their own data.
        
        Args:
            cvss_score: CVSS base score (0-10)
            epss_score: EPSS probability (0-1), None if unavailable
            asset_value: Asset replacement/recovery cost (USD)
            asset_criticality: critical, high, medium, low
            
        Returns:
            FAIR input parameters
        """
        # Map CVSS to vulnerability (probability control fails)
        # CVSS ≥ 9.0: Very high vulnerability
        # CVSS 7.0-8.9: High vulnerability
        # CVSS 4.0-6.9: Medium vulnerability
        # CVSS < 4.0: Low vulnerability
        
        if cvss_score >= 9.0:
            vuln_min, vuln_mode, vuln_max = 0.7, 0.85, 0.95
        elif cvss_score >= 7.0:
            vuln_min, vuln_mode, vuln_max = 0.5, 0.7, 0.85
        elif cvss_score >= 4.0:
            vuln_min, vuln_mode, vuln_max = 0.2, 0.4, 0.6
        else:
            vuln_min, vuln_mode, vuln_max = 0.05, 0.15, 0.3
        
        # Map EPSS to Threat Event Frequency × Probability of Action
        # EPSS represents 30-day exploitation probability
        # Annualize: multiply by 12, then decompose into TEF and PoA
        
        if epss_score is not None:
            annual_exploit_prob = epss_score * 12
            # High EPSS = frequent, determined threat actors
            contact_freq_mode = min(annual_exploit_prob * 100, 1000)
            prob_action_mode = min(annual_exploit_prob, 0.9)
        else:
            # Conservative defaults if EPSS unavailable
            contact_freq_mode = 50  # 50 threat events/year
            prob_action_mode = 0.3
        
        contact_freq_min = contact_freq_mode * 0.5
        contact_freq_max = contact_freq_mode * 2.0
        
        prob_action_min = max(prob_action_mode * 0.5, 0.01)
        prob_action_max = min(prob_action_mode * 1.5, 1.0)
        
        # Map asset criticality to loss magnitude
        criticality_multipliers = {
            'critical': 3.0,
            'high': 2.0,
            'medium': 1.0,
            'low': 0.5
        }
        
        multiplier = criticality_multipliers.get(asset_criticality, 1.0)
        
        # Primary loss: direct costs (data breach, recovery, forensics)
        primary_loss_mode = asset_value * multiplier
        primary_loss_min = primary_loss_mode * 0.3
        primary_loss_max = primary_loss_mode * 3.0
        
        # Secondary loss: reputation, regulatory fines, business disruption
        # Typically 1-5x primary loss for high-profile breaches
        secondary_loss_mode = primary_loss_mode * 1.5
        secondary_loss_min = primary_loss_mode * 0.5
        secondary_loss_max = primary_loss_mode * 5.0
        
        return FairInput(
            contact_frequency_min=contact_freq_min,
            contact_frequency_mode=contact_freq_mode,
            contact_frequency_max=contact_freq_max,
            probability_of_action_min=prob_action_min,
            probability_of_action_mode=prob_action_mode,
            probability_of_action_max=prob_action_max,
            vulnerability_min=vuln_min,
            vulnerability_mode=vuln_mode,
            vulnerability_max=vuln_max,
            primary_loss_min=primary_loss_min,
            primary_loss_mode=primary_loss_mode,
            primary_loss_max=primary_loss_max,
            secondary_loss_min=secondary_loss_min,
            secondary_loss_mode=secondary_loss_mode,
            secondary_loss_max=secondary_loss_max
        )


class RiskAnalysisService:
    """
    Service layer for executing and persisting FAIR risk analysis.
    """
    
    def __init__(self, database_url: str, simulation_runs: int = 10000):
        self.database_url = database_url
        self.engine = FairRiskEngine(simulation_runs=simulation_runs)
    
    def connect_db(self):
        return psycopg2.connect(self.database_url)
    
    def analyze_vulnerability(
        self,
        vuln_id: str,
        asset_id: str,
        cvss_score: float,
        epss_score: Optional[float],
        asset_value: float = 100000.0,  # Default $100k
        asset_criticality: str = 'medium'
    ) -> FairOutput:
        """
        Run FAIR analysis for a single vulnerability.
        
        Returns:
            FAIR output with EAL confidence intervals
        """
        logger.info(f"Analyzing {vuln_id} on asset {asset_id}")
        
        # Convert CVSS/EPSS to FAIR inputs
        fair_inputs = self.engine.cvss_to_fair_inputs(
            cvss_score=cvss_score,
            epss_score=epss_score,
            asset_value=asset_value,
            asset_criticality=asset_criticality
        )
        
        # Run Monte Carlo simulation
        result = self.engine.calculate_fair(fair_inputs)
        
        # Persist to database
        self._save_to_database(vuln_id, asset_id, fair_inputs, result)
        
        return result
    
    def _save_to_database(
        self,
        vuln_id: str,
        asset_id: str,
        inputs: FairInput,
        output: FairOutput
    ):
        """Save FAIR analysis results to PostgreSQL"""
        conn = self.connect_db()
        try:
            with conn.cursor() as cursor:
                # Prepare distribution data (sample 100 points for visualization)
                distribution_sample = np.percentile(
                    output.eal_distribution,
                    np.linspace(0, 100, 100)
                ).tolist()
                
                cursor.execute("""
                    INSERT INTO risk_analysis (
                        vuln_id, asset_id,
                        threat_event_frequency, vulnerability,
                        contact_frequency, probability_of_action,
                        primary_loss, secondary_loss,
                        eal_min, eal_mode, eal_max, eal_95th_percentile,
                        simulation_runs, raw_simulation_data
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                    )
                """, (
                    vuln_id, asset_id,
                    Json({
                        'min': inputs.contact_frequency_min,
                        'mode': inputs.contact_frequency_mode,
                        'max': inputs.contact_frequency_max
                    }),
                    Json({
                        'min': inputs.vulnerability_min,
                        'mode': inputs.vulnerability_mode,
                        'max': inputs.vulnerability_max
                    }),
                    Json({
                        'min': inputs.contact_frequency_min,
                        'mode': inputs.contact_frequency_mode,
                        'max': inputs.contact_frequency_max
                    }),
                    Json({
                        'min': inputs.probability_of_action_min,
                        'mode': inputs.probability_of_action_mode,
                        'max': inputs.probability_of_action_max
                    }),
                    Json({
                        'min': inputs.primary_loss_min,
                        'mode': inputs.primary_loss_mode,
                        'max': inputs.primary_loss_max
                    }),
                    Json({
                        'min': inputs.secondary_loss_min,
                        'mode': inputs.secondary_loss_mode,
                        'max': inputs.secondary_loss_max
                    }),
                    output.eal_min,
                    output.eal_mode,
                    output.eal_max,
                    output.eal_95th_percentile,
                    output.simulation_runs,
                    Json({'percentiles': distribution_sample})
                ))
                conn.commit()
                logger.info(f"Saved FAIR analysis for {vuln_id}")
        except Exception as e:
            logger.error(f"Failed to save FAIR analysis: {e}")
            conn.rollback()
        finally:
            conn.close()


def main():
    """Standalone testing"""
    from dotenv import load_dotenv
    import os
    load_dotenv()
    
    service = RiskAnalysisService(os.getenv('DATABASE_URL'))
    
    # Example analysis
    result = service.analyze_vulnerability(
        vuln_id='CVE-2024-0001',
        asset_id='asset-001',
        cvss_score=9.8,
        epss_score=0.85,
        asset_value=500000.0,
        asset_criticality='critical'
    )
    
    print(f"\n{'='*60}")
    print("FAIR RISK ANALYSIS RESULTS")
    print(f"{'='*60}")
    print(f"Expected Annual Loss (EAL):")
    print(f"  Minimum:        ${result.eal_min:,.2f}")
    print(f"  Most Likely:    ${result.eal_mode:,.2f}")
    print(f"  Mean:           ${result.eal_mean:,.2f}")
    print(f"  95th %ile:      ${result.eal_95th_percentile:,.2f}")
    print(f"  Maximum:        ${result.eal_max:,.2f}")
    print(f"\nInterpretation:")
    print(f"  We are 95% confident the annual loss will not exceed ${result.eal_95th_percentile:,.2f}")
    print(f"{'='*60}\n")


if __name__ == '__main__':
    main()
