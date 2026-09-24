"""
DATA LAYER: CVE/EPSS Ingestion Agent

Ingests vulnerability data from:
1. NVD API (https://services.nvd.nist.gov/rest/json/cves/2.0)
2. FIRST.org EPSS API (https://api.first.org/data/v1/epss)

API Access Requirements:
- NVD API: Free tier (5 requests/30s), API key recommended (50 requests/30s)
  Request key at: https://nvd.nist.gov/developers/request-an-api-key
- EPSS API: Free, no authentication, rate limit ~100 requests/minute

Author: Senior Cybersecurity Engineer
"""

import os
import time
import requests
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from loguru import logger
import psycopg2
from psycopg2.extras import Json, execute_values
from tenacity import retry, stop_after_attempt, wait_exponential


@dataclass
class VulnerabilityData:
    """Unified vulnerability schema"""
    asset_id: str
    vuln_id: str  # CVE-XXXX-XXXXX
    cvss_score: float
    epss_score: Optional[float]
    discovery_date: datetime
    severity: str
    description: str
    raw_data: dict


class NVDClient:
    """
    National Vulnerability Database API Client
    
    Rate Limits:
    - Without API Key: 5 requests per 30 seconds
    - With API Key: 50 requests per 30 seconds
    """
    
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.session = requests.Session()
        if api_key:
            self.session.headers.update({'apiKey': api_key})
        
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=60),
        reraise=True
    )
    def fetch_recent_cves(
        self, 
        days_back: int = 7,
        results_per_page: int = 2000
    ) -> List[Dict]:
        """
        Fetch CVEs published in the last N days.
        
        Args:
            days_back: Number of days to look back
            results_per_page: Max results per request (2000 is API max)
            
        Returns:
            List of CVE records
        """
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days_back)
        
        params = {
            'pubStartDate': start_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
            'pubEndDate': end_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
            'resultsPerPage': results_per_page,
            'startIndex': 0
        }
        
        all_cves = []
        
        while True:
            logger.info(f"Fetching CVEs from NVD (startIndex: {params['startIndex']})")
            
            response = self.session.get(self.BASE_URL, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])
            all_cves.extend(vulnerabilities)
            
            total_results = data.get('totalResults', 0)
            fetched = params['startIndex'] + len(vulnerabilities)
            
            logger.info(f"Fetched {fetched}/{total_results} CVEs")
            
            if fetched >= total_results:
                break
                
            params['startIndex'] = fetched
            
            # Rate limiting: sleep 6 seconds (safe for both tiers)
            time.sleep(6)
        
        return all_cves
    
    @staticmethod
    def parse_cve(cve_item: Dict) -> Optional[Dict]:
        """
        Extract relevant fields from NVD CVE JSON.
        
        Returns:
            Parsed CVE dict or None if invalid
        """
        try:
            cve = cve_item.get('cve', {})
            cve_id = cve.get('id')
            
            if not cve_id:
                return None
            
            # Extract CVSS score (prefer v3.1, fallback to v3.0, v2)
            cvss_score = 0.0
            metrics = cve.get('metrics', {})
            
            if 'cvssMetricV31' in metrics:
                cvss_score = metrics['cvssMetricV31'][0]['cvssData']['baseScore']
            elif 'cvssMetricV30' in metrics:
                cvss_score = metrics['cvssMetricV30'][0]['cvssData']['baseScore']
            elif 'cvssMetricV2' in metrics:
                cvss_score = metrics['cvssMetricV2'][0]['cvssData']['baseScore']
            
            # Determine severity
            if cvss_score >= 9.0:
                severity = 'critical'
            elif cvss_score >= 7.0:
                severity = 'high'
            elif cvss_score >= 4.0:
                severity = 'medium'
            else:
                severity = 'low'
            
            # Extract description
            descriptions = cve.get('descriptions', [])
            description = next(
                (d['value'] for d in descriptions if d['lang'] == 'en'),
                'No description available'
            )
            
            # Published date
            published = cve.get('published', datetime.utcnow().isoformat())
            
            return {
                'vuln_id': cve_id,
                'cvss_score': cvss_score,
                'severity': severity,
                'description': description,
                'published_date': published,
                'raw_data': cve_item
            }
            
        except Exception as e:
            logger.error(f"Failed to parse CVE: {e}")
            return None


class EPSSClient:
    """
    FIRST.org Exploit Prediction Scoring System API Client
    
    Rate Limits: ~100 requests/minute (undocumented, conservative estimate)
    """
    
    BASE_URL = "https://api.first.org/data/v1/epss"
    
    def __init__(self):
        self.session = requests.Session()
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        reraise=True
    )
    def get_epss_scores(self, cve_ids: List[str]) -> Dict[str, float]:
        """
        Fetch EPSS scores for a list of CVE IDs.
        
        EPSS score represents the probability (0-1) that a vulnerability
        will be exploited in the wild in the next 30 days.
        
        Args:
            cve_ids: List of CVE identifiers
            
        Returns:
            Dict mapping CVE ID to EPSS score
        """
        if not cve_ids:
            return {}
        
        # EPSS API accepts comma-separated CVE IDs
        # Batch in groups of 100 to avoid URL length limits
        batch_size = 100
        epss_map = {}
        
        for i in range(0, len(cve_ids), batch_size):
            batch = cve_ids[i:i + batch_size]
            cve_param = ','.join(batch)
            
            logger.info(f"Fetching EPSS scores for {len(batch)} CVEs")
            
            params = {'cve': cve_param}
            response = self.session.get(self.BASE_URL, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            for entry in data.get('data', []):
                cve_id = entry.get('cve')
                epss_score = float(entry.get('epss', 0.0))
                epss_map[cve_id] = epss_score
            
            # Rate limiting
            time.sleep(0.6)  # ~100 req/min
        
        return epss_map


class DataIngestionAgent:
    """
    Orchestrates CVE/EPSS data ingestion and normalization.
    """
    
    def __init__(self, database_url: str, nvd_api_key: Optional[str] = None):
        self.database_url = database_url
        self.nvd_client = NVDClient(api_key=nvd_api_key)
        self.epss_client = EPSSClient()
        
    def connect_db(self):
        """Establish database connection"""
        return psycopg2.connect(self.database_url)
    
    def ingest_vulnerabilities(
        self,
        asset_mapping: Dict[str, List[str]],  # {asset_id: [cve_ids]}
        days_back: int = 7
    ) -> Tuple[int, int]:
        """
        Main ingestion pipeline.
        
        Args:
            asset_mapping: Maps asset IDs to CVE IDs they're vulnerable to
            days_back: How many days of CVEs to fetch from NVD
            
        Returns:
            (successful_inserts, failed_inserts)
        """
        logger.info(f"Starting data ingestion (lookback: {days_back} days)")
        
        # Step 1: Fetch recent CVEs from NVD
        logger.info("Fetching CVEs from NVD...")
        nvd_cves = self.nvd_client.fetch_recent_cves(days_back=days_back)
        logger.info(f"Retrieved {len(nvd_cves)} CVEs from NVD")
        
        # Step 2: Parse and normalize CVE data
        parsed_cves = {}
        for cve_item in nvd_cves:
            parsed = self.nvd_client.parse_cve(cve_item)
            if parsed:
                parsed_cves[parsed['vuln_id']] = parsed
        
        logger.info(f"Parsed {len(parsed_cves)} valid CVEs")
        
        # Step 3: Fetch EPSS scores
        cve_ids = list(parsed_cves.keys())
        logger.info(f"Fetching EPSS scores for {len(cve_ids)} CVEs...")
        epss_scores = self.epss_client.get_epss_scores(cve_ids)
        logger.info(f"Retrieved {len(epss_scores)} EPSS scores")
        
        # Step 4: Merge data and prepare for database insert
        vulnerabilities_to_insert = []
        
        for asset_id, asset_cves in asset_mapping.items():
            for cve_id in asset_cves:
                if cve_id not in parsed_cves:
                    logger.warning(f"CVE {cve_id} not found in NVD data")
                    continue
                
                cve_data = parsed_cves[cve_id]
                
                vuln_record = {
                    'asset_id': asset_id,
                    'vuln_id': cve_id,
                    'cvss_score': cve_data['cvss_score'],
                    'epss_score': epss_scores.get(cve_id),
                    'discovery_date': cve_data['published_date'],
                    'status': 'open',
                    'severity': cve_data['severity'],
                    'description': cve_data['description'],
                    'raw_data': Json(cve_data['raw_data'])
                }
                
                vulnerabilities_to_insert.append(vuln_record)
        
        # Step 5: Bulk insert into PostgreSQL
        logger.info(f"Inserting {len(vulnerabilities_to_insert)} vulnerability records")
        
        success_count = 0
        failed_count = 0
        
        conn = self.connect_db()
        try:
            with conn.cursor() as cursor:
                insert_query = """
                    INSERT INTO vulnerabilities (
                        asset_id, vuln_id, cvss_score, epss_score, 
                        discovery_date, status, severity, description, raw_data
                    ) VALUES %s
                    ON CONFLICT (vuln_id, asset_id) 
                    DO UPDATE SET 
                        cvss_score = EXCLUDED.cvss_score,
                        epss_score = EXCLUDED.epss_score,
                        updated_at = NOW()
                """
                
                values = [
                    (
                        v['asset_id'], v['vuln_id'], v['cvss_score'], v['epss_score'],
                        v['discovery_date'], v['status'], v['severity'], 
                        v['description'], v['raw_data']
                    )
                    for v in vulnerabilities_to_insert
                ]
                
                execute_values(cursor, insert_query, values)
                conn.commit()
                success_count = len(values)
                
        except Exception as e:
            logger.error(f"Database insertion failed: {e}")
            conn.rollback()
            failed_count = len(vulnerabilities_to_insert)
        finally:
            conn.close()
        
        logger.info(f"Ingestion complete: {success_count} success, {failed_count} failed")
        return success_count, failed_count


def main():
    """Standalone execution for testing"""
    from dotenv import load_dotenv
    load_dotenv()
    
    database_url = os.getenv('DATABASE_URL')
    nvd_api_key = os.getenv('NVD_API_KEY')  # Optional
    
    agent = DataIngestionAgent(database_url, nvd_api_key)
    
    # Example: Map sample assets to recent CVEs
    # In production, this would come from asset inventory
    sample_assets = {
        'asset-001': ['CVE-2024-0001', 'CVE-2024-0002'],
        'asset-002': ['CVE-2024-0003']
    }
    
    agent.ingest_vulnerabilities(sample_assets, days_back=30)


if __name__ == '__main__':
    main()
