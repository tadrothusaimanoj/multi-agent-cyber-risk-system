import urllib.request
import json
import logging

logger = logging.getLogger(__name__)

# Simple in-memory cache to avoid rate-limiting during testing/seeding
_threat_cache = {}

def fetch_live_threat_intel(cve_id: str) -> dict:
    """
    Fetches real-world threat intelligence for a given CVE.
    Pulls CVSS from NIST NVD and EPSS from FIRST.org.
    """
    if not cve_id or not cve_id.startswith("CVE-"):
        return None

    if cve_id in _threat_cache:
        return _threat_cache[cve_id]

    result = {
        "cvss_score": None,
        "epss_score": None,
        "severity": None
    }

    # 1. Fetch EPSS from FIRST.org
    try:
        req = urllib.request.Request(f'https://api.first.org/data/v1/epss?cve={cve_id}', headers={'User-Agent': 'CyberGuard-AI-Bot'})
        res = urllib.request.urlopen(req, timeout=5)
        data = json.loads(res.read())
        if data.get('data') and len(data['data']) > 0:
            result['epss_score'] = float(data['data'][0]['epss'])
    except Exception as e:
        logger.warning(f"Failed to fetch EPSS for {cve_id}: {e}")

    # 2. Fetch CVSS from NIST NVD
    try:
        req = urllib.request.Request(f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}', headers={'User-Agent': 'CyberGuard-AI-Bot'})
        res = urllib.request.urlopen(req, timeout=5)
        data = json.loads(res.read())
        
        if data.get('vulnerabilities') and len(data['vulnerabilities']) > 0:
            metrics = data['vulnerabilities'][0]['cve'].get('metrics', {})
            
            # Prefer CVSS 3.1, fallback to 3.0 or 2.0
            if 'cvssMetricV31' in metrics:
                cvss_data = metrics['cvssMetricV31'][0]['cvssData']
            elif 'cvssMetricV30' in metrics:
                cvss_data = metrics['cvssMetricV30'][0]['cvssData']
            elif 'cvssMetricV2' in metrics:
                cvss_data = metrics['cvssMetricV2'][0]['cvssData']
            else:
                cvss_data = None
                
            if cvss_data:
                result['cvss_score'] = float(cvss_data.get('baseScore', 0.0))
                severity_raw = cvss_data.get('baseSeverity', 'MEDIUM')
                result['severity'] = severity_raw.lower()
                
    except Exception as e:
        logger.warning(f"Failed to fetch CVSS for {cve_id}: {e}")

    # Cache and return
    # Only cache if we got at least one score to prevent caching failures forever
    if result['cvss_score'] is not None or result['epss_score'] is not None:
        _threat_cache[cve_id] = result
        
    return result
