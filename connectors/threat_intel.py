"""
Threat Intelligence Connector (Plugin Zone 2)
Interrogates FIRST.org EPSS REST API and CISA KEV Catalog
to dynamically compute active threat exploitation multipliers.
"""

import time
import json
import urllib.request
from config import logger

class LiveThreatIntelConnector:
    def __init__(self, cache_ttl_seconds=3600):
        self.epss_api_url = "https://api.first.org/data/v1/epss"
        self.cisa_kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        self.cache_ttl = cache_ttl_seconds
        self._cisa_kev_cache = set()
        self._cisa_last_updated = 0
        self._epss_cache = {}

    def refresh_cisa_kev_catalog(self):
        """Fetches and caches active weaponized vulnerabilities from CISA."""
        now = time.time()
        if now - self._cisa_last_updated < self.cache_ttl and self._cisa_kev_cache:
            return
        try:
            req = urllib.request.Request(self.cisa_kev_url, headers={'User-Agent': 'CyberRiskPlatform/2.0'})
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                vulns = data.get('vulnerabilities', [])
                self._cisa_kev_cache = {v['cveID'] for v in vulns if 'cveID' in v}
                self._cisa_last_updated = now
        except Exception as e:
            logger.warning(f"Failed to fetch live CISA KEV: {e}. Falling back to default signatures.")
            self._cisa_kev_cache = {"CVE-2023-34362", "CVE-2021-44228", "CVE-2023-23397", "CVE-2021-34527"}

    def get_threat_status(self, cve_id: str) -> dict:
        """Calculates dynamic threat severity and EPSS probability for an input CVE."""
        cve_clean = cve_id.strip().upper()
        self.refresh_cisa_kev_catalog()
        is_kev = cve_clean in self._cisa_kev_cache
        
        epss_score = self._epss_cache.get(cve_clean)
        source = "Local Memory Cache"
        if epss_score is None:
            try:
                url = f"{self.epss_api_url}?cve={cve_clean}"
                req = urllib.request.Request(url, headers={'User-Agent': 'CyberRiskPlatform/2.0'})
                with urllib.request.urlopen(req, timeout=3) as resp:
                    payload = json.loads(resp.read().decode('utf-8'))
                    if 'data' in payload and len(payload['data']) > 0:
                        epss_score = float(payload['data'][0].get('epss', 0.15))
                        self._epss_cache[cve_clean] = epss_score
                        source = "Live FIRST.org EPSS API"
            except Exception:
                epss_score = 0.842 if is_kev else 0.12
                source = "Simulated Fallback Feed"

        if is_kev:
            multiplier = 1.70
            level = "Critical (CISA KEV Weaponized Active Threat)"
        elif epss_score > 0.50:
            multiplier = 1.35
            level = "Moderate (High Probability Exploitation Window)"
        else:
            multiplier = 1.00
            level = "Low (Baseline Surveillance)"

        return {
            "cve_id": cve_clean,
            "is_cisa_kev": is_kev,
            "epss_probability": epss_score,
            "multiplier": multiplier,
            "threat_level": level,
            "source": source
        }
