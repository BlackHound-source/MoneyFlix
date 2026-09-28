"""
Global Configuration & Regulatory Standards Mapping
Contains currency conversion baselines, random seeds, and compliance frameworks
for ISO 27001, NIST CSF, RBI CSF, and SEBI CSCRF.
"""

import sys
import logging
import warnings

# Suppress non-critical warnings
warnings.filterwarnings('ignore', category=UserWarning)
warnings.filterwarnings('ignore', category=FutureWarning)

RANDOM_SEED = 42
USD_TO_INR = 83.50

# Configure centralized structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("CyberRiskPlatform")

# Enterprise Regulatory Mapping Dictionary
REGULATORY_FRAMEWORKS = {
    1: {
        'name': 'Privileged IAM & Multi-Factor Authentication (MFA)',
        'cost': 1500000.0,  # INR 15 Lakhs
        'NIST_CSF': 'PR.AC-7 (Identity Verification & Authentication)',
        'ISO_27001': 'A.9.4.2 (Secure Log-on Procedures)',
        'CIS_Controls': 'CIS 6.3 (Require MFA for Privileged Access)',
        'RBI_CSF': 'Annex-1 Clause 2.1 (Multi-Factor Authentication Mandate)',
        'SEBI_CSCRF': 'Section 3.2.1 (Privileged Access & IAM Architecture)'
    },
    2: {
        'name': 'Endpoint Detection & Response (EDR / XDR Rollout)',
        'cost': 3500000.0,  # INR 35 Lakhs
        'NIST_CSF': 'DE.CM-4 (Malicious Code & Host Behavior Detection)',
        'ISO_27001': 'A.12.2.1 (Controls Against Malware)',
        'CIS_Controls': 'CIS 10.1 (Deploy Automated Anti-Malware Software)',
        'RBI_CSF': 'Annex-1 Clause 3.4 (Continuous Endpoint Telemetry)',
        'SEBI_CSCRF': 'Section 4.1 (EDR/SOC Real-Time Alert Telemetry)'
    },
    3: {
        'name': 'Targeted Vulnerability Patch Management Campaign',
        'cost': 2000000.0,  # INR 20 Lakhs
        'NIST_CSF': 'PR.IP-12 (Vulnerability Management & Remediation)',
        'ISO_27001': 'A.12.6.1 (Management of Technical Vulnerabilities)',
        'CIS_Controls': 'CIS 7.4 (Perform Automated Vulnerability Remediation)',
        'RBI_CSF': 'Annex-1 Clause 2.4 (Security Patch Deployment Timelines)',
        'SEBI_CSCRF': 'Section 3.4.2 (Critical & KEV Patching SLA < 15 Days)'
    },
    4: {
        'name': 'Zero-Trust Network Segmentation & Micro-Perimeter',
        'cost': 1000000.0,  # INR 10 Lakhs
        'NIST_CSF': 'PR.AC-5 (Network Access Protection & Segmentation)',
        'ISO_27001': 'A.13.1.1 (Network Controls and Perimeter Separation)',
        'CIS_Controls': 'CIS 12.2 (Secure Network Infrastructure & Architecture)',
        'RBI_CSF': 'Annex-1 Clause 1.2 (Perimeter Defense & Subnetting)',
        'SEBI_CSCRF': 'Section 3.1 (Isolation of DMZ & Internal Core Banking Zones)'
    }
}
