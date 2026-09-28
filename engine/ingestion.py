"""
Telemetry Ingestion & Data Sanitization (Plugin Zone 1)
Parses external SIEM batches and prepares raw input matrices
with robust edge-case clipping and default baseline synthesis.
"""

import glob
import numpy as np
import pandas as pd
from config import USD_TO_INR, logger

def load_enterprise_telemetry() -> pd.DataFrame:
    """Discovers local CSV datasets or synthesizes an enterprise baseline."""
    candidates = []
    for path in ["**/*Cyber*.csv", "**/*.csv"]:
        candidates.extend(glob.glob(path, recursive=True))
        if candidates:
            break
            
    if not candidates:
        logger.warning("No local CSV located; generating enterprise synthetic baseline...")
        return pd.DataFrame({
            'Financial_Loss_USD': np.random.lognormal(10.0, 1.2, 5000),
            'Recovery_Cost_USD': np.random.lognormal(9.0, 1.0, 5000),
            'CVSS_Score': np.random.uniform(5.0, 10.0, 5000),
            'Open_Vulnerabilities': np.random.randint(10, 120, 5000),
            'Security_Audit_Score': np.random.uniform(30.0, 90.0, 5000),
            'MFA': np.random.choice([0, 1], 5000),
            'EDR': np.random.choice([0, 1], 5000),
            'Firewall': np.random.choice([0, 1], 5000),
            'Asset_Criticality': np.random.uniform(1.0, 5.0, 5000)
        })
        
    return pd.read_csv(candidates[0])

def sanitize_telemetry(df: pd.DataFrame) -> pd.DataFrame:
    """Cleans, normalizes, and casts raw telemetry metrics into INR losses."""
    df = df.copy()
    loss_cols = [c for c in df.columns if any(k in c.lower() for k in ['financial_loss', 'loss_usd', 'total_loss'])]
    recov_cols = [c for c in df.columns if any(k in c.lower() for k in ['recovery_cost', 'incident_cost', 'remediation_cost'])]
    
    primary_loss = pd.to_numeric(df[loss_cols[0]], errors='coerce').fillna(0.0) if loss_cols else pd.Series(np.random.lognormal(10.2, 1.2, len(df)))
    recovery_loss = pd.to_numeric(df[recov_cols[0]], errors='coerce').fillna(0.0) if recov_cols else primary_loss * 0.28

    total_loss_inr = (primary_loss + recovery_loss) * USD_TO_INR
    total_loss_inr = np.where(total_loss_inr <= 0.0, np.nan, total_loss_inr)
    
    median_val = np.nanmedian(total_loss_inr)
    df['Total_Loss_INR'] = np.nan_to_num(total_loss_inr, nan=3000000.0 if np.isnan(median_val) else median_val)
    
    feature_schema = {
        'CVSS_Score': ('cvss', 7.2, 0.0, 10.0),
        'Open_Vulnerabilities': ('vuln', 45.0, 0.0, 500.0),
        'Security_Audit_Score': ('audit', 58.0, 0.0, 100.0),
        'MFA': ('mfa', 0.0, 0.0, 1.0),
        'EDR': ('edr', 0.0, 0.0, 1.0),
        'Firewall': ('firewall', 1.0, 0.0, 1.0),
        'Asset_Criticality': ('asset', 3.5, 1.0, 5.0)
    }
    
    bool_map = {
        'yes': 1.0, 'no': 0.0, 'true': 1.0, 'false': 0.0,
        'enabled': 1.0, 'disabled': 0.0, 'active': 1.0, 'inactive': 0.0, '1': 1.0, '0': 0.0
    }

    clean_data = pd.DataFrame(index=df.index)
    for col, (kw, default, min_v, max_v) in feature_schema.items():
        matched = [c for c in df.columns if kw in c.lower()]
        if matched:
            series = df[matched[0]]
            if series.dtype == object:
                series = series.astype(str).str.strip().str.lower().map(bool_map)
            series = pd.to_numeric(series, errors='coerce').fillna(default)
            clean_data[col] = np.clip(series, min_v, max_v)
        else:
            clean_data[col] = default

    clean_data['Total_Loss_INR'] = df['Total_Loss_INR'].astype(float)
    return clean_data[np.isfinite(clean_data).all(axis=1)].copy()
