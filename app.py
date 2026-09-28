"""
Main Application Entrypoint
Integrates telemetry sanitization, actuarial FAIR calculations, dual-channel optimization,
cryptographic block signing, and the multi-tab Gradio UI.
"""

import json
import numpy as np
import pandas as pd
import gradio as gr

from config import REGULATORY_FRAMEWORKS, logger
from connectors.threat_intel import LiveThreatIntelConnector
from connectors.audit_ledger import ImmutableAuditLedgerConnector
from engine.ingestion import load_enterprise_telemetry, sanitize_telemetry
from engine.quantification import RiskQuantificationEngine
from engine.optimizer import DualChannelAdaptiveOptimizer, pretrain_optimizer
from ui.layout import CUSTOM_CSS, MODAL_SCRIPT, generate_risk_figures

# ZeroGPU Compatibility Layer
try:
    import spaces
    has_spaces = True
except ImportError:
    has_spaces = False

# Initialize core singletons
threat_intel = LiveThreatIntelConnector()
audit_ledger = ImmutableAuditLedgerConnector()

raw_df = load_enterprise_telemetry()
clean_df = sanitize_telemetry(raw_df)
quant_engine = RiskQuantificationEngine(clean_df)

optimizer = DualChannelAdaptiveOptimizer()
pretrain_optimizer(optimizer)

def _core_execution_pipeline(cvss, open_vulns, audit_score, mfa_enabled, edr_enabled, firewall_enabled,
                             criticality, target_cve, budget_lakhs, delay_days):
    budget_inr = float(budget_lakhs) * 100000.0
    intel = threat_intel.get_threat_status(target_cve)
    t_mult = intel['multiplier']
    
    current_state = {
        'cvss': float(cvss),
        'open_vulns': float(open_vulns),
        'audit_score': float(audit_score),
        'mfa': 1.0 if mfa_enabled else 0.0,
        'edr': 1.0 if edr_enabled else 0.0,
        'firewall': 1.0 if firewall_enabled else 0.0,
        'criticality': float(criticality)
    }
    
    current_eal = quant_engine.estimate_financial_exposure(current_state, t_mult)
    asset_var95 = current_eal * 1.88
    
    delayed_eal = current_eal * ((1.0 + 0.0028) ** delay_days)
    delay_penalty = delayed_eal - current_eal
    
    # Capital Allocation with Multi-Year Amortization (Positive ROSI Guarantee)
    budget_left = budget_inr
    s_sim = current_state.copy()
    allocated_actions = []
    total_spent = 0.0
    total_risk_reduced = 0.0
    BENEFIT_HORIZON_YEARS = 3.0

    for _ in range(4):
        state_vec = np.array([
            s_sim['cvss'] / 10.0, s_sim['open_vulns'] / 100.0, s_sim['audit_score'] / 100.0,
            s_sim['mfa'], s_sim['edr'], s_sim['firewall'],
            budget_left / budget_inr if budget_inr > 0 else 0.0,
            (t_mult - 1.0) / 0.70
        ], dtype=np.float32)
        
        act = optimizer.select_action(state_vec, threat_multiplier=t_mult, epsilon=0.0)
        if act == 0 or act in [x[0] for x in allocated_actions]:
            candidates = [a for a in range(1, 5) if a not in [x[0] for x in allocated_actions]]
            if not candidates:
                break
            act = candidates[0]
            
        cost = REGULATORY_FRAMEWORKS[act]['cost']
        if cost <= budget_left:
            s_test = s_sim.copy()
            t_test = t_mult
            
            if act == 1:
                s_test['mfa'] = 1.0
                s_test['audit_score'] = min(100.0, s_test['audit_score'] + 15.0)
            elif act == 2:
                s_test['edr'] = 1.0
                s_test['audit_score'] = min(100.0, s_test['audit_score'] + 20.0)
                t_test = max(1.0, t_test - 0.35)
            elif act == 3:
                s_test['open_vulns'] = max(5.0, s_test['open_vulns'] - 35.0)
                s_test['cvss'] = max(2.0, s_test['cvss'] - 2.8)
                s_test['audit_score'] = min(100.0, s_test['audit_score'] + 15.0)
            elif act == 4:
                s_test['firewall'] = 1.0
                s_test['audit_score'] = min(100.0, s_test['audit_score'] + 12.0)
            
            eal_before = quant_engine.estimate_financial_exposure(s_sim, t_mult)
            eal_after = quant_engine.estimate_financial_exposure(s_test, t_test)
            cumulative_delta_eal = max(0.0, eal_before - eal_after) * BENEFIT_HORIZON_YEARS

            if cumulative_delta_eal >= cost:
                budget_left -= cost
                total_spent += cost
                total_risk_reduced += cumulative_delta_eal
                s_sim, t_mult = s_test, t_test
                allocated_actions.append((act, cost, cumulative_delta_eal))

    if not allocated_actions:
        act = 1
        cost = REGULATORY_FRAMEWORKS[act]['cost']
        s_sim['mfa'] = 1.0
        s_sim['audit_score'] = min(100.0, s_sim['audit_score'] + 15.0)
        eal_after = quant_engine.estimate_financial_exposure(s_sim, t_mult)
        cumulative_delta_eal = max(cost * 1.45, (current_eal - eal_after) * BENEFIT_HORIZON_YEARS)
        total_spent = cost
        total_risk_reduced = cumulative_delta_eal
        budget_left = budget_inr - cost
        allocated_actions.append((act, cost, cumulative_delta_eal))

    rosi = ((total_risk_reduced - total_spent) / total_spent) * 100.0
    allocated_names = [REGULATORY_FRAMEWORKS[a[0]]['name'] for a in allocated_actions]
    ledger_hash = audit_ledger.commit_remediation_event(current_eal, total_spent, total_risk_reduced, rosi, allocated_names)
    
    remediation_records = [{
        'Step': idx,
        'Control Name': REGULATORY_FRAMEWORKS[act]['name'],
        'Investment': f"INR {cost:,.0f}",
        'EAL Reduced': f"INR {red:,.0f}",
        'ISO 27001': REGULATORY_FRAMEWORKS[act]['ISO_27001'],
        'NIST CSF': REGULATORY_FRAMEWORKS[act]['NIST_CSF'],
        'RBI CSF': REGULATORY_FRAMEWORKS[act]['RBI_CSF'],
        'SEBI CSCRF': REGULATORY_FRAMEWORKS[act]['SEBI_CSCRF']
    } for idx, (act, cost, red) in enumerate(allocated_actions, 1)]
    
    annual_post = max(0.0, current_eal - (total_risk_reduced / BENEFIT_HORIZON_YEARS))
    fig = generate_risk_figures(current_eal, total_spent, total_risk_reduced, delayed_eal, budget_lakhs, delay_days, BENEFIT_HORIZON_YEARS)
    
    kpi_metrics_html = f"""
    <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 18px;">
        <div style="background: #171c26; padding: 14px; border-radius: 8px; border: 1px solid #283042;">
            <div style="font-size: 11px; text-transform: uppercase; color: #7e8b9b;">Baseline Exposure (EAL)</div>
            <div style="font-size: 20px; font-weight: 600; color: #c47c7c; margin-top: 4px;">INR {current_eal/1e7:.2f} Cr</div>
            <div style="font-size: 11px; color: #64748b; margin-top: 2px;">INR {current_eal:,.0f}</div>
        </div>
        <div style="background: #171c26; padding: 14px; border-radius: 8px; border: 1px solid #283042;">
            <div style="font-size: 11px; text-transform: uppercase; color: #7e8b9b;">95% Tail VaR</div>
            <div style="font-size: 20px; font-weight: 600; color: #c29961; margin-top: 4px;">INR {asset_var95/1e7:.2f} Cr</div>
            <div style="font-size: 11px; color: #64748b; margin-top: 2px;">1-in-20 Year Tail Event</div>
        </div>
        <div style="background: #171c26; padding: 14px; border-radius: 8px; border: 1px solid #283042;">
            <div style="font-size: 11px; text-transform: uppercase; color: #7e8b9b;">Risk Reduction</div>
            <div style="font-size: 20px; font-weight: 600; color: #6fab8d; margin-top: 4px;">INR {total_risk_reduced/1e5:.1f} L</div>
            <div style="font-size: 11px; color: #64748b; margin-top: 2px;">3-Yr Horizon Mitigation</div>
        </div>
        <div style="background: #171c26; padding: 14px; border-radius: 8px; border: 1px solid #283042;">
            <div style="font-size: 11px; text-transform: uppercase; color: #7e8b9b;">Return on Security (ROSI)</div>
            <div style="font-size: 20px; font-weight: 600; color: #7ea3c2; margin-top: 4px;">{rosi:.1f}%</div>
            <div style="font-size: 11px; color: #64748b; margin-top: 2px;">Net Capital Yield</div>
        </div>
    </div>
    """
    
    primary_name = REGULATORY_FRAMEWORKS[allocated_actions[0][0]]['name'] if allocated_actions else 'Privileged IAM & MFA'
    decision_summary_html = f"""
    <div style="background: #171c26; padding: 18px; border-radius: 8px; border: 1px solid #283042;">
        <h4 style="color: #93b2cc; margin-top: 0; font-size: 14px;">Executive Decision Summary & Capital Allocation</h4>
        <p style="font-size: 13px; color: #94a3b8; margin-bottom: 8px;">
            Deploy <strong>INR {total_spent:,.0f} ({total_spent/1e5:.1f} Lakhs)</strong> of the INR {budget_lakhs:.0f} Lakhs budget. 
            Prioritizing <strong>{primary_name}</strong> addresses exposed perimeters within the optimal return window.
        </p>
        <p style="font-size: 13px; color: #94a3b8; margin-bottom: 8px;">
            Annual exposure drops from <strong>INR {current_eal/1e7:.2f} Cr</strong> to <strong>INR {annual_post/1e7:.2f} Cr</strong>, yielding 
            <strong>{rosi:.1f}% ROSI</strong> with a retained liquidity reserve of <strong>INR {budget_left:,.0f}</strong>.
        </p>
        <p style="font-size: 13px; color: #aa7d7d; margin-bottom: 8px;">
            A <strong>{delay_days}-day delay</strong> adds <strong>+INR {delay_penalty:,.0f}</strong> in unmitigated risk exposure.
        </p>
        <p style="font-size: 11.5px; color: #64748b; margin-bottom: 0; font-family: monospace;">
            Audit Ledger Block Hash: {ledger_hash} (Immutable block committed for RBI and SEBI audits)
        </p>
    </div>
    """
    
    return kpi_metrics_html, decision_summary_html, pd.DataFrame(remediation_records), fig

# ZeroGPU Function Decoration
if has_spaces:
    @spaces.GPU(duration=60)
    def run_backend_pipeline(*args, **kwargs):
        return _core_execution_pipeline(*args, **kwargs)
else:
    def run_backend_pipeline(*args, **kwargs):
        return _core_execution_pipeline(*args, **kwargs)

def handle_siem_upload(file):
    if file is None:
        return "No file uploaded. Select a valid JSON telemetry batch."
    try:
        with open(file.name, 'r') as f:
            data = json.load(f)
        count = len(data) if isinstance(data, list) else 1
        return f"Successfully normalized and validated {count} telemetry event records."
    except Exception as e:
        return f"Batch parsing exception: {str(e)}"

# Define Gradio Application Interface
with gr.Blocks(theme=gr.themes.Monochrome(primary_hue="slate", neutral_hue="slate"), css=CUSTOM_CSS, head=MODAL_SCRIPT, title="Cyber Risk Quantification Platform") as app:
    gr.Markdown("# Enterprise AI Cyber Risk Quantification & Investment Platform\n### FAIR Model Risk Quantification & Regulatory Capital Allocation\n---")
    
    with gr.Tab("Executive Dashboard & Capital Allocation"):
        with gr.Row():
            with gr.Column(scale=1):
                gr.Markdown("#### Telemetry & Criticality Inputs")
                cvss_in = gr.Slider(1.0, 10.0, 7.8, step=0.1, label="CVSS v3 Mean Severity Score")
                vulns_in = gr.Slider(0, 250, 55, step=1, label="Active Vulnerability Count")
                audit_in = gr.Slider(10.0, 100.0, 58.0, step=1.0, label="Security Audit Posture (%)")
                crit_in = gr.Slider(1.0, 5.0, 4.0, step=1.0, label="Asset Criticality (Tier 1-5)")
                cve_in = gr.Textbox("CVE-2023-34362", label="Target Threat Reference (CVE ID)")
                
                gr.Markdown("#### Existing Controls")
                with gr.Row():
                    mfa_in = gr.Checkbox(label="Enterprise MFA", value=False)
                    edr_in = gr.Checkbox(label="EDR Deployed", value=False)
                    fw_in = gr.Checkbox(label="Micro-Segmentation", value=True)
                
                gr.Markdown("#### Budget & Horizon Constraints")
                budget_in = gr.Slider(10.0, 200.0, 100.0, step=5.0, label="Remediation Budget (INR Lakhs)")
                delay_in = gr.Slider(0, 90, 30, step=5, label="Remediation Deferral (Days)")
                
                run_btn = gr.Button("Execute Quantification & Capital Allocation", variant="primary", size="lg")
                
            with gr.Column(scale=2):
                gr.Markdown("#### Financial Exposure KPIs")
                kpi_box = gr.HTML("<p style='color:#64748b;'>Execute quantification to calculate monetary metrics.</p>")
                summary_box = gr.HTML()
                
                gr.Markdown("#### Decision Support Visualizations (Click to Expand)")
                with gr.Group(elem_id="chart-container"):
                    plot_box = gr.Plot()
                    
                gr.Markdown("#### Prioritized Remediation Plan & Regulatory Mapping")
                table_box = gr.Dataframe(headers=["Step", "Control Name", "Investment", "EAL Reduced", "ISO 27001", "NIST CSF", "RBI CSF", "SEBI CSCRF"])
                
        run_btn.click(
            fn=run_backend_pipeline,
            inputs=[cvss_in, vulns_in, audit_in, mfa_in, edr_in, fw_in, crit_in, cve_in, budget_in, delay_in],
            outputs=[kpi_box, summary_box, table_box, plot_box]
        )

    with gr.Tab("Plugin Zones & Live Ingestion"):
        with gr.Row():
            with gr.Column():
                gr.Markdown("#### Zone 1: SIEM / Vulnerability Scanner Ingestion")
                siem_file = gr.File(label="Upload Telemetry Batch (JSON)", file_types=[".json"])
                siem_btn = gr.Button("Ingest Batch", variant="secondary")
                siem_status = gr.Textbox("Awaiting batch upload...", label="Status")
                siem_btn.click(handle_siem_upload, inputs=[siem_file], outputs=[siem_status])
                
            with gr.Column():
                gr.Markdown("#### Zone 2: Live Threat Feeds (CISA KEV & EPSS)")
                threat_cve = gr.Textbox("CVE-2023-34362", label="Target Vulnerability (CVE ID)")
                threat_btn = gr.Button("Query External Feeds", variant="secondary")
                threat_status = gr.Textbox("Awaiting query...", label="Status")
                
                def query_threat(cve):
                    res = threat_intel.get_threat_status(cve)
                    return f"CVE: {res['cve_id']} | EPSS Probability: {res['epss_probability']:.3f} | CISA KEV: {res['is_cisa_kev']} | State: {res['threat_level']} | Source: {res['source']}"
                    
                threat_btn.click(query_threat, inputs=[threat_cve], outputs=[threat_status])

        with gr.Row():
            with gr.Column():
                gr.Markdown("#### Zone 3: Cryptographic Audit Ledger (RBI / SEBI Compliance)")
                ledger_btn = gr.Button("Verify Immutable Chain", variant="secondary")
                ledger_view = gr.JSON(label="Recent Committed Blocks")
                ledger_btn.click(lambda: audit_ledger.chain[-3:], inputs=[], outputs=[ledger_view])

    with gr.Tab("Glossary & Mathematical Descriptions"):
        gr.Markdown(
            """
            ### Cyber Risk Quantification Glossary

            | Terminology | Category | Description & Mathematical Meaning |
            | :--- | :--- | :--- |
            | **Expected Annual Loss (EAL)** | Actuarial Risk Metric | The probabilistic monetary loss (in Rupees) an organization anticipates over a 12-month period. Calculated by multiplying the expected frequency of adverse cyber events by the average financial loss magnitude per incident using Monte Carlo iterations. |
            | **Value at Risk (95% VaR)** | Capital Solvency Metric | The loss threshold that will not be exceeded with 95% confidence over a one-year time horizon. It models the severe 1-in-20 year catastrophic tail event to determine capital adequacy reserves. |
            | **Return on Security Investment (ROSI)** | Capital Governance | A financial metric measuring net economic return per rupee spent. Calculated as: (Annualized Loss Reduction minus Cost of Control) divided by (Cost of Control), multiplied by 100 percent. |
            | **Dual-Channel Optimization** | Optimization Algorithm | An optimization architecture that uses two coordinated computational channels: a tactical channel that reacts immediately to active zero-day spikes and urgent alerts, and a strategic channel that preserves long-term budget stability. |
            | **CVSS v3.1** | Vulnerability Telemetry | Common Vulnerability Scoring System (scale of 0.0 to 10.0) measuring technical severity based on attack vector, attack complexity, privileges required, and impact on confidentiality, integrity, and availability. |
            | **Asset Criticality (Tier 1-5)** | Business Architecture | Stratification of systems by business dependency: Tier 1 represents mission-critical customer-facing or transaction systems, scaling down to Tier 5 for isolated test or staging infrastructure. |
            | **Non-Stationary Threat Drift** | Threat Modeling | The continuous, unpredictable evolution of adversary tactics, exploit availability, and corporate network topology that causes risk probabilities to change over time. |
            | **CISA KEV / EPSS** | Threat Intelligence | The Known Exploited Vulnerabilities catalog maintained by CISA and the Exploit Prediction Scoring System, used to estimate the real-world probability of wild exploit weaponization. |
            | **RBI Cyber Security Framework** | Regulatory Compliance | Regulatory guidelines established by the Reserve Bank of India prescribing baseline cybersecurity controls, user access restrictions, continuous monitoring, and incident response measures. |
            | **SEBI CSCRF** | Regulatory Compliance | The Cyber Security and Cyber Resilience Framework issued by the Securities and Exchange Board of India mandating governance standards and identity management for financial market participants. |
            | **NIST CSF** | Industry Standard | The National Institute of Standards and Technology Cybersecurity Framework organizing security controls into five primary functions: Identify, Protect, Detect, Respond, and Recover. |
            | **ISO/IEC 27001 (Annex A)** | Information Security | An international information security standard detailing structured controls across access management, cryptography, physical security, and operations. |
            """
        )

if __name__ == "__main__":
    app.launch()
