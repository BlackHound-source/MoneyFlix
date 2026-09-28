"""
UI Styling, Modal Viewport Scripting & Chart Builders
Constructs dark executive layouts, responsive modal viewers, and Matplotlib risk figures.
"""

import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

CUSTOM_CSS = """
body, .gradio-container {
    background-color: #0f1218 !important;
    color: #94a3b8 !important;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
}
.gradio-container h1, .gradio-container h2, .gradio-container h3, .gradio-container h4 {
    color: #cbd5e1 !important;
    font-weight: 600;
}
input, select, textarea, .gr-input, .gr-box {
    background-color: #171c26 !important;
    border-color: #283042 !important;
    color: #cbd5e1 !important;
}
.gr-button-primary {
    background: #2a394a !important;
    border: 1px solid #3d5167 !important;
    color: #dbe4ee !important;
}
.gr-button-primary:hover {
    background: #33465c !important;
}
.gr-button-secondary {
    background: #1e2430 !important;
    border: 1px solid #2d3748 !important;
    color: #94a3b8 !important;
}
table, th, td {
    border-color: #283042 !important;
}
th {
    background-color: #171c26 !important;
    color: #94a3b8 !important;
}
td {
    background-color: #11151c !important;
    color: #8a99ad !important;
}
#chart-container {
    cursor: zoom-in;
    transition: transform 0.15s ease, border-color 0.15s ease;
    border-radius: 8px;
    border: 1px solid #283042;
    padding: 6px;
    background: #171c26;
}
#chart-container:hover {
    border-color: #3d5167;
}
#fullscreen-modal {
    display: none;
    position: fixed;
    z-index: 99999;
    left: 0;
    top: 0;
    width: 100vw;
    height: 100vh;
    background-color: rgba(11, 15, 23, 0.95);
    backdrop-filter: blur(6px);
    justify-content: center;
    align-items: center;
    cursor: zoom-out;
}
#modal-content-container {
    width: 95vw;
    height: 90vh;
    display: flex;
    justify-content: center;
    align-items: center;
    background: #171c26;
    border: 1px solid #283042;
    border-radius: 12px;
    padding: 16px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.5);
}
#close-modal-btn {
    position: absolute;
    top: 24px;
    right: 36px;
    color: #94a3b8;
    font-size: 28px;
    cursor: pointer;
    background: #1f2533;
    border: 1px solid #334155;
    border-radius: 6px;
    width: 36px;
    height: 36px;
    display: flex;
    align-items: center;
    justify-content: center;
}
"""

MODAL_SCRIPT = """
<div id="fullscreen-modal" onclick="closeChartModal(event)">
    <div id="close-modal-btn" onclick="closeChartModal(event)">&times;</div>
    <div id="modal-content-container" onclick="event.stopPropagation()"></div>
</div>
<script>
function attachChartModalClick() {
    const chartWrapper = document.getElementById('chart-container');
    if (!chartWrapper) return;
    chartWrapper.onclick = function() {
        const modal = document.getElementById('fullscreen-modal');
        const modalContainer = document.getElementById('modal-content-container');
        const chartElement = chartWrapper.querySelector('svg') || chartWrapper.querySelector('img');
        if (chartElement && modal && modalContainer) {
            modalContainer.innerHTML = '';
            const clone = chartElement.cloneNode(true);
            clone.style.width = '100%';
            clone.style.height = '100%';
            clone.style.maxHeight = '85vh';
            clone.style.objectFit = 'contain';
            modalContainer.appendChild(clone);
            modal.style.display = 'flex';
        }
    };
}
function closeChartModal(event) {
    const modal = document.getElementById('fullscreen-modal');
    if (modal) {
        modal.style.display = 'none';
        const modalContainer = document.getElementById('modal-content-container');
        if (modalContainer) modalContainer.innerHTML = '';
    }
}
const observer = new MutationObserver(attachChartModalClick);
window.addEventListener('load', function() {
    const target = document.getElementById('chart-container');
    if (target) {
        observer.observe(target, { childList: true, subtree: true });
        attachChartModalClick();
    }
});
</script>
"""

def generate_risk_figures(current_eal, total_spent, total_risk_reduced, delayed_eal, budget_lakhs, delay_days, benefit_horizon):
    """Renders dual-pane Matplotlib visualizations for the Pareto frontier and scenario comparisons."""
    plt.style.use('dark_background')
    fig, axes = plt.subplots(1, 2, figsize=(16, 6.5), dpi=150)
    plt.subplots_adjust(wspace=0.28)
    
    BG_COLOR, SURFACE_COLOR, MUTED_TEXT = '#171c26', '#1f2533', '#94a3b8'
    MUTED_LINE, MUTED_BLUE, MUTED_ACCENT = '#334155', '#5b82a6', '#b46363'
    MUTED_GREEN, MUTED_AMBER = '#5a9678', '#b5894b'

    fig.patch.set_facecolor(BG_COLOR)
    for ax in axes:
        ax.set_facecolor(SURFACE_COLOR)
        ax.tick_params(colors=MUTED_TEXT, labelsize=9)
        for spine in ax.spines.values():
            spine.set_color(MUTED_LINE)
            
    # Chart 1: Investment vs. Risk Reduction
    spend_x = np.linspace(0, max(120.0, budget_lakhs * 1.5), 80)
    ideal_risk_y = (current_eal / 1e5) * (1.0 - np.exp(-0.038 * spend_x))
    
    axes[0].plot(spend_x, ideal_risk_y, color=MUTED_BLUE, lw=2.4, label='Risk Reduction Frontier')
    axes[0].axvline(x=total_spent / 1e5, color=MUTED_ACCENT, linestyle='--', lw=1.8, label=f'Optimal Allocation: INR {total_spent/1e5:.1f} Lakhs')
    axes[0].scatter([total_spent / 1e5], [total_risk_reduced / 1e5], color=MUTED_ACCENT, s=110, zorder=5, edgecolors=MUTED_TEXT, linewidths=1.0)
    axes[0].set_title("Capital Investment vs. Risk Reduction", fontsize=12, fontweight='bold', color=MUTED_TEXT, pad=12)
    axes[0].set_xlabel("Capital Invested (INR Lakhs)", fontsize=10, color=MUTED_TEXT, labelpad=8)
    axes[0].set_ylabel("Financial Exposure Reduced (INR Lakhs)", fontsize=10, color=MUTED_TEXT, labelpad=8)
    axes[0].grid(True, linestyle='--', alpha=0.3, color=MUTED_LINE)
    axes[0].legend(loc="lower right", fontsize=9, framealpha=0.6, facecolor=SURFACE_COLOR, edgecolor=MUTED_LINE)
    
    # Chart 2: Decision Scenario Comparisons
    annual_post = max(0.0, current_eal - (total_risk_reduced / benefit_horizon))
    scenarios = ['Baseline Exposure', 'Optimal Posture', f'Delayed ({delay_days}d)']
    values = [current_eal / 1e7, annual_post / 1e7, delayed_eal / 1e7]
    
    bars = axes[1].bar(scenarios, values, color=[MUTED_AMBER, MUTED_GREEN, MUTED_ACCENT], width=0.50, edgecolor=MUTED_LINE, linewidth=1.0)
    axes[1].set_title("Financial Exposure Across Decision Scenarios", fontsize=12, fontweight='bold', color=MUTED_TEXT, pad=12)
    axes[1].set_ylabel("Expected Annual Loss (INR Crores)", fontsize=10, color=MUTED_TEXT, labelpad=8)
    for bar, v in zip(bars, values):
        axes[1].text(bar.get_x() + bar.get_width()/2, v + 0.02, f"INR {v:.2f} Cr", ha='center', va='bottom', color=MUTED_TEXT, fontsize=10)
    axes[1].set_ylim(0, max(values) * 1.20)
    axes[1].grid(axis='y', linestyle='--', alpha=0.3, color=MUTED_LINE)
    
    plt.tight_layout()
    return fig
