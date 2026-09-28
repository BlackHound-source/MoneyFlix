"""
Actuarial FAIR Risk Quantification Engine
Combines Monte Carlo simulations for Expected Annual Loss (EAL) and 95% Value at Risk (VaR)
with a supervised Gradient Boosting Regressor for dynamic asset-level loss prediction.
"""

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import GradientBoostingRegressor
from sklearn.metrics import r2_score
from config import RANDOM_SEED

class RiskQuantificationEngine:
    def __init__(self, data: pd.DataFrame):
        self.data = data
        self.feature_cols = ['CVSS_Score', 'Open_Vulnerabilities', 'Security_Audit_Score', 'MFA', 'EDR', 'Firewall']
        self._train_loss_model()
        
    def calculate_fair_monte_carlo(self, n_simulations=50000):
        """Calculates global portfolio EAL and 95% tail VaR via lognormal Monte Carlo iterations."""
        losses = np.maximum(self.data['Total_Loss_INR'].to_numpy(), 5000.0)
        log_losses = np.log(losses)
        mu, sigma = np.mean(log_losses), np.std(log_losses)
        simulations = np.random.lognormal(mean=mu, sigma=sigma, size=n_simulations)
        return float(np.mean(simulations)), float(np.percentile(simulations, 95))

    def _train_loss_model(self):
        """Trains a gradient boosted ensemble to predict monetary exposure from telemetry inputs."""
        X = self.data[self.feature_cols]
        y = self.data['Total_Loss_INR']
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=RANDOM_SEED)
        
        self.model = GradientBoostingRegressor(n_estimators=100, max_depth=4, learning_rate=0.08, random_state=RANDOM_SEED)
        self.model.fit(X_train, y_train)
        self.r2 = r2_score(y_test, self.model.predict(X_test))

    def estimate_financial_exposure(self, state_dict: dict, threat_alert_multiplier=1.0) -> float:
        """Projects monetary exposure adjusted by business criticality and external threat indicators."""
        base_df = pd.DataFrame([{
            'CVSS_Score': state_dict['cvss'],
            'Open_Vulnerabilities': state_dict['open_vulns'],
            'Security_Audit_Score': state_dict['audit_score'],
            'MFA': state_dict['mfa'],
            'EDR': state_dict['edr'],
            'Firewall': state_dict['firewall']
        }])
        pred_loss = self.model.predict(base_df)[0]
        criticality_weight = 1.0 + (0.15 * (state_dict.get('criticality', 3.0) - 1.0))
        return float(pred_loss * criticality_weight * threat_alert_multiplier)
