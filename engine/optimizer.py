"""
Dual-Channel Adaptive Optimizer
Maintains dual learning rates to handle both rapid zero-day containment (Tactical)
and long-term capital preservation (Strategic), gated by active threat severity.
"""

import numpy as np

class DualChannelAdaptiveOptimizer:
    def __init__(self, state_dim=8, action_dim=5):
        self.state_dim = state_dim
        self.action_dim = action_dim
        
        # Tactical stream weights (high reactivity)
        self.w_tactical = np.random.normal(0, 0.05, (state_dim, action_dim))
        self.lr_tactical = 0.045
        self.gamma_tactical = 0.80
        
        # Strategic stream weights (capital stability)
        self.w_strategic = np.random.normal(0, 0.01, (state_dim, action_dim))
        self.lr_strategic = 0.005
        self.gamma_strategic = 0.95

    def get_q_streams(self, state):
        return state @ self.w_tactical, state @ self.w_strategic

    def select_action(self, state, threat_multiplier=1.0, epsilon=0.0) -> int:
        if np.random.rand() < epsilon:
            return np.random.randint(self.action_dim)
            
        q_tact, q_strat = self.get_q_streams(state)
        # Shift arbitration weight dynamically when exploits are active
        alpha = 0.80 if threat_multiplier > 1.20 else 0.20
        q_combined = alpha * q_tact + (1.0 - alpha) * q_strat
        return int(np.argmax(q_combined))

    def update(self, s, a, r, s_next, done):
        q_tact_s, q_strat_s = self.get_q_streams(s)
        q_tact_next, q_strat_next = self.get_q_streams(s_next)
        
        t_tact = r if done else r + self.gamma_tactical * np.max(q_tact_next)
        t_strat = r if done else r + self.gamma_strategic * np.max(q_strat_next)
        
        self.w_tactical[:, a] += self.lr_tactical * (t_tact - q_tact_s[a]) * s
        self.w_strategic[:, a] += self.lr_strategic * (t_strat - q_strat_s[a]) * s

def pretrain_optimizer(optimizer: DualChannelAdaptiveOptimizer):
    """Initializes policy weights across simulated threat drift cycles."""
    for ep in range(350):
        s = np.array([
            np.random.uniform(0.6, 0.95),
            np.random.uniform(0.3, 0.9),
            np.random.uniform(0.4, 0.7),
            0.0, 0.0, 1.0, 1.0,
            float(np.random.choice([0, 1, 2])) / 2.0
        ], dtype=np.float32)
        rem_budget = 1.0
        
        for _ in range(5):
            a = optimizer.select_action(s, threat_multiplier=1.35, epsilon=max(0.04, 0.45 * (0.985 ** ep)))
            reward = np.random.uniform(0.8, 3.5) if a > 0 else 0.0
            rem_budget -= 0.18
            s_next = s.copy()
            s_next[6] = max(0.0, rem_budget)
            optimizer.update(s, a, reward, s_next, rem_budget <= 0)
            s = s_next
            if rem_budget <= 0:
                break
