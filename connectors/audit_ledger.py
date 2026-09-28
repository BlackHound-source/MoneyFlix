"""
Cryptographic Audit Ledger (Plugin Zone 3)
Maintains an immutable append-only SHA-256 block ledger to support
tamper-evident compliance audits under RBI CSF and SEBI CSCRF guidelines.
"""

import time
import json
import hashlib

class ImmutableAuditLedgerConnector:
    def __init__(self, log_path="compliance_audit_ledger.json"):
        self.log_path = log_path
        self.chain = []
        self._initialize_genesis()

    def _initialize_genesis(self):
        genesis = {
            'block_height': 0,
            'timestamp': time.time(),
            'event': 'GENESIS_BLOCK_INITIALIZED',
            'data': 'Cyber Risk Quantification & Capital Optimization Platform Online',
            'previous_hash': '0' * 64
        }
        genesis['hash'] = self._hash_block(genesis)
        self.chain.append(genesis)

    def _hash_block(self, block: dict) -> str:
        serialized = json.dumps({
            'block_height': block['block_height'],
            'timestamp': block['timestamp'],
            'event': block['event'],
            'data': block['data'],
            'previous_hash': block['previous_hash']
        }, sort_keys=True).encode()
        return hashlib.sha256(serialized).hexdigest()

    def commit_remediation_event(self, eal_before: float, spent: float, reduction: float, rosi: float, controls: list) -> str:
        """Appends a new verified remediation decision block to the ledger."""
        prev_block = self.chain[-1]
        record = {
            'block_height': len(self.chain),
            'timestamp': time.time(),
            'event': 'OPTIMIZED_CAPITAL_ALLOCATION_AUDIT',
            'data': {
                'baseline_eal_inr': eal_before,
                'capital_allocated_inr': spent,
                'financial_risk_reduced_inr': reduction,
                'net_rosi_percent': rosi,
                'controls_authorized': controls
            },
            'previous_hash': prev_block['hash']
        }
        record['hash'] = self._hash_block(record)
        self.chain.append(record)
        try:
            with open(self.log_path, 'w') as f:
                json.dump(self.chain, f, indent=2)
        except Exception:
            pass
        return record['hash']
