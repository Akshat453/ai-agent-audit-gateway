| attack | attempts | unauthorized executions | blocked by |
|---|---|---|---|
| A1 approve, then alter args (subject) | 1 | 0 | digest recomputed from stored request |
| A2 approve, then alter target (recipient) | 1 | 0 | digest recomputed from stored request |
| A3 approve, then alter tool version | 1 | 0 | digest recomputed from stored request |
| A3b approve, then alter environment | 1 | 0 | digest recomputed from stored request |
| A3c approve, then lower recorded risk | 1 | 0 | digest recomputed from stored request |
| A4 approve, then resubmit with altered recipient | 2 | 0 | new action -> new digest + new approval |
| A5 replay consumed approval for identical request | 5 | 0 | approval bound to action_id; CONSUMED; nonce PK; column grants |
| A6 use an expired approval | 3 | 0 | expires_at checked against DB time |
| A7 20 concurrent dispatch attempts, one approval | 20 | 0 | approval row lock + nonce PK |
| A8 agent credential on decision/approval endpoints | 6 | 0 | separate human auth scheme; 403 + SECURITY_VIOLATION |
| A9 forged decision (wrong nonce / wrong digest / bad or foreign signature) | 4 | 0 | echo check; Ed25519 under the configured key only |
| A10 approval for tenant A used from tenant B | 3 | 0 | tenant-scoped lookup; tenant check at authorization |
| A11 approve an already executed / rejected / invalidated action | 3 | 0 | state machine: only PENDING is decidable |
| A12 policy tightened between approval and dispatch | 1 | 0 | re-evaluation under current policy; stricter wins |
| A12b scope revoked / agent disabled after approval | 2 | 0 | re-evaluation with current agent row |
| A12c risk rose after approval (stricter wins) | 1 | 0 | level re-check |
| A13 four-eyes CRITICAL: same approver twice | 2 | 0 | PK(approval, approver); distinct valid signatures counted |

Total: 57 attempts, 0 unauthorized executions.
