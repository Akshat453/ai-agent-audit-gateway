SIMULATED, local, preliminary. 5 seeds x 1.0 h, 1 s sealer tick.
| rate (actions/s) | policy | epochs/h | epochs by reason | HIGH+CRIT max unsealed s | HIGH+CRIT p95 s | all-events max s | all-events mean s |
|---|---|---|---|---|---|---|---|
| 0.05 | fixed-100 | 12 | MAX_AGE 11, MAX_EVENTS 1 | 300.8 | 283.5 | 301.0 | 157.7 |
| 0.05 | adaptive (lowest, default) | 32 | MAX_AGE 23, RISK_CRITICAL 2, RISK_HIGH 8 | 1.0 | 0.9 | 300.9 | 72.5 |
| 0.05 | adaptive (strictest) | 40 | MAX_AGE 17, MAX_EVENTS 14, RISK_CRITICAL 2, RISK_HIGH 8 | 1.0 | 0.9 | 300.7 | 69.5 |
| 0.5 | fixed-100 | 89 | MAX_AGE 1, MAX_EVENTS 88 | 300.6 | 48.7 | 300.6 | 22.2 |
| 0.5 | adaptive (lowest, default) | 135 | MAX_AGE 2, MAX_EVENTS 51, RISK_CRITICAL 15, RISK_HIGH 67 | 1.0 | 0.9 | 300.4 | 17.2 |
| 0.5 | adaptive (strictest) | 365 | MAX_AGE 1, MAX_EVENTS 286, RISK_CRITICAL 14, RISK_HIGH 65 | 1.0 | 0.9 | 300.4 | 8.0 |
| 5.0 | fixed-100 | 887 | MAX_AGE 1, MAX_EVENTS 886 | 299.0 | 5.0 | 300.9 | 2.6 |
| 5.0 | adaptive (lowest, default) | 1293 | MAX_AGE 1, MAX_EVENTS 586, RISK_CRITICAL 149, RISK_HIGH 557 | 1.0 | 1.0 | 300.9 | 2.2 |
| 5.0 | adaptive (strictest) | 3669 | MAX_AGE 1, MAX_EVENTS 3149, RISK_CRITICAL 111, RISK_HIGH 407 | 1.0 | 1.0 | 300.9 | 1.3 |
