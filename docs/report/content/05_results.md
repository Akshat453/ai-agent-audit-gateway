# Result Analysis and Discussion

All numbers in this chapter come from committed result files under `experiments/` or from the phase reports in `docs/gateway/phases/`. The Phase 10 write-up that the repository README links (`docs/gateway/research/results.md`) is not present, and raw outputs exist only for RQ1; the RQ2 to RQ7 runners therefore have no reportable results. Where an earlier phase measured the same question, that measurement is used and labelled.

## Gateway Overhead and Latency

{tab:rq1} and {fig:rq1} report *decision* latency (request to the gateway's answer), excluding asynchronous execution and human waits.

::table rq1 | RQ1 decision latency and throughput with one agent (5 runs; 95 % bootstrap interval for the median)
::widths 12,26,14,14,16,18
| Config | p50 (ms) [95 % interval] | p95 (ms) | p99 (ms) | Throughput (req/s) | Errors at 50 agents (%) |
|---|---|---|---|---|---|
| C0 | 0.002 [0.001, 0.002] | 0.002 | 0.003 | 483,201 | 0.0 |
| C1 | 8.4 [8.2, 8.6] | 11.1 | 16.8 | 113.6 | 0.0 |
| C2 | 31.5 [27.3, 34.9] | 53.8 | 71.8 | 29.7 | 8.5 |
| C3 | 42.1 [32.1, 53.8] | 105.1 | 238.6 | 21.2 | 0.9 |
| C4 | 17.7 [15.4, 21.1] | 32.3 | 52.0 | 53.2 | 0.0 |
| C5 | 14.8 [14.2, 15.1] | 19.2 | 22.9 | 65.9 | 0.0 |
| C6 | 20.1 [17.3, 23.1] | 43.8 | 120.1 | 45.7 | 0.0 |

::figure rq1 | fig5_1_rq1_latency.png | RQ1 median decision latency by configuration and concurrency (log scale; bars show 95 % bootstrap intervals) | 5.77

With one agent, the full system (C6) answers in a median of 20.1 ms against 8.4 ms for authorisation alone (C1). The per-stage timers show that risk and policy take under 1 ms (0.73 ms and 0.035 ms in C6) while the durable transactions dominate (tx1 11.7 ms, dispatch 9.0 ms, result 9.5 ms), so the hot path is the database, not the CPU. At 50 agents the C6 median rises to 694.9 ms, because one chain-head lock serialises writers per tenant; Phase 2 measured 470 events/s for 8 threads on one tenant against 1,222 events/s over 8 tenants. The configurations are not monotonic (C2 and C3 are slower than C4 to C6, with non-overlapping intervals, and C2 returned 8.5 % fail-closed errors at 50 agents); the recorded data does not explain this, and since the run used an uncommitted tree on a shared machine these differences are indicative only. In Phase 8 the SDK decision added 14.72 ms (median) over a direct call, while a full call took 309.6 ms, dominated by the 0.25 s long-poll interval; LangGraph added no measurable overhead and MCP one hop. Phase 2 measured canonicalise-and-hash at 54.3 microseconds per event (p50).

## Tamper Detection

{tab:tamper} combines the Phase 3 tamper matrix with chain-backed tests from Phases 6, 7, 9 and C3b. A *naive* attacker edits rows; a *rewriter* controls the database and recomputes every hash consistently.

::table tamper | Tamper detection by attack class and required trust root
::widths 34,33,33
| Attack | Without external root | With a root at or after the attacked epoch |
|---|---|---|
| Edit event (naive) | TAMPERED (prev-hash mismatch) | TAMPERED |
| Edit, delete or reorder events (rewriter) | Not detected (UNANCHORED) | TAMPERED (root mismatch) |
| Delete whole epoch (naive / rewriter) | Detected (epoch gap) / not detected | TAMPERED (truncated before root) |
| Fork an epoch (rewriter) | Not detected | Detected; contract refuses second root |
| Consistent re-seal after anchoring | Passes offline checks | TAMPERED vs. chain (anchor root mismatch) |
| Delete database tail after anchoring | Shorter history looks valid | TAMPERED (epochs missing vs. chain) |
| Bundle claims another contract | - | UNTRUSTED_ANCHOR (exit 5) |
| Swap ciphertexts between events | TAMPERED (decrypt failed, AAD) | TAMPERED |
| Edit unhashed display copy | TAMPERED (stored copy mismatch) | TAMPERED; monitor alert |

Naive edits are caught by chain and continuity checks alone; a full rewriter only by a root obtained out of band, which is what anchoring supplies. "Not detected" never appears as VERIFIED, except for tail truncation checked against an older root that genuinely covers what remains. The monitor caught a one-byte header flip within one cycle. A development walkthrough found that the console showed an unhashed, editable copy of each record; ADR-0038 made displays read the sealed bytes and the monitor compare the copy.

## Authorisation Enforcement

{tab:authz} summarises the enforcement experiments; none produced an unauthorised execution.

::table authz | Authorisation enforcement results
::widths 52,16,32
| Experiment | Attempts | Unauthorised executions |
|---|---|---|
| Approval attacks A1-A13 (alteration, replay, expiry, races, forgery, cross-tenant, four-eyes) | 57 | 0 |
| Prompt-injection corpus (13 documents x 2 modes) | 26 | 0 (e-mail case pending approval) |
| Containment probe of the agent container | 12 targets | Only the gateway reachable |
| Concurrent delegation over-use (max 3 uses) | 12 | Exactly 3 allowed |
| Labelled risk dataset, final level / decision agreement | 67 | 67/67 and 67/67 |

The injected e-mail was contained by approval, not policy: injection of an *allowed* action needs a human check. The risk dataset first agreed on 64/67 levels and 65/67 decisions; both decision errors were too permissive and were fixed by the rule MR-UNTRUSTED-SENSITIVE (labels and weights share an author, so this measures consistency, not validity). With the chain RPC down, the CRITICAL gate timed out and the adapter was called zero times.

## Risk-Adaptive versus Fixed Batching

{tab:seal} and {fig:seal} compare fixed 100-event sealing with adaptive sealing in a simulation that uses the production decision function but no database, network or concurrency effects.

::table seal | Fixed versus adaptive sealing (simulated; 5 seeds x 1 h; 1 s sealer tick)
::widths 14,22,18,24,22
| Rate (act/s) | Policy | Epochs per hour | HIGH+CRITICAL p95 unsealed (s) | Mean unsealed, all (s) |
|---|---|---|---|---|
| 0.05 | Fixed 100 | 12 | 283.5 | 157.7 |
| 0.05 | Adaptive | 32 | 0.9 | 72.5 |
| 0.5 | Fixed 100 | 89 | 48.7 | 22.2 |
| 0.5 | Adaptive | 135 | 0.9 | 17.2 |
| 5.0 | Fixed 100 | 887 | 5.0 | 2.6 |
| 5.0 | Adaptive | 1,293 | 1.0 | 2.2 |

::figure seal | fig5_2_seal_comparison.png | Exposure of high-risk events and sealing cost for fixed and adaptive policies (simulated; panel (b) on a log scale) | 5.77

Adaptive sealing bounds the unsealed time of HIGH and CRITICAL events to one tick (maximum 1.0 s), against up to about 300 s for fixed batching, at the cost of 1.5 to 2.7 times more epochs and therefore more anchors. On Anvil, 40 mined anchors used 96,171 gas for a recorder's first anchor and a median of 81,569 afterwards (mean of all 40: 81,930.8). Under stated assumptions (ETH at USD 3,000, an L2 gas price of 0.01 gwei, L2 execution gas only) an anchor costs about USD 0.0025. The layer-1 (L1) data fee and time to finality on Base Sepolia were not measured.

## Coding-Agent Results

{tab:codingres} lists the coding-agent measurements recorded in the repository.

::table codingres | Coding-agent governance results
::widths 50,50
| Measurement | Result |
|---|---|
| Strict policy table: 191 actions (44 allow / 61 ask / 86 deny; 27 traps) | 100 % agreement (211 tests) |
| Balanced profile table | 165 cases pass; strict denies kept |
| Adapter goldens; fail-closed without gateway | 80 passed; dead gateway gives deny |
| `agw` binary vs. live gateway: 6 agents x allow / deny / ask | 8 passed |
| GitHub flow (mocked): submit passes check; manual push fails | 6 passed |
| First real Claude Code session (one-line fix) | 18 decisions; 9 stops (7 approvals, 1 CRITICAL, 1 block) |

The real session showed the strict profile was too noisy (money-path patterns caught UI pages, unlisted utilities asked, a temporary-file write was CRITICAL), so ADR-0037 made a "balanced" profile the default: every action is recorded, humans are asked locally only at crucial points, and the full strict check runs at submit. No fix rate over the 21 MintRail issues, approval latency or bypass counts for real agents are recorded, so none are reported.

## Failure Resilience and Independent Verification

In Phase 6, killing the RPC connection mid-submission, or crashing the worker before broadcast, led a new worker to re-send a byte-identical transaction with exactly one anchor per epoch; a simulated reorg re-broadcast the same root. In the RQ5 partition (the database container paused), requests blocked because there is no client-side query timeout, but nothing executed without committed evidence. In Phase 7, an auditor environment without gateway code verified disclosed bundles end to end (exit 0); a flipped ciphertext byte gave TAMPERED (exit 1) and a missing auditor key INCOMPLETE (exit 2). Dependency scanning found no vulnerable packages (pip-audit over 138 packages; npm audit), and bandit reported 30 LOW and no MEDIUM or HIGH findings.

## Discussion

The results support separate failure modes for enforcement and evidence: zero unauthorised executions, a precise mapping from attack class to required trust root, and overhead dominated by durable writes rather than decision logic. {tab:paperb} places the project beside Paper B; the setups differ, so the comparison is indicative only.

::table paperb | Project measurements beside Paper B's reported numbers (different setups)
::widths 30,32,38
| Quantity | Paper B [@bindschaedler2026] | This project |
|---|---|---|
| Per-event CPU (canonicalise + hash) | ~48 microseconds (in-process) | 54.3 microseconds p50 |
| Per-action cost | Not applicable (no gateway) | 20.1 ms p50 decision (C6, 1 agent) |
| Gas per anchor | 91,800 mean (Base Sepolia) | 81,930.8 mean (Anvil) |
| Detection, full stack | 100 % edit / delete / reorder / fork | All classes, given a later trusted root |

**Limitations and threats to validity.** Measurements come from one machine and an uncommitted working tree. The sealing comparison is simulated. Dataset labels and policy weights share an author. Injection and integration runs use a deterministic mock LLM. Base Sepolia and the live GitHub path were not exercised by committed tests. Coding-agent hooks are client-side: Codex and Gemini CLI fail open if the hook process is killed, and content rules are regular expressions that obfuscation can evade.
