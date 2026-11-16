# Integration effort and added latency (Phase 8, ADR-0030)

`make integration-latency`; N = 60 calls per path after 5 warm-up calls; one machine, localhost, Postgres in Docker, executor in-process. Hypothesis-free numbers for THIS setup only.

| path | median ms | p95 ms | added vs direct ms | added vs SDK ms |
|---|---|---|---|---|
| direct | 0.09 | 0.21 | 0.0 | -309.51 |
| sdk_decision_only | 14.72 | 26.62 | 14.64 | -294.87 |
| sdk | 309.6 | 351.62 | 309.51 | 0.0 |
| langgraph | 305.74 | 426.73 | 305.65 | -3.86 |
| mcp | 321.14 | 360.62 | 321.05 | 11.54 |

Reading: the enforcement + evidence cost is `sdk_decision_only`. The rest of a full call is asynchronous execution plus the result long-poll, whose server loop re-checks every 0.25 s (`GET /v1/actions/{id}?wait=`), which dominates the full-call numbers. LangGraph adds no measurable overhead over the SDK; MCP adds one protocol hop.

| adapter | code lines | total lines (with docs) |
|---|---|---|
| agw_sdk (client + errors) | 330 | 442 |
| agw_langgraph | 122 | 161 |
| agw_mcp | 253 | 316 |
| example glue (agentlib graphs + multi_agent) | 224 | 281 |
