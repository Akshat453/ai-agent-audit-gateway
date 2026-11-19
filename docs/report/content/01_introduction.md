# Introduction

## Background

Large language model (LLM) agents now act through tools: they read documents, call web services, change databases and hand work to other agents. Coding agents such as Claude Code, Codex, Cursor and Gemini CLI run shell commands, edit company code and open pull requests (PRs), often hundreds of tool calls per session. Paper B observes that the dominant failure of such agents is a wrong sequence of actions, such as a destructive command in production or an injected instruction spreading across agents [@bindschaedler2026]. An organisation therefore needs a decision *before* an action runs and, afterwards, evidence that a third party can check and that cannot be silently changed. AgentGuard provides both through an active gateway on the execution path between agents and their tools.

## Problem Statement

Three problems motivate the work. **Unauthorised actions:** an agent holding tool credentials can call anything they allow, and its own permission prompts are answered by the developer whose agent it is; both base papers record actions but neither prevents them [@bromme2026; @bindschaedler2026]. **Unverifiable logs:** ordinary logs are mutable rows that an insider or compromised host can edit, delete, reorder or fork without any signal to an auditor. **Prompt injection:** retrieved content can instruct an agent to export data or escalate privileges, and model-based authorisation can be talked out of its decision. The project asks how to build a gateway whose enforcement fails closed and whose evidence a third party can verify without trusting the operator.

## Motivation

Paper A proposes an evidence pipeline and risk-based evidence selection without implementing them [@bromme2026]; Paper B implements a flight recorder evaluated mostly on synthetic workloads [@bindschaedler2026]. Neither enforces policy, makes authorisation durable before the side effect, or handles a crash between dispatch and result, and Paper B's Merkle construction is ambiguous for odd leaf counts. This project closes these gaps in working code and applies them to coding agents.

## Objectives

1. **O1 Enforcement:** no unauthenticated, unregistered, out-of-scope or unapproved action reaches a controlled tool (zero unauthorised executions in the attack, injection and delegation suites).
2. **O2 Tamper evidence:** offline verification by a verifier sharing no code with the gateway (edit, delete, reorder, truncation and fork reported as TAMPERED given a covering trusted root).
3. **O3 Risk-adaptive sealing:** HIGH and CRITICAL events sealed within one sealer tick; no CRITICAL dispatch without a final anchor.
4. **O4 Action-bound approval:** one approval authorises one exact action, once, before expiry (all altered, replayed, expired or forged attempts fail).
5. **O5 Privacy:** per-event payload encryption and selective disclosure (a database-only attacker reads nothing; a grant for one event opens no other).
6. **O6 Coding-agent governance:** Claude Code, Codex, Cursor and Gemini CLI governed through one API, and GitHub changes only through the gateway (100 % agreement on a labelled policy table; end-to-end tests per agent).
7. **O7 Overhead:** latency percentiles with confidence intervals per ablation configuration.

## Scope and Assumptions

Enforcement holds only for tools whose credentials the gateway alone holds. Evidence proves that a record existed unchanged no later than its anchor time, not that the action was truthful, complete or correct; this claim boundary comes from both papers. The threat model assumes an immutable chain after finality, an honest verifier, an off-host copy of the evidence, and database superusers separate from agent operators. Entries written after a full gateway compromise and the not-yet-sealed tail are residual risks (Section 3.10). Evaluation used one machine with Postgres and an Anvil test chain; the Base Sepolia deployment is prepared but was not run.

## Report Organisation

Chapter 2 reviews the literature, Chapter 3 the methodology, Chapter 4 the implementation and setup, and Chapter 5 the results; conclusions, future work, appendices and references follow.
