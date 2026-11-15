# ADR-0001: Active gateway, registered tools only, deny by default
Status: Accepted · Date: 2026-11-15 · Deciders: project owner (Phase 0)

## Context
Both papers *record* agent actions. Neither prevents them (Paper A §2: prevention "still depends on ... policy enforcement"; Paper B §III-A lists completeness as a non-goal). Paper A §4 recommends an "evidence controller or audit gateway" that assigns sequence numbers and applies policy checks.
## Decision
The gateway is on the execution path. Agents never hold tool credentials or routes. Only tools registered in code and in `tool_registry` are callable. Every system check (tool known, args valid, environment allowed, scope present) runs before policy rules, and the absence of an explicit ALLOW is a DENY.
## Consequences
+ Enforcement is a property of the system, not of agent cooperation. Bypass needs a network or credential breach (03 assumption 4).
− Every tool needs an adapter. The gateway is a single point of failure, which fails closed (08 §8).
## Alternatives rejected
Passive sidecar or log tap (can't block). Allow-by-default with deny lists (unknown tools reachable).
