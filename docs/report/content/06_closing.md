#* Conclusion

AgentGuard was built and evaluated against the objectives of Section 1.4. **O1 Enforcement** was met within the tested scope: no unauthorised execution occurred in 57 approval attacks, 26 prompt-injection runs, the delegation over-use test or the containment probe, and every phase's guards were confirmed by mutation. **O2 Tamper evidence** was met: the independent verifier detected every tested attack class given a trusted root at or after the attacked epoch, anchors made consistent rewrites, tail deletions and forks detectable, and an insider edit of the unhashed display copy found during development is now detected by the console and the monitor. **O3 Risk-adaptive sealing** was met in simulation: high-risk events stayed unsealed for at most one 1 s tick against up to about 300 s with fixed batching, at 1.5 to 2.7 times more epochs; on Anvil, CRITICAL actions ran only after their authorisation was anchored and the gate failed closed without the chain. **O4 Action-bound approval** was met: altered, replayed, expired, forged, cross-tenant and same-approver attempts all failed, and 20 concurrent dispatches with one approval executed once. **O5 Privacy** was met: a database-only attacker read no payload, a grant for one event could not open another, and an auditor without gateway code verified disclosed bundles. **O6 Coding-agent governance** was met for the implemented integrations: the 191-case policy table agreed fully, six agent kinds passed end-to-end tests, GitHub changes pass only through the server-side submit and evidence check, and the first real session led to a balanced default profile. **O7 Overhead** was met for RQ1: the full system's median decision latency was 20.1 ms against 8.4 ms for authorisation alone with one agent, dominated by durable writes; results for the other research questions were not available. The main limitations are a single-machine evaluation, a simulated sealing comparison, an untested public testnet, client-side hooks, and the claim boundary that evidence shows a record is unchanged, not that it is true.

#* Scope for Future Work

The design documents and phase reports identify these open items:

1. **Identity:** OIDC/SSO for human sign-in, WebAuthn so that approval signatures come from the human rather than the gateway, and TOTP or lockout for approvers.
2. **Keys and evidence format:** an AWS KMS adapter and HSM-backed anchor signers; a salted argument digest (version 2) against guessing of low-entropy confidential arguments; a signed operator manifest for trust roots.
3. **Verifier:** lifecycle checks that dispatched arguments equal approved arguments and that each CRITICAL dispatch has an earlier final anchor; cross-checks across two RPC providers.
4. **Deployment:** a Base Sepolia run measuring the L1 data fee and time to finality; a shared rate limiter across replicas; client-side database timeouts; incremental monitor checkpoints.
5. **Agents:** native adapters for VS Code agent mode and Antigravity, a filtering MCP proxy, live GitHub App runs and a fix-rate study over the MintRail backlog.
6. **Research:** TEE attestation for capture completeness, threshold-signed anchors, zero-knowledge inclusion proofs, and a user study of the plain-English console.

#* Appendices

##* Appendix A: API Endpoint Summary

{tab:api} groups the main HTTP endpoints. The full contract is in `docs/gateway/11-api-and-data-contracts.md`.

::table api | Main API endpoints by group
::widths 22,78
| Group | Endpoints |
|---|---|
| Actions | `POST /v1/actions`; `GET /v1/actions/{id}?wait=N`; `POST /v1/actions/{id}/reconcile`; `GET /v1/tools` |
| Evidence | `GET /v1/events`; `GET /v1/events/{id}/proof`; `GET /v1/epochs/{n or latest}`; `GET /v1/runs/{id}/timeline`; `POST /v1/exports` |
| Approvals | `GET /v1/approvals`; `GET /v1/approvals/{id}`; `POST /v1/approvals/{id}/decision`; `GET /v1/approvals-signing-keys` |
| Human auth | `POST /v1/auth/login`, `/logout`, `/step-up`, `/signup`; `GET /v1/auth/me` |
| Delegation | `POST /v1/delegations`; `POST /v1/delegations/{id}/revoke`; `GET /v1/delegations/{id}/timeline`; `POST /v1/oauth/token` |
| Disclosure | `POST /v1/auditor-keys`; `POST /v1/disclosures`; `POST /v1/disclosures/{id}/export`, `/revoke` |
| Coding | `POST /v1/coding/sessions`, `/decide`, `/observe`, `/repos`; `POST /v1/coding/sessions/{id}/end`; `GET /v1/coding/status` |
| Connectors | `GET`/`POST /v1/connectors`; `POST /v1/connectors/{id}/classify-proposed`; `POST /v1/webhooks/github/{id}` |
| Enrolment, MCP | `POST /v1/device/authorize`, `/token`; `/oauth/register`, `/oauth/token`; `POST /mcp` |

##* Appendix B: Evidence Bundle Structure

An evidence bundle (`agw-bundle/v1`, JSON Schema in `packages/schemas/bundle/`) holds everything needed to verify one event offline. Its fields are:

::code
format, bundle_version, tenant
event        { event_id, seq, header (CBOR, hex), payload }
proof        { epoch_no, tree_size, leaf_index, audit_path[] }
epoch        { first_seq, last_seq, merkle_root, prev_root, root,
               seal_reason }
epoch_chain  [ epoch headers back to the trusted epoch ]
trust_root   { epoch_no, epoch_root, source: "anchor" }
anchor       { chain_id, contract, recorder_id, epoch_no, status,
               tx_hash, block_number }
::endcode

##* Appendix C: Sample Policy Rules with Descriptions

Rule descriptions live in companion files next to the policies. They are kept separate because the policy bytes are hashed into every decision. {tab:rules} shows a sample.

::table rules | Sample policy rules and their plain-English descriptions
::widths 28,14,58
| Rule id | Effect | Description shown to users |
|---|---|---|
| SECRET-READ | deny | The file holds secrets (like .env or private keys), so the agent may not read it. |
| CMD-NETWORK | deny | The command talks to another computer (curl, ssh, scp...), which could send data out. |
| GIT-PUSH | deny | Agents may not push; changes go to GitHub only through AgentGuard's reviewed submit. |
| CONTENT-SIGNATURE-BYPASS | deny | The change would remove webhook signature checks. |
| CONTENT-MONEY-NUMBER | deny | The change turns exact money amounts (bigint) into ordinary numbers, which can lose paise. |
| MR-DELETE-PROD | floor CRITICAL | Deleting data in production. |

##* Appendix D: Glossary of Console Terms

{tab:glossary} defines the terms used in the console and in this report.

::table glossary | Glossary of console terms
::widths 22,78
| Term | Meaning |
|---|---|
| Run / session | All actions of one agent session; for coding agents, one session per repository and issue |
| Action | One tool call the agent asked for, with its decision and outcome |
| Event | One immutable, hashed record in the tenant's chain |
| Epoch | A sealed batch of consecutive events with one Merkle root |
| Anchor | The epoch root written to the chain; Locked, Sent, Included, Permanent in Simple view |
| Approval | A routed human decision bound to one action digest, single use, with expiry |
| Trust root | An epoch root obtained out of band (from the chain) that verification relies on |

##* Appendix E: How to Reproduce

::code
make up && make migrate      # Postgres, MinIO, Anvil; migrations
make test                    # lint, types, pytest, coverage gates
make demo                    # end-to-end demo with offline verify
make rq1                     # RQ1 latency -> experiments/rq1_latency/results/
make risk-eval seal-compare  # risk dataset and sealing comparison
make approval-attacks injection-corpus anchor-gas
make dashboard-e2e           # Playwright console tests (isolated ports)
python3 docs/report/build_report.py   # rebuild this report (.docx and .pdf)
::endcode
