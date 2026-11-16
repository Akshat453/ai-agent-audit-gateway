"""Delegation tokens (Phase 8, ADR-0030).

Submodules: ``token`` (pure codec + Ed25519 signatures), ``constraint`` (pure: what a resolved
chain allows; consumed by the policy engine), ``service`` (DB: create, revoke, resolve, use).
This package's ``__init__`` imports nothing, so the pure policy engine can import
``agw_gateway.delegation.constraint`` without pulling in the database layer.
"""
