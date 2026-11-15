"""Thin Python client for the AGW gateway. No server internals (import-linter enforced)."""

from agw_sdk.client import ActionResponse, Client, GatewayError

__all__ = ["ActionResponse", "Client", "GatewayError"]
