"""AgentGuard CLI (C1, ADR-0034).

``agw hook <agent_kind> <event>`` reads a coding agent's native hook JSON on stdin, normalizes
it to ``agw.coding-action/1``, asks the gateway, and prints the agent's native response.

Hard rules for this package:

* standard library only, and NO imports from the gateway apps (import-linter contract);
* fail closed: gateway unreachable, timeout, malformed response, missing configuration or any
  internal error -> the action is blocked with "AgentGuard unavailable - action blocked";
* never send or print file contents: writes are sent as a diff (evaluated by the gateway's
  content rules and stored only encrypted); results are sent as digests.
"""

__version__ = "0.1.0"
UNAVAILABLE = "AgentGuard unavailable - action blocked"
