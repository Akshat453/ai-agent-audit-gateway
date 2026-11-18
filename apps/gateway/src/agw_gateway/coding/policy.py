"""Coding risk policy engine (C1 §4, ADR-0034 §4). Pure and deterministic: no I/O, no clock,
no randomness, no LLM. The same (policy file, action, diff) always gives the same decision.

``evaluate`` collects every matching rule (a :class:`Hit`), then combines them:
deny > ask > allow, risk level = max. Mandatory rules (secrets, denied commands, content rules)
are denies, so they override everything. Unknown action types and anything the policy cannot
interpret ask a human; nothing unknown is ever allowed.
"""

from __future__ import annotations

import copy
import hashlib
import posixpath
import re
import tomllib
from collections.abc import Iterable, Mapping
from contextvars import ContextVar
from dataclasses import dataclass
from importlib import resources
from typing import Any, Final
from urllib.parse import urlsplit

from agw_gateway.coding import content
from agw_gateway.coding.commands import (
    SUBST_TOKEN,
    WRITE_REDIRECTS,
    CommandUnparseable,
    Segment,
    parse,
    split_command_text,
)
from agw_gateway.coding.globs import (
    PathInvalid,
    first_match,
    glob_match,
    is_outside,
    normalize_path,
)
from agw_gateway.coding.model import KNOWN_ACTION_TYPES, CodingAction
from agw_gateway.coding.rules import Combined, Hit, combine
from agw_gateway.crypto.tags import domain_tag

CODING_POLICY_TAG: Final = "AGW/coding-policy/v1"
ENGINE_VERSION: Final = "coding-policy-v1"
BUNDLED_POLICY: Final = "coding-mintrail-v2.toml"  # "balanced" (the default profile)
STRICT_POLICY: Final = "coding-mintrail-v1.toml"  # "strict" (C1: ask at every sensitive step)
PROFILE_FILES: Final = {"balanced": BUNDLED_POLICY, "strict": STRICT_POLICY}
# The evaluation stage: "local" (the agent's machine, via the hook) or "submit" (the change
# leaving the machine: git_submit_change). The balanced profile relaxes only "local".
_STAGE: ContextVar[str] = ContextVar("agw_coding_stage", default="local")
_BARE_HOST: Final = re.compile(
    r"^(localhost|\d{1,3}(?:\.\d{1,3}){3}|\[::1\]|[a-z0-9-]+(?:\.[a-z0-9-]+)+)(?::\d+)?(?:/|$)",
    re.I,
)
_TEMP_PREFIXES: Final = (
    "/tmp/",  # noqa: S108 - a path CLASS, nothing is created
    "/private/tmp/",
    "/var/folders/",
    "/private/var/folders/",
)
# Rules the balanced profile turns into "allow (recorded)" on the developer's machine. The
# change is inspected again, strictly, when it is submitted.
_RELAX_LOCAL: Final = frozenset(
    {
        "PATH-HIGH",
        "PATH-DELETE-TEST",
        "CONTENT-UNKNOWN",
        "CONTENT-TEST-SKIP",
        "CONTENT-TEST-REMOVED",
        "PATH-CRITICAL-DEPENDENCIES",
        "CMD-UNKNOWN",
        "CMD-DOCKER",
        "CMD-CHMOD",
        "CMD-SCRIPT",
        "CMD-RM-RECURSIVE",
        "CMD-RM-GLOB",
        "GIT-CONFIG",
        "GIT-NO-VERIFY",
        "WEB-ASK",
    }
)
_SECRET_VAR: Final = re.compile(
    r"\$\{?[A-Za-z_]*(SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|PRIVATE|CREDENTIAL|ACCESS_KEY)"
    r"[A-Za-z0-9_]*\}?",
    re.IGNORECASE,
)
_ENV_DUMP: Final = re.compile(r"process\.env\b(?!\s*\.\s*\w|\s*\[)|os\.environ\b(?!\s*\[|\.get)")
_ENV_ANY: Final = re.compile(r"process\.env|os\.environ|getenv")
_HOST_RE: Final = re.compile(
    r"(?:[a-z][a-z0-9+.\-]*://)?(?:[^@/\s]+@)?([a-z0-9][a-z0-9.\-]*\.[a-z]{2,})", re.I
)


@dataclass(frozen=True)
class CodingDecision:
    effect: str  # allow | ask | deny
    level: str  # LOW | MEDIUM | HIGH | CRITICAL
    rule_ids: tuple[str, ...]
    reason: str
    approval_role: str | None
    policy_id: str
    policy_version: int
    policy_digest: bytes

    @property
    def gateway_effect(self) -> str:
        """The gateway-wide vocabulary used in evidence (04 §4.4)."""
        return {"allow": "ALLOW", "deny": "DENY", "ask": "REQUIRE_APPROVAL"}[self.effect]


def _list(doc: dict[str, Any], section: str, key: str) -> tuple[str, ...]:
    value = doc.get(section, {}).get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ValueError(f"{section}.{key} must be a list of strings")
    return tuple(value)


class CodingPolicy:
    """One immutable, versioned coding policy document."""

    def __init__(self, raw: bytes) -> None:
        doc = tomllib.loads(raw.decode("utf-8"))
        self.raw = raw
        self.digest = hashlib.sha256(domain_tag(CODING_POLICY_TAG) + raw).digest()
        self.policy_id = str(doc["policy_id"])
        self.version = int(doc["version"])
        mode = str(doc.get("profile", {}).get("mode", "strict"))
        if mode not in PROFILE_FILES:
            raise ValueError(f"unknown coding policy profile: {mode}")
        self.profile = mode
        roles = doc.get("roles", {})
        self.critical_role = str(roles.get("critical", "security"))
        self.default_role = str(roles.get("default", "maintainer"))
        self.owners = tuple((str(o["glob"]), str(o["role"])) for o in doc.get("owners", []))
        p = "paths"
        self.secret = _list(doc, p, "secret")
        self.secret_exceptions = _list(doc, p, "secret_exceptions")
        self.secret_key_name = re.compile(doc[p].get("secret_key_name_regex", r"^$"))
        self.critical = _list(doc, p, "critical")
        self.high = _list(doc, p, "high")
        self.tests = _list(doc, p, "tests")
        self.ci = _list(doc, p, "ci")
        self.hook_config = _list(doc, p, "hook_config")
        self.authorized_keys = _list(doc, p, "authorized_keys")
        self.build_artifacts = _list(doc, p, "build_artifacts")
        self.signing = _list(doc, p, "signing")
        self.money = _list(doc, p, "money")
        c = "commands"
        self.cmd: dict[str, frozenset[str]] = {
            k: frozenset(_list(doc, c, k))
            for k in (
                "network",
                "privilege",
                "deploy",
                "package_runners",
                "shells",
                "interpreters",
                "env_print",
                "readers",
                "searchers",
                "harmless",
                "pnpm_allowed",
                "pnpm_allowed_scripts",
                "pnpm_migration_scripts",
                "make_allowed",
                "git_allowed",
                "git_read_only",
            )
        }
        self.production_hosts = _list(doc, "network_policy", "production_hosts")
        self.local_hosts = frozenset(_list(doc, "network_policy", "local_hosts"))
        self.web_allow = frozenset(d.lower() for d in _list(doc, "web", "allow_domains"))
        self.overlay_rule: str | None = None
        self.repo_deny_commands: tuple[str, ...] = ()
        self.repo_allow_commands: tuple[str, ...] = ()
        self.repo_allow_paths: tuple[str, ...] = ()
        self.mcp_allow = _list(doc, "mcp", "allow")
        self.mcp_deny = _list(doc, "mcp", "deny")

    def with_overlay(self, overlay: Mapping[str, Any], version: int, digest: bytes) -> CodingPolicy:
        """C2 (ADR-0035 §7): a repository overlay. ``sensitive`` / ``deny_paths`` /
        ``deny_commands`` only TIGHTEN and come from the repo's .agentguard.yaml;
        ``allow_paths`` / ``allow_commands`` exist only after an admin approved a proposal and
        can only relax HIGH-path and unknown-command asks: never a secret, a CRITICAL path,
        a content rule or a denied command."""
        p = copy.copy(self)
        sens = [s for s in overlay.get("sensitive", []) if isinstance(s, dict)]
        p.secret = (*self.secret, *overlay.get("deny_paths", []))
        p.critical = (*self.critical, *(s["path"] for s in sens if s.get("level") == "critical"))
        p.high = (*self.high, *(s["path"] for s in sens if s.get("level") == "high"))
        p.owners = (
            *((s["path"], s["owner"]) for s in sens if s.get("owner") and s.get("level") == "high"),
            *self.owners,
        )
        p.repo_deny_commands = tuple(overlay.get("deny_commands", []))
        p.repo_allow_commands = tuple(overlay.get("allow_commands", []))
        p.repo_allow_paths = tuple(overlay.get("allow_paths", []))
        p.overlay_rule = f"REPO-OVERLAY-v{version}"
        p.digest = hashlib.sha256(self.digest + digest).digest()
        return p

    @classmethod
    def bundled(cls, profile: str = "balanced") -> CodingPolicy:
        """The bundled policy of a profile: "balanced" (default) or "strict"."""
        if profile not in PROFILE_FILES:
            raise ValueError(f"unknown coding policy profile: {profile}")
        raw = resources.files("agw_gateway.coding").joinpath("policies", PROFILE_FILES[profile])
        return cls(raw.read_bytes())

    @classmethod
    def strict(cls) -> CodingPolicy:
        return cls.bundled("strict")

    # ------------------------------------------------------------------ path classes
    def is_secret(self, path: str) -> bool:
        if first_match(path, self.secret_exceptions):
            return False
        base = posixpath.basename(path)
        # A directory whose contents are secret (``~/.ssh``) is secret itself.
        return (
            bool(first_match(path, self.secret))
            or bool(first_match(path.rstrip("/") + "/_", self.secret))
            or bool(self.secret_key_name.match(base))
        )

    def is_test(self, path: str) -> bool:
        return first_match(path, self.tests) is not None

    def _owner(self, path: str) -> str:
        return next((role for g, role in self.owners if glob_match(path, g)), self.default_role)

    def read_hits(self, path: str) -> list[Hit]:
        if self.is_secret(path):
            return [Hit("SECRET-READ", "deny", "CRITICAL", f"Reading secrets is denied: {path}")]
        return [Hit("PATH-READ", "allow", "LOW", "Read of a non-secret path.")]

    def write_hits(self, path: str, *, delete: bool = False) -> list[Hit]:
        verb = "Deleting" if delete else "Writing"
        if first_match(path, self.authorized_keys) or path.startswith("~/.ssh"):
            return [Hit("PATH-SSH", "deny", "CRITICAL", "Writing SSH keys is denied.")]
        if self.is_secret(path):
            return [Hit("SECRET-WRITE", "deny", "CRITICAL", f"{verb} secret files is denied.")]
        hits: list[Hit] = []
        if delete and self.is_test(path):
            hits.append(Hit("PATH-DELETE-TEST", "ask", "CRITICAL", f"Deleting a test file: {path}"))
        if is_outside(path):
            hits.append(
                Hit(
                    "PATH-OUTSIDE-WORKSPACE",
                    "ask",
                    "CRITICAL",
                    f"{verb} outside the workspace: {path}",
                    tag="temp" if path.startswith(_TEMP_PREFIXES) else None,
                )
            )
        elif (pat := first_match(path, self.critical)) is not None:
            hits.append(
                Hit(
                    "PATH-CRITICAL",
                    "ask",
                    "CRITICAL",
                    f"{verb} a protected path ({pat}).",
                    tag="hook-config" if first_match(path, self.hook_config) else None,
                )
            )
        elif (pat := first_match(path, self.high)) is not None and first_match(
            path, self.repo_allow_paths
        ):
            hits.append(Hit("REPO-ALLOW-PATH", "allow", "MEDIUM", "Admin-approved repo exception."))
        elif (pat := first_match(path, self.high)) is not None:
            hits.append(
                Hit(
                    "PATH-HIGH",
                    "ask",
                    "HIGH",
                    f"{verb} a high-risk path ({pat}).",
                    role=self._owner(path),
                )
            )
        if not hits:
            hits.append(Hit("PATH-LOW", "allow", "LOW", "Normal source or test file."))
        return hits

    def content_hits(self, path: str, diff: str | None) -> list[Hit]:
        if diff is None:
            return [
                Hit(
                    "CONTENT-UNKNOWN",
                    "ask",
                    "MEDIUM",
                    "The change could not be inspected (no diff was provided).",
                )
            ]
        return content.scan(
            path,
            content.split_diff(diff),
            is_test=self.is_test,
            is_ci=lambda p: first_match(p, self.ci) is not None,
            is_signing=lambda p: first_match(p, self.signing) is not None,
            is_money=lambda p: first_match(p, self.money) is not None,
            is_authorized_keys=lambda p: first_match(p, self.authorized_keys) is not None,
        )

    def host_hits(self, tokens: Iterable[str]) -> list[Hit]:
        for tok in tokens:
            for m in _HOST_RE.finditer(tok):
                host = m.group(1).lower()
                if host in self.local_hosts:
                    continue
                if any(glob_match(host, pat) for pat in self.production_hosts):
                    return [Hit("NET-PRODUCTION", "deny", "CRITICAL", "Targets a production host.")]
        return []

    # ------------------------------------------------------------------ entry point
    def evaluate(
        self, action: CodingAction, diff: str | None = None, *, stage: str = "local"
    ) -> CodingDecision:
        """``stage``: "local" (the hook, on the developer's machine) or "submit" (the change
        leaving the machine). The balanced profile relaxes everyday local work only."""
        if stage not in ("local", "submit"):
            raise ValueError(f"unknown stage: {stage}")
        token = _STAGE.set(stage)
        try:
            return self._evaluate(action, diff)
        finally:
            _STAGE.reset(token)

    def _evaluate(self, action: CodingAction, diff: str | None) -> CodingDecision:
        root = action.workspace_root
        hits: list[Hit] = []
        if action.incomplete:
            hits.append(
                Hit(
                    "CODE-INCOMPLETE",
                    "ask",
                    "MEDIUM",
                    "The agent's request could not be fully interpreted.",
                )
            )
        try:
            paths = [normalize_path(p, root) for p in action.targets.paths]
        except PathInvalid:
            paths = []
            hits.append(Hit("PATH-INVALID", "deny", "HIGH", "A target path is invalid."))
        kind = action.action_type
        if kind not in KNOWN_ACTION_TYPES:
            hits.append(Hit("CODE-UNKNOWN-TYPE", "ask", "HIGH", "Unknown action type."))
        elif kind in ("file_read", "search"):
            hits.extend(self._read(paths, action))
        elif kind == "file_write":
            if not paths:
                hits.append(Hit("CODE-NO-TARGET", "ask", "HIGH", "A write without a target path."))
            for path in paths:
                hits.extend(self.write_hits(path))
                hits.extend(self.content_hits(path, diff))
        elif kind == "file_delete":
            if not paths:
                hits.append(Hit("CODE-NO-TARGET", "ask", "HIGH", "A delete without a target."))
            for path in paths:
                hits.extend(self.write_hits(path, delete=True))
        elif kind in ("command_exec", "git_op"):
            text = action.targets.command or (
                split_command_text(list(action.targets.argv)) if action.targets.argv else ""
            )
            hits.extend(self.command_hits(text, root, depth=0))
        elif kind == "web_fetch":
            hits.extend(self._web(action.targets.url))
        elif kind == "mcp_call":
            hits.extend(self._mcp(action))
        if self.profile == "balanced" and _STAGE.get() == "local":
            hits = [relaxed(h) for h in hits]
        if self.overlay_rule is not None:
            hits.append(Hit(self.overlay_rule, "allow", "LOW", "Repository overlay applied."))
        c: Combined = combine(hits, self.default_role, self.critical_role)
        return CodingDecision(
            effect=c.effect,
            level=c.level,
            rule_ids=c.rule_ids,
            reason=c.reason,
            approval_role=c.role,
            policy_id=self.policy_id,
            policy_version=self.version,
            policy_digest=self.digest,
        )

    def _read(self, paths: list[str], action: CodingAction) -> list[Hit]:
        hits: list[Hit] = []
        for path in paths:
            hits.extend(self.read_hits(path))
        if not paths:
            hits.append(Hit("PATH-READ", "allow", "LOW", "Search in the workspace."))
        return hits

    def _web(self, url: str | None) -> list[Hit]:
        if not url:
            return [Hit("WEB-NO-URL", "ask", "MEDIUM", "A web fetch without a URL.")]
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        if parts.scheme not in ("http", "https") or not host:
            return [Hit("WEB-SCHEME", "deny", "HIGH", "Only http(s) URLs may be fetched.")]
        prod = self.host_hits([host])
        if prod:
            return prod
        if host in self.web_allow and not parts.query:
            return [Hit("WEB-DOCS", "allow", "LOW", "Fetch from an allowed documentation host.")]
        return [
            Hit("WEB-ASK", "ask", "MEDIUM", f"Fetch from a host that is not allowlisted: {host}")
        ]

    def _mcp(self, action: CodingAction) -> list[Hit]:
        mcp = action.targets.mcp
        if mcp is None:
            return [Hit("MCP-UNKNOWN", "ask", "HIGH", "An MCP call without a tool name.")]
        name = f"{mcp.server or '?'}/{mcp.tool}"
        if any(glob_match(name, pat) for pat in self.mcp_deny):
            return [Hit("MCP-DENIED", "deny", "HIGH", f"MCP tool is denied: {name}")]
        if any(glob_match(name, pat) for pat in self.mcp_allow):
            return [Hit("MCP-ALLOWED", "allow", "LOW", "Allowlisted MCP tool.")]
        return [Hit("MCP-ASK", "ask", "MEDIUM", f"MCP tool is not allowlisted: {name}")]

    # ------------------------------------------------------------------ commands
    def command_hits(self, text: str, root: str | None, depth: int) -> list[Hit]:
        if not text.strip():
            return [Hit("CMD-EMPTY", "ask", "MEDIUM", "Empty command.")]
        if depth > 3:
            return [Hit("CMD-TOO-NESTED", "ask", "HIGH", "Command nesting is too deep.")]
        try:
            parsed = parse(text)
        except CommandUnparseable:
            return [Hit("CMD-UNPARSEABLE", "ask", "HIGH", "The command could not be parsed.")]
        hits: list[Hit] = []
        for inner in parsed.substitutions:
            hits.extend(self.command_hits(inner, root, depth + 1))
        hits.extend(self.host_hits([text]))
        if not parsed.segments:
            hits.append(Hit("CMD-EMPTY", "ask", "MEDIUM", "Empty command."))
        for seg in parsed.segments:
            hits.extend(self._segment(seg, root, depth))
        return hits

    def _path(self, raw: str, root: str | None) -> str | None:
        try:
            return normalize_path(raw, root)
        except PathInvalid:
            return None

    def _redirects(self, seg: Segment, root: str | None) -> list[Hit]:
        hits: list[Hit] = []
        body = "\n".join(seg.heredocs) if seg.heredocs else None
        for op, target in seg.redirects:
            if target in ("/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty"):
                continue
            path = self._path(target, root)
            if path is None or SUBST_TOKEN in target:
                hits.append(Hit("CMD-REDIRECT-UNKNOWN", "ask", "HIGH", "Unclear redirection."))
                continue
            if op in WRITE_REDIRECTS:
                hits.extend(self.write_hits(path))
                hits.extend(self.content_hits(path, body))
            else:
                hits.extend(self.read_hits(path))
        return hits

    def _segment(self, seg: Segment, root: str | None, depth: int) -> list[Hit]:
        hits = self._redirects(seg, root)
        argv = list(seg.argv)
        while argv and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", argv[0]):
            argv.pop(0)  # VAR=value prefix
        if not argv:
            return hits or [Hit("CMD-ASSIGN", "allow", "LOW", "Variable assignment.")]
        argv = self._unwrap(argv)
        if not argv:
            return [*hits, Hit("CMD-ENV-PRINT", "deny", "CRITICAL", "Printing the environment.")]
        text = " ".join(argv)
        if any(text == c or text.startswith(c + " ") for c in self.repo_deny_commands):
            return [*hits, Hit("CMD-REPO-DENY", "deny", "HIGH", "Denied by the repository policy.")]
        exe = posixpath.basename(argv[0])
        args = argv[1:]
        if seg.piped_in and (exe in self.cmd["shells"] or exe in self.cmd["interpreters"]):
            return [*hits, Hit("CMD-PIPE-TO-SHELL", "deny", "CRITICAL", "Piping into a shell.")]
        if exe in self.cmd["shells"] or exe == "eval":
            return hits + self._shell(exe, args, root, depth, seg)
        own = self._exe(exe, args, root, depth)
        if (
            own
            and all(h.rule == "CMD-UNKNOWN" for h in own)
            and any(text == c or text.startswith(c + " ") for c in self.repo_allow_commands)
        ):
            own = [Hit("REPO-ALLOW-CMD", "allow", "LOW", "Admin-approved repo command.")]
        return hits + own

    def _unwrap(self, argv: list[str]) -> list[str]:
        """Strip harmless wrappers (time, nice, nohup, timeout, command, exec, xargs, env)."""
        while argv:
            exe = posixpath.basename(argv[0])
            if exe in ("time", "nohup", "command", "builtin", "exec", "caffeinate"):
                argv = [a for a in argv[1:] if not (a.startswith("-") and argv[0] == "time")]
                continue
            if exe in ("nice", "ionice", "stdbuf"):
                rest = argv[1:]
                while rest and rest[0].startswith("-"):
                    rest = rest[2:] if rest[0] in ("-n", "-c") else rest[1:]
                argv = rest
                continue
            if exe in ("timeout", "gtimeout"):
                rest = [a for a in argv[1:] if not a.startswith("-")]
                argv = rest[1:]
                continue
            if exe == "xargs":
                rest = argv[1:]
                while rest and rest[0].startswith("-"):
                    rest = rest[2:] if rest[0] in ("-n", "-I", "-L", "-P", "-d", "-E") else rest[1:]
                argv = rest or ["echo"]
                continue
            if exe in self.cmd["env_print"] and exe == "env":
                rest = argv[1:]
                while rest and (rest[0].startswith("-") or "=" in rest[0]):
                    rest = rest[1:]
                return rest  # empty -> printing the environment
            return argv
        return argv

    def _shell(
        self, exe: str, args: list[str], root: str | None, depth: int, seg: Segment
    ) -> list[Hit]:
        if exe == "eval":
            return self.command_hits(" ".join(args), root, depth + 1)
        if "-c" in args:
            i = args.index("-c")
            if i + 1 < len(args):
                return self.command_hits(args[i + 1], root, depth + 1)
        if not args and (seg.heredocs or seg.piped_in):
            return [Hit("CMD-PIPE-TO-SHELL", "deny", "CRITICAL", "Feeding a script to a shell.")]
        return [Hit("CMD-SCRIPT", "ask", "HIGH", "Running a shell script.")]

    def _exe(self, exe: str, args: list[str], root: str | None, depth: int) -> list[Hit]:
        cmd = self.cmd
        joined = " ".join(args)
        if exe in cmd["privilege"]:
            return [Hit("CMD-PRIVILEGE", "deny", "CRITICAL", f"{exe} is denied.")]
        if exe in cmd["network"]:
            return [
                Hit(
                    "CMD-NETWORK",
                    "deny",
                    "CRITICAL",
                    f"Network tool {exe} is denied.",
                    tag=self._net_tag(exe, args),
                )
            ]
        if exe in cmd["deploy"]:
            return [Hit("CMD-DEPLOY", "deny", "CRITICAL", f"Deployment tool {exe} is denied.")]
        if exe in cmd["package_runners"]:
            return [Hit("CMD-PACKAGE-RUNNER", "deny", "HIGH", f"{exe} runs unvetted packages.")]
        if exe in cmd["env_print"]:
            return [Hit("CMD-ENV-PRINT", "deny", "CRITICAL", "Printing the environment.")]
        if exe in ("set", "export", "declare", "typeset"):
            if not args or any(a in ("-p", "-x", "-px") for a in args):
                return [Hit("CMD-ENV-PRINT", "deny", "CRITICAL", "Printing the environment.")]
            return [Hit("CMD-SHELL-SETTING", "allow", "LOW", "Shell setting.")]
        if exe in ("echo", "printf") and _SECRET_VAR.search(joined):
            return [Hit("CMD-ENV-PRINT", "deny", "CRITICAL", "Printing a secret variable.")]
        if exe in cmd["interpreters"]:
            return self._interpreter(exe, args)
        if exe == "git":
            return self._git(args, root)
        if exe == "pnpm":
            return self._pnpm(args)
        if exe in ("npm", "yarn"):
            return self._npm(exe, args)
        if exe == "make":
            targets = [a for a in args if not a.startswith("-") and "=" not in a]
            if targets and all(t in cmd["make_allowed"] for t in targets):
                return [Hit("CMD-ALLOW", "allow", "LOW", "Allowed make target.")]
            return [Hit("CMD-UNKNOWN", "ask", "MEDIUM", "make target is not on the allowlist.")]
        if exe in ("drizzle-kit", "tsx") and any(
            a in ("push", "migrate", "generate", "drop") for a in args
        ):
            return [Hit("CMD-MIGRATION", "ask", "HIGH", "Database migration command.")]
        if exe == "docker":
            if any(a == "--privileged" or a.startswith("--privileged=") for a in args) or any(
                a.startswith("/:") or a in ("/:/host", "/:/mnt") for a in args
            ):
                return [Hit("CMD-DOCKER-PRIVILEGED", "deny", "CRITICAL", "Privileged container.")]
            return [Hit("CMD-DOCKER", "ask", "MEDIUM", "Docker command.")]
        if exe in ("chmod", "chown", "chgrp", "chattr", "chflags"):
            return self._chmod(exe, args, root)
        if exe in ("rm", "rmdir", "unlink", "shred"):
            return self._rm(exe, args, root)
        if exe in ("mv", "cp", "ln", "install", "rsync"):
            return self._copy(exe, args, root)
        if exe == "tee":
            hits: list[Hit] = []
            for a in args:
                if not a.startswith("-") and (p := self._path(a, root)):
                    hits.extend(self.write_hits(p))
                    hits.extend(self.content_hits(p, None))
            return hits or [Hit("CMD-ALLOW", "allow", "LOW", "tee to stdout.")]
        if exe in ("sed", "perl") and any(a == "-i" or a.startswith("-i") for a in args):
            return self._in_place(args, root)
        if exe in cmd["readers"] or exe == "sed":
            return self._reader(args, root, skip_first=exe == "sed")
        if exe in cmd["searchers"]:
            return self._searcher(args, root)
        if exe == "find":
            if any(a in ("-exec", "-execdir", "-delete", "-ok", "-okdir", "-fprint") for a in args):
                return [
                    Hit(
                        "CMD-FIND-EXEC",
                        "ask",
                        "MEDIUM",
                        "find with -exec / -delete.",
                        tag="delete" if "-delete" in args or "rm" in args else None,
                    )
                ]
            return [Hit("CMD-ALLOW", "allow", "LOW", "Read-only find.")]
        if exe in cmd["harmless"]:
            return self._reader(args, root, skip_first=False, harmless=True)
        if exe in ("tsc", "vitest", "eslint", "prettier", "playwright"):
            if exe == "tsc" and "--noEmit" not in args:
                return [Hit("CMD-UNKNOWN", "ask", "MEDIUM", "tsc that emits files.")]
            if exe in ("eslint", "prettier") and any(a in ("--fix", "--write", "-w") for a in args):
                return [Hit("CMD-UNKNOWN", "ask", "MEDIUM", "Formatter that rewrites files.")]
            return [Hit("CMD-ALLOW", "allow", "LOW", "Allowed developer tool.")]
        return [Hit("CMD-UNKNOWN", "ask", "MEDIUM", f"Command is not on the allowlist: {exe}")]

    def _interpreter(self, exe: str, args: list[str]) -> list[Hit]:
        inline = next(
            (
                args[i + 1]
                for i, a in enumerate(args[:-1])
                if a in ("-e", "-p", "--eval", "--print", "-c")
            ),
            None,
        )
        if inline is not None:
            if _ENV_DUMP.search(inline) or (
                _ENV_ANY.search(inline)
                and re.search(r"console\.log|print\(|JSON\.stringify", inline)
            ):
                return [Hit("CMD-ENV-PRINT", "deny", "CRITICAL", "Printing the environment.")]
            return [Hit("CMD-INLINE-CODE", "ask", "HIGH", f"Inline {exe} code.")]
        return [Hit("CMD-UNKNOWN", "ask", "MEDIUM", f"Running {exe} scripts needs approval.")]

    def _git(self, args: list[str], root: str | None) -> list[Hit]:
        hits: list[Hit] = []
        rest = list(args)
        while rest and rest[0].startswith("-"):
            opt = rest.pop(0)
            if opt in ("-c", "--config-env") and rest:
                kv = rest.pop(0).lower()
                if kv.startswith(("credential", "core.hookspath", "core.sshcommand", "url.")):
                    return [
                        Hit("GIT-CONFIG-DENIED", "deny", "CRITICAL", "Dangerous git -c option.")
                    ]
                hits.append(Hit("GIT-CONFIG", "ask", "MEDIUM", "git -c option."))
            elif opt in ("-C", "--git-dir", "--work-tree") and rest:
                rest.pop(0)
        if not rest:
            return [*hits, Hit("CMD-ALLOW", "allow", "LOW", "git.")]
        sub, sargs = rest[0], rest[1:]
        if sub == "push":
            return [Hit("GIT-PUSH", "deny", "HIGH", "git push is denied; the developer pushes.")]
        if sub == "remote" and sargs and sargs[0] in ("add", "set-url", "rename", "remove", "rm"):
            return [Hit("GIT-REMOTE", "deny", "HIGH", "Changing git remotes is denied.")]
        if sub == "config":
            keys = [a.lower() for a in sargs if not a.startswith("-")]
            if any(
                k.startswith(("credential", "core.hookspath", "core.sshcommand", "url."))
                for k in keys
            ):
                return [Hit("GIT-CONFIG-DENIED", "deny", "CRITICAL", "Dangerous git config.")]
            if (
                any(a in ("--get", "--get-all", "--list", "-l", "--get-regexp") for a in sargs)
                or len(keys) <= 1
            ):
                return [*hits, Hit("CMD-ALLOW", "allow", "LOW", "Reading git config.")]
            return [*hits, Hit("GIT-CONFIG", "ask", "MEDIUM", "Changing git config.")]
        for a in sargs:  # git show HEAD:.env, git add .env, git diff -- secrets
            candidate = a.split(":", 1)[1] if ":" in a and sub == "show" else a
            if candidate.startswith("-") or not candidate:
                continue
            p = self._path(candidate, root)
            if p is not None and self.is_secret(p):
                return [Hit("SECRET-READ", "deny", "CRITICAL", "git on a secret file is denied.")]
        if sub == "commit" and any(a in ("--no-verify", "-n") for a in sargs):
            return [*hits, Hit("GIT-NO-VERIFY", "ask", "HIGH", "Commit that skips git hooks.")]
        if sub in ("checkout", "switch"):
            if sargs and sargs[0] in ("-b", "-c", "--create"):
                return [*hits, Hit("CMD-ALLOW", "allow", "LOW", "New branch.")]
            discards = "--" in sargs or "." in sargs or any(a in ("-f", "--force") for a in sargs)
            return [
                *hits,
                Hit(
                    "GIT-ASK",
                    "ask",
                    "MEDIUM",
                    f"git {sub} can discard work.",
                    tag="destructive" if discards else None,
                ),
            ]
        if sub in self.cmd["git_allowed"]:
            return [*hits, Hit("CMD-ALLOW", "allow", "LOW", f"git {sub}.")]
        if sub in self.cmd["git_read_only"] and (
            not sargs
            or all(
                a.startswith("-") and a not in ("-D", "-d", "--delete", "-m", "-M") for a in sargs
            )
        ):
            return [*hits, Hit("CMD-ALLOW", "allow", "LOW", f"Read-only git {sub}.")]
        destructive = (
            (sub == "reset" and "--hard" in sargs)
            or sub
            in ("clean", "filter-branch", "filter-repo", "update-ref", "reflog", "gc", "prune")
            or (sub == "branch" and any(a in ("-D", "-d", "--delete", "-M", "-m") for a in sargs))
            or (sub == "stash" and sargs[:1] in (["drop"], ["clear"]))
            or (sub == "rebase")
        )
        return [
            *hits,
            Hit(
                "GIT-ASK",
                "ask",
                "MEDIUM",
                f"git {sub} needs approval.",
                tag="destructive" if destructive else None,
            ),
        ]

    def _net_tag(self, exe: str, args: list[str]) -> str | None:
        """curl-like tools only: "local-net" when every URL is a local host (uploads allowed:
        testing your own API) or, without an upload, an allowed documentation host. Anything
        else gets no tag and stays DENIED, as do remote shells / copies (ssh, scp, nc, ...)."""
        if exe not in ("curl", "wget", "http", "httpie", "xh"):
            return None
        uploads = ("-d", "--data", "--data-binary", "--data-raw", "--data-urlencode", "-F",
                   "--form", "-T", "--upload-file", "--post-file", "--post-data")  # fmt: skip
        upload = any(a in uploads or a.startswith(("--data", "--form", "--upload")) for a in args)
        hosts: list[str] = []
        for a in args:  # only URLs and bare host[:port][/path] operands; never option values
            if "://" in a:
                try:
                    host = urlsplit(a).hostname
                except ValueError:
                    return None
                if not host:
                    return None
                hosts.append(host.lower())
            elif m := _BARE_HOST.match(a):
                hosts.append(m.group(1).lower().strip("[]"))
        if hosts and all(h in self.local_hosts for h in hosts):
            return "local-net"
        if upload:
            return None
        if hosts and all(h in self.local_hosts or h in self.web_allow for h in hosts):
            return "local-net"
        return None  # any other host: denied, as in the strict profile

    def _pnpm(self, args: list[str]) -> list[Hit]:
        rest = list(args)
        while rest and rest[0].startswith("-"):
            opt = rest.pop(0)
            if opt in ("--filter", "-F", "-C", "--dir", "--workspace") and rest:
                rest.pop(0)
        if not rest:
            return [Hit("CMD-UNKNOWN", "ask", "MEDIUM", "pnpm without a command.")]
        sub, sargs = rest[0], rest[1:]
        if sub in ("dlx", "create", "exec") and sub != "exec":
            return [
                Hit("CMD-PACKAGE-RUNNER", "deny", "HIGH", f"pnpm {sub} runs unvetted packages.")
            ]
        if sub in ("publish", "login", "adduser", "token"):
            return [Hit("CMD-PUBLISH", "deny", "CRITICAL", f"pnpm {sub} is denied.")]
        if sub in ("install", "i"):
            if "--frozen-lockfile" in sargs and not [a for a in sargs if not a.startswith("-")]:
                return [Hit("CMD-ALLOW", "allow", "LOW", "Frozen-lockfile install.")]
            return [Hit("PKG-INSTALL", "ask", "HIGH", "Install that may change the lockfile.")]
        if sub in ("add", "update", "up", "upgrade", "remove", "rm", "uninstall", "link"):
            return [Hit("PKG-ADD", "ask", "HIGH", f"pnpm {sub} changes dependencies.")]
        if sub == "exec":
            return (
                self._exe(posixpath.basename(sargs[0]), sargs[1:], None, 0)
                if sargs
                else [Hit("CMD-UNKNOWN", "ask", "MEDIUM", "pnpm exec without a command.")]
            )
        if sub == "run":
            sub, sargs = (sargs[0], sargs[1:]) if sargs else ("", [])
        if sub in self.cmd["pnpm_migration_scripts"]:
            return [Hit("CMD-MIGRATION", "ask", "HIGH", "Database migration command.")]
        if sub == "tsc":
            ok = "--noEmit" in sargs
            return (
                [Hit("CMD-ALLOW", "allow", "LOW", "Type check.")]
                if ok
                else [Hit("CMD-UNKNOWN", "ask", "MEDIUM", "tsc that emits files.")]
            )
        if sub == "playwright":
            if sargs[:1] == ["test"]:
                return [Hit("CMD-ALLOW", "allow", "LOW", "Playwright tests.")]
            return [Hit("CMD-UNKNOWN", "ask", "MEDIUM", "playwright subcommand.")]
        if sub == "drizzle-kit":
            return [Hit("CMD-MIGRATION", "ask", "HIGH", "Database migration command.")]
        if sub in self.cmd["pnpm_allowed"] or sub in self.cmd["pnpm_allowed_scripts"]:
            return [Hit("CMD-ALLOW", "allow", "LOW", f"pnpm {sub}.")]
        return [Hit("CMD-UNKNOWN", "ask", "MEDIUM", f"pnpm {sub} is not on the allowlist.")]

    def _npm(self, exe: str, args: list[str]) -> list[Hit]:
        sub = next((a for a in args if not a.startswith("-")), "")
        rest = args[args.index(sub) + 1 :] if sub else []
        if sub in ("exec", "x", "dlx", "create", "init"):
            return [Hit("CMD-PACKAGE-RUNNER", "deny", "HIGH", f"{exe} {sub} runs packages.")]
        if sub in ("publish", "login", "adduser", "token"):
            return [Hit("CMD-PUBLISH", "deny", "CRITICAL", f"{exe} {sub} is denied.")]
        if sub == "ci":
            return [Hit("CMD-ALLOW", "allow", "LOW", "Clean install from the lockfile.")]
        if sub in ("install", "i", "add", "update", "remove", "uninstall", ""):
            return [
                Hit("PKG-ADD", "ask", "HIGH", f"{exe} {sub or 'install'} changes dependencies.")
            ]
        if sub in ("test", "t") or (
            sub == "run" and rest[:1] and rest[0] in self.cmd["pnpm_allowed_scripts"]
        ):
            return [Hit("CMD-ALLOW", "allow", "LOW", f"{exe} test.")]
        return [Hit("CMD-UNKNOWN", "ask", "MEDIUM", f"{exe} {sub} is not on the allowlist.")]

    def _operands(self, args: list[str]) -> list[str]:
        out: list[str] = []
        after_dd = False
        for a in args:
            if a == "--" and not after_dd:
                after_dd = True
                continue
            if after_dd or not a.startswith("-"):
                out.append(a)
        return out

    def _reader(
        self, args: list[str], root: str | None, *, skip_first: bool, harmless: bool = False
    ) -> list[Hit]:
        operands = self._operands(args)
        if skip_first and operands:
            operands = operands[1:]
        hits: list[Hit] = []
        for a in operands:
            if SUBST_TOKEN in a:
                continue
            p = self._path(a, root)
            if p is not None and self.is_secret(p):
                return [Hit("SECRET-READ", "deny", "CRITICAL", f"Reading secrets is denied: {p}")]
        hits.append(Hit("CMD-ALLOW", "allow", "LOW", "Read-only command on non-secret paths."))
        return hits

    def _searcher(self, args: list[str], root: str | None) -> list[Hit]:
        explicit_pattern = any(a in ("-e", "--regexp", "-f", "--file") for a in args)
        files = [args[i + 1] for i, a in enumerate(args[:-1]) if a in ("-f", "--file")]
        for f in files:
            p = self._path(f, root)
            if p is not None and self.is_secret(p):
                return [Hit("SECRET-READ", "deny", "CRITICAL", "Reading secrets is denied.")]
        return self._reader(args, root, skip_first=not explicit_pattern)

    def _chmod(self, exe: str, args: list[str], root: str | None) -> list[Hit]:
        for a in args:  # every argument: "-x" is a valid chmod mode, not only a flag
            p = self._path(a, root)
            if p is not None and first_match(p, self.hook_config):
                return [
                    Hit("CMD-CHMOD-HOOKS", "deny", "CRITICAL", "Changing hook/config permissions.")
                ]
        return [Hit("CMD-CHMOD", "ask", "MEDIUM", f"{exe} needs approval.")]

    def _rm(self, exe: str, args: list[str], root: str | None) -> list[Hit]:
        recursive = any(
            a.startswith("-") and ("r" in a.lower() or a == "--recursive") for a in args
        )
        operands = self._operands(args)
        if not operands:
            return [Hit("CMD-UNKNOWN", "ask", "MEDIUM", "rm without operands.")]
        hits: list[Hit] = []
        for a in operands:
            if any(ch in a for ch in "*?[") or SUBST_TOKEN in a or a.startswith("$"):
                hits.append(Hit("CMD-RM-GLOB", "ask", "HIGH", "rm with a wildcard or variable."))
                continue
            p = self._path(a, root)
            if p is None or p in (".", "/", "~") or is_outside(p):
                hits.append(Hit("CMD-RM-OUTSIDE", "deny", "CRITICAL", "rm outside the workspace."))
                continue
            if first_match(p, self.build_artifacts):
                hits.append(Hit("CMD-ALLOW", "allow", "LOW", "Removing build output."))
                continue
            if recursive:
                hits.append(
                    Hit("CMD-RM-RECURSIVE", "ask", "HIGH", "Recursive delete in the workspace.")
                )
            hits.extend(self.write_hits(p, delete=True))
        return hits

    def _copy(self, exe: str, args: list[str], root: str | None) -> list[Hit]:
        operands = [o for o in self._operands(args) if SUBST_TOKEN not in o]
        if exe == "rsync" or any(re.match(r"^[^/]+:", o) for o in operands):
            return [Hit("CMD-NETWORK", "deny", "CRITICAL", "Remote copy is denied.")]
        if len(operands) < 2:
            return [Hit("CMD-UNKNOWN", "ask", "MEDIUM", f"{exe} with unclear operands.")]
        hits: list[Hit] = []
        for src in operands[:-1]:
            p = self._path(src, root)
            if p is None:
                continue
            hits.extend(self.read_hits(p))
            if exe == "mv":
                hits.extend(self.write_hits(p, delete=True))
        dest = self._path(operands[-1], root)
        if dest is not None:
            hits.extend(self.write_hits(dest))
            if not is_outside(dest):
                hits.extend(self.content_hits(dest, ""))  # content unchanged by a copy
        return hits

    def _in_place(self, args: list[str], root: str | None) -> list[Hit]:
        operands = self._operands(args)[1:]
        hits: list[Hit] = []
        for a in operands:
            p = self._path(a, root)
            if p is not None:
                hits.extend(self.write_hits(p))
                hits.extend(self.content_hits(p, None))  # the edit is a script: no diff
        return hits or [Hit("CMD-UNKNOWN", "ask", "MEDIUM", "In-place edit.")]


def relaxed(h: Hit) -> Hit:
    """The balanced profile, on the developer's machine: everyday asks become "allow
    (recorded)"; denies and crucial asks stay. Pure."""
    note = " Allowed and recorded (balanced profile); checked again on submit."
    if h.rule == "CMD-NETWORK" and h.tag == "local-net":
        return Hit(h.rule, "allow", "LOW", h.reason + " Local or documentation host: allowed.")
    if h.effect != "ask":
        return h
    if h.rule == "PATH-OUTSIDE-WORKSPACE":
        if h.tag == "temp":
            return Hit(h.rule, "allow", "LOW", "Temporary file outside the repository.")
        return Hit(h.rule, "ask", "HIGH", h.reason, h.role)
    if h.rule == "PATH-CRITICAL" and h.tag == "hook-config":
        return h  # the agent editing its own guard: always a human
    if h.rule in ("GIT-ASK", "CMD-FIND-EXEC"):
        return h if h.tag in ("destructive", "delete") else Hit(h.rule, "allow", "LOW", h.reason)
    if h.rule == "PATH-CRITICAL" or h.rule in _RELAX_LOCAL:
        level = "MEDIUM" if h.level in ("HIGH", "CRITICAL") else h.level
        return Hit(h.rule, "allow", level, h.reason + note)
    return h
