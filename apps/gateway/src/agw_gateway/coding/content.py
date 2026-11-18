"""Content rules evaluated on the DIFF of a file write (C1 §4). Pure: no I/O.

Input is a unified diff (``+``/``-`` lines; ``+++``/``---`` headers ignored), the agent's
own patch format (Codex ``apply_patch``: ``+``/``-`` lines too), or, for a brand-new file or
a here-document, plain text treated as all-added. Each rule is a fixed regular expression or
a token count; none of them executes anything and none of them reports matched text: a
finding names the rule, never the content (the diff may hold a secret).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

from agw_gateway.coding.rules import Hit


@dataclass(frozen=True)
class DiffLines:
    added: tuple[str, ...]
    removed: tuple[str, ...]


def split_diff(diff: str) -> DiffLines:
    lines = diff.splitlines()
    looks_unified = any(
        ln.startswith(("@@", "--- ", "+++ ", "*** Begin Patch", "*** Update File")) for ln in lines
    )
    if not looks_unified:
        return DiffLines(tuple(lines), ())
    added: list[str] = []
    removed: list[str] = []
    for ln in lines:
        if ln.startswith(("+++", "---", "***")):
            continue
        if ln.startswith("+"):
            added.append(ln[1:])
        elif ln.startswith("-"):
            removed.append(ln[1:])
    return DiffLines(tuple(added), tuple(removed))


def _count(pattern: re.Pattern[str], lines: tuple[str, ...]) -> int:
    return sum(len(pattern.findall(ln)) for ln in lines)


def _any(pattern: re.Pattern[str], lines: tuple[str, ...]) -> bool:
    return any(pattern.search(ln) for ln in lines)


# ------------------------------------------------------------------ signature verification
_SIG_TOKENS: Final = re.compile(
    r"MintRail-Signature|SIGNATURE_HEADER|verifyWebhook|signatures\.verify|timingSafeEqual"
    r"|createHmac|verifySignature|\bverify\s*\("
)
_SIG_BYPASS: Final = re.compile(
    r"(?i)(skip|disable|bypass|ignore|no)[_-]?(webhook[_-]?)?(sig(nature)?s?|hmac|verif\w*)\b"
    r"|verify\w*\s*[:=]\s*(async\s*)?\(\s*[^)]*\)\s*=>\s*(true|\{\s*\}|undefined|null)"
)
_RETURN_TRUE: Final = re.compile(r"^\s*return\s+(true|0|null|undefined)\s*;?\s*(//.*)?$")

# ------------------------------------------------------------------------------- tests
_TEST_SKIP: Final = re.compile(
    r"\b(it|test|describe|suite|bench|context)\s*\.\s*(skip|only|todo|fails|skipIf|runIf)\b"
    r"|\b(xit|xdescribe|xtest|fit|fdescribe|ftest)\s*\("
)
_TEST_CASE: Final = re.compile(r"\b(it|test)\s*(\.\s*\w+\s*)?\(\s*['\"`]")

# ------------------------------------------------------------------------------- money
_BIGINT: Final = re.compile(r"\bbigint\b|\bBigInt\s*\(|\b\d[\d_]*n\b")
_NUMBERISH: Final = re.compile(r"\bnumber\b|\bNumber\s*\(|\bparseFloat\s*\(|\bparseInt\s*\(")
_MONEY_TO_NUMBER: Final = re.compile(
    r"(?i)(Number|parseFloat|parseInt|Math\.(round|floor|ceil))\s*\(\s*[\w.\[\]'\"]*"
    r"(amount|minor|cents|balance|fee|total|price|money|value|units)"
    r"|(amount|minor|cents|balance|fee|total|price|money)\w*\s*:\s*number\b"
    r"|\.toNumber\s*\(\s*\)"
)

# ----------------------------------------------------------------------------- secrets
_SECRET_PATTERNS: Final = (
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"),
    re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\b[rs]k_live_[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bmr_live_[A-Za-z0-9]{20,}\b"),  # MintRail live API key
    re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
    re.compile(
        r"(?i)\b(postgres(ql)?|mysql|mongodb(\+srv)?|redis|amqps?)://[^:\s/@]+:[^@\s]{3,}@"
        r"(?!(localhost|127\.0\.0\.1|0\.0\.0\.0|postgres|db)\b)"
    ),
)
_GENERIC_SECRET: Final = re.compile(
    r"""(?ix)\b\w*?(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token
        |client[_-]?secret|private[_-]?key|signing[_-]?key|webhook[_-]?secret)\b["']?
        \s*[:=]\s*["']([^"'\s]{8,})["']"""
)
_PLACEHOLDER: Final = re.compile(
    r"(?i)^(<.*>|\$\{.*\}|.*(changeme|example|placeholder|dummy|redacted|xxxx|your[_-]|test|"
    r"fake|sample|todo).*)$"
)

# --------------------------------------------------------------------------------- SSH
_SSH_KEY_LINE: Final = re.compile(r"^\s*(ssh-(rsa|ed25519|dss)|ecdsa-sha2-|sk-ssh-|sk-ecdsa-)")

# ---------------------------------------------------------------------------------- CI
_CI_DISABLE: Final = re.compile(
    r"^\s*-?\s*if:\s*(false|0|'false'|\"false\"|\$\{\{\s*false\s*\}\})\s*$"
    r"|continue-on-error:\s*true"
    r"|^\s*#\s*-?\s*(run|uses|name):"
)
_CI_STEP: Final = re.compile(
    r"(run:.*\b(pnpm|npm|yarn|make|npx)\b.*\b(test|lint|typecheck|build|audit|coverage|tsc)\b)"
    r"|(uses:\s*\S*(codeql|audit|scan|gitleaks|test)\S*)",
    re.IGNORECASE,
)

# ------------------------------------------------------------------------ package.json
_DEP_SECTION: Final = re.compile(
    r'"(dependencies|devDependencies|peerDependencies|optionalDependencies'
    r'|bundledDependencies|overrides|resolutions|pnpm)"\s*:'
)
_DEP_SPEC: Final = re.compile(
    r'^\s*"(@?[\w.\-]+(/[\w.\-]+)?)"\s*:\s*"(workspace:|link:|file:|npm:|git[+:]|github:|https?:'
    r"|[~^<>=*]|\d|latest|next|catalog:)"
)


def secret_in(lines: tuple[str, ...]) -> bool:
    for ln in lines:
        if any(p.search(ln) for p in _SECRET_PATTERNS):
            return True
        for m in _GENERIC_SECRET.finditer(ln):
            if not _PLACEHOLDER.match(m.group(2)):
                return True
    return False


def scan(
    path: str,
    diff: DiffLines,
    *,
    is_test: Callable[[str], bool],
    is_ci: Callable[[str], bool],
    is_signing: Callable[[str], bool],
    is_money: Callable[[str], bool],
    is_authorized_keys: Callable[[str], bool],
) -> list[Hit]:
    """All content findings for one file's diff (deny unless stated)."""
    a, r = diff.added, diff.removed
    hits: list[Hit] = []
    if secret_in(a):
        hits.append(
            Hit("CONTENT-SECRET", "deny", "CRITICAL", "The change adds a hardcoded credential.")
        )
    if _count(_SIG_TOKENS, r) > _count(_SIG_TOKENS, a) or _any(_SIG_BYPASS, a):
        hits.append(
            Hit(
                "CONTENT-SIGNATURE-BYPASS",
                "deny",
                "CRITICAL",
                "The change removes or bypasses MintRail-Signature / HMAC verification.",
            )
        )
    elif is_signing(path) and _any(_RETURN_TRUE, a):
        hits.append(
            Hit(
                "CONTENT-SIGNATURE-BYPASS",
                "deny",
                "CRITICAL",
                "The change short-circuits signature verification code.",
            )
        )
    if is_test(path):
        if _any(_TEST_SKIP, a):
            hits.append(
                Hit(
                    "CONTENT-TEST-SKIP",
                    "deny",
                    "HIGH",
                    "The change adds .skip / .only / .todo to tests.",
                )
            )
        if _count(_TEST_CASE, r) > _count(_TEST_CASE, a):
            hits.append(
                Hit(
                    "CONTENT-TEST-REMOVED",
                    "ask",
                    "CRITICAL",
                    "The change removes test cases.",
                )
            )
    if (_count(_BIGINT, r) > _count(_BIGINT, a) and _any(_NUMBERISH, a)) or (
        _any(_MONEY_TO_NUMBER, a) and (is_money(path) or _any(_BIGINT, r))
    ):
        hits.append(
            Hit(
                "CONTENT-MONEY-NUMBER",
                "deny",
                "CRITICAL",
                "The change converts bigint money to number.",
            )
        )
    if (is_authorized_keys(path) and (a or _any(_SSH_KEY_LINE, a))) or (
        _any(_SSH_KEY_LINE, a) and "/.ssh/" in f"/{path}"
    ):
        hits.append(
            Hit("CONTENT-AUTHORIZED-KEYS", "deny", "CRITICAL", "The change adds an SSH key.")
        )
    if is_ci(path) and (_any(_CI_DISABLE, a) or _count(_CI_STEP, r) > _count(_CI_STEP, a)):
        hits.append(
            Hit("CONTENT-CI-DISABLED", "deny", "CRITICAL", "The change disables a CI step.")
        )
    if path.rsplit("/", 1)[-1].lower() == "package.json" and (
        _any(_DEP_SECTION, a + r) or _any(_DEP_SPEC, a + r)
    ):
        hits.append(
            Hit(
                "PATH-CRITICAL-DEPENDENCIES",
                "ask",
                "CRITICAL",
                "The change edits package.json dependency sections.",
            )
        )
    return hits
