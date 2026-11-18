"""Shell command parsing for the coding policy. Pure: no I/O, nothing is ever executed.

The parser is deliberately conservative. It splits a command line into simple commands
(``;``, ``&&``, ``||``, ``&``, ``|``, newlines, subshell parentheses), records redirections,
pipes and here-documents, and lifts every command substitution (``$(..)``, backticks,
``<(..)``, ``>(..)``) out so the policy evaluates the inner command too. Anything it cannot
tokenize raises :class:`CommandUnparseable` and the policy asks a human.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from typing import Final

MAX_COMMAND_LEN: Final = 65536
MAX_DEPTH: Final = 4
SEPARATORS: Final = frozenset({";", "&&", "||", "&", "|", "|&", "(", ")", ";;"})
REDIRECTS: Final = frozenset({">", ">>", ">|", "&>", "&>>", "<", "<<", "<<-", "<<<", ">&", "<&"})
WRITE_REDIRECTS: Final = frozenset({">", ">>", ">|", "&>", "&>>"})
SUBST_TOKEN: Final = "__AGW_SUBST__"  # noqa: S105 - a placeholder, not a secret
_HEREDOC_RE: Final = re.compile(r"<<(-?)\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\2")


class CommandUnparseable(ValueError):
    """The command line cannot be tokenized reliably (unbalanced quotes, too long, NUL)."""


@dataclass
class Segment:
    argv: list[str] = field(default_factory=list)
    redirects: list[tuple[str, str]] = field(default_factory=list)  # (operator, target)
    piped_in: bool = False  # receives another command's stdout
    heredocs: list[str] = field(default_factory=list)  # here-document bodies (data)


@dataclass
class Parsed:
    segments: list[Segment]
    substitutions: list[str]  # inner command texts, evaluated recursively by the policy
    background: bool = False


def _extract_heredocs(text: str) -> tuple[str, list[str]]:
    """Remove here-document bodies (data, not commands); return (text, bodies)."""
    lines = text.split("\n")
    out: list[str] = []
    bodies: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        pending = list(_HEREDOC_RE.finditer(line))
        if not pending:
            out.append(line)
            i += 1
            continue
        new_line = line
        for n, m in enumerate(pending):
            new_line = new_line.replace(m.group(0), f"<< __AGW_HEREDOC_{len(bodies) + n}__", 1)
        out.append(new_line)
        i += 1
        for m in pending:
            strip = m.group(1) == "-"
            delim = m.group(3)
            body: list[str] = []
            while i < len(lines):
                candidate = lines[i].lstrip("\t") if strip else lines[i]
                i += 1
                if candidate.strip() == delim:
                    break
                body.append(lines[i - 1])
            else:
                pass  # unterminated: the rest of the text is the body (bash does the same)
            bodies.append("\n".join(body))
    return "\n".join(out), bodies


def _extract_substitutions(text: str) -> tuple[str, list[str]]:
    """Lift ``$(...)``, ``<(...)``, ``>(...)`` and backtick spans out of the text.

    Single-quoted text is literal in the shell, so nothing inside it is lifted. ``$((..))``
    arithmetic is lifted too (it is evaluated, conservatively, as a command).
    """
    out: list[str] = []
    subs: list[str] = []
    i, n = 0, len(text)
    quote: str | None = None
    while i < n:
        c = text[i]
        if quote == "'":
            out.append(c)
            if c == "'":
                quote = None
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            out.append(text[i : i + 2])
            i += 2
            continue
        if c == "'" and quote is None:
            quote = "'"
            out.append(c)
            i += 1
            continue
        if c == '"':
            quote = None if quote == '"' else '"'
            out.append(c)
            i += 1
            continue
        if c in "$<>" and i + 1 < n and text[i + 1] == "(":
            depth, j = 1, i + 2
            while j < n and depth:
                if text[j] == "(":
                    depth += 1
                elif text[j] == ")":
                    depth -= 1
                j += 1
            if depth:
                raise CommandUnparseable("unbalanced substitution")
            subs.append(text[i + 2 : j - 1])
            out.append(SUBST_TOKEN)
            i = j
            continue
        if c == "`":
            j = text.find("`", i + 1)
            if j < 0:
                raise CommandUnparseable("unbalanced backtick")
            subs.append(text[i + 1 : j])
            out.append(SUBST_TOKEN)
            i = j + 1
            continue
        out.append(c)
        i += 1
    return "".join(out), subs


def parse(command: str) -> Parsed:
    if not command or "\x00" in command or len(command) > MAX_COMMAND_LEN:
        raise CommandUnparseable("empty or oversized")
    text, bodies = _extract_heredocs(command)
    text, subs = _extract_substitutions(text)
    text = text.replace("\\\n", " ").replace("\n", " ; ")
    lexer = shlex.shlex(text, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = "#"
    try:
        tokens = list(lexer)
    except ValueError as exc:
        raise CommandUnparseable(str(exc)) from None
    segments: list[Segment] = []
    current = Segment()
    background = False
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in SEPARATORS or (tok and set(tok) <= set(";&|()") and tok not in REDIRECTS):
            if current.argv or current.redirects:
                segments.append(current)
            current = Segment(piped_in=tok in ("|", "|&"))
            background = background or tok == "&"
            i += 1
            continue
        if tok in REDIRECTS:
            target = tokens[i + 1] if i + 1 < len(tokens) else ""
            if tok in (">&", "<&") and (target.isdigit() or target == "-"):
                i += 2  # fd duplication (2>&1), not a file
                continue
            if tok in ("<<", "<<-") and target.startswith("__AGW_HEREDOC_"):
                idx = int(target.removeprefix("__AGW_HEREDOC_").rstrip("_"))
                current.heredocs.append(bodies[idx] if idx < len(bodies) else "")
            else:
                current.redirects.append((tok, target))
            i += 2
            continue
        if tok.isdigit() and i + 1 < len(tokens) and tokens[i + 1] in REDIRECTS:
            i += 1  # "2>" -> the fd number belongs to the redirection
            continue
        current.argv.append(tok)
        i += 1
    if current.argv or current.redirects:
        segments.append(current)
    return Parsed(segments=segments, substitutions=subs, background=background)


def split_command_text(argv: list[str]) -> str:
    """Re-quote argv into one shell string (for ``sh -c``-style recursion and records)."""
    return " ".join(shlex.quote(a) for a in argv)
