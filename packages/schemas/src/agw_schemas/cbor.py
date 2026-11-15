"""AGW-CBOR-v1: the deterministic CBOR profile (docs/gateway/05 §6, ADR-0005, ADR-0021).

RFC 8949 §4.2.1 core deterministic encoding, restricted further:

* integers in [-2^63, 2^64-1], shortest head; definite lengths only;
* map keys are text strings, unique, sorted bytewise by their encoded form;
* no floats, no tags, no ``undefined``, no simple values other than false/true/null;
* text is valid UTF-8, hashed as given (no normalization);
* nesting depth <= 16.

``decode`` is strict: it rejects any input that is not exactly what ``encode`` would produce,
and finally re-encodes and compares byte-for-byte (05 §6 rule 8).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Final

MAX_DEPTH: Final = 16
_UINT_MAX: Final = 2**64 - 1
_NINT_MIN: Final = -(2**63)

CborValue = None | bool | int | bytes | str | list["CborValue"] | dict[str, "CborValue"]


class CanonicalError(ValueError):
    """Value not representable, or input bytes not canonical, under AGW-CBOR-v1."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


# --------------------------------------------------------------------------- encode
def _head(major: int, arg: int) -> bytes:
    mt = major << 5
    if arg < 24:
        return bytes([mt | arg])
    if arg < 0x100:
        return bytes([mt | 24, arg])
    if arg < 0x10000:
        return bytes([mt | 25]) + arg.to_bytes(2, "big")
    if arg < 0x100000000:
        return bytes([mt | 26]) + arg.to_bytes(4, "big")
    return bytes([mt | 27]) + arg.to_bytes(8, "big")


def _enc(value: Any, depth: int, out: bytearray) -> None:
    if depth > MAX_DEPTH:
        raise CanonicalError("DEPTH", f"nesting deeper than {MAX_DEPTH}")
    if value is None:
        out.append(0xF6)
    elif value is True:
        out.append(0xF5)
    elif value is False:
        out.append(0xF4)
    elif isinstance(value, int):
        if value > _UINT_MAX or value < _NINT_MIN:
            raise CanonicalError("INT_RANGE", "integer outside [-2^63, 2^64-1]")
        out += _head(0, value) if value >= 0 else _head(1, -1 - value)
    elif isinstance(value, bytes | bytearray | memoryview):
        blob = bytes(value)
        out += _head(2, len(blob)) + blob
    elif isinstance(value, str):
        try:
            text = value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise CanonicalError("UTF8", "text is not valid UTF-8") from exc
        out += _head(3, len(text)) + text
    elif isinstance(value, Mapping):
        items: list[tuple[bytes, Any]] = []
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalError("MAP_KEY", "map keys must be text strings")
            key_buf = bytearray()
            _enc(key, depth + 1, key_buf)
            items.append((bytes(key_buf), item))
        items.sort(key=lambda kv: kv[0])
        out += _head(5, len(items))
        for key_bytes, item in items:
            out += key_bytes
            _enc(item, depth + 1, out)
    elif isinstance(value, Sequence):
        out += _head(4, len(value))
        for item in value:
            _enc(item, depth + 1, out)
    elif isinstance(value, float):
        raise CanonicalError("FLOAT", "floats are not allowed (use canonical decimal text)")
    else:
        raise CanonicalError("TYPE", f"unsupported type {type(value).__name__}")


def encode(value: Any) -> bytes:
    out = bytearray()
    _enc(value, 0, out)
    return bytes(out)


# --------------------------------------------------------------------------- decode
class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise CanonicalError("TRUNCATED", "unexpected end of input")
        chunk = self.data[self.pos : self.pos + n]
        self.pos += n
        return chunk

    def head(self) -> tuple[int, int]:
        ib = self.take(1)[0]
        major, ai = ib >> 5, ib & 0x1F
        if major == 7:
            return 7, ai
        if ai < 24:
            return major, ai
        if ai == 31:
            raise CanonicalError("INDEFINITE", "indefinite-length items are not allowed")
        if ai > 27:
            raise CanonicalError("RESERVED", "reserved additional information")
        size = 1 << (ai - 24)
        arg = int.from_bytes(self.take(size), "big")
        minimum = 24 if size == 1 else 1 << (4 * size)  # 24, 2^8, 2^16, 2^32
        if arg < minimum:
            raise CanonicalError("NON_SHORTEST", "argument not in shortest form")
        return major, arg

    def item(self, depth: int) -> Any:
        if depth > MAX_DEPTH:
            raise CanonicalError("DEPTH", f"nesting deeper than {MAX_DEPTH}")
        major, arg = self.head()
        if major == 0:
            return arg
        if major == 1:
            if arg > 2**63 - 1:
                raise CanonicalError("INT_RANGE", "negative integer below -2^63")
            return -1 - arg
        if major == 2:
            return self.take(arg)
        if major == 3:
            try:
                return self.take(arg).decode("utf-8")
            except UnicodeDecodeError as exc:
                raise CanonicalError("UTF8", "invalid UTF-8 text") from exc
        if major == 4:
            return [self.item(depth + 1) for _ in range(arg)]
        if major == 5:
            result: dict[str, Any] = {}
            prev_key: bytes | None = None
            for _ in range(arg):
                start = self.pos
                if self.data[start : start + 1] and (self.data[start] >> 5) != 3:
                    raise CanonicalError("MAP_KEY", "map keys must be text strings")
                key = self.item(depth + 1)
                kb = self.data[start : self.pos]
                if prev_key is not None:
                    if kb == prev_key:
                        raise CanonicalError("DUPLICATE_KEY", "duplicate map key")
                    if kb < prev_key:
                        raise CanonicalError("KEY_ORDER", "map keys not in canonical order")
                prev_key = kb
                result[key] = self.item(depth + 1)
            return result
        if major == 6:
            raise CanonicalError("TAG", "tags are not allowed")
        # major 7
        if arg == 20:
            return False
        if arg == 21:
            return True
        if arg == 22:
            return None
        if arg == 23:
            raise CanonicalError("UNDEFINED", "undefined is not allowed")
        if arg in (25, 26, 27):
            raise CanonicalError("FLOAT", "floats are not allowed")
        if arg == 31:
            raise CanonicalError("INDEFINITE", "break outside indefinite item")
        raise CanonicalError("SIMPLE", "simple values other than false/true/null")


def decode(data: bytes) -> Any:
    """Strictly decode one canonical item; reject anything else."""
    raw = bytes(data)
    reader = _Reader(raw)
    value = reader.item(0)
    if reader.pos != len(raw):
        raise CanonicalError("TRAILING", "trailing bytes after the item")
    if encode(value) != raw:  # pragma: no cover - defence in depth; checks above are exhaustive
        raise CanonicalError("NON_CANONICAL", "re-encoding differs")
    return value
