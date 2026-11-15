"""Independent strict decoder/encoder for AGW-CBOR-v1 (05 §6). Stdlib only.

Strategy: decode each item, then require that the canonical re-encoding of every map key and
of the whole item equals the input bytes. Anything else is rejected with a reason code.
"""

from __future__ import annotations

from typing import Any

MAX_DEPTH = 16


class NonCanonical(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _hd(major: int, n: int) -> bytes:
    if n <= 23:
        return bytes([(major << 5) | n])
    for ai, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * width):
            return bytes([(major << 5) | ai]) + n.to_bytes(width, "big")
    raise NonCanonical("INT_RANGE")


def dumps(v: Any, depth: int = 0) -> bytes:
    if depth > MAX_DEPTH:
        raise NonCanonical("DEPTH")
    if v is None:
        return b"\xf6"
    if v is True:
        return b"\xf5"
    if v is False:
        return b"\xf4"
    if isinstance(v, int):
        if not -(2**63) <= v <= 2**64 - 1:
            raise NonCanonical("INT_RANGE")
        return _hd(0, v) if v >= 0 else _hd(1, -1 - v)
    if isinstance(v, bytes):
        return _hd(2, len(v)) + v
    if isinstance(v, str):
        b = v.encode("utf-8")
        return _hd(3, len(b)) + b
    if isinstance(v, list):
        return _hd(4, len(v)) + b"".join(dumps(x, depth + 1) for x in v)
    if isinstance(v, dict):
        pairs = sorted((dumps(k, depth + 1), dumps(x, depth + 1)) for k, x in v.items())
        return _hd(5, len(pairs)) + b"".join(k + x for k, x in pairs)
    raise NonCanonical("TYPE")


def _item(b: bytes, i: int, depth: int) -> tuple[Any, int]:
    if depth > MAX_DEPTH:
        raise NonCanonical("DEPTH")
    if i >= len(b):
        raise NonCanonical("TRUNCATED")
    ib = b[i]
    major, ai = ib >> 5, ib & 31
    i += 1
    if major == 7:
        simple = {20: False, 21: True, 22: None}
        if ai in simple:
            return simple[ai], i
        raise NonCanonical(
            {23: "UNDEFINED", 25: "FLOAT", 26: "FLOAT", 27: "FLOAT", 31: "INDEFINITE"}.get(
                ai, "SIMPLE"
            )
        )
    if ai == 31:
        raise NonCanonical("INDEFINITE")
    if ai in (28, 29, 30):
        raise NonCanonical("RESERVED")
    if ai < 24:
        n = ai
    else:
        width = 1 << (ai - 24)
        if i + width > len(b):
            raise NonCanonical("TRUNCATED")
        n = int.from_bytes(b[i : i + width], "big")
        i += width
        if _hd(0, n)[0] & 31 != ai:  # a shorter head exists
            raise NonCanonical("NON_SHORTEST")
    if major == 0:
        return n, i
    if major == 1:
        if n >= 2**63:
            raise NonCanonical("INT_RANGE")
        return -1 - n, i
    if major in (2, 3):
        if i + n > len(b):
            raise NonCanonical("TRUNCATED")
        raw = b[i : i + n]
        if major == 2:
            return raw, i + n
        try:
            return raw.decode("utf-8"), i + n
        except UnicodeDecodeError:
            raise NonCanonical("UTF8") from None
    if major == 4:
        out = []
        for _ in range(n):
            x, i = _item(b, i, depth + 1)
            out.append(x)
        return out, i
    if major == 5:
        d: dict[str, Any] = {}
        last = b""
        for idx in range(n):
            start = i
            if i < len(b) and b[i] >> 5 != 3:
                raise NonCanonical("MAP_KEY")
            k, i = _item(b, i, depth + 1)
            kb = b[start:i]
            if idx and kb == last:
                raise NonCanonical("DUPLICATE_KEY")
            if idx and kb < last:
                raise NonCanonical("KEY_ORDER")
            last = kb
            d[k], i = _item(b, i, depth + 1)
        return d, i
    raise NonCanonical("TAG")


def loads(b: bytes) -> Any:
    value, end = _item(b, 0, 0)
    if end != len(b):
        raise NonCanonical("TRAILING")
    if dumps(value) != b:
        raise NonCanonical("NON_CANONICAL")
    return value
