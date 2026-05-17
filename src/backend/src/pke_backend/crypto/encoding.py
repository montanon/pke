"""Base64url and hex encoding helpers for on-the-wire binary fields.

Binary fields on the wire are base64url WITHOUT padding (RFC 4648 section 5,
with trailing `=` stripped). Padded base64 input, standard-alphabet `+`/`/`,
non-ASCII input, and invalid lengths are all rejected at decode time.

Error `reason` strings never contain raw input — only counts, offsets, or
character-class hints — to avoid leaking key bytes or plaintext.
"""

from __future__ import annotations

import base64
import binascii
import re
import string

from pke_backend.crypto.errors import EncodingError

__all__ = ["b64url_decode", "b64url_encode", "hex_decode", "hex_encode"]

# Base64url alphabet (RFC 4648 section 5) without padding.
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")

# Hex alphabet, both cases accepted on decode (see hex_decode docstring).
_HEX_ALLOWED = frozenset(string.hexdigits)


def b64url_encode(data: bytes) -> str:
    """Encode `data` as base64url without padding (RFC 4648 section 5)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    """Decode an unpadded base64url string.

    Rejects:
      * any `=` padding,
      * characters outside the base64url alphabet (notably `+` and `/`),
      * non-ASCII input,
      * lengths invalid for unpadded base64url (length mod 4 == 1).
    """
    try:
        s.encode("ascii")
    except UnicodeEncodeError as exc:
        raise EncodingError(reason="non-ascii input") from exc

    if "=" in s:
        raise EncodingError(reason="padded input rejected (unpadded base64url required)")

    if not _B64URL_RE.fullmatch(s):
        raise EncodingError(reason="character outside base64url alphabet")

    n = len(s)
    rem = n % 4
    if rem == 1:
        raise EncodingError(reason=f"invalid base64url length: {n} (mod 4 == 1)")

    padded = s + ("=" * ((4 - rem) % 4))
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (ValueError, binascii.Error) as exc:
        raise EncodingError(reason="base64url decode failure") from exc


def hex_encode(data: bytes) -> str:
    """Encode `data` as lowercase hex without prefix."""
    return data.hex()


def hex_decode(s: str) -> bytes:
    """Decode a hex string.

    Permissive on case (accepts upper and lower) for symmetry with `bytes.fromhex`,
    but strict on alphabet: any whitespace or non-hex character is rejected.
    `hex_encode` always emits lowercase, so round-trips remain lowercase-only.
    """
    if len(s) % 2 != 0:
        raise EncodingError(reason=f"odd-length hex input: {len(s)}")

    # bytes.fromhex tolerates ASCII whitespace; we do not.
    for ch in s:
        if ch not in _HEX_ALLOWED:
            raise EncodingError(reason="character outside hex alphabet")

    try:
        return bytes.fromhex(s)
    except ValueError as exc:
        raise EncodingError(reason="hex decode failure") from exc
