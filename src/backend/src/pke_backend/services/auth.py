"""Password hashing and verification primitives for the PKE backend.

Per HLAM-122 S2: argon2id at fixed parameters (``time_cost=3``,
``memory_cost=65536 KiB``, ``parallelism=4``). The PHC string returned by
:func:`hash_password` is what goes into ``users.password_hash``.

A precomputed :data:`DUMMY_HASH` is exported so the login route (HLAM-122 S4)
can run :func:`verify_password` on the unknown-username path with the same
shape of work as a real verify, keeping wall-time indistinguishable.

Passwords are hashed as their UTF-8 byte representation; no Unicode
normalization is applied. Callers (the request schemas in S3/S4) own length
and character validation.
"""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import (
    InvalidHashError,
    VerificationError,
    VerifyMismatchError,
)

_TIME_COST = 3
_MEMORY_COST_KIB = 64 * 1024
_PARALLELISM = 4
_HASH_LEN = 32
_SALT_LEN = 16

_HASHER = PasswordHasher(
    time_cost=_TIME_COST,
    memory_cost=_MEMORY_COST_KIB,
    parallelism=_PARALLELISM,
    hash_len=_HASH_LEN,
    salt_len=_SALT_LEN,
)

# Precomputed at import — the value of the plaintext does not matter; what
# matters is that the PHC string is well-formed at the configured params so
# ``verify_password`` against it executes the same code path as a real verify.
DUMMY_HASH: str = _HASHER.hash("dummy-password-do-not-use")


def hash_password(plain: str) -> str:
    """Return a self-describing argon2id PHC string for ``plain``."""
    return _HASHER.hash(plain)


def verify_password(plain: str, phc: str | None) -> bool:
    """Return whether ``plain`` matches the argon2id PHC string ``phc``.

    Returns ``False`` for any failure mode — mismatched password, malformed
    PHC, ``None``/empty hash, or any other library-raised exception. The
    caller cannot distinguish these cases, which is by design.
    """
    if not phc:
        # Run a dummy verify so the "no stored hash" path still pays the
        # argon2 cost — otherwise a missing hash would short-circuit and
        # leak timing info.
        try:
            _HASHER.verify(DUMMY_HASH, plain)
        except (VerifyMismatchError, InvalidHashError, VerificationError):
            pass
        except Exception:
            pass
        return False
    try:
        return _HASHER.verify(phc, plain)
    except (VerifyMismatchError, InvalidHashError, VerificationError):
        return False
    except Exception:
        return False
