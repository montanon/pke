"""Unit tests for ``pke_backend.services.auth`` (HLAM-122 S2).

Covers the 8 acceptance criteria: PHC shape, salt uniqueness, happy-path
verify, wrong-password, malformed/empty hash safety, dummy-hash timing
parity, type-safety (implicit via mypy strict on the source), and a P50
latency sanity bound.
"""

from __future__ import annotations

import statistics
import time

import pytest

from pke_backend.services.auth import DUMMY_HASH, hash_password, verify_password

_PW = "correct-horse-battery-staple"


# --- AC1: PHC format & params ------------------------------------------


def test_hash_format_starts_with_argon2id_phc_prefix() -> None:
    phc = hash_password(_PW)
    assert phc.startswith("$argon2id$v=19$"), phc
    assert "m=65536" in phc
    assert "t=3" in phc
    assert "p=4" in phc


# --- AC2: Random salt --------------------------------------------------


def test_hashing_same_password_twice_yields_different_phc() -> None:
    a = hash_password(_PW)
    b = hash_password(_PW)
    assert a != b


# --- AC3: Correct password verifies ------------------------------------


def test_verify_returns_true_for_correct_password() -> None:
    phc = hash_password(_PW)
    assert verify_password(_PW, phc) is True


# --- AC4: Wrong password returns False ---------------------------------


def test_verify_returns_false_for_wrong_password() -> None:
    phc = hash_password(_PW)
    assert verify_password("not-the-password", phc) is False


# --- AC5: Malformed / empty / None hash returns False ------------------


@pytest.mark.parametrize("bad_phc", ["", "not-a-hash", "$argon2id$totally$broken", None])
def test_verify_returns_false_for_malformed_or_missing_hash(bad_phc: str | None) -> None:
    assert verify_password(_PW, bad_phc) is False


# --- AC6: Dummy-hash timing parity -------------------------------------


def _mean_verify_ms(plain: str, phc: str, samples: int = 5) -> float:
    times: list[float] = []
    for _ in range(samples):
        t0 = time.perf_counter()
        verify_password(plain, phc)
        times.append((time.perf_counter() - t0) * 1000)
    return statistics.mean(times)


def test_dummy_hash_verify_takes_similar_time_to_real_verify() -> None:
    real_phc = hash_password(_PW)
    real_mean = _mean_verify_ms(_PW, real_phc, samples=5)
    dummy_mean = _mean_verify_ms(_PW, DUMMY_HASH, samples=5)
    # Both runs hit the same argon2id code path. Loose ±40% window absorbs
    # CI runner jitter without letting an order-of-magnitude gap slip
    # through (which would be a real timing-side-channel regression).
    ratio = dummy_mean / real_mean
    assert 0.6 <= ratio <= 1.4, (
        f"timing parity off: dummy={dummy_mean:.1f}ms, real={real_mean:.1f}ms, ratio={ratio:.2f}"
    )


# --- AC7: Type-safety is enforced by mypy strict in CI, no test needed.


# --- AC8: P50 latency bound --------------------------------------------


def test_verify_p50_under_150ms() -> None:
    phc = hash_password(_PW)
    samples = [_measure_one(_PW, phc) for _ in range(9)]
    p50 = statistics.median(samples)
    assert p50 < 150, f"p50 verify latency = {p50:.1f} ms"


def _measure_one(plain: str, phc: str) -> float:
    t0 = time.perf_counter()
    verify_password(plain, phc)
    return (time.perf_counter() - t0) * 1000


# --- Empty / unicode edges --------------------------------------------


def test_empty_password_round_trips() -> None:
    phc = hash_password("")
    assert verify_password("", phc) is True
    assert verify_password("not-empty", phc) is False


def test_unicode_password_round_trips() -> None:
    pw = "пароль-密码-🔒"
    phc = hash_password(pw)
    assert verify_password(pw, phc) is True
    # NFC vs NFD differ as byte strings.
    assert verify_password(pw + " ", phc) is False
