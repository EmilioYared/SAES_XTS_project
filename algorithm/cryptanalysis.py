"""brute-force and differential cryptanalysis helpers for S-AES."""

from __future__ import annotations

from dataclasses import dataclass
from time import perf_counter
from typing import Iterable

from helpers.bit_utils import validate_width

from .saes import encrypt_block

KEYSPACE_SIZE = 1 << 16
DEFAULT_KNOWN_PLAINTEXT = 0x1234
DEFAULT_DIFFERENTIAL_PAIRS: tuple[tuple[int, int], ...] = (
    (0x0000, 0x00FF),
    (0x0F0F, 0xF0F0),
    (0xAAAA, 0xAA55),
)


@dataclass(frozen=True)
class KnownPair:
    """A plaintext-ciphertext pair produced under one unknown S-AES key."""

    plaintext: int
    ciphertext: int


@dataclass(frozen=True)
class DifferentialObservation:
    """Observed differential relation from two chosen-plaintext queries."""

    plaintext_left: int
    plaintext_right: int
    ciphertext_left: int
    ciphertext_right: int

    @property
    def delta_plaintext(self) -> int:
        return self.plaintext_left ^ self.plaintext_right

    @property
    def delta_ciphertext(self) -> int:
        return self.ciphertext_left ^ self.ciphertext_right


@dataclass(frozen=True)
class DifferentialAttackReport:
    """Results from the educational differential-plus-brute-force workflow."""

    secret_key: int
    known_pair: KnownPair
    observations: tuple[DifferentialObservation, ...]
    filtered_candidates: tuple[int, ...]
    recovered_keys: tuple[int, ...]
    differential_filter_seconds: float
    brute_force_seconds: float


def brute_force_keys_from_known_pair(
    known_pair: KnownPair,
    candidate_keys: Iterable[int] | None = None,
) -> list[int]:
    """Return all 16-bit keys that match one known plaintext-ciphertext pair."""

    validate_width(known_pair.plaintext, 16, "known_pair plaintext")
    validate_width(known_pair.ciphertext, 16, "known_pair ciphertext")

    keys_to_test = list(range(KEYSPACE_SIZE)) if candidate_keys is None else list(candidate_keys)
    matches: list[int] = []
    for key in keys_to_test:
        validate_width(key, 16, "candidate key")
        if encrypt_block(known_pair.plaintext, key) == known_pair.ciphertext:
            matches.append(key)
    return matches


def filter_keys_with_differentials(
    observations: Iterable[DifferentialObservation],
) -> list[int]:
    """Keep only keys that satisfy all observed input/output XOR differences."""

    observations = tuple(observations)
    for observation in observations:
        validate_width(observation.plaintext_left, 16, "plaintext_left")
        validate_width(observation.plaintext_right, 16, "plaintext_right")
        validate_width(observation.ciphertext_left, 16, "ciphertext_left")
        validate_width(observation.ciphertext_right, 16, "ciphertext_right")

    candidates: list[int] = []
    for key in range(KEYSPACE_SIZE):
        valid = True
        for observation in observations:
            predicted_delta = encrypt_block(observation.plaintext_left, key) ^ encrypt_block(observation.plaintext_right, key)
            if predicted_delta != observation.delta_ciphertext:
                valid = False
                break
        if valid:
            candidates.append(key)
    return candidates


def collect_differential_observations(
    secret_key: int,
    chosen_pairs: Iterable[tuple[int, int]] = DEFAULT_DIFFERENTIAL_PAIRS,
) -> list[DifferentialObservation]:
    """Generate educational differential observations from an encryption oracle."""

    validate_width(secret_key, 16, "secret_key")
    observations: list[DifferentialObservation] = []
    for plaintext_left, plaintext_right in chosen_pairs:
        validate_width(plaintext_left, 16, "plaintext_left")
        validate_width(plaintext_right, 16, "plaintext_right")
        observations.append(
            DifferentialObservation(
                plaintext_left=plaintext_left,
                plaintext_right=plaintext_right,
                ciphertext_left=encrypt_block(plaintext_left, secret_key),
                ciphertext_right=encrypt_block(plaintext_right, secret_key),
            )
        )
    return observations


def run_differential_attack(
    secret_key: int,
    *,
    known_plaintext: int = DEFAULT_KNOWN_PLAINTEXT,
    chosen_pairs: Iterable[tuple[int, int]] = DEFAULT_DIFFERENTIAL_PAIRS,
) -> DifferentialAttackReport:
    """Simulate an educational differential cryptanalysis workflow on S-AES."""

    validate_width(secret_key, 16, "secret_key")
    validate_width(known_plaintext, 16, "known_plaintext")

    known_pair = KnownPair(
        plaintext=known_plaintext,
        ciphertext=encrypt_block(known_plaintext, secret_key),
    )
    observations = tuple(collect_differential_observations(secret_key, chosen_pairs))

    filter_start = perf_counter()
    filtered_candidates = tuple(filter_keys_with_differentials(observations))
    filter_end = perf_counter()

    brute_force_start = perf_counter()
    recovered_keys = tuple(brute_force_keys_from_known_pair(known_pair, filtered_candidates))
    brute_force_end = perf_counter()

    return DifferentialAttackReport(
        secret_key=secret_key,
        known_pair=known_pair,
        observations=observations,
        filtered_candidates=filtered_candidates,
        recovered_keys=recovered_keys,
        differential_filter_seconds=filter_end - filter_start,
        brute_force_seconds=brute_force_end - brute_force_start,
    )
