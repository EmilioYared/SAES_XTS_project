"""Tests for the educational S-AES cryptanalysis helpers."""

from __future__ import annotations

import unittest

from algorithm.cryptanalysis import (
    KnownPair,
    brute_force_keys_from_known_pair,
    collect_differential_observations,
    filter_keys_with_differentials,
    run_differential_attack,
)
from algorithm.saes import encrypt_block


class CryptanalysisTests(unittest.TestCase):
    def test_brute_force_known_pair_recovers_unique_key(self) -> None:
        known_pair = KnownPair(plaintext=0x1234, ciphertext=encrypt_block(0x1234, 0x4AF5))
        self.assertEqual(brute_force_keys_from_known_pair(known_pair), [0x4AF5])

    def test_differential_filter_recovers_unique_key(self) -> None:
        observations = collect_differential_observations(0x4AF5)
        self.assertEqual(filter_keys_with_differentials(observations), [0x4AF5])

    def test_run_differential_attack_reports_recovered_key(self) -> None:
        report = run_differential_attack(0x4AF5)
        self.assertEqual(report.known_pair.ciphertext, encrypt_block(report.known_pair.plaintext, 0x4AF5))
        self.assertEqual(report.filtered_candidates, (0x4AF5,))
        self.assertEqual(report.recovered_keys, (0x4AF5,))


if __name__ == "__main__":
    unittest.main()
