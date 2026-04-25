"""Tests for the educational SAES-XTS/XEX wrapper."""

from __future__ import annotations

import unittest

from algorithm.xts import (
    decrypt_message,
    decrypt_message_bits,
    decrypt_message_with_trace,
    derive_initial_tweak,
    encrypt_message,
    encrypt_message_bits,
    encrypt_message_with_trace,
    multiply_tweak_by_alpha,
)


DATA_KEY = 0x4AF5
TWEAK_KEY = 0xBEEF
DATA_UNIT = 0x0001


class XTSTests(unittest.TestCase):
    def test_tweak_derivation_and_progression(self) -> None:
        initial_tweak = derive_initial_tweak(DATA_UNIT, TWEAK_KEY)
        self.assertEqual(initial_tweak, 0x77E5)
        self.assertEqual(multiply_tweak_by_alpha(initial_tweak), 0xEFCA)
        self.assertEqual(multiply_tweak_by_alpha(0xEFCA), 0xDFB9)

    def test_one_block_encryption_and_decryption(self) -> None:
        ciphertext = encrypt_message(b"AB", DATA_KEY, TWEAK_KEY, DATA_UNIT)
        self.assertEqual(ciphertext, bytes.fromhex("79c3"))
        self.assertEqual(decrypt_message(ciphertext, DATA_KEY, TWEAK_KEY, DATA_UNIT), b"AB")

    def test_multiblock_encryption_and_decryption(self) -> None:
        ciphertext = encrypt_message(b"ABABAB", DATA_KEY, TWEAK_KEY, DATA_UNIT)
        self.assertEqual(ciphertext, bytes.fromhex("79c312e55d11"))
        self.assertEqual(decrypt_message(ciphertext, DATA_KEY, TWEAK_KEY, DATA_UNIT), b"ABABAB")

    def test_ciphertext_stealing_encrypt_and_decrypt(self) -> None:
        ciphertext = encrypt_message(b"ABCDE", DATA_KEY, TWEAK_KEY, DATA_UNIT)
        self.assertEqual(ciphertext, bytes.fromhex("79c3dd7a9d"))
        self.assertEqual(decrypt_message(ciphertext, DATA_KEY, TWEAK_KEY, DATA_UNIT), b"ABCDE")

    def test_same_plaintext_with_different_data_units_changes_ciphertext(self) -> None:
        ciphertext_one = encrypt_message(b"AB", DATA_KEY, TWEAK_KEY, 0x0001)
        ciphertext_two = encrypt_message(b"AB", DATA_KEY, TWEAK_KEY, 0x0002)
        self.assertNotEqual(ciphertext_one, ciphertext_two)

    def test_same_inputs_are_deterministic(self) -> None:
        self.assertEqual(
            encrypt_message(b"ABABAB", DATA_KEY, TWEAK_KEY, DATA_UNIT),
            encrypt_message(b"ABABAB", DATA_KEY, TWEAK_KEY, DATA_UNIT),
        )

    def test_one_block_trace_matches_manual_xex_values(self) -> None:
        ciphertext, trace = encrypt_message_with_trace(b"AB", DATA_KEY, TWEAK_KEY, DATA_UNIT)
        self.assertEqual(ciphertext, bytes.fromhex("79c3"))
        self.assertFalse(trace.used_ciphertext_stealing)
        self.assertEqual(len(trace.block_traces), 1)
        block_trace = trace.block_traces[0]
        self.assertEqual(block_trace.tweak, 0x77E5)
        self.assertEqual(block_trace.pre_whitened, 0x36A7)
        self.assertEqual(block_trace.core_output, 0x0E26)
        self.assertEqual(block_trace.output_block, bytes.fromhex("79c3"))
        self.assertEqual(block_trace.tweak_after, 0xEFCA)

    def test_ciphertext_stealing_trace_contains_expected_values(self) -> None:
        ciphertext, trace = encrypt_message_with_trace(b"ABCDE", DATA_KEY, TWEAK_KEY, DATA_UNIT)
        self.assertEqual(ciphertext, bytes.fromhex("79c3dd7a9d"))
        self.assertTrue(trace.used_ciphertext_stealing)
        self.assertEqual(len(trace.block_traces), 1)
        self.assertIsNotNone(trace.cts_trace)
        cts = trace.cts_trace
        self.assertEqual(cts.partial_length, 1)
        self.assertEqual(cts.provisional_tweak, 0xEFCA)
        self.assertEqual(cts.final_tweak, 0xDFB9)
        self.assertEqual(cts.provisional_ciphertext_block, bytes.fromhex("9d20"))
        self.assertEqual(cts.stolen_ciphertext_fragment, bytes.fromhex("9d"))
        self.assertEqual(cts.final_penultimate_ciphertext_block, bytes.fromhex("dd7a"))

    def test_trace_and_non_trace_results_match(self) -> None:
        ciphertext = encrypt_message(b"ABABAB", DATA_KEY, TWEAK_KEY, DATA_UNIT)
        traced_ciphertext, trace = encrypt_message_with_trace(b"ABABAB", DATA_KEY, TWEAK_KEY, DATA_UNIT)
        self.assertEqual(ciphertext, traced_ciphertext)
        self.assertEqual(trace.output_message, ciphertext)

        plaintext = decrypt_message(ciphertext, DATA_KEY, TWEAK_KEY, DATA_UNIT)
        traced_plaintext, decrypt_trace = decrypt_message_with_trace(ciphertext, DATA_KEY, TWEAK_KEY, DATA_UNIT)
        self.assertEqual(plaintext, traced_plaintext)
        self.assertEqual(decrypt_trace.output_message, plaintext)

    def test_bit_wrappers_round_trip(self) -> None:
        plaintext_bits = "01000001 01000010"
        ciphertext_bits = encrypt_message_bits(
            plaintext_bits,
            "01001010 11110101",
            "10111110 11101111",
            "00000000 00000001",
        )
        self.assertEqual(ciphertext_bits, "01111001 11000011")
        self.assertEqual(
            decrypt_message_bits(
                ciphertext_bits,
                "01001010 11110101",
                "10111110 11101111",
                "00000000 00000001",
            ),
            plaintext_bits,
        )

    def test_partial_message_without_a_full_block_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            encrypt_message(b"A", DATA_KEY, TWEAK_KEY, DATA_UNIT)


if __name__ == "__main__":
    unittest.main()
