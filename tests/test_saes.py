"""End-to-end tests for the simplified AES cipher."""

from __future__ import annotations

import unittest

from algorithm.saes import (
    decrypt_bits,
    decrypt_block,
    decrypt_block_with_trace,
    encrypt_bits,
    encrypt_block,
    encrypt_block_with_trace,
)


class SAESTests(unittest.TestCase):
    def test_encrypt_bits_matches_pdf_ciphertext(self) -> None:
        self.assertEqual(
            encrypt_bits("1101 0111 0010 1000", "0100 1010 1111 0101"),
            "0010 0100 1110 1100",
        )

    def test_decrypt_bits_matches_pdf_plaintext(self) -> None:
        self.assertEqual(
            decrypt_bits("0010 0100 1110 1100", "0100 1010 1111 0101"),
            "1101 0111 0010 1000",
        )

    def test_encrypt_and_decrypt_integer_blocks(self) -> None:
        self.assertEqual(encrypt_block(0xD728, 0x4AF5), 0x24EC)
        self.assertEqual(decrypt_block(0x24EC, 0x4AF5), 0xD728)

    def test_encrypt_trace_matches_pdf_intermediate_values(self) -> None:
        trace = encrypt_block_with_trace(0xD728, 0x4AF5)
        self.assertEqual(trace.round_keys, (0x4AF5, 0xDD28, 0x87AF))
        self.assertEqual(trace.after_add_round_key, 0x9DDD)
        self.assertEqual(trace.after_sub_nibbles, 0x2EEE)
        self.assertEqual(trace.after_shift_rows, 0x2EEE)
        self.assertEqual(trace.after_mix_columns, 0xF633)
        self.assertEqual(trace.after_round_one_key, 0x2B1B)
        self.assertEqual(trace.after_final_sub_nibbles, 0xA343)
        self.assertEqual(trace.after_final_shift_rows, 0xA343)
        self.assertEqual(trace.ciphertext, 0x24EC)

    def test_decrypt_trace_matches_pdf_intermediate_values(self) -> None:
        trace = decrypt_block_with_trace(0x24EC, 0x4AF5)
        self.assertEqual(trace.round_keys, (0x4AF5, 0xDD28, 0x87AF))
        self.assertEqual(trace.after_add_round_key, 0xA343)
        self.assertEqual(trace.after_inverse_shift_rows, 0xA343)
        self.assertEqual(trace.after_inverse_sub_nibbles, 0x2B1B)
        self.assertEqual(trace.after_round_one_key, 0xF633)
        self.assertEqual(trace.after_inverse_mix_columns, 0x2EEE)
        self.assertEqual(trace.after_final_inverse_shift_rows, 0x2EEE)
        self.assertEqual(trace.after_final_inverse_sub_nibbles, 0x9DDD)
        self.assertEqual(trace.plaintext, 0xD728)

    def test_round_trip_holds_for_additional_blocks(self) -> None:
        key = 0x4AF5
        for block in (0x0000, 0x0001, 0x1234, 0xABCD, 0xFFFF):
            self.assertEqual(decrypt_block(encrypt_block(block, key), key), block)


if __name__ == "__main__":
    unittest.main()
