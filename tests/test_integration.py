"""Integration tests across helpers, algorithm, mode, and visualization adapters."""

from __future__ import annotations

import unittest

from algorithm.xts import decrypt_message_bits, encrypt_message_bits, encrypt_message_with_trace
from visualization.trace_adapter import adapt_xts_trace


class IntegrationTests(unittest.TestCase):
    def test_bit_wrappers_and_trace_adapter_align(self) -> None:
        plaintext_bits = "01000001 01000010 01000011 01000100 01000101"
        ciphertext_bits = encrypt_message_bits(
            plaintext_bits,
            "01001010 11110101",
            "10111110 11101111",
            "00000000 00000001",
        )
        self.assertEqual(ciphertext_bits, "01111001 11000011 11011101 01111010 10011101")
        self.assertEqual(
            decrypt_message_bits(
                ciphertext_bits,
                "01001010 11110101",
                "10111110 11101111",
                "00000000 00000001",
            ),
            plaintext_bits,
        )

        _, trace = encrypt_message_with_trace(b"ABCDE", 0x4AF5, 0xBEEF, 0x0001)
        adapted = adapt_xts_trace(trace)
        self.assertEqual(adapted["output_message_bits"], ciphertext_bits)
        self.assertEqual(adapted["cts"]["final_penultimate_ciphertext_bits"], "11011101 01111010")


if __name__ == "__main__":
    unittest.main()
