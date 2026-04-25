"""Tests for shared bit and state helper utilities."""

from __future__ import annotations

import unittest

from helpers.bit_utils import (
    bits_to_bytes,
    bits_to_int,
    bytes_to_bits,
    int_to_bits,
    join_nibbles,
    split_nibbles,
    xor_bytes,
    xor_words,
)
from helpers.block_utils import bytes_to_word, join_blocks, split_blocks, word_to_bytes
from helpers.state_utils import state_to_rows, state_to_word, word_to_state


class BitUtilsTests(unittest.TestCase):
    def test_bits_round_trip(self) -> None:
        bits = "1101 0111 0010 1000"
        value = bits_to_int(bits)
        self.assertEqual(value, 0xD728)
        self.assertEqual(int_to_bits(value, 16), bits)

    def test_split_and_join_nibbles(self) -> None:
        value = 0x4AF5
        self.assertEqual(split_nibbles(value), (0x4, 0xA, 0xF, 0x5))
        self.assertEqual(join_nibbles((0x4, 0xA, 0xF, 0x5)), value)

    def test_xor_words(self) -> None:
        self.assertEqual(xor_words(0xD728, 0x4AF5), 0x9DDD)

    def test_bytes_bits_round_trip(self) -> None:
        data = b"ABC"
        self.assertEqual(bytes_to_bits(data), "01000001 01000010 01000011")
        self.assertEqual(bits_to_bytes("01000001 01000010 01000011"), data)

    def test_xor_bytes(self) -> None:
        self.assertEqual(xor_bytes(b"\xAA\x55", b"\x0F\xF0"), b"\xA5\xA5")


class BlockUtilsTests(unittest.TestCase):
    def test_bytes_word_round_trip(self) -> None:
        self.assertEqual(bytes_to_word(b"AB"), 0x4142)
        self.assertEqual(word_to_bytes(0x4142), b"AB")

    def test_split_and_join_blocks(self) -> None:
        blocks, remainder = split_blocks(b"ABCDE", block_size=2)
        self.assertEqual(blocks, (b"AB", b"CD"))
        self.assertEqual(remainder, b"E")
        self.assertEqual(join_blocks(blocks, remainder), b"ABCDE")


class StateUtilsTests(unittest.TestCase):
    def test_state_round_trip_uses_pdf_column_major_order(self) -> None:
        word = 0x2EEE
        state = word_to_state(word)
        self.assertEqual(state, ((0x2, 0xE), (0xE, 0xE)))
        self.assertEqual(state_to_word(state), word)

    def test_state_rows_are_formatted_for_visual_checks(self) -> None:
        self.assertEqual(
            state_to_rows(word_to_state(0x2EEE)),
            (("0010", "1110"), ("1110", "1110")),
        )


if __name__ == "__main__":
    unittest.main()
