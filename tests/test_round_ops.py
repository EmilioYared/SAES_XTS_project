"""Tests for low-level S-AES round operations."""

from __future__ import annotations

import unittest

from algorithm.round_ops import (
    INV_S_BOX,
    S_BOX,
    gf_multiply,
    inverse_mix_columns_word,
    inverse_shift_rows_word,
    inverse_substitute_word,
    mix_columns_word,
    shift_rows_word,
    substitute_nibble,
    substitute_word,
)


class RoundOpsTests(unittest.TestCase):
    def test_selected_s_box_entries_match_the_pdf_example(self) -> None:
        self.assertEqual(substitute_nibble(0x9, S_BOX), 0x2)
        self.assertEqual(substitute_nibble(0xD, S_BOX), 0xE)
        self.assertEqual(substitute_nibble(0x2, INV_S_BOX), 0x9)
        self.assertEqual(substitute_nibble(0xE, INV_S_BOX), 0xD)

    def test_substitute_and_inverse_substitute_word(self) -> None:
        self.assertEqual(substitute_word(0x9DDD), 0x2EEE)
        self.assertEqual(inverse_substitute_word(0xA343), 0x2B1B)

    def test_shift_rows_swaps_second_row_positions(self) -> None:
        self.assertEqual(shift_rows_word(0x1234), 0x1432)
        self.assertEqual(inverse_shift_rows_word(0x1432), 0x1234)

    def test_mix_columns_matches_pdf_worked_example(self) -> None:
        self.assertEqual(mix_columns_word(0x2EEE), 0xF633)
        self.assertEqual(inverse_mix_columns_word(0xF633), 0x2EEE)

    def test_gf_products_match_values_used_in_the_pdf(self) -> None:
        self.assertEqual(gf_multiply(0x4, 0xE), 0xD)
        self.assertEqual(gf_multiply(0x4, 0x2), 0x8)
        self.assertEqual(gf_multiply(0x9, 0xF), 0xE)
        self.assertEqual(gf_multiply(0x2, 0x6), 0xC)
        self.assertEqual(gf_multiply(0x9, 0x6), 0x3)
        self.assertEqual(gf_multiply(0x9, 0x3), 0x8)
        self.assertEqual(gf_multiply(0x2, 0x3), 0x6)


if __name__ == "__main__":
    unittest.main()
