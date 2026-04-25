"""Tests for the S-AES key expansion."""

from __future__ import annotations

import unittest

from algorithm.key_schedule import expand_round_keys, expand_words, g, rot_nib, sub_nib


class KeyScheduleTests(unittest.TestCase):
    def test_rot_nib_and_sub_nib_match_the_pdf_example(self) -> None:
        self.assertEqual(rot_nib(0xF5), 0x5F)
        self.assertEqual(sub_nib(0x5F), 0x17)

    def test_g_function_matches_the_first_round_word_transformation(self) -> None:
        self.assertEqual(g(0xF5, 0x80), 0x97)

    def test_expand_words_matches_pdf_values(self) -> None:
        self.assertEqual(expand_words(0x4AF5), (0x4A, 0xF5, 0xDD, 0x28, 0x87, 0xAF))

    def test_expand_round_keys_matches_pdf_values(self) -> None:
        self.assertEqual(expand_round_keys(0x4AF5), (0x4AF5, 0xDD28, 0x87AF))


if __name__ == "__main__":
    unittest.main()
