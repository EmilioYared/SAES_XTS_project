"""Helpers for the 2x2 nibble state used by the simplified AES example."""

from __future__ import annotations

from typing import Tuple

from .bit_utils import join_nibbles, split_nibbles, validate_width

State = Tuple[Tuple[int, int], Tuple[int, int]]


def word_to_state(word: int) -> State:
    """Convert a 16-bit word into the PDF's 2x2 nibble state matrix.

    The PDF serializes the state column-by-column as:
    s00, s10, s01, s11
    """

    validate_width(word, 16, "word")
    s00, s10, s01, s11 = split_nibbles(word)
    return ((s00, s01), (s10, s11))


def state_to_word(state: State) -> int:
    """Serialize a 2x2 nibble state back to a 16-bit word in PDF order."""
    (s00, s01), (s10, s11) = state
    return join_nibbles((s00, s10, s01, s11))


def state_to_rows(state: State) -> Tuple[Tuple[str, str], Tuple[str, str]]:
    """Return the state as two binary-string rows for educational display."""
    return tuple(
        tuple(format(cell, "04b") for cell in row)
        for row in state
    )  # type: ignore[return-value]
