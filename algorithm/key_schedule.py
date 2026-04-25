"""Key schedule for the 16-bit simplified AES example."""

from __future__ import annotations

from typing import Tuple

from helpers.bit_utils import validate_width, xor_words
from .round_ops import S_BOX, substitute_byte

RCON1 = 0x80
RCON2 = 0x30
ROUND_CONSTANTS: Tuple[int, int] = (RCON1, RCON2)


def rot_nib(byte: int) -> int:
    """Swap the high and low nibble of an 8-bit word."""
    validate_width(byte, 8, "byte")
    return ((byte & 0x0F) << 4) | ((byte >> 4) & 0x0F)


def sub_nib(byte: int) -> int:
    """Apply the encryption S-box to both nibbles of an 8-bit word."""
    validate_width(byte, 8, "byte")
    return substitute_byte(byte, S_BOX)


def g(word: int, round_constant: int) -> int:
    """Apply RotNib, SubNib, and XOR with the round constant."""
    validate_width(word, 8, "word")
    validate_width(round_constant, 8, "round_constant")
    return xor_words(sub_nib(rot_nib(word)), round_constant, width=8)


def expand_words(key: int) -> Tuple[int, int, int, int, int, int]:
    """Expand the 16-bit key into the six 8-bit words w0..w5."""
    validate_width(key, 16, "key")
    w0 = (key >> 8) & 0xFF
    w1 = key & 0xFF

    w2 = xor_words(w0, g(w1, RCON1), width=8)
    w3 = xor_words(w2, w1, width=8)
    w4 = xor_words(w2, g(w3, RCON2), width=8)
    w5 = xor_words(w4, w3, width=8)
    return (w0, w1, w2, w3, w4, w5)


def expand_round_keys(key: int) -> Tuple[int, int, int]:
    """Return the three 16-bit round keys used by S-AES."""
    w0, w1, w2, w3, w4, w5 = expand_words(key)
    return (
        (w0 << 8) | w1,
        (w2 << 8) | w3,
        (w4 << 8) | w5,
    )
