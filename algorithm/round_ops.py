"""Round operations for the simplified AES example."""

from __future__ import annotations

from typing import Iterable, Sequence, Tuple

from helpers.bit_utils import join_nibbles, split_nibbles, validate_width
from helpers.state_utils import State, state_to_word, word_to_state

S_BOX: Tuple[int, ...] = (
    0x9, 0x4, 0xA, 0xB,
    0xD, 0x1, 0x8, 0x5,
    0x6, 0x2, 0x0, 0x3,
    0xC, 0xE, 0xF, 0x7,
)

INV_S_BOX: Tuple[int, ...] = (
    0xA, 0x5, 0x9, 0xB,
    0x1, 0x7, 0x8, 0xF,
    0x6, 0x0, 0x2, 0x3,
    0xC, 0x4, 0xD, 0xE,
)

MIX_COLUMNS_MATRIX: Tuple[Tuple[int, int], Tuple[int, int]] = ((0x1, 0x4), (0x4, 0x1))
INV_MIX_COLUMNS_MATRIX: Tuple[Tuple[int, int], Tuple[int, int]] = ((0x9, 0x2), (0x2, 0x9))
GF_MODULUS = 0b10011


def substitute_nibble(nibble: int, s_box: Sequence[int]) -> int:
    """Map a nibble through an S-box."""
    validate_width(nibble, 4, "nibble")
    return s_box[nibble]


def substitute_byte(byte: int, s_box: Sequence[int]) -> int:
    """Apply an S-box to both nibbles in an 8-bit value."""
    validate_width(byte, 8, "byte")
    high, low = split_nibbles(byte, count=2)
    return join_nibbles((substitute_nibble(high, s_box), substitute_nibble(low, s_box)))


def substitute_word(word: int, s_box: Sequence[int] = S_BOX) -> int:
    """Apply an S-box to all nibbles of a 16-bit word."""
    validate_width(word, 16, "word")
    return join_nibbles(substitute_nibble(nibble, s_box) for nibble in split_nibbles(word))


def inverse_substitute_word(word: int) -> int:
    """Apply the inverse S-box to a 16-bit word."""
    return substitute_word(word, INV_S_BOX)


def sub_state(state: State, s_box: Sequence[int] = S_BOX) -> State:
    """Apply an S-box to each nibble in the state matrix."""
    return tuple(
        tuple(substitute_nibble(cell, s_box) for cell in row)
        for row in state
    )  # type: ignore[return-value]


def inverse_sub_state(state: State) -> State:
    """Apply the inverse S-box to the state matrix."""
    return sub_state(state, INV_S_BOX)


def shift_rows(state: State) -> State:
    """Swap the two nibbles in the second row of the 2x2 nibble state."""
    (s00, s01), (s10, s11) = state
    return ((s00, s01), (s11, s10))


def inverse_shift_rows(state: State) -> State:
    """Inverse shift rows, identical to shift rows for a 2x2 state."""
    return shift_rows(state)


def gf_multiply(left: int, right: int) -> int:
    """Multiply two nibbles in GF(2^4) with modulus x^4 + x + 1."""
    validate_width(left, 4, "left")
    validate_width(right, 4, "right")
    result = 0
    multiplicand = left
    multiplier = right
    for _ in range(4):
        if multiplier & 1:
            result ^= multiplicand
        multiplier >>= 1
        carry = multiplicand & 0x8
        multiplicand = (multiplicand << 1) & 0xF
        if carry:
            multiplicand ^= GF_MODULUS & 0xF
    return result & 0xF


def _mix_columns_with_matrix(state: State, matrix: Sequence[Sequence[int]]) -> State:
    (s00, s01), (s10, s11) = state
    left_column = (
        gf_multiply(matrix[0][0], s00) ^ gf_multiply(matrix[0][1], s10),
        gf_multiply(matrix[1][0], s00) ^ gf_multiply(matrix[1][1], s10),
    )
    right_column = (
        gf_multiply(matrix[0][0], s01) ^ gf_multiply(matrix[0][1], s11),
        gf_multiply(matrix[1][0], s01) ^ gf_multiply(matrix[1][1], s11),
    )
    return (
        (left_column[0], right_column[0]),
        (left_column[1], right_column[1]),
    )


def mix_columns(state: State) -> State:
    """Apply the encryption MixColumns matrix [[1, 4], [4, 1]]."""
    return _mix_columns_with_matrix(state, MIX_COLUMNS_MATRIX)


def inverse_mix_columns(state: State) -> State:
    """Apply the inverse MixColumns matrix [[9, 2], [2, 9]]."""
    return _mix_columns_with_matrix(state, INV_MIX_COLUMNS_MATRIX)


def sub_word_state(word: int, s_box: Sequence[int] = S_BOX) -> int:
    """Apply word substitution by converting through the state representation."""
    return state_to_word(sub_state(word_to_state(word), s_box))


def shift_rows_word(word: int) -> int:
    """Apply ShiftRows to a serialized 16-bit word."""
    return state_to_word(shift_rows(word_to_state(word)))


def inverse_shift_rows_word(word: int) -> int:
    """Apply inverse ShiftRows to a serialized 16-bit word."""
    return state_to_word(inverse_shift_rows(word_to_state(word)))


def mix_columns_word(word: int) -> int:
    """Apply MixColumns to a serialized 16-bit word."""
    return state_to_word(mix_columns(word_to_state(word)))


def inverse_mix_columns_word(word: int) -> int:
    """Apply inverse MixColumns to a serialized 16-bit word."""
    return state_to_word(inverse_mix_columns(word_to_state(word)))
