"""Pure simplified AES implementation following the local PDF example."""

from __future__ import annotations

from dataclasses import dataclass

from helpers.bit_utils import bits_to_int, int_to_bits, validate_width, xor_words
from .key_schedule import expand_round_keys
from .round_ops import (
    inverse_mix_columns_word,
    inverse_shift_rows_word,
    inverse_substitute_word,
    mix_columns_word,
    shift_rows_word,
    substitute_word,
)


@dataclass(frozen=True)
class EncryptionTrace:
    """Intermediate 16-bit values produced during encryption."""

    plaintext: int
    round_keys: tuple[int, int, int]
    after_add_round_key: int
    after_sub_nibbles: int
    after_shift_rows: int
    after_mix_columns: int
    after_round_one_key: int
    after_final_sub_nibbles: int
    after_final_shift_rows: int
    ciphertext: int


@dataclass(frozen=True)
class DecryptionTrace:
    """Intermediate 16-bit values produced during decryption."""

    ciphertext: int
    round_keys: tuple[int, int, int]
    after_add_round_key: int
    after_inverse_shift_rows: int
    after_inverse_sub_nibbles: int
    after_round_one_key: int
    after_inverse_mix_columns: int
    after_final_inverse_shift_rows: int
    after_final_inverse_sub_nibbles: int
    plaintext: int


def encrypt_block_with_trace(plaintext: int, key: int) -> EncryptionTrace:
    """Encrypt one 16-bit block and return the intermediate round values."""
    validate_width(plaintext, 16, "plaintext")
    validate_width(key, 16, "key")
    key0, key1, key2 = expand_round_keys(key)

    after_add_round_key = xor_words(plaintext, key0)
    after_sub_nibbles = substitute_word(after_add_round_key)
    after_shift_rows = shift_rows_word(after_sub_nibbles)
    after_mix_columns = mix_columns_word(after_shift_rows)
    after_round_one_key = xor_words(after_mix_columns, key1)
    after_final_sub_nibbles = substitute_word(after_round_one_key)
    after_final_shift_rows = shift_rows_word(after_final_sub_nibbles)
    ciphertext = xor_words(after_final_shift_rows, key2)

    return EncryptionTrace(
        plaintext=plaintext,
        round_keys=(key0, key1, key2),
        after_add_round_key=after_add_round_key,
        after_sub_nibbles=after_sub_nibbles,
        after_shift_rows=after_shift_rows,
        after_mix_columns=after_mix_columns,
        after_round_one_key=after_round_one_key,
        after_final_sub_nibbles=after_final_sub_nibbles,
        after_final_shift_rows=after_final_shift_rows,
        ciphertext=ciphertext,
    )


def encrypt_block(plaintext: int, key: int) -> int:
    """Encrypt a single 16-bit block."""
    return encrypt_block_with_trace(plaintext, key).ciphertext


def decrypt_block_with_trace(ciphertext: int, key: int) -> DecryptionTrace:
    """Decrypt a 16-bit ciphertext block and expose the inverse round states."""
    validate_width(ciphertext, 16, "ciphertext")
    validate_width(key, 16, "key")
    key0, key1, key2 = expand_round_keys(key)

    after_add_round_key = xor_words(ciphertext, key2)
    after_inverse_shift_rows = inverse_shift_rows_word(after_add_round_key)
    after_inverse_sub_nibbles = inverse_substitute_word(after_inverse_shift_rows)
    after_round_one_key = xor_words(after_inverse_sub_nibbles, key1)
    after_inverse_mix_columns = inverse_mix_columns_word(after_round_one_key)
    after_final_inverse_shift_rows = inverse_shift_rows_word(after_inverse_mix_columns)
    after_final_inverse_sub_nibbles = inverse_substitute_word(after_final_inverse_shift_rows)
    plaintext = xor_words(after_final_inverse_sub_nibbles, key0)

    return DecryptionTrace(
        ciphertext=ciphertext,
        round_keys=(key0, key1, key2),
        after_add_round_key=after_add_round_key,
        after_inverse_shift_rows=after_inverse_shift_rows,
        after_inverse_sub_nibbles=after_inverse_sub_nibbles,
        after_round_one_key=after_round_one_key,
        after_inverse_mix_columns=after_inverse_mix_columns,
        after_final_inverse_shift_rows=after_final_inverse_shift_rows,
        after_final_inverse_sub_nibbles=after_final_inverse_sub_nibbles,
        plaintext=plaintext,
    )


def decrypt_block(ciphertext: int, key: int) -> int:
    """Decrypt a single 16-bit block."""
    return decrypt_block_with_trace(ciphertext, key).plaintext


def encrypt_bits(plaintext_bits: str, key_bits: str) -> str:
    """Encrypt grouped or ungrouped bitstrings and return grouped ciphertext bits."""
    ciphertext = encrypt_block(bits_to_int(plaintext_bits), bits_to_int(key_bits))
    return int_to_bits(ciphertext, width=16)


def decrypt_bits(ciphertext_bits: str, key_bits: str) -> str:
    """Decrypt grouped or ungrouped bitstrings and return grouped plaintext bits."""
    plaintext = decrypt_block(bits_to_int(ciphertext_bits), bits_to_int(key_bits))
    return int_to_bits(plaintext, width=16)
