"""Reusable helper utilities for the educational cryptography project."""

from .bit_utils import (
    bits_to_bytes,
    bits_to_int,
    bytes_to_bits,
    int_to_bits,
    join_nibbles,
    split_nibbles,
    validate_width,
    xor_bytes,
    xor_words,
)
from .block_utils import bytes_to_word, join_blocks, split_blocks, word_to_bytes
from .encoding_utils import describe_latin1_message, encode_latin1_text

__all__ = [
    "bits_to_bytes",
    "bits_to_int",
    "bytes_to_bits",
    "bytes_to_word",
    "describe_latin1_message",
    "encode_latin1_text",
    "int_to_bits",
    "join_blocks",
    "join_nibbles",
    "split_blocks",
    "split_nibbles",
    "validate_width",
    "word_to_bytes",
    "xor_bytes",
    "xor_words",
]
