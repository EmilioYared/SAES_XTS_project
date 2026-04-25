"""Utilities for packing 16-bit S-AES blocks and splitting byte messages."""

from __future__ import annotations

from typing import Sequence, Tuple

from .bit_utils import validate_width


def bytes_to_word(block: bytes) -> int:
    """Convert a 2-byte big-endian block into a 16-bit integer."""
    if len(block) != 2:
        raise ValueError(f"Expected a 2-byte block, got {len(block)} bytes.")
    return int.from_bytes(block, byteorder="big")


def word_to_bytes(word: int, length: int = 2) -> bytes:
    """Convert an integer into a big-endian byte string of fixed length."""
    validate_width(word, length * 8, "word")
    return word.to_bytes(length, byteorder="big")


def split_blocks(data: bytes, block_size: int = 2) -> tuple[tuple[bytes, ...], bytes]:
    """Split data into full blocks and a final remainder."""
    if block_size <= 0:
        raise ValueError("block_size must be positive.")
    full_block_count = len(data) // block_size
    full_blocks = tuple(
        data[index * block_size:(index + 1) * block_size]
        for index in range(full_block_count)
    )
    remainder = data[full_block_count * block_size:]
    return full_blocks, remainder


def join_blocks(blocks: Sequence[bytes], remainder: bytes = b"") -> bytes:
    """Join blocks and an optional remainder back into one byte string."""
    return b"".join(blocks) + remainder
