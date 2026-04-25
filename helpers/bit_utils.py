"""Bit and nibble utilities shared by the S-AES implementation and tests."""

from __future__ import annotations

from typing import Iterable, Tuple


def validate_width(value: int, width: int, name: str = "value") -> int:
    """Ensure an integer fits within the requested unsigned bit width."""
    if value < 0 or value >= (1 << width):
        raise ValueError(f"{name} must fit in {width} bits, got {value}.")
    return value


def bits_to_int(bits: str) -> int:
    """Parse a grouped or ungrouped binary string into an integer."""
    cleaned = bits.replace(" ", "").replace("_", "")
    if not cleaned:
        raise ValueError("bits must not be empty.")
    if any(bit not in "01" for bit in cleaned):
        raise ValueError(f"bits must contain only 0 or 1, got {bits!r}.")
    return int(cleaned, 2)


def int_to_bits(value: int, width: int) -> str:
    """Format an integer as grouped binary digits using 4-bit groups."""
    validate_width(value, width)
    raw = format(value, f"0{width}b")
    return " ".join(raw[index:index + 4] for index in range(0, width, 4))


def bytes_to_bits(data: bytes) -> str:
    """Format a byte string as grouped binary digits using 8-bit groups."""
    return " ".join(format(byte, "08b") for byte in data)


def bits_to_bytes(bits: str) -> bytes:
    """Parse a grouped bitstring into bytes.

    The total length must be byte-aligned.
    """

    cleaned = bits.replace(" ", "").replace("_", "")
    if not cleaned:
        return b""
    if len(cleaned) % 8 != 0:
        raise ValueError("Bitstrings used as messages must be byte-aligned.")
    if any(bit not in "01" for bit in cleaned):
        raise ValueError(f"bits must contain only 0 or 1, got {bits!r}.")
    return bytes(int(cleaned[index:index + 8], 2) for index in range(0, len(cleaned), 8))


def split_nibbles(value: int, count: int = 4) -> Tuple[int, ...]:
    """Split an integer into high-to-low 4-bit chunks."""
    validate_width(value, count * 4)
    return tuple((value >> (4 * shift)) & 0xF for shift in range(count - 1, -1, -1))


def join_nibbles(nibbles: Iterable[int]) -> int:
    """Pack an iterable of 4-bit values into one integer."""
    result = 0
    for nibble in nibbles:
        validate_width(nibble, 4, "nibble")
        result = (result << 4) | nibble
    return result


def xor_words(*values: int, width: int = 16) -> int:
    """XOR one or more integers and constrain the result to the requested width."""
    if not values:
        raise ValueError("xor_words requires at least one value.")
    result = 0
    for value in values:
        validate_width(value, width)
        result ^= value
    return result


def xor_bytes(left: bytes, right: bytes) -> bytes:
    """XOR two byte strings of the same length."""
    if len(left) != len(right):
        raise ValueError("Byte strings must be the same length to XOR.")
    return bytes(left_byte ^ right_byte for left_byte, right_byte in zip(left, right))
