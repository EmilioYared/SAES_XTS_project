"""Encoding and partitioning helpers for the educational web app."""

from __future__ import annotations

from typing import Any

from .bit_utils import bytes_to_bits
from .block_utils import bytes_to_word, split_blocks


def encode_latin1_text(text: str) -> bytes:
    """Encode plaintext as Latin-1 so each character maps to one byte.

    The educational UI treats plaintext as an 8-bit character stream. Latin-1
    is used because it provides a direct one-byte mapping for every character in
    the supported range and cleanly covers plain ASCII as a subset.
    """

    try:
        return text.encode("latin-1")
    except UnicodeEncodeError as exc:
        raise ValueError(
            "Plaintext must use only Latin-1 / ASCII characters so each character maps to one 8-bit byte."
        ) from exc


def describe_latin1_message(text: str, *, block_size: int = 2) -> dict[str, Any]:
    """Describe plaintext encoding and 16-bit block partitioning for the UI."""

    encoded = encode_latin1_text(text)
    full_blocks, tail = split_blocks(encoded, block_size)

    character_rows = []
    for index, (character, byte_value) in enumerate(zip(text, encoded)):
        block_index = index // block_size
        byte_offset = index % block_size
        is_tail = index >= len(full_blocks) * block_size
        if is_tail:
            block_label = f"Tail byte {byte_offset}"
        else:
            block_label = f"P{block_index} byte {byte_offset}"
        character_rows.append(
            {
                "index": index,
                "character": _display_character(character),
                "code_point": f"U+{ord(character):04X}",
                "byte": byte_value,
                "byte_hex": f"{byte_value:02X}",
                "bits": format(byte_value, "08b"),
                "block_label": block_label,
                "is_tail": is_tail,
            }
        )

    block_rows = []
    for index, block in enumerate(full_blocks):
        block_rows.append(_describe_chunk(block, index=index, role="full"))

    tail_row = _describe_chunk(tail, index=len(full_blocks), role="tail") if tail else None
    return {
        "text": text,
        "bytes": encoded,
        "bits": bytes_to_bits(encoded),
        "block_size": block_size,
        "character_rows": character_rows,
        "blocks": block_rows,
        "tail": tail_row,
        "has_tail": tail_row is not None,
    }


def _describe_chunk(block: bytes, *, index: int, role: str) -> dict[str, Any]:
    """Describe a full block or tail chunk for educational display."""

    entry = {
        "index": index,
        "role": role,
        "bytes": list(block),
        "byte_hex": [f"{byte:02X}" for byte in block],
        "hex": block.hex().upper(),
        "bits": bytes_to_bits(block),
        "ascii": "".join(_display_character(chr(byte), compact=True) for byte in block),
        "length": len(block),
        "is_partial": len(block) < 2,
    }
    if len(block) == 2:
        word = bytes_to_word(block)
        entry["word"] = word
        entry["word_hex"] = f"{word:04X}"
    return entry


def _display_character(character: str, *, compact: bool = False) -> str:
    """Render a user-facing character label for tables and badges."""

    special_names = {
        "\0": "\\0",
        "\t": "\\t",
        "\n": "\\n",
        "\r": "\\r",
    }
    if character in special_names:
        return special_names[character]
    if character == " ":
        return "space" if compact else "' '"
    if 32 <= ord(character) <= 126:
        return character
    return f"0x{ord(character):02X}"
