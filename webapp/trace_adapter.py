"""Adapters that reshape real SAES-XTS traces for the educational web UI."""

from __future__ import annotations

from string import hexdigits
from typing import Any

from algorithm.key_schedule import ROUND_CONSTANTS, expand_words, rot_nib, sub_nib
from algorithm.round_ops import MIX_COLUMNS_MATRIX, S_BOX, gf_multiply
from algorithm.saes import EncryptionTrace
from algorithm.xts import CTSBlockTrace, TWEAK_REDUCTION_POLYNOMIAL, XEXBlockTrace, encrypt_message_with_trace
from helpers.bit_utils import bytes_to_bits, int_to_bits, validate_width
from helpers.block_utils import bytes_to_word, split_blocks
from helpers.encoding_utils import describe_latin1_message
from helpers.state_utils import state_to_rows, word_to_state

DEFAULT_PLAINTEXT = "ABABABX"
DEFAULT_DATA_KEY = 0x4AF5
DEFAULT_TWEAK_KEY = 0xBEEF
DEFAULT_DATA_UNIT = 0x0001


def parse_uint16(value: str, field_name: str) -> int:
    """Parse a 16-bit integer from hex, binary, or decimal user input."""

    cleaned = value.strip().replace("_", "").replace(" ", "")
    if not cleaned:
        raise ValueError(f"{field_name} is required.")

    try:
        if cleaned.lower().startswith(("0x", "0b")):
            parsed = int(cleaned, 0)
        elif any(character in "ABCDEFabcdef" for character in cleaned):
            parsed = int(cleaned, 16)
        elif len(cleaned) == 4 and all(character in hexdigits for character in cleaned):
            parsed = int(cleaned, 16)
        else:
            parsed = int(cleaned, 10)
    except ValueError as exc:
        raise ValueError(
            f"{field_name} must be a 16-bit value written as hex, binary, or decimal."
        ) from exc

    validate_width(parsed, 16, field_name)
    return parsed


def normalize_encryption_inputs(
    plaintext_text: str,
    data_key_text: str,
    tweak_key_text: str,
    data_unit_text: str,
) -> dict[str, Any]:
    """Validate and normalize raw user input from the Streamlit form."""

    if plaintext_text == "":
        raise ValueError("Enter at least one plaintext character.")

    return {
        "plaintext_text": plaintext_text,
        "data_key": parse_uint16(data_key_text, "Data key"),
        "tweak_key": parse_uint16(tweak_key_text, "Tweak key"),
        "data_unit": parse_uint16(data_unit_text, "Data-unit value"),
        "data_key_text": data_key_text,
        "tweak_key_text": tweak_key_text,
        "data_unit_text": data_unit_text,
    }


def _clean_grouped_bits(grouped_bits: str) -> str:
    return grouped_bits.replace(" ", "")


def _bitwise_rows(left_bits: str, right_bits: str, result_bits: str) -> list[dict[str, str | int]]:
    """Build a bit-by-bit XOR comparison table for educational screens."""

    left = _clean_grouped_bits(left_bits)
    right = _clean_grouped_bits(right_bits)
    result = _clean_grouped_bits(result_bits)
    return [
        {
            "position": len(left) - index - 1,
            "left": left_bit,
            "right": right_bit,
            "result": result_bit,
        }
        for index, (left_bit, right_bit, result_bit) in enumerate(zip(left, right, result))
    ]


def _s_box_rows() -> list[list[str]]:
    """Return the S-box in a 4x4 grid for the wizard screens."""

    return [[f"{S_BOX[row * 4 + col]:X}" for col in range(4)] for row in range(4)]


def _tweak_progression_data(used_tweaks: list[int]) -> dict[str, Any]:
    """Describe tweak derivation and alpha-multiplication progression."""

    if not used_tweaks:
        raise ValueError("At least one tweak value is required.")

    snapshots = [_snapshot_word(tweak) for tweak in used_tweaks]
    progression = []
    for index in range(len(used_tweaks) - 1):
        current = used_tweaks[index]
        shifted = (current << 1) & 0xFFFF
        carry = bool(current & 0x8000)
        next_tweak = used_tweaks[index + 1]
        progression.append(
            {
                "from_label": f"T{index}",
                "to_label": f"T{index + 1}",
                "from": snapshots[index],
                "shifted": _snapshot_word(shifted),
                "carry": carry,
                "reduction_constant_hex": f"{TWEAK_REDUCTION_POLYNOMIAL:04X}",
                "reduction_applied": carry,
                "to": snapshots[index + 1],
                "note": (
                    "High bit spilled out, so XOR with the reduction polynomial 0x002D."
                    if carry
                    else "No spill from the high bit, so the shift result is already the next tweak."
                ),
            }
        )
    return {
        "values": [{"label": f"T{index}", "snapshot": snapshot} for index, snapshot in enumerate(snapshots)],
        "progression": progression,
    }


def _snapshot_byte(value: int) -> dict[str, Any]:
    """Return an 8-bit snapshot for key-schedule displays."""

    return {
        "value": value,
        "hex": f"{value:02X}",
        "bits": int_to_bits(value, 8),
        "high_nibble_bits": format((value >> 4) & 0xF, "04b"),
        "low_nibble_bits": format(value & 0xF, "04b"),
    }


def _build_key_schedule_detail(key: int) -> dict[str, Any]:
    """Describe the real S-AES key expansion in a UI-friendly structure."""

    w0, w1, w2, w3, w4, w5 = expand_words(key)
    words = [w0, w1, w2, w3, w4, w5]
    round_keys = [
        (w0 << 8) | w1,
        (w2 << 8) | w3,
        (w4 << 8) | w5,
    ]

    temporary_inputs = ((w1, ROUND_CONSTANTS[0]), (w3, ROUND_CONSTANTS[1]))
    temporaries = []
    for temp_label, (source_word, rcon_value) in zip(("t2", "t4"), temporary_inputs):
        rotated = rot_nib(source_word)
        substituted = sub_nib(rotated)
        output = substituted ^ rcon_value
        temporaries.append(
            {
                "label": temp_label,
                "input": _snapshot_byte(source_word),
                "rotated": _snapshot_byte(rotated),
                "substituted": _snapshot_byte(substituted),
                "rcon": _snapshot_byte(rcon_value),
                "output": _snapshot_byte(output),
                "formula": f"{temp_label} = SubNib(RotNib({_snapshot_byte(source_word)['hex']})) xor {rcon_value:02X}",
            }
        )

    xor_steps = [
        ("w2", "w0", _snapshot_byte(w0), "t2", temporaries[0]["output"], _snapshot_byte(w2)),
        ("w3", "w2", _snapshot_byte(w2), "w1", _snapshot_byte(w1), _snapshot_byte(w3)),
        ("w4", "w2", _snapshot_byte(w2), "t4", temporaries[1]["output"], _snapshot_byte(w4)),
        ("w5", "w4", _snapshot_byte(w4), "w3", _snapshot_byte(w3), _snapshot_byte(w5)),
    ]

    return {
        "cipher_key": _snapshot_word(key),
        "nibbles": [
            {"label": f"n{index}", "hex": nibble, "bits": format(int(nibble, 16), "04b")}
            for index, nibble in enumerate(f"{key:04X}")
        ],
        "words": [{"label": f"w{index}", "snapshot": _snapshot_byte(word)} for index, word in enumerate(words)],
        "temporaries": temporaries,
        "xor_steps": [
            {
                "label": label,
                "left_label": left_label,
                "left": left,
                "right_label": right_label,
                "right": right,
                "result": result,
                "bitwise_rows": _bitwise_rows(left["bits"], right["bits"], result["bits"]),
            }
            for label, left_label, left, right_label, right, result in xor_steps
        ],
        "round_keys": [
            {
                "label": f"K{index}",
                "snapshot": _snapshot_word(round_key),
                "word_labels": (f"w{index * 2}", f"w{index * 2 + 1}"),
            }
            for index, round_key in enumerate(round_keys)
        ],
        "operation_notes": {
            "rot_nib": "RotWord / RotNib swaps the two nibbles in one 8-bit word.",
            "sub_nib": "SubWord / SubNib sends each 4-bit nibble through the S-AES S-box.",
            "rcon": "RCon injects the round constant so each expansion round differs.",
        },
    }


def build_encryption_walkthrough(
    plaintext_text: str,
    data_key: int,
    tweak_key: int,
    data_unit: int,
) -> dict[str, Any]:
    """Build the full educational encryption payload used by the web app."""

    encoding = describe_latin1_message(plaintext_text)
    plaintext_bytes = encoding["bytes"]
    ciphertext, xts_trace = encrypt_message_with_trace(plaintext_bytes, data_key, tweak_key, data_unit)
    cipher_blocks, cipher_tail = split_blocks(ciphertext, 2)

    message_blocks = list(encoding["blocks"])
    if encoding["tail"] is not None:
        message_blocks.append(encoding["tail"])

    ciphertext_blocks = [_snapshot_block(block, index=index, role="ciphertext") for index, block in enumerate(cipher_blocks)]
    if cipher_tail:
        ciphertext_blocks.append(_snapshot_block(cipher_tail, index=len(cipher_blocks), role="ciphertext-tail"))

    cts_detail = _build_cts_detail(xts_trace.cts_trace) if xts_trace.cts_trace else None
    used_tweaks = [block_trace.tweak for block_trace in xts_trace.block_traces]
    if not used_tweaks:
        used_tweaks = [xts_trace.initial_tweak]
    if cts_detail is not None:
        provisional_tweak = cts_detail["provisional_tweak"]["word"]
        final_tweak = cts_detail["final_tweak"]["word"]
        if used_tweaks[-1] != provisional_tweak:
            used_tweaks.append(provisional_tweak)
        used_tweaks.append(final_tweak)

    tweak_generation = _tweak_progression_data(used_tweaks)
    regular_block_rows = [_build_regular_row(block_trace) for block_trace in xts_trace.block_traces]
    block_options, block_details = _build_block_detail_index(xts_trace.block_traces, xts_trace.cts_trace)
    if not block_options:
        raise ValueError("The selected message does not expose any full block encryption detail to inspect.")

    block_selection = _build_block_selection_entries(xts_trace.block_traces, cts_detail)
    final_assignment = _build_final_assignment_entries(xts_trace.block_traces, cts_detail)

    return {
        "constants": {
            "s_box_rows": _s_box_rows(),
            "s_box_axis_labels": ["00", "01", "10", "11"],
            "mix_columns_matrix": [[str(value) for value in row] for row in MIX_COLUMNS_MATRIX],
            "tweak_reduction_polynomial_hex": f"{TWEAK_REDUCTION_POLYNOMIAL:04X}",
        },
        "inputs": {
            "plaintext_text": plaintext_text,
            "plaintext_bytes": plaintext_bytes,
            "plaintext_hex": " ".join(f"{byte:02X}" for byte in plaintext_bytes),
            "plaintext_bits": bytes_to_bits(plaintext_bytes),
            "encoding_label": "Latin-1 / ASCII, 8 bits per character",
            "data_key": _snapshot_word(data_key),
            "tweak_key": _snapshot_word(tweak_key),
            "data_unit": _snapshot_word(data_unit),
        },
        "encoding": encoding,
        "tweak_generation": {
            "data_unit": _snapshot_word(data_unit),
            "tweak_key": _snapshot_word(tweak_key),
            "initial_tweak": _snapshot_word(xts_trace.initial_tweak),
            "black_box_label": "T0 = S-AES_{tweak key}(data-unit)",
            "alpha_constant": {
                "decimal": 2,
                "hex": "0002",
                "bits": int_to_bits(2, 16),
                "explanation": "Alpha is the field element 2, so multiplying by alpha starts as a left shift.",
            },
            **tweak_generation,
        },
        "key_schedule": _build_key_schedule_detail(data_key),
        "overview": {
            "initial_tweak": _snapshot_word(xts_trace.initial_tweak),
            "used_ciphertext_stealing": xts_trace.used_ciphertext_stealing,
            "message_blocks": message_blocks,
            "ciphertext_blocks": ciphertext_blocks,
            "regular_block_rows": regular_block_rows,
            "tweak_sequence": tweak_generation["values"],
            "block_count": len(message_blocks),
        },
        "block_selection": block_selection,
        "final_assignment": final_assignment,
        "block_options": block_options,
        "block_details": block_details,
        "default_block_id": block_options[0]["id"],
        "cts": cts_detail,
        "output": {
            "ciphertext_bytes": list(ciphertext),
            "ciphertext_hex": " ".join(f"{byte:02X}" for byte in ciphertext),
            "ciphertext_bits": bytes_to_bits(ciphertext),
            "ciphertext_blocks": ciphertext_blocks,
            "used_ciphertext_stealing": xts_trace.used_ciphertext_stealing,
        },
    }


def extract_block_detail(walkthrough: dict[str, Any], block_id: str) -> dict[str, Any]:
    """Return one selected block detail for the UI."""

    try:
        return walkthrough["block_details"][block_id]
    except KeyError as exc:
        raise ValueError(f"Unknown block selection: {block_id!r}.") from exc


def _build_regular_row(block_trace: XEXBlockTrace) -> dict[str, Any]:
    return {
        "block_index": block_trace.block_index,
        "kind": "regular",
        "plaintext_hex": block_trace.input_block.hex().upper(),
        "tweak_hex": f"{block_trace.tweak:04X}",
        "pre_whitened_hex": f"{block_trace.pre_whitened:04X}",
        "core_output_hex": f"{block_trace.core_output:04X}",
        "ciphertext_hex": block_trace.output_block.hex().upper(),
        "tweak_after_hex": f"{block_trace.tweak_after:04X}",
    }


def _build_block_selection_entries(
    block_traces: tuple[XEXBlockTrace, ...],
    cts_detail: dict[str, Any] | None,
) -> dict[str, Any]:
    """Build the wizard's block/tweak chooser entries."""

    options = []
    for block_trace in block_traces:
        options.append(
            {
                "id": f"regular:{block_trace.block_index}",
                "kind": "regular",
                "label": f"Block {block_trace.block_index}",
                "plaintext_block": _snapshot_block(block_trace.input_block, index=block_trace.block_index, role="plaintext"),
                "tweak": _snapshot_word(block_trace.tweak),
                "caption": "Full 16-bit block processed with the standard XEX structure.",
            }
        )

    if cts_detail is not None:
        options.append(
            {
                "id": "tail-case",
                "kind": "tail",
                "label": "Last 1.5 blocks - ciphertext stealing",
                "plaintext_block": cts_detail["penultimate_plaintext"],
                "tail_block": cts_detail["partial_plaintext"],
                "provisional_tweak": cts_detail["provisional_tweak"],
                "final_tweak": cts_detail["final_tweak"],
                "caption": "The final full block and the 8-bit tail must be handled together.",
            }
        )

    if not options:
        raise ValueError("At least one block-selection option is required.")

    return {
        "options": options,
        "default_selection_id": options[0]["id"],
    }


def _build_final_assignment_entries(
    block_traces: tuple[XEXBlockTrace, ...],
    cts_detail: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Build the final overview rows that include ciphertext outputs."""

    entries = []
    for block_trace in block_traces:
        entries.append(
            {
                "id": f"regular:{block_trace.block_index}",
                "kind": "regular",
                "label": f"Block {block_trace.block_index}",
                "plaintext_block": _snapshot_block(block_trace.input_block, index=block_trace.block_index, role="plaintext"),
                "tweak": _snapshot_word(block_trace.tweak),
                "ciphertext_block": _snapshot_block(block_trace.output_block, index=block_trace.block_index, role="ciphertext"),
            }
        )

    if cts_detail is not None:
        entries.append(
            {
                "id": "tail-case",
                "kind": "tail",
                "label": "Last 1.5 blocks - ciphertext stealing",
                "plaintext_block": cts_detail["penultimate_plaintext"],
                "tail_block": cts_detail["partial_plaintext"],
                "provisional_tweak": cts_detail["provisional_tweak"],
                "final_tweak": cts_detail["final_tweak"],
                "ciphertext_block": cts_detail["final_penultimate_ciphertext"],
                "ciphertext_tail": cts_detail["stolen_fragment"],
            }
        )

    return entries


def _build_block_detail_index(
    block_traces: tuple[XEXBlockTrace, ...],
    cts_trace: CTSBlockTrace | None,
) -> tuple[list[dict[str, str]], dict[str, dict[str, Any]]]:
    block_options: list[dict[str, str]] = []
    block_details: dict[str, dict[str, Any]] = {}

    for block_trace in block_traces:
        block_id = f"regular:{block_trace.block_index}"
        block_options.append({"id": block_id, "label": f"Block {block_trace.block_index} - standard XEX"})
        block_details[block_id] = _regular_block_detail(block_trace)

    if cts_trace is not None:
        provisional_id = f"cts-provisional:{cts_trace.block_index}"
        composite_id = f"cts-composite:{cts_trace.block_index}"
        block_options.append(
            {
                "id": provisional_id,
                "label": f"Block {cts_trace.block_index} - CTS provisional full block",
            }
        )
        block_options.append(
            {
                "id": composite_id,
                "label": f"Block {cts_trace.block_index} - CTS composite full block",
            }
        )
        block_details[provisional_id] = _cts_provisional_detail(cts_trace)
        block_details[composite_id] = _cts_composite_detail(cts_trace)

    return block_options, block_details


def _build_regular_wizard(detail: dict[str, Any]) -> dict[str, Any]:
    """Build screen-oriented payloads for the normal block wizard path."""

    saes = detail["saes"]
    round_keys = saes["round_keys"]
    round1_key = round_keys[1]
    round2_key = round_keys[2]
    return {
        "xts_overview": {
            "plaintext_word": detail["plaintext_word"],
            "tweak": detail["tweak"],
            "pre_whitened": detail["pre_whitened"],
            "saes_output": detail["core_output"],
            "ciphertext_word": detail["ciphertext_word"],
        },
        "pre_xor": {
            "plaintext_word": detail["plaintext_word"],
            "tweak": detail["tweak"],
            "result": detail["pre_whitened"],
            "bitwise_rows": _bitwise_rows(
                detail["plaintext_word"]["bits"],
                detail["tweak"]["bits"],
                detail["pre_whitened"]["bits"],
            ),
        },
        "saes_initial_add_round_key": {
            "round_key": round_keys[0],
            "before": saes["input"],
            "after": saes["operations"][0]["after"],
            "bitwise_rows": _bitwise_rows(
                saes["input"]["bits"],
                round_keys[0]["bits"],
                saes["operations"][0]["after"]["bits"],
            ),
        },
        "round1": {
            "round_key": round1_key,
            "overview_steps": ["SubNib", "ShiftRows", "MixColumns", "AddRoundKey"],
            "subnib": saes["operations"][1],
            "shiftrows": saes["operations"][2],
            "mixcolumns": {
                **saes["operations"][3],
                "matrix": [[str(value) for value in row] for row in MIX_COLUMNS_MATRIX],
            },
            "add_round_key": {
                **saes["operations"][4],
                "bitwise_rows": _bitwise_rows(
                    saes["operations"][4]["before"]["bits"],
                    round1_key["bits"],
                    saes["operations"][4]["after"]["bits"],
                ),
            },
        },
        "round2": {
            "round_key": round2_key,
            "overview_steps": ["SubNib", "ShiftRows", "AddRoundKey"],
            "subnib": saes["operations"][5],
            "shiftrows": saes["operations"][6],
            "add_round_key": {
                **saes["operations"][7],
                "bitwise_rows": _bitwise_rows(
                    saes["operations"][7]["before"]["bits"],
                    round2_key["bits"],
                    saes["operations"][7]["after"]["bits"],
                ),
            },
        },
        "post_xor": {
            "saes_output": detail["core_output"],
            "tweak": detail["tweak"],
            "ciphertext_word": detail["ciphertext_word"],
            "bitwise_rows": _bitwise_rows(
                detail["core_output"]["bits"],
                detail["tweak"]["bits"],
                detail["ciphertext_word"]["bits"],
            ),
        },
    }


def _regular_block_detail(block_trace: XEXBlockTrace) -> dict[str, Any]:
    plaintext_word = bytes_to_word(block_trace.input_block)
    ciphertext_word = int.from_bytes(block_trace.output_block, byteorder="big")
    detail = {
        "id": f"regular:{block_trace.block_index}",
        "label": f"Block {block_trace.block_index}",
        "kind": "regular",
        "note": "This is a standard SAES-XTS block with pre-whitening, S-AES encryption, and post-whitening.",
        "block_index": block_trace.block_index,
        "plaintext_block": _snapshot_block(block_trace.input_block, index=block_trace.block_index, role="plaintext"),
        "plaintext_word": _snapshot_word(plaintext_word),
        "tweak": _snapshot_word(block_trace.tweak),
        "pre_whitened": _snapshot_word(block_trace.pre_whitened),
        "saes": _build_saes_detail(block_trace.saes_trace),
        "core_output": _snapshot_word(block_trace.core_output),
        "ciphertext_block": _snapshot_block(block_trace.output_block, index=block_trace.block_index, role="ciphertext"),
        "ciphertext_word": _snapshot_word(ciphertext_word),
    }
    detail["wizard"] = _build_regular_wizard(detail)
    return detail


def _cts_provisional_detail(cts_trace: CTSBlockTrace) -> dict[str, Any]:
    plaintext_word = bytes_to_word(cts_trace.penultimate_plaintext_block)
    provisional_word = int.from_bytes(cts_trace.provisional_ciphertext_block, byteorder="big")
    detail = {
        "id": f"cts-provisional:{cts_trace.block_index}",
        "label": f"CTS provisional block {cts_trace.block_index}",
        "kind": "cts_provisional",
        "note": (
            "This is the provisional encryption of the final full plaintext block before the short tail steals bytes "
            "from its ciphertext."
        ),
        "block_index": cts_trace.block_index,
        "plaintext_block": _snapshot_block(
            cts_trace.penultimate_plaintext_block,
            index=cts_trace.block_index,
            role="cts-penultimate-plaintext",
        ),
        "plaintext_word": _snapshot_word(plaintext_word),
        "tweak": _snapshot_word(cts_trace.provisional_tweak),
        "pre_whitened": _snapshot_word(cts_trace.provisional_pre_whitened),
        "saes": _build_saes_detail(cts_trace.provisional_saes_trace),
        "core_output": _snapshot_word(cts_trace.provisional_core_output),
        "ciphertext_block": _snapshot_block(
            cts_trace.provisional_ciphertext_block,
            index=cts_trace.block_index,
            role="cts-provisional-ciphertext",
        ),
        "ciphertext_word": _snapshot_word(provisional_word),
    }
    detail["wizard"] = _build_regular_wizard(detail)
    return detail


def _cts_composite_detail(cts_trace: CTSBlockTrace) -> dict[str, Any]:
    plaintext_word = bytes_to_word(cts_trace.composite_plaintext_block)
    final_word = int.from_bytes(cts_trace.final_penultimate_ciphertext_block, byteorder="big")
    detail = {
        "id": f"cts-composite:{cts_trace.block_index}",
        "label": f"CTS composite block {cts_trace.block_index}",
        "kind": "cts_composite",
        "note": (
            "This full block is built from the short final plaintext byte plus the unstolen byte from the provisional "
            "ciphertext block."
        ),
        "block_index": cts_trace.block_index,
        "plaintext_block": _snapshot_block(
            cts_trace.composite_plaintext_block,
            index=cts_trace.block_index,
            role="cts-composite-plaintext",
        ),
        "plaintext_word": _snapshot_word(plaintext_word),
        "tweak": _snapshot_word(cts_trace.final_tweak),
        "pre_whitened": _snapshot_word(cts_trace.composite_pre_whitened),
        "saes": _build_saes_detail(cts_trace.composite_saes_trace),
        "core_output": _snapshot_word(cts_trace.composite_core_output),
        "ciphertext_block": _snapshot_block(
            cts_trace.final_penultimate_ciphertext_block,
            index=cts_trace.block_index,
            role="cts-final-penultimate-ciphertext",
        ),
        "ciphertext_word": _snapshot_word(final_word),
    }
    detail["wizard"] = _build_regular_wizard(detail)
    return detail


def _build_cts_detail(cts_trace: CTSBlockTrace) -> dict[str, Any]:
    retained_fragment = cts_trace.provisional_ciphertext_block[cts_trace.partial_length:]
    cts_detail = {
        "block_index": cts_trace.block_index,
        "partial_length": cts_trace.partial_length,
        "penultimate_plaintext": _snapshot_block(
            cts_trace.penultimate_plaintext_block,
            index=cts_trace.block_index,
            role="cts-penultimate-plaintext",
        ),
        "partial_plaintext": _snapshot_block(
            cts_trace.partial_plaintext_block,
            index=cts_trace.block_index + 1,
            role="cts-tail-plaintext",
        ),
        "provisional_tweak": _snapshot_word(cts_trace.provisional_tweak),
        "final_tweak": _snapshot_word(cts_trace.final_tweak),
        "provisional_ciphertext": _snapshot_block(
            cts_trace.provisional_ciphertext_block,
            index=cts_trace.block_index,
            role="cts-provisional-ciphertext",
        ),
        "stolen_fragment": _snapshot_block(
            cts_trace.stolen_ciphertext_fragment,
            index=cts_trace.block_index + 1,
            role="cts-stolen-fragment",
        ),
        "retained_fragment": _snapshot_block(
            retained_fragment,
            index=cts_trace.block_index,
            role="cts-retained-fragment",
        ),
        "composite_plaintext": _snapshot_block(
            cts_trace.composite_plaintext_block,
            index=cts_trace.block_index,
            role="cts-composite-plaintext",
        ),
        "final_penultimate_ciphertext": _snapshot_block(
            cts_trace.final_penultimate_ciphertext_block,
            index=cts_trace.block_index,
            role="cts-final-penultimate-ciphertext",
        ),
        "length_preserved": len(cts_trace.penultimate_plaintext_block) + len(cts_trace.partial_plaintext_block)
        == len(cts_trace.final_penultimate_ciphertext_block) + len(cts_trace.stolen_ciphertext_fragment),
        "notes": [
            "The final 8-bit tail cannot be encrypted directly as a 16-bit S-AES block.",
            "A provisional ciphertext block is first produced from the last full plaintext block.",
            "The first byte of that provisional ciphertext is stolen to become the final short ciphertext tail.",
            "The remaining provisional byte is combined with the short plaintext byte to form a composite full block.",
        ],
    }
    cts_detail["wizard"] = {
        "selection_id": "tail-case",
        "current_tweaks": [cts_detail["provisional_tweak"], cts_detail["final_tweak"]],
        "rearrangement_rows": [
            {
                "stage": "Start",
                "left": cts_detail["penultimate_plaintext"]["hex"],
                "middle": cts_detail["partial_plaintext"]["hex"],
                "right": "One full block plus one 8-bit tail",
            },
            {
                "stage": "Provisional encryption",
                "left": cts_detail["provisional_ciphertext"]["hex"],
                "middle": cts_detail["stolen_fragment"]["hex"],
                "right": "The first byte is reserved for the short final ciphertext tail",
            },
            {
                "stage": "Composite plaintext",
                "left": cts_detail["partial_plaintext"]["hex"],
                "middle": cts_detail["retained_fragment"]["hex"],
                "right": "Short plaintext byte plus retained provisional byte make a full 16-bit block",
            },
            {
                "stage": "Final outputs",
                "left": cts_detail["final_penultimate_ciphertext"]["hex"],
                "middle": cts_detail["stolen_fragment"]["hex"],
                "right": "These become the last full ciphertext block and the final 8-bit tail",
            },
        ],
    }
    return cts_detail

def _build_saes_detail(trace: EncryptionTrace) -> dict[str, Any]:
    round_keys = [_snapshot_word(key) for key in trace.round_keys]
    return {
        "input": _snapshot_word(trace.plaintext),
        "round_keys": round_keys,
        "operations": [
            {
                "name": "AddRoundKey K0",
                "before": _snapshot_word(trace.plaintext),
                "after": _snapshot_word(trace.after_add_round_key),
                "key": round_keys[0],
                "kind": "xor",
            },
            {
                "name": "SubNib",
                "before": _snapshot_word(trace.after_add_round_key),
                "after": _snapshot_word(trace.after_sub_nibbles),
                "kind": "subnib",
                "mappings": _subnib_details(trace.after_add_round_key, trace.after_sub_nibbles),
            },
            {
                "name": "ShiftRows",
                "before": _snapshot_word(trace.after_sub_nibbles),
                "after": _snapshot_word(trace.after_shift_rows),
                "kind": "shiftrows",
                "moves": [
                    {"label": "s10", "from": (1, 0), "to": (1, 1)},
                    {"label": "s11", "from": (1, 1), "to": (1, 0)},
                ],
            },
            {
                "name": "MixColumns",
                "before": _snapshot_word(trace.after_shift_rows),
                "after": _snapshot_word(trace.after_mix_columns),
                "kind": "mixcolumns",
                "columns": _mixcolumns_details(trace.after_shift_rows, trace.after_mix_columns),
            },
            {
                "name": "AddRoundKey K1",
                "before": _snapshot_word(trace.after_mix_columns),
                "after": _snapshot_word(trace.after_round_one_key),
                "key": round_keys[1],
                "kind": "xor",
            },
            {
                "name": "Final SubNib",
                "before": _snapshot_word(trace.after_round_one_key),
                "after": _snapshot_word(trace.after_final_sub_nibbles),
                "kind": "subnib",
                "mappings": _subnib_details(trace.after_round_one_key, trace.after_final_sub_nibbles),
            },
            {
                "name": "Final ShiftRows",
                "before": _snapshot_word(trace.after_final_sub_nibbles),
                "after": _snapshot_word(trace.after_final_shift_rows),
                "kind": "shiftrows",
                "moves": [
                    {"label": "s10", "from": (1, 0), "to": (1, 1)},
                    {"label": "s11", "from": (1, 1), "to": (1, 0)},
                ],
            },
            {
                "name": "AddRoundKey K2",
                "before": _snapshot_word(trace.after_final_shift_rows),
                "after": _snapshot_word(trace.ciphertext),
                "key": round_keys[2],
                "kind": "xor",
            },
        ],
        "output": _snapshot_word(trace.ciphertext),
    }


def _snapshot_block(block: bytes, *, index: int, role: str) -> dict[str, Any]:
    return {
        "index": index,
        "role": role,
        "bytes": list(block),
        "byte_hex": [f"{byte:02X}" for byte in block],
        "hex": block.hex().upper(),
        "bits": bytes_to_bits(block),
        "length": len(block),
        "is_partial": len(block) < 2,
    }


def _snapshot_word(word: int) -> dict[str, Any]:
    state = word_to_state(word)
    row_bits = state_to_rows(state)
    cells = []
    labels = ("s00", "s01", "s10", "s11")
    label_index = 0
    for row in range(2):
        for col in range(2):
            value = state[row][col]
            cells.append(
                {
                    "label": labels[label_index],
                    "row": row,
                    "col": col,
                    "hex": f"{value:X}",
                    "bits": format(value, "04b"),
                    "int": value,
                }
            )
            label_index += 1
    return {
        "word": word,
        "hex": f"{word:04X}",
        "bits": int_to_bits(word, 16),
        "state_hex_rows": [[f"{state[row][col]:X}" for col in range(2)] for row in range(2)],
        "state_bit_rows": [[row_bits[row][col] for col in range(2)] for row in range(2)],
        "cells": cells,
    }


def _subnib_details(before_word: int, after_word: int) -> list[dict[str, Any]]:
    before = _snapshot_word(before_word)
    after = _snapshot_word(after_word)
    details = []
    for before_cell, after_cell in zip(before["cells"], after["cells"]):
        row_bits = before_cell["bits"][:2]
        col_bits = before_cell["bits"][2:]
        details.append(
            {
                "label": before_cell["label"],
                "row": before_cell["row"],
                "col": before_cell["col"],
                "before": before_cell["hex"],
                "before_bits": before_cell["bits"],
                "row_bits": row_bits,
                "column_bits": col_bits,
                "after": after_cell["hex"],
                "after_bits": after_cell["bits"],
            }
        )
    return details


def _mixcolumns_details(before_word: int, after_word: int) -> list[dict[str, Any]]:
    before_state = word_to_state(before_word)
    after_state = word_to_state(after_word)
    columns = []
    for col in range(2):
        top_input = before_state[0][col]
        bottom_input = before_state[1][col]
        top_output = after_state[0][col]
        bottom_output = after_state[1][col]
        columns.append(
            {
                "index": col,
                "input": [f"{top_input:X}", f"{bottom_input:X}"],
                "output": [f"{top_output:X}", f"{bottom_output:X}"],
                "top_formula": f"1*{top_input:X} xor 4*{bottom_input:X} = {top_output:X}",
                "bottom_formula": f"4*{top_input:X} xor 1*{bottom_input:X} = {bottom_output:X}",
                "top_terms": [
                    f"1*{top_input:X} = {gf_multiply(0x1, top_input):X}",
                    f"4*{bottom_input:X} = {gf_multiply(0x4, bottom_input):X}",
                ],
                "bottom_terms": [
                    f"4*{top_input:X} = {gf_multiply(0x4, top_input):X}",
                    f"1*{bottom_input:X} = {gf_multiply(0x1, bottom_input):X}",
                ],
            }
        )
    return columns
