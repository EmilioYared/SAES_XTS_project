from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

from helpers.bit_utils import bits_to_bytes, bytes_to_bits, int_to_bits, validate_width, xor_words
from helpers.block_utils import bytes_to_word, split_blocks, word_to_bytes
from .saes import (
    DecryptionTrace,
    EncryptionTrace,
    decrypt_block_with_trace,
    encrypt_block_with_trace,
)

BLOCK_SIZE_BITS = 16
BLOCK_SIZE_BYTES = BLOCK_SIZE_BITS // 8
TWEAK_REDUCTION_POLYNOMIAL = 0x002D


@dataclass(frozen=True)
class XEXBlockTrace:
    """Trace for one full XEX block operation."""

    block_index: int
    mode: str
    input_block: bytes
    output_block: bytes
    tweak: int
    pre_whitened: int
    core_output: int
    tweak_after: int
    saes_trace: EncryptionTrace | DecryptionTrace


@dataclass(frozen=True)
class CTSBlockTrace:
    """Trace for the ciphertext-stealing step used with a partial final block."""

    block_index: int
    partial_length: int
    penultimate_plaintext_block: bytes
    partial_plaintext_block: bytes
    provisional_tweak: int
    final_tweak: int
    provisional_pre_whitened: int
    provisional_core_output: int
    provisional_ciphertext_block: bytes
    stolen_ciphertext_fragment: bytes
    composite_plaintext_block: bytes
    composite_pre_whitened: int
    composite_core_output: int
    final_penultimate_ciphertext_block: bytes
    provisional_saes_trace: EncryptionTrace
    composite_saes_trace: EncryptionTrace


@dataclass(frozen=True)
class XTSTrace:
    """Message-level trace for educational XTS encryption or decryption."""

    mode: str
    input_message: bytes
    output_message: bytes
    data_unit: int
    initial_tweak: int
    block_size_bytes: int
    used_ciphertext_stealing: bool
    block_traces: Tuple[XEXBlockTrace, ...]
    cts_trace: CTSBlockTrace | None


def multiply_tweak_by_alpha(tweak: int) -> int:
    """Advance the tweak by multiplying by alpha in GF(2^16).

    The reduction constant 0x002D corresponds to the educational
    GF(2^16) polynomial x^16 + x^5 + x^3 + x^2 + 1.
    """

    validate_width(tweak, BLOCK_SIZE_BITS, "tweak")
    carry = tweak & 0x8000
    doubled = (tweak << 1) & 0xFFFF
    if carry:
        doubled ^= TWEAK_REDUCTION_POLYNOMIAL
    return doubled


def derive_initial_tweak(data_unit: int, tweak_key: int) -> int:
    """Derive the initial tweak by encrypting the 16-bit data-unit identifier."""
    validate_width(data_unit, BLOCK_SIZE_BITS, "data_unit")
    validate_width(tweak_key, BLOCK_SIZE_BITS, "tweak_key")
    return encrypt_block_with_trace(data_unit, tweak_key).ciphertext


def _crypt_full_block(
    *,
    block: bytes,
    block_index: int,
    tweak: int,
    data_key: int,
    mode: str,
) -> tuple[bytes, XEXBlockTrace]:
    block_word = bytes_to_word(block)
    pre_whitened = xor_words(block_word, tweak)
    if mode == "encrypt":
        saes_trace = encrypt_block_with_trace(pre_whitened, data_key)
        core_output = saes_trace.ciphertext
    else:
        saes_trace = decrypt_block_with_trace(pre_whitened, data_key)
        core_output = saes_trace.plaintext
    output_word = xor_words(core_output, tweak)
    output_block = word_to_bytes(output_word, BLOCK_SIZE_BYTES)
    tweak_after = multiply_tweak_by_alpha(tweak)
    return (
        output_block,
        XEXBlockTrace(
            block_index=block_index,
            mode=mode,
            input_block=block,
            output_block=output_block,
            tweak=tweak,
            pre_whitened=pre_whitened,
            core_output=core_output,
            tweak_after=tweak_after,
            saes_trace=saes_trace,
        ),
    )


def _encrypt_with_ciphertext_stealing(
    *,
    prefix_blocks: tuple[bytes, ...],
    penultimate_block: bytes,
    partial_block: bytes,
    tweak: int,
    data_key: int,
) -> tuple[bytes, tuple[XEXBlockTrace, ...], CTSBlockTrace]:
    output_blocks: list[bytes] = []
    traces: list[XEXBlockTrace] = []
    current_tweak = tweak

    for block_index, block in enumerate(prefix_blocks):
        output_block, block_trace = _crypt_full_block(
            block=block,
            block_index=block_index,
            tweak=current_tweak,
            data_key=data_key,
            mode="encrypt",
        )
        output_blocks.append(output_block)
        traces.append(block_trace)
        current_tweak = block_trace.tweak_after

    provisional_pre_whitened = xor_words(bytes_to_word(penultimate_block), current_tweak)
    provisional_saes_trace = encrypt_block_with_trace(provisional_pre_whitened, data_key)
    provisional_core_output = provisional_saes_trace.ciphertext
    provisional_ciphertext_word = xor_words(provisional_core_output, current_tweak)
    provisional_ciphertext_block = word_to_bytes(provisional_ciphertext_word, BLOCK_SIZE_BYTES)

    partial_length = len(partial_block)
    stolen_ciphertext_fragment = provisional_ciphertext_block[:partial_length]
    composite_plaintext_block = partial_block + provisional_ciphertext_block[partial_length:]

    final_tweak = multiply_tweak_by_alpha(current_tweak)
    composite_pre_whitened = xor_words(bytes_to_word(composite_plaintext_block), final_tweak)
    composite_saes_trace = encrypt_block_with_trace(composite_pre_whitened, data_key)
    composite_core_output = composite_saes_trace.ciphertext
    final_penultimate_ciphertext_word = xor_words(composite_core_output, final_tweak)
    final_penultimate_ciphertext_block = word_to_bytes(final_penultimate_ciphertext_word, BLOCK_SIZE_BYTES)

    output_blocks.append(final_penultimate_ciphertext_block)
    output_blocks.append(stolen_ciphertext_fragment)

    return (
        b"".join(output_blocks),
        tuple(traces),
        CTSBlockTrace(
            block_index=len(prefix_blocks),
            partial_length=partial_length,
            penultimate_plaintext_block=penultimate_block,
            partial_plaintext_block=partial_block,
            provisional_tweak=current_tweak,
            final_tweak=final_tweak,
            provisional_pre_whitened=provisional_pre_whitened,
            provisional_core_output=provisional_core_output,
            provisional_ciphertext_block=provisional_ciphertext_block,
            stolen_ciphertext_fragment=stolen_ciphertext_fragment,
            composite_plaintext_block=composite_plaintext_block,
            composite_pre_whitened=composite_pre_whitened,
            composite_core_output=composite_core_output,
            final_penultimate_ciphertext_block=final_penultimate_ciphertext_block,
            provisional_saes_trace=provisional_saes_trace,
            composite_saes_trace=composite_saes_trace,
        ),
    )


def _decrypt_with_ciphertext_stealing(
    *,
    prefix_blocks: tuple[bytes, ...],
    penultimate_ciphertext_block: bytes,
    partial_ciphertext_block: bytes,
    tweak: int,
    data_key: int,
) -> tuple[bytes, tuple[XEXBlockTrace, ...], CTSBlockTrace]:
    output_blocks: list[bytes] = []
    traces: list[XEXBlockTrace] = []
    current_tweak = tweak

    for block_index, block in enumerate(prefix_blocks):
        output_block, block_trace = _crypt_full_block(
            block=block,
            block_index=block_index,
            tweak=current_tweak,
            data_key=data_key,
            mode="decrypt",
        )
        output_blocks.append(output_block)
        traces.append(block_trace)
        current_tweak = block_trace.tweak_after

    final_tweak = multiply_tweak_by_alpha(current_tweak)
    composite_pre_whitened = xor_words(bytes_to_word(penultimate_ciphertext_block), final_tweak)
    composite_saes_trace = decrypt_block_with_trace(composite_pre_whitened, data_key)
    composite_core_output = composite_saes_trace.plaintext
    composite_plaintext_word = xor_words(composite_core_output, final_tweak)
    composite_plaintext_block = word_to_bytes(composite_plaintext_word, BLOCK_SIZE_BYTES)

    partial_length = len(partial_ciphertext_block)
    partial_plaintext_block = composite_plaintext_block[:partial_length]
    provisional_ciphertext_block = partial_ciphertext_block + composite_plaintext_block[partial_length:]

    provisional_pre_whitened = xor_words(bytes_to_word(provisional_ciphertext_block), current_tweak)
    provisional_saes_trace = decrypt_block_with_trace(provisional_pre_whitened, data_key)
    provisional_core_output = provisional_saes_trace.plaintext
    penultimate_plaintext_word = xor_words(provisional_core_output, current_tweak)
    penultimate_plaintext_block = word_to_bytes(penultimate_plaintext_word, BLOCK_SIZE_BYTES)

    output_blocks.append(penultimate_plaintext_block)
    output_blocks.append(partial_plaintext_block)

    return (
        b"".join(output_blocks),
        tuple(traces),
        CTSBlockTrace(
            block_index=len(prefix_blocks),
            partial_length=partial_length,
            penultimate_plaintext_block=penultimate_plaintext_block,
            partial_plaintext_block=partial_plaintext_block,
            provisional_tweak=current_tweak,
            final_tweak=final_tweak,
            provisional_pre_whitened=provisional_pre_whitened,
            provisional_core_output=provisional_core_output,
            provisional_ciphertext_block=provisional_ciphertext_block,
            stolen_ciphertext_fragment=partial_ciphertext_block,
            composite_plaintext_block=composite_plaintext_block,
            composite_pre_whitened=composite_pre_whitened,
            composite_core_output=composite_core_output,
            final_penultimate_ciphertext_block=penultimate_ciphertext_block,
            provisional_saes_trace=provisional_saes_trace,
            composite_saes_trace=composite_saes_trace,
        ),
    )


def encrypt_message_with_trace(
    plaintext: bytes,
    data_key: int,
    tweak_key: int,
    data_unit: int,
) -> tuple[bytes, XTSTrace]:
    """Encrypt a byte string using the educational SAES-XTS construction."""
    validate_width(data_key, BLOCK_SIZE_BITS, "data_key")
    validate_width(tweak_key, BLOCK_SIZE_BITS, "tweak_key")
    validate_width(data_unit, BLOCK_SIZE_BITS, "data_unit")

    initial_tweak = derive_initial_tweak(data_unit, tweak_key)
    full_blocks, tail = split_blocks(plaintext, BLOCK_SIZE_BYTES)

    if not tail:
        output_blocks: list[bytes] = []
        block_traces: list[XEXBlockTrace] = []
        current_tweak = initial_tweak
        for block_index, block in enumerate(full_blocks):
            output_block, block_trace = _crypt_full_block(
                block=block,
                block_index=block_index,
                tweak=current_tweak,
                data_key=data_key,
                mode="encrypt",
            )
            output_blocks.append(output_block)
            block_traces.append(block_trace)
            current_tweak = block_trace.tweak_after

        ciphertext = b"".join(output_blocks)
        trace = XTSTrace(
            mode="encrypt",
            input_message=plaintext,
            output_message=ciphertext,
            data_unit=data_unit,
            initial_tweak=initial_tweak,
            block_size_bytes=BLOCK_SIZE_BYTES,
            used_ciphertext_stealing=False,
            block_traces=tuple(block_traces),
            cts_trace=None,
        )
        return ciphertext, trace

    if not full_blocks:
        raise ValueError(
            "Ciphertext stealing requires at least one full block before a partial final block. "
            "For the 16-bit S-AES block size, the shortest valid partial-length message is 3 bytes."
        )

    ciphertext, prefix_traces, cts_trace = _encrypt_with_ciphertext_stealing(
        prefix_blocks=full_blocks[:-1],
        penultimate_block=full_blocks[-1],
        partial_block=tail,
        tweak=initial_tweak,
        data_key=data_key,
    )
    trace = XTSTrace(
        mode="encrypt",
        input_message=plaintext,
        output_message=ciphertext,
        data_unit=data_unit,
        initial_tweak=initial_tweak,
        block_size_bytes=BLOCK_SIZE_BYTES,
        used_ciphertext_stealing=True,
        block_traces=prefix_traces,
        cts_trace=cts_trace,
    )
    return ciphertext, trace


def encrypt_message(plaintext: bytes, data_key: int, tweak_key: int, data_unit: int) -> bytes:
    """Encrypt a byte string using the educational SAES-XTS construction."""
    return encrypt_message_with_trace(plaintext, data_key, tweak_key, data_unit)[0]


def decrypt_message_with_trace(
    ciphertext: bytes,
    data_key: int,
    tweak_key: int,
    data_unit: int,
) -> tuple[bytes, XTSTrace]:
    """Decrypt a byte string using the educational SAES-XTS construction."""
    validate_width(data_key, BLOCK_SIZE_BITS, "data_key")
    validate_width(tweak_key, BLOCK_SIZE_BITS, "tweak_key")
    validate_width(data_unit, BLOCK_SIZE_BITS, "data_unit")

    initial_tweak = derive_initial_tweak(data_unit, tweak_key)
    full_blocks, tail = split_blocks(ciphertext, BLOCK_SIZE_BYTES)

    if not tail:
        output_blocks: list[bytes] = []
        block_traces: list[XEXBlockTrace] = []
        current_tweak = initial_tweak
        for block_index, block in enumerate(full_blocks):
            output_block, block_trace = _crypt_full_block(
                block=block,
                block_index=block_index,
                tweak=current_tweak,
                data_key=data_key,
                mode="decrypt",
            )
            output_blocks.append(output_block)
            block_traces.append(block_trace)
            current_tweak = block_trace.tweak_after

        plaintext = b"".join(output_blocks)
        trace = XTSTrace(
            mode="decrypt",
            input_message=ciphertext,
            output_message=plaintext,
            data_unit=data_unit,
            initial_tweak=initial_tweak,
            block_size_bytes=BLOCK_SIZE_BYTES,
            used_ciphertext_stealing=False,
            block_traces=tuple(block_traces),
            cts_trace=None,
        )
        return plaintext, trace

    if not full_blocks:
        raise ValueError(
            "Ciphertext stealing requires at least one full block before a partial final block. "
            "For the 16-bit S-AES block size, the shortest valid partial-length message is 3 bytes."
        )

    plaintext, prefix_traces, cts_trace = _decrypt_with_ciphertext_stealing(
        prefix_blocks=full_blocks[:-1],
        penultimate_ciphertext_block=full_blocks[-1],
        partial_ciphertext_block=tail,
        tweak=initial_tweak,
        data_key=data_key,
    )
    trace = XTSTrace(
        mode="decrypt",
        input_message=ciphertext,
        output_message=plaintext,
        data_unit=data_unit,
        initial_tweak=initial_tweak,
        block_size_bytes=BLOCK_SIZE_BYTES,
        used_ciphertext_stealing=True,
        block_traces=prefix_traces,
        cts_trace=cts_trace,
    )
    return plaintext, trace


def decrypt_message(ciphertext: bytes, data_key: int, tweak_key: int, data_unit: int) -> bytes:
    """Decrypt a byte string using the educational SAES-XTS construction."""
    return decrypt_message_with_trace(ciphertext, data_key, tweak_key, data_unit)[0]


def encrypt_message_bits(
    plaintext_bits: str,
    data_key_bits: str,
    tweak_key_bits: str,
    data_unit_bits: str,
) -> str:
    """Bitstring wrapper around :func:`encrypt_message`.

    Message bits must be byte-aligned because the educational XTS wrapper works
    on byte strings and supports at most a one-byte partial final block.
    """

    ciphertext = encrypt_message(
        bits_to_bytes(plaintext_bits),
        int(bits_to_bytes(data_key_bits).hex(), 16),
        int(bits_to_bytes(tweak_key_bits).hex(), 16),
        int(bits_to_bytes(data_unit_bits).hex(), 16),
    )
    return bytes_to_bits(ciphertext)


def decrypt_message_bits(
    ciphertext_bits: str,
    data_key_bits: str,
    tweak_key_bits: str,
    data_unit_bits: str,
) -> str:
    """Bitstring wrapper around :func:`decrypt_message`."""

    plaintext = decrypt_message(
        bits_to_bytes(ciphertext_bits),
        int(bits_to_bytes(data_key_bits).hex(), 16),
        int(bits_to_bytes(tweak_key_bits).hex(), 16),
        int(bits_to_bytes(data_unit_bits).hex(), 16),
    )
    return bytes_to_bits(plaintext)
