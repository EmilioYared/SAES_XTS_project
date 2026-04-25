"""Pure wizard-flow metadata and navigation rules for the SAES-XTS app."""

from __future__ import annotations

from typing import Final

INPUT_SCREEN: Final[str] = "input"
PARTITION_SCREEN: Final[str] = "partition"
TWEAK_GENERATION_SCREEN: Final[str] = "tweak_generation"
BLOCK_SELECTION_SCREEN: Final[str] = "block_selection"
BLOCK_XTS_OVERVIEW_SCREEN: Final[str] = "block_xts_overview"
PRE_XOR_SCREEN: Final[str] = "pre_xor"
SAES_INITIAL_ADDROUNDKEY_SCREEN: Final[str] = "saes_initial_add_round_key"
ROUND1_OVERVIEW_SCREEN: Final[str] = "round1_overview"
ROUND1_SUBNIB_SCREEN: Final[str] = "round1_subnib"
ROUND1_SHIFTROWS_SCREEN: Final[str] = "round1_shiftrows"
ROUND1_MIXCOLUMNS_SCREEN: Final[str] = "round1_mixcolumns"
ROUND1_ADDROUNDKEY_SCREEN: Final[str] = "round1_add_round_key"
ROUND2_OVERVIEW_SCREEN: Final[str] = "round2_overview"
ROUND2_SUBNIB_SCREEN: Final[str] = "round2_subnib"
ROUND2_SHIFTROWS_SCREEN: Final[str] = "round2_shiftrows"
ROUND2_ADDROUNDKEY_SCREEN: Final[str] = "round2_add_round_key"
FINAL_XOR_SCREEN: Final[str] = "final_xor"
CTS_OVERVIEW_SCREEN: Final[str] = "cts_overview"
FINAL_OVERVIEW_SCREEN: Final[str] = "final_overview"


COMMON_SEQUENCE: Final[tuple[str, ...]] = (
    INPUT_SCREEN,
    PARTITION_SCREEN,
    TWEAK_GENERATION_SCREEN,
    BLOCK_SELECTION_SCREEN,
)

NORMAL_SEQUENCE: Final[tuple[str, ...]] = COMMON_SEQUENCE + (
    BLOCK_XTS_OVERVIEW_SCREEN,
    PRE_XOR_SCREEN,
    SAES_INITIAL_ADDROUNDKEY_SCREEN,
    ROUND1_OVERVIEW_SCREEN,
    ROUND1_SUBNIB_SCREEN,
    ROUND1_SHIFTROWS_SCREEN,
    ROUND1_MIXCOLUMNS_SCREEN,
    ROUND1_ADDROUNDKEY_SCREEN,
    ROUND2_OVERVIEW_SCREEN,
    ROUND2_SUBNIB_SCREEN,
    ROUND2_SHIFTROWS_SCREEN,
    ROUND2_ADDROUNDKEY_SCREEN,
    FINAL_XOR_SCREEN,
    FINAL_OVERVIEW_SCREEN,
)

TAIL_SEQUENCE: Final[tuple[str, ...]] = COMMON_SEQUENCE + (
    CTS_OVERVIEW_SCREEN,
    FINAL_OVERVIEW_SCREEN,
)


SCREEN_TITLES: Final[dict[str, str]] = {
    INPUT_SCREEN: "Screen 1 - Input Screen",
    PARTITION_SCREEN: "Screen 2 - Plaintext Partitioning",
    TWEAK_GENERATION_SCREEN: "Screen 3 - Tweak Generation",
    BLOCK_SELECTION_SCREEN: "Screen 4 - Blocks with Their Tweak Keys",
    BLOCK_XTS_OVERVIEW_SCREEN: "Screen 5 - Holistic SAES-XTS View for the Selected Block",
    PRE_XOR_SCREEN: "Screen 6 - XOR Plaintext with Tweak",
    SAES_INITIAL_ADDROUNDKEY_SCREEN: "Screen 7 - Start of S-AES: Initial AddRoundKey",
    ROUND1_OVERVIEW_SCREEN: "Screen 8 - Round 1 Overview",
    ROUND1_SUBNIB_SCREEN: "Screen 9 - Round 1 SubNib",
    ROUND1_SHIFTROWS_SCREEN: "Screen 10 - Round 1 ShiftRows",
    ROUND1_MIXCOLUMNS_SCREEN: "Screen 11 - Round 1 MixColumns",
    ROUND1_ADDROUNDKEY_SCREEN: "Screen 12 - Round 1 AddRoundKey",
    ROUND2_OVERVIEW_SCREEN: "Screen 13 - Round 2 Overview",
    ROUND2_SUBNIB_SCREEN: "Screen 14 - Round 2 SubNib",
    ROUND2_SHIFTROWS_SCREEN: "Screen 15 - Round 2 ShiftRows",
    ROUND2_ADDROUNDKEY_SCREEN: "Screen 16 - Round 2 AddRoundKey",
    FINAL_XOR_SCREEN: "Screen 17 - Final XOR with Tweak",
    CTS_OVERVIEW_SCREEN: "Tail Screen 1 - Holistic Ciphertext Stealing Overview",
    FINAL_OVERVIEW_SCREEN: "Screen 18 / Tail Screen 2 - Return to Block/Tweak Overview",
}


def selection_kind(selection_id: str | None) -> str | None:
    """Resolve the branch kind from the current block-selection value."""

    if selection_id is None:
        return None
    return "tail" if selection_id == "tail-case" else "normal"


def sequence_for_selection(selection_id: str | None) -> tuple[str, ...]:
    """Return the active wizard sequence for the current selection."""

    kind = selection_kind(selection_id)
    if kind == "tail":
        return TAIL_SEQUENCE
    if kind == "normal":
        return NORMAL_SEQUENCE
    return COMMON_SEQUENCE


def next_screen(current_screen: str, selection_id: str | None) -> str | None:
    """Return the next screen in the wizard sequence, if any."""

    sequence = sequence_for_selection(selection_id)
    try:
        index = sequence.index(current_screen)
    except ValueError:
        return None
    if index + 1 >= len(sequence):
        return None
    return sequence[index + 1]


def previous_screen(current_screen: str, selection_id: str | None) -> str | None:
    """Return the previous screen in the wizard sequence, if any."""

    sequence = sequence_for_selection(selection_id)
    try:
        index = sequence.index(current_screen)
    except ValueError:
        return None
    if index == 0:
        return None
    return sequence[index - 1]


def progress(current_screen: str, selection_id: str | None) -> tuple[int, int]:
    """Return a one-based position and total count for the active branch."""

    sequence = sequence_for_selection(selection_id)
    try:
        index = sequence.index(current_screen)
    except ValueError:
        return (0, len(sequence))
    return (index + 1, len(sequence))


def title_for_screen(screen_id: str) -> str:
    """Return the user-facing screen title."""

    return SCREEN_TITLES[screen_id]


def is_common_screen(screen_id: str) -> bool:
    """Return whether the screen appears before the branch split."""

    return screen_id in COMMON_SEQUENCE
