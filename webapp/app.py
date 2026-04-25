"""Streamlit entry point for the educational SAES project app."""

from __future__ import annotations

import sys
from pathlib import Path

if __package__ in (None, ""):
    project_root = Path(__file__).resolve().parent.parent
    project_root_str = str(project_root)
    if project_root_str not in sys.path:
        sys.path.insert(0, project_root_str)

from algorithm.cryptanalysis import (
    DEFAULT_DIFFERENTIAL_PAIRS,
    KnownPair,
    brute_force_keys_from_known_pair,
    run_differential_attack,
)
from algorithm.saes import decrypt_block, encrypt_block
from algorithm.xts import decrypt_message, encrypt_message
from helpers.bit_utils import bytes_to_bits, int_to_bits
from helpers.block_utils import bytes_to_word, word_to_bytes
from helpers.encoding_utils import encode_latin1_text
from webapp.components import (
    inject_base_styles,
    render_callout,
    render_credit,
    render_screen_header,
    render_scrollable_table,
    render_table,
    render_value_cards,
)
from webapp.streamlit_compat import require_streamlit, st
from webapp.trace_adapter import (
    DEFAULT_DATA_KEY,
    DEFAULT_DATA_UNIT,
    DEFAULT_PLAINTEXT,
    DEFAULT_TWEAK_KEY,
    build_encryption_walkthrough,
    normalize_encryption_inputs,
    parse_uint16,
)
from webapp.views.block_detail_view import (
    render_block_xts_overview_screen,
    render_final_xor_screen,
    render_pre_xor_screen,
    render_round1_add_round_key_screen,
    render_round1_mixcolumns_screen,
    render_round1_overview_screen,
    render_round1_shiftrows_screen,
    render_round1_subnib_screen,
    render_round2_add_round_key_screen,
    render_round2_overview_screen,
    render_round2_shiftrows_screen,
    render_round2_subnib_screen,
    render_saes_initial_add_round_key_screen,
)
from webapp.views.cts_view import render_cts_overview_screen
from webapp.views.input_view import render_input_screen
from webapp.views.overview_view import render_block_selection_screen
from webapp.views.partition_view import render_partition_screen
from webapp.views.tweak_view import render_tweak_generation_screen
from webapp.wizard_flow import (
    BLOCK_SELECTION_SCREEN,
    BLOCK_XTS_OVERVIEW_SCREEN,
    CTS_OVERVIEW_SCREEN,
    FINAL_OVERVIEW_SCREEN,
    FINAL_XOR_SCREEN,
    INPUT_SCREEN,
    PARTITION_SCREEN,
    PRE_XOR_SCREEN,
    ROUND1_ADDROUNDKEY_SCREEN,
    ROUND1_MIXCOLUMNS_SCREEN,
    ROUND1_OVERVIEW_SCREEN,
    ROUND1_SHIFTROWS_SCREEN,
    ROUND1_SUBNIB_SCREEN,
    ROUND2_ADDROUNDKEY_SCREEN,
    ROUND2_OVERVIEW_SCREEN,
    ROUND2_SHIFTROWS_SCREEN,
    ROUND2_SUBNIB_SCREEN,
    SAES_INITIAL_ADDROUNDKEY_SCREEN,
    TWEAK_GENERATION_SCREEN,
    next_screen,
    previous_screen,
    progress,
    selection_kind,
    title_for_screen,
)


MENU_SECTION = "menu"
EDUCATIONAL_SECTION = "educational"
ENCRYPT_DECRYPT_SECTION = "encrypt_decrypt"
CRYPTANALYSIS_SECTION = "cryptanalysis"

APP_SECTION_KEY = "saes_app_section"
FORM_STATE_KEY = "saes_xts_wizard_form_values"
INPUT_STATE_KEY = "saes_xts_wizard_inputs"
WALKTHROUGH_STATE_KEY = "saes_xts_wizard_walkthrough"
ERROR_STATE_KEY = "saes_xts_wizard_error"
SCREEN_STATE_KEY = "saes_xts_wizard_screen"
SELECTION_STATE_KEY = "saes_xts_wizard_selection_id"


def main() -> None:
    """Run the educational SAES project app."""

    require_streamlit()
    st.set_page_config(page_title="SAES Project App", layout="wide")
    inject_base_styles()
    _ensure_state()

    section = st.session_state[APP_SECTION_KEY]
    if section == MENU_SECTION:
        _render_main_menu()
    elif section == EDUCATIONAL_SECTION:
        _render_educational_mode()
    elif section == ENCRYPT_DECRYPT_SECTION:
        _render_encrypt_decrypt_mode()
    elif section == CRYPTANALYSIS_SECTION:
        _render_cryptanalysis_mode()
    else:
        st.session_state[APP_SECTION_KEY] = MENU_SECTION
        st.rerun()


def _render_main_menu() -> None:
    """Render the landing page with the three top-level modes."""

    st.title("S-AES Project App")
    render_credit("Created by Emilio Yared and Antonio Youssef")
    render_callout(
        "Main menu",
        "Choose one mode. Educational Mode is the guided wizard. Encrypt / Decrypt is the direct tool mode. "
        "Cryptanalysis is only for S-AES and includes brute force plus a differential-analysis demonstration.",
    )

    columns = st.columns(3)
    cards = [
        (
            "Cryptanalysis",
            "Run S-AES brute force from a known plaintext/ciphertext pair, or simulate differential cryptanalysis with an encryption oracle.",
            CRYPTANALYSIS_SECTION,
            "Open Cryptanalysis",
        ),
        (
            "Educational Mode",
            "Use the existing SAES-XTS wizard and walk through the algorithm one screen at a time.",
            EDUCATIONAL_SECTION,
            "Open Educational Mode",
        ),
        (
            "Encrypt / Decrypt",
            "Use S-AES or SAES-XTS directly. Choose encrypt or decrypt and supply the required keys.",
            ENCRYPT_DECRYPT_SECTION,
            "Open Encrypt / Decrypt",
        ),
    ]

    for column, (title, description, section, button_label) in zip(columns, cards):
        with column:
            render_callout(title, description)
            if st.button(button_label, key=f"menu:{section}", use_container_width=True):
                st.session_state[APP_SECTION_KEY] = section
                st.rerun()


def _render_educational_mode() -> None:
    """Render the existing educational wizard under the new main menu."""

    _render_mode_header(
        "Educational Mode",
        "The guided SAES-XTS walkthrough remains here unchanged in structure.",
    )

    screen_id = st.session_state[SCREEN_STATE_KEY]
    if screen_id == INPUT_SCREEN:
        position, total = progress(INPUT_SCREEN, None)
        render_screen_header(
            title_for_screen(INPUT_SCREEN),
            position=position,
            total=total,
            subtitle=_screen_subtitle(INPUT_SCREEN),
        )
        _render_input_step()
        return

    walkthrough = st.session_state.get(WALKTHROUGH_STATE_KEY)
    if walkthrough is None:
        _reset_educational_state()
        st.rerun()
        return

    _synchronize_selection_with_walkthrough(walkthrough)
    screen_id = st.session_state[SCREEN_STATE_KEY]
    selected_id = st.session_state[SELECTION_STATE_KEY]
    current_detail = _selected_regular_detail(walkthrough, selected_id)

    position, total = progress(screen_id, selected_id)
    render_screen_header(
        title_for_screen(screen_id),
        position=position,
        total=total,
        subtitle=_screen_subtitle(screen_id),
    )

    if screen_id == PARTITION_SCREEN:
        render_partition_screen(walkthrough)
    elif screen_id == TWEAK_GENERATION_SCREEN:
        render_tweak_generation_screen(walkthrough)
    elif screen_id == BLOCK_SELECTION_SCREEN:
        updated_selection = render_block_selection_screen(
            walkthrough,
            selected_id=selected_id,
            include_ciphertexts=False,
        )
        st.session_state[SELECTION_STATE_KEY] = updated_selection
    elif screen_id == BLOCK_XTS_OVERVIEW_SCREEN and current_detail is not None:
        render_block_xts_overview_screen(current_detail)
    elif screen_id == PRE_XOR_SCREEN and current_detail is not None:
        render_pre_xor_screen(current_detail)
    elif screen_id == SAES_INITIAL_ADDROUNDKEY_SCREEN and current_detail is not None:
        render_saes_initial_add_round_key_screen(walkthrough, current_detail)
    elif screen_id == ROUND1_OVERVIEW_SCREEN and current_detail is not None:
        render_round1_overview_screen(current_detail)
    elif screen_id == ROUND1_SUBNIB_SCREEN and current_detail is not None:
        render_round1_subnib_screen(current_detail, walkthrough["constants"])
    elif screen_id == ROUND1_SHIFTROWS_SCREEN and current_detail is not None:
        render_round1_shiftrows_screen(current_detail)
    elif screen_id == ROUND1_MIXCOLUMNS_SCREEN and current_detail is not None:
        render_round1_mixcolumns_screen(current_detail)
    elif screen_id == ROUND1_ADDROUNDKEY_SCREEN and current_detail is not None:
        render_round1_add_round_key_screen(current_detail)
    elif screen_id == ROUND2_OVERVIEW_SCREEN and current_detail is not None:
        render_round2_overview_screen(current_detail)
    elif screen_id == ROUND2_SUBNIB_SCREEN and current_detail is not None:
        render_round2_subnib_screen(current_detail, walkthrough["constants"])
    elif screen_id == ROUND2_SHIFTROWS_SCREEN and current_detail is not None:
        render_round2_shiftrows_screen(current_detail)
    elif screen_id == ROUND2_ADDROUNDKEY_SCREEN and current_detail is not None:
        render_round2_add_round_key_screen(current_detail)
    elif screen_id == FINAL_XOR_SCREEN and current_detail is not None:
        render_final_xor_screen(current_detail)
    elif screen_id == CTS_OVERVIEW_SCREEN:
        render_cts_overview_screen(walkthrough)
    elif screen_id == FINAL_OVERVIEW_SCREEN:
        updated_selection = render_block_selection_screen(
            walkthrough,
            selected_id=selected_id,
            include_ciphertexts=True,
        )
        st.session_state[SELECTION_STATE_KEY] = updated_selection
    else:
        render_callout("Rendering issue", "The current wizard screen could not be rendered.")
        return

    _render_navigation(screen_id)


def _render_encrypt_decrypt_mode() -> None:
    """Render the direct S-AES / SAES-XTS encryption and decryption tools."""

    _render_mode_header(
        "Encrypt / Decrypt",
        "Choose S-AES for one 16-bit block, or SAES-XTS for the message-level educational mode wrapper.",
    )

    algorithm_choice = st.radio("Algorithm", ("S-AES", "SAES-XTS"), horizontal=True)
    action = st.radio("Mode", ("Encrypt", "Decrypt"), horizontal=True)

    if algorithm_choice == "S-AES":
        render_callout(
            "S-AES input format",
            "S-AES works on exactly one 16-bit block. For encryption, enter exactly 2 Latin-1 / ASCII characters so the app can map them to one 16-bit block. "
            "For decryption, enter one ciphertext block as hex, binary, or decimal.",
        )
        with st.form("saes_tool_form"):
            if action == "Encrypt":
                plaintext_text = st.text_input("Plaintext block (2 characters)", value="AB", max_chars=2)
                block_value_text = ""
            else:
                block_value_text = st.text_input("Ciphertext block", value="0x24EC")
                plaintext_text = ""
            key_text = st.text_input("S-AES key", value=f"0x{DEFAULT_DATA_KEY:04X}")
            submitted = st.form_submit_button("Run")

        if submitted:
            try:
                key = parse_uint16(key_text, "S-AES key")
                if action == "Encrypt":
                    plaintext_bytes = _parse_saes_plaintext_block_text(plaintext_text)
                    block_value = bytes_to_word(plaintext_bytes)
                    result = encrypt_block(block_value, key)
                else:
                    block_value = parse_uint16(block_value_text, "Ciphertext block")
                    result = decrypt_block(block_value, key)
            except ValueError as exc:
                render_callout("Input validation", str(exc))
            else:
                if action == "Encrypt":
                    render_value_cards(
                        [
                            {"label": "Plaintext", "value": plaintext_text},
                            {"label": "Plaintext bytes", "value": plaintext_bytes.hex().upper()},
                            {"label": "Plaintext block", "value": f"{block_value:04X} ({int_to_bits(block_value, 16)})"},
                            {"label": "Ciphertext block", "value": f"{result:04X} ({int_to_bits(result, 16)})"},
                        ]
                    )
                    render_value_cards([{"label": "Key", "value": f"{key:04X} ({int_to_bits(key, 16)})"}])
                else:
                    recovered_bytes = word_to_bytes(result)
                    render_value_cards(
                        [
                            {"label": "Ciphertext block", "value": f"{block_value:04X} ({int_to_bits(block_value, 16)})"},
                            {"label": "Key", "value": f"{key:04X} ({int_to_bits(key, 16)})"},
                            {"label": "Recovered block", "value": f"{result:04X} ({int_to_bits(result, 16)})"},
                            {"label": "Recovered text", "value": recovered_bytes.decode('latin-1')},
                        ]
                    )
                    render_callout("Recovered bytes", recovered_bytes.hex().upper())
    else:
        render_callout(
            "SAES-XTS input format",
            "Encryption takes Latin-1 / ASCII plaintext text. Decryption takes ciphertext bytes written in hexadecimal.",
        )
        with st.form("saes_xts_tool_form"):
            if action == "Encrypt":
                message_text = st.text_area("Plaintext message", value=DEFAULT_PLAINTEXT)
                ciphertext_hex_text = ""
            else:
                ciphertext_hex_text = st.text_area("Ciphertext bytes (hex)", value="79 C3 DD 7A 9D")
                message_text = ""
            data_key_text = st.text_input("Data key", value=f"0x{DEFAULT_DATA_KEY:04X}")
            tweak_key_text = st.text_input("Tweak key", value=f"0x{DEFAULT_TWEAK_KEY:04X}")
            data_unit_text = st.text_input("Data-unit value", value=f"0x{DEFAULT_DATA_UNIT:04X}")
            submitted = st.form_submit_button("Run")

        if submitted:
            try:
                data_key = parse_uint16(data_key_text, "Data key")
                tweak_key = parse_uint16(tweak_key_text, "Tweak key")
                data_unit = parse_uint16(data_unit_text, "Data-unit value")
                if action == "Encrypt":
                    plaintext_bytes = encode_latin1_text(message_text)
                    result_bytes = encrypt_message(plaintext_bytes, data_key, tweak_key, data_unit)
                    render_value_cards(
                        [
                            {"label": "Plaintext", "value": message_text},
                            {"label": "Plaintext bytes", "value": plaintext_bytes.hex().upper()},
                            {"label": "Ciphertext bytes", "value": result_bytes.hex().upper()},
                        ]
                    )
                    render_callout("Ciphertext bits", bytes_to_bits(result_bytes))
                else:
                    ciphertext_bytes = _parse_hex_bytes(ciphertext_hex_text, "Ciphertext bytes")
                    result_bytes = decrypt_message(ciphertext_bytes, data_key, tweak_key, data_unit)
                    render_value_cards(
                        [
                            {"label": "Ciphertext bytes", "value": ciphertext_bytes.hex().upper()},
                            {"label": "Recovered text", "value": result_bytes.decode('latin-1')},
                            {"label": "Recovered bytes", "value": result_bytes.hex().upper()},
                        ]
                    )
                    render_callout("Recovered bits", bytes_to_bits(result_bytes))
            except ValueError as exc:
                render_callout("Input validation", str(exc))


def _render_cryptanalysis_mode() -> None:
    """Render the S-AES brute-force and differential cryptanalysis tools."""

    _render_mode_header(
        "Cryptanalysis",
        "This section is only for S-AES. It includes exhaustive brute force and a differential-analysis demonstration.",
    )

    tool_choice = st.radio("Cryptanalysis method", ("Brute force", "Differential"), horizontal=True)

    if tool_choice == "Brute force":
        render_callout(
            "Brute force on S-AES",
            "Because the S-AES key is only 16 bits, the app can test all 65,536 possible keys and keep the ones that match one known plaintext/ciphertext pair.",
        )
        with st.form("bruteforce_form"):
            plaintext_text = st.text_input("Known plaintext block", value="0x1234")
            ciphertext_text = st.text_input("Known ciphertext block", value="0xF4B1")
            submitted = st.form_submit_button("Recover key")

        if submitted:
            try:
                plaintext = parse_uint16(plaintext_text, "Known plaintext")
                ciphertext = parse_uint16(ciphertext_text, "Known ciphertext")
                matches = brute_force_keys_from_known_pair(KnownPair(plaintext=plaintext, ciphertext=ciphertext))
            except ValueError as exc:
                render_callout("Input validation", str(exc))
            else:
                render_value_cards(
                    [
                        {"label": "Known plaintext", "value": f"{plaintext:04X} ({int_to_bits(plaintext, 16)})"},
                        {"label": "Known ciphertext", "value": f"{ciphertext:04X} ({int_to_bits(ciphertext, 16)})"},
                        {"label": "Matching keys", "value": str(len(matches))},
                    ]
                )
                render_scrollable_table(
                    "Recovered key candidates",
                    ["Index", "Key", "Bits"],
                    [[index, f"{key:04X}", int_to_bits(key, 16)] for index, key in enumerate(matches)],
                    height_px=260,
                    max_width_px=1000,
                )

    else:
        render_callout(
            "Differential cryptanalysis demonstration",
            "In this educational simulation, the cryptanalyst has access to the S-AES encryption oracle under one hidden key. "
            "You provide that secret key so the app can generate chosen-plaintext observations, filter the keyspace with input/output differentials, and then finish with a known-pair check.",
        )
        with st.form("differential_form"):
            secret_key_text = st.text_input("Secret S-AES key used by the encryption oracle", value=f"0x{DEFAULT_DATA_KEY:04X}")
            known_plaintext_text = st.text_input("Known plaintext block used for the final key check", value="0x1234")
            submitted = st.form_submit_button("Run differential analysis")

        if submitted:
            try:
                secret_key = parse_uint16(secret_key_text, "Secret S-AES key")
                known_plaintext = parse_uint16(known_plaintext_text, "Known plaintext")
                report = run_differential_attack(secret_key, known_plaintext=known_plaintext)
            except ValueError as exc:
                render_callout("Input validation", str(exc))
            else:
                render_callout(
                    "How the attack works",
                    "1. Query the S-AES encryption oracle on chosen plaintext pairs.\n"
                    "2. For each pair, compute ΔP = P_left xor P_right and ΔC = C_left xor C_right.\n"
                    "3. Keep only keys that reproduce every observed ΔP -> ΔC relation.\n"
                    "4. Use one known plaintext/ciphertext pair to isolate the final key from the filtered candidates.",
                )
                render_table(
                    ["Chosen plaintext left", "Chosen plaintext right"],
                    [[f"{left:04X}", f"{right:04X}"] for left, right in DEFAULT_DIFFERENTIAL_PAIRS],
                )
                render_scrollable_table(
                    "Observed differentials from the encryption oracle",
                    ["P left", "P right", "C left", "C right", "ΔP", "ΔC"],
                    [
                        [
                            f"{observation.plaintext_left:04X}",
                            f"{observation.plaintext_right:04X}",
                            f"{observation.ciphertext_left:04X}",
                            f"{observation.ciphertext_right:04X}",
                            f"{observation.delta_plaintext:04X}",
                            f"{observation.delta_ciphertext:04X}",
                        ]
                        for observation in report.observations
                    ],
                    height_px=250,
                    max_width_px=1100,
                )
                render_value_cards(
                    [
                        {"label": "Filtered candidate count", "value": str(len(report.filtered_candidates))},
                        {"label": "Known pair", "value": f'{report.known_pair.plaintext:04X} -> {report.known_pair.ciphertext:04X}'},
                        {"label": "Recovered key count", "value": str(len(report.recovered_keys))},
                    ]
                )
                render_value_cards(
                    [
                        {"label": "Recovered key", "value": ", ".join(f'{key:04X}' for key in report.recovered_keys) or "None"},
                        {"label": "Differential filter time", "value": f"{report.differential_filter_seconds:.4f} s"},
                        {"label": "Final known-pair check time", "value": f"{report.brute_force_seconds:.4f} s"},
                    ]
                )
                if report.recovered_keys:
                    render_callout(
                        "Why this key is the answer",
                        f"The final recovered key is {report.recovered_keys[0]:04X}. It survives every differential observation and also encrypts the known plaintext {report.known_pair.plaintext:04X} to the observed ciphertext {report.known_pair.ciphertext:04X}.",
                    )


def _render_input_step() -> None:
    """Render the educational wizard input screen and advance on valid input."""

    submitted_values = render_input_screen(
        st.session_state[FORM_STATE_KEY],
        st.session_state[ERROR_STATE_KEY],
    )
    if submitted_values is None:
        return

    st.session_state[FORM_STATE_KEY] = submitted_values
    try:
        normalized = normalize_encryption_inputs(**submitted_values)
        walkthrough = build_encryption_walkthrough(
            normalized["plaintext_text"],
            normalized["data_key"],
            normalized["tweak_key"],
            normalized["data_unit"],
        )
    except ValueError as exc:
        st.session_state[ERROR_STATE_KEY] = str(exc)
        return

    st.session_state[INPUT_STATE_KEY] = normalized
    st.session_state[WALKTHROUGH_STATE_KEY] = walkthrough
    st.session_state[SELECTION_STATE_KEY] = None
    st.session_state[ERROR_STATE_KEY] = None
    st.session_state[SCREEN_STATE_KEY] = PARTITION_SCREEN
    st.rerun()


def _render_navigation(screen_id: str) -> None:
    """Render the educational wizard's Back/Next controls."""

    selected_id = st.session_state.get(SELECTION_STATE_KEY)
    back_target = previous_screen(screen_id, selected_id)
    next_target = next_screen(screen_id, selected_id)
    if screen_id == FINAL_OVERVIEW_SCREEN:
        next_target = next_screen(BLOCK_SELECTION_SCREEN, selected_id)

    left, middle, right = st.columns([1, 1, 2])
    with left:
        if back_target is not None and st.button("Back", key=f"edu:back:{screen_id}", use_container_width=True):
            st.session_state[SCREEN_STATE_KEY] = back_target
            st.rerun()
    with middle:
        next_label = "Next" if screen_id != FINAL_OVERVIEW_SCREEN else "Inspect selected choice"
        if next_target is not None and st.button(next_label, key=f"edu:next:{screen_id}", use_container_width=True):
            st.session_state[SCREEN_STATE_KEY] = next_target
            st.rerun()
    with right:
        if screen_id != INPUT_SCREEN and st.button("Restart Educational Mode", key=f"edu:restart:{screen_id}", use_container_width=False):
            _reset_educational_state()
            st.rerun()


def _render_mode_header(title: str, subtitle: str) -> None:
    """Render a common mode header with a back-to-menu button."""

    left, right = st.columns([5, 1])
    with left:
        st.title(title)
        st.write(subtitle)
    with right:
        if st.button("Main menu", key=f"back:{title}", use_container_width=True):
            st.session_state[APP_SECTION_KEY] = MENU_SECTION
            st.rerun()


def _selected_regular_detail(walkthrough: dict, selected_id: str | None) -> dict | None:
    """Return the regular-block detail payload for the normal wizard path."""

    if selection_kind(selected_id) != "normal":
        return None
    return walkthrough["block_details"][selected_id]


def _screen_subtitle(screen_id: str) -> str:
    """Return a small explanatory subtitle for the current screen."""

    subtitles = {
        INPUT_SCREEN: "Provide plaintext, the 16-bit data key, the 16-bit tweak key, and the 16-bit data-unit value.",
        PARTITION_SCREEN: "Watch 8-bit characters become bytes, then pair those bytes into 16-bit S-AES blocks.",
        TWEAK_GENERATION_SCREEN: "T0 comes from S-AES, then later tweaks are derived by multiplying by alpha.",
        BLOCK_SELECTION_SCREEN: "Choose a normal block or the special tail case before entering the detailed walkthrough.",
        BLOCK_XTS_OVERVIEW_SCREEN: "See the whole XEX structure before diving into the detailed steps.",
        PRE_XOR_SCREEN: "This is the first whitening XOR: plaintext block against the current tweak.",
        SAES_INITIAL_ADDROUNDKEY_SCREEN: "The output of the first XOR becomes the input to S-AES.",
        ROUND1_OVERVIEW_SCREEN: "Round 1 includes SubNib, ShiftRows, MixColumns, and AddRoundKey.",
        ROUND1_SUBNIB_SCREEN: "Each nibble is substituted through the real S-box.",
        ROUND1_SHIFTROWS_SCREEN: "The second row is permuted to change where the nibbles sit in the state.",
        ROUND1_MIXCOLUMNS_SCREEN: "Each state column is multiplied by the MixColumns constant matrix.",
        ROUND1_ADDROUNDKEY_SCREEN: "The Round 1 key is XORed into the mixed state.",
        ROUND2_OVERVIEW_SCREEN: "Round 2 is final, so it omits MixColumns.",
        ROUND2_SUBNIB_SCREEN: "SubNib is applied again with the same S-box.",
        ROUND2_SHIFTROWS_SCREEN: "ShiftRows prepares the state for the final AddRoundKey.",
        ROUND2_ADDROUNDKEY_SCREEN: "This produces the final S-AES output before returning to XTS.",
        FINAL_XOR_SCREEN: "The final XEX step XORs the S-AES output with the same tweak again.",
        CTS_OVERVIEW_SCREEN: "When a single byte is left over, the last full block and the tail must be processed together.",
        FINAL_OVERVIEW_SCREEN: "Return to the whole message and see how plaintext blocks, tweaks, and ciphertexts line up.",
    }
    return subtitles[screen_id]


def _ensure_state() -> None:
    """Initialize session state for the app and the educational wizard."""

    defaults = _default_form_values()
    st.session_state.setdefault(APP_SECTION_KEY, MENU_SECTION)
    st.session_state.setdefault(FORM_STATE_KEY, defaults)
    st.session_state.setdefault(INPUT_STATE_KEY, None)
    st.session_state.setdefault(WALKTHROUGH_STATE_KEY, None)
    st.session_state.setdefault(ERROR_STATE_KEY, None)
    st.session_state.setdefault(SCREEN_STATE_KEY, INPUT_SCREEN)
    st.session_state.setdefault(SELECTION_STATE_KEY, None)


def _synchronize_selection_with_walkthrough(walkthrough: dict) -> None:
    """Ensure the current block-selection id is valid for the walkthrough."""

    valid_ids = [option["id"] for option in walkthrough["block_selection"]["options"]]
    current_screen = st.session_state[SCREEN_STATE_KEY]
    if current_screen in (INPUT_SCREEN, PARTITION_SCREEN, TWEAK_GENERATION_SCREEN, BLOCK_SELECTION_SCREEN):
        return
    if st.session_state[SELECTION_STATE_KEY] not in valid_ids:
        st.session_state[SELECTION_STATE_KEY] = walkthrough["block_selection"]["default_selection_id"]


def _reset_educational_state() -> None:
    """Reset the educational wizard back to its first screen."""

    st.session_state[SCREEN_STATE_KEY] = INPUT_SCREEN
    st.session_state[ERROR_STATE_KEY] = None
    st.session_state[WALKTHROUGH_STATE_KEY] = None
    st.session_state[INPUT_STATE_KEY] = None
    st.session_state[SELECTION_STATE_KEY] = None


def _default_form_values() -> dict[str, str]:
    return {
        "plaintext_text": DEFAULT_PLAINTEXT,
        "data_key_text": f"0x{DEFAULT_DATA_KEY:04X}",
        "tweak_key_text": f"0x{DEFAULT_TWEAK_KEY:04X}",
        "data_unit_text": f"0x{DEFAULT_DATA_UNIT:04X}",
    }


def _parse_hex_bytes(value: str, field_name: str) -> bytes:
    """Parse a whitespace-friendly hexadecimal byte string."""

    cleaned = value.strip().replace("0x", "").replace("0X", "").replace("_", "").replace(" ", "").replace("\n", "")
    if not cleaned:
        raise ValueError(f"{field_name} is required.")
    if len(cleaned) % 2 != 0:
        raise ValueError(f"{field_name} must contain a whole number of bytes written in hex.")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be valid hexadecimal bytes.") from exc


def _parse_saes_plaintext_block_text(value: str) -> bytes:
    """Encode exactly one 16-bit S-AES plaintext block from a 2-character string."""

    encoded = encode_latin1_text(value)
    if len(encoded) != 2:
        raise ValueError("S-AES plaintext must contain exactly 2 Latin-1 / ASCII characters.")
    return encoded


if __name__ == "__main__":
    main()
