"""Normal block-flow screens for the SAES-XTS wizard."""

from __future__ import annotations

from webapp.components import (
    render_bitwise_xor,
    render_callout,
    render_formula_block,
    render_mermaid_diagram,
    render_round_key_banner,
    render_sbox_matrix,
    render_scrollable_table,
    render_state_snapshot,
    render_table,
    render_tweak_banner,
    render_value_cards,
    render_vector_matrix_equation,
    render_word_triplet,
)
from webapp.streamlit_compat import require_streamlit, st


def render_block_xts_overview_screen(detail: dict) -> None:
    """Render Screen 5: the full XEX pipeline for one selected block."""

    require_streamlit()
    render_tweak_banner([{"label": "Current tweak", "snapshot": detail["tweak"]}])
    render_mermaid_diagram(
        "Selected block pipeline",
        "\n".join(
            [
                "flowchart LR",
                f'    p["P{detail["block_index"]} = {detail["plaintext_block"]["hex"]}"]',
                f'    t["T{detail["block_index"]} = {detail["tweak"]["hex"]}"]',
                f'    x1["P xor T = {detail["pre_whitened"]["hex"]}"]',
                '    saes["S-AES"]',
                f'    x2["S-AES out xor T = {detail["ciphertext_block"]["hex"]}"]',
                f'    c["C{detail["block_index"]} = {detail["ciphertext_block"]["hex"]}"]',
                "    p --> x1",
                "    t --> x1",
                "    x1 --> saes --> x2 --> c",
                "    t --> x2",
            ]
        ),
        height=260,
    )
    render_value_cards(
        [
            {"label": "Plaintext block", "value": f"{detail['plaintext_block']['hex']} ({detail['plaintext_word']['bits']})"},
            {"label": "Pre-whitened value", "value": f"{detail['pre_whitened']['hex']} ({detail['pre_whitened']['bits']})"},
            {"label": "S-AES output", "value": f"{detail['core_output']['hex']} ({detail['core_output']['bits']})"},
            {"label": "Ciphertext block", "value": f"{detail['ciphertext_block']['hex']} ({detail['ciphertext_word']['bits']})"},
        ]
    )


def render_pre_xor_screen(detail: dict) -> None:
    """Render Screen 6: XOR plaintext with tweak."""

    require_streamlit()
    render_tweak_banner([{"label": "Current tweak", "snapshot": detail["tweak"]}])
    pre_xor = detail["wizard"]["pre_xor"]
    render_bitwise_xor(
        left_label="Plaintext",
        left_snapshot=pre_xor["plaintext_word"],
        right_label="Tweak",
        right_snapshot=pre_xor["tweak"],
        result_label="P xor T",
        result_snapshot=pre_xor["result"],
        bitwise_rows=pre_xor["bitwise_rows"],
    )


def render_saes_initial_add_round_key_screen(walkthrough: dict, detail: dict) -> None:
    """Render Screen 7: the initial AddRoundKey step inside S-AES."""

    require_streamlit()
    initial = detail["wizard"]["saes_initial_add_round_key"]
    key_schedule = walkthrough["key_schedule"]
    render_round_key_banner("Round Key 0", initial["round_key"], caption="This is the first AddRoundKey value used by S-AES.")
    render_callout(
        "Why AddRoundKey uses K0 here",
        "Before Round 1 starts, S-AES expands the 16-bit data key into three round keys: K0, K1, and K2. "
        "The selected block enters S-AES only after it is XORed with K0.",
    )
    render_mermaid_diagram(
        "Real S-AES key expansion",
        "\n".join(
            [
                "flowchart TB",
                "  classDef key fill:#f3f4f6,stroke:#111,stroke-width:1.5px,color:#111;",
                "  classDef word fill:#d9d9d9,stroke:#111,stroke-width:1.5px,color:#111;",
                "  classDef temp fill:#111,stroke:#111,stroke-width:1.5px,color:#fff,font-weight:bold;",
                "  classDef xor fill:#fff,stroke:#111,stroke-width:1.5px,color:#111;",
                "  classDef note fill:#fff,stroke:#111,stroke-width:1.5px,color:#111;",
                "  classDef process fill:#fff,stroke:#111,stroke-width:2px,color:#111,font-weight:bold;",
                '  subgraph CK["Cipher key"]',
                "    direction LR",
                '    n0["n₀"]:::key',
                '    n1["n₁"]:::key',
                '    n2["n₂"]:::key',
                '    n3["n₃"]:::key',
                "  end",
                f'  n0 --> w0["w₀ = {key_schedule["words"][0]["snapshot"]["hex"]}"]:::word',
                "  n1 --> w0",
                f'  n2 --> w1["w₁ = {key_schedule["words"][1]["snapshot"]["hex"]}"]:::word',
                "  n3 --> w1",
                f'  w0 --> x2(("⊕")):::xor',
                f'  t2["t₂ = {key_schedule["temporaries"][0]["output"]["hex"]}"]:::temp --> x2',
                f'  x2 --> w2["w₂ = {key_schedule["words"][2]["snapshot"]["hex"]}"]:::word',
                "  w1 --> x3((\"⊕\")):::xor",
                "  w2 --> x3",
                f'  x3 --> w3["w₃ = {key_schedule["words"][3]["snapshot"]["hex"]}"]:::word',
                "  w2 --> x4((\"⊕\")):::xor",
                f'  t4["t₄ = {key_schedule["temporaries"][1]["output"]["hex"]}"]:::temp --> x4',
                f'  x4 --> w4["w₄ = {key_schedule["words"][4]["snapshot"]["hex"]}"]:::word',
                "  w3 --> x5((\"⊕\")):::xor",
                "  w4 --> x5",
                f'  x5 --> w5["w₅ = {key_schedule["words"][5]["snapshot"]["hex"]}"]:::word',
                '  subgraph PRE["Pre-round"]',
                "    direction LR",
                "    w0",
                "    w1",
                "  end",
                '  subgraph R1["Round 1"]',
                "    direction LR",
                "    t2",
                "    x2",
                "    w2",
                "    x3",
                "    w3",
                "  end",
                '  subgraph R2["Round 2"]',
                "    direction LR",
                "    t4",
                "    x4",
                "    w4",
                "    x5",
                "    w5",
                "  end",
                '  subgraph MAKE["Making of temporary words tᵢ"]',
                "    direction LR",
                '    wi["wᵢ₋₁"]:::word --> rot["RotWord"]:::process',
                '    rot --> sub["SubWord"]:::process',
                '    sub --> xr(("⊕")):::xor',
                '    rcon["RCon[Nᵣ]"]:::note --> xr',
                '    xr --> ti["tᵢ"]:::temp',
                "  end",
                '  rconNote["RCon[1] = 80₁₆<br/>RCon[2] = 30₁₆"]:::note',
                "  MAKE --- rconNote",
                '  caption["Making of tᵢ temporary words: i = 2Nᵣ, where Nᵣ is the round number"]:::note',
                "  MAKE --- caption",
            ]
        ),
        height=340,
        scrollable=True,
        min_width_px=1200,
    )
    render_table(
        ["Operation", "Meaning"],
        [
            ["RotWord / RotNib", key_schedule["operation_notes"]["rot_nib"]],
            ["SubWord / SubNib", key_schedule["operation_notes"]["sub_nib"]],
            ["RCon", key_schedule["operation_notes"]["rcon"]],
        ],
    )
    render_table(
        ["Nibble", "Hex", "Bits"],
        [[nibble["label"], nibble["hex"], nibble["bits"]] for nibble in key_schedule["nibbles"]],
    )
    render_table(
        ["Word", "Value", "Bits"],
        [[word["label"], word["snapshot"]["hex"], word["snapshot"]["bits"]] for word in key_schedule["words"][:2]],
    )
    for temporary in key_schedule["temporaries"]:
        render_table(
            [
                "Temporary",
                "Input word",
                "RotWord / RotNib",
                "SubWord / SubNib",
                "RCon",
                "Output",
            ],
            [[
                temporary["label"],
                temporary["input"]["hex"],
                temporary["rotated"]["hex"],
                temporary["substituted"]["hex"],
                temporary["rcon"]["hex"],
                temporary["output"]["hex"],
            ]],
        )
    render_scrollable_table(
        "Word derivation",
        ["Result", "Left", "Right", "Value", "Bits"],
        [
            [
                step["label"],
                f'{step["left_label"]} = {step["left"]["hex"]}',
                f'{step["right_label"]} = {step["right"]["hex"]}',
                step["result"]["hex"],
                step["result"]["bits"],
            ]
            for step in key_schedule["xor_steps"]
        ],
        height_px=230,
        max_width_px=1050,
    )
    render_table(
        ["Round key", "Built from", "Value", "Bits"],
        [
            [
                round_key["label"],
                f'{round_key["word_labels"][0]} || {round_key["word_labels"][1]}',
                round_key["snapshot"]["hex"],
                round_key["snapshot"]["bits"],
            ]
            for round_key in key_schedule["round_keys"]
        ],
    )
    render_bitwise_xor(
        left_label="S-AES input",
        left_snapshot=initial["before"],
        right_label="K0",
        right_snapshot=initial["round_key"],
        result_label="After AddRoundKey",
        result_snapshot=initial["after"],
        bitwise_rows=initial["bitwise_rows"],
    )
    render_state_snapshot("Input state", initial["before"])
    render_state_snapshot("State after AddRoundKey", initial["after"])


def render_round1_overview_screen(detail: dict) -> None:
    """Render Screen 8: Round 1 overview."""

    require_streamlit()
    round1 = detail["wizard"]["round1"]
    render_round_key_banner("Round 1 key", round1["round_key"], caption="Round 1 ends with AddRoundKey using K1.")
    render_mermaid_diagram(
        "Round 1 pipeline",
        "\n".join(
            [
                "flowchart LR",
                '    in_state["Round 1 input"]',
                '    sub["SubNib"]',
                '    shift["ShiftRows"]',
                '    mix["MixColumns"]',
                '    ark["AddRoundKey"]',
                f'    key["K1 = {round1["round_key"]["hex"]}"]',
                "    in_state --> sub --> shift --> mix --> ark",
                "    key --> ark",
            ]
        ),
        height=220,
    )
    render_callout("Round 1", "Round 1 applies SubNib, ShiftRows, MixColumns, then AddRoundKey with K1.")


def render_round1_subnib_screen(detail: dict, constants: dict) -> None:
    """Render Screen 9: Round 1 SubNib."""

    require_streamlit()
    round1 = detail["wizard"]["round1"]
    operation = round1["subnib"]
    render_round_key_banner("Round 1 key", round1["round_key"])
    render_state_snapshot("Input state", operation["before"])
    render_sbox_matrix("S-box lookup matrix", constants["s_box_axis_labels"], constants["s_box_rows"])
    render_table(
        ["Cell", "Input bits", "Row bits", "Column bits", "Output nibble", "Output bits"],
        [
            [
                mapping["label"],
                mapping["before_bits"],
                mapping["row_bits"],
                mapping["column_bits"],
                mapping["after"],
                mapping["after_bits"],
            ]
            for mapping in operation["mappings"]
        ],
    )
    render_callout(
        "How the lookup works",
        "For each 4-bit nibble, the first two bits choose the S-box row and the last two bits choose the S-box column.",
    )
    render_state_snapshot("Output state", operation["after"])


def render_round1_shiftrows_screen(detail: dict) -> None:
    """Render Screen 10: Round 1 ShiftRows."""

    require_streamlit()
    round1 = detail["wizard"]["round1"]
    operation = round1["shiftrows"]
    render_round_key_banner("Round 1 key", round1["round_key"])
    columns = st.columns([1, 0.35, 1])
    with columns[0]:
        render_state_snapshot("Input state", operation["before"])
    with columns[1]:
        render_formula_block("ShiftRows", ["→", "We switch the two bottom-row elements."])
    with columns[2]:
        render_state_snapshot("Output state", operation["after"])


def render_round1_mixcolumns_screen(detail: dict) -> None:
    """Render Screen 11: Round 1 MixColumns."""

    require_streamlit()
    round1 = detail["wizard"]["round1"]
    operation = round1["mixcolumns"]
    render_round_key_banner("Round 1 key", round1["round_key"])
    render_state_snapshot("Input state", operation["before"])
    for column in operation["columns"]:
        render_vector_matrix_equation(
            f"Column {column['index']}",
            input_vector=column["input"],
            matrix_rows=operation["matrix"],
            output_vector=column["output"],
            formulas=[
                column["top_formula"],
                *column["top_terms"],
                column["bottom_formula"],
                *column["bottom_terms"],
            ],
        )
    render_state_snapshot("Output state", operation["after"])


def render_round1_add_round_key_screen(detail: dict) -> None:
    """Render Screen 12: Round 1 AddRoundKey."""

    require_streamlit()
    round1 = detail["wizard"]["round1"]
    operation = round1["add_round_key"]
    render_round_key_banner("Round 1 key", round1["round_key"])
    render_bitwise_xor(
        left_label="Round 1 state",
        left_snapshot=operation["before"],
        right_label="K1",
        right_snapshot=round1["round_key"],
        result_label="After K1",
        result_snapshot=operation["after"],
        bitwise_rows=operation["bitwise_rows"],
    )
    render_state_snapshot("State entering AddRoundKey", operation["before"])
    render_state_snapshot("State after AddRoundKey", operation["after"])


def render_round2_overview_screen(detail: dict) -> None:
    """Render Screen 13: Round 2 overview."""

    require_streamlit()
    round2 = detail["wizard"]["round2"]
    render_round_key_banner("Round 2 key", round2["round_key"], caption="Round 2 is the final round, so MixColumns is omitted.")
    render_mermaid_diagram(
        "Round 2 pipeline",
        "\n".join(
            [
                "flowchart LR",
                '    in_state["Round 2 input"]',
                '    sub["SubNib"]',
                '    shift["ShiftRows"]',
                '    ark["AddRoundKey"]',
                f'    key["K2 = {round2["round_key"]["hex"]}"]',
                "    in_state --> sub --> shift --> ark",
                "    key --> ark",
            ]
        ),
        height=220,
    )
    render_callout("Round 2", "Round 2 omits MixColumns and ends with AddRoundKey using K2.")


def render_round2_subnib_screen(detail: dict, constants: dict) -> None:
    """Render Screen 14: Round 2 SubNib."""

    require_streamlit()
    round2 = detail["wizard"]["round2"]
    operation = round2["subnib"]
    render_round_key_banner("Round 2 key", round2["round_key"])
    render_state_snapshot("Input state", operation["before"])
    render_sbox_matrix("S-box lookup matrix", constants["s_box_axis_labels"], constants["s_box_rows"])
    render_table(
        ["Cell", "Input bits", "Row bits", "Column bits", "Output nibble", "Output bits"],
        [
            [
                mapping["label"],
                mapping["before_bits"],
                mapping["row_bits"],
                mapping["column_bits"],
                mapping["after"],
                mapping["after_bits"],
            ]
            for mapping in operation["mappings"]
        ],
    )
    render_callout(
        "How the lookup works",
        "For each 4-bit nibble, the first two bits choose the S-box row and the last two bits choose the S-box column.",
    )
    render_state_snapshot("Output state", operation["after"])


def render_round2_shiftrows_screen(detail: dict) -> None:
    """Render Screen 15: Round 2 ShiftRows."""

    require_streamlit()
    round2 = detail["wizard"]["round2"]
    operation = round2["shiftrows"]
    render_round_key_banner("Round 2 key", round2["round_key"])
    columns = st.columns([1, 0.35, 1])
    with columns[0]:
        render_state_snapshot("Input state", operation["before"])
    with columns[1]:
        render_formula_block("ShiftRows", ["→", "We switch the two bottom-row elements."])
    with columns[2]:
        render_state_snapshot("Output state", operation["after"])


def render_round2_add_round_key_screen(detail: dict) -> None:
    """Render Screen 16: Round 2 AddRoundKey."""

    require_streamlit()
    round2 = detail["wizard"]["round2"]
    operation = round2["add_round_key"]
    render_round_key_banner("Round 2 key", round2["round_key"])
    render_bitwise_xor(
        left_label="Round 2 state",
        left_snapshot=operation["before"],
        right_label="K2",
        right_snapshot=round2["round_key"],
        result_label="Final S-AES output",
        result_snapshot=operation["after"],
        bitwise_rows=operation["bitwise_rows"],
    )
    render_state_snapshot("State entering AddRoundKey", operation["before"])
    render_state_snapshot("Final S-AES output", operation["after"])


def render_final_xor_screen(detail: dict) -> None:
    """Render Screen 17: the final XEX XOR with the tweak."""

    require_streamlit()
    post_xor = detail["wizard"]["post_xor"]
    render_tweak_banner([{"label": "Current tweak", "snapshot": detail["tweak"]}])
    render_bitwise_xor(
        left_label="S-AES output",
        left_snapshot=post_xor["saes_output"],
        right_label="Tweak",
        right_snapshot=post_xor["tweak"],
        result_label="Ciphertext",
        result_snapshot=post_xor["ciphertext_word"],
        bitwise_rows=post_xor["bitwise_rows"],
    )
    render_word_triplet("S-AES output", post_xor["saes_output"], "Tweak", post_xor["tweak"], "Ciphertext", post_xor["ciphertext_word"])
