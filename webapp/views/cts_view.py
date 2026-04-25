"""Tail screens for the ciphertext-stealing branch of the wizard."""

from __future__ import annotations

from webapp.components import render_callout, render_mermaid_diagram, render_named_block_row, render_table, render_tweak_banner
from webapp.streamlit_compat import require_streamlit, st


def render_cts_overview_screen(walkthrough: dict) -> None:
    """Render Tail Screen 1: the holistic CTS overview."""

    require_streamlit()
    cts = walkthrough["cts"]
    if cts is None:
        render_callout("No tail present", "This message has no 8-bit tail, so ciphertext stealing is not needed.")
        return

    render_tweak_banner(
        [
            {"label": "Provisional tweak", "snapshot": cts["provisional_tweak"]},
            {"label": "Final tweak", "snapshot": cts["final_tweak"]},
        ]
    )
    render_callout(
        "Why ciphertext stealing is needed",
        "Normal 16-bit block processing is not enough here because the plaintext ends with only one byte. "
        "The last full block and the final 8-bit tail must be processed together."
    )
    render_mermaid_diagram(
        "CTS step-by-step flow",
        "\n".join(
            [
                "flowchart LR",
                f'    full["Last full block = {cts["penultimate_plaintext"]["hex"]}"]',
                f'    tail["8-bit tail = {cts["partial_plaintext"]["hex"]}"]',
                f'    provisional["Provisional ciphertext = {cts["provisional_ciphertext"]["hex"]}"]',
                f'    retained["Retained byte = {cts["retained_fragment"]["hex"]}"]',
                f'    composite["Tail + retained byte = {cts["composite_plaintext"]["hex"]}"]',
                f'    final_block["Final full ciphertext = {cts["final_penultimate_ciphertext"]["hex"]}"]',
                f'    final_tail["Final tail ciphertext = {cts["stolen_fragment"]["hex"]}"]',
                "    full --> provisional",
                "    provisional --> retained",
                "    tail --> composite",
                "    retained --> composite",
                "    composite --> final_block",
                "    provisional --> final_tail",
            ]
        ),
        height=300,
    )
    render_callout(
        "Reading the flow",
        "First we encrypt the last full plaintext block to get a provisional ciphertext. "
        "Its first byte becomes the final short ciphertext tail. "
        "Its remaining byte is concatenated with the plaintext tail byte to make a new 16-bit block, "
        "which is then encrypted with SAES_XTS to produce the final ciphertext block before the tail.",
    )
    render_table(
        ["Step", "Value", "Meaning"],
        [
            ["1", cts["provisional_ciphertext"]["hex"], "Encrypt the last full plaintext block before considering the tail."],
            ["2", cts["stolen_fragment"]["hex"], "Take the first byte of that provisional ciphertext as the final short ciphertext tail."],
            ["3", cts["partial_plaintext"]["hex"], "Keep the original 8-bit plaintext tail."],
            ["4", cts["composite_plaintext"]["hex"], "Concatenate the plaintext tail byte with the retained provisional byte."],
            ["5", cts["final_penultimate_ciphertext"]["hex"], "Encrypt that composite block with SAES_XTS to get the final ciphertext block before the tail."],
        ],
    )
    render_table(
        ["Stage", "Left value", "Middle value", "What it means"],
        [
            [row["stage"], row["left"], row["middle"], row["right"]]
            for row in cts["wizard"]["rearrangement_rows"]
        ],
    )
    render_named_block_row(
        "CTS block snapshots",
        [
            {"title": "Last full plaintext block", "snapshot": cts["penultimate_plaintext"]},
            {"title": "Final 8-bit tail", "snapshot": cts["partial_plaintext"]},
            {"title": "Provisional ciphertext block", "snapshot": cts["provisional_ciphertext"]},
            {"title": "Retained byte from the provisional ciphertext", "snapshot": cts["retained_fragment"]},
            {"title": "Composite plaintext used for the second encryption", "snapshot": cts["composite_plaintext"]},
            {"title": "Final ciphertext block", "snapshot": cts["final_penultimate_ciphertext"]},
            {"title": "Final ciphertext tail", "snapshot": cts["stolen_fragment"]},
        ],
        scrollable=True,
        height_px=250,
        max_width_px=1200,
    )
    render_callout(
        "Length preservation",
        "The total ciphertext length still matches the total plaintext length, and both encryptions in this flow use SAES_XTS.",
    )
