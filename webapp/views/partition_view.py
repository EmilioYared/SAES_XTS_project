"""Screen 2: plaintext partitioning screen for the SAES-XTS wizard."""

from __future__ import annotations

from webapp.components import render_block_strip, render_callout, render_partition_story, render_table, render_value_cards
from webapp.streamlit_compat import require_streamlit, st


def render_partition_screen(walkthrough: dict) -> None:
    """Render the wizard screen that explains 8-bit encoding and 16-bit grouping."""

    require_streamlit()
    inputs = walkthrough["inputs"]
    encoding = walkthrough["encoding"]

    render_value_cards(
        [
            {"label": "Encoding rule", "value": inputs["encoding_label"]},
            {"label": "Plaintext bytes", "value": inputs["plaintext_hex"]},
            {"label": "Plaintext bits", "value": inputs["plaintext_bits"]},
        ]
    )
    st.markdown(
        "The wizard now turns the plaintext into a byte stream, then cuts that stream into 16-bit S-AES blocks."
    )
    render_partition_story(encoding)
    if encoding["blocks"]:
        render_block_strip(
            "Grouped 16-bit blocks",
            encoding["blocks"],
            scrollable=True,
            height_px=220,
            max_width_px=1100,
        )
    if encoding["tail"] is not None:
        render_block_strip(
            "Remaining 8-bit tail",
            [encoding["tail"]],
            scrollable=True,
            height_px=180,
            max_width_px=420,
        )
    render_table(
        ["Index", "Character", "Byte", "8-bit value", "Grouped into"],
        [
            [row["index"], row["character"], row["byte_hex"], row["bits"], row["block_label"]]
            for row in encoding["character_rows"]
        ],
    )
    if encoding["tail"] is not None:
        render_callout(
            "Tail detected",
            "One final 8-bit byte remains after pairing. That leftover byte will trigger ciphertext stealing later.",
        )
    else:
        render_callout(
            "Full-block partitioning",
            "The plaintext divides cleanly into full 16-bit blocks.",
        )
