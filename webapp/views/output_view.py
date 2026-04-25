"""Final ciphertext summary section."""

from __future__ import annotations

from ..components import render_block_strip, render_value_cards
from ..streamlit_compat import require_streamlit, st


def render_output_view(walkthrough: dict) -> None:
    """Render the final ciphertext output summary."""

    require_streamlit()
    st.subheader("Section 7 - Final Output View")
    output = walkthrough["output"]

    render_value_cards(
        [
            {"label": "Ciphertext bytes", "value": output["ciphertext_hex"]},
            {"label": "Ciphertext bits", "value": output["ciphertext_bits"]},
            {"label": "Ciphertext stealing", "value": "Used" if output["used_ciphertext_stealing"] else "Not used"},
        ]
    )
    render_block_strip("Final ciphertext grouped as blocks", output["ciphertext_blocks"])
