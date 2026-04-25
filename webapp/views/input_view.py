"""Screen 1: input screen for the SAES-XTS wizard."""

from __future__ import annotations

from webapp.components import render_callout
from webapp.streamlit_compat import require_streamlit, st


def render_input_screen(defaults: dict[str, str], error_message: str | None = None) -> dict[str, str] | None:
    """Render the wizard's first screen and return submitted raw values."""

    require_streamlit()
    st.subheader("Enter the plaintext and the 16-bit values used by the real SAES-XTS implementation.")
    render_callout(
        "Encoding assumption",
        "Every plaintext character is treated as one 8-bit Latin-1 / ASCII-style byte. "
        "Two bytes become one 16-bit S-AES block."
    )
    if error_message:
        render_callout("Input validation", error_message)

    with st.form("saes_xts_wizard_input_form"):
        plaintext_text = st.text_area(
            "Plaintext",
            value=defaults["plaintext_text"],
            help="Latin-1 / ASCII characters only. Each character becomes one byte.",
        )
        key_columns = st.columns(3)
        data_key_text = key_columns[0].text_input(
            "S-AES data key",
            value=defaults["data_key_text"],
            help="16-bit value, such as 0x4AF5.",
        )
        tweak_key_text = key_columns[1].text_input(
            "Tweak-generation key",
            value=defaults["tweak_key_text"],
            help="16-bit value used to derive the first tweak from the data-unit value.",
        )
        data_unit_text = key_columns[2].text_input(
            "Data-unit value",
            value=defaults["data_unit_text"],
            help="16-bit value encrypted under the tweak key to produce T0.",
        )
        submitted = st.form_submit_button("Next")

    if not submitted:
        return None
    return {
        "plaintext_text": plaintext_text,
        "data_key_text": data_key_text,
        "tweak_key_text": tweak_key_text,
        "data_unit_text": data_unit_text,
    }
