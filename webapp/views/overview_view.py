"""Screens 4 and 18: block/tweak overview screens for the wizard."""

from __future__ import annotations

from webapp.components import render_block_strip, render_mermaid_diagram, render_table, render_tweak_banner
from webapp.streamlit_compat import require_streamlit, st


def render_block_selection_screen(
    walkthrough: dict,
    *,
    selected_id: str,
    include_ciphertexts: bool,
) -> str:
    """Render the block/tweak overview and return the current selection id."""

    require_streamlit()
    selection = walkthrough["block_selection"]
    final_assignment = walkthrough["final_assignment"]
    options = selection["options"]
    ids = [option["id"] for option in options]
    labels = {option["id"]: option["label"] for option in options}
    if selected_id not in ids:
        selected_id = selection["default_selection_id"]

    st.markdown(
        "Each full 16-bit block gets its own tweak. If the plaintext ends with a single byte, "
        "the final 1.5 blocks are explored through the ciphertext-stealing path."
    )
    diagram_entries = final_assignment if include_ciphertexts else options
    render_mermaid_diagram(
        "Block-to-tweak assignment",
        _assignment_diagram(diagram_entries, include_ciphertexts),
        height=280,
        scrollable=True,
        min_width_px=max(1000, 260 * len(diagram_entries)),
    )

    render_block_strip(
        "Plaintext blocks",
        walkthrough["overview"]["message_blocks"],
        scrollable=True,
        height_px=240,
        max_width_px=1100,
    )
    st.markdown("**Block assignment**")
    render_table(
        ["Selection", "Plaintext", "Tweak", "Tail information"],
        [
            [
                option["label"],
                option["plaintext_block"]["hex"],
                (
                    option["tweak"]["hex"]
                    if option["kind"] == "regular"
                    else f"{option['provisional_tweak']['hex']} then {option['final_tweak']['hex']}"
                ),
                option.get("tail_block", {}).get("hex", "-") if option["kind"] == "tail" else "-",
            ]
            for option in options
        ],
    )

    if include_ciphertexts:
        render_block_strip(
            "Ciphertext blocks",
            walkthrough["output"]["ciphertext_blocks"],
            scrollable=True,
            height_px=240,
            max_width_px=1100,
        )
        render_table(
            ["Selection", "Plaintext", "Tweak(s)", "Ciphertext result"],
            [
                [
                    entry["label"],
                    entry["plaintext_block"]["hex"],
                    (
                        entry["tweak"]["hex"]
                        if entry["kind"] == "regular"
                        else f"{entry['provisional_tweak']['hex']} then {entry['final_tweak']['hex']}"
                    ),
                    (
                        entry["ciphertext_block"]["hex"]
                        if entry["kind"] == "regular"
                        else f"{entry['ciphertext_block']['hex']} + {entry['ciphertext_tail']['hex']}"
                    ),
                ]
                for entry in final_assignment
            ],
        )

    selected_id = st.radio(
        "Choose what to inspect next",
        ids,
        index=ids.index(selected_id),
        format_func=lambda option_id: labels[option_id],
    )

    selected_option = next(option for option in options if option["id"] == selected_id)
    if selected_option["kind"] == "regular":
        render_tweak_banner([{"label": f"Tweak for {selected_option['label']}", "snapshot": selected_option["tweak"]}])
    else:
        render_tweak_banner(
            [
                {"label": "Provisional tweak", "snapshot": selected_option["provisional_tweak"]},
                {"label": "Final tweak", "snapshot": selected_option["final_tweak"]},
            ]
        )
    st.caption(selected_option["caption"])
    return selected_id


def _assignment_diagram(entries: list[dict], include_ciphertexts: bool) -> str:
    """Build a Mermaid summary of block assignments for the overview screens."""

    lines = ["flowchart TB"]
    for index, entry in enumerate(entries):
        if entry["kind"] == "regular":
            lines.extend(
                [
                    f'    p{index}["{entry["label"]}<br/>P = {entry["plaintext_block"]["hex"]}"]',
                    f'    t{index}["Tweak<br/>{entry["tweak"]["hex"]}"]',
                    f'    x{index}["XEX block path"]',
                    "    p{0} --> x{0}".format(index),
                    "    t{0} --> x{0}".format(index),
                ]
            )
            if include_ciphertexts:
                lines.append(f'    c{index}["Ciphertext<br/>{entry["ciphertext_block"]["hex"]}"]')
                lines.append("    x{0} --> c{0}".format(index))
        else:
            lines.extend(
                [
                    f'    p{index}["Tail case<br/>full = {entry["plaintext_block"]["hex"]}<br/>tail = {entry["tail_block"]["hex"]}"]',
                    f'    t{index}["Tweaks<br/>{entry["provisional_tweak"]["hex"]} then {entry["final_tweak"]["hex"]}"]',
                    f'    x{index}["Ciphertext stealing path"]',
                    "    p{0} --> x{0}".format(index),
                    "    t{0} --> x{0}".format(index),
                ]
            )
            if include_ciphertexts:
                tail_hex = entry.get("ciphertext_tail", {}).get("hex", "")
                lines.append(f'    c{index}["Ciphertext<br/>{entry["ciphertext_block"]["hex"]} + {tail_hex}"]')
                lines.append("    x{0} --> c{0}".format(index))
    return "\n".join(lines)
