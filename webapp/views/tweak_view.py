"""Screen 3: tweak generation screen for the SAES-XTS wizard."""

from __future__ import annotations

from webapp.components import render_callout, render_mermaid_diagram, render_scrollable_table, render_table, render_value_cards
from webapp.streamlit_compat import require_streamlit, st


def render_tweak_generation_screen(walkthrough: dict) -> None:
    """Render the tweak-derivation and alpha-multiplication explanation."""

    require_streamlit()
    tweak_generation = walkthrough["tweak_generation"]
    constants = walkthrough["constants"]

    render_value_cards(
        [
            {"label": "Tweak-generation key", "value": f"{tweak_generation['tweak_key']['hex']} ({tweak_generation['tweak_key']['bits']})"},
            {"label": "Data-unit value", "value": f"{tweak_generation['data_unit']['hex']} ({tweak_generation['data_unit']['bits']})"},
            {"label": "Initial tweak T0", "value": f"{tweak_generation['initial_tweak']['hex']} ({tweak_generation['initial_tweak']['bits']})"},
        ]
    )
    render_mermaid_diagram(
        "T0 = S-AES_{TWEAK key}(data-unit)",
        "\n".join(
            [
                "flowchart LR",
                f'    key["TWEAK key<br/>{tweak_generation["tweak_key"]["hex"]}"]',
                f'    pt["data-unit<br/>{tweak_generation["data_unit"]["hex"]}"]',
                '    saes["S-AES"]',
                f'    ct["ciphertext = T0<br/>{tweak_generation["initial_tweak"]["hex"]}"]',
                "    key --> saes",
                "    pt --> saes",
                "    saes --> ct",
            ]
        ),
        height=260,
    )
    render_callout(
        "First tweak",
        f"{tweak_generation['black_box_label']}. This is a real S-AES encryption under the tweak key.",
    )

    progression_nodes = [
        f'{entry["label"]} = {entry["snapshot"]["hex"]}'
        for entry in tweak_generation["values"]
    ]
    progression_diagram = ["flowchart LR"]
    progression_diagram.append(f'    du["Data-unit = {tweak_generation["data_unit"]["hex"]}"]')
    progression_diagram.append('    saes["S-AES under tweak key"]')
    progression_diagram.append("    du --> saes")
    progression_diagram.append('    t0["T0"]')
    progression_diagram.append("    saes --> t0")
    if progression_nodes:
        progression_diagram[-1] = f'    saes --> t0["{progression_nodes[0]}"]'
    for index in range(len(progression_nodes) - 1):
        progression_diagram.append(f'    t{index} -->|multiply by alpha| t{index + 1}["{progression_nodes[index + 1]}"]')
    render_mermaid_diagram(
        "Tweak progression across blocks",
        "\n".join(progression_diagram),
        height=220,
        scrollable=True,
        min_width_px=max(900, 230 * len(progression_nodes)),
    )
    render_callout(
        "Why a left shift appears",
        "Alpha is the field constant 2, written here as 0x0002. Multiplying by alpha starts as a left shift. "
        "If the old top bit spills out, the reduction polynomial is XORed back in to stay inside GF(2^16).",
    )
    render_table(
        ["Constant", "Value", "Meaning"],
        [
            ["alpha", f"{tweak_generation['alpha_constant']['decimal']} / {tweak_generation['alpha_constant']['hex']}", tweak_generation["alpha_constant"]["explanation"]],
            ["Reduction polynomial", constants["tweak_reduction_polynomial_hex"], "Used only when the top bit spills during the left shift."],
        ],
    )

    if tweak_generation["progression"]:
        render_scrollable_table(
            "Tweak progression details",
            ["From", "Shift-left result", "Carry?", "Reduction", "Next tweak", "Explanation"],
            [
                [
                    step["from"]["hex"],
                    step["shifted"]["hex"],
                    "Yes" if step["carry"] else "No",
                    constants["tweak_reduction_polynomial_hex"] if step["reduction_applied"] else "Not needed",
                    step["to"]["hex"],
                    step["note"],
                ]
                for step in tweak_generation["progression"]
            ],
            height_px=250,
            max_width_px=1100,
        )

    render_scrollable_table(
        "Tweak values",
        ["Tweak", "Value", "Bits"],
        [
            [entry["label"], entry["snapshot"]["hex"], entry["snapshot"]["bits"]]
            for entry in tweak_generation["values"]
        ],
        height_px=220,
        max_width_px=900,
    )
