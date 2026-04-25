"""Reusable Streamlit rendering helpers for the educational SAES-XTS app."""

from __future__ import annotations

import html
from uuid import uuid4

from .state_formatters import build_html_table, escape_html, format_block_snapshot, format_word_snapshot
from .streamlit_compat import require_streamlit, require_streamlit_components, st, st_components


def inject_base_styles() -> None:
    """Load monochrome CSS snippets shared by the wizard screens."""

    require_streamlit()
    st.markdown(
        """
        <style>
        :root {
            --saes-black: #000000;
            --saes-white: #ffffff;
        }
        .stApp,
        .stApp p,
        .stApp small,
        .stApp label,
        .stApp li,
        .stApp h1,
        .stApp h2,
        .stApp h3,
        .stApp h4,
        .stApp h5,
        .stApp h6,
        .stApp code {
            color: var(--saes-black);
        }
        .stApp code,
        .stApp pre {
            background: var(--saes-white) !important;
            color: var(--saes-black) !important;
            box-shadow: none !important;
        }
        [data-testid="stAppViewContainer"],
        [data-testid="stHeader"],
        [data-testid="stToolbar"],
        section[data-testid="stSidebar"] {
            background: var(--saes-white);
        }
        [data-testid="stCaptionContainer"],
        [data-testid="stCaptionContainer"] * {
            color: var(--saes-black) !important;
            opacity: 1 !important;
        }
        .stTextInput input,
        .stTextArea textarea,
        .stSelectbox div[data-baseweb="select"] > div,
        .stNumberInput input {
            background: var(--saes-white) !important;
            color: var(--saes-black) !important;
            border: 2px solid var(--saes-black) !important;
            border-radius: 0 !important;
        }
        .stButton > button,
        .stFormSubmitButton > button {
            background: var(--saes-black) !important;
            color: var(--saes-white) !important;
            border: 2px solid var(--saes-black) !important;
            border-radius: 0 !important;
            box-shadow: none !important;
        }
        .stButton > button *,
        .stFormSubmitButton > button * {
            color: var(--saes-white) !important;
        }
        .stButton > button:hover,
        .stFormSubmitButton > button:hover {
            background: var(--saes-white) !important;
            color: var(--saes-black) !important;
        }
        .stButton > button:hover *,
        .stFormSubmitButton > button:hover * {
            color: var(--saes-black) !important;
        }
        input[type="radio"] {
            accent-color: var(--saes-black);
        }
        .saes-banner {
            border: 3px solid var(--saes-black);
            background: var(--saes-white);
            padding: 1rem 1rem 0.9rem 1rem;
            margin-bottom: 1rem;
        }
        .saes-banner-top {
            display: flex;
            justify-content: space-between;
            gap: 1rem;
            align-items: baseline;
            flex-wrap: wrap;
        }
        .saes-banner h3,
        .saes-banner p {
            margin: 0;
        }
        .saes-banner,
        .saes-banner * {
            color: var(--saes-black);
        }
        .saes-progress {
            margin-top: 0.8rem;
            height: 0.85rem;
            border: 2px solid var(--saes-black);
            background: var(--saes-white);
        }
        .saes-progress-fill {
            height: 100%;
            background: var(--saes-black);
        }
        .saes-card {
            border: 2px solid var(--saes-black);
            padding: 0.85rem 1rem;
            background: var(--saes-white);
            min-height: 8rem;
        }
        .saes-card h4 {
            margin: 0 0 0.35rem 0;
            font-size: 0.95rem;
        }
        .saes-card,
        .saes-card * {
            color: var(--saes-black);
        }
        .saes-card code,
        .saes-callout code {
            display: block;
            font-size: 0.95rem;
            white-space: pre-wrap;
            color: var(--saes-black) !important;
            background: var(--saes-white) !important;
            border: 2px solid var(--saes-black);
            padding: 0.45rem 0.55rem;
            border-radius: 0;
        }
        .saes-table {
            width: 100%;
            border-collapse: collapse;
            margin: 0.35rem 0 0.75rem 0;
            background: var(--saes-white);
        }
        .saes-table-wrap {
            width: 100%;
            overflow-x: auto;
        }
        .saes-table th,
        .saes-table td {
            border: 2px solid var(--saes-black);
            padding: 0.45rem 0.55rem;
            text-align: left;
            vertical-align: top;
        }
        .saes-table th {
            background: var(--saes-black);
            color: var(--saes-white);
        }
        .saes-table th * {
            color: var(--saes-white) !important;
        }
        .saes-table td,
        .saes-table td * {
            color: var(--saes-black);
        }
        .saes-chip {
            display: inline-block;
            margin: 0.2rem 0.3rem 0.2rem 0;
            padding: 0.4rem 0.6rem;
            border: 2px solid var(--saes-black);
            background: var(--saes-white);
            font-family: monospace;
        }
        .saes-chip,
        .saes-chip * {
            color: var(--saes-black);
        }
        .saes-callout {
            border: 2px solid var(--saes-black);
            background: var(--saes-white);
            padding: 0.85rem 1rem;
            margin: 0.75rem 0 1rem 0;
        }
        .saes-callout h4,
        .saes-callout p {
            margin: 0;
        }
        .saes-callout p + p {
            margin-top: 0.45rem;
        }
        .saes-callout,
        .saes-callout * {
            color: var(--saes-black);
        }
        .saes-mermaid-label {
            margin: 0.25rem 0 0.45rem 0;
            font-weight: 600;
        }
        .saes-scroll-frame {
            border: 2px solid var(--saes-black);
            background: var(--saes-white);
            padding: 0.6rem;
            overflow: auto;
            margin: 0.35rem 0 0.9rem 0;
        }
        .saes-scroll-frame > *:last-child {
            margin-bottom: 0;
        }
        .saes-block-row {
            display: flex;
            gap: 0.75rem;
            align-items: stretch;
            width: max-content;
            min-width: 100%;
        }
        .saes-block-card {
            border: 2px solid var(--saes-black);
            background: var(--saes-white);
            padding: 0.75rem;
            min-width: 12rem;
            max-width: 12rem;
            flex: 0 0 12rem;
        }
        .saes-block-card h4,
        .saes-block-card p {
            margin: 0;
        }
        .saes-block-card p {
            margin-top: 0.45rem;
        }
        .saes-state-layout {
            display: grid;
            grid-template-columns: repeat(2, minmax(13rem, 1fr));
            gap: 1rem;
            margin: 0.4rem 0 0.9rem 0;
        }
        .saes-state-box {
            border: 2px solid var(--saes-black);
            background: var(--saes-white);
            padding: 0.75rem;
        }
        .saes-state-box h5 {
            margin: 0 0 0.6rem 0;
        }
        .saes-state-grid {
            display: grid;
            grid-template-columns: repeat(2, minmax(3.5rem, 1fr));
            gap: 0.5rem;
        }
        .saes-state-cell {
            border: 2px solid var(--saes-black);
            min-height: 3rem;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: monospace;
            font-size: 1rem;
            font-weight: 600;
        }
        .saes-arrow-stack {
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 2rem;
            font-weight: 700;
            min-height: 100%;
        }
        .saes-formula-box {
            border: 2px solid var(--saes-black);
            background: var(--saes-white);
            padding: 0.75rem;
            margin: 0.35rem 0 0.9rem 0;
        }
        .saes-formula-box h5,
        .saes-formula-box p {
            margin: 0;
        }
        .saes-formula-box p + p,
        .saes-formula-box ul {
            margin-top: 0.45rem;
        }
        .saes-formula-box ul {
            padding-left: 1.1rem;
        }
        .saes-credit {
            margin: 0.35rem 0 1rem 0;
            padding: 0.7rem 1rem;
            border: 1.5px solid var(--saes-black);
            background: var(--saes-white);
            text-align: center;
            font-weight: 600;
            letter-spacing: 0.06em;
            text-transform: uppercase;
            font-size: 0.9rem;
        }
        .saes-credit,
        .saes-credit * {
            color: var(--saes-black);
        }
        @media (max-width: 900px) {
            [data-testid="stHorizontalBlock"] {
                gap: 0.75rem !important;
                flex-wrap: wrap !important;
            }
            [data-testid="column"] {
                min-width: calc(50% - 0.75rem) !important;
                flex: 1 1 calc(50% - 0.75rem) !important;
            }
            .saes-state-layout {
                grid-template-columns: 1fr;
            }
            .saes-block-card {
                min-width: 10rem;
                max-width: 10rem;
                flex: 0 0 10rem;
            }
            .saes-card {
                min-height: auto;
            }
        }
        @media (max-width: 640px) {
            .block-container,
            .stApp {
                font-size: 0.96rem;
            }
            [data-testid="stHorizontalBlock"] {
                flex-direction: column !important;
            }
            [data-testid="column"] {
                min-width: 100% !important;
                flex: 1 1 100% !important;
            }
            .saes-banner {
                padding: 0.85rem;
            }
            .saes-banner-top {
                flex-direction: column;
                align-items: flex-start;
            }
            .saes-state-grid {
                gap: 0.35rem;
            }
            .saes-state-cell {
                min-height: 2.4rem;
                font-size: 0.88rem;
            }
            .saes-block-row {
                min-width: max-content;
            }
            .saes-block-card {
                min-width: 9rem;
                max-width: 9rem;
                flex: 0 0 9rem;
                padding: 0.65rem;
            }
            .saes-scroll-frame {
                padding: 0.45rem;
            }
            .saes-table th,
            .saes-table td {
                white-space: nowrap;
            }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_screen_header(title: str, *, position: int, total: int, subtitle: str | None = None) -> None:
    """Render the wizard title and monochrome progress banner."""

    require_streamlit()
    width_percent = 0 if total == 0 else max(0.0, min(100.0, (position / total) * 100))
    subtitle_html = f"<p>{escape_html(subtitle)}</p>" if subtitle else ""
    st.markdown(
        (
            "<div class='saes-banner'>"
            "<div class='saes-banner-top'>"
            f"<h3>{escape_html(title)}</h3>"
            f"<p>Step {position} of {total}</p>"
            "</div>"
            f"{subtitle_html}"
            "<div class='saes-progress'>"
            f"<div class='saes-progress-fill' style='width: {width_percent:.2f}%;'></div>"
            "</div>"
            "</div>"
        ),
        unsafe_allow_html=True,
    )


def render_callout(title: str, body: str) -> None:
    """Render a monochrome explanatory callout."""

    require_streamlit()
    paragraphs = "".join(f"<p>{escape_html(line)}</p>" for line in body.split("\n") if line.strip())
    st.markdown(
        (
            "<div class='saes-callout'>"
            f"<h4>{escape_html(title)}</h4>"
            f"{paragraphs}"
            "</div>"
        ),
        unsafe_allow_html=True,
    )


def render_credit(text: str) -> None:
    """Render a simple monochrome credit block."""

    require_streamlit()
    st.markdown(f"<div class='saes-credit'>{escape_html(text)}</div>", unsafe_allow_html=True)


def render_value_cards(cards: list[dict[str, str]]) -> None:
    """Render a row of labeled value cards."""

    require_streamlit()
    if not cards:
        return
    columns = st.columns(len(cards))
    for column, card in zip(columns, cards):
        with column:
            caption_html = f"<p>{escape_html(card['caption'])}</p>" if card.get("caption") else ""
            column.markdown(
                (
                    "<div class='saes-card'>"
                    f"<h4>{escape_html(card['label'])}</h4>"
                    f"<code>{escape_html(card['value'])}</code>"
                    f"{caption_html}"
                    "</div>"
                ),
                unsafe_allow_html=True,
            )


def render_table(headers: list[str], rows: list[list[object]]) -> None:
    """Render a simple HTML table."""

    require_streamlit()
    st.markdown(build_html_table(headers, rows), unsafe_allow_html=True)


def render_scrollable_table(
    title: str,
    headers: list[str],
    rows: list[list[object]],
    *,
    height_px: int,
    max_width_px: int | None = None,
) -> None:
    """Render a table inside a fixed-size scrollable frame."""

    require_streamlit()
    st.markdown(f"**{escape_html(title)}**")
    _render_scroll_frame(build_html_table(headers, rows), height_px=height_px, max_width_px=max_width_px)


def render_block_strip(
    title: str,
    blocks: list[dict],
    *,
    scrollable: bool = False,
    height_px: int = 220,
    max_width_px: int | None = None,
) -> None:
    """Render a horizontal strip of blocks or tail chunks."""

    require_streamlit()
    st.markdown(f"**{escape_html(title)}**")
    if not blocks:
        st.markdown("<p>No blocks to display.</p>", unsafe_allow_html=True)
        return
    cards = []
    for block in blocks:
        label = f"Block {block['index']}" if not block["is_partial"] else f"Tail {block['index']}"
        cards.append(
            (
                "<div class='saes-block-card'>"
                f"<h4>{escape_html(label)}</h4>"
                f"<code>{escape_html(format_block_snapshot(block))}</code>"
                f"<p>{escape_html(block['bits'])}</p>"
                "</div>"
            )
        )
    html_body = f"<div class='saes-block-row'>{''.join(cards)}</div>"
    if scrollable:
        _render_scroll_frame(html_body, height_px=height_px, max_width_px=max_width_px)
    else:
        st.markdown(html_body, unsafe_allow_html=True)


def render_named_block_row(
    title: str,
    items: list[dict[str, object]],
    *,
    scrollable: bool = False,
    height_px: int = 240,
    max_width_px: int | None = None,
) -> None:
    """Render a row of labeled block cards."""

    require_streamlit()
    st.markdown(f"**{escape_html(title)}**")
    cards = []
    for item in items:
        snapshot = item["snapshot"]
        assert isinstance(snapshot, dict)
        cards.append(
            (
                "<div class='saes-block-card'>"
                f"<h4>{escape_html(item['title'])}</h4>"
                f"<code>{escape_html(format_block_snapshot(snapshot))}</code>"
                f"<p>{escape_html(snapshot['bits'])}</p>"
                "</div>"
            )
        )
    html_body = f"<div class='saes-block-row'>{''.join(cards)}</div>"
    if scrollable:
        _render_scroll_frame(html_body, height_px=height_px, max_width_px=max_width_px)
    else:
        st.markdown(html_body, unsafe_allow_html=True)


def render_state_snapshot(title: str, snapshot: dict) -> None:
    """Render paired hex/binary 2x2 state matrices."""

    require_streamlit()
    st.markdown(f"**{escape_html(title)}**")
    st.markdown(
        (
            "<div class='saes-state-layout'>"
            f"{_build_state_box('Hex state', snapshot['state_hex_rows'])}"
            f"{_build_state_box('Binary state', snapshot['state_bit_rows'])}"
            "</div>"
        ),
        unsafe_allow_html=True,
    )
    st.caption(f"{snapshot['hex']}  |  {snapshot['bits']}")


def render_word_triplet(left_label: str, left_snapshot: dict, right_label: str, right_snapshot: dict, result_label: str, result_snapshot: dict) -> None:
    """Render a simple three-stage word relationship such as P xor T -> PP."""

    render_value_cards(
        [
            {"label": left_label, "value": format_word_snapshot(left_snapshot)},
            {"label": right_label, "value": format_word_snapshot(right_snapshot)},
            {"label": result_label, "value": format_word_snapshot(result_snapshot)},
        ]
    )


def render_tweak_banner(tweaks: list[dict[str, str]]) -> None:
    """Render the current tweak or tweak pair on XTS-related screens."""

    if not tweaks:
        return
    render_value_cards(
        [
            {"label": tweak["label"], "value": format_word_snapshot(tweak["snapshot"])}
            for tweak in tweaks
        ]
    )


def render_round_key_banner(label: str, key_snapshot: dict, *, caption: str | None = None) -> None:
    """Render the relevant AddRoundKey value for an S-AES screen."""

    render_value_cards(
        [
            {
                "label": label,
                "value": format_word_snapshot(key_snapshot),
                "caption": caption or "",
            }
        ]
    )


def render_bitwise_xor(
    *,
    left_label: str,
    left_snapshot: dict,
    right_label: str,
    right_snapshot: dict,
    result_label: str,
    result_snapshot: dict,
    bitwise_rows: list[dict[str, str | int]],
) -> None:
    """Render a bit-by-bit XOR explanation table."""

    render_word_triplet(left_label, left_snapshot, right_label, right_snapshot, result_label, result_snapshot)
    render_table(
        ["Bit position", left_label, right_label, result_label],
        [
            [row["position"], row["left"], row["right"], row["result"]]
            for row in bitwise_rows
        ],
    )


def render_pipeline_steps(title: str, steps: list[str]) -> None:
    """Render a linear flow as a Mermaid diagram."""

    diagram_lines = ["flowchart LR"]
    for index, step in enumerate(steps):
        diagram_lines.append(f'    n{index}["{_mermaid_label(step)}"]')
    for index in range(len(steps) - 1):
        diagram_lines.append(f"    n{index} --> n{index + 1}")
    render_mermaid_diagram(title, "\n".join(diagram_lines), height=_diagram_height(len(steps), 180))


def render_mermaid_diagram(
    title: str,
    diagram: str,
    *,
    height: int = 220,
    scrollable: bool = False,
    min_width_px: int | None = None,
) -> None:
    """Render a Mermaid diagram inside an HTML component."""

    require_streamlit()
    st.markdown(f"<p class='saes-mermaid-label'>{escape_html(title)}</p>", unsafe_allow_html=True)
    if st_components is None:
        st.code(diagram, language="mermaid")
        return

    container_id = f"saes-mermaid-{uuid4().hex}"
    html_document = f"""
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8" />
      <style>
        body {{
          margin: 0;
          padding: 0;
          background: #ffffff;
        }}
        .mermaid-frame {{
          border: 2px solid #000000;
          background: #ffffff;
          padding: 0.4rem;
          box-sizing: border-box;
          min-width: {0 if min_width_px is None else min_width_px}px;
        }}
        .mermaid svg {{
          max-width: 100%;
          height: auto;
        }}
      </style>
    </head>
    <body>
      <div class="mermaid-frame">
        <pre class="mermaid" id="{container_id}">{html.escape(diagram)}</pre>
      </div>
      <script type="module">
        import mermaid from "https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs";
        mermaid.initialize({{
          startOnLoad: true,
          theme: "base",
          securityLevel: "loose",
          fontFamily: "Georgia, Times New Roman, serif",
          themeVariables: {{
            primaryColor: "#ffffff",
            primaryTextColor: "#000000",
            primaryBorderColor: "#000000",
            secondaryColor: "#ffffff",
            secondaryTextColor: "#000000",
            secondaryBorderColor: "#000000",
            tertiaryColor: "#ffffff",
            tertiaryTextColor: "#000000",
            tertiaryBorderColor: "#000000",
            lineColor: "#000000",
            textColor: "#000000",
            mainBkg: "#ffffff",
            nodeBkg: "#ffffff",
            nodeTextColor: "#000000",
            clusterBkg: "#ffffff",
            clusterBorder: "#000000",
            edgeLabelBackground: "#ffffff",
            background: "#ffffff"
          }}
        }});
        await mermaid.run({{ nodes: [document.getElementById("{container_id}")] }});
      </script>
    </body>
    </html>
    """
    require_streamlit_components()
    st_components.html(html_document, height=height, scrolling=scrollable)


def render_reference_matrix(title: str, rows: list[list[str]]) -> None:
    """Render a compact matrix or S-box table."""

    require_streamlit()
    st.markdown(f"**{escape_html(title)}**")
    render_table([f"Col {index}" for index in range(len(rows[0]))], rows)


def render_sbox_matrix(title: str, axis_labels: list[str], rows: list[list[str]]) -> None:
    """Render the S-box with 2-bit row/column headers."""

    require_streamlit()
    st.markdown(f"**{escape_html(title)}**")
    render_table(
        ["row \\ col", *axis_labels],
        [[axis_labels[index], *row] for index, row in enumerate(rows)],
    )


def render_formula_block(title: str, lines: list[str]) -> None:
    """Render a compact bordered explanation block."""

    require_streamlit()
    paragraphs = "".join(f"<p>{escape_html(line)}</p>" for line in lines)
    st.markdown(
        (
            "<div class='saes-formula-box'>"
            f"<h5>{escape_html(title)}</h5>"
            f"{paragraphs}"
            "</div>"
        ),
        unsafe_allow_html=True,
    )


def render_vector_matrix_equation(
    title: str,
    *,
    input_vector: list[str],
    matrix_rows: list[list[str]],
    output_vector: list[str],
    formulas: list[str],
) -> None:
    """Render one MixColumns-style vector-by-matrix explanation."""

    require_streamlit()
    columns = st.columns([1.1, 1.2, 1.1])
    with columns[0]:
        st.markdown(f"**{escape_html(title)}**")
        st.markdown(_build_state_box("Input column", [[value] for value in input_vector]), unsafe_allow_html=True)
    with columns[1]:
        st.markdown(_build_state_box("Constant matrix", matrix_rows), unsafe_allow_html=True)
        render_formula_block("Formulas", formulas)
    with columns[2]:
        st.markdown(_build_state_box("Output column", [[value] for value in output_vector]), unsafe_allow_html=True)


def render_partition_story(encoding: dict) -> None:
    """Render a guided character -> byte -> block partitioning story."""

    require_streamlit()
    render_pipeline_steps(
        "Partitioning flow",
        [
            "Characters",
            "8-bit bytes",
            "Pair bytes into 16-bit blocks",
            "Leave one 8-bit tail only if the byte count is odd",
        ],
    )
    characters = "".join(
        f"<span class='saes-chip'>{escape_html(row['character'])}</span>"
        for row in encoding["character_rows"]
    )
    byte_values = "".join(
        f"<span class='saes-chip'>{escape_html(row['byte_hex'])}</span>"
        for row in encoding["character_rows"]
    )
    st.markdown("**Step 1 - Characters**")
    st.markdown(characters or "<em>No characters</em>", unsafe_allow_html=True)
    st.markdown("**Step 2 - Each character becomes one byte**")
    st.markdown(byte_values or "<em>No bytes</em>", unsafe_allow_html=True)


def _mermaid_label(text: str) -> str:
    """Escape labels so they stay valid inside Mermaid node definitions."""

    return text.replace('"', "'").replace("\n", "<br/>")


def _diagram_height(step_count: int, minimum: int) -> int:
    """Estimate a reasonable iframe height for a small Mermaid diagram."""

    return max(minimum, 120 + (step_count * 24))


def _render_scroll_frame(html_body: str, *, height_px: int, max_width_px: int | None = None) -> None:
    """Render raw HTML inside a bordered scrollable frame."""

    require_streamlit()
    width_style = "width: 100%;"
    if max_width_px is not None:
        width_style += f" max-width: {max_width_px}px;"
    st.markdown(
        (
            f"<div class='saes-scroll-frame' style='height: {height_px}px; {width_style}'>"
            f"{html_body}"
            "</div>"
        ),
        unsafe_allow_html=True,
    )


def _build_state_box(title: str, rows: list[list[str]]) -> str:
    """Build a boxed matrix with arbitrary dimensions."""

    if not rows:
        return ""
    column_count = len(rows[0])
    cells = "".join(
        f"<div class='saes-state-cell'>{escape_html(cell)}</div>"
        for row in rows
        for cell in row
    )
    return (
        "<div class='saes-state-box'>"
        f"<h5>{escape_html(title)}</h5>"
        f"<div class='saes-state-grid' style='grid-template-columns: repeat({column_count}, minmax(3.5rem, 1fr));'>{cells}</div>"
        "</div>"
    )
