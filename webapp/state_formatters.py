"""Pure formatting helpers for the educational SAES-XTS web UI."""

from __future__ import annotations

from html import escape
from typing import Iterable


def escape_html(value: object) -> str:
    """Escape user-visible values before inserting them into HTML snippets."""

    return escape(str(value))


def format_byte_hex_sequence(values: Iterable[int]) -> str:
    """Format a byte iterable as grouped hexadecimal values."""

    return " ".join(f"{value:02X}" for value in values)


def format_block_snapshot(block: dict) -> str:
    """Format a block snapshot as grouped hexadecimal bytes."""

    return " ".join(block["byte_hex"])


def format_word_snapshot(snapshot: dict) -> str:
    """Format a 16-bit snapshot with both hex and grouped bits."""

    return f"{snapshot['hex']} ({snapshot['bits']})"


def format_state_rows(snapshot: dict) -> list[list[str]]:
    """Return human-readable state rows such as [['4', 'A'], ['F', '5']]."""

    return [[snapshot["state_hex_rows"][row][col] for col in range(2)] for row in range(2)]


def build_html_table(headers: list[str], rows: list[list[object]]) -> str:
    """Build a lightweight HTML table for Streamlit markdown rendering."""

    header_cells = "".join(f"<th>{escape_html(header)}</th>" for header in headers)
    body_rows = []
    for row in rows:
        cells = "".join(f"<td>{escape_html(cell)}</td>" for cell in row)
        body_rows.append(f"<tr>{cells}</tr>")
    return (
        "<div class='saes-table-wrap'>"
        "<table class='saes-table'>"
        f"<thead><tr>{header_cells}</tr></thead>"
        f"<tbody>{''.join(body_rows)}</tbody>"
        "</table>"
        "</div>"
    )
