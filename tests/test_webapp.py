"""Tests for the educational SAES-XTS web app helpers and trace adapters."""

from __future__ import annotations

import importlib
import py_compile
import unittest
from pathlib import Path

from helpers.encoding_utils import describe_latin1_message, encode_latin1_text
from webapp.trace_adapter import (
    build_encryption_walkthrough,
    extract_block_detail,
    parse_uint16,
)
from webapp.wizard_flow import (
    BLOCK_SELECTION_SCREEN,
    BLOCK_XTS_OVERVIEW_SCREEN,
    CTS_OVERVIEW_SCREEN,
    FINAL_OVERVIEW_SCREEN,
    INPUT_SCREEN,
    NORMAL_SEQUENCE,
    TAIL_SEQUENCE,
    next_screen,
    previous_screen,
    progress,
)


DATA_KEY = 0x4AF5
TWEAK_KEY = 0xBEEF
DATA_UNIT = 0x0001


class EncodingHelperTests(unittest.TestCase):
    def test_encode_latin1_rejects_non_latin1_characters(self) -> None:
        with self.assertRaises(ValueError):
            encode_latin1_text("A🙂")

    def test_describe_latin1_message_groups_bytes_into_blocks_and_tail(self) -> None:
        description = describe_latin1_message("ABC")
        self.assertEqual(description["bytes"], b"ABC")
        self.assertEqual(len(description["blocks"]), 1)
        self.assertEqual(description["blocks"][0]["hex"], "4142")
        self.assertTrue(description["has_tail"])
        self.assertEqual(description["tail"]["hex"], "43")
        self.assertEqual(description["character_rows"][0]["block_label"], "P0 byte 0")
        self.assertEqual(description["character_rows"][2]["block_label"], "Tail byte 0")


class TraceAdapterTests(unittest.TestCase):
    def test_parse_uint16_accepts_supported_formats(self) -> None:
        self.assertEqual(parse_uint16("0x4AF5", "data key"), 0x4AF5)
        self.assertEqual(parse_uint16("4AF5", "data key"), 0x4AF5)
        self.assertEqual(parse_uint16("19189", "data key"), 19189)
        self.assertEqual(parse_uint16("0b0000000000001010", "data key"), 0x000A)

    def test_build_encryption_walkthrough_for_normal_message(self) -> None:
        walkthrough = build_encryption_walkthrough("ABABAB", DATA_KEY, TWEAK_KEY, DATA_UNIT)
        self.assertFalse(walkthrough["overview"]["used_ciphertext_stealing"])
        self.assertIsNone(walkthrough["cts"])
        self.assertEqual(len(walkthrough["overview"]["message_blocks"]), 3)
        self.assertEqual([option["id"] for option in walkthrough["block_options"]], ["regular:0", "regular:1", "regular:2"])
        self.assertEqual(walkthrough["block_selection"]["options"][0]["id"], "regular:0")
        self.assertEqual(walkthrough["tweak_generation"]["values"][0]["snapshot"]["hex"], "77E5")
        self.assertEqual(walkthrough["tweak_generation"]["alpha_constant"]["decimal"], 2)
        self.assertEqual(walkthrough["key_schedule"]["round_keys"][0]["snapshot"]["hex"], "4AF5")
        self.assertEqual(walkthrough["key_schedule"]["words"][5]["snapshot"]["hex"], "AF")

    def test_build_encryption_walkthrough_for_tail_message_exposes_cts(self) -> None:
        walkthrough = build_encryption_walkthrough("ABABABX", DATA_KEY, TWEAK_KEY, DATA_UNIT)
        self.assertTrue(walkthrough["overview"]["used_ciphertext_stealing"])
        self.assertIsNotNone(walkthrough["cts"])
        self.assertIn("cts-provisional:2", [option["id"] for option in walkthrough["block_options"]])
        self.assertIn("cts-composite:2", [option["id"] for option in walkthrough["block_options"]])
        self.assertTrue(walkthrough["cts"]["length_preserved"])
        self.assertEqual(walkthrough["block_selection"]["options"][-1]["id"], "tail-case")
        self.assertEqual(
            [entry["snapshot"]["hex"] for entry in walkthrough["tweak_generation"]["values"]],
            ["77E5", "EFCA", "DFB9", "BF5F"],
        )

    def test_three_byte_message_still_exposes_cts_block_details(self) -> None:
        walkthrough = build_encryption_walkthrough("ABX", DATA_KEY, TWEAK_KEY, DATA_UNIT)
        self.assertEqual(walkthrough["default_block_id"], "cts-provisional:0")
        self.assertEqual([option["id"] for option in walkthrough["block_options"]], ["cts-provisional:0", "cts-composite:0"])
        self.assertEqual(walkthrough["block_selection"]["default_selection_id"], "tail-case")

    def test_extract_block_detail_returns_selected_regular_block(self) -> None:
        walkthrough = build_encryption_walkthrough("ABABAB", DATA_KEY, TWEAK_KEY, DATA_UNIT)
        detail = extract_block_detail(walkthrough, "regular:1")
        self.assertEqual(detail["kind"], "regular")
        self.assertEqual(detail["block_index"], 1)
        self.assertEqual(detail["ciphertext_block"]["length"], 2)
        self.assertEqual(detail["saes"]["operations"][0]["name"], "AddRoundKey K0")
        self.assertEqual(detail["wizard"]["round1"]["round_key"]["hex"], "DD28")
        self.assertEqual(detail["wizard"]["round2"]["round_key"]["hex"], "87AF")
        self.assertEqual(len(detail["wizard"]["round1"]["subnib"]["mappings"][0]["row_bits"]), 2)
        self.assertEqual(len(detail["wizard"]["round1"]["subnib"]["mappings"][0]["column_bits"]), 2)

    def test_extract_block_detail_returns_selected_cts_composite_block(self) -> None:
        walkthrough = build_encryption_walkthrough("ABABABX", DATA_KEY, TWEAK_KEY, DATA_UNIT)
        detail = extract_block_detail(walkthrough, "cts-composite:2")
        self.assertEqual(detail["kind"], "cts_composite")
        self.assertEqual(detail["plaintext_block"]["length"], 2)
        self.assertEqual(detail["ciphertext_block"]["length"], 2)


class WizardFlowTests(unittest.TestCase):
    def test_normal_flow_branch_moves_from_selection_to_block_walkthrough(self) -> None:
        self.assertEqual(next_screen(BLOCK_SELECTION_SCREEN, "regular:1"), BLOCK_XTS_OVERVIEW_SCREEN)
        self.assertEqual(previous_screen(FINAL_OVERVIEW_SCREEN, "regular:1"), NORMAL_SEQUENCE[-2])
        self.assertEqual(progress(BLOCK_XTS_OVERVIEW_SCREEN, "regular:1"), (5, len(NORMAL_SEQUENCE)))

    def test_tail_flow_branch_moves_from_selection_to_cts_walkthrough(self) -> None:
        self.assertEqual(next_screen(BLOCK_SELECTION_SCREEN, "tail-case"), CTS_OVERVIEW_SCREEN)
        self.assertEqual(previous_screen(FINAL_OVERVIEW_SCREEN, "tail-case"), TAIL_SEQUENCE[-2])
        self.assertEqual(progress(CTS_OVERVIEW_SCREEN, "tail-case"), (5, len(TAIL_SEQUENCE)))

    def test_common_flow_without_selection_stays_in_common_prefix(self) -> None:
        self.assertEqual(progress(INPUT_SCREEN, None), (1, 4))
        self.assertEqual(next_screen(INPUT_SCREEN, None), NORMAL_SEQUENCE[1])


class WebAppSourceTests(unittest.TestCase):
    def test_webapp_sources_compile(self) -> None:
        for path in (
            Path("webapp/app.py"),
            Path("webapp/components.py"),
            Path("webapp/state_formatters.py"),
            Path("webapp/streamlit_compat.py"),
            Path("webapp/trace_adapter.py"),
            Path("webapp/wizard_flow.py"),
            Path("webapp/views/input_view.py"),
            Path("webapp/views/partition_view.py"),
            Path("webapp/views/tweak_view.py"),
            Path("webapp/views/overview_view.py"),
            Path("webapp/views/block_detail_view.py"),
            Path("webapp/views/cts_view.py"),
            Path("webapp/views/output_view.py"),
        ):
            py_compile.compile(str(path), doraise=True)

    def test_app_module_imports_without_streamlit_installed(self) -> None:
        module = importlib.import_module("webapp.app")
        self.assertTrue(hasattr(module, "main"))

    def test_app_source_bootstraps_project_root_for_script_execution(self) -> None:
        app_source = Path("webapp/app.py").read_text(encoding="utf-8")
        self.assertIn("if __package__ in (None, \"\"):", app_source)
        self.assertIn("sys.path.insert(0, project_root_str)", app_source)

    def test_webapp_uses_mermaid_and_avoids_colored_status_widgets(self) -> None:
        components_source = Path("webapp/components.py").read_text(encoding="utf-8")
        self.assertIn("render_mermaid_diagram", components_source)
        self.assertIn("mermaid.esm.min.mjs", components_source)
        self.assertIn(".stButton > button *", components_source)
        self.assertIn(".saes-table th *", components_source)
        self.assertIn(".saes-card code,", components_source)
        self.assertIn("background: var(--saes-white) !important;", components_source)
        self.assertIn("display: block;", components_source)
        self.assertNotIn(".stApp div,", components_source)
        self.assertNotIn(".stApp span,", components_source)

        disallowed_calls = ("st.info(", "st.success(", "st.warning(", "st.error(", "st.progress(")
        for path in Path("webapp").rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            source = path.read_text(encoding="utf-8")
            for call in disallowed_calls:
                self.assertNotIn(call, source, msg=f"{path} still uses {call}")


if __name__ == "__main__":
    unittest.main()
