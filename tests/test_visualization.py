"""Tests for trace adapters and visualization source files."""

from __future__ import annotations

import importlib.util
import py_compile
import unittest
from pathlib import Path

from algorithm.saes import encrypt_block_with_trace
from algorithm.xts import encrypt_message_with_trace
from visualization.trace_adapter import adapt_saes_trace, adapt_xts_trace, build_master_walkthrough_data


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class TraceAdapterTests(unittest.TestCase):
    def test_adapt_saes_trace_has_expected_structure(self) -> None:
        adapted = adapt_saes_trace(encrypt_block_with_trace(0xD728, 0x4AF5))
        self.assertEqual(adapted["mode"], "encrypt")
        self.assertEqual(len(adapted["steps"]), 10)
        self.assertEqual(adapted["steps"][0]["label"], "Plaintext")
        self.assertEqual(adapted["steps"][-1]["value"], "0010 0100 1110 1100")

    def test_adapt_xts_trace_covers_cts_fields(self) -> None:
        _, trace = encrypt_message_with_trace(b"ABCDE", 0x4AF5, 0xBEEF, 0x0001)
        adapted = adapt_xts_trace(trace)
        self.assertTrue(adapted["used_ciphertext_stealing"])
        self.assertEqual(adapted["initial_tweak_bits"], "0111 0111 1110 0101")
        self.assertEqual(len(adapted["blocks"]), 1)
        self.assertEqual(adapted["blocks"][0]["output_block_bits"], "01111001 11000011")
        self.assertIsNotNone(adapted["cts"])
        self.assertEqual(adapted["cts"]["stolen_fragment_bits"], "10011101")

    def test_master_walkthrough_data_supports_normal_and_cts_inputs(self) -> None:
        normal = build_master_walkthrough_data(message=b"ABABAB")
        self.assertIsNone(normal["cts"])
        self.assertEqual(len(normal["message_blocks"]), 3)

        cts = build_master_walkthrough_data(message=b"ABABABX")
        self.assertIsNotNone(cts["cts"])
        self.assertEqual(cts["selected_encrypt_block"]["plaintext_block"]["hex"], "4142")
        self.assertEqual(cts["cts"]["stolen_fragment"]["hex"], "5D")
        self.assertEqual(cts["tweak_sequence"][0]["snapshot"]["hex"], "77E5")


class VisualizationSourceTests(unittest.TestCase):
    def test_visualization_sources_compile(self) -> None:
        paths = [
            PROJECT_ROOT / "visualization" / "trace_adapter.py",
            PROJECT_ROOT / "visualization" / "render_helpers.py",
            PROJECT_ROOT / "visualization" / "scenes" / "master_walkthrough_scene.py",
            PROJECT_ROOT / "visualization" / "scenes" / "saes_round_scene.py",
            PROJECT_ROOT / "visualization" / "scenes" / "xts_block_scene.py",
            PROJECT_ROOT / "visualization" / "scenes" / "xts_multiblock_scene.py",
            PROJECT_ROOT / "visualization" / "scenes" / "xts_decryption_scene.py",
        ]
        for path in paths:
            py_compile.compile(str(path), doraise=True)

    @unittest.skipUnless(importlib.util.find_spec("manim"), "manim is not installed in this environment")
    def test_scene_modules_import_when_manim_is_available(self) -> None:
        __import__("visualization.scenes.master_walkthrough_scene")
        __import__("visualization.scenes.saes_round_scene")
        __import__("visualization.scenes.xts_block_scene")
        __import__("visualization.scenes.xts_multiblock_scene")
        __import__("visualization.scenes.xts_decryption_scene")


if __name__ == "__main__":
    unittest.main()
