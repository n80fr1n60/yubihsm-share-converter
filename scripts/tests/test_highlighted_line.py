"""Unit tests for the C1 menu-highlight parser in drive_manager.py.

These cover only the pure-Python helper ``highlighted_line`` and the
``HILITE`` regex; the full pexpect-driven flow needs a real PTY plus an
installed ``yubihsm-manager`` binary and is exercised by the end-to-end HSM
roundtrip script, not here.
"""
import importlib.util
import os
import sys
import unittest

# Load drive_manager.py without executing its CLI ``main()``: the module-level
# code is now guarded by ``if __name__ == "__main__"``, so importing under a
# different module name is side-effect-free.
_HERE = os.path.dirname(os.path.abspath(__file__))
_DRIVER_PATH = os.path.normpath(os.path.join(_HERE, "..", "drive_manager.py"))
_spec = importlib.util.spec_from_file_location("drive_manager_under_test",
                                               _DRIVER_PATH)
_dm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_dm)

highlighted_line = _dm.highlighted_line
HILITE = _dm.HILITE
has_destructive_highlight = _dm.has_destructive_highlight
_is_destructive = _dm._is_destructive
DESTRUCTIVE = _dm.DESTRUCTIVE


class HighlightedLineTests(unittest.TestCase):
    def test_plain_highlight_extracts_label(self):
        # Bare ❯ glyph plus label, no ANSI dressing.
        buf = "  List\n  Get Key Properties\n❯ Import Wrap Key\n  Delete Wrap Key\n"
        self.assertEqual(highlighted_line(buf), "Import Wrap Key")

    def test_ansi_wrapped_highlight_extracts_label(self):
        # cliclack typically emits SGR colour codes around the glyph and label;
        # the ANSI strip in highlighted_line() must pull them off cleanly.
        buf = (
            "  List\r\n"
            "  Get Key Properties\r\n"
            "\x1b[36m❯\x1b[0m \x1b[1mImport Wrap Key\x1b[0m\r\n"
            "  Delete Wrap Key\r\n"
        )
        self.assertEqual(highlighted_line(buf), "Import Wrap Key")

    def test_literal_gt_does_not_match(self):
        # A bare ASCII '>' is NOT a highlight glyph; the regex must ignore it.
        # This guards against false positives when a label or banner contains
        # '>' (e.g. a usage line or prompt rendering).
        buf = "  List\n> Some banner line with a stray gt\n  Import Wrap Key\n"
        self.assertIsNone(highlighted_line(buf))

    def test_no_highlight_returns_none(self):
        # Frame with no highlight glyph at all (e.g. before the menu has been
        # rendered) must return None, not crash and not pick the first label.
        buf = "  List\n  Get Key Properties\n  Import Wrap Key\n"
        self.assertIsNone(highlighted_line(buf))

    def test_destructive_label_is_returned_so_deny_check_can_fire(self):
        # The parser itself must not redact destructive items — it just reports
        # the highlight; the deny-list check in main() is what bails out.
        buf = "  List\n  Get Key Properties\n❯ Delete Wrap Key\n"
        self.assertEqual(highlighted_line(buf), "Delete Wrap Key")

    def test_filled_circle_glyph_extracts_label(self):
        # cliclack 0.3.x renders the focused row with ● (and unfocused with ○).
        # Real-world output observed from yubihsm-manager 1.0.0:
        #   "│  ● List (List all wrap keys stored on the YubiHSM)\n"
        buf = "│  ● List (List all wrap keys stored on the YubiHSM)\n│  ○ Get Object Properties\n"
        self.assertEqual(highlighted_line(buf),
                         "List (List all wrap keys stored on the YubiHSM)")

    def test_unfilled_circle_glyph_does_not_match(self):
        # ○ marks UNFOCUSED options; matching it would misidentify the first
        # non-highlighted row as highlighted on every redraw. Must return None
        # when only ○ rows are visible.
        buf = "│  ○ Get Object Properties\n│  ○ Generate Wrap Key\n"
        self.assertIsNone(highlighted_line(buf))

    # ---- H-S1: stale-frame "last-match" race ---------------------------

    def test_stale_frame_with_old_highlight_at_higher_offset(self):
        # Bug shape: cliclack uses cursor-up + line-rewrite; raw PTY buffer
        # accumulates a fully OLD frame followed by a NEW repaint. In raw
        # bytes (cursor-up escapes stripped), the NEW frame's opener sits
        # at a HIGHER offset than the stale ● line from the previous frame.
        # The slicer must anchor on the LAST frame-opener so the parser
        # picks the new highlight — NOT the older one whose ● appears
        # earlier in file order under a previous border.
        stale_old_frame = (
            "┌ wrap menu\n"
            "│  ● List\n"  # the OLD highlight, at a LOWER byte offset
            "│  ○ Get Object Properties\n"
            "│  ○ Import Wrap Key\n"
        )
        new_frame = (
            "┌ wrap menu\n"
            "│  ○ List\n"
            "│  ● Get Object Properties\n"  # the NEW highlight
            "│  ○ Import Wrap Key\n"
        )
        buf = stale_old_frame + new_frame
        self.assertEqual(highlighted_line(buf), "Get Object Properties")

    def test_destructive_in_stale_frame_still_denied(self):
        # Sec 1.3: even if a future ┌ between the real top-border and the
        # destructive highlight would slice it out of the LATEST frame, the
        # UNSLICED deny-scan must still catch it.
        buf = (
            "┌ wrap menu\n"
            "│  ○ List\n"
            "│  ● Import Wrap Key\n"
            "┌ inner widget\n"
            "│  ● Delete Wrap Key\n"
        )
        self.assertEqual(has_destructive_highlight(buf), "Delete Wrap Key")

    def test_rounded_corner_opener(self):
        # H-S1 v2 sec 1.1: the frame-opener alternation must include rounded
        # (╭) corners alongside the plain (┌) form.
        buf = "╭ wrap menu\n│  ● Import Wrap Key\n"
        self.assertEqual(highlighted_line(buf), "Import Wrap Key")

    # ---- H-S5: broadened deny-list -------------------------------------

    def test_deny_catches_reset_destroy_wipe(self):
        for lbl in ["Reset Device", "Destroy Object", "Wipe Storage",
                    "Erase Wrap Key", "Factory Reset", "Delete Wrap Key"]:
            self.assertTrue(_is_destructive(lbl), lbl)

    def test_deny_passes_safe(self):
        for lbl in ["List", "Get Object Properties", "Generate Wrap Key",
                    "Import Wrap Key"]:
            self.assertFalse(_is_destructive(lbl), lbl)

    def test_deny_word_boundary_rejects_inner_match(self):
        # v2 (sec 5.1): substring "Drop"/"Clear"/"Format" must NOT match
        # WITHIN other words. The spec's literal test sample listed
        # "Drop privileges" / "Clear cache" alongside "Reformat output" with
        # assertFalse, but `\bDrop\b` and `\bClear\b` do match those phrases
        # at word boundaries — so to honour the test's stated INTENT (the
        # comment says "within other words") we use genuine mid-word
        # collisions for the negative half.
        for lbl in ["Eavesdropping", "Reformat output", "Cleared cache"]:
            self.assertFalse(_is_destructive(lbl), lbl)
        # And word-boundary still matches at start/end:
        for lbl in ["Drop session", "Clear scratch", "Format disk"]:
            self.assertTrue(_is_destructive(lbl), lbl)

    def test_generate_is_NOT_in_deny_list(self):
        # v2 (sec 5.2): load-bearing — a future contributor adding "Generate"
        # would silently break the List → Import Wrap Key menu transit.
        self.assertNotIn("Generate", DESTRUCTIVE)
        self.assertFalse(_is_destructive("Generate Wrap Key"))


if __name__ == "__main__":
    unittest.main()
