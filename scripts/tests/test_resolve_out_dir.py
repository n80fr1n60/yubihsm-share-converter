"""Unit tests for H-3-3: drive_manager._resolve_out_dir().

The helper hard-fails (sys.exit) if OUT_DIR is unset, instead of silently
defaulting to /tmp. Test both branches: the unset path raises SystemExit
(with exit code 1 — Python's default for ``sys.exit("string")``) and the
set path returns the literal env-var value verbatim.
"""
import os
import sys
import unittest

# Make ``scripts/`` importable when this file is run via
# ``python -m unittest scripts.tests.test_resolve_out_dir`` from the repo
# root. Mirror the loading pattern used by the other tests in this dir.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))

import drive_manager  # noqa: E402


class ResolveOutDirTests(unittest.TestCase):
    def setUp(self):
        # Snapshot OUT_DIR so each test can mutate it freely without
        # leaking state between cases.
        self._saved = os.environ.pop("OUT_DIR", None)

    def tearDown(self):
        os.environ.pop("OUT_DIR", None)
        if self._saved is not None:
            os.environ["OUT_DIR"] = self._saved

    def test_unset_raises_systemexit_with_banner(self):
        # OUT_DIR removed in setUp.
        with self.assertRaises(SystemExit) as cm:
            drive_manager._resolve_out_dir()
        # sys.exit("string") sets .code to the string; Python turns this
        # into exit-status 1 at process teardown — see drive_manager.py
        # docstring (v2 sec M2).
        self.assertIsInstance(cm.exception.code, str)
        self.assertIn("OUT_DIR is unset", cm.exception.code)
        self.assertIn("stale", cm.exception.code.lower())

    def test_empty_string_treated_as_unset(self):
        # Posix shells `export OUT_DIR=""` is functionally identical to
        # unset for our purposes — we want a real path, not the empty
        # string. The helper uses `if not d:` which catches both.
        os.environ["OUT_DIR"] = ""
        with self.assertRaises(SystemExit) as cm:
            drive_manager._resolve_out_dir()
        self.assertIn("OUT_DIR is unset", cm.exception.code)

    def test_set_returns_value_verbatim(self):
        os.environ["OUT_DIR"] = "/dev/shm/keymat-12345"
        self.assertEqual(
            drive_manager._resolve_out_dir(),
            "/dev/shm/keymat-12345",
        )

    def test_whitespace_only_is_truthy(self):
        # ``OUT_DIR=" "`` (whitespace-only) is truthy in Python and accepted
        # by the helper. ``os.open`` later will fail loudly enough downstream
        # that we don't need a second guard here.
        os.environ["OUT_DIR"] = " "
        self.assertEqual(drive_manager._resolve_out_dir(), " ")

    def test_helper_exists_at_module_scope(self):
        # Sanity: the helper must be importable from drive_manager so a
        # future refactor (inlining the body, renaming, etc.) can't quietly
        # drop the protection without failing tests.
        self.assertTrue(hasattr(drive_manager, "_resolve_out_dir"))
        self.assertTrue(callable(drive_manager._resolve_out_dir))


if __name__ == "__main__":
    unittest.main()
