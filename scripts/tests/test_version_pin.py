"""Unit tests for H-S3 / H-S4: yubihsm-manager version-pin parser.

H-S3 covers the timeout + TimeoutExpired handling.
H-S4 covers the tolerant MAJOR.MINOR.PATCH base parser.

These are pure-Python unit tests: the regex is exercised directly, and
``subprocess.run`` is monkey-patched so the helper can be driven without a
real ``yubihsm-manager`` binary on PATH.
"""
import os
import subprocess
import sys
import unittest
from unittest import mock

# Make `scripts/` importable when this file is run via ``python -m unittest
# scripts.tests.test_version_pin`` from the repo root.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))

import drive_manager  # noqa: E402


def _fake_completed(stdout):
    """Build a minimal CompletedProcess stand-in with the given stdout."""
    return subprocess.CompletedProcess(
        args=["yubihsm-manager", "--version"],
        returncode=0,
        stdout=stdout,
        stderr="",
    )


class VersionParserAcceptanceTests(unittest.TestCase):
    """Direct regex tests for accepted strings — no subprocess plumbing."""

    def test_version_parser_accepts_release(self):
        m = drive_manager._VER_RE.search("yubihsm-manager 1.0.0")
        self.assertIsNotNone(m)
        self.assertEqual(
            (int(m.group(1)), int(m.group(2)), int(m.group(3))),
            (1, 0, 0),
        )
        self.assertIn((1, 0, 0), drive_manager._KNOWN_GOOD_BASE)

    def test_version_parser_accepts_rc(self):
        m = drive_manager._VER_RE.search("yubihsm-manager 1.0.0-rc1")
        self.assertIsNotNone(m)
        base = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
        self.assertEqual(base, (1, 0, 0))
        self.assertIn(base, drive_manager._KNOWN_GOOD_BASE)

    def test_version_parser_accepts_build_metadata(self):
        m = drive_manager._VER_RE.search("yubihsm-manager 1.0.0+abc")
        self.assertIsNotNone(m)
        base = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
        self.assertEqual(base, (1, 0, 0))
        self.assertIn(base, drive_manager._KNOWN_GOOD_BASE)

    def test_version_parser_accepts_git_described(self):
        m = drive_manager._VER_RE.search("yubihsm-manager 1.0.0-3-gabcd")
        self.assertIsNotNone(m)
        base = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
        self.assertEqual(base, (1, 0, 0))
        self.assertIn(base, drive_manager._KNOWN_GOOD_BASE)

    def test_version_parser_accepts_known_good_patch(self):
        m = drive_manager._VER_RE.search("yubihsm-manager 1.0.1")
        self.assertIsNotNone(m)
        base = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
        self.assertEqual(base, (1, 0, 1))
        self.assertIn(base, drive_manager._KNOWN_GOOD_BASE)


class VersionParserRejectionTests(unittest.TestCase):
    """Strings that must NOT pass the version pin."""

    def test_version_parser_rejects_unknown_major(self):
        m = drive_manager._VER_RE.search("yubihsm-manager 2.0.0")
        self.assertIsNotNone(m)
        base = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
        self.assertEqual(base, (2, 0, 0))
        self.assertNotIn(base, drive_manager._KNOWN_GOOD_BASE)

    def test_version_parser_rejects_unrelated_version_substring(self):
        # v2 (sec 4.1): a stack-trace banner or loader message that contains
        # a version-shaped substring but no leading "yubihsm-manager " prefix
        # must not poison the parse.
        self.assertIsNone(
            drive_manager._VER_RE.search("error: glibc 2.38.0 mismatch")
        )


class GetVersionDriverTests(unittest.TestCase):
    """Drive ``_get_version()`` end-to-end via a patched subprocess.run."""

    def test_get_version_returns_stdout_for_known_good(self):
        with mock.patch(
            "drive_manager.subprocess.run",
            return_value=_fake_completed("yubihsm-manager 1.0.0\n"),
        ):
            self.assertEqual(drive_manager._get_version(), "yubihsm-manager 1.0.0")

    def test_get_version_exits_on_unknown_base(self):
        with mock.patch(
            "drive_manager.subprocess.run",
            return_value=_fake_completed("yubihsm-manager 2.0.0\n"),
        ):
            with self.assertRaises(SystemExit) as cm:
                drive_manager._get_version()
            self.assertIn("not in known-good", str(cm.exception))

    def test_get_version_exits_on_unparseable_output(self):
        with mock.patch(
            "drive_manager.subprocess.run",
            return_value=_fake_completed("complete garbage\n"),
        ):
            with self.assertRaises(SystemExit) as cm:
                drive_manager._get_version()
            self.assertIn("could not parse version", str(cm.exception))

    def test_version_timeout_exits(self):
        # H-S3: hanging binary must abort with a clear "timed out" message,
        # not block the driver indefinitely.
        def _raise_timeout(*args, **kwargs):
            raise subprocess.TimeoutExpired(cmd=args[0], timeout=10)

        with mock.patch("drive_manager.subprocess.run", side_effect=_raise_timeout):
            with self.assertRaises(SystemExit) as cm:
                drive_manager._get_version()
            self.assertIn("timed out", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
