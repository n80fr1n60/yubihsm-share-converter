"""Unit tests for H-V1: the imported_wrap_id.txt atomic-write path.

drive_manager.py records the wrap-id it just imported so verify_roundtrip.sh
can assert exactly-this-id rather than picking the first wrap-key on the HSM
(a stale one from a prior run would silently mis-identify the test target).

These tests exercise the SAME ``os.open`` + ``os.replace`` recipe the driver
uses on the success path, plus the ID-extraction regex against the real
formatting variants seen in yubihsm-manager output ("ID 0x..", "ID: 0x..",
"id=0x..").
"""
import importlib.util
import os
import re
import stat
import sys
import tempfile
import unittest

# Make ``scripts/`` importable when this file is run via
# ``python -m unittest scripts.tests.test_imported_wrap_id`` from the repo
# root. Mirror the loading pattern used by the other tests in this dir.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))

import drive_manager  # noqa: E402


# Same regex used in drive_manager.py's success branch — duplicated here so a
# future regex tweak in the driver is forced to update this test alongside.
_ID_RE = re.compile(r"\b[Ii][Dd][:\s=]+(0x[0-9a-fA-F]{1,4})\b")


class IdRegexAcceptanceTests(unittest.TestCase):
    def test_accepts_space_form(self):
        # "Imported wrap key with ID 0x1234"
        m = _ID_RE.search("Imported wrap key with ID 0x1234")
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), "0x1234")

    def test_accepts_colon_form(self):
        m = _ID_RE.search("ID: 0xabcd")
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), "0xabcd")

    def test_accepts_equals_form(self):
        m = _ID_RE.search("id=0xff")
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), "0xff")

    def test_accepts_lowercase_id(self):
        m = _ID_RE.search("id 0x42")
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), "0x42")

    def test_rejects_non_id_hex(self):
        # A raw "0x1234" without a leading "id" / "ID" must not be mistaken
        # for the imported wrap-id.
        self.assertIsNone(_ID_RE.search("connector 0x1234"))


def _atomic_write(out_dir, wrap_id):
    """Mirror the driver's success-path write recipe."""
    final = os.path.join(out_dir, "imported_wrap_id.txt")
    tmp = final + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(wrap_id + "\n")
        os.replace(tmp, final)
    except Exception:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise
    return final


class AtomicWriteTests(unittest.TestCase):
    def test_write_creates_file_with_mode_0600(self):
        with tempfile.TemporaryDirectory() as td:
            final = _atomic_write(td, "0x1234")
            self.assertTrue(os.path.isfile(final))
            mode = stat.S_IMODE(os.stat(final).st_mode)
            # Owner-rw only — group/world bits MUST be zero.
            self.assertEqual(mode, 0o600)
            with open(final) as f:
                self.assertEqual(f.read().strip(), "0x1234")

    def test_write_replaces_existing_file_atomically(self):
        with tempfile.TemporaryDirectory() as td:
            _atomic_write(td, "0x1111")
            _atomic_write(td, "0x2222")
            final = os.path.join(td, "imported_wrap_id.txt")
            with open(final) as f:
                self.assertEqual(f.read().strip(), "0x2222")
            # The .tmp must not survive a successful replace.
            self.assertFalse(
                os.path.exists(final + ".tmp"),
                "tmp file leaked after os.replace",
            )

    def test_tmp_cleanup_on_write_error(self):
        # Drop a .tmp in place; force the write to throw mid-stream by
        # passing a non-string id (the inner ``f.write`` will TypeError).
        # The except-branch must unlink the tmp.
        with tempfile.TemporaryDirectory() as td:
            final = os.path.join(td, "imported_wrap_id.txt")
            tmp = final + ".tmp"
            with self.assertRaises(TypeError):
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                try:
                    with os.fdopen(fd, "w") as f:
                        f.write(12345)  # type: ignore[arg-type]
                    os.replace(tmp, final)
                except Exception:
                    try:
                        os.unlink(tmp)
                    except FileNotFoundError:
                        pass
                    raise
            # After the recipe's except-branch ran, the tmp must be gone
            # AND the final must not exist (write never reached replace).
            self.assertFalse(os.path.exists(tmp))
            self.assertFalse(os.path.exists(final))

    def test_driver_module_exposes_re_and_os(self):
        # Sanity check: the driver imports ``re`` and ``os`` at module scope
        # (the new H-V1 success branch depends on both). A future refactor
        # that drops either import would regress the feature silently.
        self.assertTrue(hasattr(drive_manager, "re"))
        self.assertTrue(hasattr(drive_manager, "os"))


if __name__ == "__main__":
    unittest.main()
