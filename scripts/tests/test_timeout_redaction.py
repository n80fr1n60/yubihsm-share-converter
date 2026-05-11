"""Unit tests for E-M1(c): timeout-handler share-shape redaction.

drive_manager.py's failure-path teardown prints repr(p.before) — pexpect's
internal PTY buffer — which can contain raw share bytes if the timeout
fires while yubihsm-manager is mid-echo on the "paste shares" prompt.
The H-S2 _RedactingStream scrubs the logfile_read tee, but p.before is
a separate buffer; without scrubbing, a timeout dumps unredacted shares
to stderr.

E-M1(c) adds:
  - _SHARE_RE_STR: str-mode counterpart of _SHARE_RE, derived from the
    bytes-mode pattern via .pattern.decode("ascii") to prevent drift.
  - _RedactingStream.scrub_str(): classmethod that mirrors the bytes-
    mode write() redaction on a str.
  - Timeout handler routes repr(p.before) through scrub_str().

These tests verify the parity of the two regexes and the scrub_str
contract.
"""
import importlib.util
import os
import unittest

# Load drive_manager.py without executing its CLI main(): the module-level
# code is guarded by ``if __name__ == "__main__"``, so importing under a
# different module name is side-effect-free.
_HERE = os.path.dirname(os.path.abspath(__file__))
_DRIVER_PATH = os.path.normpath(os.path.join(_HERE, "..", "drive_manager.py"))
_spec = importlib.util.spec_from_file_location(
    "drive_manager_under_test_em1c", _DRIVER_PATH
)
_dm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_dm)

_SHARE_RE = _dm._SHARE_RE
_SHARE_RE_STR = _dm._SHARE_RE_STR
_RedactingStream = _dm._RedactingStream

# Share-shaped token from the round-6 canary (AES-256 wrap key, 64 hex
# chars after the T-X- prefix). Exercises the manager-hex alternative of
# the regex (T-X-hex{32+}).
TOKEN_STR = "5-7-29363f040d0a1318616e777c45424b5059a6afb4bdba8388919ee7ecf5f2fbc0"
TOKEN_BYTES = TOKEN_STR.encode("ascii")


class ShareReStrParityTests(unittest.TestCase):
    """The bytes-mode and str-mode regexes must accept identical tokens
    and produce identical substitutions (modulo bytes/str return type).
    """

    def test_share_re_str_parity_with_share_re(self):
        # Both regexes must match a share-shaped token.
        self.assertIsNotNone(_SHARE_RE.search(TOKEN_BYTES))
        self.assertIsNotNone(_SHARE_RE_STR.search(TOKEN_STR))
        # Both substitute to the same shape on a prefixed input.
        self.assertEqual(
            _SHARE_RE.sub(b"<R>", b"prefix " + TOKEN_BYTES),
            b"prefix <R>",
        )
        self.assertEqual(
            _SHARE_RE_STR.sub("<R>", "prefix " + TOKEN_STR),
            "prefix <R>",
        )

    def test_share_re_str_derived_from_share_re_pattern(self):
        # Sanity-check the derivation contract: _SHARE_RE_STR.pattern must
        # equal _SHARE_RE.pattern.decode("ascii"). A future maintainer who
        # edits _SHARE_RE will automatically get the str-mode counterpart
        # updated at import time; this guards against accidental drift if
        # someone hand-edits _SHARE_RE_STR.
        self.assertEqual(
            _SHARE_RE_STR.pattern,
            _SHARE_RE.pattern.decode("ascii"),
        )


class ScrubStrTests(unittest.TestCase):
    """The _RedactingStream.scrub_str classmethod is the timeout handler's
    redaction entry-point. It must redact share-shaped tokens, leave non-
    share text alone, and work on repr()-wrapped input.
    """

    def test_scrub_str_smoke_redacts_inline_share(self):
        out = _RedactingStream.scrub_str(f"contains {TOKEN_STR} inline")
        self.assertIn("<REDACTED-SHARE>", out)
        self.assertNotIn(TOKEN_STR, out)

    def test_scrub_str_no_op_on_non_share_text(self):
        # Normal log line, no shares. Must pass through unchanged.
        line = "normal log line, no shares here"
        self.assertEqual(_RedactingStream.scrub_str(line), line)

    def test_pbefore_shape_simulation_repr_then_scrub(self):
        # Simulate the timeout handler's call path: p.before is a bytes
        # (or bytes-like) buffer; we repr() it then scrub_str() the
        # resulting Python str. The hex body of the share must NOT
        # survive; <REDACTED-SHARE> must appear.
        fake_pbefore = b"manager echo prefix " + TOKEN_BYTES + b" suffix bytes"
        scrubbed = _RedactingStream.scrub_str(repr(fake_pbefore))
        self.assertIn("<REDACTED-SHARE>", scrubbed)
        self.assertNotIn(TOKEN_STR, scrubbed)
        # Also assert the hex-only body (the suffix portion that uniquely
        # identifies the canary token) does not survive.
        self.assertNotIn(
            "29363f040d0a1318616e777c45424b5059a6afb4bdba8388919ee7ecf5f2fbc0",
            scrubbed,
        )

    def test_scrub_str_is_classmethod(self):
        # Sanity: callable as a classmethod, no instance required.
        self.assertTrue(callable(_RedactingStream.scrub_str))
        # And it returns a str when fed a str.
        self.assertIsInstance(_RedactingStream.scrub_str("hi"), str)


if __name__ == "__main__":
    unittest.main()
