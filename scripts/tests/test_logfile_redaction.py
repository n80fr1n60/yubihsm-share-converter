"""Unit tests for H-S2: the _RedactingStream PTY-mirror tee.

Covers share-shaped-token redaction across whole-line writes, partial-write
splits, bare-\\r cursor-return termination (PTY quirk), and flush()/close()
emission of any held tail (v2 architect H-5).
"""
import importlib.util
import io
import os
import unittest

# Load drive_manager.py without executing its CLI ``main()``: the module-level
# code is guarded by ``if __name__ == "__main__"``, so importing under a
# different module name is side-effect-free.
_HERE = os.path.dirname(os.path.abspath(__file__))
_DRIVER_PATH = os.path.normpath(os.path.join(_HERE, "..", "drive_manager.py"))
_spec = importlib.util.spec_from_file_location(
    "drive_manager_under_test_hs2", _DRIVER_PATH
)
_dm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_dm)

_RedactingStream = _dm._RedactingStream
_SHARE_RE = _dm._SHARE_RE


class _BytesSink:
    """Minimal stand-in for sys.stderr that exposes a ``buffer`` byte sink.

    The real ``_RedactingStream`` prefers ``sink.buffer`` (binary path) and
    falls back to text. Mirroring sys.stderr's structure here lets us assert
    on raw bytes without UTF-8 decoding noise.
    """

    def __init__(self):
        self.buffer = io.BytesIO()

    def flush(self):
        pass


class RedactingStreamTests(unittest.TestCase):
    # 32-hex-char share suffix (manager-hex form: T-X-hex{32+}).
    SHARE_HEX = "3-2-aabbccddeeff00112233445566778899aabbccddeeff0011"

    def test_share_lines_redacted_in_stderr_mirror(self):
        sink = _BytesSink()
        rs = _RedactingStream(sink)
        rs.write(f"ok\n{self.SHARE_HEX}\nnext\n")
        out = sink.buffer.getvalue()
        self.assertIn(b"<redacted-share>", out)
        # The hex body must NOT appear anywhere in the mirrored bytes.
        self.assertNotIn(b"aabbccddeeff00112233445566778899", out)
        self.assertIn(b"ok", out)
        self.assertIn(b"next", out)

    def test_partial_write_with_share_split_across_chunks(self):
        sink = _BytesSink()
        rs = _RedactingStream(sink)
        # Split the share roughly in half across two write() calls.
        full = self.SHARE_HEX + "\n"
        cut = len(self.SHARE_HEX) // 2
        rs.write(full[:cut])
        rs.write(full[cut:])
        out = sink.buffer.getvalue()
        # The hex body must not survive the split.
        self.assertNotIn(b"aabbccddeeff00112233445566778899", out)
        self.assertIn(b"<redacted-share>", out)

    def test_carriage_return_terminator_does_not_stall(self):
        sink = _BytesSink()
        rs = _RedactingStream(sink)
        # PTYs commonly emit bare \r for cursor-return; the stream must
        # treat that as a flushable terminator, not stall in _tail.
        rs.write("hello world\r")
        out = sink.buffer.getvalue()
        self.assertIn(b"hello world", out)
        self.assertEqual(rs._tail, b"")

    def test_flush_emits_scrubbed_tail(self):
        sink = _BytesSink()
        rs = _RedactingStream(sink)
        # Write the share with NO trailing newline — it sits in _tail.
        rs.write(self.SHARE_HEX)
        # Pre-flush: nothing emitted yet, share is buffered.
        self.assertEqual(sink.buffer.getvalue(), b"")
        self.assertNotEqual(rs._tail, b"")
        rs.flush()
        out = sink.buffer.getvalue()
        self.assertIn(b"<redacted-share>", out)
        self.assertNotIn(b"aabbccddeeff00112233445566778899", out)
        self.assertEqual(rs._tail, b"")

    def test_close_calls_flush(self):
        sink = _BytesSink()
        rs = _RedactingStream(sink)
        rs.write(self.SHARE_HEX)
        self.assertEqual(sink.buffer.getvalue(), b"")
        rs.close()
        out = sink.buffer.getvalue()
        self.assertIn(b"<redacted-share>", out)
        self.assertNotIn(b"aabbccddeeff00112233445566778899", out)
        self.assertEqual(rs._tail, b"")

    def test_legacy_base64_share_also_redacted(self):
        sink = _BytesSink()
        rs = _RedactingStream(sink)
        # Legacy-base64 form: T-X-b64{70}. Use 70 valid base64 chars
        # containing NO hex-only digits-or-letters runs (the regex tries
        # the hex alternative first but caps at "32+ hex"; a 70-char
        # base64 with mixed case + symbols won't satisfy the hex shape).
        b64_70 = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/AbCdEfGhIjKlMnOpQrStUvWxYz012345"
        self.assertEqual(len(b64_70), 70)
        line = f"2-1-{b64_70}\n"
        rs.write(line)
        out = sink.buffer.getvalue()
        self.assertIn(b"<redacted-share>", out)
        self.assertNotIn(b64_70.encode(), out)


if __name__ == "__main__":
    unittest.main()
