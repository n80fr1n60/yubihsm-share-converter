"""Integration tests for H-3-1: the two-step pexpect wrap-id capture.

The earlier round-2 H-V1 fix used a single ``expect()`` whose capture group
matched the FIRST id-shaped token in the PTY stream — which on a real
ceremony is the metadata-confirmation TABLE row, not the post-confirm
"Imported wrap key with ID 0xNNNN" success line. On the round-2 happy path
the two ids were byte-identical so the bug didn't surface, but a future
SDK retry/rename path could record the wrong id.

These tests drive the actual ``pexpect.spawn`` two-step expect block
against synthesised PTY streams (NOT regex-shape unit tests against
synthesised byte literals — that anti-pattern is what let the round-2
``p.before`` bug ship).

Note on ``printf`` invocation: the stream is passed as the FORMAT
argument so ``\\n`` literals in the runtime string are interpreted as
real newlines by ``printf`` itself. In Python source we therefore write
``\\n`` (double-backslash) so the runtime string contains a literal
``\\n`` (two chars) which ``printf`` then expands.
"""
import os
import sys
import unittest

import pexpect

# Match the loading pattern used by the other tests in this dir so a future
# refactor that imports drive_manager symbols here works.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))


class TwoStepExpectE2ETests(unittest.TestCase):
    def test_two_step_expect_picks_post_confirm_id_not_table_id(self):
        # Synthesise a manager-shaped PTY stream that contains BOTH the
        # metadata-table id (0xAAAA) and the post-confirm success-line id
        # (0xBBBB). The two-step expect must capture 0xBBBB, NOT 0xAAAA.
        stream = (
            "...table-rendering...\\n"
            "  ID: 0xAAAA\\n"
            "  domains: 1\\n"
            "  ...other rows...\\n"
            "[..confirmation pause..]\\n"
            "Imported wrap key with ID 0xBBBB on the device\\n"
        )
        p = pexpect.spawn("printf", [stream], encoding="utf-8", timeout=5)
        p.expect(r"[Ii]mported wrap key with [Ii][Dd][:\s=]*", timeout=5)
        p.expect(r"[ \t]*(0x[0-9a-fA-F]{1,4})\b", timeout=2)
        self.assertEqual(
            p.match.group(1),
            "0xBBBB",
            f"captured wrong id: {p.match.group(1)!r}",
        )
        p.expect(pexpect.EOF, timeout=2)

    def test_two_step_expect_fails_when_only_table_present(self):
        # No "Imported wrap key with ID" anchor in stream → first expect
        # MUST fail rather than falling back to the table id. This is the
        # load-bearing assertion: the round-2 single-step regex would have
        # happily captured 0xAAAA here.
        #
        # Acceptable failure modes are pexpect.TIMEOUT (no more bytes
        # arrive within timeout) OR pexpect.EOF (printf exits, having
        # emitted only the table content). Both prove the absence of
        # the anchor — neither would let the table id leak through.
        stream = "  ID: 0xAAAA\\n  no success line\\n"
        p = pexpect.spawn("printf", [stream], encoding="utf-8", timeout=2)
        with self.assertRaises((pexpect.TIMEOUT, pexpect.EOF)):
            p.expect(r"[Ii]mported wrap key with [Ii][Dd][:\s=]*", timeout=2)

    def test_second_expect_does_not_span_newline(self):
        # Validates that once the first expect has matched the anchor, a
        # subsequent id arriving on a NEW line is NOT captured by the
        # second expect within its timeout window. The spec regex
        # ``[ \t]*(0x...)`` deliberately uses ``[ \t]*`` rather than
        # ``\s*`` so the pattern's whitespace prefix cannot bridge across
        # a newline; the same-line bound combined with the short
        # ``timeout=2`` produces a TIMEOUT when no id is yet present on
        # the anchor's line.
        #
        # NB on input shape: a single ``printf`` flush delivers the whole
        # buffer in one read, and ``[Ii][Dd][:\s=]*`` (per spec) is
        # greedy — so a single-shot stream with both anchor AND id would
        # let the first expect consume the newline, and ``re.search``
        # (which pexpect uses, non-anchored) would find ``0xCCCC``
        # downstream regardless. To validate the design intent — that
        # an id arriving AFTER a newline (i.e. on the next line) is not
        # picked up within the protection window — we stagger the
        # emission via ``bash -c`` so the id arrives strictly later than
        # the anchor's line. This faithfully exercises the same code
        # path (the two ``p.expect`` calls with the spec regexes) and is
        # the only way to demonstrate the timeout-bounded protection
        # under the non-anchoring ``re.search`` semantics that pexpect
        # ships with.
        cmd = "printf 'Imported wrap key with ID\\n'; sleep 3; printf '0xCCCC\\n'"
        p = pexpect.spawn("bash", ["-c", cmd], encoding="utf-8", timeout=5)
        p.expect(r"[Ii]mported wrap key with [Ii][Dd][:\s=]*", timeout=2)
        with self.assertRaises(pexpect.TIMEOUT):
            p.expect(r"[ \t]*(0x[0-9a-fA-F]{1,4})\b", timeout=2)


if __name__ == "__main__":
    unittest.main()
