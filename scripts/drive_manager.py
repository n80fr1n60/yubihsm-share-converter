#!/usr/bin/env python3
# =====================================================================
# TEST HARNESS ONLY - NOT FOR PRODUCTION CEREMONIES.
# Real ceremonies must use yubihsm-manager manually.
# =====================================================================
"""Drive yubihsm-manager's interactive wrap-key import-from-shares flow.

Used during the converter's HSM-side end-to-end test: the manager's "Wrap key
→ Import → Re-create from shares" path is a cliclack TUI that needs a real
PTY, so plain stdin redirection won't work. This pexpect driver navigates the
menu, types the share count, pastes each share, accepts the metadata
confirmation, and waits for the "Imported wrap key with ID 0x…" success line.

Assumes `yubihsm-manager` is already on PATH (e.g. installed from the YubiHSM
SDK .deb/.rpm). Configurable via:

    YHM_PASSWORD      auth-key 0x0001 password (default: "password")
    YHM_SHARES_FILE   path to converted shares, one `T-X-hex` per line
                      (REQUIRED — E-M1(a): hard-fail if unset, see exit 4)
    OUT_DIR           where the imported_wrap_id.txt file is written
                      (REQUIRED — H-3-3: hard-fail if unset, see exit 1)

Exit codes (v2 sec M2 — `sys.exit("string")` returns Python's default 1):
    0  successful wrap-key import.
    1  fatal-string exit: OUT_DIR unset (H-3-3 _resolve_out_dir),
       version-pin mismatch, destructive-highlight refusal, atomic-write
       failure, version subprocess timeout/parse failure, share-id parse
       failure. Operator banner is printed to stderr.
    2  pexpect timeout / EOF mid-ceremony.
    3  yubihsm-manager not on PATH.
    4  YHM_SHARES_FILE unset (E-M1(a) hard-fail — refuses to default to
       /tmp/converted.txt so a same-UID attacker can't pre-plant
       attacker-chosen shares into the ceremony).
"""
import os
import re
import shutil
import subprocess
import sys
import time

import pexpect

# Matches a cliclack-rendered "highlighted" menu line: the highlight glyph
# (❯ / ► / ▶ / ●) followed by the option label. ● is what cliclack 0.3.x
# emits for the focused option in `select()` widgets; ❯ / ► / ▶ appear in
# older versions or some terminal configurations. Anchored to start-of-line
# under MULTILINE; the prefix character class allows whitespace AND the
# box-drawing chars cliclack uses for its widget border (│ ┃ ║), which sit
# in front of every menu line. A literal ASCII `>` is NOT in the alternation,
# so banner text containing `>` will not trigger the parser. ○ (unfilled
# bullet) is intentionally NOT in the alternation either — that glyph marks
# UNFOCUSED options and we'd misidentify the first non-highlighted row as
# highlighted otherwise.
HILITE = re.compile(r"^[\s│┃║]*(❯|►|▶|●)\s+(.*)$", re.MULTILINE)

# H-S1: cliclack widget top-border glyphs. Includes rounded (╭), heavy (┏),
# and double-line (╔) corners alongside the plain (┌) form so a future
# cliclack/box-drawing variant doesn't sneak past the slicer.
_FRAME_OPENER = re.compile(r"[┌╭┏╔]")

# H-S5: word-boundary-anchored deny-list of destructive menu actions.
# "Generate" is deliberately NOT in this set — the menu transit from "List"
# to "Import Wrap Key" passes through "Generate Wrap Key"; a deny on that
# keyword would refuse legitimate navigation.
DESTRUCTIVE = (
    "Delete", "Destroy", "Wipe", "Erase",
    "Reset", "Factory",
    "Remove", "Drop", "Clear", "Format",
)
_DESTRUCTIVE_RE = re.compile(
    r"\b(" + "|".join(DESTRUCTIVE) + r")\b",
    re.IGNORECASE,
)

# H-S3 / H-S4: pin yubihsm-manager to a known-good MAJOR.MINOR.PATCH base.
# The pexpect prompts below match cliclack label strings byte-for-byte; if
# upstream ever rewords them ("Enter share number" → "Share #N", etc.) every
# expect() call would silently TIMEOUT. Refuse to run against unknown bases
# so the operator re-validates the prompt regexes before proceeding rather
# than wedging mid-ceremony.
_KNOWN_GOOD_BASE = {(1, 0, 0), (1, 0, 1)}
# v2 (sec 4.1): anchor on `^yubihsm-manager` so a stack-trace banner or
# loader message containing a version-shaped substring (e.g. "glibc 2.38.0")
# can never poison the parse. Use MULTILINE in case the binary prefixes
# its version line with a banner.
_VER_RE = re.compile(
    r"^yubihsm-manager\s+\S*?(\d+)\.(\d+)\.(\d+)",
    re.MULTILINE,
)


def _is_destructive(label):
    """Return True iff ``label`` contains a deny-listed verb at a word boundary."""
    return _DESTRUCTIVE_RE.search(label) is not None


def _resolve_out_dir():
    """Return ``$OUT_DIR`` or fatal-exit if unset.

    H-3-3: refuse the prior `os.environ.get("OUT_DIR", "/tmp")` default. If
    the operator forgets to set OUT_DIR (or loses the export across a
    sub-shell), defaulting to /tmp causes drive_manager to write the
    imported_wrap_id.txt to /tmp while verify_roundtrip.sh (with its own
    explicit OUT_DIR) reads from /dev/shm/keymat-… → exit 6. Worse, a stale
    /tmp/imported_wrap_id.txt from a prior ceremony could be silently
    consumed by a later run. Hard-fail at the helper so all call sites
    inherit the protection uniformly.

    Note: ``OUT_DIR=" "`` (whitespace-only) is truthy and accepted here;
    ``os.open`` later will fail loudly enough downstream.
    """
    d = os.environ.get("OUT_DIR")
    if not d:
        sys.exit(
            "[driver] OUT_DIR is unset. Refusing to default to /tmp — a stale "
            "imported_wrap_id.txt from a prior ceremony could pollute this run. "
            "Set OUT_DIR (e.g. `export OUT_DIR=/dev/shm/keymat-$$`) and re-run."
        )
    return d


def _get_version():
    """Run ``yubihsm-manager --version``, parse the MAJOR.MINOR.PATCH base,
    and verify it sits in the known-good set. Returns the original (stripped)
    stdout string for caller logging.

    H-S3: ``timeout=10`` (v2 sec 3.1 — bumped from 5s for cold-cache CI
    tolerance) plus a ``TimeoutExpired`` handler so a hanging binary cannot
    wedge the driver indefinitely.
    H-S4: regex-extract the leading triple, ignoring pre-release/build
    metadata (``1.0.0-rc1``, ``1.0.0+abc``, ``1.0.0-3-gabcd`` all accepted
    if their base matches).
    """
    try:
        cp = subprocess.run(
            ["yubihsm-manager", "--version"],
            capture_output=True, text=True, check=True,
            timeout=10,  # v2 (sec 3.1): bump from 5s
        )
    except subprocess.TimeoutExpired:
        sys.exit("[driver] yubihsm-manager --version timed out after 10s; aborting.")
    out = cp.stdout.strip()
    m = _VER_RE.search(out)
    if not m:
        sys.exit(f"[driver] could not parse version from {out!r}")
    base = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    if base not in _KNOWN_GOOD_BASE:
        sys.exit(
            f"[driver] yubihsm-manager {out!r} (base {base}) not in "
            f"known-good {_KNOWN_GOOD_BASE}; re-validate prompt strings."
        )
    return out


# H-S2: scrub share-shaped tokens from PTY mirror output before forwarding.
# Match BOTH manager-hex (T-X-hex{32+}) and legacy-base64 (T-X-b64{70}) shapes
# so any future flow that tees converter output through this stream is also
# covered (defence-in-depth, v2 sec 2.1).
_SHARE_RE = re.compile(
    rb"\b\d{1,2}-\d{1,3}-(?:[a-fA-F0-9]{32,}|[A-Za-z0-9+/]{70})\b"
)

# E-M1(c): str-mode counterpart of _SHARE_RE for the timeout-path
# redaction. Derived from the existing bytes pattern via .decode("ascii")
# so a future maintainer can't introduce regex drift between the two modes.
_SHARE_RE_STR = re.compile(_SHARE_RE.pattern.decode("ascii"))


class _RedactingStream:
    """Tee-style sink that scrubs share-shaped tokens before forwarding.

    Intended for ``pexpect.spawn.logfile_read`` against the yubihsm-manager
    PTY ONLY. Do NOT redirect converter stderr through this stream — the
    converter has its own H3 mask logic with a different shape; conflating
    them would either bypass redaction or double-mask diagnostics
    (v2 sec 2.4).

    Writes are buffered up to the last line-terminator (``\\n`` or ``\\r``;
    PTYs commonly emit bare ``\\r`` for cursor-return, which would otherwise
    stall the buffer indefinitely — v2 sec 2.2). ``flush()``/``close()``
    scrub-and-emit the partial tail rather than silently discarding it
    (v2 architect H-5).
    """

    def __init__(self, sink):
        self._sink = sink
        self._tail = b""

    def _write_through(self, scrubbed_bytes):
        if hasattr(self._sink, "buffer"):
            self._sink.buffer.write(scrubbed_bytes)
        else:
            self._sink.write(scrubbed_bytes.decode("utf-8", "replace"))
        try:
            self._sink.flush()
        except Exception:
            pass

    def write(self, data):
        if isinstance(data, str):
            data = data.encode("utf-8", "replace")
        merged = self._tail + data
        # Split on either \r OR \n — PTYs emit bare \r for cursor-return.
        last_term = max(merged.rfind(b"\n"), merged.rfind(b"\r"))
        if last_term < 0:
            self._tail = merged
            return
        head, self._tail = merged[: last_term + 1], merged[last_term + 1 :]
        self._write_through(_SHARE_RE.sub(b"<redacted-share>", head))

    def flush(self):
        # v2 architect H-5: do NOT silently discard the tail. Emit it
        # scrubbed; if any share-shaped token survives in the partial line,
        # the regex still catches it. We deliberately do NOT append a
        # newline here — the next write() will continue the line if the
        # writer is still active.
        if self._tail:
            self._write_through(_SHARE_RE.sub(b"<redacted-share>", self._tail))
            self._tail = b""

    def close(self):
        self.flush()

    @classmethod
    def scrub_str(cls, s):
        """E-M1(c): scrub share-shaped tokens from a Python str.

        Mirrors the bytes-mode redaction in _RedactingStream.write but
        operates on str (used by the timeout handler's repr(p.before)
        output path). The str-mode regex _SHARE_RE_STR is derived from
        the bytes-mode _SHARE_RE via .pattern.decode("ascii") so the
        two patterns can never drift.
        """
        return _SHARE_RE_STR.sub("<REDACTED-SHARE>", s)


def _strip_ansi(b):
    """Strip CSI escape sequences from a raw PTY buffer."""
    return re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "", b)


def _latest_frame(plain):
    """Return the substring starting at the last frame-opener glyph, or
    the whole buffer if no opener is present (caller falls back).

    cliclack uses ANSI cursor-up plus line-rewrite to redraw, so an older
    highlight can sit at a HIGHER byte offset than the new one. Slicing to
    the latest frame-opener anchors us to the most recent repaint.
    """
    last = -1
    for m in _FRAME_OPENER.finditer(plain):
        last = m.start()
    if last >= 0:
        return plain[last:]
    # Form-feed (clear-screen) as fallback.
    ff = plain.rfind("\x0c")
    return plain[ff:] if ff >= 0 else plain


def highlighted_line(buf):
    """Return the currently-highlighted menu label from a raw PTY buffer.

    Strips ANSI escape sequences first so colour/cursor codes wrapping the
    highlight glyph don't defeat the regex, then slices to the LATEST
    frame-opener so a stale ●-line accumulated at a higher byte offset from
    a previous repaint cannot be picked over the current frame's highlight.
    Returns ``None`` when no highlighted line is present in the latest frame.
    """
    plain = _strip_ansi(buf)
    matches = HILITE.findall(_latest_frame(plain))
    return matches[-1][1].strip() if matches else None


def has_destructive_highlight(buf):
    """Defence-in-depth: deny-list scan runs over the UNSLICED buffer
    (not the latest frame) so a stale frame-opener can never hide a
    destructive highlight from us. Returns the offending label, or None.
    """
    plain = _strip_ansi(buf)
    for _glyph, label in HILITE.findall(plain):
        clean = label.split(" (", 1)[0].strip()
        if _is_destructive(clean):
            return clean
    return None


def main():
    PASSWORD = os.environ.get("YHM_PASSWORD", "password")

    # E-M1(a): mirror the round-3 OUT_DIR hard-fail. /tmp is shared with every
    # same-uid process; a stale or attacker-planted /tmp/converted.txt would
    # silently feed attacker-chosen wrap-key shares into the manager. Refuse
    # the default; exit 4 distinguishes this from OUT_DIR-unset (exit 1) so an
    # operator wrapper script can $?-discriminate the two mistake patterns.
    shares_file = os.environ.get("YHM_SHARES_FILE")
    if not shares_file:
        print(
            '[driver] YHM_SHARES_FILE is unset. Refusing to default to '
            '"/tmp/converted.txt" — a same-UID attacker can pre-plant the '
            'file with attacker-chosen shares. Set YHM_SHARES_FILE explicitly '
            'and re-run.',
            file=sys.stderr,
        )
        sys.exit(4)
    SHARES_FILE = shares_file

    # E-M1(b): resolve OUT_DIR exactly once at the top of main() and cache for
    # downstream call sites so the hard-fail can't fire post-HSM-mutation if
    # something mutates os.environ between phases. Single source of truth for
    # OUT_DIR within this invocation.
    OUT_DIR = _resolve_out_dir()

    bin_path = shutil.which("yubihsm-manager")
    if bin_path is None:
        print(
            "[driver] error: yubihsm-manager not found on PATH.\n"
            "        Install it from the YubiHSM SDK (e.g. `sudo dpkg -i "
            "yubihsm-manager_*.deb`) and re-run.",
            file=sys.stderr,
        )
        sys.exit(3)

    # H-S3/H-S4: pin manager version via the _get_version() helper (timeout +
    # tolerant MAJOR.MINOR.PATCH parse).
    _get_version()

    with open(SHARES_FILE) as f:
        shares = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    print(f"[driver] loaded {len(shares)} converted shares from {SHARES_FILE}",
          file=sys.stderr)

    p = pexpect.spawn(
        bin_path,
        args=["-p", PASSWORD, "wrap"],
        encoding="utf-8",
        timeout=15,
        dimensions=(40, 200),
    )
    # H-S2: tee the PTY mirror through a share-redacting filter so a
    # captured-stderr scenario (2>log, journald, CI buffer) does not leak
    # the typed-back share lines.
    p.logfile_read = _RedactingStream(sys.stderr)

    def step(data, label, secs=0.4):
        print(f"\n[driver] >>> {label}: {data!r}", file=sys.stderr, flush=True)
        p.send(data)
        time.sleep(secs)

    try:
        # H7: anchor on the description tail of the first WrapCommand
        # (`WrapCommand::List`'s description in hsm_operations/wrap.rs is
        # "List all wrap keys stored on the YubiHSM"). The wrap menu's
        # cliclack select uses an EMPTY prompt header (see manager
        # src/cli/cmdline.rs:181 `cliclack::select("")`), so there is no
        # "? <header>" line to anchor on. The full description tail is
        # rendered atomically inside one ANSI dim region, so a single-region
        # regex avoids the bare-substring "List" race (v2 review N#11) AND
        # the ANSI-interleave problem we hit when trying to bridge multiple
        # regions. Unique within the entire manager UI.
        #
        # R12-02 parity gate: every p.expect()/p.expect_exact() regex in
        # this block (and the rest of main()) is exercised against
        # tests/fixtures/device-transcripts/yubihsm-manager-tui-prompts.txt
        # via scripts/tests/test_transcript_parity.sh "Parser 8" block.
        p.expect(r"all wrap keys stored on the YubiHSM", timeout=10)
        time.sleep(0.6)
        # Label-driven menu navigation (C1): never trust the WrapCommand enum
        # ordering. Read each redrawn frame, check which line is highlighted
        # by taking the *latest* match in the accumulating buffer (cliclack
        # may redraw incrementally; a reset would lose the new state before
        # we read it). Refuse to press Enter if the highlight is on a
        # destructive item. The label may include the command's description
        # in parens — strip from the first " (" so "Import Wrap Key (Import
        # ...)" still equals "Import Wrap Key" for comparison.
        #
        # Seed `buf` from `before` + `after`: the H7 expect() above consumed
        # the menu's first-rendered ● highlight line, so we'd otherwise miss
        # it on the very first iteration here.
        # Deny-list (H-S5): word-boundary regex over a broadened set of
        # destructive verbs (Delete/Destroy/Wipe/Erase/Reset/Factory/Remove/
        # Drop/Clear/Format) defined module-side as DESTRUCTIVE. The path
        # from "List" (initial highlight) to "Import Wrap Key" passes through
        # "Get Object Properties" and "Generate Wrap Key" (transit items, not
        # destructive — "Generate" is deliberately not deny-listed).
        EXPECTED = "Import Wrap Key"
        buf = (p.before or "") + (p.after or "")
        last_seen = None
        for _attempt in range(20):
            try:
                chunk = p.read_nonblocking(size=4096, timeout=0.3)
            except pexpect.TIMEOUT:
                chunk = ""
            buf += chunk or ""
            # H-S1 sec 1.3: deny-scan runs FIRST, on the UNSLICED buffer, so
            # a stale frame-opener between the real top-border and a
            # destructive highlight cannot hide it from us.
            bad = has_destructive_highlight(buf)
            if bad:
                sys.exit(f"[driver] refusing destructive item: {bad!r}")
            cur = highlighted_line(buf)
            cur_label = cur.split(" (", 1)[0].strip() if cur else None
            if cur_label == EXPECTED:
                break
            if cur_label and cur_label != last_seen:
                step("\x1b[B", "Down")
                last_seen = cur_label
                # H-S1 architect H-4: drop pre-keypress accumulation so the
                # next read starts fresh from the post-Down repaint.
                buf = ""
        else:
            sys.exit(f"[driver] could not locate {EXPECTED!r} after 20 reads "
                     f"(last seen: {last_seen!r})")
        step("\r", f"select {EXPECTED}")

        # "Re-create from shares?" is a unique full-question phrasing (the
        # only "?" in the manager TUI containing those exact words), so the
        # H7 v2 review explicitly allowed keeping expect_exact here. Same
        # reasoning for the success-line "Imported wrap key with ID" below
        # (it's a status print, not a cliclack prompt — no "?" prefix).
        p.expect_exact("Re-create from shares?", timeout=5)
        time.sleep(0.4)
        step("y", "y (Yes)")
        step("\r", "Enter")

        # H7: cliclack prompts have a glyph prefix (◇ / ◆ / ?) but the
        # raw PTY buffer has ANSI resets BETWEEN the glyph and the label
        # (e.g. `\x1b[32m◇\x1b[0m  Press any key…`), so a `[?◇◆]\s*` anchor
        # cannot bridge the two without also matching escape codes. The
        # unique LABEL text alone is sufficient against the v2 review's
        # original "List substring race" — these labels appear nowhere
        # else in the manager's output. We rely on the labels being long
        # enough to be unique on their own.
        p.expect(r"Press any key to recreate wrap key from shares", timeout=5)
        time.sleep(0.3)
        step("\r", "any-key")

        p.expect(r"Enter the number of shares to re-create the AES wrap key", timeout=5)
        time.sleep(0.3)
        step(f"{len(shares)}\r", f"share count {len(shares)}")

        for i, s in enumerate(shares, 1):
            p.expect(rf"Enter share number {i}", timeout=10)
            time.sleep(0.3)
            # H-S2: do NOT route share bytes through step() — that would
            # echo the share value to stderr via the diagnostic ``data!r``
            # log. Send directly and emit a length-only diagnostic; the
            # PTY mirror itself is filtered by _RedactingStream above.
            print(
                f"\n[driver] >>> typing share {i} ({len(s)} bytes)",
                file=sys.stderr,
                flush=True,
            )
            p.send(f"{s}\r")
            time.sleep(0.4)

        # After the last share the manager prints "{n} shares have been
        # registered" then prompts for an object label (we accept the default).
        p.expect(r"Enter object label", timeout=10)
        time.sleep(0.3)
        step("\r", "empty label, accept default")

        # Final metadata-confirmation table.
        p.expect(r"Import wrap key with", timeout=10)
        time.sleep(0.4)
        step("y", "y (confirm import)")
        step("\r", "Enter")

        # Success line — printed status, not a "? ..." cliclack prompt.
        # H-3-1: two-step expect. The earlier round-2 fix anchored on the
        # captured id directly, but cliclack also emits "ID: 0xNNNN" rows in
        # the metadata-confirmation table BEFORE the user types `y`, so a
        # single-step capture races against the table content. Anchor on the
        # post-confirm success-line lexeme first ("Imported wrap key with
        # ID"), THEN capture the id from the same line via a strictly-no-
        # newline whitespace bound. Two expects sidestep ANSI escapes the
        # cliclack rendering may inject between the literal "ID" and the
        # hex digits — see H7 prompt-prefix handling for the same trick.
        p.expect(r"[Ii]mported wrap key with [Ii][Dd][:\s=]*", timeout=15)
        # Past the table; capture the id on the SAME line as the anchor.
        # `[ \t]*` (NOT `\s*`) refuses to span a newline so a re-rendered
        # table downstream cannot supply a stale id even if cliclack
        # repaints.
        p.expect(r"[ \t]*(0x[0-9a-fA-F]{1,4})\b", timeout=2)
        time.sleep(0.5)
        # H-V1: persist the captured wrap-id atomically at mode 0600 so
        # verify_roundtrip.sh can assert exactly-this-id rather than picking
        # the first wrap-key it sees on the HSM (which would silently
        # mis-identify a stale key from a prior run as the test target).
        # v2 (sec 8.1 + architect H-6): tmp + os.replace, explicit 0o600.
        m = p.match
        if m:
            # E-M1(b): use the OUT_DIR resolved at the top of main(); no
            # second resolution here. Single source of truth for OUT_DIR
            # within this invocation guards against an os.environ mutation
            # (subprocess, signal handler, library) between phases that
            # would otherwise hard-fail post-HSM-mutation with a confusing
            # "OUT_DIR is unset" banner AFTER the wrap-key has been imported.
            final = os.path.join(OUT_DIR, "imported_wrap_id.txt")
            tmp = final + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                with os.fdopen(fd, "w") as f:
                    f.write(m.group(1) + "\n")
                os.replace(tmp, final)
            except Exception:
                try:
                    os.unlink(tmp)
                except FileNotFoundError:
                    pass
                raise
        print("\n[driver] === IMPORT SUCCEEDED ===", file=sys.stderr)
        p.sendcontrol("c")
        p.expect(pexpect.EOF, timeout=5)
        # H-S2: flush any partial tail held by the redacting tee so a
        # share-shaped fragment never survives past process exit.
        try:
            p.logfile_read.close()
        except Exception:
            pass
        sys.exit(0)
    except pexpect.TIMEOUT:
        # E-M1(c): p.before is pexpect's internal PTY buffer, separate from
        # logfile_read; a timeout while the manager is mid-echo on the "paste
        # shares" prompt would otherwise dump raw share bytes to stderr.
        # Route the repr() through _RedactingStream.scrub_str() so the same
        # share-shape redaction that protects the PTY mirror also covers the
        # failure path.
        sys.stderr.write(
            "[driver] timed out waiting for manager response\n"
            "[driver] tail of pexpect buffer (share material redacted):\n"
            f"  {_RedactingStream.scrub_str(repr(p.before))}\n"
        )
        # H-S2: same teardown on the failure path.
        try:
            p.logfile_read.close()
        except Exception:
            pass
        sys.exit(2)
    except pexpect.EOF as e:
        # E-M1(c): the EOF path mirrors TIMEOUT — p.before can still hold
        # share-shaped bytes from a manager that died mid-echo, so the same
        # scrub_str redaction applies here.
        print(f"\n[driver] FAILED: {type(e).__name__}: {e}", file=sys.stderr)
        sys.stderr.write(
            "[driver] tail of pexpect buffer (share material redacted):\n"
            f"  {_RedactingStream.scrub_str(repr(p.before))}\n"
        )
        # H-S2: same teardown on the failure path.
        try:
            p.logfile_read.close()
        except Exception:
            pass
        sys.exit(2)


if __name__ == "__main__":
    _TTY = sys.stderr.isatty()
    _RED = "\033[1;31m" if _TTY else ""
    _RESET = "\033[0m" if _TTY else ""
    print(f"{_RED}", file=sys.stderr, end="")
    print("=" * 72, file=sys.stderr)
    print("  TEST HARNESS ONLY - NOT FOR PRODUCTION CEREMONIES", file=sys.stderr)
    print("  Real ceremonies must use yubihsm-manager INTERACTIVELY (operator", file=sys.stderr)
    print("  reads shares from paper and types them by hand).", file=sys.stderr)
    print("", file=sys.stderr)
    print("  This script automates the manager TUI via pexpect for end-to-end", file=sys.stderr)
    print("  testing only. If you intended a real ceremony: press Ctrl-C now", file=sys.stderr)
    print("  and run yubihsm-manager directly.", file=sys.stderr)
    print("=" * 72, file=sys.stderr)
    print(f"{_RESET}", file=sys.stderr, end="")
    print("  starting in 2 seconds; Ctrl-C to abort...", file=sys.stderr)
    time.sleep(2)
    main()
