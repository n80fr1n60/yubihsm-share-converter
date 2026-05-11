"""Unit tests for E-M1(a): YHM_SHARES_FILE hard-fail.

drive_manager.py refuses to default the shares file to /tmp/converted.txt
(which a same-UID attacker could pre-plant with attacker-chosen shares).
The hard-fail fires inside main() before any HSM interaction; the exit
code is the next free numeric after the existing 0/1/2/3 docstring
table — i.e. 4 — so an operator wrapper script can $?-discriminate this
mistake pattern from the round-3 OUT_DIR-unset hard-fail (which uses 1).

These tests invoke the driver as a subprocess because the hard-fail
happens inside main(); importing drive_manager directly does not trigger
main() (it is guarded by ``if __name__ == "__main__"``), so we exercise
the actual command-line entry path.
"""
import os
import subprocess
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_DRIVER_PATH = os.path.normpath(os.path.join(_HERE, "..", "drive_manager.py"))


def _run_driver(env_overrides):
    """Invoke drive_manager.py with the given env, return CompletedProcess.

    We pipe stdin from /dev/null so the driver never blocks on input.
    A 10-second timeout protects the test runner from a wedged subprocess.
    """
    env = dict(os.environ)
    # Strip pre-existing values for the variables we want to control so
    # the parent shell's settings don't leak in. Re-add only what the
    # caller wants set.
    for key in ("YHM_SHARES_FILE", "OUT_DIR"):
        env.pop(key, None)
    for k, v in env_overrides.items():
        if v is None:
            env.pop(k, None)
        else:
            env[k] = v
    # The driver sleeps 2s before main() starts; use a longer timeout so
    # the YHM_SHARES_FILE check has time to fire.
    return subprocess.run(
        [sys.executable, _DRIVER_PATH],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        stdin=subprocess.DEVNULL,
    )


class YhmSharesFileUnsetTests(unittest.TestCase):
    def test_unset_hard_fails_with_exit_4(self):
        # YHM_SHARES_FILE unset → driver exits 4 with the explanatory
        # banner. OUT_DIR is set so the round-3 hard-fail doesn't fire
        # first (we want to isolate the E-M1(a) path).
        cp = _run_driver({
            "YHM_SHARES_FILE": None,
            "OUT_DIR": "/tmp/some-out-dir-for-test",
        })
        self.assertEqual(
            cp.returncode, 4,
            f"expected exit 4, got {cp.returncode}\nstderr={cp.stderr!r}",
        )
        self.assertIn("YHM_SHARES_FILE is unset", cp.stderr)
        # The error message quotes the path (so a grep over the source can
        # locate exactly one `"/tmp/converted.txt"` literal); accept both
        # quoted and unquoted forms in the assertion.
        self.assertIn("/tmp/converted.txt", cp.stderr)
        self.assertIn("Refusing to default", cp.stderr)

    def test_empty_string_hard_fails_with_exit_4(self):
        # Posix `export YHM_SHARES_FILE=""` is functionally identical to
        # unset for our purposes — the helper uses `if not shares_file:`
        # which catches both.
        cp = _run_driver({
            "YHM_SHARES_FILE": "",
            "OUT_DIR": "/tmp/some-out-dir-for-test",
        })
        self.assertEqual(
            cp.returncode, 4,
            f"expected exit 4, got {cp.returncode}\nstderr={cp.stderr!r}",
        )
        self.assertIn("YHM_SHARES_FILE is unset", cp.stderr)

    def test_set_proceeds_past_check(self):
        # YHM_SHARES_FILE=/some/path (non-empty value) → does NOT exit 4.
        # Downstream failure mode is acceptable (file may not exist,
        # yubihsm-manager may not be on PATH, etc); the only thing we
        # assert here is that the E-M1(a) hard-fail did NOT fire.
        cp = _run_driver({
            "YHM_SHARES_FILE": "/nonexistent/path/that/does/not/exist.txt",
            "OUT_DIR": "/tmp/some-out-dir-for-test",
            # Force yubihsm-manager off PATH so the driver exits via the
            # exit-3 path (not on PATH) rather than the exit-4 path.
            "PATH": "/nonexistent-bin-dir",
        })
        self.assertNotEqual(
            cp.returncode, 4,
            "E-M1(a) hard-fail fired when YHM_SHARES_FILE was set\n"
            f"stderr={cp.stderr!r}",
        )


if __name__ == "__main__":
    unittest.main()
