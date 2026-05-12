# Device-transcript fixtures (R12-01 + R12-02)

This directory holds **synthetic/redacted** transcripts of the upstream
`yubihsm-shell` / `yubihsm-setup` / `yubihsm-manager` output formats that
shell-out parsers in `scripts/` consume. They are the load-bearing
input for `scripts/tests/test_transcript_parity.sh` (the anti-R10-L2
methodology gate).

## Synthetic-discipline policy

All transcripts in this directory MUST use synthetic IDs (canary
`0xa5a2`-style); NO verbatim real-device captures. Regeneration MUST
use synthetic-ID-stuffed inputs. **Any future PR that introduces a
real-device transcript is a security regression** — the gate exists
precisely so that the format-shape can be CI-checked against the
production parsers without committing real ceremony state.

The committed synthetic IDs are:

| ID        | Role                                            |
|-----------|-------------------------------------------------|
| `0x0001`  | Default factory auth-key (real upstream value)  |
| `0xa5a2`  | Synthetic wrap-key canary (matches converter)   |
| `0xc995`  | Synthetic application auth-key                  |
| `0x0042`  | Synthetic victim asymmetric key                 |
| `0xDEAD`  | R10-L2 foil: auth-key with `my-wrap-key-label`  |

The `0xDEAD` value is uppercase deliberately so the lowercase-hex
acceptance grep (`grep -rE '0x[0-9a-f]{4}'`) skips it — it serves as
the R10-L2 substring-label foil and would otherwise be flagged by the
"no unexpected hex ids" gate.

## Files

| File | Purpose | Parsers exercised |
|------|---------|-------------------|
| `yubihsm-shell-list-objects.txt`  | Real format of `yubihsm-shell -a list-objects` (R10-L2-hotfix shape: `id: 0xXXXX, type: T, algo: A, sequence: 0, label: L`). Includes the `my-wrap-key-label` foil to guard against the pre-hotfix substring-match regression. | `stage_legacy_setup.sh:173, :205-206, :208-209, :251`; `verify_roundtrip.sh:69-71` |
| `yubihsm-setup-ksp.txt`           | Real format of `yubihsm-setup ksp` raw log output with ANSI escapes + 3 synthetic 2-of-3 shares + a noise `00-00-` line. | `_extract_shares.sh:12-15` |
| `yubihsm-shell-put-wrapped-ok.txt`        | Successful put-wrapped stdout. | `verify_roundtrip.sh:96-104` (success path) |
| `yubihsm-shell-put-wrapped-authfail.txt`  | put-wrapped CCM auth-failure stderr (wrap-id mismatch). | `verify_roundtrip.sh:96-104` (FAILED banner path) |
| `yubihsm-shell-get-public-key.txt` | PEM-shaped get-public-key output. | `verify_roundtrip.sh:107`  (no parse — sha256 only) |
| `yubihsm-manager-tui-prompts.txt` | One line per yubihsm-manager TUI prompt the pexpect driver matches. | `drive_manager.py:361, :416, :429, :433, :438, :454, :459, :474` |

## Regeneration protocol

If upstream `yubihsm-shell` / `yubihsm-setup` / `yubihsm-manager` change
their output format:

1. Run the tool against a **synthetic-ID-stuffed** test device (use the
   canary IDs above; never commit a real-device capture).
2. Update the corresponding `*.txt` fixture in this directory.
3. Re-run `bash scripts/tests/test_transcript_parity.sh`.
4. If any parser fails its parity check, fix the parser (NOT the
   fixture) — the fixture is the source-of-truth for "real" output
   shape; a divergent parser is the R10-L2-class bug the gate exists
   to catch.

## Anti-R10-L2 contract

The methodology lock: **every parser site MUST be exercised against a
transcript fixture in this directory**. A new shell-out parser that
ships without a corresponding fixture + parity test block is a
regression in the methodology gate itself. See `FIX_PLAN.html`
anchors `#r12-01` and `#r12-02` for the locked policy.
