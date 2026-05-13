# Device-transcript fixtures (R12-01 + R12-02 + R13-05 / Phase E)

This directory holds **synthetic/redacted** transcripts of the upstream
`yubihsm-shell` / `yubihsm-setup` / `yubihsm-manager` output formats that
shell-out parsers in `scripts/` consume. They are the load-bearing
input for `scripts/tests/test_transcript_parity.sh` (the anti-R10-L2
methodology gate).

Per R13-05 (Phase E) the fixture tree is **per-SDK-version**: each
`v_X.Y.Z/` subdirectory captures the upstream output shape for one
target SDK release, and the parity gate iterates over every subdir.

## Per-version layout

```
tests/fixtures/device-transcripts/
├── README.md                       (this file; documents the per-version policy)
├── v_2.7.1/                        (prior-version synthetic: pre-hotfix shape)
│   └── {6 .txt fixtures}
├── v_2.7.3/                        (R12-B baseline; post-R10-L2-hotfix shape)
│   └── {6 .txt fixtures}
└── v_2.7.4/                        (future-version synthetic: trailing-fields extension)
    └── {6 .txt fixtures}
```

The per-version target list reflects the SD-R13-5 default (locked at
v_2.7.1 + v_2.7.3 + v_2.7.4). A future R14+ revision MAY substitute the
upper-end label for v_2.8.0 (or whichever release becomes "latest")
once the YubiHSM SDK release cadence advances; the existing layout
accommodates that swap with no script changes.

## Why per-version?

A single-version fixture set verifies that the parsers MATCH the
captured output shape. It does NOT verify that the parsers TOLERATE
version drift across the upstream SDK release cadence — i.e. that a
future yubihsm-shell minor release that adds a column to
`list-objects` (or reshapes a banner) is gracefully consumed. The
per-version tree gives format-drift detection across SDK versions:

- `v_2.7.1/` exercises the **pre-hotfix shape** (fixed-column alignment
  without comma separators on the list-objects rows; terser banners).
- `v_2.7.3/` is the **R12-B baseline** (post-R10-L2-hotfix
  `id: 0xXXXX, type: T, algo: A, sequence: 0, label: L` shape).
- `v_2.7.4/` exercises a **hypothetical trailing-fields extension**
  (e.g. a `generation: N` column added to list-objects, comparable
  trailing additions in the other fixtures).

The post-R13-E posture is **format-drift detection, NOT
semantic-drift detection** — see "Risks & residue" below.

## Synthetic-discipline policy

All transcripts in **every** per-version subdirectory MUST use
synthetic IDs (canary `0xa5a2`-style); NO verbatim real-device
captures. Regeneration MUST use synthetic-ID-stuffed inputs. **Any
future PR that introduces a real-device transcript is a security
regression** — the gate exists precisely so that the format-shape
can be CI-checked against the production parsers without committing
real ceremony state.

The committed synthetic IDs (allow-list, lowercase-hex) are:

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

Per R13-E the lockdown applies across **every** subdirectory: the
parity script's synthetic-discipline grep targets
`"${FIXTURES_ROOT}"/v_*/*.txt`, so any hex id outside the allow-list
is a hard fail **regardless of which subdirectory it appears in**.

## Files (per-version matrix)

The 6 canonical fixture filenames are identical across every
`v_X.Y.Z/` subdirectory; only the contents differ to reflect each
version's output shape. Each fixture is exercised by the
production-parser sites listed below.

| File | Purpose | Parsers exercised |
|------|---------|-------------------|
| `yubihsm-shell-list-objects.txt`  | `yubihsm-shell -a list-objects` output. v_2.7.3 = R10-L2-hotfix shape (`id: 0xXXXX, type: T, ...`). Includes the `my-wrap-key-label` foil to guard against the pre-hotfix substring-match regression. | `stage_legacy_setup.sh:173, :205-206, :208-209, :251`; `verify_roundtrip.sh:69-71` |
| `yubihsm-setup-ksp.txt`           | `yubihsm-setup ksp` raw log with ANSI escapes + 3 synthetic 2-of-3 shares + a noise `00-00-` line. | `_extract_shares.sh:12-15` |
| `yubihsm-shell-put-wrapped-ok.txt`        | Successful put-wrapped stdout. | `verify_roundtrip.sh:96-104` (success path) |
| `yubihsm-shell-put-wrapped-authfail.txt`  | put-wrapped CCM auth-failure stderr (wrap-id mismatch). | `verify_roundtrip.sh:96-104` (FAILED banner path) |
| `yubihsm-shell-get-public-key.txt` | PEM-shaped get-public-key output. | `verify_roundtrip.sh:107` (no parse — sha256 only) |
| `yubihsm-manager-tui-prompts.txt` | One line per yubihsm-manager TUI prompt the pexpect driver matches. | `drive_manager.py:361, :416, :429, :433, :438, :454, :459, :474` |

## Per-version differences

| File | v_2.7.1 (pre-hotfix) | v_2.7.3 (R12-B baseline) | v_2.7.4 (future extension) |
|------|----------------------|--------------------------|-----------------------------|
| `yubihsm-shell-list-objects.txt`  | Fixed-column alignment, NO comma separators between fields | Post-R10-L2-hotfix: comma-separated `id: 0xXXXX, type: T, algo: A, sequence: 0, label: L` | Same as v_2.7.3 PLUS trailing `, generation: 0` column |
| `yubihsm-setup-ksp.txt`           | Terser banner (`YubiHSM Setup` only, no "Welcome to"); shorter setup chatter | Full R12-B banner shape | Adds trailing `share-receipt hash: sha256:…` diagnostic line |
| `yubihsm-shell-put-wrapped-ok.txt`        | Minimal `Object imported as 0xXXXX` only | Same as v_2.7.1 | Adds trailing `Object metadata: domains=…, capabilities=…, generation=0` line |
| `yubihsm-shell-put-wrapped-authfail.txt`  | Minimal `Unable to import … invalid wrap-key` only | Same as v_2.7.1 | Adds trailing `Diagnostic: wrap-id mismatch …` line |
| `yubihsm-shell-get-public-key.txt` | Terser session preamble (`Session 0 open`) before the PEM block | Standard session preamble before PEM block | Adds a `Public key for object 0xXXXX (algo: …, generation: …):` header before the PEM block |
| `yubihsm-manager-tui-prompts.txt` | Pre-redesign bullet glyphs (ASCII `*` instead of unicode `●`/`○`) | Current TUI glyphs (`●`/`○`) | Adds `Rotate Wrap Key` menu item + `Generation: 0` metadata row |

The parsers' production patterns (column-anchored awk on `-F'[, ]+'`,
case-insensitive `[Ii]mported`, etc.) MUST tolerate all three shapes;
the parity gate verifies this on every CI run.

## Regeneration protocol

If upstream `yubihsm-shell` / `yubihsm-setup` / `yubihsm-manager` change
their output format within an existing target version:

1. Run the tool against a **synthetic-ID-stuffed** test device (use the
   canary IDs from the allow-list above; never commit a real-device
   capture).
2. Update the corresponding `*.txt` fixture in the matching
   `v_X.Y.Z/` subdirectory.
3. Re-run `bash scripts/tests/test_transcript_parity.sh`.
4. If any parser fails its parity check, fix the parser (NOT the
   fixture) — the fixture is the source-of-truth for "real" output
   shape; a divergent parser is the R10-L2-class bug the gate exists
   to catch.

The original R12-B regeneration protocol is preserved for the
`v_2.7.3/` baseline subdirectory.

## Adding a new SDK-version subdirectory

To onboard a new target version (e.g. when 2.8.0 ships):

1. `mkdir tests/fixtures/device-transcripts/v_2.8.0/`
2. Author the 6 canonical fixture files under that subdirectory,
   exercising the new version's format quirks. Every hex id MUST come
   from the synthetic-discipline allow-list above.
3. Re-run `bash scripts/tests/test_transcript_parity.sh`. The
   subdirectory loop in the parity script picks up the new version
   automatically; no script edit is required.
4. Add a row to the "Per-version differences" table above.
5. If the new version supersedes an EOL upstream release, optionally
   drop the now-EOL subdirectory (`rm -r v_X.Y.Z/`) and update this
   README's "Per-version layout" + differences table accordingly.

## Anti-R10-L2 contract

The methodology lock: **every parser site MUST be exercised against
the matching fixture in every per-version subdirectory**. A new
shell-out parser that ships without a corresponding fixture entry +
parity test block is a regression in the methodology gate itself.

## Risks & residue

- **Synthetic transcript fidelity.** The per-version transcripts are
  synthetic; they preserve the FORMAT differences across versions but
  not the SEMANTIC differences. A future R14+ round could capture
  REAL-device transcripts behind a gitignored opt-in (e.g.
  `tests/fixtures/device-transcripts-real/` with the directory itself
  in `.gitignore`) but the LOCKED R13-E posture is synthetic-only.
- **Version-target list staleness.** The SD-R13-5 default reflects
  the 2025-snapshot of the YubiHSM SDK release cadence. If 2.8.x
  releases, swap `v_2.7.4/` → `v_2.8.0/` per the impl-time tweak; the
  parity script's `v_*` glob picks up the rename with no edits.
- **Parity-gate runtime growth.** Each per-version subdirectory
  roughly multiplies the parity-script runtime by 1. Pre-R13 the
  gate ran in ~1-2 s; post-R13-E it runs in ~3-6 s. Still well within
  the shell-tests CI budget; tracked as a future R14+ residue if the
  version target list expands to >= 5 subdirectories.
