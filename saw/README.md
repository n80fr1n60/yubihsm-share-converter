# SAW symbolic Rust↔Cryptol equivalence

This directory hosts the R13-B / R13-02 layer of the yubihsm-share-converter
formal-methods stack: SAW (the Software Analysis Workbench) proofs that the
production Rust GF kernels under `src/legacy.rs` + `src/resplit.rs` are
**operationally equivalent in LLVM IR** to the Cryptol formal spec under
`spec/gf256.cry`.

## What SAW proves

The Cryptol `:prove` directives in `.github/workflows/cryptol-proofs.yml`
prove **algebraic identities of the SPEC** (commutativity, associativity,
distributivity over XOR, inv-round-trip, etc.). They do
NOT prove that the Rust impl matches the spec — a spec-vs-implementation
drift (e.g. a subtle bit-order regression in `legacy::mul`) would be
invisible at the Cryptol layer: the spec proofs would still return
`Q.E.D.`, the Rust property tests in `src/legacy.rs::tests` would still
pass (because they compare Rust-vs-Rust), but the Rust implementation
would have diverged from the formal spec.

SAW closes that gap for the CI-safe GF kernels. The driver script
`saw/yubihsm-share-converter.saw` runs three `llvm_verify` directives:

| SAW target              | Production kernel                                  | Cryptol spec                 |
|-------------------------|----------------------------------------------------|------------------------------|
| `saw_legacy_mul`        | `yubihsm_share_converter::legacy::mul`             | `mul_legacy` (poly 0x11D)    |
| `saw_resplit_mul_aes`   | `yubihsm_share_converter::resplit::mul_aes`        | `mul_aes` (poly 0x11B)       |
| `saw_legacy_inv`        | `yubihsm_share_converter::legacy::inv`             | `inv_legacy` (a^254)         |

Each proof is universally quantified over the full `u8` input domain via
`llvm_fresh_var` symbolic byte inputs; SAW lowers the LLVM bitcode +
Cryptol spec to a single SMT query and discharges it via Z3. A
`Proof succeeded! <target>` line means the Rust implementation and the
Cryptol spec agree on every input for that target; a `Counterexample`
return means the SMT solver found a concrete input on which they disagree,
which would be a release-blocking spec-vs-implementation drift.

The Lagrange `interp_at_zero` t=2/t=3 SAW wrappers are kept in
`saw/lagrange-offline.saw` for explicit offline/deep verification. They are
not part of the normal CI/CD lane because the exact Rust slice/iterator LLVM
shape depends on patched SAW/Crucible behavior and the t=3 proof can be
solver-expensive.

The `saw_*` symbol names are stable C-ABI no-mangle wrappers committed
under `saw/extracted/lib.rs`. They exist as a SAW seam over the production
kernels — no behavioural difference; the wrappers call the production
`yubihsm_share_converter::*` functions directly and the cdylib crate
pulls the production kernel bodies in transitively via a path dependency.

## Quick start

The canonical local-run entry point for the SAW equivalence proofs is
the R13-F top-level proof-runner wrapper:

```bash
bash scripts/run-proofs.sh saw
```

The wrapper builds the LLVM bitcode at the deterministic literal path
`saw/extracted/proof-target/release/deps/yubihsm_share_converter_saw_extracted.bc`
(R13-v2 M5), then runs the
SAW driver inside the pinned Docker image. Image digest is sourced
from `.github/workflows/proof-digests.env` (single source of truth
shared with `.github/workflows/saw-proofs.yml`), so the local
invocation is byte-identical to the CI lane.

**Memory/CPU advisory.** The CI-safe GF SAW pipeline is expected to be quick;
offline Lagrange SAW verification can take much longer and use several GB of
RAM. Run offline verification on a workstation with enough spare memory.
The wrapper prints this advisory banner before invoking SAW
(suppress with `YHSC_PROOF_QUIET=1`).

**Bitcode-build prerequisite.** The wrapper invokes
`cargo +<channel> rustc ... --emit=llvm-bc` where `<channel>` is
parsed from `saw/extracted/rust-toolchain.toml`. If the pinned toolchain
is not installed locally, the wrapper exits 3 with the remediation
hint `rustup toolchain install <channel>`. Install via:

```bash
rustup toolchain install "$(awk -F '"' '/^channel/ { print $2 }' saw/extracted/rust-toolchain.toml)"
```

**Wrapper exit codes.** `0` = all proofs pass; `1` = counterexample
or solver failure; `3` = missing prerequisite (Docker / pinned
rustc); `4` = bitcode build failed; `5` = Docker pull failed.

Expected SAW output on success:

```
Proof succeeded! saw_legacy_mul
Proof succeeded! saw_resplit_mul_aes
Proof succeeded! saw_legacy_inv
ALL CI SAW CORE EQUIVALENCE PROOFS RETURNED Q.E.D.
```

The CI lane at `.github/workflows/saw-proofs.yml` runs the same
pipeline on every push to `main`, every pull request, and a weekly
Sunday 07:00 UTC cron.

## Manual Docker invocation (advanced)

Reviewers who want to drive SAW interactively (for ad-hoc proof
exploration outside the locked driver script) can still invoke the
pinned container directly:

```bash
# 1. Build the LLVM bitcode at the deterministic literal path.
channel=$(awk -F '"' '/^channel/ { print $2 }' saw/extracted/rust-toolchain.toml)
cargo +"${channel}" rustc --manifest-path saw/extracted/Cargo.toml \
    --locked \
    --target-dir saw/extracted/proof-target \
    --crate-type cdylib --release -- \
    --emit=llvm-bc \
    -C codegen-units=1 \
    -C opt-level=0 \
    -C lto=off
test -f saw/extracted/proof-target/release/deps/yubihsm_share_converter_saw_extracted.bc

# 2. Run the SAW driver inside the pinned container.
docker run --rm \
    -e CRYPTOLPATH=/work:/work/spec \
    -v "$PWD:/work" -w /work \
    "$(awk -F= '/^SAW_IMAGE=/ { print $2 }' .github/workflows/proof-digests.env)" \
    saw/yubihsm-share-converter.saw
```

## Offline Lagrange verification

The production Lagrange wrappers remain available for manual SAW runs:

```bash
# Build the same bitcode path used by the CI-safe SAW driver first, then run:
docker run --rm \
    -e CRYPTOLPATH=/work:/work/spec \
    -v "$PWD:/work" -w /work \
    "$(awk -F= '/^SAW_IMAGE=/ { print $2 }' .github/workflows/proof-digests.env)" \
    saw/lagrange-offline.saw
```

Expected behavior depends on the SAW/Crucible stack. The pinned CI Docker
image is not required to pass this offline driver; local patched builds can
be used for upstream debugging and deep verification.

## How to add a new SAW equivalence proof

When a new GF kernel or offline Lagrange wrapper needs a SAW equivalence guard:

1. Add the Cryptol spec twin to `spec/gf256.cry` or `spec/lagrange.cry`.
   Cross-reference the production Rust function in the comment header.
2. Add a `#[no_mangle] #[inline(never)] pub extern "C" fn saw_<name>(...)`
   wrapper to `saw/extracted/lib.rs`. The wrapper's body calls the
   production function directly; it exists solely as a stable C-ABI
   symbol seam (the Itanium-ABI mangling on path-qualified Rust functions
   makes them awkward to reference from SAWScript).
3. Add an `llvm_verify m "saw_<name>" [] false <setup> z3;` block to
   `saw/yubihsm-share-converter.saw` only for CI-safe GF-style kernels.
   Put closure/iterator-heavy Lagrange proofs in `saw/lagrange-offline.saw`.
   The setup encodes the input shape via `llvm_fresh_var`, any preconditions
   via `llvm_precond`, and the expected return value via the corresponding
   Cryptol expression.
4. Verify locally per the Docker invocation above; if SAW prints
   `Proof succeeded! saw_<name>`, commit.
5. The CI lane expects exactly three core `Proof succeeded! saw_*` lines
   today. If adding a new CI-safe proof, update the expected count in
   `scripts/run-proofs.sh` and `.github/workflows/saw-proofs.yml` in the
   same change.

If the new function is closure-generic or otherwise at the edge of SAW's
symbolic-execution envelope, keep its SAW proof offline and add a focused
Rust/spec cross-check as the CI equivalence guard.

## Maintenance protocol

See `saw/MAINTENANCE.md` for the soak-period record, `[skip saw]`
label-override policy, quarterly toolchain rotation cadence, cron-side
non-blocking posture, and image-deletion contingency.
