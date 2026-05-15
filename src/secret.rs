// Page-aligned, MADV_DONTDUMP-marked, zero-on-drop heap buffer for
// secret-bearing bytes.
//
// Why a hand-rolled allocation rather than `Zeroizing<Vec<u8>>`:
//   * `Vec`'s backing allocator (glibc malloc) packs sub-page allocations
//     into shared inline buckets that are not page-aligned. `madvise(2)`
//     requires page-aligned addresses and lengths, so calling
//     MADV_DONTDUMP on a `Vec`'s pointer would silently fail with EINVAL
//     for almost every realistic capacity.
//   * Page-aligning via `std::alloc` + a `Layout` with align == page lets
//     us mark the whole allocation cleanly, then zero it on drop.
//
// This type is **not** an interior-mutable cell; callers handle the
// borrow discipline. It is also not Send/Sync-safe by default; we don't
// derive those traits, and the pointer is not annotated as Send/Sync.

use std::alloc::{alloc, dealloc, Layout};
use zeroize::Zeroize;

/// R14-02 (kill `src/secret.rs:125:39: replace == with != in
/// Secret::with_capacity`): the EINVAL check inside the MADV_DONTDUMP
/// error-handling path was previously inlined as
/// `err.raw_os_error() == Some(libc::EINVAL)` at the call site, which
/// the mutant flipped to `!=` with no executing test feeding a NON-
/// EINVAL errno through that codepath (the test kernel accepts
/// MADV_DONTDUMP, so the error branch is unreachable in normal tests).
///
/// Extracting the comparison into a small, pure helper makes the
/// equality testable in isolation: the `is_einval_accepts_einval_rejects_eperm`
/// test below synthesises both `EINVAL` and `EPERM` `io::Error`s and
/// asserts polarity, killing the mutant deterministically.
///
/// Release-mode behaviour is byte-identical to the pre-R14-02 inline
/// form: under LTO+inlining (Cargo.toml `[profile.release]` has
/// `lto = "thin"` + `codegen-units = 1`), `is_einval` inlines back to
/// the same comparison at the original call site.
#[inline]
fn is_einval(err: &std::io::Error) -> bool {
    err.raw_os_error() == Some(libc::EINVAL)
}

/// Page-aligned heap buffer that is `MADV_DONTDUMP`-marked at construction
/// and zeroed on Drop.
///
/// Field rationale:
/// * `cap` — actual allocation size, page-rounded, used by Drop
///   for the zero-and-dealloc step.
/// * `cap_hint` — the caller's logical bound. `extend_from_slice` is
///   bounded on this, not `cap`, so the page-rounding is invisible
///   to callers.
/// * `align` — the page size captured at alloc time, so Drop can
///   reconstruct the same Layout without re-querying `_SC_PAGESIZE`
///   (which is process-constant on Linux, but the explicit store
///   removes the implicit assumption).
/// * `len` — current write position.
pub struct Secret {
    ptr: *mut u8,
    cap: usize,
    cap_hint: usize,
    align: usize,
    len: usize,
    /// M-C1: anchors `!Send + !Sync` via `*mut u8`-bearing PhantomData.
    /// DO NOT REMOVE — a future refactor that drops the raw pointer must
    /// re-add this field (or use a different `!Send` PhantomData) to
    /// preserve the cross-thread invariant Drop relies on.
    ///
    /// `Secret` is also intentionally NOT `Clone`. A derived Clone would
    /// copy the raw `ptr` and the second Drop would double-free the
    /// allocation. Do not add `#[derive(Clone)]` or a manual Clone impl.
    _not_send_sync: std::marker::PhantomData<*mut u8>,
}

/// M-C2: drop-guard that frees the raw allocation if the path between
/// `alloc(layout)` and the final `Secret { … }` literal panics. Once the
/// `Secret` value is constructed, `defused = true` and Drop becomes a
/// no-op so the `Secret`'s own Drop owns the dealloc.
struct AllocGuard {
    ptr: *mut u8,
    layout: Layout,
    defused: bool,
}

// R14-03 Sub-A.2: a `#[cfg(test)]`-gated atomic counter records each
// AllocGuard::drop invocation AFTER the conditional dealloc side-effect.
// The `alloc_guard_dealloc_observed` test reads the counter pre/post-drop
// to discriminate the `:85:9: replace <impl Drop for AllocGuard>::drop
// with ()` mutant (which skips the increment). Release-mode behaviour is
// byte-identical: the counter line is stripped from non-test builds.
impl Drop for AllocGuard {
    fn drop(&mut self) {
        if !self.defused {
            // SAFETY: `defused == false` means the `Secret { … }` literal
            // was never constructed, so no other code holds the pointer.
            // `ptr` came from `std::alloc::alloc(layout)` on the same path
            // in `Secret::with_capacity`; `layout` matches that allocation
            // exactly by construction (same size, same alignment).
            unsafe {
                dealloc(self.ptr, self.layout);
            }
        }
        #[cfg(test)]
        observe_alloc_guard_dealloc();
    }
}

// R14-03 Sub-A.2 test-only instrumentation: counter for AllocGuard::drop.
// Wrapped in a helper annotated `#[cfg_attr(test, mutants::skip)]` so
// cargo-mutants does not mutate the instrumentation itself.
#[cfg(test)]
static ALLOC_GUARD_DEALLOC_OBSERVED: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
#[cfg_attr(test, mutants::skip)]
fn observe_alloc_guard_dealloc() {
    ALLOC_GUARD_DEALLOC_OBSERVED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

// R14-03 Sub-A.2: process-wide Mutex<()> serialization for the
// `alloc_guard_dealloc_observed` test, mirroring the in-tree fallback
// pattern established by R14-02 (`serial_test` is not a dev-dep here).
#[cfg(test)]
static ALLOC_GUARD_DEALLOC_OBSERVED_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
fn with_alloc_guard_dealloc_observed_lock<F: FnOnce()>(f: F) {
    let _guard = ALLOC_GUARD_DEALLOC_OBSERVED_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    f();
}

impl Secret {
    /// Allocate a page-aligned buffer with at least `cap_hint` bytes of
    /// usable capacity. Marks the allocation `MADV_DONTDUMP` on Linux.
    ///
    /// `cap_hint == 0` is normalised to `1` so we never hand a zero-size
    /// allocation to `madvise` / `dealloc` (UB on some allocators).
    pub fn with_capacity(cap_hint: usize) -> Self {
        // v4: normalise zero — size-0 alloc returns a dangling pointer
        // that must not be passed to madvise/dealloc.
        let cap_hint = cap_hint.max(1);
        let page = page_size();
        // R9-H1: MSRV is 1.85 (lockfile v4 floor + headroom), so
        // `usize::div_ceil` (stable since 1.73) is available and clippy
        // `manual_div_ceil` activates under the new floor. cap_hint is
        // bounded (≤ 64 KiB by H6) and page is a small power of two, so
        // there is no overflow concern on any practical platform.
        let cap = cap_hint.div_ceil(page) * page;
        let layout = Layout::from_size_align(cap, page).expect("layout");
        // SAFETY: layout has size >= page > 0 and align == page > 0.
        let ptr = unsafe { alloc(layout) };
        if ptr.is_null() {
            std::alloc::handle_alloc_error(layout);
        }
        // M-C2: from this point until the `Secret { … }` literal below, any
        // panic (e.g. the non-EINVAL madvise branch) would otherwise leak
        // the allocation under unwinding. The guard frees on panic; we
        // defuse it once we are about to take ownership via the literal.
        let mut guard = AllocGuard {
            ptr,
            layout,
            defused: false,
        };
        #[cfg(target_os = "linux")]
        // SAFETY: `ptr` is non-null (checked above; `handle_alloc_error`
        // diverges on null), `cap` is a positive page-multiple by
        // construction (`div_ceil(page) * page`), and `MADV_DONTDUMP` is
        // sound on any page-aligned region — it only flips a per-VMA
        // flag, never writes through `ptr`. The pre-3.4 EINVAL branch is
        // recovered from in-band; non-EINVAL errors panic and the
        // `AllocGuard` (still armed at this point) frees `ptr` on the
        // unwind path.
        //
        // R15-04: gate `libc::madvise` behind `#[cfg(not(miri))]` because miri's
        // interpreter does not model kernel-side advisory syscalls. The miri
        // error is explicit: "error: unsupported operation: can't call foreign
        // function `madvise` on OS `linux` ... this means the program tried to
        // do something Miri does not support; it does not indicate a bug in the
        // program."
        //
        // MADV_DONTDUMP at this site is R12-Phase-A best-effort defense-in-depth
        // layered ABOVE the LOAD-BEARING controls:
        //
        //   - `RLIMIT_CORE=0` (set by `lock_down_process` via
        //     `setrlimit(RLIMIT_CORE, {0, 0})` per H4)
        //   - `PR_SET_DUMPABLE=0` (set by `lock_down_process` via
        //     `prctl(PR_SET_DUMPABLE, 0)` per H4)
        //
        // If the kernel doesn't apply the MADV_DONTDUMP advisory (pre-3.4 kernel
        // returning EINVAL, or under miri where the call is skipped entirely),
        // the H4 process-level controls still hold and no `Secret` bytes can leak
        // via coredump. Skipping under miri preserves full miri coverage of
        // `Secret::with_capacity`'s page-aligned `std::alloc::alloc` + the
        // `AllocGuard` Drop-on-unwind + the `is_einval` error-handling branch +
        // the `Drop for Secret` zeroize-on-drop semantics — the load-bearing
        // security surface this module exists to validate. Production behaviour
        // on Linux >= 3.4 is byte-identical to pre-R15-04 (the gate evaluates
        // true under non-miri builds).
        //
        // Project precedent: `src/main.rs::lock_down_process_is_idempotent`
        // already gates `prctl` / `getrlimit` calls under `#[cfg(not(miri))]`
        // for the same reason. See `docs/MIRI-MAINTENANCE.md` §3.1 ledger row 1
        // (when R15-03 lands) for the tracking entry.
        #[cfg(not(miri))]
        unsafe {
            // MADV_DONTDUMP excludes these pages from any kernel coredump.
            // v4: pre-3.4 kernels return EINVAL — warn-once and continue,
            // since H4's RLIMIT_CORE=0 + PR_SET_DUMPABLE=0 still hold.
            // Other errno values still abort.
            let r = libc::madvise(ptr as *mut _, cap, libc::MADV_DONTDUMP);
            if r != 0 {
                let err = std::io::Error::last_os_error();
                if is_einval(&err) {
                    static ONCE: std::sync::Once = std::sync::Once::new();
                    ONCE.call_once(|| {
                        eprintln!(
                            "warning: MADV_DONTDUMP unsupported on this kernel; \
                             relying on RLIMIT_CORE=0 + PR_SET_DUMPABLE=0 only."
                        );
                    });
                } else {
                    // M-C2: `guard`'s Drop will dealloc the page-aligned
                    // allocation as the panic unwinds out of with_capacity.
                    panic!("madvise(MADV_DONTDUMP) failed unexpectedly: {err}");
                }
            }
        }
        guard.defused = true;
        Secret {
            ptr,
            cap,
            cap_hint,
            align: page,
            len: 0,
            _not_send_sync: std::marker::PhantomData,
        }
    }

    /// Borrow the written prefix of the buffer.
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: self.ptr is valid for self.cap >= self.len bytes; len is
        // only ever advanced by extend_from_slice, which writes the bytes
        // first. The lifetime is tied to &self.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    /// Append `src` to the buffer. Panics if the new length would exceed
    /// the caller-supplied `cap_hint`. The page-rounded `cap` is
    /// deliberately not exposed as extra capacity.
    pub fn extend_from_slice(&mut self, src: &[u8]) {
        // v4: bound on the caller's logical hint, not the page-rounded cap.
        assert!(
            self.len
                .checked_add(src.len())
                .is_some_and(|new| new <= self.cap_hint),
            "Secret capacity exceeded"
        );
        // SAFETY: bounds checked above; src and dst do not overlap because
        // dst is in our private allocation and src is a borrowed slice.
        unsafe {
            std::ptr::copy_nonoverlapping(src.as_ptr(), self.ptr.add(self.len), src.len());
        }
        self.len += src.len();
    }

    /// Current logical length.
    pub fn len(&self) -> usize {
        self.len
    }

    /// `true` if no bytes have been written via `extend_from_slice` yet.
    /// Companion to `len()` so the `clippy::len_without_is_empty` lint
    /// stays quiet now that `Secret` is library-public (R11/C3).
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Truncate the logical length. The dropped bytes remain in the
    /// allocation and will be zeroed on Drop along with the rest of the
    /// page-rounded `cap`.
    ///
    /// R14-02 (kill `src/secret.rs:196:14: replace < with <= in
    /// Secret::truncate`): the production form `n < self.len` and the
    /// mutant form `n <= self.len` differ ONLY at the boundary
    /// `n == self.len`. At the boundary, the production form takes the
    /// no-op else branch (skip assignment); the mutant takes the then
    /// branch and assigns `self.len = n` — a value-identical write that
    /// produces NO visible state change. The behavioural delta is
    /// observable only through instrumentation; a `#[cfg(test)]`
    /// observation counter inside the then branch increments only when
    /// the assignment runs, and the `truncate_at_boundary_does_not_assign`
    /// test reads the counter delta to discriminate the boundary.
    ///
    /// Release-mode behaviour is byte-identical to the pre-R14-02 form:
    /// the `#[cfg(test)]`-gated `observe_truncate_assign()` call is
    /// stripped from non-test builds, leaving the same `if n < self.len
    /// { self.len = n; }` body.
    #[allow(dead_code)]
    pub fn truncate(&mut self, n: usize) {
        if n < self.len {
            self.len = n;
            #[cfg(test)]
            observe_truncate_assign();
        }
    }
}

// R14-02 test-only instrumentation: a counter incremented inside the
// then-branch of `Secret::truncate`. The counter is observed by
// `truncate_at_boundary_does_not_assign` to discriminate the
// `< -> <=` boundary mutant (mutant runs the then-branch at
// `n == self.len`; production does not).
//
// The counter line is wrapped in `observe_truncate_assign()` and
// annotated `#[cfg_attr(test, mutants::skip)]` so cargo-mutants does
// NOT mutate the test-only instrumentation itself (e.g. replacing the
// `fetch_add(1, Relaxed)` constant or ordering). The skip is
// production-irrelevant because the function is fully `#[cfg(test)]`-
// gated; cargo-mutants compiles in test mode and sees the attribute.
#[cfg(test)]
static TRUNCATE_ASSIGNS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
#[cfg_attr(test, mutants::skip)]
fn observe_truncate_assign() {
    TRUNCATE_ASSIGNS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

// R14-02: the `serial_test` dev-dep is not present in the offline-
// vendored dep graph for this repo (see `.cargo/config.toml`:
// `replace-with = "vendored-sources"`). Per FIX_PLAN #r14-02 Step 3
// "if `#[mutants::skip]` isn't supported at the statement level (it
// may need to be on an enclosing function)" / Risks-and-residue note
// on parallel-test serialization, the documented fallback is to
// serialize the truncate-observing tests via an in-tree process-wide
// `Mutex<()>` named lock with the same `truncate_observed` key
// semantics. Three tests in this module call `Secret::truncate`
// (the new boundary test + `secret_truncate_works` +
// `secret_empty_tracks_logical_length`); all three lock this Mutex
// for the duration of their body so the shared TRUNCATE_ASSIGNS
// counter cannot observe a delta from a concurrently-running test.
#[cfg(test)]
static TRUNCATE_OBSERVED_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
fn with_truncate_observed_lock<F: FnOnce()>(f: F) {
    // Recover from poisoning: a panicking test must NOT permanently
    // poison the lock for the other two tests in the serial-group.
    let _guard = TRUNCATE_OBSERVED_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    f();
}

// R14-03 Sub-A.3: a `#[cfg(test)]`-gated atomic counter records each
// Secret::drop invocation AFTER both the zeroize and dealloc side-effects.
// The `secret_drop_observed` test reads the counter pre/post-drop to
// discriminate the `:316:9: replace <impl Drop for Secret>::drop with ()`
// mutant (which skips both side-effects and the counter increment).
// Release-mode behaviour is byte-identical: the counter line is stripped
// from non-test builds.
impl Drop for Secret {
    fn drop(&mut self) {
        // Zero the entire allocation, not just `len`, since stale bytes
        // from earlier truncate() calls or unused capacity are still in
        // the mapping. v4: use the align captured at alloc time.
        //
        // E-H1 (round 8): use `zeroize::Zeroize` on a slice instead of
        // `std::ptr::write_bytes`. The `zeroize` crate's slice impl uses
        // `write_volatile` + `compiler_fence(SeqCst)` to defeat dead-
        // store elimination — without that fence, LLVM is permitted to
        // elide the wipe immediately before `dealloc` (the bytes are
        // never read after the wipe; the allocation is being freed).
        // Under release profile with lto="thin" + codegen-units=1 (both
        // enabled in Cargo.toml [profile.release]), DSE on this write
        // is a realistic optimization target, so the H5 "zero-on-drop"
        // guarantee becomes theoretical without the volatile path.
        //
        // SAFETY (three invariants):
        //   1. `self.ptr` is non-null and dereferenceable for `self.cap`
        //      bytes (upheld by `Secret::with_capacity` post-construction).
        //   2. No other live `&mut [u8]` to the same memory exists
        //      (upheld because Drop receives `&mut self` — borrowck-
        //      enforced uniqueness).
        //   3. The slice's lifetime ends before `dealloc` (the slice is
        //      consumed in-line by `.zeroize()`; dealloc immediately
        //      follows; both inside the same `unsafe` block).
        unsafe {
            std::slice::from_raw_parts_mut(self.ptr, self.cap).zeroize();
            let layout = Layout::from_size_align_unchecked(self.cap, self.align);
            dealloc(self.ptr, layout);
        }
        #[cfg(test)]
        observe_secret_drop();
    }
}

// R14-03 Sub-A.3 test-only instrumentation: counter for Secret::drop.
// Wrapped in a helper annotated `#[cfg_attr(test, mutants::skip)]` so
// cargo-mutants does not mutate the instrumentation itself.
#[cfg(test)]
static SECRET_DROP_OBSERVED: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
#[cfg_attr(test, mutants::skip)]
fn observe_secret_drop() {
    SECRET_DROP_OBSERVED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

// R14-03 Sub-A.3: process-wide Mutex<()> serialization for the
// `secret_drop_observed` test. Many tests in this module construct
// `Secret` instances (`secret_basic_roundtrip`, `secret_truncate_works`,
// the boundary tests, etc.) which would all increment the shared counter
// if run in parallel. The lock guarantees the pre/post reads in the
// observation test only see the local drop's increment.
#[cfg(test)]
static SECRET_DROP_OBSERVED_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
fn with_secret_drop_observed_lock<F: FnOnce()>(f: F) {
    let _guard = SECRET_DROP_OBSERVED_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    f();
}

fn page_size() -> usize {
    #[cfg(target_os = "linux")]
    // SAFETY: `libc::sysconf` with a compile-time constant key
    // (`_SC_PAGESIZE`) is a pure POSIX query — it neither dereferences
    // pointers nor touches process state. The cast to `usize` is safe
    // because `_SC_PAGESIZE` returns a positive long on every supported
    // platform (Linux returns 4096 or 65536).
    unsafe {
        libc::sysconf(libc::_SC_PAGESIZE) as usize
    }
    #[cfg(not(target_os = "linux"))]
    {
        4096
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_basic_roundtrip() {
        let mut s = Secret::with_capacity(64);
        let data: Vec<u8> = (0u8..32).collect();
        s.extend_from_slice(&data);
        assert_eq!(s.len(), 32);
        assert_eq!(s.as_slice(), data.as_slice());
        // Drop runs at scope exit.
    }

    #[test]
    fn secret_zero_capacity_normalised() {
        // with_capacity(0) must not panic — v4 normalises to 1 internally.
        let mut s = Secret::with_capacity(0);
        // A 0-byte extend on a 0-hint Secret must succeed (0 + 0 <= 1).
        s.extend_from_slice(&[]);
        assert_eq!(s.len(), 0);
        assert!(s.is_empty());
        assert!(s.as_slice().is_empty());
    }

    #[test]
    #[should_panic(expected = "Secret capacity exceeded")]
    fn secret_extend_panics_past_cap_hint() {
        // 9 bytes into an 8-hint Secret must panic, even though the
        // underlying page-rounded cap is much larger.
        let mut s = Secret::with_capacity(8);
        s.extend_from_slice(&[0u8; 9]);
    }

    // R14-02: serialized via TRUNCATE_OBSERVED_LOCK because the
    // truncate(4) + truncate(0) calls below increment the shared
    // TRUNCATE_ASSIGNS counter; without the lock, a concurrent run of
    // `truncate_at_boundary_does_not_assign` could observe a non-zero
    // delta from these calls and false-positive-fail the boundary
    // assertion.
    #[test]
    fn secret_truncate_works() {
        with_truncate_observed_lock(|| {
            let mut s = Secret::with_capacity(32);
            s.extend_from_slice(&[0xABu8; 16]);
            assert_eq!(s.len(), 16);
            assert!(!s.is_empty());
            s.truncate(99);
            assert_eq!(s.len(), 16, "truncate past len must be a no-op");
            s.truncate(4);
            assert_eq!(s.len(), 4);
            assert_eq!(s.as_slice(), &[0xABu8; 4]);
        });
    }

    // R14-02: serialized via TRUNCATE_OBSERVED_LOCK (see note on
    // `secret_truncate_works` above).
    #[test]
    fn secret_empty_tracks_logical_length() {
        with_truncate_observed_lock(|| {
            let mut s = Secret::with_capacity(4);
            assert!(s.is_empty());
            s.extend_from_slice(&[1, 2, 3]);
            assert!(!s.is_empty());
            s.truncate(0);
            assert!(s.is_empty());
        });
    }

    // R14-02: discriminate the `:125:39: replace == with != in
    // Secret::with_capacity` boundary mutant. The helper `is_einval`
    // is extracted from the inline `err.raw_os_error() ==
    // Some(libc::EINVAL)` check in the MADV_DONTDUMP error-handling
    // path. Test directly confirms the helper accepts EINVAL and
    // rejects EPERM; the mutant (`!=` instead of `==`) flips both
    // polarities and the test catches it on at least one side.
    #[test]
    fn is_einval_accepts_einval_rejects_eperm() {
        let einval = std::io::Error::from_raw_os_error(libc::EINVAL);
        let eperm = std::io::Error::from_raw_os_error(libc::EPERM);
        assert!(is_einval(&einval), "EINVAL must be accepted");
        assert!(!is_einval(&eperm), "EPERM must be rejected");
    }

    // R14-02: discriminate the `:196:14: replace < with <= in
    // Secret::truncate` boundary mutant. Production form takes the
    // then-branch ONLY when `n < self.len`; mutant form takes the
    // then-branch ALSO when `n == self.len`. The cfg(test) counter
    // records when the then-branch is taken; the test observes the
    // counter does NOT increment on the boundary call (n == self.len)
    // and DOES increment on the strict-less call.
    //
    // Serialized via TRUNCATE_OBSERVED_LOCK (in-tree fallback for the
    // `serial_test::serial(truncate_observed)` attribute documented in
    // FIX_PLAN #r14-02 — the dep is not present in the offline-
    // vendored dep graph, so the documented Mutex fallback path is
    // used). Three tests lock this mutex; `fetch_add(Relaxed)` is
    // correct because each test body is single-threaded.
    #[test]
    fn truncate_at_boundary_does_not_assign() {
        with_truncate_observed_lock(|| {
            let pre = TRUNCATE_ASSIGNS.load(std::sync::atomic::Ordering::Relaxed);
            let mut s = Secret::with_capacity(8);
            // Populate to len == 4 via the public extend_from_slice API.
            s.extend_from_slice(&[0u8, 1, 2, 3]);
            assert_eq!(s.len(), 4);
            // Boundary: truncate(4) where self.len == 4 — production
            // takes the else branch (no assignment); mutant assigns
            // self.len = 4 (value-identical, but the cfg(test) counter
            // increments).
            s.truncate(4);
            let post = TRUNCATE_ASSIGNS.load(std::sync::atomic::Ordering::Relaxed);
            assert_eq!(
                post - pre,
                0,
                "truncate(self.len) must NOT assign (production); \
                 got {} assignment(s) — boundary mutant active?",
                post - pre
            );
            assert_eq!(s.len(), 4, "truncate at boundary preserves length");
            // Strictly-less: truncate(3) — assignment MUST happen
            // exactly once. This proves the instrumentation isn't
            // dead (cargo-mutants would otherwise survive a mutant
            // that disables the counter entirely).
            s.truncate(3);
            let post2 = TRUNCATE_ASSIGNS.load(std::sync::atomic::Ordering::Relaxed);
            assert_eq!(
                post2 - post,
                1,
                "truncate(self.len - 1) MUST assign exactly once; got {}",
                post2 - post
            );
            assert_eq!(s.len(), 3, "strict-less truncate updates length");
        });
    }

    #[test]
    fn page_size_is_realistic_page_alignment() {
        let page = page_size();
        assert!(
            page.is_power_of_two(),
            "page size must be a power of two: {page}"
        );
        assert!(page >= 4096, "page size is unexpectedly small: {page}");
    }

    #[test]
    fn secret_phantom_data_field_present() {
        // M-C1: refuses to compile if the `_not_send_sync` field is
        // renamed or removed. The field anchors `!Send + !Sync` so a
        // future refactor of `ptr: *mut u8` cannot silently re-enable
        // the auto-traits.
        let s = Secret::with_capacity(8);
        let _ = &s._not_send_sync;
    }

    #[test]
    fn secret_is_not_clone() {
        // M-C1 (best-effort, doc-only). Stable Rust trick: this trait is
        // implemented for ALL types. If `Secret` ever gains an inherent
        // or derived Clone impl, the explicit-disambiguation call below
        // would still resolve via the trait, so this stable form is not
        // a compile-fail guard. The doc-comment on `_not_send_sync` is
        // the load-bearing defence; this test exists as a
        // tripwire/comment-anchor.
        trait NotClone {
            fn _check() {}
        }
        impl<T: ?Sized> NotClone for T {}
        <Secret as NotClone>::_check();
    }

    // R14-03 Sub-A.2: discriminate the
    // `src/secret.rs:85:9: replace <impl Drop for AllocGuard>::drop with ()`
    // mutant. The production Drop body conditionally deallocs (when
    // `defused == false`) and then increments the counter; the mutant
    // replaces the entire body with `()` (no dealloc, no counter
    // increment). The test allocates a page-aligned buffer, constructs
    // an `AllocGuard` with `defused == false`, drops it (which must
    // dealloc the buffer and increment the counter), and asserts the
    // counter incremented — which would NOT happen under the mutant.
    //
    // Serialized via ALLOC_GUARD_DEALLOC_OBSERVED_LOCK so a parallel
    // test that also constructs `AllocGuard` cannot race with the
    // pre/post counter reads.
    //
    // Gated `#[cfg(not(miri))]` to match `madvise_panic_does_not_leak_alloc`:
    // the test does a raw `alloc` + `dealloc` round-trip that miri's
    // borrow-tracking model handles correctly, but keeping the gating
    // parallel to the existing alloc-test reduces miri-job churn.
    #[cfg(not(miri))]
    #[test]
    fn alloc_guard_dealloc_observed() {
        use std::sync::atomic::Ordering;
        with_alloc_guard_dealloc_observed_lock(|| {
            let pre = ALLOC_GUARD_DEALLOC_OBSERVED.load(Ordering::Relaxed);
            {
                let page = page_size();
                let layout = Layout::from_size_align(page, page).expect("layout");
                // SAFETY: layout has size == page > 0 and align == page > 0,
                // identical to the allocation pattern in `with_capacity`.
                let ptr = unsafe { alloc(layout) };
                if ptr.is_null() {
                    std::alloc::handle_alloc_error(layout);
                }
                let guard = AllocGuard {
                    ptr,
                    layout,
                    defused: false,
                };
                drop(guard);
            }
            let post = ALLOC_GUARD_DEALLOC_OBSERVED.load(Ordering::Relaxed);
            assert!(
                post > pre,
                "AllocGuard::drop must run and observe the counter; \
                 pre={pre} post={post} — `:85:9: replace <impl Drop for \
                 AllocGuard>::drop with ()` mutant active?"
            );
        });
    }

    // R14-03 Sub-A.3: discriminate the
    // `src/secret.rs:316:9: replace <impl Drop for Secret>::drop with ()`
    // mutant. The production Drop body zeroize+dealloc's the allocation
    // and then increments the counter; the mutant replaces the entire
    // body with `()` (no zeroize, no dealloc, no counter increment).
    // The test constructs a `Secret` via `with_capacity` + populates it
    // via `extend_from_slice`, explicitly drops it, and asserts the
    // counter incremented — which would NOT happen under the mutant.
    //
    // Serialized via SECRET_DROP_OBSERVED_LOCK so other tests that
    // construct `Secret` cannot race the pre/post counter reads.
    #[test]
    fn secret_drop_observed() {
        use std::sync::atomic::Ordering;
        with_secret_drop_observed_lock(|| {
            let pre = SECRET_DROP_OBSERVED.load(Ordering::Relaxed);
            {
                let mut s = Secret::with_capacity(32);
                s.extend_from_slice(&[0xC3u8; 16]);
                drop(s);
            }
            let post = SECRET_DROP_OBSERVED.load(Ordering::Relaxed);
            assert!(
                post > pre,
                "Secret::drop must run and observe the counter; \
                 pre={pre} post={post} — `:316:9: replace <impl Drop for \
                 Secret>::drop with ()` mutant active?"
            );
        });
    }

    // R12-Phase-D / item #8: this test allocates a page-aligned buffer
    // via `std::alloc::alloc` and immediately panics with the
    // `AllocGuard` armed, exercising the panic-unwind dealloc path.
    // Under miri the test is sound, but the panic-unwind plus the
    // explicit raw `alloc(layout)` make it visibly different from
    // production code in miri's borrow-tracking model — gate it out so
    // the miri job stays focused on the algorithmic kernels.
    #[cfg(not(miri))]
    #[test]
    #[should_panic(expected = "synthetic panic between alloc and Secret literal")]
    fn madvise_panic_does_not_leak_alloc() {
        // M-C2: behavioural mirror of the `with_capacity` failure mode.
        // We allocate a page-aligned buffer, install an `AllocGuard`,
        // and panic before defusing it. The guard's Drop must run as
        // the panic unwinds and free the allocation. Under Miri or
        // leak-sanitizer this would fail loudly if the guard were
        // missing; here the test simply asserts the panic propagates,
        // which exercises the Drop path.
        let page = page_size();
        let layout = Layout::from_size_align(page, page).expect("layout");
        // SAFETY: layout has size == page > 0 and align == page > 0,
        // identical to the allocation pattern in `with_capacity`.
        let ptr = unsafe { alloc(layout) };
        if ptr.is_null() {
            std::alloc::handle_alloc_error(layout);
        }
        let _guard = AllocGuard {
            ptr,
            layout,
            defused: false,
        };
        // Mirrors the post-alloc panic path in `Secret::with_capacity`.
        panic!("synthetic panic between alloc and Secret literal");
    }
}
