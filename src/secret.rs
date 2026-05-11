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
    }
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
        unsafe {
            // MADV_DONTDUMP excludes these pages from any kernel coredump.
            // v4: pre-3.4 kernels return EINVAL — warn-once and continue,
            // since H4's RLIMIT_CORE=0 + PR_SET_DUMPABLE=0 still hold.
            // Other errno values still abort.
            let r = libc::madvise(ptr as *mut _, cap, libc::MADV_DONTDUMP);
            if r != 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINVAL) {
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

    /// Mutably borrow the written prefix of the buffer.
    #[allow(dead_code)]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: see as_slice; the &mut self lifetime makes the borrow
        // exclusive.
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
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

    /// Truncate the logical length. The dropped bytes remain in the
    /// allocation and will be zeroed on Drop along with the rest of the
    /// page-rounded `cap`.
    #[allow(dead_code)]
    pub fn truncate(&mut self, n: usize) {
        if n < self.len {
            self.len = n;
        }
    }
}

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
    }
}

fn page_size() -> usize {
    #[cfg(target_os = "linux")]
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

    #[test]
    fn secret_truncate_works() {
        let mut s = Secret::with_capacity(32);
        s.extend_from_slice(&[0xABu8; 16]);
        assert_eq!(s.len(), 16);
        s.truncate(4);
        assert_eq!(s.len(), 4);
        assert_eq!(s.as_slice(), &[0xABu8; 4]);
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
