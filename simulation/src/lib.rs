//! Side-channel attack simulator for barnowld integration tests.
//!
//! Attack families implemented:
//!
//! | Attack            | clflush | Detectable | Notes                          |
//! |-------------------|---------|------------|--------------------------------|
//! | Flush+Reload      | yes     | yes ~100%  | classic, shared memory         |
//! | Prime+Probe       | no      | yes ~92%   | no shared memory, cross-VM     |
//! | Flush+Flush       | yes     | **no**     | barnowld's blind spot          |
//! | LLC Contention    | no      | yes ~88%   | cross-VM, pure cache pressure  |
//! | Shared-Lib Spy    | yes     | yes ~100%  | realistic: mmap libc, spy      |
//! | Evict+Reload      | no      | yes ~80%   | no clflush, eviction-set style |

#[cfg(not(target_arch = "x86_64"))]
compile_error!("barnowld-simulation requires x86_64 (uses clflush / rdtsc)");

use rand::seq::SliceRandom;
use std::time::{Duration, Instant};

// ── Constants (mirrored from barnowld) ────────────────────────────────────────

/// Miss ratio (%) above which barnowld declares an attack.
pub const MISS_THRESHOLD: f64 = 90.0;

/// Minimum cache-references/second below which barnowld ignores a sample.
pub const IGNORE_REFS_PER_SEC: u64 = 10_000;

/// Recording duration for fast per-process tests (no root needed).
pub const RECORD_SECS_FAST: usize = 2;

/// Recording duration for system-wide tests — matches barnowld's RECORDING_TIME_MIN.
pub const RECORD_SECS_FULL: usize = 5;

// ── LLC size detection ────────────────────────────────────────────────────────

/// Detect the Last Level Cache size from sysfs.
///
/// Reads `/sys/devices/system/cpu/cpu0/cache/index*/level` and `size`.
/// Falls back to 16 MB when the kernel doesn't expose this information.
pub fn detect_llc_size() -> usize {
    for index in 0..16 {
        let level = std::fs::read_to_string(format!(
            "/sys/devices/system/cpu/cpu0/cache/index{}/level",
            index
        ));
        let size = std::fs::read_to_string(format!(
            "/sys/devices/system/cpu/cpu0/cache/index{}/size",
            index
        ));
        if let (Ok(l), Ok(s)) = (level, size) {
            if l.trim() == "3" {
                let s = s.trim();
                if let Some(k) = s.strip_suffix('K') {
                    if let Ok(kb) = k.parse::<usize>() {
                        return kb * 1024;
                    }
                }
                if let Some(m) = s.strip_suffix('M') {
                    if let Ok(mb) = m.parse::<usize>() {
                        return mb * 1024 * 1024;
                    }
                }
            }
        }
    }
    16 * 1024 * 1024 // default: 16 MB
}

// ── Attack 1: Flush+Reload ────────────────────────────────────────────────────

fn flush_and_access(buf: &[u8], order: &[usize]) -> u64 {
    use std::arch::x86_64::{_mm_clflush, _mm_mfence};
    unsafe {
        for i in (0..buf.len()).step_by(64) {
            _mm_clflush(buf.as_ptr().add(i));
        }
        _mm_mfence();
    }
    let mut sum = 0u64;
    for &off in order {
        sum = sum.wrapping_add(buf[off] as u64);
    }
    std::hint::black_box(sum)
}

/// **Flush+Reload** — explicit clflush followed by randomised reload.
///
/// The canonical LLC side-channel attack. Attacker and victim share a physical
/// memory page (e.g. a shared library). Attacker flushes a cache line, victim
/// accesses it (bringing it back into LLC), attacker reloads and measures
/// timing — a fast reload reveals the victim's access pattern.
///
/// PMU signature: ~100% LLC miss ratio (every reload is a guaranteed miss).
/// barnowld: **DETECTED**.
pub fn flush_and_reload_thrash(duration: Duration) {

    // 128 KB → 2048 lines.  Order vector = 16 KB → fits in L1D so index
    // traversal generates no LLC references and cannot dilute the ratio.
    const BUF_SIZE: usize = 128 * 1024;
    const LINE_SIZE: usize = 64;
    let buf = vec![1u8; BUF_SIZE];
    let num_lines = BUF_SIZE / LINE_SIZE;
    let mut rng = rand::thread_rng();
    let mut order: Vec<usize> = (0..num_lines).map(|i| i * LINE_SIZE).collect();

    let end = Instant::now() + duration;
    while Instant::now() < end {
        order.shuffle(&mut rng); // new order per iteration defeats the prefetcher
        flush_and_access(&buf, &order);
    }
}

// ── Attack 2: Prime+Probe ─────────────────────────────────────────────────────

/// **Prime+Probe** — no clflush, no shared memory.
///
/// Attacker fills every LLC set with its own data (prime), waits for the
/// victim to run, then re-reads the same sets and measures which were evicted
/// (probe). Works across process boundaries and across VMs with no shared
/// memory mapping — only cache-set knowledge is needed.
///
/// Emulated here by random access to a buffer 12× the LLC size: the natural
/// eviction rate keeps most accesses in "miss" territory regardless of victim
/// activity.
///
/// PMU signature: ~88–95% LLC miss ratio (depends on LLC size).
/// barnowld: **DETECTED** on typical hardware (LLC ≤ 32 MB).
/// Pre-allocate the Prime+Probe working buffer.
///
/// Call once outside the PMU measurement window so allocation overhead
/// (page faults, zeroing) is not counted in the LLC miss statistics.
/// Returns a buffer of `20 × LLC_size`, capped at 1 GB.
pub fn prime_probe_alloc() -> Vec<u8> {
    let llc_size = detect_llc_size();
    // 20× LLC → ~5 % hit probability → ~95 % miss rate.
    // LCG repeat-visits inflate the effective hit rate vs. a perfect permutation
    // so we overprovision vs. the theoretical minimum.
    let buf_size = (llc_size * 20).min(1024 * 1024 * 1024);
    vec![1u8; buf_size] // zeroing pre-faults all pages
}

/// Run the Prime+Probe access pattern against a pre-allocated buffer.
///
/// Separate allocation (`prime_probe_alloc`) from measurement so the PMU
/// window captures only random-access cache misses, not first-touch faults.
pub fn prime_probe_access(buf: &[u8], duration: Duration) {
    let num_lines = buf.len() / 64;
    let end = Instant::now() + duration;
    let mut state: u64 = 0xdead_beef_cafe_babe;
    while Instant::now() < end {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let idx = (state >> 6) as usize % num_lines;
        let _ = std::hint::black_box(buf[idx * 64]);
    }
}

/// Convenience wrapper: allocate + run (allocation IS inside the PMU window).
/// Use `prime_probe_alloc` + `prime_probe_access` when precise measurement matters.
pub fn prime_probe_thrash(duration: Duration) {
    let buf = prime_probe_alloc();
    prime_probe_access(&buf, duration);
}

// ── Attack 3: Flush+Flush ─────────────────────────────────────────────────────

/// **Flush+Flush** — measures clflush latency instead of reload latency.
///
/// Instead of reloading a cache line and timing the load, the attacker
/// flushes the line a second time and measures the flush duration:
/// - slow clflush → line was in LLC (victim accessed it) → HIT
/// - fast clflush → line was already evicted → MISS
///
/// The spy never issues explicit load instructions against the target memory,
/// so the process generates almost no LLC-reference events. barnowld's
/// activity threshold (`IGNORE_REFS_PER_SEC`) fires and the sample is ignored.
///
/// PMU signature: refs/sec ≪ 10 000 → sample ignored by barnowld.
/// barnowld: **NOT DETECTED** — documented blind spot (see README).
pub fn flush_flush_attack(duration: Duration) {
    use std::arch::x86_64::{_mm_clflush, _mm_mfence, _rdtsc};

    const BUF_SIZE: usize = 4 * 1024 * 1024;
    let buf = vec![1u8; BUF_SIZE];
    let end = Instant::now() + duration;

    while Instant::now() < end {
        // Phase 1: initial flush — evict all lines (spy "setup").
        unsafe {
            for i in (0..BUF_SIZE).step_by(64) {
                _mm_clflush(buf.as_ptr().add(i));
            }
            _mm_mfence();
        }
        // (In a real attack the victim accesses buf here on another CPU.)

        // Phase 2: spy measures second-flush latency.
        // No load from buf → no CACHE_REFERENCES events generated.
        let mut timing = 0u64;
        unsafe {
            for i in (0..BUF_SIZE).step_by(64) {
                let t1 = _rdtsc();
                _mm_clflush(buf.as_ptr().add(i));
                let t2 = _rdtsc();
                // In a real attack: if (t2-t1) > threshold → victim used this line.
                timing = timing.wrapping_add(t2.wrapping_sub(t1));
            }
            _mm_mfence();
        }
        std::hint::black_box(timing);
    }
}

// ── Attack 4: LLC Contention ──────────────────────────────────────────────────

/// **LLC Contention** — continuous random hammering of a buffer >> LLC size.
///
/// Models the cross-VM cache eviction attack: an attacker on one VM hammers
/// all LLC sets continuously, forcing the co-located victim's cache lines out.
/// No shared memory mapping, no special instructions — pure memory bandwidth.
/// This is the simplest attack vector that generates detectable cache pressure.
///
/// PMU signature: ~80–90% LLC miss ratio (varies with LLC size).
/// barnowld: **DETECTED** on most systems; marginal on machines with LLC > 32 MB.
/// Pre-allocate the LLC Contention working buffer.
/// Returns a buffer of `12 × LLC_size`, capped at 768 MB.
pub fn llc_contention_alloc() -> Vec<u8> {
    let llc_size = detect_llc_size();
    let buf_size = (llc_size * 12).min(768 * 1024 * 1024);
    vec![1u8; buf_size]
}

/// Run the LLC Contention access pattern against a pre-allocated buffer.
pub fn llc_contention_access(buf: &[u8], duration: Duration) {
    let num_lines = buf.len() / 64;
    let end = Instant::now() + duration;
    let mut state: u64 = 0xfeed_face_dead_beef;
    while Instant::now() < end {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let idx = (state >> 6) as usize % num_lines;
        let _ = std::hint::black_box(buf[idx * 64]);
    }
}

/// Convenience wrapper: allocate + run (allocation IS inside the PMU window).
pub fn llc_contention_thrash(duration: Duration) {
    let buf = llc_contention_alloc();
    llc_contention_access(&buf, duration);
}

// ── Attack 5: Shared-Library Spy ─────────────────────────────────────────────

/// Find a readable shared library on this Linux system.
pub fn find_shared_lib() -> Option<&'static str> {
    const CANDIDATES: &[&str] = &[
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/lib64/libc.so.6",
        "/usr/lib/x86_64-linux-gnu/libc.so.6",
        "/usr/lib64/libc.so.6",
        "/usr/lib/libc.so.6",
    ];
    CANDIDATES
        .iter()
        .find(|&&p| std::path::Path::new(p).exists())
        .copied()
}

/// **Shared-Library Spy** — Flush+Reload on real shared library pages.
///
/// Maps a system shared library (`libc.so`) read-only via `mmap(MAP_SHARED)`,
/// then performs Flush+Reload on its first 128 KB (2048 cache lines). In a
/// real attack the attacker and victim share the library's physical pages at
/// the same physical addresses, letting the attacker infer which library
/// functions the victim calls by timing page reloads.
///
/// This is the most realistic attack emulation: it operates on real OS pages,
/// not a synthetic buffer.
///
/// PMU signature: ~100% LLC miss ratio on the probed pages.
/// barnowld: **DETECTED**.
///
/// Returns `Err` if no readable shared library is found (rare on Linux).
pub fn shared_library_spy(duration: Duration) -> Result<(), String> {
    use std::arch::x86_64::{_mm_clflush, _mm_mfence};

    let path = find_shared_lib().ok_or_else(|| "no shared library found".to_string())?;

    let cpath = std::ffi::CString::new(path).unwrap();
    let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDONLY) };
    if fd < 0 {
        return Err(format!("open({path}) failed"));
    }

    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } < 0 {
        unsafe { libc::close(fd) };
        return Err("fstat failed".to_string());
    }
    let file_size = st.st_size as usize;

    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            file_size,
            libc::PROT_READ,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        unsafe { libc::close(fd) };
        return Err("mmap failed".to_string());
    }

    // Spy on the first 128 KB — contains hot libc entry points.
    // 2048 lines × 8 bytes index = 16 KB order vector → fits in L1D.
    const LINE_SIZE: usize = 64;
    let spy_size = file_size.min(128 * 1024);
    let num_lines = spy_size / LINE_SIZE;

    let mut rng = rand::thread_rng();
    let mut order: Vec<usize> = (0..num_lines).map(|i| i * LINE_SIZE).collect();
    let base = ptr as *const u8;
    let end = Instant::now() + duration;

    while Instant::now() < end {
        order.shuffle(&mut rng);
        unsafe {
            for &off in &order {
                _mm_clflush(base.add(off));
            }
            _mm_mfence();
        }
        let mut sum = 0u64;
        for &off in &order {
            sum = sum.wrapping_add(unsafe { *base.add(off) } as u64);
        }
        std::hint::black_box(sum);
    }

    unsafe {
        libc::munmap(ptr, file_size);
        libc::close(fd);
    }
    Ok(())
}

// ── Attack 6: Evict+Reload ────────────────────────────────────────────────────

/// **Evict+Reload** — eviction-set pressure without clflush.
///
/// The attacker uses a 2× LLC-sized eviction buffer (accessed randomly) to
/// displace the target from all LLC sets, then reloads the target and times
/// the access. Works on hardware without unprivileged `clflush` access and
/// is the preferred technique on ARM and in some hardened environments.
///
/// Three phases per cycle:
///   1. **Load target** → bring 128 KB target into LLC.
///   2. **Evict** → random-access 2× LLC eviction buffer, displacing target.
///   3. **Reload target** → target lines are now LLC misses.
///
/// PMU signature: ~70–85% LLC miss ratio (less reliable than clflush-based).
/// barnowld: **likely DETECTED**; result depends on eviction effectiveness.
pub fn evict_reload_thrash(duration: Duration) {
    let llc_size = detect_llc_size();

    const TARGET_LINES: usize = 2048; // 128 KB target
    const LINE_SIZE: usize = 64;

    let target = vec![1u8; TARGET_LINES * LINE_SIZE];
    let evict_buf = vec![1u8; llc_size * 2]; // 2× LLC to fill all sets
    let evict_lines = evict_buf.len() / LINE_SIZE;

    let mut rng = rand::thread_rng();
    let mut target_order: Vec<usize> = (0..TARGET_LINES).map(|i| i * LINE_SIZE).collect();
    let mut lcg: u64 = 0xc0_ffee_dead;

    let end = Instant::now() + duration;

    while Instant::now() < end {
        target_order.shuffle(&mut rng);

        // Step 1: load target into LLC.
        let mut s = 0u64;
        for &i in &target_order {
            s = s.wrapping_add(target[i] as u64);
        }
        std::hint::black_box(s);

        // Step 2: fill LLC with random eviction buffer accesses.
        let mut es = 0u64;
        for _ in 0..evict_lines {
            lcg = lcg
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let idx = (lcg as usize) % evict_lines;
            es = es.wrapping_add(evict_buf[idx * LINE_SIZE] as u64);
        }
        std::hint::black_box(es);

        // Step 3: reload target — most lines evicted in step 2 → LLC misses.
        let mut s2 = 0u64;
        for &i in &target_order {
            s2 = s2.wrapping_add(target[i] as u64);
        }
        std::hint::black_box(s2);
    }
}

// ── Benign baseline ───────────────────────────────────────────────────────────

/// **Sequential access** — cache-friendly benign baseline.
///
/// Repeatedly scans a 256 KB buffer sequentially. After the first pass the
/// buffer lives in L2 and every subsequent access is a cache hit.
/// The hardware prefetcher performs perfectly here.
///
/// PMU signature: refs/sec below `IGNORE_REFS_PER_SEC` → sample ignored.
/// barnowld: **NOT detected** (no false positive).
pub fn sequential_access(duration: Duration) {
    const BUF_SIZE: usize = 256 * 1024;
    let buf = vec![1u8; BUF_SIZE];
    let end = Instant::now() + duration;
    let mut acc = 0u64;
    while Instant::now() < end {
        for &byte in &buf {
            acc = acc.wrapping_add(byte as u64);
        }
    }
    std::hint::black_box(acc);
}

// ── PMU measurement helpers ───────────────────────────────────────────────────

/// Measure CACHE_REFERENCES and CACHE_MISSES for the calling process while
/// `work` runs.
///
/// Uses `observe_pid(0)` — **no root required** (`perf_event_paranoid ≤ 2`).
pub fn measure_with<F: FnOnce()>(work: F) -> (u64, u64) {
    use perf_event::{events::Hardware, Builder};

    let mut refs = Builder::new()
        .observe_pid(0)
        .kind(Hardware::CACHE_REFERENCES)
        .build()
        .expect("per-process CACHE_REFERENCES unavailable; check perf_event_paranoid");
    let mut misses = Builder::new()
        .observe_pid(0)
        .kind(Hardware::CACHE_MISSES)
        .build()
        .expect("per-process CACHE_MISSES unavailable");

    refs.enable().unwrap();
    misses.enable().unwrap();
    work();
    refs.disable().unwrap();
    misses.disable().unwrap();

    (refs.read().unwrap(), misses.read().unwrap())
}

/// Measure CACHE_REFERENCES and CACHE_MISSES system-wide on `cpu` while
/// `work` runs.
///
/// Uses `observe_pid(-1)` — requires **root** or `perf_event_paranoid ≤ 1`.
pub fn measure_system_wide_with<F: FnOnce()>(cpu: usize, work: F) -> (u64, u64) {
    use perf_event::{events::Hardware, Builder};

    let mut refs = Builder::new()
        .one_cpu(cpu)
        .observe_pid(-1)
        .kind(Hardware::CACHE_REFERENCES)
        .build()
        .expect(
            "system-wide CACHE_REFERENCES failed — run as root or: \
             sudo sysctl -w kernel.perf_event_paranoid=-1",
        );
    let mut misses = Builder::new()
        .one_cpu(cpu)
        .observe_pid(-1)
        .kind(Hardware::CACHE_MISSES)
        .build()
        .expect("system-wide CACHE_MISSES failed");

    refs.enable().unwrap();
    misses.enable().unwrap();
    work();
    refs.disable().unwrap();
    misses.disable().unwrap();

    (refs.read().unwrap(), misses.read().unwrap())
}

// ── Detection logic (mirrors barnowld) ───────────────────────────────────────

/// Cache miss ratio as a percentage.
pub fn miss_ratio(refs: u64, misses: u64) -> f64 {
    if refs == 0 {
        return 0.0;
    }
    (misses as f64 / refs as f64) * 100.0
}

/// Returns `true` if the counter values would trigger barnowld's detection.
/// Mirrors `check_ratio` in `barnowld/src/main.rs` exactly.
pub fn would_trigger(refs: u64, misses: u64, record_secs: usize) -> bool {
    if refs == 0 {
        return false;
    }
    if refs / (record_secs as u64) < IGNORE_REFS_PER_SEC {
        return false;
    }
    miss_ratio(refs, misses) > MISS_THRESHOLD
}

// ── Utilities ─────────────────────────────────────────────────────────────────

/// Pin the calling thread to `cpu` via `sched_setaffinity`.
pub fn pin_to_cpu(cpu: usize) {
    use nix::sched::{sched_setaffinity, CpuSet};
    use nix::unistd::Pid;
    let mut set = CpuSet::new();
    set.set(cpu).expect("CPU index out of range for CpuSet");
    sched_setaffinity(Pid::from_raw(0), &set).expect("sched_setaffinity failed");
}

/// Print a one-line measurement summary.
pub fn print_measurement(label: &str, refs: u64, misses: u64, record_secs: usize) {
    let ratio = miss_ratio(refs, misses);
    let refs_per_sec = if record_secs > 0 {
        refs / record_secs as u64
    } else {
        0
    };
    println!(
        "{}: refs={} ({}/sec)  misses={}  ratio={:.1}%  → {}",
        label,
        refs,
        refs_per_sec,
        misses,
        ratio,
        if would_trigger(refs, misses, record_secs) {
            "DETECTED"
        } else {
            "not detected"
        }
    );
}
