//! Standalone side-channel attack simulator.
//!
//! Runs every attack emulation back-to-back with per-process PMU counters and
//! prints whether barnowld's detection logic would fire.
//!
//! Usage:
//!   cargo run -p barnowld-simulation          # per-process measurement
//!   make simulate
//!
//! To validate against the live daemon, start barnowld in a second terminal:
//!   sudo systemd-run --system --wait ./target/debug/barnowld -v

use simulation::{
    detect_llc_size, evict_reload_thrash, flush_and_reload_thrash, flush_flush_attack,
    llc_contention_alloc, llc_contention_access, measure_with, miss_ratio, print_measurement,
    prime_probe_alloc, prime_probe_access, sequential_access, shared_library_spy,
    would_trigger, RECORD_SECS_FULL,
};
use std::time::Duration;

// Outcome a test case expects.
enum Expect {
    Detected,         // must exceed 90 % miss threshold
    NotDetected,      // must stay below threshold (blind spot / benign)
    Elevated(f64),    // no-clflush attacks: miss ratio must exceed this floor
}

struct Case {
    name: &'static str,
    expect: Expect,
}

fn run(case: &Case, work: impl FnOnce()) -> bool {
    let tag = match case.expect {
        Expect::Detected       => "attack",
        Expect::NotDetected    => "benign",
        Expect::Elevated(_)    => "attack",
    };
    println!("[{}] {}", tag, case.name);
    let (refs, misses) = measure_with(work);
    print_measurement("     result", refs, misses, RECORD_SECS_FULL);

    let detected = would_trigger(refs, misses, RECORD_SECS_FULL);
    let ratio    = miss_ratio(refs, misses);

    let ok = match case.expect {
        Expect::Detected => {
            if !detected {
                eprintln!("     FAIL: expected DETECTED (ratio={:.1}% < 90%)", ratio);
                false
            } else { true }
        }
        Expect::NotDetected => {
            if detected {
                eprintln!("     FAIL: expected not-detected but ratio={:.1}%", ratio);
                false
            } else { true }
        }
        Expect::Elevated(floor) => {
            if ratio < floor {
                eprintln!(
                    "     FAIL: expected elevated misses > {:.0}%, got {:.1}%",
                    floor, ratio
                );
                false
            } else {
                if !detected {
                    println!(
                        "     NOTE: ratio {:.1}% elevated but below barnowld's 90% threshold \
                         (per-process PMU; system-wide monitoring may differ)",
                        ratio
                    );
                }
                true
            }
        }
    };
    println!();
    ok
}

fn main() {
    let llc_mb = detect_llc_size() / (1024 * 1024);
    println!("=== barnowld side-channel attack simulator ===");
    println!("LLC size: {} MB   Recording: {} s/workload\n", llc_mb, RECORD_SECS_FULL);

    let d = Duration::from_secs(RECORD_SECS_FULL as u64);

    // Pre-allocate large buffers outside the PMU windows.
    let pp_buf   = prime_probe_alloc();
    let llc_buf  = llc_contention_alloc();

    let mut ok = true;

    // ── clflush-based attacks: reliable >90% per-process ─────────────────────
    ok &= run(
        &Case { name: "Flush+Reload  (clflush + random reload, ~100% miss)",
                expect: Expect::Detected },
        || flush_and_reload_thrash(d),
    );
    ok &= run(
        &Case { name: "Shared-Library Spy  (clflush on mmap'd libc, ~100% miss)",
                expect: Expect::Detected },
        || { let _ = shared_library_spy(d); },
    );

    // ── No-clflush attacks: elevated misses, may not reach 90% per-process ───
    ok &= run(
        &Case { name: "Prime+Probe  (20× LLC LCG random, ~70–85% miss, no clflush)",
                expect: Expect::Elevated(60.0) },
        || prime_probe_access(&pp_buf, d),
    );
    ok &= run(
        &Case { name: "LLC Contention  (12× LLC cross-VM pressure, ~80–90% miss)",
                expect: Expect::Elevated(60.0) },
        || llc_contention_access(&llc_buf, d),
    );
    ok &= run(
        &Case { name: "Evict+Reload  (2× LLC eviction, no clflush, ~70–85% miss)",
                expect: Expect::Elevated(50.0) },
        || evict_reload_thrash(d),
    );

    // ── barnowld blind spots ──────────────────────────────────────────────────
    ok &= run(
        &Case { name: "Flush+Flush  (clflush timing spy — refs/sec below threshold → NOT detected)",
                expect: Expect::NotDetected },
        || flush_flush_attack(d),
    );
    ok &= run(
        &Case { name: "Sequential access  (benign — no false positive)",
                expect: Expect::NotDetected },
        || sequential_access(d),
    );

    // ── Summary ───────────────────────────────────────────────────────────────
    println!("─────────────────────────────────────────────────────────");
    if ok {
        println!("All expectations matched.");
    } else {
        eprintln!("One or more expectations failed.");
        std::process::exit(1);
    }
}
