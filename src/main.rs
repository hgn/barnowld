use clap::{value_parser, Arg, ArgAction, Command};
use log::{error, warn, LevelFilter, Log};
use nix::unistd::chdir;
use perf_event::events::Hardware;
use perf_event::Builder;
use rand::seq::SliceRandom;
use rand::Rng;
use std::io::prelude::*;
use std::path::Path;
use std::thread;
use std::time::Duration;
use systemd_journal_logger::{connected_to_journal, JournalLog};

const CACHE_MISS_REF_RATIO_THRESHOLD: f64 = 90.0;
const CACHE_MISS_IGNORE_THRESHOLD: u64 = 10_000;
const RECORDING_TIME_MIN: usize = 5;
const RECORDING_TIME_MAX: usize = 10;

macro_rules! verboseln {
    ($cfg:expr, $($arg:tt)*) => {
        if $cfg.verbose && !$cfg.daemon {
            println!($($arg)*);
        }
    };
}

struct SimpleLogger;
static SIMPLE_LOGGER: SimpleLogger = SimpleLogger;

impl Log for SimpleLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        let _ = writeln!(std::io::stderr(), "{}", record.args());
    }

    fn flush(&self) {
        let _ = std::io::stderr().flush();
    }
}

#[derive(Default, Debug)]
pub struct Config {
    verbose: bool,
    daemon: bool,
    cpu_min: Option<usize>,
    cpu_max: Option<usize>,
    relax_time: Option<u64>,
}

fn get_num_cpus() -> usize {
    const CONF_NAME: libc::c_int = libc::_SC_NPROCESSORS_ONLN;
    let cpus = unsafe { libc::sysconf(CONF_NAME) };
    if cpus < 1 {
        1
    } else {
        cpus as usize
    }
}

fn generate_cpu_list(rng: &mut impl Rng, cfg: &Config) -> Vec<usize> {
    let no_cpus = get_num_cpus() - 1;
    let cpu_start = cfg.cpu_min.unwrap_or(0);
    let cpu_end = cfg.cpu_max.unwrap_or(no_cpus);
    let mut numbers: Vec<usize> = (cpu_start..=cpu_end).collect();
    numbers.shuffle(rng);
    numbers
}

fn sleep_sec(sleeptime: u64) {
    thread::sleep(Duration::from_secs(sleeptime));
}

fn cli() -> Command {
    Command::new("barnowld")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Hagen Paul Pfeifer <hagen@jauu.net>")
        .about("A Daemon for Real-Time Detection of Cache Side-Channel Attacks")
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(ArgAction::SetTrue)
                .help("Increase verbosity level"),
        )
        .arg(
            Arg::new("daemon")
                .short('d')
                .long("daemon")
                .action(ArgAction::SetTrue)
                .help("Print to journal, suppress debug output"),
        )
        .arg(
            Arg::new("cpu")
                .long("cpu")
                .value_parser(value_parser!(usize))
                .help("Pin the scan to one particular CPU"),
        )
        .arg(
            Arg::new("cpu-min")
                .long("cpu-min")
                .value_parser(value_parser!(usize))
                .help("Lower bound of the CPU range to scan (inclusive, 0-indexed)"),
        )
        .arg(
            Arg::new("cpu-max")
                .long("cpu-max")
                .value_parser(value_parser!(usize))
                .help("Upper bound of the CPU range to scan (inclusive, max: num_cpus - 1)"),
        )
        .arg(
            Arg::new("relax-time")
                .long("relax-time")
                .value_parser(value_parser!(u64))
                .help("Seconds to pause between full CPU scan cycles (default: 0)"),
        )
}

fn build_config(matches: clap::ArgMatches) -> Result<Config, String> {
    let mut cfg = Config {
        verbose: matches.get_flag("verbose"),
        daemon: matches.get_flag("daemon"),
        cpu_min: matches.get_one::<usize>("cpu-min").copied(),
        cpu_max: matches.get_one::<usize>("cpu-max").copied(),
        relax_time: matches.get_one::<u64>("relax-time").copied(),
    };

    if let Some(&cpu) = matches.get_one::<usize>("cpu") {
        if cfg.cpu_min.is_some() || cfg.cpu_max.is_some() {
            return Err("--cpu cannot be combined with --cpu-min or --cpu-max".to_string());
        }
        cfg.cpu_min = Some(cpu);
        cfg.cpu_max = Some(cpu);
    }

    let max_cpu_idx = get_num_cpus() - 1;
    if let Some(min) = cfg.cpu_min {
        if min > max_cpu_idx {
            return Err(format!(
                "--cpu-min {} exceeds highest CPU index {}",
                min, max_cpu_idx
            ));
        }
    }
    if let Some(max) = cfg.cpu_max {
        if max > max_cpu_idx {
            return Err(format!(
                "--cpu-max {} exceeds highest CPU index {}",
                max, max_cpu_idx
            ));
        }
    }
    if let (Some(min), Some(max)) = (cfg.cpu_min, cfg.cpu_max) {
        if min > max {
            return Err(format!(
                "--cpu-min {} is greater than --cpu-max {}",
                min, max
            ));
        }
    }

    Ok(cfg)
}

fn parse_args() -> Result<Config, String> {
    build_config(cli().get_matches())
}

/// Returns the miss/ref ratio if it exceeds the alert threshold with sufficient activity, None otherwise.
fn check_ratio(cache_refs: u64, cache_misses: u64, record_time: usize) -> Option<f64> {
    if cache_refs == 0 {
        return None;
    }
    if cache_refs / (record_time as u64) < CACHE_MISS_IGNORE_THRESHOLD {
        return None;
    }
    let ratio = (cache_misses as f64 / cache_refs as f64) * 100.0;
    if ratio > CACHE_MISS_REF_RATIO_THRESHOLD {
        Some(ratio)
    } else {
        None
    }
}

fn recording(cpu: usize, record_time: usize, cfg: &Config) -> Result<(), String> {
    if record_time < RECORDING_TIME_MIN {
        return Err(format!(
            "record_time {} is below minimum of {} seconds",
            record_time, RECORDING_TIME_MIN
        ));
    }

    let mut cache_refs = Builder::new()
        .one_cpu(cpu)
        .observe_pid(-1)
        .kind(Hardware::CACHE_REFERENCES)
        .build()
        .map_err(|e| {
            format!(
                "failed to open cache-references counter on CPU {}: {}",
                cpu, e
            )
        })?;

    let mut cache_misses = Builder::new()
        .one_cpu(cpu)
        .observe_pid(-1)
        .kind(Hardware::CACHE_MISSES)
        .build()
        .map_err(|e| format!("failed to open cache-misses counter on CPU {}: {}", cpu, e))?;

    cache_refs
        .enable()
        .map_err(|e| format!("failed to enable cache-references counter: {}", e))?;
    cache_misses
        .enable()
        .map_err(|e| format!("failed to enable cache-misses counter: {}", e))?;
    sleep_sec(record_time as u64);
    cache_refs
        .disable()
        .map_err(|e| format!("failed to disable cache-references counter: {}", e))?;
    cache_misses
        .disable()
        .map_err(|e| format!("failed to disable cache-misses counter: {}", e))?;

    let cache_refs_no = cache_refs
        .read()
        .map_err(|e| format!("failed to read cache-references counter: {}", e))?;
    let cache_misses_no = cache_misses
        .read()
        .map_err(|e| format!("failed to read cache-misses counter: {}", e))?;

    if cache_refs_no > 0 {
        verboseln!(
            cfg,
            "cpu {}: refs={} misses={} ratio={:.2}%",
            cpu,
            cache_refs_no,
            cache_misses_no,
            (cache_misses_no as f64 / cache_refs_no as f64) * 100.0
        );
    } else {
        verboseln!(cfg, "cpu {}: no cache references recorded", cpu);
    }

    if let Some(ratio) = check_ratio(cache_refs_no, cache_misses_no, record_time) {
        error!(
            "Possible cache side-channel attack on CPU {} detected!\n\
             Cache miss/ref ratio {:.2}% above trigger threshold of {:.2}%\n\
             Within {} recorded seconds on CPU {}, {} cache references where detected and {} cache misses\n\
             To further investigate this alert please install perf and execute the following\n\
             commands to narrow down the specific origin process.\n\
               perf record -e cache-references,cache-misses -C {}\n\
               perf report --stdio",
            cpu,
            ratio,
            CACHE_MISS_REF_RATIO_THRESHOLD,
            record_time,
            cpu,
            cache_refs_no,
            cache_misses_no,
            cpu
        );
    }

    Ok(())
}

// Sets working directory to / and initialises the logger. Actual process
// detachment is handled by systemd (Type=simple), so no double-fork is needed.
fn init_logging() -> Result<(), String> {
    chdir::<Path>(Path::new("/")).map_err(|_| "failed to chdir to /".to_string())?;

    if connected_to_journal() {
        JournalLog::default()
            .install()
            .map_err(|e| format!("failed to install journal logger: {}", e))?;
    } else {
        log::set_logger(&SIMPLE_LOGGER)
            .map_err(|e| format!("failed to install stderr logger: {}", e))?;
    }

    log::set_max_level(LevelFilter::Info);
    Ok(())
}

fn banner() {
    let no_cpus = get_num_cpus();
    let total_seconds_max = no_cpus * RECORDING_TIME_MAX;
    warn!(
        "barnowl started [cores detected: {}, max cycle: {:02}:{:02}]",
        no_cpus,
        total_seconds_max / 60,
        total_seconds_max % 60,
    );
}

fn main() {
    let cfg = parse_args().unwrap_or_else(|e| {
        eprintln!("error: {}", e);
        std::process::exit(1);
    });

    init_logging().unwrap_or_else(|e| {
        eprintln!("error: {}", e);
        std::process::exit(1);
    });

    banner();

    let mut rng = rand::thread_rng();
    loop {
        for cpu in generate_cpu_list(&mut rng, &cfg) {
            let record_time = rng.gen_range(RECORDING_TIME_MIN..=RECORDING_TIME_MAX);
            verboseln!(cfg, "checking cpu {} for {} seconds", cpu, record_time);
            if let Err(e) = recording(cpu, record_time, &cfg) {
                eprintln!("error on CPU {}: {}", cpu, e);
            }
        }
        if let Some(relax) = cfg.relax_time {
            verboseln!(cfg, "pausing for {} seconds", relax);
            sleep_sec(relax);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    // ── helper ───────────────────────────────────────────────────────────────

    fn parse_from(args: &[&str]) -> Result<Config, String> {
        cli()
            .try_get_matches_from(args)
            .map_err(|e| e.to_string())
            .and_then(build_config)
    }

    // ── generate_cpu_list ────────────────────────────────────────────────────

    #[test]
    fn cpu_list_covers_all_cpus_by_default() {
        let cfg = Config::default();
        let mut rng = rand::thread_rng();
        let mut cpus = generate_cpu_list(&mut rng, &cfg);
        cpus.sort_unstable();
        assert_eq!(cpus, (0..get_num_cpus()).collect::<Vec<_>>());
    }

    #[test]
    fn cpu_list_length_matches_range() {
        if get_num_cpus() < 4 {
            return;
        }
        let cfg = Config {
            cpu_min: Some(1),
            cpu_max: Some(3),
            ..Config::default()
        };
        let mut rng = rand::thread_rng();
        assert_eq!(generate_cpu_list(&mut rng, &cfg).len(), 3);
    }

    #[test]
    fn cpu_list_pinned_to_single_cpu() {
        let cfg = Config {
            cpu_min: Some(0),
            cpu_max: Some(0),
            ..Config::default()
        };
        let mut rng = rand::thread_rng();
        assert_eq!(generate_cpu_list(&mut rng, &cfg), vec![0]);
    }

    #[test]
    fn cpu_list_pinned_to_last_cpu() {
        let last = get_num_cpus() - 1;
        let cfg = Config {
            cpu_min: Some(last),
            cpu_max: Some(last),
            ..Config::default()
        };
        let mut rng = rand::thread_rng();
        assert_eq!(generate_cpu_list(&mut rng, &cfg), vec![last]);
    }

    #[test]
    fn cpu_list_respects_explicit_range() {
        if get_num_cpus() < 3 {
            return;
        }
        let cfg = Config {
            cpu_min: Some(0),
            cpu_max: Some(1),
            ..Config::default()
        };
        let mut rng = rand::thread_rng();
        let mut cpus = generate_cpu_list(&mut rng, &cfg);
        cpus.sort_unstable();
        assert_eq!(cpus, vec![0, 1]);
    }

    #[test]
    fn cpu_list_shuffle_is_deterministic_with_seeded_rng() {
        let cfg = Config::default();
        let mut rng1 = StdRng::seed_from_u64(0xdeadbeef);
        let mut rng2 = StdRng::seed_from_u64(0xdeadbeef);
        assert_eq!(
            generate_cpu_list(&mut rng1, &cfg),
            generate_cpu_list(&mut rng2, &cfg),
        );
    }

    #[test]
    fn cpu_list_different_seeds_differ_on_multi_cpu() {
        if get_num_cpus() < 2 {
            return;
        }
        // Different seeds should produce different orderings at least sometimes.
        // Try 20 seed pairs; if every single one matches, the shuffle is broken.
        let cfg = Config::default();
        let identical_count = (0u64..20)
            .filter(|&seed| {
                let mut r1 = StdRng::seed_from_u64(seed);
                let mut r2 = StdRng::seed_from_u64(seed + 1_000_000);
                generate_cpu_list(&mut r1, &cfg) == generate_cpu_list(&mut r2, &cfg)
            })
            .count();
        assert!(
            identical_count < 20,
            "shuffle appears to produce no variation"
        );
    }

    // ── CLI flag parsing ─────────────────────────────────────────────────────

    #[test]
    fn cli_defaults_are_false_and_none() {
        let m = cli().try_get_matches_from(["barnowld"]).unwrap();
        assert!(!m.get_flag("verbose"));
        assert!(!m.get_flag("daemon"));
        assert!(m.get_one::<usize>("cpu-min").is_none());
        assert!(m.get_one::<usize>("cpu-max").is_none());
        assert!(m.get_one::<u64>("relax-time").is_none());
    }

    #[test]
    fn cli_short_verbose_flag() {
        let m = cli().try_get_matches_from(["barnowld", "-v"]).unwrap();
        assert!(m.get_flag("verbose"));
        assert!(!m.get_flag("daemon"));
    }

    #[test]
    fn cli_long_verbose_flag() {
        let m = cli()
            .try_get_matches_from(["barnowld", "--verbose"])
            .unwrap();
        assert!(m.get_flag("verbose"));
    }

    #[test]
    fn cli_daemon_flag() {
        let m = cli().try_get_matches_from(["barnowld", "-d"]).unwrap();
        assert!(m.get_flag("daemon"));
    }

    #[test]
    fn cli_verbose_and_daemon_together() {
        let m = cli()
            .try_get_matches_from(["barnowld", "-v", "-d"])
            .unwrap();
        assert!(m.get_flag("verbose"));
        assert!(m.get_flag("daemon"));
    }

    #[test]
    fn cli_cpu_range_parsed() {
        let m = cli()
            .try_get_matches_from(["barnowld", "--cpu-min", "0", "--cpu-max", "2"])
            .unwrap();
        assert_eq!(m.get_one::<usize>("cpu-min").copied(), Some(0));
        assert_eq!(m.get_one::<usize>("cpu-max").copied(), Some(2));
    }

    #[test]
    fn cli_relax_time_parsed() {
        let m = cli()
            .try_get_matches_from(["barnowld", "--relax-time", "30"])
            .unwrap();
        assert_eq!(m.get_one::<u64>("relax-time").copied(), Some(30));
    }

    #[test]
    fn cli_relax_time_zero() {
        let m = cli()
            .try_get_matches_from(["barnowld", "--relax-time", "0"])
            .unwrap();
        assert_eq!(m.get_one::<u64>("relax-time").copied(), Some(0));
    }

    // ── parse_args / build_config validation ─────────────────────────────────

    #[test]
    fn parse_args_cpu_pin_sets_both_min_and_max() {
        let cfg = parse_from(&["barnowld", "--cpu", "0"]).unwrap();
        assert_eq!(cfg.cpu_min, Some(0));
        assert_eq!(cfg.cpu_max, Some(0));
    }

    #[test]
    fn parse_args_cpu_and_cpu_min_combined_errors() {
        let err = parse_from(&["barnowld", "--cpu", "0", "--cpu-min", "0"]).unwrap_err();
        assert!(err.contains("--cpu"), "expected --cpu in: {}", err);
    }

    #[test]
    fn parse_args_cpu_and_cpu_max_combined_errors() {
        let err = parse_from(&["barnowld", "--cpu", "0", "--cpu-max", "0"]).unwrap_err();
        assert!(err.contains("--cpu"), "expected --cpu in: {}", err);
    }

    #[test]
    fn parse_args_cpu_min_greater_than_max_errors() {
        // Skip if there aren't at least 2 CPUs (both values must be in range first)
        if get_num_cpus() < 2 {
            return;
        }
        let err = parse_from(&["barnowld", "--cpu-min", "1", "--cpu-max", "0"]).unwrap_err();
        assert!(
            err.contains("cpu-min") && err.contains("cpu-max"),
            "expected min/max mention in: {}",
            err
        );
    }

    #[test]
    fn parse_args_cpu_min_out_of_range_errors() {
        let too_high = (get_num_cpus() + 100).to_string();
        let err = parse_from(&["barnowld", "--cpu-min", &too_high]).unwrap_err();
        assert!(err.contains("cpu-min"), "expected cpu-min in: {}", err);
    }

    #[test]
    fn parse_args_cpu_max_out_of_range_errors() {
        let too_high = (get_num_cpus() + 100).to_string();
        let err = parse_from(&["barnowld", "--cpu-max", &too_high]).unwrap_err();
        assert!(err.contains("cpu-max"), "expected cpu-max in: {}", err);
    }

    #[test]
    fn parse_args_all_flags_combined() {
        let cfg = parse_from(&[
            "barnowld",
            "-v",
            "-d",
            "--cpu-min",
            "0",
            "--cpu-max",
            "0",
            "--relax-time",
            "5",
        ])
        .unwrap();
        assert!(cfg.verbose);
        assert!(cfg.daemon);
        assert_eq!(cfg.cpu_min, Some(0));
        assert_eq!(cfg.cpu_max, Some(0));
        assert_eq!(cfg.relax_time, Some(5));
    }

    // ── check_ratio ──────────────────────────────────────────────────────────

    #[test]
    fn check_ratio_zero_refs_returns_none() {
        assert!(check_ratio(0, 0, 5).is_none());
    }

    #[test]
    fn check_ratio_activity_just_below_ignore_threshold_returns_none() {
        // 49_999 refs / 5 sec = 9_999 refs/sec  →  9_999 < 10_000 → ignored
        assert!(check_ratio(49_999, 49_999, 5).is_none());
    }

    #[test]
    fn check_ratio_activity_at_ignore_threshold_not_ignored() {
        // 50_000 refs / 5 sec = 10_000 refs/sec  →  NOT < 10_000 → proceeds to ratio check
        // 95% miss rate → alert
        let ratio = check_ratio(50_000, 47_500, 5).unwrap();
        assert!(ratio > 94.9 && ratio < 95.1);
    }

    #[test]
    fn check_ratio_record_time_affects_ignore_check() {
        // 100_000 refs over 10 sec = 10_000/sec → at threshold, 95% → alert
        assert!(check_ratio(100_000, 95_000, 10).is_some());
        // Same refs over 11 sec = 9_090/sec → below threshold → ignored
        assert!(check_ratio(100_000, 95_000, 11).is_none());
    }

    #[test]
    fn check_ratio_below_90_percent_returns_none() {
        // 50% miss rate, sufficient activity
        assert!(check_ratio(100_000, 50_000, 5).is_none());
    }

    #[test]
    fn check_ratio_89_percent_returns_none() {
        // 89% miss rate, sufficient activity → below 90% threshold
        assert!(check_ratio(1_000_000, 890_000, 5).is_none());
    }

    #[test]
    fn check_ratio_threshold_is_exclusive() {
        // The condition is ratio > 90.0, not >=; 90% itself must not alert
        // Use values where floating-point result is clearly below 90.1%
        assert!(check_ratio(1_000_000, 891_000, 5).is_none()); // 89.1%
    }

    #[test]
    fn check_ratio_91_percent_triggers_alert() {
        let ratio = check_ratio(1_000_000, 910_000, 5).unwrap();
        assert!(ratio > 90.9 && ratio < 91.1);
    }

    #[test]
    fn check_ratio_95_percent_triggers_alert() {
        let ratio = check_ratio(1_000_000, 950_000, 5).unwrap();
        assert!(ratio > 94.9 && ratio < 95.1);
    }

    #[test]
    fn check_ratio_100_percent_triggers_alert() {
        // All references are misses
        let ratio = check_ratio(1_000_000, 1_000_000, 5).unwrap();
        assert!((ratio - 100.0).abs() < 0.01);
    }

    #[test]
    fn check_ratio_misses_exceeding_refs_triggers_alert() {
        // Shouldn't happen in hardware, but the math must not panic or produce garbage
        let ratio = check_ratio(1_000_000, 1_100_000, 5).unwrap();
        assert!(ratio > 100.0);
    }

    // ── recording guard ──────────────────────────────────────────────────────

    #[test]
    fn recording_rejects_sub_minimum_duration() {
        // This check fires before any perf_event_open call, so no root needed
        let cfg = Config::default();
        let err = recording(0, RECORDING_TIME_MIN - 1, &cfg).unwrap_err();
        assert!(err.contains("below minimum"), "unexpected error: {}", err);
    }

    // ── PMU: per-process counters (no root, paranoid=2 sufficient) ────────────

    #[test]
    fn perf_counter_current_process_cache_refs_readable() {
        // observe_pid(0) = current process, no one_cpu = any CPU.
        // Works at perf_event_paranoid <= 2 without root.
        let mut counter = Builder::new()
            .observe_pid(0)
            .kind(Hardware::CACHE_REFERENCES)
            .build()
            .expect("per-process CACHE_REFERENCES unavailable; check perf_event_paranoid");
        counter.enable().unwrap();
        // Touch memory to generate cache activity
        let v: Vec<u64> = (0..4096).collect();
        let _sum: u64 = v.iter().sum();
        counter.disable().unwrap();
        let _ = counter.read().unwrap();
    }

    #[test]
    fn perf_counter_current_process_cache_misses_readable() {
        let mut counter = Builder::new()
            .observe_pid(0)
            .kind(Hardware::CACHE_MISSES)
            .build()
            .expect("per-process CACHE_MISSES unavailable; check perf_event_paranoid");
        counter.enable().unwrap();
        let v: Vec<u64> = (0..4096).collect();
        let _sum: u64 = v.iter().sum();
        counter.disable().unwrap();
        let _ = counter.read().unwrap();
    }

    #[test]
    fn perf_counter_refs_exceed_misses_under_normal_load() {
        // A simple summation loop has a low miss rate; refs should exceed misses
        let mut refs_ctr = Builder::new()
            .observe_pid(0)
            .kind(Hardware::CACHE_REFERENCES)
            .build()
            .expect("CACHE_REFERENCES unavailable");
        let mut miss_ctr = Builder::new()
            .observe_pid(0)
            .kind(Hardware::CACHE_MISSES)
            .build()
            .expect("CACHE_MISSES unavailable");

        refs_ctr.enable().unwrap();
        miss_ctr.enable().unwrap();
        // Repeated access to the same small buffer → mostly cache hits
        let buf = vec![1u64; 64];
        let mut acc = 0u64;
        for _ in 0..10_000 {
            acc = acc.wrapping_add(buf.iter().sum::<u64>());
        }
        let _ = acc; // prevent optimisation
        refs_ctr.disable().unwrap();
        miss_ctr.disable().unwrap();

        let refs = refs_ctr.read().unwrap();
        let misses = miss_ctr.read().unwrap();
        assert!(
            refs >= misses,
            "cache misses ({}) exceeded references ({}) — counter issue",
            misses,
            refs
        );
    }

    // ── system-wide PMU (requires root or perf_event_paranoid <= 1) ──────────

    #[test]
    #[ignore = "needs root or perf_event_paranoid<=1; run with: sudo cargo test -- --include-ignored"]
    fn perf_counter_system_wide_cpu0_readable() {
        let mut counter = Builder::new()
            .one_cpu(0)
            .observe_pid(-1)
            .kind(Hardware::CACHE_REFERENCES)
            .build()
            .expect("system-wide counter on CPU 0 failed");
        counter.enable().unwrap();
        counter.disable().unwrap();
        let _ = counter.read().unwrap();
    }
}
