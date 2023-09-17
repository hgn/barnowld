extern crate clap;
use clap::{value_parser, Arg, Command};
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
    ($extra:expr, $($arg:tt)*) => {
        {
            if ($extra.verbose && !$extra.daemon) {
                println!($($arg)*);
            }
        }
    };
}

struct SimpleLogger;

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

pub struct Config {
    verbose: bool,
    daemon: bool,
    cpu_min: usize,
    cpu_max: usize,
    relax_time: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

impl Config {
    pub fn new() -> Self {
        Config {
            verbose: false,
            daemon: false,
            cpu_min: usize::MAX,
            cpu_max: usize::MAX,
            relax_time: u64::MAX,
        }
    }
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

fn generate_cpu_list(mut rng: rand::rngs::ThreadRng, cfg: &Config) -> Vec<usize> {
    let mut cpu_start = 0;
    let no_cpus = get_num_cpus() - 1;
    let mut cpu_end = no_cpus;
    if cfg.cpu_min != usize::MAX {
        // user specified custom cpu start
        if cfg.cpu_min > no_cpus {
            panic!(
                "specified cpu_min {} higher then number of CPUs {}",
                cfg.cpu_min, no_cpus
            );
        }
        cpu_start = cfg.cpu_min;
    }
    if cfg.cpu_max != usize::MAX {
        if cfg.cpu_max > no_cpus {
            panic!(
                "specified cpu_max {} higher then number of CPUs {}",
                cfg.cpu_max, no_cpus
            );
        }
        cpu_end = cfg.cpu_max;
    }
    let mut numbers: Vec<usize> = (cpu_start..=cpu_end).collect();
    numbers.shuffle(&mut rng);
    numbers
}

fn sleep_sec(sleeptime: u64) {
    let sleep_duration = Duration::from_secs(sleeptime);
    thread::sleep(sleep_duration);
}

fn cli() -> Command {
    Command::new("barnowld")
        .version("0.1.0")
        .author("Hagen Paul Pfeifer <hagen@jauu.net>")
        .about("A Daemon for Real-Time Detection of Cache Side-Channel Attacks")
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .required(false)
                .num_args(0)
                .help("Increase verbosity level"),
        )
        .arg(
            Arg::new("daemon")
                .short('d')
                .long("daemon")
                .required(false)
                .num_args(0)
                .help("Print warn to journal, no debug messages & light daemonize"),
        )
        .arg(
            Arg::new("cpu")
                .long("cpu")
                .required(false)
                .value_parser(value_parser!(usize))
                .help("Pin the scan to one particular CPU"),
        )
        .arg(
            Arg::new("cpu-min")
                .long("cpu-min")
                .required(false)
                .value_parser(value_parser!(usize))
                .help("Limits the analysed CPU range (minimum CPU), starts with 0"),
        )
        .arg(
            Arg::new("cpu-max")
                .long("cpu-max")
                .required(false)
                .value_parser(value_parser!(usize))
                .help("Limits the analysed CPU range (maximum CPU), max: mumber of cores - 1"),
        )
        .arg(
            Arg::new("relax-time")
                .long("relax-time")
                .required(false)
                .value_parser(value_parser!(u64))
                .help("allow to make a break between core scanns, in seconds to wait between, default: 0"),
        )
}

fn parse_args() -> Config {
    let mut cfg = Config::new();
    let matches = cli().get_matches();

    if let Some(c) = matches.get_one::<bool>("verbose") {
        cfg.verbose = *c;
    }
    if let Some(c) = matches.get_one::<usize>("cpu-min") {
        cfg.cpu_min = *c
    }
    if let Some(c) = matches.get_one::<usize>("cpu-max") {
        cfg.cpu_max = *c
    }

    if let Some(c) = matches.get_one::<usize>("cpu") {
        if cfg.cpu_max != usize::MAX || cfg.cpu_min != usize::MAX {
            // user specifed max/min AND cpu - this is not possible
            panic!("option cpu-max/cpu-min AND cpu at the same time not supported");
        }
        cfg.cpu_min = *c;
        cfg.cpu_max = *c;
    }

    if cfg.cpu_min > cfg.cpu_max {
        panic!(
            "cpu-min larger as cpu-max, {} vs {}",
            cfg.cpu_min, cfg.cpu_max
        );
    }

    if let Some(c) = matches.get_one::<bool>("daemon") {
        cfg.daemon = *c
    }
    if let Some(c) = matches.get_one::<u64>("relax-time") {
        cfg.relax_time = *c
    }

    cfg
}

fn recording(cpu: usize, record_time: usize, cfg: &Config) {
    if record_time < RECORDING_TIME_MIN {
        panic!(
            "a recording should be at least {} seconds",
            RECORDING_TIME_MIN
        );
    }

    let mut cache_refs = Builder::new()
        .one_cpu(cpu)
        .observe_pid(-1)
        .kind(Hardware::CACHE_REFERENCES)
        .build()
        .unwrap();

    let mut cache_misses = Builder::new()
        .one_cpu(cpu)
        .observe_pid(-1)
        .kind(Hardware::CACHE_MISSES)
        .build()
        .unwrap();

    cache_refs.enable().unwrap();
    cache_misses.enable().unwrap();
    sleep_sec(record_time as u64);
    cache_refs.disable().unwrap();
    cache_misses.disable().unwrap();

    let cache_misses_no = cache_misses.read().unwrap();
    let cache_refs_no = cache_refs.read().unwrap();
    let ratio = (cache_misses_no as f64 / cache_refs_no as f64) * 100.0;

    let cache_refs_per_second = cache_refs_no / record_time as u64;
    if cache_refs_per_second < CACHE_MISS_IGNORE_THRESHOLD {
        verboseln!(
            cfg,
            "ignore record, just nearly no instructions recorded: {}",
            cache_refs_no
        );
        return;
    }

    if cfg.verbose {
        println!(
            "misses: {} refs: {}, ratio: {:.2}%",
            cache_misses_no, cache_refs_no, ratio
        );
    }

    if ratio > CACHE_MISS_REF_RATIO_THRESHOLD {
        let mut msg = String::new();
        msg += &format!(
            "Possible cache side-channel attack on CPU {} detected!\n",
            cpu
        );
        msg += &format!(
            "Cache miss/ref ratio {:.2}% above trigger threshold of {:.2}%\n",
            ratio, CACHE_MISS_REF_RATIO_THRESHOLD
        );
        msg += &format!(
            "Within {} recorded seconds on CPU {}, {} cache references \
               where detected and {} cache misses\n",
            record_time, cpu, cache_refs_no, cache_misses_no
        );
        msg += "To further invesigative this alert please install perf \
               and execute to following commands to narrow down the \
               specific origin process.\n";
        msg += &format!(
            "  perf record -e cache-references,cache-misses -C {}\n",
            cpu
        );
        msg += "  perf report --stdio";
        error!("{}", msg);
    }
}

fn daemonize_it(_cfg: &Config) -> Result<(), &'static str> {
    if chdir::<Path>(Path::new("/")).is_err() {
        return Err("Failed to change directory to root (/)");
    }

    if connected_to_journal() {
        JournalLog::default().install().unwrap();
    } else {
        log::set_logger(&SimpleLogger).unwrap();
    }

    log::set_max_level(LevelFilter::Info);

    Ok(())
}

fn banner() {
    let no_cpus = get_num_cpus();
    let total_seconds_max = no_cpus * RECORDING_TIME_MAX;
    let minutes = total_seconds_max / 60;
    let seconds = total_seconds_max % 60;
    warn!(
        "barnowl started [cores detected: {}, max cycle: {:02}:{:02}]",
        no_cpus, minutes, seconds
    );
}

fn main() -> std::io::Result<()> {
    let mut rng = rand::thread_rng();
    let cfg = parse_args();

    daemonize_it(&cfg).unwrap();
    banner();

    loop {
        let rng2 = rand::thread_rng();
        let cpus = generate_cpu_list(rng2, &cfg);
        for cpu in &cpus {
            let record_time = rng.gen_range(RECORDING_TIME_MIN..=RECORDING_TIME_MAX);
            verboseln!(cfg, "checking cpu {} for {} seconds", cpu, record_time);
            recording(*cpu, record_time, &cfg);
        }
        if cfg.relax_time != u64::MAX {
            verboseln!(cfg, "pause scanning for {} seconds", cfg.relax_time);
            sleep_sec(cfg.relax_time)
        }
    }

    #[allow(unreachable_code)]
    Ok(())
}
