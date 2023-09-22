extern crate clap;
use clap::{Arg, Command};


use perf_event::events::Hardware;
use perf_event::Builder;
use rand::seq::SliceRandom;
use std::thread;
use std::time::Duration;

use rand::Rng;

pub struct Config {
    verbose: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

impl Config {

    pub fn new() -> Self {
        Config { verbose: false }
    }

    pub fn verbose(&self) -> bool {
        self.verbose
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

fn xsleep(sleeptime: u64) {
    let sleep_duration = Duration::from_secs(sleeptime);
    thread::sleep(sleep_duration);
}

fn generate_cpu_list(mut rng: rand::rngs::ThreadRng) -> Vec<usize> {
    let no_cpus = get_num_cpus() - 1;
    let mut numbers: Vec<usize> = (0..=no_cpus).collect();
    numbers.shuffle(&mut rng);
    numbers
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
}

fn parse_args() -> Config {
    let mut cfg = Config::new();
    let matches = cli().get_matches();

    if let Some(c) = matches.get_one::<bool>("verbose") {
        cfg.verbose = *c;
    }

    cfg
}

fn recording(cpu: usize, record_time: usize, cfg: &Config) {
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
    xsleep(record_time as u64);
    cache_refs.disable().unwrap();
    cache_misses.disable().unwrap();

    let cache_misses_no = cache_misses.read().unwrap();
    let cache_refs_no = cache_refs.read().unwrap();
    let ratio = (cache_misses_no as f64 / cache_refs_no as f64) * 100.0;

    if cfg.verbose {
        println!(
            "misses: {} refs: {}, ratio: {}",
            cache_misses_no, cache_refs_no, ratio
        );
    }
}

fn main() -> std::io::Result<()> {
    let mut rng = rand::thread_rng();
    let cfg = parse_args();

    let rng2 = rand::thread_rng();
    let cpus = generate_cpu_list(rng2);

    for cpu in &cpus {
        let record_time = rng.gen_range(5..=10);
        println!("checking cpu {} for {} seconds", cpu, record_time);
        recording(*cpu, record_time, &cfg);
    }

    Ok(())
}
