use perf_event::events::Hardware;
use perf_event::Builder;
use std::thread;
use std::time::Duration;

fn xsleep(sleeptime: u64) {
    let sleep_duration = Duration::from_secs(sleeptime);
    thread::sleep(sleep_duration);
}

fn main() -> std::io::Result<()> {
    let mut cache_refs = Builder::new()
        .one_cpu(0)
        .observe_pid(-1)
        .kind(Hardware::CACHE_REFERENCES)
        .build()?;

    let mut cache_misses = Builder::new()
        .one_cpu(0)
        .observe_pid(-1)
        .kind(Hardware::CACHE_MISSES)
        .build()?;

    cache_refs.enable()?;
    cache_misses.enable()?;
    xsleep(2);
    cache_refs.disable()?;
    cache_misses.disable()?;

    let cache_misses_no = cache_misses.read()?;
    let cache_refs_no = cache_refs.read()?;
    let ratio = (cache_misses_no as f64 / cache_refs_no as f64) * 100.0;

    println!(
        "misses: {} refs: {}, ratio: {}",
        cache_misses_no, cache_refs_no, ratio
    );

    Ok(())
}
