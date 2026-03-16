mod analyzer;
mod config;
mod discovery;
mod state;
mod writer;

use anyhow::{bail, Context, Result};
use analyzer::analyze_bin;
use config::Config;
use discovery::collect_bin_files;
use indicatif::{ProgressBar, ProgressStyle};
use state::AnalyzerState;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::thread;
use writer::write_finding;

fn main() -> Result<()> {
    let config = Config::from_args();

    println!("Input dir:      {}", config.input_dir.display());
    println!("Findings dir:   {}", config.findings_dir.display());
    println!("State dir:      {}", config.state_dir.display());
    println!("Fail logs dir:  {}", config.fail_dir.display());

    fs::create_dir_all(&config.findings_dir)
        .with_context(|| format!("creating findings dir {}", config.findings_dir.display()))?;
    fs::create_dir_all(&config.state_dir)
        .with_context(|| format!("creating state dir {}", config.state_dir.display()))?;
    fs::create_dir_all(&config.fail_dir)
        .with_context(|| format!("creating fail dir {}", config.fail_dir.display()))?;

    let files = collect_bin_files(&config.input_dir);

    println!("Discovered {} BIN files", files.len());
    if files.is_empty() {
        println!("Done.");
        return Ok(());
    }

    let core_ids = core_affinity::get_core_ids()
        .ok_or_else(|| anyhow::anyhow!("failed to get CPU core IDs for affinity pinning"))?;

    let worker_count = core_ids.len();
    println!("Using {} workers (one per CPU)", worker_count);

    let pb = ProgressBar::new(files.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len}")
            .unwrap(),
    );

    let chunk_size = files.len().div_ceil(worker_count);

    let mut handles = Vec::new();

    for (worker_idx, core_id) in core_ids.into_iter().enumerate() {
        let start = worker_idx * chunk_size;
        if start >= files.len() {
            break;
        }

        let end = ((worker_idx + 1) * chunk_size).min(files.len());
        let chunk: Vec<PathBuf> = files[start..end].to_vec();

        let worker_config = config.clone();
        let worker_pb = pb.clone();

        let handle = thread::spawn(move || -> Result<()> {
            process_chunk(worker_idx, core_id, chunk, worker_config, worker_pb)
        });

        handles.push(handle);
    }

    for handle in handles {
        match handle.join() {
            Ok(result) => result?,
            Err(_) => bail!("a worker thread panicked"),
        }
    }

    pb.finish();
    println!("Done.");
    Ok(())
}

fn process_chunk(
    worker_idx: usize,
    core_id: core_affinity::CoreId,
    files: Vec<PathBuf>,
    config: Config,
    pb: ProgressBar,
) -> Result<()> {
    let pinned = core_affinity::set_for_current(core_id);
    if !pinned {
        eprintln!(
            "warning: worker {} could not be pinned to CPU {}",
            worker_idx, core_id.id
        );
    }

    let state_file = config
        .state_dir
        .join(format!("state.core-{worker_idx:02}.json"));

    let fail_file = config
        .fail_dir
        .join(format!("failed_files.core-{worker_idx:02}.log"));

    let findings_dir = config
        .findings_dir
        .join(format!("core-{worker_idx:02}"));

    fs::create_dir_all(&findings_dir)
        .with_context(|| format!("creating findings dir {}", findings_dir.display()))?;

    let mut state = AnalyzerState::load(&state_file)
        .with_context(|| format!("loading state file {}", state_file.display()))?;

    let mut fail_log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&fail_file)
        .with_context(|| format!("opening fail log {}", fail_file.display()))?;

    let mut increment = 0;
    for file in files {
        if state.has_processed(&file) {
            increment += 1;
            continue;
        }

        if let Some(name) = file.file_name().and_then(|n| n.to_str()) {
            //skip snapshot files from the fuzzer
            if name.starts_with("fuzz_state") {
                increment += 1;
                continue;
            }
        }

        match analyze_bin(&file) {
            Ok(Some(finding)) => {
                write_finding(&findings_dir, &finding)
                    .with_context(|| format!("writing finding for {}", file.display()))?;

                state.mark_processed(&file);
                state.save(&state_file)
                    .with_context(|| format!("saving state file {}", state_file.display()))?;
            }
            Ok(None) => {
                state.mark_processed(&file);
                state.save(&state_file)
                    .with_context(|| format!("saving state file {}", state_file.display()))?;
            }
            Err(err) => {
                writeln!(fail_log, "{} -> {}", file.display(), err)
                    .with_context(|| format!("writing fail log {}", fail_file.display()))?;
            }
        }

        increment += 1;

        if increment >= 100 {
            pb.inc(increment);
            increment = 0;
        }
    }

    if increment > 0 {
        pb.inc(increment);
    }

    Ok(())
}