mod analyzer;
mod config;
mod discovery;
mod state;
mod writer;

use anyhow::Result;
use analyzer::analyze_csv;
use config::Config;
use discovery::collect_csv_files;
use state::AnalyzerState;
use writer::write_finding;

use indicatif::{ProgressBar, ProgressStyle};

fn main() -> Result<()> {
    let config = Config::from_args();

    println!("Input dir:    {}", config.input_dir.display());
    println!("Findings dir: {}", config.findings_dir.display());
    println!("State file:   {}", config.state_file.display());

    let mut state = AnalyzerState::load(&config.state_file)?;
    let files = collect_csv_files(&config.input_dir);

    println!("Discovered {} CSV files", files.len());

    let pb = ProgressBar::new(files.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len}")
            .unwrap()
    );


    for file in files.iter() {
        if state.has_processed(file) {
            pb.inc(1);
            continue;
        }

        match analyze_csv(file) {
            Ok(Some(finding)) => {
                write_finding(&config.findings_dir, &finding)?;
                state.mark_processed(file);
                state.save(&config.state_file)?;
            }
            Ok(None) => {
                state.mark_processed(file);
                state.save(&config.state_file)?;
            }
            Err(err) => {
                eprintln!("  -> failed: {err}");
            }
        }
        pb.inc(1);
    }

    pb.finish();
    println!("Done.");
    Ok(())
}