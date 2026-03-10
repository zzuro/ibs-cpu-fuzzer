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

fn main() -> Result<()> {
    let config = Config::from_args();

    println!("Input dir:    {}", config.input_dir.display());
    println!("Findings dir: {}", config.findings_dir.display());
    println!("State file:   {}", config.state_file.display());

    let mut state = AnalyzerState::load(&config.state_file)?;
    let files = collect_csv_files(&config.input_dir);

    println!("Discovered {} CSV files", files.len());

    for file in files.iter() {
        if state.has_processed(file) {
            continue;
        }

        match analyze_csv(file) {
            Ok(Some(finding)) => {
                write_finding(&config.findings_dir, &finding)?;
                println!("  -> finding written");
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
    }

    println!("Done.");
    Ok(())
}