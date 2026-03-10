use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize)]
pub struct Finding {
    pub source_file: String,
    pub uop_cnt: Vec<u64>,
}

pub fn write_finding(output_dir: &Path, finding: &Finding) -> Result<()> {
    fs::create_dir_all(output_dir)?;

    let source_path = Path::new(&finding.source_file);

    let file_stem = source_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown");

    let output_file: PathBuf = output_dir.join(format!("{file_stem}_finding.json"));
    let json = serde_json::to_string_pretty(finding)?;
    fs::write(output_file, json)?;

    Ok(())
}