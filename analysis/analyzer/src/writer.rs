use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::fmt;

#[derive(Debug, Serialize, Deserialize)]
pub struct ResultEntry {
    pub uop_cnt: i64,
    #[serde(serialize_with = "serialize_hex")]
    pub phys_addr: u64,
    #[serde(serialize_with = "serialize_hex")]
    pub lin_addr: u64,
    #[serde(serialize_with = "serialize_hex")]
    pub branch_target_rip: u64,
    pub reasons: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Finding {
    pub source_file: String,
    pub res_entry: Vec<ResultEntry>,
}


impl fmt::Display for ResultEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "uop_cnt={} phys=0x{:x} lin=0x{:x} branch=0x{:x}",
            self.uop_cnt,
            self.phys_addr,
            self.lin_addr,
            self.branch_target_rip
        )?;

        if !self.reasons.is_empty() {
            write!(f, " reasons=[{}]", self.reasons.join(", "))?;
        }

        Ok(())
    }
}

fn serialize_hex<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&format!("0x{:x}", value))
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