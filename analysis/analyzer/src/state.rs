use anyhow::Result;
use serde_json;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct AnalyzerState {
    pub processed_files: HashSet<String>,
}

impl AnalyzerState {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let content = fs::read_to_string(path)?;
        let state = serde_json::from_str(&content)?;
        Ok(state)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json)?;
        Ok(())
    }

    pub fn has_processed(&self, file: &Path) -> bool {
        let key = normalize_path(file);
        self.processed_files.contains(&key)
    }

    pub fn mark_processed(&mut self, file: &Path) {
        let key = normalize_path(file);
        self.processed_files.insert(key);
    }
}

fn normalize_path(path: &Path) -> String {
    path.to_string_lossy().to_string()
}