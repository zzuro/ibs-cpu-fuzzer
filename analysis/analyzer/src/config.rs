use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Config {
    pub input_dir: PathBuf,
    pub findings_dir: PathBuf,
    pub state_file: PathBuf,
}

impl Config {
    pub fn from_args() -> Self {
        let mut args = std::env::args().skip(1);

        let input_dir = args
            .next()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/mnt/truenas/ibs_log"));

        let findings_dir = args
            .next()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/mnt/truenas/ibs_findings"));

        let state_file = args
            .next()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/mnt/truenas/state.json"));

        Self {
            input_dir,
            findings_dir,
            state_file,
        }
    }
}