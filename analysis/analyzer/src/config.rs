use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Config {
    pub input_dir: PathBuf,
    pub findings_dir: PathBuf,
    pub state_dir: PathBuf,
    pub fail_dir: PathBuf,
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

        let state_dir = args
            .next()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/mnt/truenas/ibs_state"));

        let fail_dir = args
            .next()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/mnt/truenas/ibs_fail_logs"));

        Self {
            input_dir,
            findings_dir,
            state_dir,
            fail_dir,
        }
    }
}