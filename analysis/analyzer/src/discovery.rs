use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub fn collect_csv_files(input_dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();

    for entry in WalkDir::new(input_dir)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();

        if path.is_file()
            && path
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| ext.eq_ignore_ascii_case("csv"))
                .unwrap_or(false)
        {
            files.push(path.to_path_buf());
        }
    }

    files.sort();
    files
}