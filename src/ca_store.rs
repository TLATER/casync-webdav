use std::path::{Path, PathBuf};

use snafu::Snafu;

#[derive(Debug, Snafu)]
pub enum StoreError {
    /// This error is returned when we are asked to operate on a path
    /// that is not valid inside a casync store; e.g. when it contains
    /// anything that is not a valid chunk name.
    #[snafu(display("Invalid store path: '{}'", path.to_string_lossy()))]
    InvalidStorePath { path: PathBuf },
}

pub fn chunk_path_from_hash(hash: &str) -> PathBuf {
    let path_string = format!("{}/{}.cacnk", &hash[..4], hash);
    Path::new(&path_string).to_path_buf()
}

pub fn hash_from_chunk_path(path: &Path) -> Result<&str, StoreError> {
    path.file_stem()
        .ok_or(StoreError::InvalidStorePath {
            path: path.to_path_buf(),
        })?
        .to_str()
        .ok_or(StoreError::InvalidStorePath {
            path: path.to_path_buf(),
        })
}
