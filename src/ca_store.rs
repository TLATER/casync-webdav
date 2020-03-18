use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct CAChunk {
    path: PathBuf,
    hash: String,
}

impl CAChunk {
    pub fn from_path(path: PathBuf) -> Result<CAChunk, Box<dyn std::error::Error>> {
        if let Some(hash) = path.clone().file_stem() {
            if let Some(hash) = hash.to_str() {
                Ok(CAChunk {
                    path: path.canonicalize()?,
                    hash: hash.to_string(),
                })
            } else {
                Err(format!(
                    "Invalid utf-8 in cacnk path name: {}",
                    path.to_string_lossy()
                )
                .into())
            }
        } else {
            Err(format!("Invalid cacnk path: {}", path.to_string_lossy()).into())
        }
    }

    pub fn get_hash(&self) -> &str {
        &self.hash
    }

    pub fn get_path(&self) -> &Path {
        &self.path
    }
}

pub struct CAStore {
    path: PathBuf,
}

impl CAStore {
    pub fn new(path: PathBuf) -> CAStore {
        CAStore { path }
    }

    pub fn get_chunks(self: &Self) -> Vec<CAChunk> {
        self.path
            .read_dir()
            .unwrap()
            .flat_map(|chunk_collection| {
                chunk_collection
                    .unwrap()
                    .path()
                    .read_dir()
                    .unwrap()
                    .map(|chunk| CAChunk::from_path(chunk.unwrap().path()).unwrap())
            })
            .collect()
    }
}
