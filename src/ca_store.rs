use std::path::{Path, PathBuf};

pub struct CAStore {
    path: PathBuf,
}

impl CAStore {
    pub fn new(path: &Path) -> CAStore {
        CAStore {
            path: path.to_path_buf(),
        }
    }

    fn chunk_path(&self, hash: &str) -> PathBuf {
        let subdir: String = hash.chars().take(4).collect();
        let chunk_path = format!("{}/{}.cacnk", subdir, hash);
        Path::new(&chunk_path).to_path_buf()
    }

    pub fn get_chunk_path(&self, hash: &str) -> PathBuf {
        self.chunk_path(hash)
    }

    fn get_chunk_paths(self: &Self) -> Result<Vec<PathBuf>, std::io::Error> {
        Ok(self
            .path
            .read_dir()?
            .flat_map(|chunk_collection| -> Result<Vec<PathBuf>, std::io::Error> {
                chunk_collection?
                    .path()
                    .read_dir()?
                    .map(|chunk| Ok(chunk?.path()))
                    .collect()
            })
            .flatten()
            .collect())
    }

    pub fn list_chunks(self: &Self) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        self.get_chunk_paths()?
            .iter()
            .map(|chunk| {
                Ok(chunk
                    .file_stem()
                    .ok_or_else(|| format!("Invalid chunk path: '{:?}'", chunk))?
                    .to_str()
                    .ok_or_else(|| format!("Invalid chunk path: '{:?}'", chunk))?
                    .to_string())
            })
            .collect()
    }
}
