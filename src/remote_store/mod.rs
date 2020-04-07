use std::fs::{create_dir_all, File};
use std::io::{Read, Write};
use std::path::PathBuf;

use bytes::Bytes;
use futures::{stream, StreamExt};
use snafu::Snafu;
use trait_async::trait_async;

use crate::ca_store::{hash_from_chunk_path, StoreError};

mod webdav_store;
pub use webdav_store::WebdavStore;

#[derive(Debug, Snafu)]
pub enum RemoteError {
    #[snafu(display("Could not process chunk: {}", error))]
    InvalidChunkPath { error: Box<dyn std::error::Error> },
    #[snafu(display("Failed to authenticate: {}", error))]
    Authentication { error: Box<dyn std::error::Error> },
    #[snafu(display("Failed to make request: {}", error))]
    Request { error: reqwest::Error },
    #[snafu(display("Chunk request failed for chunk: {}", hash))]
    ChunkRequest { hash: String, error: reqwest::Error },
    #[snafu(display("Could not find chunk with hash '{}' on the remote", hash))]
    NoSuchChunk { hash: String },
    #[snafu(display("Remote content for chunk '{}' had invalid hash '{}", chunk, hash))]
    InvalidChunkHash { chunk: String, hash: String },
}

impl From<std::io::Error> for RemoteError {
    fn from(error: std::io::Error) -> Self {
        Self::InvalidChunkPath {
            error: Box::new(error),
        }
    }
}

impl From<StoreError> for RemoteError {
    fn from(error: StoreError) -> Self {
        Self::InvalidChunkPath {
            error: Box::new(error),
        }
    }
}

impl From<reqwest::Error> for RemoteError {
    fn from(error: reqwest::Error) -> Self {
        Self::Request { error }
    }
}

#[trait_async]
pub trait RemoteStore {
    async fn create_store(&mut self) -> Result<(), RemoteError>;
    async fn has_chunk(&self, hash: &str) -> Result<bool, RemoteError>;
    async fn send_chunk(&mut self, hash: &str, data: Bytes) -> Result<(), RemoteError>;
    async fn pull_chunk(&self, hash: &str) -> Result<Bytes, RemoteError>;
}

pub fn push_chunks<'a>(
    remote: &'a (impl RemoteStore + Clone),
    chunks: &'a [PathBuf],
) -> impl StreamExt<Item = impl std::future::Future<Output = Result<PathBuf, RemoteError>> + 'a> {
    stream::iter(chunks.to_vec()).map(move |path| {
        let mut remote = remote.clone();

        async move {
            let hash = hash_from_chunk_path(&path)?;

            if !remote.has_chunk(hash).await? {
                let mut data = Vec::new();
                let mut f = File::open(&path)?;
                f.read_to_end(&mut data)?;

                remote.send_chunk(&hash, Bytes::from(data)).await?;
            }

            Ok::<PathBuf, RemoteError>(path)
        }
    })
}

pub fn pull_chunks<'a>(
    remote: &'a (impl RemoteStore + Clone),
    chunks: &'a [PathBuf],
) -> impl StreamExt<Item = impl std::future::Future<Output = Result<PathBuf, RemoteError>> + 'a> {
    stream::iter(chunks.to_vec()).map(move |path| {
        let remote = remote.clone();

        async move {
            let hash = hash_from_chunk_path(&path)?;
            let data = remote.pull_chunk(&hash).await?;

            create_dir_all(
                path.parent()
                    .expect("Chunks always have a parent directory"),
            )?;
            let mut f = File::create(&path)?;
            f.write_all(&data)?;

            Ok::<PathBuf, RemoteError>(path)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;
    use std::fs::File;
    use std::io::Write;

    use assert_fs::prelude::*;
    use assert_fs::TempDir;
    use crypto::digest::Digest;
    use crypto::sha2::Sha256;
    use futures::executor::block_on;

    use crate::ca_store::chunk_path_from_hash;

    mod dummy_store;
    use dummy_store::DummyStore;

    fn hash(input: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.input(input);
        hasher.result_str()
    }

    #[test]
    fn test_sending_chunks() {
        let tempdir = TempDir::new().unwrap();

        let chunks: HashMap<String, Vec<u8>> = vec![
            b"Technically these should be catar files but it doesn't matter".to_vec(),
            b"At least, at the moment".to_vec(),
        ]
        .iter()
        .map(|chunk| (hash(chunk), chunk.to_vec()))
        .collect();

        let chunk_paths: Vec<PathBuf> = chunks
            .iter()
            .map(|(hash, chunk)| {
                let file = tempdir.child(chunk_path_from_hash(&hash));
                file.touch().unwrap();
                let mut f = File::create(file.path()).unwrap();
                f.write_all(chunk).unwrap();
                file.path().to_path_buf()
            })
            .collect();

        let mut remote = DummyStore::new();
        match block_on(remote.create_store()) {
            Ok(_) => {}
            Err(err) => panic!("{}", err),
        };
        block_on(
            push_chunks(&remote, &chunk_paths).for_each_concurrent(None, |path| {
                async {
                    let path = path.await;

                    match path {
                        Ok(path) => println!("Sent path {}", path.display()),
                        Err(err) => panic!("Failed to send path: {}", err),
                    }
                }
            }),
        );

        assert_eq!(remote.get_chunks(), chunks);
    }

    #[test]
    fn test_pulling_chunks() {
        let tempdir = TempDir::new().unwrap();

        let chunks: HashMap<String, Vec<u8>> = vec![
            b"Technically these should be catar files but it doesn't matter".to_vec(),
            b"At least, at the moment".to_vec(),
        ]
        .iter()
        .map(|chunk| (hash(chunk), chunk.to_vec()))
        .collect();

        let mut remote = DummyStore::new();
        block_on(remote.create_store()).unwrap();
        remote.set_chunks(&chunks);

        let chunk_paths: Vec<PathBuf> = chunks
            .iter()
            .map(|(hash, chunk)| {
                let file = tempdir.child(chunk_path_from_hash(&hash));
                file.touch().unwrap();
                let mut f = File::create(file.path()).unwrap();
                f.write_all(chunk).unwrap();
                file.path().to_path_buf()
            })
            .collect();

        block_on(
            pull_chunks(&remote, &chunk_paths).for_each_concurrent(None, |path| {
                async {
                    match path.await {
                        Ok(path) => println!("Pulled path {}", path.display()),
                        Err(err) => panic!("Failed to pull path: {}", err),
                    }
                }
            }),
        );

        assert_eq!(
            remote.get_chunks(),
            chunk_paths
                .iter()
                .map(|path| {
                    let mut file = File::open(path).expect("Failed to open expected file");
                    let mut chunk = Vec::new();
                    file.read_to_end(&mut chunk)
                        .expect("Failed to read expected file");

                    (hash_from_chunk_path(path).unwrap().to_string(), chunk)
                })
                .collect()
        );
    }
}
