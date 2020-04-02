use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use bytes::Bytes;
use trait_async::trait_async;

use crate::remote_store::{RemoteError, RemoteStore};

#[derive(Clone)]
pub struct DummyStore {
    chunks: Option<Arc<RwLock<HashMap<String, Vec<u8>>>>>,
}

impl DummyStore {
    pub fn new() -> Self {
        Self { chunks: None }
    }

    pub fn get_chunks(&self) -> HashMap<String, Vec<u8>> {
        self.chunks()
            .read()
            .expect("Poisoned lock in dummy store")
            .clone()
    }

    pub fn set_chunks(&self, source: &HashMap<String, Vec<u8>>) {
        for (hash, chunk) in source {
            self.chunks()
                .write()
                .expect("Poisoned lock in dummy store")
                .insert(hash.to_string(), chunk.to_vec());
        }
    }

    fn chunks(&self) -> &Arc<RwLock<HashMap<String, Vec<u8>>>> {
        match &self.chunks {
            Some(chunks) => chunks,
            None => panic!("Using uninitialized dummy store"),
        }
    }
}

#[trait_async]
impl RemoteStore for DummyStore {
    async fn create_store(&mut self) -> Result<(), RemoteError> {
        self.chunks = Some(Arc::new(RwLock::new(HashMap::new())));
        Ok(())
    }

    async fn has_chunk(&self, hash: &str) -> Result<bool, RemoteError> {
        Ok(self
            .chunks()
            .read()
            .expect("Poisoned lock in dummy store")
            .contains_key(hash))
    }

    async fn send_chunk(&mut self, hash: &str, data: Bytes) -> Result<(), RemoteError> {
        self.chunks()
            .write()
            .expect("Poisoned lock in dummy store")
            .insert(hash.to_string(), data.to_vec());
        Ok(())
    }

    async fn pull_chunk(&self, hash: &str) -> Result<Bytes, RemoteError> {
        match self
            .chunks()
            .read()
            .expect("Poisoned lock in dummy store")
            .get(hash)
        {
            Some(data) => Ok(Bytes::from(data.clone())),
            None => Err(RemoteError::NoSuchChunk {
                hash: hash.to_string(),
            }),
        }
    }
}
