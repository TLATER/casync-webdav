use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::str::FromStr;

use bytes::Bytes;
use crypto::digest::Digest;
use hyper::header;
use log::info;
use reqwest::header::{HeaderName, HeaderValue};
use reqwest::{Client, Identity, Method, StatusCode, Url};
use trait_async::trait_async;

use crate::ca_store::chunk_path_from_hash;
use crate::remote_store::{RemoteError, RemoteStore};

#[derive(Clone)]
pub struct WebdavStore {
    remote_root: Url,
    client: Option<Client>,
}

impl WebdavStore {
    pub fn new(url: &Url) -> Self {
        Self {
            remote_root: url.to_owned(),
            client: None,
        }
    }

    pub fn set_no_auth(&mut self) -> &Self {
        let client = Client::new();
        self.client = Some(client);
        self
    }

    pub fn set_password_auth(
        &mut self,
        username: &str,
        password: &str,
    ) -> Result<&Self, RemoteError> {
        let client = Client::builder();

        let auth_header = get_basic_auth_header(&username, &password)?;
        let mut headers = header::HeaderMap::new();
        headers.insert(auth_header.0, auth_header.1);

        let client = client.default_headers(headers).build()?;

        self.client = Some(client);
        Ok(self)
    }

    pub fn set_certificate_auth(
        &mut self,
        certificate: &Path,
        password: &Option<String>,
    ) -> Result<&Self, RemoteError> {
        let client = Client::builder();

        let identity = get_identity(certificate, password)?;
        let client = client.identity(identity).build()?;

        self.client = Some(client);
        Ok(self)
    }

    fn abspath(&self, path: &Path) -> Url {
        self.remote_root
            .join(path.to_str().expect("Invalid UTF-8 in casync store"))
            .expect("This should always be a valid URL")
    }

    fn client(&self) -> &Client {
        match &self.client {
            Some(client) => client,
            None => panic!("Using uninitialized RemoteStore"),
        }
    }

    async fn create_path_recursively(&self, path: &Path) -> Result<(), reqwest::Error> {
        let mut failed_paths = vec![];

        // We create the ancestors in turn. Unfortunately there is no
        // recursive MKCOL, so we need to walk backwards and create
        // paths with missing parents - this is done to minimize the
        // number of HTTP requests required.
        for dir in path.ancestors() {
            let res = self.create_dir_if_not_exists(dir).await;
            match res {
                Ok(_) => {
                    // This path exists now. Start creating its
                    // children we failed to create.
                    break;
                }
                Err(e) => {
                    if let Some(StatusCode::CONFLICT) = e.status() {
                        // The parent does not exist, we'll need to
                        // revisit it later.
                        failed_paths.push(dir);
                    } else {
                        // Something actually went wrong.
                        return Err(e);
                    }
                }
            }
        }

        for dir in failed_paths {
            self.create_dir_if_not_exists(dir).await?;
        }

        Ok(())
    }

    /// Create a directory in the remote store if it does not exist.
    ///
    /// The given path will be created relative to the store root. If
    /// the path is "", the store root will be created.
    ///
    /// This will return true if the directory did not exist and was
    /// created, false otherwise.
    ///
    /// # Errors
    ///
    /// Errors encountered during the http request, except 405, will
    /// be returned. 405 errors are assumed to mean "the directory
    /// already exists".
    ///
    /// # Panics
    ///
    /// This method will panic if the path contains invalid UTF-8
    /// characters, or if the resulting URL is invalid. This should
    /// never happen in practice with casync stores.
    ///
    async fn create_dir_if_not_exists(&self, path: &Path) -> Result<bool, reqwest::Error> {
        let response = self
            .client()
            .request(
                Method::from_str("MKCOL").expect("MKOL should be a valid method"),
                self.abspath(path),
            )
            .send()
            .await?;

        if response.status() != StatusCode::METHOD_NOT_ALLOWED {
            response.error_for_status()?;
            Ok(false)
        } else {
            info!(
                "Directory '{}' already exists on the remote.",
                path.to_string_lossy()
            );
            Ok(true)
        }
    }

    async fn push_file(&self, path: &Url, file: Bytes) -> Result<(), reqwest::Error> {
        self.client()
            .put(path.clone())
            .body(file.to_vec())
            .send()
            .await?
            .error_for_status()?;

        Ok(())
    }

    async fn pull_file(&self, path: &Url) -> Result<Bytes, reqwest::Error> {
        let res = self
            .client()
            .get(path.clone())
            .send()
            .await?
            .error_for_status()?;

        Ok(res.bytes().await?)
    }
}

#[trait_async]
impl RemoteStore for WebdavStore {
    async fn create_store(&mut self) -> Result<(), RemoteError> {
        Ok(self
            .create_path_recursively(Path::new("default.castr/"))
            .await?)
    }

    async fn has_chunk(&self, hash: &str) -> Result<bool, RemoteError> {
        let chunk_path = Path::new("default.castr/").join(chunk_path_from_hash(hash));

        let res = self.client().head(self.abspath(&chunk_path)).send().await?;

        Ok(res.status().is_success())
    }

    async fn send_chunk(&mut self, hash: &str, data: Bytes) -> Result<(), RemoteError> {
        let chunk_path = Path::new("default.castr/").join(chunk_path_from_hash(hash));
        let url = self.abspath(&chunk_path);

        let res = self.push_file(&url, data.clone()).await;
        if let Err(e) = res {
            // If we lack parent directories, try to create them and
            // re-send.
            if let Some(StatusCode::NOT_FOUND) = e.status() {
                self.create_path_recursively(
                    chunk_path
                        .parent()
                        .expect("This path should always have a parent"),
                )
                .await?;

                // This time, we don't ignore any errors
                self.push_file(&url, data).await?;
            } else {
                return Err(e.into());
            }
        }

        Ok(())
    }

    async fn pull_chunk(&self, hash: &str) -> Result<Bytes, RemoteError> {
        let chunk_path = Path::new("default.castr/").join(chunk_path_from_hash(hash));
        let url = self.abspath(&chunk_path);

        let res = self.pull_file(&url).await?;

        Ok(res)
    }
}

fn get_basic_auth_header(
    username: &str,
    password: &str,
) -> Result<(HeaderName, HeaderValue), RemoteError> {
    let auth_string = format!(
        "Basic {}",
        base64::encode(format!("{}:{}", username, password))
    );

    match header::HeaderValue::from_str(&auth_string) {
        Ok(value) => Ok((header::AUTHORIZATION, value)),
        Err(error) => Err(RemoteError::Authentication {
            error: Box::new(error),
        }),
    }
}

fn get_identity(certificate: &Path, password: &Option<String>) -> Result<Identity, RemoteError> {
    let mut cert = Vec::new();
    File::open(certificate)?.read_to_end(&mut cert)?;

    match password {
        Some(password) => Identity::from_pkcs12_der(&cert, password),
        None => Identity::from_pem(&cert),
    }
    .map_err(|err| RemoteError::Authentication {
        error: Box::new(err),
    })
}
