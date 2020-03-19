use std::fs::read;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use log::info;
use reqwest::header;
use reqwest::{Client, Identity, Method, StatusCode, Url};

pub struct RemoteStore {
    store_root: Url,
    client: Option<Client>,
}

impl RemoteStore {
    pub fn new(webdav_root: Url, store_path: &Path) -> Self {
        Self {
            store_root: webdav_root
                .join(&store_path.to_string_lossy())
                .expect("This can only be an invalid URL if the store path is invalid"),
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
    ) -> Result<&Self, Box<dyn std::error::Error>> {
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
        password: &str,
    ) -> Result<&Self, Box<dyn std::error::Error>> {
        let client = Client::builder();

        let identity = get_identity(certificate, password)?;
        let client = client.identity(identity).build()?;

        self.client = Some(client);
        Ok(self)
    }

    /// Create the default.castr store directory.
    ///
    /// This should be called at least once before every other store
    /// operation. There is no guarantee that the store directory
    /// remains existing, so technically we should account for this,
    /// however doing so in practice can be very slow on high-latency
    /// networks.
    ///
    /// # Errors
    ///
    /// Errors encountered during the http request will be passed on.
    ///
    pub async fn create_store_directory(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.create_dir_if_not_exists(Path::new("")).await?;
        self.create_dir_if_not_exists(Path::new("default.castr"))
            .await?;
        Ok(())
    }

    /// Check if the remote store contains the given chunk.
    ///
    /// Returns true if so, false otherwise.
    ///
    /// # Errors
    ///
    /// This will return an error if the http request fails.
    ///
    pub async fn has_chunk(&self, sha: &str) -> Result<bool, Box<dyn std::error::Error>> {
        let res = self
            .client()
            .head(self.abspath(&chunk_path(sha)))
            .send()
            .await?;
        Ok(res.status().is_success())
    }

    /// Send a chunk to the remote store.
    ///
    /// Any necessary parent directories will be created automatically.
    ///
    /// # Arguments
    ///
    /// sha: The sha of the chunk.
    /// path: The path of the file to upload as a chunk.
    ///
    /// # Errors
    ///
    /// This will return an error if reading the path fails or any of
    /// the http requests fail.
    ///
    /// # Panics
    ///
    /// This should never panic, unless the casync store is corrupted.
    ///
    pub async fn send_chunk(
        &self,
        sha: &str,
        path: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let body = read(path)?;
        let remote_path = chunk_path(sha);

        let res = self.push_file(&remote_path, body.clone()).await;
        if let Err(e) = res {
            // If we lack parent directories, try to create them and
            // re-send.
            if let Some(StatusCode::NOT_FOUND) = e.status() {
                self.create_path_recursively(
                    remote_path
                        .parent()
                        .expect("This path should always have a parent"),
                )
                .await?;

                // This time, we don't ignore any errors
                self.push_file(&remote_path, body).await?;
            } else {
                return Err(e.into());
            }
        }

        info!("Sent chunk {}", sha);

        Ok(())
    }

    /// Send a .caidx file to the remote.
    ///
    pub async fn send_index(&self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let file = read(path)?;
        let name = Path::new(path.file_name().expect("This must be a valid filename"));

        self.push_file(name, file).await?;
        Ok(())
    }

    fn client(&self) -> &Client {
        if let Some(client) = &self.client {
            client
        } else {
            panic!("Using uninitialized RemoteStore");
        }
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

    /// Create a path recursively.
    ///
    /// This will ensure that a path exists on the remote, at least
    /// for the duration of the request. None of this is possible to
    /// do atomically, so failures can be expected even after this
    /// method is called.
    ///
    /// # Errors
    ///
    /// See [`create_dir_if_not_exists`]: #create_dir_if_not_exists.errors.
    ///
    /// # Panics
    ///
    /// See [`create_dir_if_not_exists`]: #create_dir_if_not_exists.panics.
    ///
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

    /// Push a given set of bytes as a file.
    ///
    /// # Errors
    ///
    /// Errors encountered during the http request will be returned.
    ///
    /// # Panics
    ///
    /// This method will panic if the path contains invalid UTF-8
    /// characters, or if the resulting URL is invalid. This should
    /// never happen in practice with casync stores.
    ///
    async fn push_file(&self, path: &Path, file: Vec<u8>) -> Result<(), reqwest::Error> {
        self.client()
            .put(self.abspath(path))
            .body(file)
            .send()
            .await?
            .error_for_status()?;

        Ok(())
    }

    fn abspath(&self, path: &Path) -> Url {
        self.store_root
            .join(path.to_str().expect("Invalid UTF-8 in casync store"))
            .expect("This should always be a valid URL")
    }
}

fn chunk_path(sha: &str) -> PathBuf {
    let path_string = format!("default.castr/{}/{}.cacnk", &sha[..4], sha);
    Path::new(&path_string).to_path_buf()
}

fn get_identity(
    certificate: &Path,
    password: &str,
) -> Result<Identity, Box<dyn std::error::Error>> {
    // let identity = Identity::from_pkcs12_der(&buf, "");

    unimplemented!()
}

fn get_basic_auth_header(
    username: &str,
    password: &str,
) -> Result<(header::HeaderName, header::HeaderValue), Box<dyn std::error::Error>> {
    let auth_string = format!(
        "Basic {}",
        base64::encode(format!("{}:{}", username, password))
    );
    dbg!(&auth_string);
    let value = header::HeaderValue::from_str(&auth_string)?;
    Ok((header::AUTHORIZATION, value))
}
