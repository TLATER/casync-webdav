use std::path::{Path, PathBuf};

use futures::StreamExt;
use log::{error, info};
use pretty_env_logger;
use reqwest::Url;
use structopt::StructOpt;

mod ca_index;
mod ca_store;
mod remote_store;

use ca_index::CaIndex;
use ca_store::chunk_path_from_hash;
use remote_store::{pull_chunks, push_chunks, RemoteError, RemoteStore, WebdavStore};

/* CLI parsing */

/// Upload chunks from a casync-based store to a remote webdav host.
#[derive(StructOpt)]
struct Opt {
    /// The store to load chunks from.
    #[structopt(short, long, parse(from_str = parse_directory), default_value = "default.castr/")]
    store: PathBuf,
    /// The client certificate to use for authentication to the remote.
    #[structopt(short = "c", long)]
    client_certificate: Option<PathBuf>,
    /// The user for authentication to the remote.
    #[structopt(short, long, requires("password"))]
    username: Option<String>,
    /// The password to use with the authentication method.
    #[structopt(short, long)]
    password: Option<String>,
    #[structopt(subcommand)]
    cmd: Command,
}

#[derive(StructOpt)]
enum Command {
    /// List the chunks contained in a `.caidx` file
    List {
        /// The index to list
        index: PathBuf,
    },

    /// Push chunks contained in a `.caidx` file to a remote.
    Push {
        /// The index to push.
        index: PathBuf,
        /// The webdav host to upload to.
        webdav_url: Url,
    },

    /// Pull chunks contained in a `.caidx` file from a remote.
    Pull {
        /// The index to pull.
        index: PathBuf,
        /// The webdav host to download from.
        webdav_url: Url,
    },
}

enum Credentials {
    Certificate {
        file: PathBuf,
        password: Option<String>,
    },
    UsernamePassword {
        username: String,
        password: String,
    },
    None,
}

impl Credentials {
    fn create(
        client_certificate: &Option<PathBuf>,
        username: &Option<String>,
        password: &Option<String>,
    ) -> Result<Self, &'static str> {
        match (client_certificate, username, password) {
            (Some(file), _, password) => Ok(Credentials::Certificate {
                file: file.to_path_buf(),
                password: password.as_ref().map(|p| p.to_string()),
            }),
            (_, Some(username), password) => {
                if let Some(password) = password {
                    Ok(Credentials::UsernamePassword {
                        username: username.to_string(),
                        password: password.to_string(),
                    })
                } else {
                    Err("When using username authentication a password must be set")
                }
            }
            (None, None, _) => Ok(Credentials::None),
        }
    }
}

fn parse_directory(dir: &str) -> PathBuf {
    let mut dir = dir.to_string();

    // Rust marks directories with a finishing '/' and will override
    // file names with Path::join, so to prevent unexpected behavior
    // we need to finish any directories in a '/'.
    if !dir.ends_with('/') {
        dir.push('/');
    }

    Path::new(&dir).to_path_buf()
}

/* Main function helpers */

fn read_index_from_file(path: &PathBuf) -> Result<CaIndex, String> {
    let data = match std::fs::read(path) {
        Ok(data) => data,
        Err(err) => {
            return Err(format!(
                "Failed to read index file '{}': {}",
                path.display(),
                err
            ));
        }
    };

    match CaIndex::parse(&data) {
        Ok(index) => Ok(index),
        Err(err) => Err(format!(
            "Failed to parse index file '{}': {}",
            path.display(),
            err
        )),
    }
}

fn make_remote(
    url: &Url,
    credentials: Credentials,
) -> Result<impl RemoteStore + Clone, RemoteError> {
    // For now, only webdav is implemented.
    let mut remote = WebdavStore::new(&url);

    match credentials {
        Credentials::Certificate { file, password } => {
            remote.set_certificate_auth(&file, &password)?;
        }
        Credentials::UsernamePassword { username, password } => {
            remote.set_password_auth(&username, &password)?;
        }
        Credentials::None => {
            remote.set_no_auth();
        }
    }

    Ok(remote)
}

#[tokio::main]
async fn main() {
    pretty_env_logger::init();

    let opt = Opt::from_args();
    match opt.cmd {
        Command::List { index } => {
            match read_index_from_file(&index) {
                Ok(index) => {
                    index.list_chunks().iter().for_each(|chunk| {
                        println!("{}", chunk);
                    });
                }
                Err(err) => {
                    error!("{}", err);
                }
            };
        }
        Command::Push { index, webdav_url } => {
            let store = opt.store.clone();

            let credentials =
                match Credentials::create(&opt.client_certificate, &opt.username, &opt.password) {
                    Ok(credentials) => credentials,
                    Err(err) => {
                        error!("{}", err);
                        return;
                    }
                };

            let index = match read_index_from_file(&index) {
                Ok(index) => index,
                Err(err) => {
                    error!("{}", err);
                    return;
                }
            };

            let mut remote = match make_remote(&webdav_url, credentials) {
                Ok(remote) => remote,
                Err(err) => {
                    error!("{}", err);
                    return;
                }
            };

            let chunks: Vec<PathBuf> = index
                .list_chunks()
                .iter()
                .map(|hash| store.join(chunk_path_from_hash(hash)))
                .collect();

            info!("Creating remote store");
            if let Err(err) = remote.create_store().await {
                error!("Failed to create remote store: {}", err);
            };
            info!("Sending chunks");
            push_chunks(&remote, &chunks)
                .for_each_concurrent(12, |path| {
                    async {
                        let path = path.await;

                        match path {
                            Ok(path) => info!("Sent path {}", path.display()),
                            Err(err) => error!("Failed to send path: {}", err),
                        }
                    }
                })
                .await;

            info!("Sent chunks!");
        }
        Command::Pull { index, webdav_url } => {
            let store = opt.store.clone();

            let credentials =
                match Credentials::create(&opt.client_certificate, &opt.username, &opt.password) {
                    Ok(credentials) => credentials,
                    Err(err) => {
                        error!("{}", err);
                        return;
                    }
                };

            let index = match read_index_from_file(&index) {
                Ok(index) => index,
                Err(err) => {
                    error!("{}", err);
                    return;
                }
            };

            let remote = match make_remote(&webdav_url, credentials) {
                Ok(remote) => remote,
                Err(err) => {
                    error!("{}", err);
                    return;
                }
            };

            let chunks: Vec<PathBuf> = index
                .list_chunks()
                .iter()
                .map(|hash| store.join(chunk_path_from_hash(hash)))
                .collect();

            info!("Downloading chunks");
            pull_chunks(&remote, &chunks)
                .for_each_concurrent(12, |path| {
                    async {
                        let path = path.await;

                        match path {
                            Ok(path) => info!("Sent path {}", path.display()),
                            Err(err) => error!("Failed to pull path: {}", err),
                        }
                    }
                })
                .await;
            info!("Downloaded chunks!");
        }
    }
}
