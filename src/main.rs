use std::path::{Path, PathBuf};

use log::info;
use pretty_env_logger;
use reqwest::Url;
use structopt::StructOpt;

mod ca_index;
mod ca_store;
mod remote_store;

use ca_index::CaIndex;
use ca_store::CAStore;
use remote_store::RemoteStore;

/// Upload chunks from a casync-based store to a remote webdav host.
#[derive(StructOpt)]
struct Opt {
    /// The index whose chunks to upload.
    index: PathBuf,
    /// The webdav host to upload to; If unset, chunks will be listed instead.
    webdav_url: Option<Url>,
    /// The store to load chunks from.
    #[structopt(short, long, default_value = "default.castr")]
    store: PathBuf,
    /// The path to upload to on the webdav host.
    #[structopt(short = "r", long, default_value = "/")]
    store_root: PathBuf,
    /// The client certificate to use for authentication to the remote.
    #[structopt(short = "c", long)]
    client_certificate: Option<PathBuf>,
    /// The password for the client certificate.
    #[structopt(short = "k", long)]
    certificate_password: Option<String>,
    /// The user for authentication to the remote.
    #[structopt(short, long)]
    username: Option<String>,
    /// The password to use with the username.
    #[structopt(short, long)]
    password: Option<String>,
}

fn remote_set_auth<'a>(
    remote: &'a mut RemoteStore,
    certificate: Option<PathBuf>,
    cert_password: Option<String>,
    username: Option<String>,
    password: Option<String>,
) -> Result<&'a RemoteStore, Box<dyn std::error::Error>> {
    match (certificate, cert_password, username, password) {
        (Some(certificate), Some(password), _, _) => {
            remote.set_certificate_auth(&certificate, &password)
        }
        (_, _, Some(username), Some(password)) => remote.set_password_auth(&username, &password),
        _ => Ok(remote.set_no_auth()),
    }
}

async fn upload_to_remote(
    remote: &RemoteStore,
    store: &CAStore,
    index: &CaIndex,
    index_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Creating remote store root directory...");
    remote.create_store_directory().await?;

    info!("Reading chunks...");
    let chunks: Vec<(String, PathBuf)> = index
        .list_chunks()
        .iter()
        .map(|hash| (hash.clone(), store.get_chunk_path(&hash)))
        .collect();

    info!("Uploading chunks...");
    remote.send_chunks(&chunks, 12).await?;

    info!("Uploading index...");
    remote.send_index(index_path).await?;

    info!("Done");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opt = Opt::from_args();
    pretty_env_logger::init();

    let store = CAStore::new(&opt.store);
    let index = CaIndex::parse(&std::fs::read(&opt.index)?)?;

    if let Some(url) = opt.webdav_url {
        let mut remote = RemoteStore::new(&url, &opt.store_root);
        let remote = remote_set_auth(
            &mut remote,
            opt.client_certificate,
            opt.certificate_password,
            opt.username,
            opt.password,
        )?;

        upload_to_remote(remote, &store, &index, &opt.index).await?;
    } else {
        for chunk in index.list_chunks() {
            println!("{}", chunk);
        }
    }

    Ok(())
}
