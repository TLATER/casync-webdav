use std::path::{Path, PathBuf};

use log::info;
use pretty_env_logger;
use reqwest::Url;
use structopt::StructOpt;

mod ca_index;
mod ca_store;
mod remote_store;

use ca_store::CAStore;
use remote_store::RemoteStore;

#[derive(StructOpt)]
struct Opt {
    index: PathBuf,
    store: PathBuf,
    webdav_url: Url,
    store_path: PathBuf,
    #[structopt(short = "c", long)]
    client_certificate: Option<PathBuf>,
    #[structopt(short = "k", long)]
    certificate_password: Option<String>,
    #[structopt(short, long)]
    username: Option<String>,
    #[structopt(short, long)]
    password: Option<String>,
}

async fn upload_to_remote(
    remote: &RemoteStore,
    store: &CAStore,
    index: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Creating remote store root directory...");
    remote.create_store_directory().await?;

    info!("Uploading chunks...");
    for chunk in store.get_chunks() {
        if !remote.has_chunk(chunk.get_hash()).await.unwrap() {
            remote.send_chunk(chunk.get_hash(), chunk.get_path()).await?;
        }
    }

    info!("Uploading index...");
    remote.send_index(index).await?;

    info!("Done");

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opt = Opt::from_args();
    pretty_env_logger::init();

    let store = ca_store::CAStore::new(opt.store);

    let mut remote = RemoteStore::new(opt.webdav_url, &opt.store_path);
    if let (Some(certificate), Some(password)) = (opt.client_certificate, opt.certificate_password)
    {
        let remote = remote.set_certificate_auth(&certificate, &password);
        upload_to_remote(remote?, &store, &opt.index).await?;
    } else if let (Some(username), Some(password)) = (opt.username, opt.password) {
        let remote = remote.set_password_auth(&username, &password);
        upload_to_remote(remote?, &store, &opt.index).await?;
    } else {
        let remote = remote.set_no_auth();
        upload_to_remote(remote, &store, &opt.index).await?;
    }

    Ok(())
}
