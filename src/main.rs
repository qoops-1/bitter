mod bencoding;
mod download;
mod utils;
mod metainfo;

use std::{env, fs, process::exit, net::{IpAddr, Ipv4Addr}};
use crate::metainfo::Metainfo;
use bencoding::*;
use download::download;

#[tokio::main]
async fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() != 2 {
        eprint!(
            "Wrong number of arguments. Expected 1, given {}",
            args.len()
        );
        exit(1);
    }
    let filename = &args[1];
    let metafile = fs::read(filename).unwrap_or_else(|e| {
        eprint!("Error opening metadata file {filename}: {e}");
        exit(1)
    });
    let parsed_metainfo: Metainfo = bdecode(&metafile).unwrap_or_else(|e| {
        eprint!("Error parsing metadata file: {e}");
        exit(1)
    });
    println!("Metadata file:");
    print!("{:#?}", parsed_metainfo);

    let settings = Settings {
        port: 6881,
        ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
    };

    download(parsed_metainfo, settings).await.unwrap()
}

pub struct Settings {
    pub port: u16,
    pub ip: IpAddr,
}

