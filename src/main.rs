mod accounting;
mod bencoding;
mod download;
mod metainfo;
mod protocol;
mod utils;

use crate::metainfo::Metainfo;
use bencoding::*;
use download::download;
use std::{
    env, fs,
    net::{IpAddr, Ipv4Addr},
    process::exit,
};

fn main() {
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

    download(parsed_metainfo, settings).unwrap()
}

#[derive(Clone)]
pub struct Settings {
    pub port: u16,
    pub ip: IpAddr,
}
