mod accounting;
mod bencoding;
mod download;
mod metainfo;
mod peer;
mod protocol;
mod utils;

use crate::metainfo::Metainfo;
use bencoding::*;
use download::download;
use metainfo::MetainfoFile;
use std::{
    env,
    fs::{self, DirBuilder, File},
    net::{IpAddr, Ipv4Addr},
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    process::exit,
};
use utils::{BitterMistake, BitterResult};

#[derive(Clone)]
pub struct Settings {
    pub port: u16,
    pub ip: IpAddr,
}

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
        eprintln!("Error opening metadata file {filename}: {e}");
        exit(1)
    });
    let parsed_metainfo: Metainfo = bdecode(&metafile).unwrap_or_else(|e| {
        eprintln!("Error parsing metadata file: {e}");
        exit(1)
    });
    println!("Metadata file:");
    print!("{:#?}", parsed_metainfo);

    let settings = Settings {
        port: 6881,
        ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
    };

    setup_dirs(&parsed_metainfo.info.files).unwrap_or_else(|e| {
        eprintln!("Error creating dirs and files for the torrent: {e}");
        exit(1)
    });

    download(parsed_metainfo, settings).unwrap()
}

fn setup_dirs(files: &Vec<MetainfoFile>) -> BitterResult<()> {
    let mut dir_builder = DirBuilder::new();
    dir_builder.recursive(true).mode(0o755);
    for MetainfoFile { length, path } in files {
        let file = PathBuf::from_iter(path);
        if let Some(dir) = file.parent() {
            dir_builder.create(dir).map_err(BitterMistake::new_err)?;
        }

        File::create(file).map_err(BitterMistake::new_err)?;
    }
    Ok(())
}
