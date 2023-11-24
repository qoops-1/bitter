use std::{
    fs::{self, DirBuilder, File},
    net::IpAddr,
    os::unix::fs::DirBuilderExt,
};

use bencoding::*;
use download::download;
use metainfo::{Metainfo, MetainfoFile};
use utils::{BitterMistake, BitterResult};

pub mod accounting;
pub mod bencoding;
mod download;
pub mod metainfo;
pub mod peer;
pub mod protocol;
pub mod utils;

#[derive(Clone)]
pub struct Settings {
    pub port: u16,
    pub ip: IpAddr,
    pub req_piece_len: u32,
}

pub fn run(filename: &str, settings: Settings) -> BitterResult<()> {
    let metafile = fs::read(filename).map_err(BitterMistake::new_err)?;
    let parsed_metainfo: Metainfo = bdecode(&metafile)?;
    println!("Metadata file:");
    print!("{:#?}", parsed_metainfo);

    // setup_dirs(&parsed_metainfo.info.files)?;
    download(parsed_metainfo, settings)
}

fn setup_dirs(files: &Vec<MetainfoFile>) -> BitterResult<()> {
    let mut dir_builder = DirBuilder::new();
    dir_builder.recursive(true).mode(0o755);
    for MetainfoFile {
        length: _,
        path: file,
    } in files
    {
        if let Some(dir) = file.parent() {
            dir_builder.create(dir).map_err(BitterMistake::new_err)?;
        }

        File::create(file).map_err(BitterMistake::new_err)?;
    }
    Ok(())
}
