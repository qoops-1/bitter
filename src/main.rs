mod bencoding;
mod download;
mod utils;
mod metainfo;

use std::{env, fs, process::exit};
use crate::metainfo::Metainfo;
use bencoding::*;

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
    let parsed_file: Metainfo = bdecode(&metafile).unwrap_or_else(|e| {
        eprint!("Error parsing metadata file: {e}");
        exit(1)
    });
    println!("Metadata file:");
    print!("{:#?}", parsed_file);
}

