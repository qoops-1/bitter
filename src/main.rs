mod bencoding;

use bencoding::BDecode;

fn main() {
    println!("Hello, world!");
}

#[derive(Debug)]
struct Metainfo {
    announce: String,
    info: MetainfoInfo,
}

impl BDecode for Metainfo {
    fn bdecode(s: &str) -> Result<Self, String> {
        unimplemented!()
    }
}

#[derive(Debug)]
struct MetainfoInfo {
    name: String,
    piece_length: u64,
    pieces: String,
    files: Box<[MetainfoFile]>,
    length: u64,
}

#[derive(Debug)]
struct MetainfoFile {
    length: u64,
    path: Box<[String]>,
}
