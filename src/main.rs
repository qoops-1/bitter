use std::error::Error;

fn main() {
    println!("Hello, world!");
}

fn b_decode<T: BDecode>(s: &str) -> T {
    T::decode(s)
}

trait BDecode: Sized {
    fn decode(s: &str) -> Result<Self, Box<dyn Error>>;
}

impl BDecode for Metainfo {
    fn decode(s: &str) -> Result<Metainfo, Box<dyn Error>> {}
}

struct Metainfo {
    announce: String,
    info: MetainfoInfo,
}

struct MetainfoInfo {
    name: String,
    piece_length: u64,
    pieces: String,
    files: Box<[MetainfoFile]>,
    length: u64,
}

struct MetainfoFile {
    length: u64,
    path: Box<[String]>,
}
