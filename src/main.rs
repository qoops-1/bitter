mod bencoding;

use std::io::Cursor;

use bencoding::*;

fn main() {
    println!("Hello, world!");
}

#[derive(Debug)]
struct Metainfo {
    announce: String,
    info: MetainfoInfo,
}

fn bdecode<T : BDecode>(s: &str) -> Result<T, String> {
    let mut c = Cursor::new(s);
    let bencoded = bdecode_any(&mut c)?;

    T::bdecode(&bencoded)
}

impl BDecode for Metainfo {
    fn bdecode(benc: &BencodedValue) -> Result<Self, String> {
        let dict = benc.try_into_dict()?;
        let announce = dict.get("announce").ok_or("Required field not found")?.try_into_string()?;
        let info = dict.get("info").ok_or("Required field not found")?;

        Ok(Metainfo {
            announce,
            info: MetainfoInfo::bdecode(info)?,
        })
    }
}

#[derive(Debug)]
struct MetainfoInfo {
    name: String,
    piece_length: i64,
    pieces: String,
    files: Box<[MetainfoFile]>,
    length: u64,
}

impl BDecode for MetainfoInfo {
    fn bdecode(benc: &BencodedValue) -> Result<Self, String> {
        let dict = benc.try_into_dict()?;
        let name = dict.get("name").ok_or("Required field not found")?.try_into_string()?;
        let piece_length = dict.get("piece_length").ok_or("Required field not found")?.try_into_int()?;

        Ok(MetainfoInfo {
            name,
            info: MetainfoInfo::bdecode(info)?,
        })
    }
}

#[derive(Debug)]
struct MetainfoFile {
    length: u64,
    path: Box<[String]>,
}
