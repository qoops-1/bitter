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
        let announce = dict.get_key("announce")?.try_into_string()?;
        let info = dict.get_key("info")?;

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
    files: Vec<MetainfoFile>,
}

impl BDecode for MetainfoInfo {
    fn bdecode(benc: &BencodedValue) -> Result<Self, String> {
        let dict = benc.try_into_dict()?;
        let name = dict.get_key("name")?.try_into_string()?;
        let piece_length = dict.get_key("piece_length")?.try_into_int()?;
        let pieces = dict.get_key("pieces")?.try_into_string()?;
        let single_file = dict.get_key("length")
            .and_then(|v| v.try_into_int())
            .map(|l| MetainfoFile { length: l, path: Vec::new() });

        let files: = match single_file {
            Ok(single_file) => vec![single_file],
            err => {
                dict.get_key("files")?.try_into_list()?.into_iter().map(|f| MetainfoFile::bdecode(&f)).collect()?
            },
        };


        Ok(MetainfoInfo {
            name,
            piece_length,
            pieces,
            files
        })
    }
}

#[derive(Debug)]
struct MetainfoFile {
    length: i64,
    path: Vec<String>,
}

impl BDecode for MetainfoFile {
    fn bdecode(benc: &BencodedValue) -> Result<Self, String> {
        unimplemented!()
    }
}
