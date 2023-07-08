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

fn bdecode<'a, T: BDecode>(s: &'a str) -> ParsingResult<'a, T> {
    let mut c = Cursor::new(s);
    let bencoded = bdecode_any(&mut c)?;

    if c.get_ref().len() > c.position() as usize {
        return Err(ParsingError::new("unparsed trailing data"));
    }
    T::bdecode(&bencoded)
}

impl BDecode for Metainfo {
    fn bdecode<'a>(benc: &BencodedValue<'a>) -> ParsingResult<'a, Self> {
        let dict = benc.try_into_dict()?;
        let announce = dict.get_key("announce")?.try_into_string()?.to_owned();
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
    fn bdecode<'a>(benc: &BencodedValue<'a>) -> ParsingResult<'a, Self> {
        let dict = benc.try_into_dict()?;
        let name = dict.get_key("name")?.try_into_string()?.to_owned();
        let piece_length = dict.get_key("piece_length")?.try_into_int()?.to_owned();
        let pieces = dict.get_key("pieces")?.try_into_string()?.to_owned();
        let single_file = dict
            .get_key("length")
            .and_then(|v| v.try_into_int())
            .map(|l| MetainfoFile {
                length: l.to_owned(),
                path: Vec::new(),
            });

        let files = match single_file {
            Ok(single_file) => vec![single_file],
            _ => dict
                .get_key("files")?
                .try_into_list()?
                .into_iter()
                .map(|f| MetainfoFile::bdecode(&f))
                .collect::<ParsingResult<Vec<_>>>()?,
        };

        Ok(MetainfoInfo {
            name,
            piece_length,
            pieces,
            files,
        })
    }
}

#[derive(Debug)]
struct MetainfoFile {
    length: i64,
    path: Vec<String>,
}

impl BDecode for MetainfoFile {
    fn bdecode<'a>(benc: &BencodedValue<'a>) -> ParsingResult<'a, Self> {
        let dict = benc.try_into_dict()?;
        let length = dict.get_key("length")?.try_into_int()?.to_owned();
        let path: Vec<String> = dict
            .get_key("path")?
            .try_into_list()?
            .into_iter()
            .map(|v| v.try_into_string().map(str::to_owned))
            .collect::<ParsingResult<Vec<_>>>()?;

        Ok(MetainfoFile { length, path })
    }
}
