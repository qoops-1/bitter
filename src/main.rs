mod bencoding;

use std::{env, fs, io::Cursor, process::exit};

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

#[derive(Debug)]
struct Metainfo {
    announce: String,
    info: MetainfoInfo,
}

fn bdecode<'a, T: BDecode>(s: &'a [u8]) -> ParsingResult<'a, T> {
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
    pieces: Vec<u8>,
    files: Vec<MetainfoFile>,
}

impl BDecode for MetainfoInfo {
    fn bdecode<'a>(benc: &BencodedValue<'a>) -> ParsingResult<'a, Self> {
        let dict = benc.try_into_dict()?;
        let name = dict.get_key("name")?.try_into_string()?.to_owned();
        let piece_length = dict.get_key("piece length")?.try_into_int()?.to_owned();
        let pieces: Vec<u8> = dict.get_key("pieces")?.try_into_bytestring()?.to_owned();
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
