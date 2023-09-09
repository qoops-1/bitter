use sha1::{Digest, Sha1};

use crate::bencoding::*;
use crate::utils::BitterResult;

#[derive(Debug)]
pub struct Metainfo {
    pub announce: String,
    pub info: MetainfoInfo,
}

impl BDecode for Metainfo {
    fn bdecode(benc: &BencodedValue) -> BitterResult<Self> {
        let dict = benc.try_into_dict()?;
        let announce = dict.get_val("announce")?.try_into_string()?.to_owned();
        let info = dict.get_val("info")?;

        Ok(Metainfo {
            announce,
            info: MetainfoInfo::bdecode(info)?,
        })
    }
}

#[derive(Debug)]
struct MetainfoInfo {
    pub name: String,
    pub piece_length: i64,
    pub pieces: Vec<u8>,
    pub files: Vec<MetainfoFile>,
    pub hash: Vec<u8>,
}

impl BDecode for MetainfoInfo {
    fn bdecode(benc: &BencodedValue) -> BitterResult<Self> {
        let dict = benc.try_into_dict()?;

        let buf_ptr = dict.get_start_ptr();
        let name = dict.get_val("name")?.try_into_string()?.to_owned();
        let piece_length = dict.get_val("piece length")?.try_into_int()?.to_owned();
        let pieces: Vec<u8> = dict.get_val("pieces")?.try_into_bytestring()?.to_owned();
        let single_file = dict
            .get_val("length")
            .and_then(|v| v.try_into_int())
            .map(|l| MetainfoFile {
                length: l.to_owned(),
                path: Vec::new(),
            });
        let hash = Sha1::digest(buf_ptr).to_vec();

        let files = match single_file {
            Ok(single_file) => vec![single_file],
            _ => dict
                .get_val("files")?
                .try_into_list()?
                .into_iter()
                .map(|f| MetainfoFile::bdecode(&f))
                .collect::<BitterResult<Vec<_>>>()?,
        };

        Ok(MetainfoInfo {
            name,
            piece_length,
            pieces,
            files,
            hash,
        })
    }
}

#[derive(Debug)]
struct MetainfoFile {
    pub length: i64,
    pub path: Vec<String>,
}

impl BDecode for MetainfoFile {
    fn bdecode(benc: &BencodedValue) -> BitterResult<Self> {
        let dict = benc.try_into_dict()?;
        let length = dict.get_val("length")?.try_into_int()?.to_owned();
        let path: Vec<String> = dict
            .get_val("path")?
            .try_into_list()?
            .into_iter()
            .map(|v| v.try_into_string().map(str::to_owned))
            .collect::<BitterResult<Vec<_>>>()?;

        Ok(MetainfoFile { length, path })
    }
}
