use std::mem::size_of;
use std::path::PathBuf;

use sha1::{Digest, Sha1};

use crate::bencoding::*;
use crate::utils::{BitterMistake, BitterResult};

pub type Hash = [u8; 20];
pub type PeerId = [u8; 20];
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
pub struct MetainfoInfo {
    pub name: String,
    pub piece_length: u32,
    pub pieces: Vec<Hash>,
    pub files: Vec<MetainfoFile>,
    pub hash: Hash,
}

impl BDecode for MetainfoInfo {
    fn bdecode(benc: &BencodedValue) -> BitterResult<Self> {
        let dict = benc.try_into_dict()?;

        let buf_ptr = dict.get_start_ptr();
        let name = dict.get_val("name")?.try_into_string()?.to_owned();
        let piece_length = dict.get_val("piece length")?.try_into_u32()?.to_owned();
        let pieces_all: Vec<u8> = dict.get_val("pieces")?.try_into_bytestring()?.to_owned();

        if pieces_all.len() % size_of::<Hash>() != 0 {
            return Err(BitterMistake::new_owned(format!(
                "Incorrect size of \"pieces\" hash: {}",
                pieces_all.len()
            )));
        }
        let pieces: Vec<Hash> = pieces_all
            .chunks_exact(size_of::<Hash>())
            .map(|slc| slc.try_into().expect("hash size mismatch"))
            .collect();

        let single_file = dict
            .get_val("length")
            .and_then(|v| v.try_into_u32())
            .map(|l| MetainfoFile {
                length: l,
                path: PathBuf::new(),
            });
        let hash: Hash = Sha1::digest(buf_ptr).into();

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
pub struct MetainfoFile {
    pub length: u32,
    pub path: PathBuf,
}

impl BDecode for MetainfoFile {
    fn bdecode(benc: &BencodedValue) -> BitterResult<Self> {
        let dict = benc.try_into_dict()?;
        let length = dict.get_val("length")?.try_into_u32()?.to_owned();
        let path = PathBuf::from_iter(
            dict.get_val("path")?
                .try_into_list()?
                .into_iter()
                .map(|v| v.try_into_string())
                .collect::<BitterResult<Vec<_>>>()?,
        );

        Ok(MetainfoFile { length, path })
    }
}
