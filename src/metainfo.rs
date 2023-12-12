use std::convert::identity;
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use std::str;

use serde::Serialize;
use sha1::{Digest, Sha1};

use crate::bencoding::*;
use crate::utils::{BitterMistake, BitterResult};

pub const BITTORRENT_HASH_LEN: usize = 20;
pub const BITTORRENT_PEERID_LEN: usize = 20;

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitterHash(pub [u8; BITTORRENT_HASH_LEN]);

impl Deref for BitterHash {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for BitterHash {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Serialize for BitterHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(unsafe { str::from_utf8_unchecked(&self.0) })
    }
}

impl TryFrom<&[u8]> for BitterHash {
    type Error = BitterMistake;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        value
            .try_into()
            .map(BitterHash)
            .map_err(BitterMistake::new_err)
    }
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerId(pub [u8; BITTORRENT_PEERID_LEN]);

impl Serialize for PeerId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(unsafe { str::from_utf8_unchecked(&self.0) })
    }
}

impl Deref for PeerId {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for PeerId {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl TryFrom<&[u8]> for PeerId {
    type Error = BitterMistake;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        value.try_into().map(PeerId).map_err(BitterMistake::new_err)
    }
}

#[derive(Debug)]
pub struct Metainfo {
    pub announce_list: Vec<Vec<String>>,
    pub info: MetainfoInfo,
}

impl BDecode for Metainfo {
    fn bdecode(benc: &BencodedValue) -> BitterResult<Self> {
        let dict = benc.try_into_dict()?;
        let announce_list_tiers: Vec<&BencodedValue> = dict
            .get_val("announce_list")
            .and_then(|l| l.try_into_list())
            .ok()
            .map(|tier| tier.iter().collect::<Vec<_>>())
            .unwrap_or_default();

        let mut announce_list: Vec<Vec<String>> = announce_list_tiers
            .into_iter()
            .map(|tier| {
                tier.try_into_list()
                    .map(|l| l.iter())
                    .unwrap_or_default()
                    .map(|tracker| tracker.try_into_string().map(str::to_owned))
                    .collect::<BitterResult<Vec<_>>>()
            })
            .collect::<BitterResult<Vec<_>>>()
            .unwrap_or_default();
        if announce_list.is_empty() {
            let announce = dict.get_val("announce")?.try_into_string()?.to_owned();

            announce_list.push(vec![announce]);
        }
        let info = dict.get_val("info")?;

        Ok(Metainfo {
            announce_list,
            info: MetainfoInfo::bdecode(info)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct MetainfoInfo {
    pub name: String,
    pub piece_length: u32,
    pub pieces: Vec<BitterHash>,
    pub files: Vec<MetainfoFile>,
    pub hash: BitterHash,
}

impl BDecode for MetainfoInfo {
    fn bdecode(benc: &BencodedValue) -> BitterResult<Self> {
        let dict = benc.try_into_dict()?;

        let buf_ptr = dict.get_start_ptr();
        let name = dict.get_val("name")?.try_into_string()?.to_owned();
        let piece_length = dict.get_val("piece length")?.try_into_u32()?.to_owned();
        let pieces_all: Vec<u8> = dict.get_val("pieces")?.try_into_bytestring()?.to_owned();

        if pieces_all.len() % BITTORRENT_HASH_LEN != 0 {
            return Err(BitterMistake::new_owned(format!(
                "Incorrect size of \"pieces\" hash: {}",
                pieces_all.len()
            )));
        }
        let pieces: Vec<BitterHash> = pieces_all
            .chunks_exact(BITTORRENT_HASH_LEN)
            .map(|slc| slc.try_into().expect("hash size mismatch"))
            .collect();

        let single_file = dict
            .get_val("length")
            .and_then(|v| v.try_into_u64())
            .map(|l| MetainfoFile {
                length: l,
                path: PathBuf::from(name.clone()),
            });
        let hash = BitterHash(Sha1::digest(buf_ptr).into());

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

#[derive(Debug, Clone)]
pub struct MetainfoFile {
    pub length: u64,
    pub path: PathBuf,
}

impl BDecode for MetainfoFile {
    fn bdecode(benc: &BencodedValue) -> BitterResult<Self> {
        let dict = benc.try_into_dict()?;
        let length = dict.get_val("length")?.try_into_u64()?.to_owned();
        let path = PathBuf::from_iter(
            dict.get_val("path")?
                .try_into_list()?
                .iter()
                .map(|v| v.try_into_string())
                .collect::<BitterResult<Vec<_>>>()?,
        );

        Ok(MetainfoFile { length, path })
    }
}
