use std::{
    convert::identity,
    io::SeekFrom,
    path::{Path, PathBuf},
    sync::Arc,
};

use bit_vec::BitVec;
use sha1::{Digest, Sha1};
use tokio::{
    fs::{File, OpenOptions},
    io::{AsyncSeekExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::{
    accounting::Accounting,
    metainfo::{Hash, MetainfoFile, MetainfoInfo, PeerId},
    protocol::{Handshake, Packet, TcpConn},
    utils::{roundup_div, BitterMistake, BitterResult},
};

const CHUNK_LEN: u32 = u32::pow(2, 15); // 32 KB
const MAX_PIECE_SIZE: u32 = u32::pow(2, 17); // 128 KB

#[derive(Clone)]
pub struct DownloadParams {
    pub peer_id: PeerId,
    pub info_hash: Hash,
    pub metainfo: Arc<MetainfoInfo>,
}

pub struct PeerHandler<'a> {
    acct: Accounting,
    params: &'a DownloadParams,
    in_progress: Vec<PieceInProgress>,
}
struct PieceInProgress {
    index: u32,
    chunks: Vec<Option<Vec<u8>>>,
}

impl<'a> PeerHandler<'a> {
    pub fn new(params: &'a DownloadParams, acct: Accounting) -> PeerHandler {
        let in_progress = Vec::new();
        PeerHandler {
            acct,
            params,
            in_progress,
        }
    }

    pub async fn run(&mut self, conn: &mut TcpConn) -> BitterResult<()> {
        loop {
            let packet = conn.read().await?;

            match packet {
                Packet::Piece { index, begin, data } => {
                    self.handle_piece(index, begin, data).await?
                }
                Packet::Bitfield(bitmap) => self.handle_bitfield(bitmap),
                _ => unimplemented!(),
            }
        }
    }

    fn handle_bitfield(&mut self, bv: BitVec) {
        self.acct.init_available(bv);
    }

    async fn handle_piece<'b>(
        &mut self,
        index: u32,
        begin: u32,
        data: &'b [u8],
    ) -> BitterResult<()> {
        self.verify_piece(index, begin, data)?;

        let chunk_no = (begin / CHUNK_LEN) as usize;
        let piece_pos_opt = self
            .in_progress
            .iter_mut()
            .position(|PieceInProgress { index: i, .. }| *i == index);

        let piece_pos = match piece_pos_opt.map(|i| (i, &mut self.in_progress[i])) {
            Some((i, piece)) => match piece.chunks[chunk_no] {
                Some(_) => {
                    return Err(BitterMistake::new_owned(format!(
                        "Piece {index}+{begin} is already received"
                    )))
                }
                None => {
                    piece.chunks[chunk_no] = Some(data.to_owned());
                    Ok(i)
                }
            },
            None => {
                let mut chunks = Vec::with_capacity(roundup_div(
                    self.params.metainfo.piece_length,
                    CHUNK_LEN,
                ) as usize);
                chunks.fill(None);
                chunks.insert(chunk_no, Some(data.to_owned()));
                let req = PieceInProgress { index, chunks };
                self.in_progress.push(req);

                Ok(self.in_progress.len() - 1)
            }
        }?;
        if self.in_progress[piece_pos].chunks.contains(&None) {
            return Ok(());
        }

        let full_piece = self.in_progress.remove(piece_pos);

        let done_chunks: Vec<&Vec<u8>> = full_piece
            .chunks
            .iter()
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        self.verify_hash(index, &done_chunks)?;
        self.save_piece(index, &done_chunks).await
    }

    async fn save_piece(&self, index: u32, chunks: &Vec<&Vec<u8>>) -> BitterResult<()> {
        let mut ftow = identify_files_to_write(
            index,
            self.params.metainfo.piece_length,
            &self.params.metainfo,
        );
        let mut c_no: usize = 0;
        let mut c_offset: usize = 0;
        for (path, mut len) in ftow.files {
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .mode(0o755)
                .open(path)
                .await
                .map_err(BitterMistake::new_err)?;

            if ftow.offset != 0 {
                file.seek(SeekFrom::Start(ftow.offset.into()))
                    .await
                    .map_err(BitterMistake::new_err)?;
                ftow.offset = 0;
            }

            while len > 0 {
                let c_write;
                if chunks[c_no].len() > c_offset + len as usize {
                    c_write = &chunks[c_no][c_offset..c_offset + len as usize];
                    c_offset += len;
                } else {
                    c_write = &chunks[c_no][c_offset..];
                    c_no += 1;
                }
                file.write_all(c_write)
                    .await
                    .map_err(BitterMistake::new_err)?;
                len -= c_write.len();
            }
        }
        Ok(())
    }

    fn verify_hash(&self, index: u32, chunks: &Vec<&Vec<u8>>) -> BitterResult<()> {
        let mut digest_state = Sha1::new();
        for chunk in chunks {
            digest_state.update(chunk);
        }
        let digest = Hash::from(digest_state.finalize());
        if digest != self.params.metainfo.pieces[index as usize] {
            return Err(BitterMistake::new("Piece hash mismatch"));
        }
        Ok(())
    }

    fn verify_piece<'b>(&self, index: u32, begin: u32, data: &'b [u8]) -> BitterResult<()> {
        if index >= self.params.metainfo.pieces.len() as u32 {
            return Err(BitterMistake::new("Piece index out of bounds"));
        }
        if begin + CHUNK_LEN > self.params.metainfo.piece_length {
            return Err(BitterMistake::new("Received chunk outside of piece bounds"));
        }
        if begin % CHUNK_LEN != 0 {
            return Err(BitterMistake::new("Received chunk at weird offset"));
        }

        if data.len() as u32 > CHUNK_LEN {
            return Err(BitterMistake::new("Received chunk of unexpected size"));
        }

        Ok(())
    }
}

fn identify_files_to_write(index: u32, len: u32, meta: &MetainfoInfo) -> FilesToWrite {
    let mut start_found = false;
    let mut bytes_seen = 0;
    let mut bytes_to_write = len;
    let chunk_start = index * len;
    let mut res = FilesToWrite::default();
    for f in &meta.files {
        let mut write_len = f.length;
        bytes_seen += f.length;

        if !start_found && bytes_seen > chunk_start {
            start_found = true;
            res.offset = chunk_start - (bytes_seen - f.length);
            write_len = bytes_seen - chunk_start;
        }

        if !start_found {
            continue;
        }

        if bytes_to_write <= write_len {
            res.files.push((f.path.as_path(), bytes_to_write as usize));
            break;
        }

        res.files.push((f.path.as_path(), write_len as usize));
        bytes_to_write -= write_len;
    }

    res
}

#[derive(Default)]
struct FilesToWrite<'a> {
    offset: u32,
    files: Vec<(&'a Path, usize)>,
}
