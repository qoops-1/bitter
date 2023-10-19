use std::{convert::identity, sync::Arc};

use bit_vec::BitVec;
use sha1::{Digest, Sha1};
use tokio::net::TcpStream;

use crate::{
    accounting::Accounting,
    metainfo::{Hash, MetainfoInfo, PeerId},
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

pub struct PeerHandler {
    conn: TcpConn,
    acct: Accounting,
    params: DownloadParams,
    in_progress: Vec<PieceInProgress>,
}
struct PieceInProgress {
    index: u32,
    chunks: Vec<Option<Vec<u8>>>,
}

impl PeerHandler {
    pub async fn init(
        params: DownloadParams,
        acct: Accounting,
        stream: TcpStream,
    ) -> BitterResult<PeerHandler> {
        let mut conn = TcpConn::new(stream);

        conn.write(&Packet::Handshake(Handshake::Bittorrent(
            &params.info_hash,
            &params.peer_id,
        )))
        .await?;

        let handshake = conn.read_handshake().await?;
        match handshake {
            Handshake::Other => {
                return Err(BitterMistake::new("Handshake failed. Unknown protocol"))
            }
            Handshake::Bittorrent(peer_hash, peer_id) => {
                if *peer_hash != params.info_hash {
                    return Err(BitterMistake::new("info_hash mismatch"));
                }
                // TODO: ("check peer id")
            }
        }

        let in_progress = Vec::new();
        Ok(PeerHandler {
            conn,
            acct,
            params,
            in_progress,
        })
    }

    pub async fn run(&mut self) -> BitterResult<()> {
        loop {
            let packet = self.conn.read().await?;

            match packet {
                Packet::Piece {
                    index: i,
                    begin,
                    data,
                } => unimplemented!(),
                Packet::Bitfield(bitmap) => self.handle_bitfield(bitmap),
                _ => unimplemented!(),
            }
        }
    }

    fn handle_bitfield(&mut self, bv: BitVec) {
        self.acct.init_available(bv);
    }

    async fn handle_piece<'a>(
        &mut self,
        index: u32,
        begin: u32,
        data: &'a [u8],
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

    async fn save_piece<'a>(&self, index: u32, chunks: &Vec<&Vec<u8>>) -> BitterResult<()> {
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

    fn verify_piece<'a>(&self, index: u32, begin: u32, data: &'a [u8]) -> BitterResult<()> {
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
