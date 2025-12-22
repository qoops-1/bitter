use std::{io::SeekFrom, marker::PhantomData, path::{Path, PathBuf}, sync::{atomic::Ordering, Arc}, time::Duration};

use bit_vec::BitVec;
use bytes::{Buf, Bytes, BytesMut};
use sha1::{Digest, Sha1};
use tokio::{
    fs::OpenOptions,
    io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt},
    select,
    time::{self, MissedTickBehavior},
};
use tracing::{info, instrument};

use crate::{
    accounting::Accounting,
    metainfo::{BitterHash, MetainfoFile, MetainfoInfo, PeerId},
    protocol::{Handshake, Packet, TcpConn, DEFAULT_BUF_SIZE},
    utils::{roundup_div, BitterMistake, BitterResult},
};

const MAX_CHUNK_LEN: u32 = u32::pow(2, 16); // 64 KB
const MAX_REQUESTS_INFLIGHT: usize = 5;

#[derive(Clone)]
pub struct PeerParams {
    pub peer_id: PeerId,
    pub metainfo: Arc<MetainfoInfo>,
    pub req_piece_len: u32,
    pub total_len: u64,
    pub start_peer_choked: bool,
    pub output_dir: PathBuf,
}

pub struct PeerHandler<'a, T> {
    acct: Accounting,
    params: &'a PeerParams,
    ptracker: ProgressTracker,
    stats: PeerStats,
    choked: bool,
    peer_choked: bool,
    interested: bool,
    peer_interested: bool,
    // Here just to be able to make peer handler generic, instead of having to declare every method generic. Not sure whether this is a good idea.
    phantom: PhantomData<T>,
}

struct ProgressTracker {
    pub pcs: Vec<PieceInProgress>,
    chunk_len: u32,
    piece_len: u32,
    total_len: u64,
}

#[derive(Debug, PartialEq, Eq)]
struct PieceInProgress {
    index: u32,
    chunks: Vec<ChunkStatus>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ChunkStatus {
    Missing,
    Downloading,
    Present(Bytes),
}

type PieceStatus = Option<Vec<Bytes>>;

// #[instrument(skip(params, acct, stream))]
pub async fn run_peer_handler<T: Unpin + AsyncRead + AsyncWrite>(
    params: PeerParams,
    acct: Accounting,
    stream: T,
) -> BitterResult<()> {
    let mut conn = TcpConn::new(stream, DEFAULT_BUF_SIZE);
    let mut handler = PeerHandler::new(&params, acct);

    conn.write(&Packet::Handshake(Handshake::Bittorrent(
        params.metainfo.hash,
        params.peer_id,
    )))
    .await?;

    let handshake = conn.read_handshake().await?;
    match handshake {
        Handshake::Other => return Err(BitterMistake::new("Handshake failed. Unknown protocol")),
        Handshake::Bittorrent(peer_hash, _) => {
            if peer_hash != params.metainfo.hash {
                return Err(BitterMistake::new("info_hash mismatch"));
            }
            // TODO: ("check peer id")
        }
    }
    let res = handler.run(&mut conn).await;
    conn.close().await;

    res
}

impl ProgressTracker {
    fn download_started(&mut self, index: u32, begin: u32) {
        let piece = match self.pcs.iter_mut().find(|p| p.index == index) {
            Some(p) => p,
            None => {
                let piece_len: u64 = self.piece_len.into();
                let index_u64: u64 = index.into();
                let chunks_per_piece;
                if piece_len * (index_u64 + 1) > self.total_len {
                    let last_piece_size: usize = (self.total_len % piece_len).try_into().unwrap();
                    chunks_per_piece = roundup_div(last_piece_size, self.chunk_len as usize);
                } else {
                    chunks_per_piece = roundup_div(self.piece_len, self.chunk_len) as usize;
                }
                let chunks = vec![ChunkStatus::Missing; chunks_per_piece];

                self.pcs.push(PieceInProgress { index, chunks });
                self.pcs.last_mut().unwrap()
            }
        };

        let chunk_no = (begin / self.chunk_len) as usize;

        piece.chunks[chunk_no] = ChunkStatus::Downloading;
    }

    fn complete_chunk<'b>(
        &mut self,
        index: u32,
        begin: u32,
        data: Bytes,
    ) -> BitterResult<PieceStatus> {
        let chunk_no = (begin / self.chunk_len) as usize;
        let piece_pos_opt = self
            .pcs
            .iter()
            .position(|PieceInProgress { index: i, .. }| *i == index);

        let piece_pos = piece_pos_opt.ok_or(BitterMistake::new_owned(format!(
            "Piece {index} is not being downloaded"
        )))?;
        match self.pcs[piece_pos].chunks[chunk_no] {
            ChunkStatus::Present(_) => {
                return Err(BitterMistake::new_owned(format!(
                    "Piece {index}+{begin} is already received"
                )))
            }
            _ => self.pcs[piece_pos].chunks[chunk_no] = ChunkStatus::Present(data),
        };
        if self.pcs[piece_pos]
            .chunks
            .iter()
            .find(|c| !matches!(c, ChunkStatus::Present(_)))
            .is_some()
        {
            return Ok(None);
        }

        let full_piece: Vec<Bytes> = self
            .pcs
            .remove(piece_pos)
            .chunks
            .into_iter()
            .filter_map(|c| match c {
                ChunkStatus::Present(c) => Some(c),
                _ => None,
            })
            .collect();

        Ok(Some(full_piece))
    }

    fn next_missing_chunk(&self) -> Option<(u32, u32)> {
        for p in &self.pcs {
            for (chunk_no, c) in p.chunks.iter().enumerate() {
                if matches!(c, ChunkStatus::Missing) {
                    return Some((p.index, chunk_no as u32 * self.chunk_len));
                }
            }
        }
        None
    }

    fn reset_downloading(&mut self) {
        for p in &mut self.pcs {
            for c in &mut p.chunks {
                if matches!(c, ChunkStatus::Downloading) {
                    *c = ChunkStatus::Missing;
                }
            }
        }
    }

    fn have_downloads(&self) -> bool {
        !self.pcs.is_empty()
    }
}

#[derive(Default)]
struct PeerStats {
    recv_pieces: usize,
    sent_pieces: usize,
}

impl<'a, T> PeerHandler<'a, T>
where
    T: Unpin + AsyncRead + AsyncWrite,
{
    pub fn new(params: &'a PeerParams, acct: Accounting) -> PeerHandler<'a, T> {
        let ptracker = ProgressTracker {
            pcs: Vec::new(),
            chunk_len: params.req_piece_len,
            piece_len: params.metainfo.piece_length,
            total_len: params.total_len,
        };
        PeerHandler {
            acct,
            params,
            ptracker,
            stats: PeerStats::default(),
            choked: true,
            peer_choked: params.start_peer_choked,
            interested: false,
            peer_interested: false,
            phantom: PhantomData,
        }
    }

    pub async fn run(&mut self, conn: &mut TcpConn<T>) -> BitterResult<()> {
        if !self.peer_choked {
            conn.write(&Packet::Unchoke).await?;
        }

        let mut choking_fibrillation = time::interval(Duration::from_secs(10));
        choking_fibrillation.set_missed_tick_behavior(MissedTickBehavior::Delay);
        choking_fibrillation.reset();

        loop {
            select! {
                _ = choking_fibrillation.tick() => {
                    self.update_peer_choking(conn).await?;
                }
                packet = conn.read() => {
                    let mut needs_request = false;

                    match packet? {
                        Packet::Choke => self.handle_choke(),
                        Packet::Unchoke => self.handle_unchoke(conn).await?,
                        Packet::Interested => self.handle_interested(),
                        Packet::NotInterested => self.handle_not_interested(),
                        Packet::Have(i) => self.handle_have(i, conn).await?,
                        Packet::Bitfield(bitmap) => self.handle_bitfield(bitmap, conn).await?,
                        Packet::Request {
                            index,
                            begin,
                            length,
                        } => self.handle_request(index, begin, length, conn).await?,
                        Packet::Piece { index, begin, data } => {
                            self.handle_piece(index, begin, data).await?;
                            needs_request = true;
                        }
                        Packet::Cancel {
                            index,
                            begin,
                            length,
                        } => self.handle_cancel(index, begin, length),
                        _ => return Err(BitterMistake::new("Received unknown packet")),
                    }
                    if needs_request && !self.choked {
                        let done = self.request_new_piece(conn).await?;
                        if done {
                            return Ok(())
                        }
                    }
                }
            }
        }
    }

    #[instrument(skip(self, conn))]
    async fn update_peer_choking(&mut self, conn: &mut TcpConn<T>) -> BitterResult<()> {
        let tft = self.gives_tit_for_tat();
        if self.peer_choked && self.peer_interested && tft {
            info!("unchoke_peer");
            conn.write(&Packet::Unchoke).await?;
            self.peer_choked = false;
        } else if !self.peer_choked && !tft {
            info!("choke_peer");
            conn.write(&Packet::Choke).await?;
            self.peer_choked = true;
        }

        Ok(())
    }

    #[inline]
    fn gives_tit_for_tat(&self) -> bool {
        self.stats.recv_pieces > 4 && self.stats.recv_pieces >= self.stats.sent_pieces
    }

    #[instrument(skip(self))]
    fn handle_choke(&mut self) {
        self.choked = true;
        // TODO: discard reservations and try to get them again on unchoke
        self.ptracker.reset_downloading();
    }

    #[instrument(skip(self, conn))]
    async fn handle_unchoke(&mut self, conn: &mut TcpConn<T>) -> BitterResult<()> {
        self.choked = false;
        self.ramp_up_piece_requests(conn).await
    }

    #[instrument(skip(self))]
    fn handle_interested(&mut self) {
        self.peer_interested = true;
        // todo!()
    }

    #[instrument(skip(self))]
    fn handle_not_interested(&mut self) {
        self.peer_interested = false;
        // todo!()
    }

    #[instrument(skip(self, conn))]
    async fn handle_have(&mut self, index: u32, conn: &mut TcpConn<T>) -> BitterResult<()> {
        self.acct.mark_available(index as usize);
        if !self.interested && !self.acct.piece_is_reserved(index as usize) {
            self.signal_interested(conn).await?;
        }
        Ok(())
    }

    #[instrument(skip(self, bv, conn))]
    async fn handle_bitfield(&mut self, bv: BitVec, conn: &mut TcpConn<T>) -> BitterResult<()> {
        self.acct.init_available(bv);
        if self.acct.have_next_to_download() {
            assert!(!self.interested);
            self.signal_interested(conn).await?;
        }
        Ok(())
    }

    #[instrument(skip(self, conn))]
    async fn handle_request(
        &mut self,
        piece_no: u32,
        chunk_offset: u32,
        chunk_len: u32,
        conn: &mut TcpConn<T>,
    ) -> BitterResult<()> {
        self.verify_piece(piece_no, chunk_offset, chunk_len)?;
        if chunk_len > MAX_CHUNK_LEN {
            return Err(BitterMistake::new("Requested piece length too long"));
        }

        let chunk = read_chunk(
            piece_no,
            chunk_offset,
            chunk_len,
            self.params.metainfo.piece_length,
            &self.params.metainfo.files,
        )
        .await?;

        
        conn.write(&Packet::Piece {
            index: piece_no,
            begin: chunk_offset,
            data: chunk,
        })
        .await?;

        self.stats.sent_pieces += 1;
        self.acct.up_cnt.fetch_add(1, Ordering::Release);
        Ok(())
    }

    #[instrument(skip(self, data))]
    async fn handle_piece(&mut self, index: u32, begin: u32, data: Bytes) -> BitterResult<()> {
        self.verify_piece(index, begin, data.len() as u32)?;

        if let Some(full_piece) = self.ptracker.complete_chunk(index, begin, data)? {
            // TODO: on hash mismatch re-request piece
            self.verify_hash(index, &full_piece)?;
            save_piece(
                index,
                self.params.metainfo.piece_length,
                &full_piece,
                &self.params.metainfo.files,
                &self.params.output_dir
            )
            .await?;
            self.acct.mark_downloaded(index as usize);
            self.stats.recv_pieces += 1;
        }
        
        Ok(())
    }

    #[instrument(skip(self))]
    fn handle_cancel(&self, _index: u32, _begin: u32, _length: u32) {
        // Nothing to do right now, we're processing requests as they come and must've already sent the piece
    }

    fn verify_hash(&self, index: u32, chunks: &Vec<Bytes>) -> BitterResult<()> {
        let mut digest_state = Sha1::new();
        for chunk in chunks {
            digest_state.update(chunk);
        }
        let digest = BitterHash(digest_state.finalize().into());
        if digest != self.params.metainfo.pieces[index as usize] {
            return Err(BitterMistake::new("Piece hash mismatch"));
        }
        Ok(())
    }

    fn verify_piece(&self, index: u32, begin: u32, length: u32) -> BitterResult<()> {
        let plen = self.params.req_piece_len;

        if index >= self.params.metainfo.pieces.len() as u32 {
            return Err(BitterMistake::new("Piece index out of bounds"));
        }
        if begin + length > self.params.metainfo.piece_length {
            return Err(BitterMistake::new("Received chunk outside of piece bounds"));
        }
        if begin % plen != 0 {
            return Err(BitterMistake::new("Received chunk at weird offset"));
        }

        if length > plen {
            return Err(BitterMistake::new("Received chunk of unexpected size"));
        }

        Ok(())
    }

    #[instrument(skip(self, conn))]
    async fn request_new_piece(&mut self, conn: &mut TcpConn<T>) -> BitterResult<bool> {
        if !self.interested {
            return Ok(false);
        }
        let next_chunk_opt = self
            .ptracker
            .next_missing_chunk()
            .or_else(|| self.acct.get_next_to_download().map(|p| (p as u32, 0)));
        let (index, begin) = match next_chunk_opt {
            Some(next_chunk) => next_chunk,
            None => {
                let done = !self.ptracker.have_downloads();
                return Ok(done);
            }
        };
        let length = self.get_chunk_len(index, begin);

        self.ptracker.download_started(index, begin);
        conn.write(&Packet::Request {
            index,
            begin,
            length,
        })
        .await?;

        Ok(false)
    }

    async fn ramp_up_piece_requests(&mut self, conn: &mut TcpConn<T>) -> BitterResult<()> {
        for _ in 0..MAX_REQUESTS_INFLIGHT {
            self.request_new_piece(conn).await?;
        }
        Ok(())
    }

    async fn signal_interested(&mut self, conn: &mut TcpConn<T>) -> BitterResult<()> {
        info!("send_interested");
        self.interested = true;
        conn.write(&Packet::Interested).await
    }

    async fn signal_not_interested(&mut self, conn: &mut TcpConn<T>) -> BitterResult<()> {
        info!("send_not_interested");
        self.interested = false;
        conn.write(&Packet::NotInterested).await
    }

    fn get_chunk_len(&self, index: u32, begin: u32) -> u32 {
        let piece_len = self.params.metainfo.piece_length;
        let total_pieces = self.params.metainfo.pieces.len() as u32;
        let mut chunk_len = self.params.req_piece_len;
        if begin + chunk_len > piece_len {
            chunk_len = piece_len - begin;
        }
        if index == total_pieces - 1 {
            let index: u64 = index.into();
            let piece_len: u64 = piece_len.into();
            let begin: u64 = begin.into();
            let chunk_len_u64: u64 = chunk_len.into();
            let piece_start = index * piece_len;
            let potential_total_len: u64 = piece_start + (begin + chunk_len_u64);

            if potential_total_len > self.params.total_len {
                let exceeding_len: u32 = (potential_total_len - self.params.total_len)
                    .try_into()
                    .expect("exceeding length must not be larger than u32");
                chunk_len -= exceeding_len;
            }
        }

        chunk_len
    }
}

impl<T> Drop for PeerHandler<'_, T> {
    fn drop(&mut self) {
        for p in &self.ptracker.pcs {
            assert!(!self.acct.piece_is_downloaded(p.index as usize));
            self.acct.mark_not_reserved(p.index as usize);
        }
    }
}

#[instrument(skip(files))]
async fn read_chunk(
    piece_no: u32,
    chunk_offset: u32,
    chunk_len: u32,
    piece_len: u32,
    files: &Vec<MetainfoFile>,
) -> BitterResult<Bytes> {
    let mut fm = match_span_to_files(piece_no, chunk_offset, chunk_len, piece_len, files);
    let mut buf = BytesMut::with_capacity(chunk_len as usize);
    for (path, mut len) in fm.files {
        let mut file = OpenOptions::new()
            .read(true)
            .open(path)
            .await
            .map_err(BitterMistake::new_err)?;

        if fm.offset != 0 {
            file.seek(SeekFrom::Start(fm.offset))
                .await
                .map_err(BitterMistake::new_err)?;
            fm.offset = 0;
        }

        while len > 0 {
            len -= file
                .read_buf(&mut buf)
                .await
                .map_err(BitterMistake::new_err)?;
        }
    }

    info!(event = "chunk_read", piece_no, chunk_offset);
    Ok(buf.freeze())
}

#[instrument(skip(chunks, files))]
// Doesn't care about sizes of chunks, simply determines the files that need to be written via index and meta piece_len, and writes the chunks there sequentially
async fn save_piece(
    index: u32,
    piece_len: u32,
    chunks: &Vec<Bytes>,
    files: &Vec<MetainfoFile>,
    output_dir: &Path,
) -> BitterResult<()> {
    let length = chunks.iter().map(|c| c.remaining() as u32).sum();
    let mut fm = match_span_to_files(index, 0, length, piece_len, files);
    let mut c_no: usize = 0;
    let mut c_offset: usize = 0;
    for (path, mut len) in fm.files {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .mode(0o755)
            .open(output_dir.join(path))
            .await
            .map_err(BitterMistake::new_err)?;

        if fm.offset != 0 {
            file.seek(SeekFrom::Start(fm.offset))
                .await
                .map_err(BitterMistake::new_err)?;
            fm.offset = 0;
        }

        while len > 0 {
            let c_write;
            if chunks[c_no].len() - c_offset > len {
                c_write = &chunks[c_no][c_offset..c_offset + len];
                c_offset += len;
            } else {
                c_write = &chunks[c_no][c_offset..];
                c_no += 1;
                c_offset = 0;
            }
            file.write_all(c_write)
                .await
                .map_err(BitterMistake::new_err)?;
            len -= c_write.len();
        }
    }

    info!(event = "piece_saved", piece_no = index);
    Ok(())
}

fn match_span_to_files(
    index: u32,
    span_offset: u32,
    mut span_length: u32,
    piece_len: u32,
    files: &Vec<MetainfoFile>,
) -> FileMapping<'_> {
    let mut start_found = false;
    let mut bytes_seen = 0;
    let index: u64 = index.into();
    let piece_len: u64 = piece_len.into();
    let span_offset: u64 = span_offset.into();
    let chunk_start = index * piece_len + span_offset;
    let mut res = FileMapping::default();
    for f in files {
        let mut file_len_left = f.length;
        bytes_seen += f.length;

        if !start_found && bytes_seen > chunk_start {
            start_found = true;
            res.offset = chunk_start - (bytes_seen - f.length);
            file_len_left = bytes_seen - chunk_start;
        }

        if !start_found {
            continue;
        }

        let span_length_u64: u64 = span_length.into();
        if span_length_u64 <= file_len_left {
            res.files.push((f.path.as_path(), span_length as usize));
            break;
        }

        res.files.push((f.path.as_path(), file_len_left as usize));

        // cast to u32 should be safe because above we have checked that span_length (u32) > file_len_left
        span_length -= file_len_left as u32;
    }

    res
}

#[derive(Default, PartialEq, Eq, Debug)]
struct FileMapping<'a> {
    offset: u64,
    files: Vec<(&'a Path, usize)>,
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use bytes::Bytes;
    use tempdir::TempDir;
    use tokio::{fs::File, io::AsyncReadExt};

    use crate::{
        metainfo::MetainfoFile,
        peer::{save_piece, ChunkStatus, PieceInProgress},
    };

    use super::{match_span_to_files, FileMapping, ProgressTracker};

    #[test]
    fn identify_ftw_whole_file_test() {
        let f1 = PathBuf::from("f1");
        let f2 = PathBuf::from("f2");

        let files = vec![
            MetainfoFile {
                length: 4,
                path: f1.clone(),
            },
            MetainfoFile {
                length: 5,
                path: f2.clone(),
            },
        ];

        assert_eq!(
            match_span_to_files(0, 0, 4, 4, &files),
            FileMapping {
                offset: 0,
                files: vec![(&f1, 4)],
            }
        );
        assert_eq!(
            match_span_to_files(1, 0, 4, 4, &files),
            FileMapping {
                offset: 0,
                files: vec![(&f2, 4)],
            }
        );
    }

    #[test]
    fn identify_ftw_offset_test() {
        let f1 = PathBuf::from("f1");

        let files = vec![MetainfoFile {
            length: 14,
            path: f1.clone(),
        }];

        assert_eq!(
            match_span_to_files(1, 0, 4, 4, &files),
            FileMapping {
                offset: 4,
                files: vec![(&f1, 4)],
            }
        );
        assert_eq!(
            match_span_to_files(2, 0, 4, 4, &files),
            FileMapping {
                offset: 8,
                files: vec![(&f1, 4)],
            }
        );
    }

    #[test]
    fn identify_ftw_multifile_test() {
        let f1 = PathBuf::from("f1");
        let f2 = PathBuf::from("f2");

        let files = vec![
            MetainfoFile {
                length: 6,
                path: f1.clone(),
            },
            MetainfoFile {
                length: 4,
                path: f2.clone(),
            },
        ];

        assert_eq!(
            match_span_to_files(1, 0, 4, 4, &files),
            FileMapping {
                offset: 4,
                files: vec![(&f1, 2), (&f2, 2)],
            }
        );
    }

    #[test]
    fn identify_ftw_all_files_test() {
        let f1 = PathBuf::from("f1");
        let f2 = PathBuf::from("f2");
        let f3 = PathBuf::from("f3");

        let files = vec![
            MetainfoFile {
                length: 2,
                path: f1.clone(),
            },
            MetainfoFile {
                length: 2,
                path: f2.clone(),
            },
            MetainfoFile {
                length: 4,
                path: f3.clone(),
            },
        ];

        assert_eq!(
            match_span_to_files(0, 0, 7, 7, &files),
            FileMapping {
                offset: 0,
                files: vec![(&f1, 2), (&f2, 2), (&f3, 3)],
            }
        );
    }

    #[tokio::test]
    async fn save_piece_aligned() {
        let plen: usize = 20;
        let tmpdir = TempDir::new("bittertest").unwrap();
        let mut file = tmpdir.path().to_owned();
        file.push("basic_test_file");

        let mut ones_piece: Vec<u8> = vec![1; plen];
        let mut h_piece: Vec<u8> = vec!['h' as u8; plen];

        let files = vec![MetainfoFile {
            length: u64::MAX,
            path: file.clone(),
        }];
        save_piece(
            0,
            plen as u32,
            &vec![Bytes::from(ones_piece.clone())],
            &files,
            &PathBuf::new(),
        )
        .await
        .unwrap();
        let mut written_file = File::open(&file).await.unwrap();
        let mut piece_from_file = Vec::with_capacity(plen);
        written_file
            .read_to_end(&mut piece_from_file)
            .await
            .unwrap();
        assert_eq!(
            ones_piece, piece_from_file,
            "file should be the same as the submitted piece"
        );

        save_piece(1, plen as u32, &vec![Bytes::from(h_piece.clone())], &files, &PathBuf::new())
            .await
            .unwrap();

        written_file = File::open(&file).await.unwrap();
        piece_from_file.clear();
        written_file
            .read_to_end(&mut piece_from_file)
            .await
            .unwrap();
        ones_piece.append(&mut h_piece);
        assert_eq!(
            ones_piece, piece_from_file,
            "file should be the same as the concatenation of submitted pieces"
        );
    }

    #[tokio::test]
    async fn save_piece_multichunk() {
        let plen: usize = 20;
        let tmpdir = TempDir::new("bittertest").unwrap();
        let mut file = tmpdir.path().to_owned();
        file.push("small_piece_test_file");

        let ones_piece: Vec<u8> = vec![1; plen];
        let (ones_piece1, ones_part2) = ones_piece.split_at(plen / 2);
        let (ones_piece2, ones_piece3) = ones_part2.split_at(ones_part2.len() / 3);

        let files = vec![MetainfoFile {
            length: u64::MAX,
            path: file.clone(),
        }];

        save_piece(
            0,
            plen as u32,
            &vec![
                Bytes::copy_from_slice(ones_piece1.clone()),
                Bytes::copy_from_slice(ones_piece2.clone()),
                Bytes::copy_from_slice(ones_piece3.clone()),
            ],
            &files,
            &PathBuf::new()
        )
        .await
        .unwrap();
        let mut written_file = File::open(&file).await.unwrap();
        let mut piece_from_file = Vec::with_capacity(plen);
        written_file
            .read_to_end(&mut piece_from_file)
            .await
            .unwrap();

        assert_eq!(
            ones_piece, piece_from_file,
            "file should be the same as the concatenation of chunks received"
        );
    }

    #[tokio::test]
    async fn save_piece_multiple_files() {
        let plen: usize = 20;
        let tmpdir = TempDir::new("bittertest").unwrap();
        let tmppath = tmpdir.path();
        let mut file1 = tmppath.to_owned();
        file1.push("test_multifile1");
        let mut file2 = tmppath.to_owned();
        file2.push("test_multifile2");
        let mut file3 = tmppath.to_owned();
        file3.push("test_multifile3");

        let files = vec![
            MetainfoFile {
                length: plen as u64 / 2,
                path: file1.clone(),
            },
            MetainfoFile {
                length: plen as u64 / 4,
                path: file2.clone(),
            },
            MetainfoFile {
                length: plen as u64,
                path: file3.clone(),
            },
        ];
        let ones = vec![1 as u8; 10];
        let twos = vec![2 as u8; 5];
        let threes = vec![3 as u8; 5];
        let mut received = ones.clone();
        received.append(&mut twos.clone());
        received.append(&mut threes.clone());
        save_piece(0, plen as u32, &vec![Bytes::from(received)], &files, &PathBuf::new())
            .await
            .unwrap();
        let mut written_file1 = File::open(&file1).await.unwrap();
        let mut written_file2 = File::open(&file2).await.unwrap();
        let mut written_file3 = File::open(&file3).await.unwrap();
        let mut piece_from_file = Vec::with_capacity(plen);
        written_file1
            .read_to_end(&mut piece_from_file)
            .await
            .unwrap();

        assert_eq!(ones, piece_from_file, "first file must contain 1s");

        piece_from_file.clear();
        written_file2
            .read_to_end(&mut piece_from_file)
            .await
            .unwrap();

        assert_eq!(twos, piece_from_file, "second file must contain 2s");

        piece_from_file.clear();
        written_file3
            .read_to_end(&mut piece_from_file)
            .await
            .unwrap();

        assert_eq!(threes, piece_from_file, "third file must contain 3s");
    }

    #[tokio::test]
    async fn save_piece_multichunk_to_multiple_files() {
        let plen: usize = 20;
        let tmpdir = TempDir::new("bittertest").unwrap();
        let tmppath = tmpdir.path();
        let mut file1 = tmppath.to_owned();
        file1.push("test_multifile1");
        let mut file2 = tmppath.to_owned();
        file2.push("test_multifile2");
        let mut file3 = tmppath.to_owned();
        file3.push("test_multifile3");

        let files = vec![
            MetainfoFile {
                length: plen as u64 / 2,
                path: file1.clone(),
            },
            MetainfoFile {
                length: plen as u64 / 4,
                path: file2.clone(),
            },
            MetainfoFile {
                length: plen as u64,
                path: file3.clone(),
            },
        ];
        let ones = vec![1 as u8; 10];
        let twos = vec![2 as u8; 5];
        let threes = vec![3 as u8; 5];
        let chunk1 = ones[..5].to_vec();
        let chunk2 = vec![&ones[5..], &twos[..2]].concat();
        let chunk3 = vec![&twos[2..], &threes].concat();

        save_piece(
            0,
            plen as u32,
            &vec![
                Bytes::from(chunk1),
                Bytes::from(chunk2),
                Bytes::from(chunk3),
            ],
            &files,
            &PathBuf::new()
        )
        .await
        .unwrap();
        let mut written_file1 = File::open(&file1).await.unwrap();
        let mut written_file2 = File::open(&file2).await.unwrap();
        let mut written_file3 = File::open(&file3).await.unwrap();
        let mut piece_from_file = Vec::with_capacity(plen);
        written_file1
            .read_to_end(&mut piece_from_file)
            .await
            .unwrap();

        assert_eq!(ones, piece_from_file, "first file must contain 1s");

        piece_from_file.clear();
        written_file2
            .read_to_end(&mut piece_from_file)
            .await
            .unwrap();

        assert_eq!(twos, piece_from_file, "second file must contain 2s");

        piece_from_file.clear();
        written_file3
            .read_to_end(&mut piece_from_file)
            .await
            .unwrap();

        assert_eq!(threes, piece_from_file, "third file must contain 3s");
    }

    #[test]
    fn first_download_progress_tracking() {
        let mut ptracker = ProgressTracker {
            pcs: Vec::new(),
            chunk_len: 4,
            piece_len: 8,
            total_len: 8,
        };
        ptracker.download_started(0, 0);
        assert_eq!(ptracker.pcs.len(), 1);
        assert_eq!(
            ptracker.pcs[0],
            PieceInProgress {
                index: 0,
                chunks: vec![ChunkStatus::Downloading, ChunkStatus::Missing],
            }
        )
    }

    #[test]
    fn progress_tracking_piece_lifecycle() {
        let mut ptracker = ProgressTracker {
            pcs: Vec::new(),
            chunk_len: 4,
            piece_len: 12,
            total_len: 12,
        };
        let p1 = Bytes::from(vec![1]);
        let p2 = Bytes::from(vec![2]);
        let p3 = Bytes::from(vec![3]);
        ptracker.download_started(0, 4);
        ptracker.download_started(0, 8);
        let p2_status = ptracker.complete_chunk(0, 4, p2.clone()).unwrap();
        assert_eq!(p2_status, None);
        let p3_status = ptracker.complete_chunk(0, 8, p3.clone()).unwrap();
        assert_eq!(p3_status, None);
        ptracker.download_started(0, 0);
        let p1_status = ptracker.complete_chunk(0, 0, p1.clone()).unwrap();
        assert_eq!(p1_status, Some(vec![p1, p2, p3]));
    }

    #[test]
    fn progress_tracking_driven_fetching() {
        let mut ptracker = ProgressTracker {
            pcs: Vec::new(),
            chunk_len: 4,
            piece_len: 8,
            total_len: 16,
        };

        assert_eq!(ptracker.next_missing_chunk(), None);
        ptracker.download_started(0, 0);
        let next_chunk = ptracker.next_missing_chunk();
        let (index, begin) = next_chunk.unwrap();
        assert_eq!((index, begin), (0, 4));
        ptracker.download_started(index, begin);
        assert_eq!(ptracker.next_missing_chunk(), None);

        ptracker.download_started(1, 4);
        let next_chunk = ptracker.next_missing_chunk();
        let (index, begin) = next_chunk.unwrap();
        assert_eq!((index, begin), (1, 0));
        ptracker.download_started(index, begin);
        assert_eq!(ptracker.next_missing_chunk(), None);
    }

    #[test]
    fn progress_tracking_complete_pieces_out_of_order() {
        let mut ptracker = ProgressTracker {
            pcs: Vec::new(),
            chunk_len: 4,
            piece_len: 8,
            total_len: 24,
        };
        let p1 = Bytes::from(vec![1]);
        let p2 = Bytes::from(vec![2]);
        let p3 = Bytes::from(vec![3]);
        let p4 = Bytes::from(vec![4]);
        let p5 = Bytes::from(vec![5]);
        let p6 = Bytes::from(vec![6]);

        ptracker.download_started(0, 0);
        ptracker.download_started(1, 0);
        ptracker.download_started(1, 4);
        ptracker.download_started(2, 4);

        // Just introduce some chaos by marking one piece as complete
        assert_eq!(ptracker.complete_chunk(1, 4, p4.clone()).unwrap(), None);

        let mut missing_chunks = vec![(0, 4), (2, 0)];
        let (index, begin) = ptracker.next_missing_chunk().unwrap();
        assert!(missing_chunks.contains(&(index, begin)));
        missing_chunks.retain(|c| c != &(index, begin));
        ptracker.download_started(index, begin);

        // Complete 2nd piece to introduce more chaos
        assert_eq!(
            ptracker.complete_chunk(1, 0, p3.clone()).unwrap(),
            Some(vec![p3.clone(), p4.clone()])
        );

        let (index, begin) = ptracker.next_missing_chunk().unwrap();
        assert!(missing_chunks.contains(&(index, begin)));
        ptracker.download_started(index, begin);

        // Now, no more chunks can be requested
        assert_eq!(ptracker.next_missing_chunk(), None);

        assert_eq!(ptracker.complete_chunk(0, 0, p1.clone()).unwrap(), None);
        assert_eq!(ptracker.complete_chunk(2, 4, p6.clone()).unwrap(), None);
        assert_eq!(
            ptracker.complete_chunk(0, 4, p2.clone()).unwrap(),
            Some(vec![p1.clone(), p2.clone()])
        );
        assert_eq!(
            ptracker.complete_chunk(2, 0, p5.clone()).unwrap(),
            Some(vec![p5.clone(), p6.clone()])
        );
    }
}
