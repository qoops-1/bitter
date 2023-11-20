use std::{io::SeekFrom, marker::PhantomData, path::Path, sync::Arc};

use bit_vec::BitVec;
use bytes::{Buf, Bytes, BytesMut};
use sha1::{Digest, Sha1};
use tokio::{
    fs::OpenOptions,
    io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt},
};

use crate::{
    accounting::Accounting,
    metainfo::{Hash, MetainfoFile, MetainfoInfo, PeerId},
    protocol::{Handshake, Packet, TcpConn, DEFAULT_BUF_SIZE},
    utils::{roundup_div, BitterMistake, BitterResult},
};

const MAX_CHUNK_LEN: u32 = u32::pow(2, 16); // 64 KB
const MAX_REQUESTS_INFLIGHT: usize = 5;

#[derive(Clone)]
pub struct DownloadParams {
    pub peer_id: PeerId,
    pub metainfo: Arc<MetainfoInfo>,
    pub req_piece_len: usize,
    pub last_chunk_size: u32,
}

pub struct PeerHandler<'a, T> {
    acct: Accounting,
    params: &'a DownloadParams,
    ptracker: ProgressTracker,
    choked: bool,
    peer_choked: bool,
    interested: bool,
    peer_interested: bool,
    // Here just to be able to make peer handler generic, instead of having to declare every method generic. Not sure whether this is a good idea.
    phantom: PhantomData<T>,
}

struct ProgressTracker {
    pcs: Vec<PieceInProgress>,
    chunk_len: usize,
    piece_len: u32,
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

impl ProgressTracker {
    fn download_started(&mut self, index: u32, begin: u32) {
        let piece = match self.pcs.iter_mut().find(|p| p.index == index) {
            Some(p) => p,
            None => {
                let chunks_per_piece = roundup_div(self.piece_len, self.chunk_len as u32) as usize;
                let chunks = vec![ChunkStatus::Missing; chunks_per_piece];

                self.pcs.push(PieceInProgress { index, chunks });
                self.pcs.last_mut().unwrap()
            }
        };

        let chunk_no = begin as usize / self.chunk_len;

        piece.chunks[chunk_no] = ChunkStatus::Downloading;
    }

    fn complete_chunk<'b>(
        &mut self,
        index: u32,
        begin: u32,
        data: Bytes,
    ) -> BitterResult<PieceStatus> {
        let chunk_len = self.chunk_len;
        let chunk_no = begin as usize / chunk_len;
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
                    return Some((p.index, (chunk_no * self.chunk_len) as u32));
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
}

impl<'a, T> PeerHandler<'a, T>
where
    T: Unpin + AsyncRead + AsyncWrite,
{
    pub fn new(params: &'a DownloadParams, acct: Accounting) -> PeerHandler<T> {
        let ptracker = ProgressTracker {
            pcs: Vec::new(),
            chunk_len: params.req_piece_len,
            piece_len: params.metainfo.piece_length,
        };
        PeerHandler {
            acct,
            params,
            ptracker,
            choked: true,
            peer_choked: true,
            interested: false,
            peer_interested: false,
            phantom: PhantomData,
        }
    }

    pub async fn run(&mut self, conn: &mut TcpConn<T>) -> BitterResult<()> {
        loop {
            let packet = conn.read().await?;
            let mut needs_request = false;
            println!("received packet {:?}", packet);

            match packet {
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
                self.request_new_piece(conn).await?;
            }
        }
    }

    fn handle_choke(&mut self) {
        self.choked = true;
        // TODO: discard reservations and try to get them again on unchoke
        self.ptracker.reset_downloading();
    }

    async fn handle_unchoke(&mut self, conn: &mut TcpConn<T>) -> BitterResult<()> {
        self.choked = false;
        self.ramp_up_piece_requests(conn).await
    }

    fn handle_interested(&mut self) {
        self.peer_interested = true;
        // todo!()
    }

    fn handle_not_interested(&mut self) {
        self.peer_interested = false;
        // todo!()
    }

    async fn handle_have(&mut self, index: u32, conn: &mut TcpConn<T>) -> BitterResult<()> {
        self.acct.mark_available(index as usize);
        if !self.interested && !self.acct.piece_is_reserved(index as usize) {
            self.signal_interested(conn).await?;
        }
        Ok(())
    }

    async fn handle_bitfield(&mut self, bv: BitVec, conn: &mut TcpConn<T>) -> BitterResult<()> {
        self.acct.init_available(bv);
        if self.acct.have_next_to_download() {
            assert!(!self.interested);
            self.signal_interested(conn).await?;
        }
        Ok(())
    }

    async fn handle_request(
        &self,
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
            &self.params.metainfo.files,
        )
        .await?;

        conn.write(&Packet::Piece {
            index: piece_no,
            begin: chunk_offset,
            data: chunk,
        })
        .await
    }

    async fn handle_piece(&mut self, index: u32, begin: u32, data: Bytes) -> BitterResult<()> {
        self.verify_piece(index, begin, data.len() as u32)?;

        if let Some(full_piece) = self.ptracker.complete_chunk(index, begin, data)? {
            // TODO: on hash mismatch re-request piece
            self.verify_hash(index, &full_piece)?;
            save_piece(
                index,
                self.params.req_piece_len,
                &full_piece,
                &self.params.metainfo.files,
            )
            .await?;
            self.acct.mark_downloaded(index as usize);
        }
        Ok(())
    }

    fn handle_cancel(&self, _index: u32, _begin: u32, length: u32) {
        // Nothing to do right now, we're processing requests as they come and must've already sent the piece
    }

    fn verify_hash(&self, index: u32, chunks: &Vec<Bytes>) -> BitterResult<()> {
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

    fn verify_piece<'b>(&self, index: u32, begin: u32, length: u32) -> BitterResult<()> {
        let plen = self.params.req_piece_len as u32;

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

    async fn request_new_piece(&mut self, conn: &mut TcpConn<T>) -> BitterResult<()> {
        if !self.interested {
            return Ok(());
        }
        let next_chunk_opt = self
            .ptracker
            .next_missing_chunk()
            .or_else(|| self.acct.get_next_to_download().map(|p| (p as u32, 0)));
        let (index, begin) = match next_chunk_opt {
            Some(next_chunk) => next_chunk,
            None => {
                self.interested = false;
                return conn.write(&Packet::NotInterested).await;
            }
        };

        self.ptracker.download_started(index, begin);
        let mut length = self.params.req_piece_len as u32;
        if index == self.params.metainfo.pieces.len() as u32
            && self.params.metainfo.piece_length == begin + self.params.req_piece_len as u32
        {
            length = self.params.last_chunk_size;
        }
        conn.write(&Packet::Request {
            index,
            begin,
            length,
        })
        .await
    }

    async fn ramp_up_piece_requests(&mut self, conn: &mut TcpConn<T>) -> BitterResult<()> {
        for _ in 0..MAX_REQUESTS_INFLIGHT {
            self.request_new_piece(conn).await?;
        }
        Ok(())
    }

    async fn signal_interested(&mut self, conn: &mut TcpConn<T>) -> BitterResult<()> {
        self.interested = true;
        conn.write(&Packet::Interested).await
    }
}

async fn read_chunk(
    piece_no: u32,
    chunk_offset: u32,
    chunk_len: u32,
    files: &Vec<MetainfoFile>,
) -> BitterResult<Bytes> {
    let mut fm = identify_files(piece_no, chunk_offset, chunk_len as usize, files);
    let mut buf = BytesMut::with_capacity(chunk_len as usize);
    for (path, mut len) in fm.files {
        let mut file = OpenOptions::new()
            .read(true)
            .open(path)
            .await
            .map_err(BitterMistake::new_err)?;

        if fm.offset != 0 {
            file.seek(SeekFrom::Start(fm.offset.into()))
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

    Ok(buf.freeze())
}

// Doesn't care about sizes of chunks, simply determines the files that need to be written via index and meta piece_len, and writes the chunks there sequentially
async fn save_piece(
    index: u32,
    piece_len: usize,
    chunks: &Vec<Bytes>,
    files: &Vec<MetainfoFile>,
) -> BitterResult<()> {
    let mut fm = identify_files(index, 0, piece_len, files);
    let mut c_no: usize = 0;
    let mut c_offset: usize = 0;
    for (path, mut len) in fm.files {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .mode(0o755)
            .open(path)
            .await
            .map_err(BitterMistake::new_err)?;

        if fm.offset != 0 {
            file.seek(SeekFrom::Start(fm.offset.into()))
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
    Ok(())
}

fn identify_files(
    index: u32,
    chunk_offset: u32,
    piece_len: usize,
    files: &Vec<MetainfoFile>,
) -> FileMapping {
    let mut start_found = false;
    let mut bytes_seen = 0;
    let mut bytes_to_write = piece_len as u32;
    let chunk_start = index * piece_len as u32 + chunk_offset;
    let mut res = FileMapping::default();
    for f in files {
        let mut f_len = f.length;
        bytes_seen += f.length;

        if !start_found && bytes_seen > chunk_start {
            start_found = true;
            res.offset = chunk_start - (bytes_seen - f.length);
            f_len = bytes_seen - chunk_start;
        }

        if !start_found {
            continue;
        }

        if bytes_to_write <= f_len {
            res.files.push((f.path.as_path(), bytes_to_write as usize));
            break;
        }

        res.files.push((f.path.as_path(), f_len as usize));
        bytes_to_write -= f_len;
    }

    res
}

#[derive(Default, PartialEq, Eq, Debug)]
struct FileMapping<'a> {
    offset: u32,
    files: Vec<(&'a Path, usize)>,
}

pub async fn run_peer_handler<T: Unpin + AsyncRead + AsyncWrite>(
    params: DownloadParams,
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
        Handshake::Bittorrent(peer_hash, peer_id) => {
            if peer_hash != params.metainfo.hash {
                return Err(BitterMistake::new("info_hash mismatch"));
            }
            // TODO: ("check peer id")
        }
    }
    handler.run(&mut conn).await?;
    Ok(())
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

    use super::{identify_files, FileMapping, ProgressTracker};

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
            identify_files(0, 0, 4, &files),
            FileMapping {
                offset: 0,
                files: vec![(&f1, 4)],
            }
        );
        assert_eq!(
            identify_files(1, 0, 4, &files),
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
            identify_files(1, 0, 4, &files),
            FileMapping {
                offset: 4,
                files: vec![(&f1, 4)],
            }
        );
        assert_eq!(
            identify_files(2, 0, 4, &files),
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
            identify_files(1, 0, 4, &files),
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
            identify_files(0, 0, 7, &files),
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
            length: u32::MAX,
            path: file.clone(),
        }];
        save_piece(0, plen, &vec![Bytes::from(ones_piece.clone())], &files)
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

        save_piece(1, plen, &vec![Bytes::from(h_piece.clone())], &files)
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
            length: u32::MAX,
            path: file.clone(),
        }];

        save_piece(
            0,
            plen,
            &vec![
                Bytes::copy_from_slice(ones_piece1.clone()),
                Bytes::copy_from_slice(ones_piece2.clone()),
                Bytes::copy_from_slice(ones_piece3.clone()),
            ],
            &files,
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
                length: plen as u32 / 2,
                path: file1.clone(),
            },
            MetainfoFile {
                length: plen as u32 / 4,
                path: file2.clone(),
            },
            MetainfoFile {
                length: plen as u32,
                path: file3.clone(),
            },
        ];
        let ones = vec![1 as u8; 10];
        let twos = vec![2 as u8; 5];
        let threes = vec![3 as u8; 5];
        let mut received = ones.clone();
        received.append(&mut twos.clone());
        received.append(&mut threes.clone());
        save_piece(0, plen, &vec![Bytes::from(received)], &files)
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
                length: plen as u32 / 2,
                path: file1.clone(),
            },
            MetainfoFile {
                length: plen as u32 / 4,
                path: file2.clone(),
            },
            MetainfoFile {
                length: plen as u32,
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
            plen,
            &vec![
                Bytes::from(chunk1),
                Bytes::from(chunk2),
                Bytes::from(chunk3),
            ],
            &files,
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
