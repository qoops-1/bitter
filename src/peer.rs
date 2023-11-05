use std::{
    io::SeekFrom,
    path::Path,
    sync::Arc,
};

use bit_vec::BitVec;
use sha1::{Digest, Sha1};
use tokio::{
    fs::OpenOptions,
    io::{AsyncRead, AsyncSeekExt, AsyncWrite, AsyncWriteExt},
};

use crate::{
    accounting::Accounting,
    metainfo::{Hash, MetainfoFile, MetainfoInfo, PeerId},
    protocol::{Packet, TcpConn},
    utils::{roundup_div, BitterMistake, BitterResult},
};

const MAX_REQUEST_PIECE_LEN: u32 = u32::pow(2, 16); // 64 KB

#[derive(Clone)]
pub struct DownloadParams {
    pub peer_id: PeerId,
    pub info_hash: Hash,
    pub metainfo: Arc<MetainfoInfo>,
    pub req_piece_len: usize,
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

    pub async fn run<T: Unpin + AsyncRead + AsyncWrite>(
        &mut self,
        conn: &mut TcpConn<T>,
    ) -> BitterResult<()> {
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

        let chunk_no = begin as usize / self.params.req_piece_len;
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
                    self.params.req_piece_len as u32,
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

        let done_chunks: Vec<&Vec<u8>> = full_piece.chunks.iter().flatten().collect::<Vec<_>>();

        self.verify_hash(index, &done_chunks)?;
        save_piece(
            index,
            self.params.req_piece_len,
            &done_chunks,
            &self.params.metainfo.files,
        )
        .await
        // self.request_new_piece().await
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
        let plen = self.params.req_piece_len as u32;

        if index >= self.params.metainfo.pieces.len() as u32 {
            return Err(BitterMistake::new("Piece index out of bounds"));
        }
        if begin + data.len() as u32 > self.params.metainfo.piece_length {
            return Err(BitterMistake::new("Received chunk outside of piece bounds"));
        }
        if begin % plen != 0 {
            return Err(BitterMistake::new("Received chunk at weird offset"));
        }

        if data.len() as u32 > plen {
            return Err(BitterMistake::new("Received chunk of unexpected size"));
        }

        Ok(())
    }
}

// Doesn't care about sizes of chunks, simply determines the files that need to be written via index and meta piece_len, and writes the chunks there sequentially
async fn save_piece(
    index: u32,
    piece_len: usize,
    chunks: &Vec<&Vec<u8>>,
    files: &Vec<MetainfoFile>,
) -> BitterResult<()> {
    let mut ftow = identify_files_to_write(index, piece_len, files);
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
            if chunks[c_no].len() > c_offset + len {
                c_write = &chunks[c_no][c_offset..c_offset + len];
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

fn identify_files_to_write(
    index: u32,
    piece_len: usize,
    files: &Vec<MetainfoFile>,
) -> FilesToWrite {
    let mut start_found = false;
    let mut bytes_seen = 0;
    let mut bytes_to_write = piece_len as u32;
    let chunk_start = index * piece_len as u32;
    let mut res = FilesToWrite::default();
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
struct FilesToWrite<'a> {
    offset: u32,
    files: Vec<(&'a Path, usize)>,
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use tempdir::TempDir;
    use tokio::{fs::File, io::AsyncReadExt};

    use crate::{
        metainfo::{Hash, MetainfoFile, MetainfoInfo},
        peer::save_piece,
    };

    use super::{identify_files_to_write, FilesToWrite};

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
            identify_files_to_write(0, 4, &files),
            FilesToWrite {
                offset: 0,
                files: vec![(&f1, 4)],
            }
        );
        assert_eq!(
            identify_files_to_write(1, 4, &files),
            FilesToWrite {
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
            identify_files_to_write(1, 4, &files),
            FilesToWrite {
                offset: 4,
                files: vec![(&f1, 4)],
            }
        );
        assert_eq!(
            identify_files_to_write(2, 4, &files),
            FilesToWrite {
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
            identify_files_to_write(1, 4, &files),
            FilesToWrite {
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
            identify_files_to_write(0, 7, &files),
            FilesToWrite {
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
        save_piece(0, plen, &vec![&ones_piece], &files)
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

        save_piece(1, plen, &vec![&h_piece], &files).await.unwrap();

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
                &ones_piece1.to_vec(),
                &ones_piece2.to_vec(),
                &ones_piece3.to_vec(),
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
        save_piece(0, plen, &vec![&received], &files).await.unwrap();
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
}
