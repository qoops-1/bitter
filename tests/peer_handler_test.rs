use bit_vec::BitVec;
use bitter::{
    accounting::Accounting,
    bencoding::bdecode,
    metainfo::{Metainfo, PeerId},
    peer::{run_peer_handler, DownloadParams},
    protocol::{Handshake, Packet, TcpConn},
};
use bytes::Bytes;
use std::{collections::HashSet, fs, sync::Arc};
use tempdir::TempDir;
use tokio::{self, io::duplex};

#[tokio::test]
async fn basic() {
    let my_peer_id: PeerId = [1; 20];
    let metafile = fs::read("./tests/testfiles/art1.png.torrent").unwrap();
    let file = fs::read("./tests/testfiles/art1.png").unwrap();
    let mut metainfo = bdecode::<Metainfo>(&metafile).unwrap();
    let req_piece_len = metainfo.info.piece_length as usize / 4;
    let pieces: Vec<&[u8]> = file.chunks(metainfo.info.piece_length as usize).collect();
    let tempdir = TempDir::new("").unwrap();
    let last_chunk_size = (pieces.len() % req_piece_len) as u32;
    let params = DownloadParams {
        peer_id: PeerId::default(),
        metainfo: Arc::new(metainfo.info.clone()),
        req_piece_len,
        last_chunk_size,
    };
    metainfo.info.files[0].path = tempdir.into_path().join(&mut metainfo.info.files[0].path);

    let (socket1, socket2) = duplex(usize::pow(2, 10));

    let res = tokio::spawn(async move {
        let acct = Accounting::new(params.metainfo.pieces.len());
        run_peer_handler(params, acct, socket2).await.unwrap();
    });

    let mut conn = TcpConn::new(socket1);
    conn.write(&Packet::Handshake(Handshake::Bittorrent(
        &metainfo.info.hash,
        &my_peer_id,
    )))
    .await
    .unwrap();
    assert_eq!(
        conn.read_handshake().await.unwrap(),
        Handshake::Bittorrent(&metainfo.info.hash, &PeerId::default())
    );

    let bfield = Packet::Bitfield(BitVec::from_elem(metainfo.info.pieces.len(), true));
    conn.write(&bfield).await.unwrap();
    let packet = conn.read().await.unwrap();
    assert_eq!(packet, Packet::Interested);
    conn.write(&Packet::Interested).await.unwrap();

    conn.write(&Packet::Unchoke).await.unwrap();
    let mut pieces_received = 0;
    let mut pending_pieces: HashSet<u32> = HashSet::new();

    while pieces_received < metainfo.info.pieces.len() {
        let packet = conn.read().await.unwrap();

        match packet {
            Packet::Have(index) => {
                assert!(pending_pieces.contains(&index));
                assert!(pending_pieces.remove(&index));
                pieces_received += 1;
            }
            Packet::Request {
                index,
                begin,
                length,
            } => {
                conn.write(&Packet::Piece {
                    index,
                    begin,
                    data: Bytes::copy_from_slice(
                        &pieces[index as usize][begin as usize..(begin + length) as usize],
                    ),
                })
                .await
                .unwrap();
                pending_pieces.insert(index);
            }
            _ => panic!("unknown packet!"),
        }
    }
    assert!(pending_pieces.is_empty());

    let downloaded_file = fs::read(&metainfo.info.files[0].path).unwrap();

    assert_eq!(file, downloaded_file);
}
