use bit_vec::BitVec;
use bitter::{
    accounting::Accounting,
    bencoding::bdecode,
    metainfo::{Metainfo, PeerId},
    peer::{PeerParams, run_peer_handler},
    protocol::{DEFAULT_BUF_SIZE, Handshake, Packet, TcpConn},
    utils::roundup_div,
};
use bytes::Bytes;
use std::{
    fs,
    path::PathBuf,
    sync::{Arc, atomic::Ordering},
};
use tempdir::TempDir;
use tokio::{self, io::duplex};

#[tokio::test]
async fn single_peer_basic_download() {
    let my_peer_id = PeerId([1; 20]);
    let metafile = fs::read("./tests/testfiles/art2.jpg.torrent").unwrap();
    let file = fs::read("./tests/testfiles/art2.jpg").unwrap();
    let mut metainfo = bdecode::<Metainfo>(&metafile).unwrap();
    let req_piece_len = metainfo.info.piece_length / 4;
    let pieces: Vec<&[u8]> = file.chunks(metainfo.info.piece_length as usize).collect();
    let tempdir = TempDir::new("").unwrap();
    let total_len = file.len() as u64;

    metainfo.info.files[0].path = tempdir.path().join(&metainfo.info.files[0].path);
    let params = PeerParams {
        peer_id: PeerId::default(),
        metainfo: Arc::new(metainfo.info.clone()),
        req_piece_len,
        total_len,
        start_peer_choked: true,
        output_dir: PathBuf::new(),
    };
    let (socket1, socket2) = duplex(usize::pow(2, 10));
    let acct = Accounting::new(params.metainfo.pieces.len());
    let acct_clone = acct.clone();
    let jhandle = tokio::spawn(async move {
        run_peer_handler(params, acct_clone, socket2).await.unwrap();
    });

    let mut conn = TcpConn::new(socket1, DEFAULT_BUF_SIZE);
    conn.write(&Packet::Handshake(Handshake::Bittorrent(
        metainfo.info.hash,
        my_peer_id,
    )))
    .await
    .unwrap();
    assert_eq!(
        conn.read_handshake().await.unwrap(),
        Handshake::Bittorrent(metainfo.info.hash, PeerId::default())
    );

    let bfield = Packet::Bitfield(BitVec::from_elem(metainfo.info.pieces.len(), true));
    conn.write(&bfield).await.unwrap();
    let packet = conn.read().await.unwrap();
    assert_eq!(packet, Packet::Interested);
    conn.write(&Packet::Interested).await.unwrap();

    conn.write(&Packet::Unchoke).await.unwrap();

    for _ in 0..roundup_div(total_len, req_piece_len.into()) {
        let packet = conn.read().await.unwrap();

        match packet {
            Packet::Request {
                index,
                begin,
                length,
            } => conn
                .write(&Packet::Piece {
                    index,
                    begin,
                    data: Bytes::copy_from_slice(
                        &pieces[index as usize][begin as usize..(begin + length) as usize],
                    ),
                })
                .await
                .unwrap(),
            p => panic!("unknown packet {:?}", p),
        }
    }

    jhandle.await.unwrap();

    let downloaded_file = fs::read(&metainfo.info.files[0].path).unwrap();
    assert_eq!(pieces.len() as u64, acct.down_cnt.load(Ordering::SeqCst));
    assert_eq!(file, downloaded_file);
    drop(tempdir);
}
