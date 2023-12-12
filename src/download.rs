use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::sync::Arc;
use std::{fmt, net::SocketAddr, str, time::Duration};
use tokio::net::{TcpListener, TcpStream};
use tokio::select;
use tokio::task::JoinSet;
use tracing::info;

use crate::accounting::Accounting;
use crate::metainfo::{BitterHash, PeerId};
use crate::peer::{run_peer_handler, DownloadParams};
use crate::tracker::{Peer, Tracker};
use crate::{
    bencoding::{bdecode, BDecode, BencodedValue},
    metainfo::Metainfo,
    utils::{BitterMistake, BitterResult},
    Settings,
};

const OPTIMISITIC_UNCHOKE_NUM: usize = 6;

pub fn download(metainfo: Metainfo, settings: Settings) -> BitterResult<()> {
    let mut sched = Downloader::new(settings);

    sched.run(metainfo)
}

pub struct Downloader {
    peer_id: String,
    peers: Vec<Peer>,
    settings: Settings,
}

impl Downloader {
    fn new(settings: Settings) -> Downloader {
        let id: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(20)
            .map(char::from)
            .collect();

        Downloader {
            peer_id: id,
            peers: Vec::new(),
            settings,
        }
    }

    #[tokio::main]
    async fn run(&mut self, metainfo: Metainfo) -> BitterResult<()> {
        let total_pieces = metainfo.info.pieces.len();
        let acct = Accounting::new(total_pieces);
        let peer_id: PeerId = self
            .peer_id
            .as_bytes()
            .try_into()
            .expect("peer_id contains more bytes than expected");
        let mut tracker = Tracker::new(&metainfo, peer_id, self.settings.port);
        let announce_resp = tracker.announce_start().await?;
        let total_len: u64 = metainfo.info.files.iter().map(|f| f.length).sum();

        let params = DownloadParams {
            peer_id,
            metainfo: Arc::new(metainfo.info),
            req_piece_len: self.settings.req_piece_len,
            total_len,
            start_peer_choked: true,
        };

        self.peers.extend(announce_resp);

        let mut jset = JoinSet::new();

        for (i, p) in self.peers.iter().enumerate() {
            let mut cur_params = params.clone();
            if i < OPTIMISITIC_UNCHOKE_NUM {
                cur_params.start_peer_choked = false;
            }
            jset.spawn(run_new_peer_conn(cur_params, p.clone(), acct.clone()));
        }

        let server = TcpListener::bind((self.settings.ip, self.settings.port))
            .await
            .map_err(BitterMistake::new_err)?;

        loop {
            select! {
                res = jset.join_next() => {
                    match res {
                        Some(Ok(Ok(()))) | None => {
                            break;
                        }
                        Some(Err(e)) => {
                            eprintln!("peer exited with error: {}", e);
                        }
                        Some(Ok(Err(e))) => {
                            eprintln!("peer exited with error: {}", e);
                        }
                }}
                res = server.accept() => {
                    // TODO: handle result properly, it can return WOULDBLOCK and etc
                    let (stream, _addr) = res.unwrap();

                    jset.spawn(run_peer_handler(params.clone(), acct.clone(), stream));
                }
            }
        }

        Ok(())
    }
}

async fn run_new_peer_conn(
    params: DownloadParams,
    peer: Peer,
    acct: Accounting,
) -> BitterResult<()> {
    let stream = TcpStream::connect(peer.addr)
        .await
        .map_err(BitterMistake::new_err)?;

    run_peer_handler(params, acct, stream).await
}
