use rand::distr::Alphanumeric;
use rand::{rng, Rng};
use tokio::signal::ctrl_c;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::select;
use tokio::task::JoinSet;
use tracing::{debug, error, warn};

use crate::accounting::Accounting;
use crate::metainfo::PeerId;
use crate::peer::{run_peer_handler, PeerParams};
use crate::tracker::{Peer, PeriodicAnnouncer, Tracker};
use crate::{
    metainfo::Metainfo,
    utils::{BitterMistake, BitterResult},
    Settings,
};

const OPTIMISITIC_UNCHOKE_NUM: usize = 6;

pub fn download(metainfo: Metainfo, settings: Settings) -> BitterResult<()> {
    let mut downldr = Downloader::new(settings);

    downldr.run(metainfo)
}

pub struct Downloader {
    peer_id: String,
    settings: Settings,
}

impl Downloader {
    fn new(settings: Settings) -> Downloader {
        let id: String = rng()
            .sample_iter(&Alphanumeric)
            .take(20)
            .map(char::from)
            .collect();

        Downloader {
            peer_id: id,
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
        let total_len: u64 = metainfo.info.files.iter().map(|f| f.length).sum();

        let tracker = Tracker::new(&metainfo, &acct, peer_id, self.settings.port, total_len).await?;

        let params = PeerParams {
            peer_id,
            metainfo: Arc::new(metainfo.info),
            req_piece_len: self.settings.req_piece_len,
            total_len,
            start_peer_choked: true,
            output_dir: self.settings.output_dir.clone(),
        };

        let server = TcpListener::bind((self.settings.ip, self.settings.port))
            .await
            .map_err(BitterMistake::new_err)?;

        let mut peer_pool = JoinSet::new();
        let mut periodic_announcer = PeriodicAnnouncer::new(&tracker);

        let mut unchoked = 0;
        
        loop {
            select! {
                res = peer_pool.join_next(), if !peer_pool.is_empty() => {
                    match res {
                        Some(r) => {
                            match r {
                                Ok(Ok(())) => debug!("peer_exit"),
                                Err(e) => error!("peer_exit_error {}", e),
                                Ok(Err(e)) => error!("peer_exit_error {}", e),
                            }
                            if total_pieces as u64 == acct.down_cnt.load(Ordering::Acquire) {
                                debug!("download done");
                                tracker.announce_completed().await?;
                                if !self.settings.keep_going {
                                    peer_pool.shutdown().await;
                                    return Ok(());
                                }
                            }
                        }
                        None => {
                            debug!("no_more_peers");
                            return Ok(())
                        }
                }}
                new_peers = periodic_announcer.announce() => {
                    for p in new_peers {
                        let mut cur_params = params.clone();
                        if unchoked < OPTIMISITIC_UNCHOKE_NUM {
                            cur_params.start_peer_choked = false;
                            unchoked += 1;
                        }
                        peer_pool.spawn(run_new_peer_conn(cur_params, p.clone(), acct.clone()));
                    }
                }
                res = server.accept() => {
                    // TODO: handle result properly, it can return WOULDBLOCK and etc
                    let (stream, _addr) = res.unwrap();

                    peer_pool.spawn(run_peer_handler(params.clone(), acct.clone(), stream));
                }
                _ = ctrl_c() => {
                    warn!("received Ctrl-C, shutting down");
                    let threads_shut = peer_pool.shutdown();
                    let announce_stop = tracker.announce_stop();

                    threads_shut.await;
                    return announce_stop.await.map(|_| ());
                }
            }
        }
    }

}

async fn run_new_peer_conn(
    params: PeerParams,
    peer: Peer,
    acct: Accounting,
) -> BitterResult<()> {
    let stream = TcpStream::connect(peer.addr)
        .await
        .map_err(BitterMistake::new_err)?;

    run_peer_handler(params, acct, stream).await
}
