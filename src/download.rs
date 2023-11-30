use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::sync::Arc;
use std::{fmt, net::SocketAddr, str, time::Duration};
use tokio::net::{TcpListener, TcpStream};
use tokio::select;
use tokio::task::JoinSet;

use crate::accounting::Accounting;
use crate::metainfo::{BitterHash, PeerId};
use crate::peer::{run_peer_handler, DownloadParams};
use crate::{
    bencoding::{bdecode, BDecode, BencodedValue},
    metainfo::Metainfo,
    utils::{urlencode, BitterMistake, BitterResult},
    Settings,
};

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
        let announce_resp = announce(
            &metainfo.announce,
            AnnounceRequest {
                info_hash: metainfo.info.hash,
                peer_id: &self.peer_id,
                port: self.settings.port,
                uploaded: 0,
                downloaded: 0,
                left: 0,
                event: AnnounceEvent::Started,
            },
        )
        .await?;
        let total_len: u64 = metainfo.info.files.iter().map(|f| f.length).sum();

        let params = DownloadParams {
            peer_id: self
                .peer_id
                .as_bytes()
                .try_into()
                .expect("peer_id contains more bytes than expected"),
            metainfo: Arc::new(metainfo.info),
            req_piece_len: self.settings.req_piece_len,
            total_len,
        };

        self.peers.extend(announce_resp.peers);

        let mut jset = JoinSet::new();

        for p in self.peers.iter() {
            jset.spawn(run_new_peer_conn(params.clone(), p.clone(), acct.clone()));
        }

        let server = TcpListener::bind((self.settings.ip, self.settings.port))
            .await
            .map_err(BitterMistake::new_err)?;

        loop {
            select! {
                _ = jset.join_next() => {unimplemented!()}
                res = server.accept() => {
                    // TODO: handle result properly, it can return WOULDBLOCK and etc
                    let (stream, addr) = res.unwrap();
                    let peer = Peer { addr, peer_id: None};

                    jset.spawn(run_peer_handler(params.clone(), acct.clone(), stream));
                }
            }
        }
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

enum AnnounceEvent {
    Started,
    Completed,
    Stopped,
    Empty,
}

impl fmt::Display for AnnounceEvent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AnnounceEvent::Started => f.write_str("started"),
            AnnounceEvent::Completed => f.write_str("completed"),
            AnnounceEvent::Stopped => f.write_str("stopped"),
            AnnounceEvent::Empty => f.write_str("empty"),
        }
    }
}

struct AnnounceRequest<'a> {
    info_hash: BitterHash,
    peer_id: &'a str,
    port: u16,
    uploaded: u64,
    downloaded: u64,
    left: u64,
    event: AnnounceEvent,
}

#[derive(Clone)]
struct Peer {
    addr: SocketAddr,
    peer_id: Option<PeerId>,
}

impl BDecode for Peer {
    fn bdecode(benc: &BencodedValue) -> BitterResult<Self> {
        let hmap = benc.try_into_dict()?;
        let peer_id: Option<PeerId> = hmap
            .get_val("peer id")
            .and_then(|v| v.try_into_bytestring())
            .and_then(|v| v.try_into().map_err(BitterMistake::new_err))
            .ok();
        let port: u16 = hmap.get_val("port")?.try_into_u16()? as u16;
        let addr = hmap.get_val("ip")?.try_into_string()?;

        let mut sockaddrs = (addr, port)
            .to_socket_addrs()
            .map_err(BitterMistake::new_err)?;

        // taking only the first resolution because peer has only one addr.
        // TODO: improve this later, add multiple addresses to a peer
        sockaddrs
            .next()
            .ok_or(BitterMistake::new_owned(format!(
                "cannot resolve host {}:{}",
                addr, port
            )))
            .map(|saddr| Peer {
                addr: saddr,
                peer_id,
            })
    }
}

impl BDecode for Vec<Peer> {
    fn bdecode(benc: &BencodedValue) -> BitterResult<Self> {
        match benc {
            BencodedValue::BencodedList(peers) => peers.iter().map(Peer::bdecode).collect(),
            BencodedValue::BencodedStr(bytes) => {
                let mut peers = Vec::new();
                let mut ptr = 0;
                while ptr + 6 < bytes.len() {
                    let addr = u32::from_be_bytes(bytes[ptr..ptr + 4].try_into().unwrap());
                    ptr += 4;
                    let port = u16::from_be_bytes(bytes[ptr..ptr + 2].try_into().unwrap());
                    ptr += 2;
                    peers.push(Peer {
                        addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::from(addr)), port),
                        peer_id: None,
                    });
                }
                if ptr != bytes.len() {
                    Err(BitterMistake::new_owned(format!(
                        "{} remaining bytes in peers array cannot be parsed into peer",
                        bytes.len() - ptr
                    )))
                } else {
                    Ok(peers)
                }
            }
            _ => Err(BitterMistake::new(
                "peer list expected to be a list or string",
            )),
        }
    }
}

async fn announce<'a>(url: &str, req: AnnounceRequest<'a>) -> BitterResult<AnnouncePeers> {
    let event_str = req.event.to_string();
    // I'll keep my custom urlencoding since I've heard urlencoding according bittorrent spec differs from http urlencoding
    let urlencoded_hash = urlencode(&req.info_hash);
    let client = reqwest::Client::new();
    // Split query in 2 calls for type inference
    let response = client
        .get(url)
        .query(&[
            ("uploaded", req.uploaded),
            ("downloaded", req.downloaded),
            ("left", req.left),
            ("port", req.port.into()),
        ])
        .query(&[
            ("peer_id", req.peer_id),
            ("event", &event_str),
            ("info_hash", &urlencoded_hash),
        ])
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .map_err(BitterMistake::new_err)?;

    // There's no way to limit the size of body in reqwest.
    // Currently a PR is pending for that: https://github.com/seanmonstar/reqwest/pull/1855
    // Right now it's possible to achieve it with streaming API,
    // but it's ugly and requires turning on streaming features.
    // So TODO: come back to this and see whether the PR got merged.
    let buf = response.bytes().await.map_err(BitterMistake::new_err)?;

    let resp = bdecode::<AnnounceResponse>(&buf)?;

    match resp {
        AnnounceResponse::Failure(f) => Result::Err(BitterMistake::new_owned(f)),
        AnnounceResponse::Peers(peers_resp) => Result::Ok(peers_resp),
    }
}

struct AnnouncePeers {
    peers: Vec<Peer>,
    interval: Duration,
}

enum AnnounceResponse {
    Failure(String),
    Peers(AnnouncePeers),
}

impl BDecode for AnnounceResponse {
    fn bdecode(benc: &BencodedValue) -> BitterResult<Self> {
        let dict = benc.try_into_dict()?;

        let fail_reason = match dict.get_val("failure reason") {
            Ok(BencodedValue::BencodedStr(bytes)) => match str::from_utf8(bytes) {
                Err(e) => {
                    return Result::Err(BitterMistake::new_owned(format!(
                        "failure reason parsing error: {}",
                        e.to_string()
                    )))
                }
                Ok(k) => Ok(AnnounceResponse::Failure(k.to_owned())),
            },
            Err(err) => Err(err),
            _ => panic!("get_key cannot return non-string"), // TODO: fix this. this can actually return non-string
        };
        if fail_reason.is_ok() {
            return fail_reason;
        }

        let peers: Vec<Peer> = dict
            .get_val("peers")?
            .try_into_list()?
            .into_iter()
            .map(|v| Peer::bdecode(v))
            .collect::<BitterResult<Vec<_>>>()?;

        let interval =
            Duration::from_secs(dict.get_val("interval")?.try_into_int()?.unsigned_abs());

        Ok(AnnounceResponse::Peers(AnnouncePeers { peers, interval }))
    }
}
