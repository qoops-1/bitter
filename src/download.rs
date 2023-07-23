use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use std::{fmt, io::Read, net::SocketAddr, str, time::Duration};
use ureq;

use crate::{
    bencoding::{bdecode, BDecode, BencodedValue},
    metainfo::Metainfo,
    utils::{urlencode, BitterMistake, BitterResult},
};
const MAX_MSG_SIZE: u64 = 1000 * 1000;

pub fn download(metainfo: Metainfo) {
    let sched = Downloader::new();

    sched.run(metainfo);
}

pub struct Downloader {
    peer_id: String,
    peers: Vec<Peer>,
}

impl Downloader {
    fn new() -> Downloader {
        let id: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(20)
            .map(char::from)
            .collect();

        Downloader {
            peer_id: id,
            peers: Vec::new(),
        }
    }
    fn run(&self, metainfo: Metainfo) -> BitterResult<()> {
        unimplemented!()
    }
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

struct AnnounceRequest {
    info_hash: Vec<u8>,
    peer_id: String,
    port: u16,
    uploaded: u64,
    downloaded: u64,
    left: u64,
    event: AnnounceEvent,
}

struct Peer {
    peer_id: Vec<u8>,
    addr: SocketAddr,
}

impl BDecode for Peer {
    fn bdecode(benc: &BencodedValue) -> BitterResult<Self> {
        unimplemented!()
    }
}

fn announce(url: String, req: AnnounceRequest) -> BitterResult<AnnouncePeers> {
    let port_str = req.port.to_string();
    let left_str = req.left.to_string();
    let event_str = req.event.to_string();
    let uploaded_str = req.uploaded.to_string();
    let downloaded_str = req.downloaded.to_string();
    let urlencoded_hash = urlencode(&req.info_hash);
    let query_params: Vec<(&str, &str)> = vec![
        ("info_hash", &urlencoded_hash),
        ("peer_id", &req.peer_id),
        ("port", &port_str),
        ("uploaded", &uploaded_str),
        ("downloaded", &downloaded_str),
        ("left", &left_str),
        ("event", &event_str),
    ];
    let mut buf = Vec::new();
    ureq::get(&url)
        .query_pairs(query_params)
        .call()
        .map_err(BitterMistake::new_err)
        .and_then(|resp: ureq::Response| {
            resp.into_reader()
                .take(MAX_MSG_SIZE)
                .read_to_end(&mut buf)
                .map_err(BitterMistake::new_err)
        })?;

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

        let fail_reason = match dict.get_key("failure reason") {
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
            .get_key("peers")?
            .try_into_list()?
            .into_iter()
            .map(|v| Peer::bdecode(v))
            .collect::<BitterResult<Vec<_>>>()?;

        let interval =
            Duration::from_secs(dict.get_key("interval")?.try_into_int()?.unsigned_abs());

        Ok(AnnounceResponse::Peers(AnnouncePeers { peers, interval }))
    }
}
