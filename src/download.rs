use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use std::net::{Ipv4Addr, IpAddr, ToSocketAddrs};
use std::{fmt, io::Read, net::SocketAddr, str, time::Duration};
use ureq;

use crate::{
    Settings,
    bencoding::{bdecode, BDecode, BencodedValue},
    metainfo::Metainfo,
    utils::{urlencode, BitterMistake, BitterResult},
};
const MAX_MSG_SIZE: u64 = 1000 * 1000;

pub fn download(metainfo: Metainfo, settings: Settings) -> BitterResult<()> {
    let sched = Downloader::new(settings);

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
            settings: settings,
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
    addr: SocketAddr,
    peer_id: Option<Vec<u8>>,
}

impl BDecode for Peer {
    fn bdecode(benc: &BencodedValue) -> BitterResult<Self> {
        let hmap = benc.try_into_dict()?;
        let peer_id = hmap.get_key("peer id").and_then(|v| v.try_into_bytestring()).ok().map(Vec::from);
        let port: u16 = *hmap.get_key("port")?.try_into_int()? as u16;
        let addr = hmap.get_key("ip")?.try_into_string()?;

        let mut sockaddrs = (addr, port).to_socket_addrs().map_err(BitterMistake::new_err)?;

        // taking only the first resolution because peer has only one addr. TODO: improve this later, add multiple addresses to a peer
        sockaddrs
            .next()
            .ok_or(BitterMistake::new_owned(format!("cannot resolve host {}:{}", addr, port)))
            .map(|saddr| Peer { addr: saddr, peer_id})
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
                    let addr = u32::from_be_bytes(bytes[ptr..ptr+4].try_into().unwrap());
                    ptr += 4;
                    let port = u16::from_be_bytes(bytes[ptr..ptr+2].try_into().unwrap());
                    ptr += 2;
                    peers.push(Peer { 
                        addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::from(addr)), port), 
                        peer_id: None 
                    });
                }
                if ptr != bytes.len() {
                    Err(BitterMistake::new_owned(format!("{} remaining bytes in peers array cannot be parsed into peer", bytes.len() - ptr)))
                } else {
                    Ok(peers)
                }
            },
            _ => Err(BitterMistake::new("peer list expected to be a list or string")),
        }
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
