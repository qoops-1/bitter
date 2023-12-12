use core::fmt;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs},
    slice::Iter,
    str,
    time::Duration, mem,
};

use rand::{seq::SliceRandom, thread_rng};
use reqwest::{Client, Response};
use serde::Serialize;

use crate::{
    bencoding::{bdecode, BDecode, BencodedValue},
    metainfo::{BitterHash, Metainfo, PeerId},
    peer,
    utils::{BitterMistake, BitterResult},
};

struct AnnounceListIter<'a> {
    trackers: &'a Vec<Vec<String>>,
    tier: usize,
    tracker_pos: usize,
}
impl<'a> AnnounceListIter<'a> {
    fn new(trackers: &'a Vec<Vec<String>>) -> AnnounceListIter<'a> {
        AnnounceListIter {
            trackers,
            tier: 0,
            tracker_pos: 0,
        }
    }
}

impl<'a> Iterator for AnnounceListIter<'a> {
    type Item = &'a String;

    fn next(&mut self) -> Option<Self::Item> {
        let res: Option<&String> = self
            .trackers
            .get(self.tier)
            .and_then(|t| t.get(self.tracker_pos));

        if res.is_some() {
            if self.tracker_pos == self.trackers[self.tier].len() - 1 {
                self.tier += 1
            } else {
                self.tracker_pos += 1
            }
        }

        res
    }
}

pub struct Tracker {
    client: Client,
    peer_id: PeerId,
    port: u16,
    info_hash: BitterHash,
    total_pieces: u64,
    trackers: Vec<Vec<String>>,
}
impl Tracker {
    pub fn new(meta: &Metainfo, peer_id: PeerId, port: u16) -> Self {
        let client = Client::new();
        let total_pieces = meta.info.pieces.len() as u64;
        let mut rng = thread_rng();

        let mut trackers = Vec::with_capacity(meta.announce_list.len());
        for tier in meta.announce_list.iter() {
            let mut t = tier.clone();
            t.shuffle(&mut rng);
            trackers.push(t);
        }

        Tracker {
            client,
            peer_id,
            port,
            info_hash: meta.info.hash,
            total_pieces,
            trackers,
        }
    }

    pub async fn announce_start(&mut self) -> BitterResult<Vec<Peer>> {
        let req = AnnounceRequest {
            info_hash: self.info_hash,
            peer_id: self.peer_id,
            port: self.port,
            uploaded: 0,
            downloaded: 0,
            left: self.total_pieces,
            event: AnnounceEvent::Started,
        };

        let mut err = BitterMistake::new("No trackers in the list");
        let mut iter = AnnounceListIter::new(&self.trackers);

        for url in &mut iter {
            let response = self
                .client
                .get(url)
                .query(&req)
                .timeout(Duration::from_secs(30))
                .send()
                .await
                .map_err(BitterMistake::new_err);

            match response {
                Ok(peers_resp) => match Self::parse_response(peers_resp).await {
                    Ok(parsed_peers) => {
                        self.move_up_current(iter.tier, iter.tracker_pos);
                        return Ok(parsed_peers);
                    }
                    Err(e) => err = e,
                },
                Err(e) => err = e,
            }
        }

        Err(err)
    }

    async fn parse_response(response: Response) -> BitterResult<Vec<Peer>> {
        // There's no way to limit the size of body in reqwest.
        // Currently a PR is pending for that: https://github.com/seanmonstar/reqwest/pull/1855
        // Right now it's possible to achieve it with streaming API,
        // but it's ugly and requires turning on streaming features.
        // So TODO: come back to this and see whether the PR got merged.
        let buf = response.bytes().await.map_err(BitterMistake::new_err)?;
        let resp = bdecode::<AnnounceResponse>(&buf)?;
        match resp {
            AnnounceResponse::Failure(f) => Err(BitterMistake::new_owned(format!(
                "Error received from tracker: {f}"
            ))),
            AnnounceResponse::Peers(resp) => Result::Ok(resp.peers),
        }
    }

    fn move_up_current(&mut self, tier: usize, tracker_pos: usize) {
        if tracker_pos == 0 {
            return;
        }
        self.trackers[tier].swap(0, tracker_pos);
    }
}

#[derive(Serialize)]
struct AnnounceRequest {
    info_hash: BitterHash,
    peer_id: PeerId,
    port: u16,
    uploaded: u64,
    downloaded: u64,
    left: u64,
    event: AnnounceEvent,
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

impl Serialize for AnnounceEvent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
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

#[derive(Clone)]
pub struct Peer {
    pub addr: SocketAddr,
    pub peer_id: Option<PeerId>,
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
            .map(|v| Peer::bdecode(&v))
            .collect::<BitterResult<Vec<_>>>()?;

        let interval =
            Duration::from_secs(dict.get_val("interval")?.try_into_int()?.unsigned_abs());

        Ok(AnnounceResponse::Peers(AnnouncePeers { peers, interval }))
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
