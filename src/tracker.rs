use core::fmt;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs},
    str,
    time::Duration,
};

use bytes::{Buf, BufMut, BytesMut};
use rand::{seq::SliceRandom, thread_rng};
use reqwest::{Client, Url};
use serde::Serialize;
use tokio::{net::UdpSocket, time::timeout};
use tracing::debug;

use crate::{
    bencoding::{bdecode, BDecode, BencodedValue},
    metainfo::{BitterHash, Metainfo, PeerId},
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
    http_client: Client,
    udp_socket: UdpSocket,
    peer_id: PeerId,
    port: u16,
    info_hash: BitterHash,
    total_len: u64,
    trackers: Vec<Vec<String>>,
}
impl Tracker {
    pub async fn new(
        meta: &Metainfo,
        peer_id: PeerId,
        port: u16,
        total_len: u64,
    ) -> BitterResult<Self> {
        let http_client = Client::new();
        let udp_socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(BitterMistake::new_err)?;
        let mut rng = thread_rng();

        let mut trackers = Vec::with_capacity(meta.announce_list.len());
        for tier in meta.announce_list.iter() {
            let mut t = tier.clone();
            t.shuffle(&mut rng);
            trackers.push(t);
        }

        Ok(Tracker {
            http_client,
            udp_socket,
            peer_id,
            port,
            info_hash: meta.info.hash,
            total_len,
            trackers,
        })
    }

    pub async fn announce_start(&mut self) -> BitterResult<Vec<Peer>> {
        let req = AnnounceRequest {
            info_hash: self.info_hash,
            peer_id: self.peer_id,
            port: self.port,
            uploaded: 0,
            downloaded: 0,
            left: self.total_len,
            event: AnnounceEvent::Started,
            numwant: 50,
            compact: true,
        };

        let mut err = BitterMistake::new("No trackers in the list");
        let mut iter = AnnounceListIter::new(&self.trackers);

        for url in &mut iter {
            match self.send_announce_request(url, &req).await {
                Ok(peers_resp) => {
                    debug!(
                        event = "received_peers",
                        tracker = url,
                        num = peers_resp.len()
                    );
                    self.move_up_current(iter.tier, iter.tracker_pos);
                    return Ok(peers_resp);
                }
                Err(e) => err = e,
            }
            debug!(
                event = "tracker_error",
                error = err.to_string(),
                tracker = url
            );
        }

        Err(err)
    }

    async fn send_announce_request(
        &self,
        url: &str,
        req: &AnnounceRequest,
    ) -> BitterResult<Vec<Peer>> {
        if url.starts_with("http://") || url.starts_with("https://") {
            http_announce(&self.http_client, url, req).await
        } else if url.starts_with("udp://") {
            udp_announce(&self.udp_socket, url, req).await
        } else {
            Err(BitterMistake::new_owned(format!(
                "invalid schema in tracker url: {url}"
            )))
        }
    }

    fn move_up_current(&mut self, tier: usize, tracker_pos: usize) {
        if tracker_pos == 0 {
            return;
        }
        self.trackers[tier].swap(0, tracker_pos);
    }
}

async fn http_announce(
    client: &Client,
    url: &str,
    req: &AnnounceRequest,
) -> BitterResult<Vec<Peer>> {
    let response = client
        .get(url)
        .query(&req)
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
        AnnounceResponse::Failure(f) => Err(BitterMistake::new_owned(format!(
            "Error received from tracker: {f}"
        ))),
        AnnounceResponse::Peers(resp) => Result::Ok(resp.peers),
    }
}

struct UdpConn(u64);

const UDP_CONN_RESPONSE_LEN: usize = 16;
const UDP_ANNOUNCE_REQUEST_LEN: usize = 98;
const UDP_ANNOUNCE_RESPONSE_MIN_LEN: usize = 20;
const UDP_ANNOUNCE_RESPONSE_MAX_LEN: usize = UDP_ANNOUNCE_RESPONSE_MIN_LEN + 6 * 50; // min response + 50 peers

const UDP_ACTION_CONNECT: u32 = 0;
const UDP_ACTION_ANNOUNCE: u32 = 1;

async fn udp_connect<T: tokio::net::ToSocketAddrs>(
    socket: &UdpSocket,
    url: T,
) -> BitterResult<UdpConn> {
    for i in 0..5 {
        let mut send_buf = BytesMut::new();
        let tx_id = rand::random::<u32>();
        send_buf.put_u64(0x41727101980); // magic constant
        send_buf.put_u32(0); // action=connect
        send_buf.put_u32(tx_id);
        let mut write_len = send_buf.len();
        while write_len > 0 {
            write_len -= socket
                .send_to(&send_buf, &url)
                .await
                .map_err(BitterMistake::new_err)?;
        }
        let mut recv_buf = BytesMut::with_capacity(UDP_CONN_RESPONSE_LEN);

        match timeout(
            Duration::from_secs(15 * (u64::pow(2, i))),
            socket.recv_buf_from(&mut recv_buf),
        )
        .await
        {
            Ok(Ok((nbytes, _addr))) => {
                if nbytes < UDP_CONN_RESPONSE_LEN {
                    return Err(BitterMistake::new(
                        "received message too small for connection handshake",
                    ));
                }

                let action = recv_buf.get_u32();
                let recv_tx_id = recv_buf.get_u32();
                let conn_id = recv_buf.get_u64();

                if action != UDP_ACTION_CONNECT {
                    return Err(BitterMistake::new(
                        "wrong action received in response to connection",
                    ));
                }

                if recv_tx_id != tx_id {
                    return Err(BitterMistake::new("transaction id mismatch"));
                }

                return Ok(UdpConn(conn_id));
            }
            Ok(Err(e)) => return Err(BitterMistake::new_err(e)),
            Err(_) => continue,
        };
    }
    Err(BitterMistake::new("timed out trying to connect"))
}

async fn udp_send_announce<T: tokio::net::ToSocketAddrs>(
    socket: &UdpSocket,
    url: T,
    conn: &UdpConn,
    req: &AnnounceRequest,
) -> BitterResult<Vec<Peer>> {
    for i in 0..5 {
        let mut send_buf = BytesMut::with_capacity(UDP_ANNOUNCE_REQUEST_LEN);
        let tx_id = rand::random::<u32>();
        send_buf.put_u64(conn.0);
        send_buf.put_u32(UDP_ACTION_ANNOUNCE);
        send_buf.put_u32(tx_id);
        send_buf.put_slice(&req.info_hash);
        send_buf.put_slice(&req.peer_id);
        send_buf.put_u64(req.downloaded);
        send_buf.put_u64(req.left);
        send_buf.put_u64(req.uploaded);
        send_buf.put_u32(req.event.as_u32());
        send_buf.put_u32(0); // IP address default
        send_buf.put_u32(0); // key, dunno what it's for
        send_buf.put_i32(req.numwant);
        send_buf.put_u16(req.port);

        let mut write_len = send_buf.len();
        while write_len > 0 {
            write_len -= socket
                .send_to(&send_buf, &url)
                .await
                .map_err(BitterMistake::new_err)?;
        }
        let mut recv_buf = BytesMut::with_capacity(UDP_ANNOUNCE_RESPONSE_MAX_LEN);

        match timeout(
            Duration::from_secs(15 * (u64::pow(2, i))),
            socket.recv_buf_from(&mut recv_buf),
        )
        .await
        {
            Ok(Ok((nbytes, _addr))) => {
                if nbytes < UDP_ANNOUNCE_RESPONSE_MIN_LEN {
                    return Err(BitterMistake::new(
                        "received message too small for announce response",
                    ));
                }
                debug!(ini_len = recv_buf.remaining(), nbytes);

                let action = recv_buf.get_u32();
                let recv_tx_id = recv_buf.get_u32();
                let interval = recv_buf.get_u32();
                let leechers = recv_buf.get_u32();
                let seeders = recv_buf.get_u32();
                debug!(remaining = recv_buf.remaining());
                let mut peers = Vec::with_capacity(recv_buf.remaining() / 6);

                while recv_buf.remaining() >= 6 {
                    let addr = recv_buf.get_u32();
                    let port = recv_buf.get_u16();

                    peers.push(Peer {
                        addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(addr), port)),
                        peer_id: None,
                    });
                }

                if recv_buf.remaining() > 0 {
                    return Err(BitterMistake::new("trailing bytes in announce packet"));
                }

                if action != UDP_ACTION_ANNOUNCE {
                    return Err(BitterMistake::new(
                        "wrong action received in response to announce",
                    ));
                }

                if recv_tx_id != tx_id {
                    return Err(BitterMistake::new("transaction id mismatch"));
                }

                return Ok(peers);
            }
            Ok(Err(e)) => return Err(BitterMistake::new_err(e)),
            Err(_) => continue,
        };
    }
    Err(BitterMistake::new("timed out trying to announce"))
}

async fn udp_announce(
    socket: &UdpSocket,
    url: &str,
    req: &AnnounceRequest,
) -> BitterResult<Vec<Peer>> {
    let authority = Url::parse(url)
        .map_err(BitterMistake::new_err)?
        .socket_addrs(|| None)
        .map_err(BitterMistake::new_err)?
        .pop()
        .ok_or(BitterMistake::new_owned(format!(
            "couldn't resolve url {url} to socket address"
        )))?;

    let conn = udp_connect(socket, authority).await?;
    udp_send_announce(socket, authority, &conn, req).await
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
    numwant: i32,
    compact: bool,
}

enum AnnounceEvent {
    Started,
    Completed,
    Stopped,
    Empty,
}

impl AnnounceEvent {
    fn as_u32(&self) -> u32 {
        match self {
            AnnounceEvent::Empty => 0,
            AnnounceEvent::Completed => 1,
            AnnounceEvent::Started => 2,
            AnnounceEvent::Stopped => 3,
        }
    }
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
