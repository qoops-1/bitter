use crate::metainfo::{Hash, PeerId};
use bytes::{Bytes, BytesMut};
use std::io;
use std::io::ErrorKind::InvalidData;
use std::mem::size_of;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::utils::BitterResult;

pub enum Packet<'a> {
    Choke,
    Unchoke,
    Interested,
    NotInterested,
    Have(u32),
    Bitfield,
    Request,
    Piece,
    Handshake(Handshake<'a>),
}

impl<'a> Packet<'a> {
    pub fn parse(buf: &[u8]) -> io::Result<Packet> {
        let msg_type = buf[0];

        match msg_type {
            0 => Ok(Packet::Choke),
            1 => Ok(Packet::Unchoke),
            2 => Ok(Packet::Interested),
            3 => Ok(Packet::NotInterested),
            4 => Self::parse_have(buf),
            _ => Err(io::Error::new(InvalidData, "unknown packet type")),
        }
    }

    fn parse_have(buf: &[u8]) -> io::Result<Packet> {
        if buf.len() != 4 {
            return Err(io::Error::new(
                InvalidData,
                "\"Have\" packet has incorrect size",
            ));
        }
        let pieceno = u32::from_be_bytes(buf.try_into().unwrap());
        Ok(Packet::Have(pieceno))
    }

    fn parse_bitfield(buf: &[u8]) -> io::Result<Packet> {
        todo!()
    }
}

#[derive(PartialEq)]
pub enum Handshake<'a> {
    Bittorrent(&'a Hash, &'a PeerId),
    Other,
}

// Common constants
const MAX_PACKET_LEN: usize = 1024 * 1024 * 8;
const BUF_SIZE: usize = MAX_PACKET_LEN as usize;
const MSG_LEN_LEN: usize = 4;
// Handshake msg constants
const BITTORRENT_PROTO: &[u8] = "BitTorrent protocol".as_bytes();
const BITTORRENT_PROTO_LEN: usize = 19;
const RESERVED_LEN: usize = 8;
const BITTORRENT_HANDSHAKE_LEN: usize =
    1 + BITTORRENT_PROTO_LEN + RESERVED_LEN + size_of::<PeerId>() + size_of::<Hash>();

pub struct TcpConn {
    stream: TcpStream,
    buf: BytesMut,
}

impl TcpConn {
    pub fn new(stream: TcpStream) -> TcpConn {
        let buf = BytesMut::with_capacity(BUF_SIZE);
        return TcpConn { buf, stream };
    }

    pub async fn read_handshake(&mut self) -> io::Result<Handshake> {
        let mut nbytes = 0;
        let mut ptr = 0;

        if !self.buf.is_empty() {
            panic!("wrong usage of read_handshake");
        }
        while nbytes < BITTORRENT_HANDSHAKE_LEN {
            nbytes += self.stream.read_buf(&mut self.buf).await?;
        }

        let slice = &self.buf[ptr..ptr + BITTORRENT_HANDSHAKE_LEN];

        let len = slice[0];
        ptr = 1;

        if len != BITTORRENT_PROTO_LEN as u8 {
            return Err(io::Error::new(
                InvalidData,
                "protocol name length doesn't match any known protocols",
            ));
        }

        let proto_name = &slice[ptr..ptr + BITTORRENT_PROTO_LEN];
        ptr += BITTORRENT_PROTO_LEN;
        if proto_name != BITTORRENT_PROTO {
            return Err(io::Error::new(InvalidData, "unknown protocol"));
        }

        let _reserved = &slice[ptr..ptr + RESERVED_LEN];
        ptr += RESERVED_LEN;
        let info_hash: &Hash = slice[ptr..ptr + size_of::<Hash>()].try_into().unwrap();
        ptr += size_of::<Hash>();
        let peer_id: &PeerId = slice[ptr..ptr + size_of::<PeerId>()].try_into().unwrap();

        Ok(Handshake::Bittorrent(info_hash, peer_id))
    }

    pub async fn read(&mut self) -> io::Result<Packet> {
        let mut nbytes = 0;

        self.buf.clear();

        while nbytes < MSG_LEN_LEN {
            nbytes += self.stream.read_buf(&mut self.buf).await?;
        }
        let msg_len = u32::from_be_bytes(self.buf[..MSG_LEN_LEN].try_into().unwrap()) as usize;

        if msg_len > MAX_PACKET_LEN {
            return Err(io::Error::new(InvalidData, "packet too large"));
        } else if msg_len < 1 {
            return Err(io::Error::new(InvalidData, "packet cannot be empty"));
        }
        nbytes = 0;
        while nbytes < msg_len {
            nbytes += self.stream.read_buf(&mut self.buf).await?;
        }

        Packet::parse(&self.buf[MSG_LEN_LEN..msg_len])
    }
    pub async fn write(&self, packet: Packet) -> BitterResult<()> {
        unimplemented!()
    }
    pub async fn close(&mut self) {
        self.stream.shutdown().await;
    }
}
