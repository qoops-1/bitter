use crate::{
    metainfo::{Hash, PeerId},
    utils::BitterMistake,
};
use bit_vec::BitVec;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::mem::size_of;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::utils::BitterResult;

// Common constants
const MAX_PACKET_LEN: usize = 1024 * 1024 * 8;
const BUF_SIZE: usize = MAX_PACKET_LEN as usize;
const MSG_LEN_LEN: usize = 4;
const INCORRECT_LEN_ERROR: &str = "Packet has incorrect size";
// Handshake msg constants
const BITTORRENT_PROTO: &[u8] = "BitTorrent protocol".as_bytes();
const BITTORRENT_PROTO_LEN: usize = 19;
const RESERVED_LEN: usize = 8;
const BITTORRENT_HANDSHAKE_LEN: usize =
    1 + BITTORRENT_PROTO_LEN + RESERVED_LEN + size_of::<PeerId>() + size_of::<Hash>();
// Request msg constants
const REQUEST_MSG_LEN: usize = 12;
// Piece msg constants
const PIECE_MSG_MIN_LEN: usize = 8;
// Message codes
const MSG_CODE_CHOKE: u8 = 0;
const MSG_CODE_UNCHOKE: u8 = 1;
const MSG_CODE_INTERESTED: u8 = 2;
const MSG_CODE_NOT_INTERESTED: u8 = 3;
const MSG_CODE_HAVE: u8 = 4;
const MSG_CODE_BITFIELD: u8 = 5;
const MSG_CODE_REQUEST: u8 = 6;
const MSG_CODE_PIECE: u8 = 7;
const MSG_CODE_CANCEL: u8 = 8;

pub enum Packet<'a> {
    Choke,
    Unchoke,
    Interested,
    NotInterested,
    Have(u32),
    Bitfield(BitVec),
    Request {
        index: u32,
        begin: u32,
        piece: u32,
    },
    Piece {
        index: u32,
        begin: u32,
        data: &'a [u8],
    },
    Cancel {
        index: u32,
        begin: u32,
        piece: u32,
    },
    Handshake(Handshake<'a>),
    Keepalive,
}

impl<'a> Packet<'a> {
    pub fn parse(buf: &'a [u8]) -> BitterResult<Self> {
        let msg_type = buf[0];

        match msg_type {
            MSG_CODE_CHOKE => Ok(Packet::Choke),
            MSG_CODE_UNCHOKE => Ok(Packet::Unchoke),
            MSG_CODE_INTERESTED => Ok(Packet::Interested),
            MSG_CODE_NOT_INTERESTED => Ok(Packet::NotInterested),
            MSG_CODE_HAVE => parse_have(buf),
            MSG_CODE_BITFIELD => parse_bitfield(buf),
            MSG_CODE_REQUEST => parse_request(buf),
            MSG_CODE_PIECE => parse_piece(buf),
            MSG_CODE_CANCEL => parse_cancel(buf),
            _ => Err(BitterMistake::new("unknown packet type")),
        }
    }

    fn serialize(&self) -> Bytes {
        match self {
            Packet::Handshake(h) => serialize_handshake(h),
            Packet::Choke => serialize_code_only(MSG_CODE_CHOKE),
            Packet::Unchoke => serialize_code_only(MSG_CODE_UNCHOKE),
            _ => unimplemented!(),
        }
    }
}

fn serialize_code_only(msg_code: u8) -> Bytes {
    let pieces = &[&u32::to_be_bytes(1)[..], &[msg_code]];

    Bytes::from(pieces.concat())
}

fn serialize_handshake(handshake: &Handshake) -> Bytes {
    let (info_hash, peer_id) = match handshake {
        Handshake::Other => panic!("tried serializing unknown message"),
        Handshake::Bittorrent(h, pid) => (h, pid),
    };
    let mut buf = BytesMut::with_capacity(BITTORRENT_HANDSHAKE_LEN);

    buf.put_u8(BITTORRENT_PROTO_LEN as u8);
    buf.put_slice(BITTORRENT_PROTO);
    buf.put_bytes(0, RESERVED_LEN);
    buf.put_slice(*peer_id);
    buf.put_slice(*info_hash);

    buf.freeze()
}

#[derive(PartialEq)]
pub enum Handshake<'a> {
    Bittorrent(&'a Hash, &'a PeerId),
    Other,
}

pub struct TcpConn<T>
where
    T: Sized + Unpin + AsyncRead + AsyncWrite,
{
    stream: T,
    buf: BytesMut,
}

impl<T> TcpConn<T>
where
    T: Sized + Unpin + AsyncRead + AsyncWrite,
{
    pub fn new(stream: T) -> TcpConn<T> {
        let buf = BytesMut::with_capacity(BUF_SIZE);
        return TcpConn { buf, stream };
    }

    pub async fn read_handshake(&mut self) -> BitterResult<Handshake> {
        let mut nbytes = 0;
        let mut ptr = 0;

        if !self.buf.is_empty() {
            panic!("wrong usage of read_handshake");
        }
        while nbytes < BITTORRENT_HANDSHAKE_LEN {
            nbytes += self
                .stream
                .read_buf(&mut self.buf)
                .await
                .map_err(BitterMistake::new_err)?;
        }

        let slice = &self.buf[ptr..ptr + BITTORRENT_HANDSHAKE_LEN];

        let len = slice[0];
        ptr = 1;

        if len != BITTORRENT_PROTO_LEN as u8 {
            return Err(BitterMistake::new(
                "protocol name length doesn't match any known protocols",
            ));
        }

        let proto_name = &slice[ptr..ptr + BITTORRENT_PROTO_LEN];
        ptr += BITTORRENT_PROTO_LEN;
        if proto_name != BITTORRENT_PROTO {
            return Err(BitterMistake::new("unknown protocol"));
        }

        let _reserved = &slice[ptr..ptr + RESERVED_LEN];
        ptr += RESERVED_LEN;
        let info_hash: &Hash = slice[ptr..ptr + size_of::<Hash>()].try_into().unwrap();
        ptr += size_of::<Hash>();
        let peer_id: &PeerId = slice[ptr..ptr + size_of::<PeerId>()].try_into().unwrap();

        Ok(Handshake::Bittorrent(info_hash, peer_id))
    }

    pub async fn read(&mut self) -> BitterResult<Packet> {
        let mut nbytes = 0;

        self.buf.clear();

        while nbytes < MSG_LEN_LEN {
            nbytes += self
                .stream
                .read_buf(&mut self.buf)
                .await
                .map_err(BitterMistake::new_err)?;
        }
        let msg_len = u32::from_be_bytes(self.buf[..MSG_LEN_LEN].try_into().unwrap()) as usize;

        if msg_len > MAX_PACKET_LEN {
            return Err(BitterMistake::new("packet too large"));
        } else if msg_len == 0 {
            return Ok(Packet::Keepalive);
        }
        nbytes = 0;
        while nbytes < msg_len {
            nbytes += self
                .stream
                .read_buf(&mut self.buf)
                .await
                .map_err(BitterMistake::new_err)?;
        }

        Packet::parse(&self.buf[MSG_LEN_LEN..MSG_LEN_LEN + msg_len])
    }
    pub async fn write<'a>(&mut self, packet: &Packet<'a>) -> BitterResult<()> {
        let mut buf = packet.serialize();
        while buf.has_remaining() {
            self.stream
                .write_buf(&mut buf)
                .await
                .map_err(BitterMistake::new_err)?;
        }
        Ok(())
    }

    pub async fn close(&mut self) {
        self.stream.shutdown().await;
    }
}

fn parse_have(buf: &[u8]) -> BitterResult<Packet> {
    if buf.len() != 4 {
        return Err(BitterMistake::new(INCORRECT_LEN_ERROR));
    }
    let pieceno = u32::from_be_bytes(buf.try_into().unwrap());
    Ok(Packet::Have(pieceno))
}

fn parse_bitfield(buf: &[u8]) -> BitterResult<Packet> {
    Ok(Packet::Bitfield(BitVec::from_bytes(buf)))
}

fn parse_request(buf: &[u8]) -> BitterResult<Packet> {
    parse_request_internal(buf).map(|(index, begin, piece)| Packet::Request {
        index,
        begin,
        piece,
    })
}

fn parse_piece(buf: &[u8]) -> BitterResult<Packet> {
    if buf.len() < PIECE_MSG_MIN_LEN {
        return Err(BitterMistake::new(INCORRECT_LEN_ERROR));
    }
    let (index_buf, buf) = buf.split_at(4);
    let (begin_buf, buf) = buf.split_at(4);

    let index = u32::from_be_bytes(index_buf.try_into().unwrap());
    let begin = u32::from_be_bytes(begin_buf.try_into().unwrap());
    let data = buf;

    Ok(Packet::Piece { index, begin, data })
}

fn parse_cancel(buf: &[u8]) -> BitterResult<Packet> {
    parse_request_internal(buf).map(|(index, begin, piece)| Packet::Cancel {
        index,
        begin,
        piece,
    })
}

fn parse_request_internal(buf: &[u8]) -> BitterResult<(u32, u32, u32)> {
    if buf.len() != REQUEST_MSG_LEN {
        return Err(BitterMistake::new(INCORRECT_LEN_ERROR));
    }

    let (index_buf, buf) = buf.split_at(4);
    let (begin_buf, buf) = buf.split_at(4);
    let (piece_buf, buf) = buf.split_at(4);

    let index = u32::from_be_bytes(index_buf.try_into().unwrap());
    let begin = u32::from_be_bytes(begin_buf.try_into().unwrap());
    let piece = u32::from_be_bytes(piece_buf.try_into().unwrap());

    Ok((index, begin, piece))
}
