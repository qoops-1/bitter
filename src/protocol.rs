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

// Message lengths
const BITTORRENT_PROTO_LEN: usize = 19;
const RESERVED_LEN: usize = 8;
const MSG_TYPE_LEN: usize = 1;
const MSG_LEN_BITTORRENT_HANDSHAKE: usize =
    1 + BITTORRENT_PROTO_LEN + RESERVED_LEN + size_of::<PeerId>() + size_of::<Hash>();
const MSG_LEN_HAVE: usize = MSG_TYPE_LEN + 4;
const MSG_LEN_REQUEST: usize = 12 + MSG_TYPE_LEN;
const MSG_MIN_LEN_PIECE: usize = 8 + MSG_TYPE_LEN;
// len of cancel msg should be the same as request and there are some assumptions about this in the code anyway, so I'll do this
const MSG_LEN_CANCEL: usize = MSG_LEN_REQUEST;
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

#[derive(PartialEq, Eq, Debug)]
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
        length: u32,
    },
    Piece {
        index: u32,
        begin: u32,
        data: &'a [u8],
    },
    Cancel {
        index: u32,
        begin: u32,
        length: u32,
    },
    Handshake(Handshake<'a>),
    Keepalive,
}

impl<'a> Packet<'a> {
    pub fn parse(buf: &'a [u8]) -> BitterResult<Self> {
        let msg_type = buf[0];
        let msg_buf = &buf[1..];

        match msg_type {
            MSG_CODE_CHOKE => Ok(Packet::Choke),
            MSG_CODE_UNCHOKE => Ok(Packet::Unchoke),
            MSG_CODE_INTERESTED => Ok(Packet::Interested),
            MSG_CODE_NOT_INTERESTED => Ok(Packet::NotInterested),
            MSG_CODE_HAVE => parse_have(msg_buf),
            MSG_CODE_BITFIELD => parse_bitfield(msg_buf),
            MSG_CODE_REQUEST => parse_request(msg_buf),
            MSG_CODE_PIECE => parse_piece(msg_buf),
            MSG_CODE_CANCEL => parse_cancel(msg_buf),
            _ => Err(BitterMistake::new("unknown packet type")),
        }
    }

    fn serialize(&self) -> Bytes {
        match self {
            Packet::Handshake(h) => serialize_handshake(h),
            Packet::Choke => serialize_code_only(MSG_CODE_CHOKE),
            Packet::Unchoke => serialize_code_only(MSG_CODE_UNCHOKE),
            Packet::Interested => serialize_code_only(MSG_CODE_INTERESTED),
            Packet::NotInterested => serialize_code_only(MSG_CODE_NOT_INTERESTED),
            Packet::Have(i) => serialize_have(*i),
            Packet::Bitfield(bitvec) => serialize_bitfield(bitvec),
            Packet::Request {
                index,
                begin,
                length,
            } => serialize_request(*index, *begin, *length),
            Packet::Piece { index, begin, data } => serialize_piece(*index, *begin, data),
            Packet::Cancel {
                index,
                begin,
                length,
            } => serialize_cancel(*index, *begin, *length),
            _ => unimplemented!(),
        }
    }
}

#[inline]
fn buf_with_len(len: usize) -> BytesMut {
    let mut buf = BytesMut::with_capacity(len + MSG_LEN_LEN);

    buf.put_u32(len as u32);

    buf
}

fn serialize_code_only(msg_code: u8) -> Bytes {
    let len = 1;
    let pieces = &[&u32::to_be_bytes(len)[..], &[msg_code]];

    Bytes::from(pieces.concat())
}

fn serialize_handshake(handshake: &Handshake) -> Bytes {
    let (info_hash, peer_id) = match handshake {
        Handshake::Other => panic!("tried serializing unknown message"),
        Handshake::Bittorrent(h, pid) => (h, pid),
    };
    // MSG_LEN_BITTORRENT_HANDSHAKE already includes len, so can't reuse buf_with_len as it adds MSG_LEN_LEN
    let mut buf = BytesMut::with_capacity(MSG_LEN_BITTORRENT_HANDSHAKE);

    buf.put_u8(BITTORRENT_PROTO_LEN as u8);
    buf.put_slice(BITTORRENT_PROTO);
    buf.put_bytes(0, RESERVED_LEN);
    buf.put_slice(*info_hash);
    buf.put_slice(*peer_id);

    buf.freeze()
}

fn serialize_have(index: u32) -> Bytes {
    let mut buf = buf_with_len(MSG_LEN_HAVE);

    buf.put_u8(MSG_CODE_HAVE);
    buf.put_u32(index);
    buf.freeze()
}

fn serialize_bitfield(bits: &BitVec) -> Bytes {
    let mut buf = buf_with_len(MSG_TYPE_LEN + bits.len());

    buf.put_u8(MSG_CODE_BITFIELD);
    buf.put_slice(&bits.to_bytes());

    buf.freeze()
}

fn serialize_request(index: u32, begin: u32, piece: u32) -> Bytes {
    let mut buf = buf_with_len(MSG_LEN_REQUEST);

    buf.put_u8(MSG_CODE_REQUEST);
    buf.put_u32(index);
    buf.put_u32(begin);
    buf.put_u32(piece);

    buf.freeze()
}

fn serialize_piece(index: u32, begin: u32, data: &[u8]) -> Bytes {
    let msg_len = MSG_MIN_LEN_PIECE + data.len();
    let mut buf = buf_with_len(msg_len);

    buf.put_u8(MSG_CODE_PIECE);
    buf.put_u32(index);
    buf.put_u32(begin);
    buf.put_slice(data);

    buf.freeze()
}

fn serialize_cancel(index: u32, begin: u32, piece: u32) -> Bytes {
    let mut buf = buf_with_len(MSG_LEN_CANCEL);

    buf.put_u8(MSG_CODE_CANCEL);
    buf.put_u32(index);
    buf.put_u32(begin);
    buf.put_u32(piece);

    buf.freeze()
}

#[derive(Eq, PartialEq, Debug)]
pub enum Handshake<'a> {
    Bittorrent(&'a Hash, &'a PeerId),
    Other,
}

pub struct TcpConn<T>
where
    T: Sized + Unpin + AsyncRead + AsyncWrite,
{
    inner: T,
    buf: BytesMut,
}

impl<T> TcpConn<T>
where
    T: Sized + Unpin + AsyncRead + AsyncWrite,
{
    pub fn new(stream: T) -> TcpConn<T> {
        let buf = BytesMut::with_capacity(BUF_SIZE);
        return TcpConn { buf, inner: stream };
    }

    pub async fn read_handshake(&mut self) -> BitterResult<Handshake> {
        let mut nbytes = 0;
        let mut ptr = 0;

        if !self.buf.is_empty() {
            panic!("wrong usage of read_handshake");
        }
        while nbytes < MSG_LEN_BITTORRENT_HANDSHAKE {
            nbytes += self
                .inner
                .read_buf(&mut self.buf)
                .await
                .map_err(BitterMistake::new_err)?;
        }

        let slice = &self.buf[ptr..ptr + MSG_LEN_BITTORRENT_HANDSHAKE];

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
                .inner
                .read_buf(&mut self.buf)
                .await
                .map_err(BitterMistake::new_err)?;
        }
        let msg_len = u32::from_be_bytes(self.buf[..MSG_LEN_LEN].try_into().unwrap()) as usize;

        if msg_len > MAX_PACKET_LEN {
            return Err(BitterMistake::new_owned(format!("packet too large: {msg_len} bytes")));
        } else if msg_len == 0 {
            return Ok(Packet::Keepalive);
        }
        while nbytes < msg_len + MSG_LEN_LEN {
            nbytes += self
                .inner
                .read_buf(&mut self.buf)
                .await
                .map_err(BitterMistake::new_err)?;
        }

        Packet::parse(&self.buf[MSG_LEN_LEN..MSG_LEN_LEN + msg_len])
    }
    pub async fn write<'a>(&mut self, packet: &Packet<'a>) -> BitterResult<()> {
        let mut buf = packet.serialize();
        while buf.has_remaining() {
            self.inner
                .write_buf(&mut buf)
                .await
                .map_err(BitterMistake::new_err)?;
        }
        Ok(())
    }

    pub async fn close(&mut self) {
        self.inner.shutdown().await;
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
    parse_request_internal(buf).map(|(index, begin, length)| Packet::Request {
        index,
        begin,
        length,
    })
}

fn parse_piece(buf: &[u8]) -> BitterResult<Packet> {
    if buf.len() < MSG_MIN_LEN_PIECE - MSG_TYPE_LEN {
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
    parse_request_internal(buf).map(|(index, begin, length)| Packet::Cancel {
        index,
        begin,
        length,
    })
}

fn parse_request_internal(buf: &[u8]) -> BitterResult<(u32, u32, u32)> {
    if buf.len() != MSG_LEN_REQUEST - MSG_TYPE_LEN {
        return Err(BitterMistake::new(INCORRECT_LEN_ERROR));
    }

    let (index_buf, buf) = buf.split_at(4);
    let (begin_buf, buf) = buf.split_at(4);
    let piece_buf = &buf[..4];

    let index = u32::from_be_bytes(index_buf.try_into().unwrap());
    let begin = u32::from_be_bytes(begin_buf.try_into().unwrap());
    let piece = u32::from_be_bytes(piece_buf.try_into().unwrap());

    Ok((index, begin, piece))
}
