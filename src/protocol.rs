use crate::{
    metainfo::{Hash, PeerId, BITTORRENT_HASH_LEN, BITTORRENT_PEERID_LEN},
    utils::BitterMistake,
};
use bit_vec::BitVec;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::mem::size_of;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::utils::BitterResult;

// Common constants
const MAX_PACKET_LEN: usize = 1024 * 1024 * 8;
pub const DEFAULT_BUF_SIZE: usize = MAX_PACKET_LEN as usize;
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

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum Packet {
    Choke,
    Unchoke,
    Interested,
    NotInterested,
    Have(u32),
    Bitfield(BitVec),
    Request { index: u32, begin: u32, length: u32 },
    Piece { index: u32, begin: u32, data: Bytes },
    Cancel { index: u32, begin: u32, length: u32 },
    Handshake(Handshake),
    Keepalive,
}

static KEEPALIVE_BYTES: &[u8] = (0 as u32).to_be_bytes().as_slice();

impl Packet {
    pub fn parse(mut buf: Bytes) -> BitterResult<Self> {
        let msg_type = buf.get_u8();

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
            Packet::Keepalive => Bytes::from_static(KEEPALIVE_BYTES),
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
    let len = u32::to_be_bytes(1);

    let pieces = vec![len[0], len[1], len[2], len[3], msg_code];

    Bytes::from(pieces)
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
    buf.put_slice(info_hash);
    buf.put_slice(peer_id);

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

#[derive(Eq, PartialEq, Debug, Clone)]
pub enum Handshake {
    Bittorrent(Hash, PeerId),
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
    pub fn new(stream: T, buf_size: usize) -> TcpConn<T> {
        let buf = BytesMut::with_capacity(buf_size);
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

        let len = self.buf.get_u8();
        ptr = 1;

        if len != BITTORRENT_PROTO_LEN as u8 {
            return Err(BitterMistake::new(
                "protocol name length doesn't match any known protocols",
            ));
        }

        let proto_name = self.buf.split_to(BITTORRENT_PROTO_LEN);
        if &proto_name != BITTORRENT_PROTO {
            return Err(BitterMistake::new("unknown protocol"));
        }

        let _reserved = self.buf.split_to(RESERVED_LEN);

        let info_hash: Hash = self
            .buf
            .split_to(BITTORRENT_HASH_LEN)
            .as_ref()
            .try_into()
            .unwrap();
        let peer_id: PeerId = self
            .buf
            .split_to(BITTORRENT_PEERID_LEN)
            .as_ref()
            .try_into()
            .unwrap();

        Ok(Handshake::Bittorrent(info_hash, peer_id))
    }

    pub async fn read(&mut self) -> BitterResult<Packet> {
        let mut nbytes = self.buf.remaining();

        while nbytes < MSG_LEN_LEN {
            nbytes += self
                .inner
                .read_buf(&mut self.buf)
                .await
                .map_err(BitterMistake::new_err)?;
        }
        let msg_len = self.buf.get_u32() as usize;

        if msg_len > MAX_PACKET_LEN {
            return Err(BitterMistake::new_owned(format!(
                "packet too large: {msg_len} bytes"
            )));
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

        Packet::parse(self.buf.split_to(msg_len).freeze())
    }

    pub async fn write<'a>(&mut self, packet: &Packet) -> BitterResult<()> {
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

fn parse_have<'a>(mut buf: Bytes) -> BitterResult<Packet> {
    if buf.remaining() != 4 {
        return Err(BitterMistake::new(INCORRECT_LEN_ERROR));
    }
    let pieceno = buf.get_u32();
    Ok(Packet::Have(pieceno))
}

fn parse_bitfield<'a>(buf: Bytes) -> BitterResult<Packet> {
    Ok(Packet::Bitfield(BitVec::from_bytes(&buf)))
}

fn parse_request<'a>(buf: Bytes) -> BitterResult<Packet> {
    parse_request_internal(buf).map(|(index, begin, length)| Packet::Request {
        index,
        begin,
        length,
    })
}

fn parse_piece<'a>(mut buf: Bytes) -> BitterResult<Packet> {
    if buf.remaining() < MSG_MIN_LEN_PIECE - MSG_TYPE_LEN {
        return Err(BitterMistake::new(INCORRECT_LEN_ERROR));
    }
    let index = buf.get_u32();
    let begin = buf.get_u32();

    Ok(Packet::Piece {
        index,
        begin,
        data: buf,
    })
}

fn parse_cancel<'a>(buf: Bytes) -> BitterResult<Packet> {
    parse_request_internal(buf).map(|(index, begin, length)| Packet::Cancel {
        index,
        begin,
        length,
    })
}

fn parse_request_internal(mut buf: Bytes) -> BitterResult<(u32, u32, u32)> {
    if buf.remaining() != MSG_LEN_REQUEST - MSG_TYPE_LEN {
        return Err(BitterMistake::new(INCORRECT_LEN_ERROR));
    }

    let index = buf.get_u32();
    let begin = buf.get_u32();
    let piece = buf.get_u32();

    Ok((index, begin, piece))
}

#[cfg(test)]
mod tests {
    use bit_vec::BitVec;
    use bytes::Bytes;
    use tokio::io::duplex;

    use crate::metainfo::Hash;
    use crate::peer;
    use crate::protocol::{Handshake, DEFAULT_BUF_SIZE, MAX_PACKET_LEN};

    use super::{Packet, TcpConn};

    #[test]
    fn test_ser_de() {
        let have_packet = Packet::Have(29);
        let bitfield_packet = Packet::Bitfield(BitVec::from_bytes(&[9, 8, 128, 0, 1]));
        let request_packet = Packet::Request {
            index: 111,
            begin: 256,
            length: 512,
        };
        let cancel_packet = Packet::Cancel {
            index: 112,
            begin: 512,
            length: 256,
        };
        // Piece packet is tested in piece_sending test
        for sent_packet in vec![
            Packet::Unchoke,
            Packet::Choke,
            Packet::Interested,
            Packet::NotInterested,
            have_packet,
            bitfield_packet,
            request_packet,
            cancel_packet,
        ] {
            let recv_packet = Packet::parse(sent_packet.serialize().split_off(4)).unwrap();

            assert_eq!(sent_packet, recv_packet);
        }
    }

    #[tokio::test]
    async fn test_handshake_sending() {
        let (input, output) = duplex(usize::pow(2, 10));
        let mut inconn = TcpConn::new(input, DEFAULT_BUF_SIZE);
        let mut outconn = TcpConn::new(output, DEFAULT_BUF_SIZE);
        let hash: Hash = [7; 20];
        let peer_id = [3; 20];
        let sent_packet = Handshake::Bittorrent(hash, peer_id);

        inconn
            .write(&Packet::Handshake(sent_packet.clone()))
            .await
            .unwrap();

        let recv_packet = outconn.read_handshake().await.unwrap();

        assert_eq!(sent_packet, recv_packet);
    }

    #[tokio::test]
    async fn test_piece_sending() {
        let (input, output) = duplex(usize::pow(2, 10));
        let piece = Bytes::copy_from_slice(&[0, 1, 2, 3]);
        let mut inconn = TcpConn::new(input, DEFAULT_BUF_SIZE);
        let mut outconn = TcpConn::new(output, DEFAULT_BUF_SIZE);
        let sent_packet = Packet::Piece {
            index: 0,
            begin: 10,
            data: piece.clone(),
        };

        inconn.write(&sent_packet).await.unwrap();

        let recv_packet = outconn.read().await.unwrap();

        assert_eq!(sent_packet, recv_packet);
    }

    #[tokio::test]
    async fn test_keepalive_sending() {
        let (input, output) = duplex(usize::pow(2, 10));
        let mut inconn = TcpConn::new(input, DEFAULT_BUF_SIZE);
        let mut outconn = TcpConn::new(output, DEFAULT_BUF_SIZE);
        let sent_packet = Packet::Keepalive;

        inconn.write(&sent_packet).await.unwrap();

        let recv_packet = outconn.read().await.unwrap();

        assert_eq!(sent_packet, recv_packet);
    }

    #[tokio::test]
    async fn test_handshake_and_packet() {
        let (input, output) = duplex(usize::pow(2, 10));
        let mut inconn = TcpConn::new(input, DEFAULT_BUF_SIZE);
        let mut outconn = TcpConn::new(output, DEFAULT_BUF_SIZE);
        let hash: Hash = [7; 20];
        let peer_id = [3; 20];

        let sent_packet = Handshake::Bittorrent(hash, peer_id);
        inconn
            .write(&Packet::Handshake(sent_packet.clone()))
            .await
            .unwrap();
        let recv_packet = outconn.read_handshake().await.unwrap();
        assert_eq!(sent_packet, recv_packet);

        let sent_packet = Packet::Keepalive;
        inconn.write(&sent_packet).await.unwrap();
        let recv_packet = outconn.read().await.unwrap();
        assert_eq!(sent_packet, recv_packet);
    }

    #[tokio::test]
    async fn test_multiple_packets() {
        let (input, output) = duplex(usize::pow(2, 10));
        let mut inconn = TcpConn::new(input, DEFAULT_BUF_SIZE);
        let mut outconn = TcpConn::new(output, DEFAULT_BUF_SIZE);

        inconn.write(&Packet::Interested).await.unwrap();
        inconn.write(&Packet::NotInterested).await.unwrap();

        let packet1 = outconn.read().await.unwrap();
        assert!(matches!(packet1, Packet::Interested));

        let packet2 = outconn.read().await.unwrap().to_owned();
        assert!(matches!(packet2, Packet::NotInterested));
    }

    #[tokio::test]
    async fn test_recv_buffer_override() {
        let (input, output) = duplex(usize::pow(2, 10));
        let mut inconn = TcpConn::new(input, 92);
        let mut outconn = TcpConn::new(output, 92);
        let piece1 = Packet::Piece {
            index: 0,
            begin: 0,
            data: Bytes::from(vec![1; 64]),
        };
        let piece2 = Packet::Piece {
            index: 0,
            begin: 64,
            data: Bytes::from(vec![2; 64]),
        };

        inconn.write(&piece1).await.unwrap();
        inconn.write(&piece2).await.unwrap();

        let recv_piece1 = outconn.read().await.unwrap();
        assert_eq!(piece1, recv_piece1);

        let recv_piece2 = outconn.read().await.unwrap();
        assert_eq!(piece2, recv_piece2);
    }

    #[tokio::test]
    async fn test_recv_buffer_overlap() {
        let (input, output) = duplex(usize::pow(2, 10));
        let mut inconn = TcpConn::new(input, 80);
        let mut outconn = TcpConn::new(output, 80);
        let piece1 = Packet::Piece {
            index: 0,
            begin: 0,
            data: Bytes::from(vec![1; 64]),
        };
        let piece2 = Packet::Piece {
            index: 0,
            begin: 64,
            data: Bytes::from(vec![2; 64]),
        };

        inconn.write(&piece1).await.unwrap();

        let recv_piece1 = outconn.read().await.unwrap();
        assert_eq!(piece1, recv_piece1);

        inconn.write(&piece2).await.unwrap();

        let recv_piece2 = outconn.read().await.unwrap();
        assert_eq!(piece2, recv_piece2);
    }

    #[tokio::test]
    async fn test_packet_too_large() {
        let (input, output) = duplex(MAX_PACKET_LEN * 2);
        let mut inconn = TcpConn::new(input, 32);
        let mut outconn = TcpConn::new(output, 32);
        let piece1 = Packet::Piece {
            index: 0,
            begin: 0,
            data: Bytes::from(vec![1; MAX_PACKET_LEN]),
        };

        inconn.write(&piece1).await.unwrap();

        let res = outconn.read().await;
        assert!(res.is_err());
    }
}
