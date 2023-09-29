use crate::metainfo::{Hash, PeerId};
use tokio::{io::AsyncWriteExt, net::TcpStream};

use crate::utils::BitterResult;

pub enum Packet {
    Handshake(Handshake),
}

#[derive(PartialEq)]
pub enum Handshake {
    Bittorrent(Hash, PeerId),
    Other,
}

pub struct TcpConn {
    stream: TcpStream,
}

impl TcpConn {
    pub fn new(stream: TcpStream) -> TcpConn {
        return TcpConn { stream };
    }
    pub async fn read_handshake(&self) -> BitterResult<Handshake> {
        unimplemented!()
    }
    pub async fn read(&self) -> BitterResult<Packet> {
        unimplemented!()
    }
    pub async fn write(&self, packet: Packet) -> BitterResult<()> {
        unimplemented!()
    }
    pub async fn close(&mut self) {
        self.stream.shutdown().await;
    }
}
