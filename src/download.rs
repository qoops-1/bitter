fn download(metainfo: Metainfo) {}

enum AnnounceEvent {
    Started,
    Completed,
    Stopped,
    Empty,
}

struct PeersRequest {
    info_hash: Vec<u8>,
    peer_id: String,
    ip: IPAddr,
    port: u16,
    uploaded: u64,
    downloaded: u64,
    left: u64,
    event: AnnounceEvent,
}

fn get_peers(req: PeersRequest) {}
