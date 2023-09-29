use std::sync::atomic::{AtomicBool, Ordering};

pub struct Accounting {
    downloaded: Vec<AtomicBool>,
    reserved: Vec<AtomicBool>,
}

impl Accounting {
    pub fn new(total: usize) -> Accounting {
        let mut downloaded = Vec::with_capacity(total);
        let mut reserved = Vec::with_capacity(total);
        downloaded.fill_with(|| AtomicBool::default());
        reserved.fill_with(|| AtomicBool::default());

        return Accounting {
            downloaded,
            reserved,
        };
    }
    pub fn piece_downloaded(&self, pieceno: usize) -> bool {
        self.downloaded[pieceno].load(Ordering::Acquire)
    }
    pub fn piece_reserved(&self, pieceno: usize) -> bool {
        self.reserved[pieceno].load(Ordering::Acquire)
    }
    pub fn download(&self, pieceno: usize) -> bool {
        self.downloaded[pieceno].swap(true, Ordering::Acquire)
    }
    pub fn reserve(&self, pieceno: usize) -> bool {
        self.reserved[pieceno].swap(true, Ordering::Acquire)
    }
}
