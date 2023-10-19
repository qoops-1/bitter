use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use bit_vec::BitVec;

#[derive(Clone)]
pub struct Accounting {
    available: BitVec,
    downloaded: Arc<Vec<AtomicBool>>,
    reserved: Arc<Vec<AtomicBool>>,
}

impl Accounting {
    pub fn new(total: usize) -> Accounting {
        let mut downloaded = Vec::with_capacity(total);
        let mut reserved = Vec::with_capacity(total);
        downloaded.fill_with(AtomicBool::default);
        reserved.fill_with(AtomicBool::default);

        return Accounting {
            available: BitVec::with_capacity(0),
            downloaded: Arc::new(downloaded),
            reserved: Arc::new(reserved),
        };
    }

    pub fn init_available(&mut self, available: BitVec) {
        self.available = available;
    }

    pub fn mark_available(&mut self, pieceno: usize) {
        self.available.set(pieceno, true);
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
