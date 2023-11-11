use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use bit_vec::BitVec;
use rand::{rngs::ThreadRng, seq::SliceRandom, thread_rng, Rng};

#[derive(Clone)]
pub struct Accounting {
    rng: ThreadRng,
    available: Vec<usize>,
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
            rng: thread_rng(),
            available: Vec::with_capacity(0),
            downloaded: Arc::new(downloaded),
            reserved: Arc::new(reserved),
        };
    }

    pub fn init_available(&mut self, available: BitVec) {
        let mut avail_pieces: Vec<usize> = available
            .iter()
            .enumerate()
            .filter(|(_, val)| *val)
            .map(|(i, _)| i)
            .collect();

        avail_pieces.shuffle(&mut self.rng);
        self.available = avail_pieces;
    }

    pub fn mark_available(&mut self, pieceno: usize) {
        let spot: usize = self.rng.gen();
        if spot == self.available.len() {
            self.available.push(pieceno);
            return;
        }
        self.available.push(self.available[spot]);
        self.available[spot] = pieceno;
    }

    pub fn get_next_to_download(&self) -> Option<usize> {
        while let Some(i) = self.available.pop() {
            if !self.reserved[i].swap(true, Ordering::Acquire) {
                return Some(i);
            }
        }

        None
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
