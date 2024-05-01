use std::{
    fmt,
    sync::{
        mpsc::{sync_channel, SyncSender},
        Arc,
    },
    thread,
    thread::JoinHandle,
};

use digest::{Digest, Output};

pub type DigestThread = (SyncSender<Arc<[u8]>>, JoinHandle<DigestResult>);

pub fn digest_thread<H>() -> DigestThread
where H: Hasher + Send + 'static {
    let (tx, rx) = sync_channel::<Arc<[u8]>>(1);
    let handle = thread::spawn(move || {
        let mut hasher = H::new();
        while let Ok(data) = rx.recv() {
            hasher.update(data.as_ref());
        }
        hasher.finalize()
    });
    (tx, handle)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DigestResult {
    Crc32(u32),
    Md5([u8; 16]),
    Sha1([u8; 20]),
    Xxh64(u64),
}

impl DigestResult {
    pub fn name(&self) -> &'static str {
        match self {
            DigestResult::Crc32(_) => "CRC32",
            DigestResult::Md5(_) => "MD5",
            DigestResult::Sha1(_) => "SHA-1",
            DigestResult::Xxh64(_) => "XXH64",
        }
    }
}

impl fmt::Display for DigestResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DigestResult::Crc32(crc) => write!(f, "{:08x}", crc),
            DigestResult::Md5(md5) => write!(f, "{:032x}", <Output<md5::Md5>>::from(*md5)),
            DigestResult::Sha1(sha1) => write!(f, "{:040x}", <Output<sha1::Sha1>>::from(*sha1)),
            DigestResult::Xxh64(xxh64) => write!(f, "{:016x}", xxh64),
        }
    }
}

pub trait Hasher {
    fn new() -> Self;
    fn finalize(self) -> DigestResult;
    fn update(&mut self, data: &[u8]);
}

impl Hasher for md5::Md5 {
    fn new() -> Self { Digest::new() }

    fn finalize(self) -> DigestResult { DigestResult::Md5(Digest::finalize(self).into()) }

    fn update(&mut self, data: &[u8]) { Digest::update(self, data) }
}

impl Hasher for sha1::Sha1 {
    fn new() -> Self { Digest::new() }

    fn finalize(self) -> DigestResult { DigestResult::Sha1(Digest::finalize(self).into()) }

    fn update(&mut self, data: &[u8]) { Digest::update(self, data) }
}

impl Hasher for crc32fast::Hasher {
    fn new() -> Self { crc32fast::Hasher::new() }

    fn finalize(self) -> DigestResult { DigestResult::Crc32(crc32fast::Hasher::finalize(self)) }

    fn update(&mut self, data: &[u8]) { crc32fast::Hasher::update(self, data) }
}

impl Hasher for xxhash_rust::xxh64::Xxh64 {
    fn new() -> Self { xxhash_rust::xxh64::Xxh64::new(0) }

    fn finalize(self) -> DigestResult {
        DigestResult::Xxh64(xxhash_rust::xxh64::Xxh64::digest(&self))
    }

    fn update(&mut self, data: &[u8]) { xxhash_rust::xxh64::Xxh64::update(self, data) }
}
