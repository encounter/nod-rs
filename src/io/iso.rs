use std::{io::BufReader, path::Path};

use crate::{
    io::{split::SplitFileReader, DiscIO},
    streams::ReadStream,
    Result,
};

pub struct DiscIOISO {
    pub inner: SplitFileReader,
}

impl DiscIOISO {
    pub fn new(filename: &Path) -> Result<Self> {
        Ok(Self { inner: SplitFileReader::new(filename)? })
    }
}

impl DiscIO for DiscIOISO {
    fn open(&self) -> Result<Box<dyn ReadStream>> {
        Ok(Box::new(BufReader::new(self.inner.clone())))
    }

    fn disc_size(&self) -> Option<u64> { Some(self.inner.len()) }
}
