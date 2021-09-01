use std::{
    fs::File,
    io,
    io::{Seek, SeekFrom},
    path::{Path, PathBuf},
};

use crate::{io::DiscIO, streams::ReadStream, Result};

pub(crate) struct DiscIOISO {
    pub(crate) filename: PathBuf,
}

impl DiscIOISO {
    pub(crate) fn new(filename: &Path) -> Result<DiscIOISO> {
        Result::Ok(DiscIOISO { filename: filename.to_owned() })
    }
}

impl DiscIO for DiscIOISO {
    fn begin_read_stream(&self, offset: u64) -> io::Result<Box<dyn ReadStream>> {
        let mut file = File::open(&*self.filename)?;
        file.seek(SeekFrom::Start(offset))?;
        io::Result::Ok(Box::from(file))
    }
}
