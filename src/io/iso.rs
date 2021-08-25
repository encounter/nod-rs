use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::io;
use std::path::{Path, PathBuf};

use crate::io::DiscIO;
use crate::Result;
use crate::streams::ReadStream;

pub(crate) struct DiscIOISO {
    pub(crate) filename: PathBuf,
}

pub(crate) fn new_disc_io_iso(filename: &Path) -> Result<DiscIOISO> {
    Result::Ok(DiscIOISO {
        filename: filename.to_owned(),
    })
}

impl DiscIO for DiscIOISO {
    fn begin_read_stream(&self, offset: u64) -> io::Result<Box<dyn ReadStream>> {
        let mut file = File::open(&*self.filename)?;
        file.seek(SeekFrom::Start(offset))?;
        io::Result::Ok(Box::from(file))
    }
}
