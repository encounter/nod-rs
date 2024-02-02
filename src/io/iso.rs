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
        Ok(DiscIOISO { filename: filename.to_owned() })
    }
}

impl DiscIO for DiscIOISO {
    fn begin_read_stream(&mut self, offset: u64) -> io::Result<Box<dyn ReadStream>> {
        let mut file = File::open(&*self.filename)?;
        file.seek(SeekFrom::Start(offset))?;
        Ok(Box::from(file))
    }
}

pub(crate) struct DiscIOISOStream<T>
where T: ReadStream + Sized
{
    pub(crate) stream: T,
}

impl<T> DiscIOISOStream<T>
where T: ReadStream + Sized
{
    pub(crate) fn new(stream: T) -> Result<DiscIOISOStream<T>> { Ok(DiscIOISOStream { stream }) }
}

impl<T> DiscIO for DiscIOISOStream<T>
where T: ReadStream + Sized + Send + Sync
{
    fn begin_read_stream<'a>(&'a mut self, offset: u64) -> io::Result<Box<dyn ReadStream + 'a>> {
        let size = self.stream.stable_stream_len()?;
        let mut stream = self.stream.new_window(0, size)?;
        stream.seek(SeekFrom::Start(offset))?;
        Ok(Box::from(stream))
    }
}
