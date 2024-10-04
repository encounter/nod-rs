pub mod digest;
pub mod redump;
pub mod shared;

use std::{
    fmt,
    fmt::Write,
    path::{Path, MAIN_SEPARATOR},
};

pub fn display(path: &Path) -> PathDisplay { PathDisplay { path } }

pub struct PathDisplay<'a> {
    path: &'a Path,
}

impl fmt::Display for PathDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for segment in self.path.iter() {
            let segment_str = segment.to_string_lossy();
            if segment_str == "." {
                continue;
            }
            if first {
                first = false;
            } else {
                f.write_char(MAIN_SEPARATOR)?;
            }
            f.write_str(&segment_str)?;
        }
        Ok(())
    }
}

pub fn has_extension(filename: &Path, extension: &str) -> bool {
    match filename.extension() {
        Some(ext) => ext.eq_ignore_ascii_case(extension),
        None => false,
    }
}
