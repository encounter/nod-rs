# nod-rs [![Build Status]][actions] [![Latest Version]][crates.io] [![Api Rustdoc]][rustdoc] ![Rust Version]

[Build Status]: https://github.com/encounter/nod-rs/workflows/build/badge.svg
[actions]: https://github.com/encounter/nod-rs/actions
[Latest Version]: https://img.shields.io/crates/v/nod.svg
[crates.io]: https://crates.io/crates/nod
[Api Rustdoc]: https://img.shields.io/badge/api-rustdoc-blue.svg
[rustdoc]: https://docs.rs/nod
[Rust Version]: https://img.shields.io/badge/rust-1.57+-blue.svg?maxAge=3600

Library for traversing & reading GameCube and Wii disc images.

Based on the C++ library [nod](https://github.com/AxioDL/nod),
but does not currently support authoring.

Currently supported file formats:
- ISO (GCM)
- WIA / RVZ
- WBFS
- NFS (Wii U VC files, e.g. `hif_000000.nfs`)

### CLI tool

This crate includes a CLI tool `nodtool`, which can be used to extract disc images to a specified directory:

```shell
nodtool extract /path/to/game.iso [outdir]
```

For Wii U VC titles, use `content/hif_*.nfs`:

```shell
nodtool extract /path/to/game/content/hif_000000.nfs [outdir]
```

### Library example

Opening a disc image and reading a file:

```rust
use std::io::Read;

use nod::{
    disc::{new_disc_base, PartHeader},
    fst::NodeType,
    io::{new_disc_io, DiscIOOptions},
};

fn main() -> nod::Result<()> {
    let options = DiscIOOptions::default();
    let mut disc_io = new_disc_io("path/to/file.iso".as_ref(), &options)?;
    let disc_base = new_disc_base(disc_io.as_mut())?;
    let mut partition = disc_base.get_data_partition(disc_io.as_mut(), false)?;
    let header = partition.read_header()?;
    if let Some(NodeType::File(node)) = header.find_node("/MP3/Worlds.txt") {
        let mut s = String::new();
        partition
            .begin_file_stream(node)
            .expect("Failed to open file stream")
            .read_to_string(&mut s)
            .expect("Failed to read file");
        println!("{}", s);
    }
    Ok(())
}
```

### License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
