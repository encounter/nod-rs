# nod-rs [![Build Status]][actions] [![Latest Version]][crates.io] [![Api Rustdoc]][rustdoc] ![Rust Version]

[Build Status]: https://github.com/encounter/nod-rs/actions/workflows/build.yaml/badge.svg
[actions]: https://github.com/encounter/nod-rs/actions
[Latest Version]: https://img.shields.io/crates/v/nod.svg
[crates.io]: https://crates.io/crates/nod
[Api Rustdoc]: https://img.shields.io/badge/api-rustdoc-blue.svg
[rustdoc]: https://docs.rs/nod
[Rust Version]: https://img.shields.io/badge/rust-1.73+-blue.svg?maxAge=3600

Library for traversing & reading GameCube and Wii disc images.

Originally based on the C++ library [nod](https://github.com/AxioDL/nod),
but does not currently support authoring.

Currently supported file formats:
- ISO (GCM)
- WIA / RVZ
- WBFS (+ NKit 2 lossless)
- CISO (+ NKit 2 lossless)
- NFS (Wii U VC)

## CLI tool

This crate includes a command-line tool called `nodtool`. 

### info

Displays information about a disc image.

```shell
nodtool info /path/to/game.iso
```

### extract

Extracts the contents of a disc image to a directory.

```shell
nodtool extract /path/to/game.iso [outdir]
```

For Wii U VC titles, use `content/hif_000000.nfs`:

```shell
nodtool extract /path/to/game/content/hif_000000.nfs [outdir]
```

### convert

Converts any supported format to raw ISO.

```shell
nodtool convert /path/to/game.wia /path/to/game.iso
``` 

### verify

Hashes the contents of a disc image and verifies it.

```shell
nodtool verify /path/to/game.iso
```

## Library example

Opening a disc image and reading a file:

```rust
use std::io::Read;

use nod::{Disc, PartitionKind};

fn main() -> nod::Result<()> {
    let disc = Disc::new("path/to/file.iso")?;
    let mut partition = disc.open_partition_kind(PartitionKind::Data)?;
    let meta = partition.meta()?;
    let fst = meta.fst()?;
    if let Some((_, node)) = fst.find("/MP3/Worlds.txt") {
        let mut s = String::new();
        partition
            .open_file(node)
            .expect("Failed to open file stream")
            .read_to_string(&mut s)
            .expect("Failed to read file");
        println!("{}", s);
    }
    Ok(())
}
```

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
