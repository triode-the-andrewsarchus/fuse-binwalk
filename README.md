# fuse-binwalk

A Rust FUSE filesystem driver powered by [Binwalk v3](https://docs.rs/binwalk/latest/binwalk/) and [`fuser`](https://docs.rs/fuser/latest/fuser/) that mounts any arbitrary binary or firmware image as a navigable, writable filesystem.

## Features

- **Bounded Signature Discovery**: Uses Binwalk v3's signature table and parsers via overlapping Aho-Corasick scanning, exposing only signatures where the parser reports a known start and end byte (`size > 0` and `offset + size <= binary_len`), including nested/overlapping signatures.
- **Top-Level Category Layout**:
  - `/raw/` — Carved byte slices (`0x<START>_0x<END>_<sig_name>.<ext>`) mapped directly from the binary's `[start..end]` byte range.
  - `/extracted/` — Directories (`0x<START>_0x<END>_<sig_name>/`) for container/compression signatures. Populated **lazily on-demand** upon first access, strictly bounded to `[start..end]`. If an extractor fails, an `_extraction_status.txt` diagnostic file is generated in the directory.
  - `/manifest.json` — Live JSON catalog of all discovered bounded regions, offsets, sizes, active `payload_size`, remaining `slack_bytes` free-space budget, `modified` state, confidence levels, and virtual paths.
- **Extended Attributes (`xattr`)**:
  - Every `/raw/` slice and `/extracted/` node exposes `user.binwalk.*` extended attributes (`name`, `description`, `offset`, `end_offset`, `span_size`, `payload_size`, `slack_bytes`, `modified`, `confidence`, `writable`, `has_extractor`) queryable via `getfattr -d` or `attr`.
- **Memory-Mapped (`mmap`) Backing Store**:
  - Uses OS page-cache memory mapping (`mmap`) for the base binary image with a sparse Copy-on-Write overlay for modified spans, enabling fast startup and low memory overhead even on large images.
- **Full Write & Repacking Support**:
  - **Persistence Modes**: Read-only by default; supports `-w/--writable` (in-place write-through), `-o/--output <PATH>` (clones the binary to `<PATH>` and writes changes there), and `--cow` (buffers modifications in a Copy-on-Write memory overlay until `fsync` or unmount).
  - **Smart Padding & Size Safety**: Rejects writes exceeding a span's original `[start..end]` size (`ENOSPC`) so subsequent offsets in the binary are never shifted. Automatically pads shorter replacements on file close or repack using smart format-aware padding (`0x20` ASCII space for text/SVG/XML/PEM, `0x00` for binary formats), overridable via `--pad-byte <BYTE>` or disabled via `--strict-size`.
  - **Editor Atomic-Save Support in `/raw/`**: Supports ephemeral scratch files (`create`, `write`, `unlink`, `rename`) inside `/raw/` so standard tools (`vim`, `sed -i`, Inkscape, etc.) can atomically save onto `/raw/` slices.
  - **Automatic Nested Container Sync**: Modifying a `/raw/` slice invalidates overlapping `/extracted/` caches and, if the slice lies inside an uncompressed (`STORE`) ZIP archive entry (such as an `.svg` inside Firefox's `omni.ja`), automatically recomputes and patches the parent ZIP's Local File Header and Central Directory CRC32 checksums.
  - **Built-in `/extracted/` Container Repackers**: Includes built-in repackers for `zip` (delta-aware pure-Rust repacker preserving untouched entries' exact compressed streams), `tar` / `tarball`, `gzip`, `zlib`, `bzip2`, `xz`, `lzma`, `cpio`, `zstd`, `lz4`, and `squashfs`. Full POSIX operations (`create`, `write`, `mkdir`, `unlink`, `rmdir`, `symlink`, `rename`, `setattr`) are supported inside writable `/extracted/` directories, while formats without an available repacker remain read-only.

## Usage

```bash
# List discovered bounded signatures and repacker support without mounting
cargo run -- <BINARY_PATH> --list

# Dump the JSON manifest to stdout without mounting
cargo run -- <BINARY_PATH> --manifest

# Mount read-only
cargo run -- <BINARY_PATH> <MOUNTPOINT>

# Clone binary to a new file and mount read-write
cargo run -- <BINARY_PATH> <MOUNTPOINT> --output /path/to/modified.bin

# Mount read-write in-place with Copy-on-Write buffering until fsync/unmount
cargo run -- <BINARY_PATH> <MOUNTPOINT> --writable --cow
```

### CLI Options

- `<BINARY_PATH>`: Path to the binary or firmware image to analyze/mount
- `[MOUNTPOINT]`: Directory where the FUSE filesystem will be mounted (optional with `--list` or `--manifest`)
- `-l, --list`: List discovered bounded signatures and repacker support to stdout without mounting
- `--manifest`: Print the JSON manifest to stdout and exit without mounting
- `-w, --writable`: Enable write support (in-place write-through unless `--cow` is set)
- `-o, --output <PATH>`: Clone the input binary to `<PATH>` before mounting and write modifications there
- `--cow`: Buffer writes in a Copy-on-Write memory overlay until `fsync` or clean unmount
- `--pad-byte <BYTE>`: Explicit padding byte (e.g., `0x00`, `0xFF`, `0x20`) when a replacement is smaller than its span
- `--strict-size`: Reject replacements smaller than the original span unless `--pad-byte` is explicitly provided
- `--min-confidence <low|medium|high>`: Minimum signature confidence level (default: `low`)
- `--include <SIG1,SIG2,...>`: Only scan for specific Binwalk signature names
- `--exclude <SIG1,SIG2,...>`: Exclude specific Binwalk signature names
- `--full-search`: Scan for short signatures throughout the entire file instead of only at offset 0
- `-d, --daemon`: Run as a background daemon instead of staying in the foreground
- `--allow-other`: Allow other system users to access the FUSE mount
