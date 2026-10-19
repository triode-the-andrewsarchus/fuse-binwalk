# fuse-binwalk

A Rust FUSE filesystem driver powered by [Binwalk v3](https://docs.rs/binwalk/latest/binwalk/) and [`fuser`](https://docs.rs/fuser/latest/fuser/) that mounts any arbitrary binary or firmware image as a navigable filesystem.

## Features

- **Bounded Signature Discovery**: Uses Binwalk v3's signature table and parsers via overlapping Aho-Corasick scanning, exposing only signatures where the parser explicitly reports a known start and end byte (`size > 0` and `offset + size <= binary_len`), including nested/overlapping signatures.
- **Top-Level Category Layout**:
  - `/raw/` — Zero-copy/windowed byte slices (`0x<START>_0x<END>_<sig_name>.<ext>`) mapped directly from the binary's `[start..end]` byte range.
  - `/extracted/` — Directories (`0x<START>_0x<END>_<sig_name>/`) for signatures with a defined Binwalk extractor. Populated **lazily on-demand** upon first access, strictly bounded to `[start..end]`. If an extractor fails, an `_extraction_status.txt` diagnostic file is generated in the directory.
  - `/manifest.json` — Structured JSON catalog of all discovered bounded regions, offsets, sizes, confidence levels, and virtual paths.
- **Write-Ready Storage & Repacking Architecture**:
  - `BinaryStore` / `OverlayBinaryStore` supports `WritePolicy::ReadOnly` (current default), `WritePolicy::InPlaceBounded` (bounded `[start..end]` writes with optional padding), and `WritePolicy::CopyOnWriteOverlay` (in-memory CoW range overlay with explicit `commit()`).
  - `RegionRepacker` & `RepackerRegistry` allow registering format repackers that serialize modified `/extracted/<entry>/` directories back into their parent `[start..end]` binary span.

## Usage

```bash
cargo run -- <BINARY_PATH> <MOUNTPOINT> [OPTIONS]
```

### CLI Options

- `<BINARY_PATH>`: Path to the binary or firmware image to mount
- `<MOUNTPOINT>`: Directory where the FUSE filesystem will be mounted
- `--min-confidence <low|medium|high>`: Minimum signature confidence level (default: `low`)
- `--include <SIG1,SIG2,...>`: Only scan for specific Binwalk signature names
- `--exclude <SIG1,SIG2,...>`: Exclude specific Binwalk signature names
- `--full-search`: Scan for short signatures throughout the entire file instead of only at offset 0
- `-d, --daemon`: Run as a background daemon instead of staying in the foreground
- `--allow-other`: Allow other system users to access the FUSE mount
