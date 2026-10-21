//! Mounts arbitrary binaries and firmware images as navigable FUSE filesystems using Binwalk v3.
//!
//! `fuse-binwalk` analyzes a binary image for embedded file signatures with known start and end
//! byte boundaries and exposes them through a virtual filesystem hierarchy:
//!
//! - `/raw/` exposes zero-copy or windowed byte slices mapped directly to each signature's
//!   [`ByteSpan`].
//! - `/extracted/` exposes directories populated lazily on first access by running Binwalk
//!   extractors strictly within the signature's [`ByteSpan`].
//! - `/manifest.json` exposes a serialized [`ManifestDocument`] cataloging every discovered region.
//!
//! When mounted with [`WritePolicy::InPlaceBounded`] or [`WritePolicy::CopyOnWriteOverlay`],
//! modifications to `/raw/` slices and repacked `/extracted/` containers are written back into
//! their bounded spans in the [`BinaryStore`].
//!
//! # Examples
//!
//! ```
//! use std::sync::Arc;
//! use fuse_binwalk::{
//!     scan_bounded_signatures, BinwalkFs, OverlayBinaryStore, ScanConfig, WritePolicy, ROOT_INO,
//! };
//!
//! let binary_data = vec![0u8; 64];
//! let entries = scan_bounded_signatures(&binary_data, &ScanConfig::default())?;
//! let store = Arc::new(OverlayBinaryStore::from_bytes(
//!     binary_data,
//!     None,
//!     WritePolicy::ReadOnly,
//! ));
//! let mut fs = BinwalkFs::new(store, entries)?;
//!
//! let root_entries = fs.list_directory(ROOT_INO).expect("root directory should list");
//! assert!(root_entries.iter().any(|e| e.name == "manifest.json"));
//! # Ok::<(), anyhow::Error>(())
//! ```

pub mod extractor;
pub mod fs;
pub mod repackers;
pub mod scanner;
pub mod storage;

pub use extractor::{ExtractionManager, ExtractionRecord, RegionRepacker, RepackerRegistry};
pub use fs::{BinwalkFs, EXTRACTED_DIR_INO, MANIFEST_INO, RAW_DIR_INO, ROOT_INO};
pub use scanner::{
    build_manifest, scan_bounded_signatures, CarvedEntry, ConfidenceLevel, ManifestDocument,
    ManifestEntry, ScanConfig,
};
pub use storage::{
    smart_pad_byte, BinaryStore, ByteSpan, OverlayBinaryStore, StorageError, WritePolicy,
};

/// Scans `binary_path`, daemonizes the current process, and serves a [`BinwalkFs`] mount at
/// `mount_point` until unmounted or terminated.
///
/// # Errors
///
/// Returns an error if reading `binary_path`, scanning signatures, initializing [`BinwalkFs`],
/// daemonizing, or mounting the FUSE filesystem fails.
pub fn run_mount_daemon(
    binary_path: &std::path::Path,
    mount_point: &std::path::Path,
    writable: bool,
) -> anyhow::Result<()> {
    use anyhow::Context;

    let policy = if writable {
        WritePolicy::InPlaceBounded {
            pad_byte: None,
            write_through: true,
        }
    } else {
        WritePolicy::ReadOnly
    };

    let store = std::sync::Arc::new(
        OverlayBinaryStore::from_file(binary_path, policy)
            .with_context(|| format!("Failed to open '{}'", binary_path.display()))?,
    );

    let scan_config = ScanConfig::default();
    let entries = scan_bounded_signatures(store.base_bytes(), &scan_config)
        .context("Failed to scan signatures")?;

    let fs = BinwalkFs::new(store, entries).context("Failed to initialize BinwalkFs")?;

    let options = vec![
        if writable {
            fuser::MountOption::RW
        } else {
            fuser::MountOption::RO
        },
        fuser::MountOption::FSName("fuse-binwalk".to_string()),
        fuser::MountOption::Subtype("binwalk".to_string()),
    ];

    let daemonize = daemonize::Daemonize::new().working_directory("/");
    daemonize
        .start()
        .context("Failed to daemonize fuse-binwalk process")?;

    let session = fuser::spawn_mount2(fs, mount_point, &options)
        .with_context(|| format!("Failed to spawn FUSE mount at '{}'", mount_point.display()))?;

    let (tx, rx) = std::sync::mpsc::channel();
    let _ = ctrlc::set_handler(move || {
        let _ = tx.send(());
    });

    let _ = rx.recv();
    drop(session);
    Ok(())
}
