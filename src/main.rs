//! Command-line entry point for mounting binary images with `fuse-binwalk`.

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use fuse_binwalk::{
    scan_bounded_signatures, BinwalkFs, ConfidenceLevel, OverlayBinaryStore, ScanConfig,
    WritePolicy,
};
use fuser::MountOption;
use log::info;
use std::path::PathBuf;
use std::sync::mpsc::channel;
use std::sync::Arc;

/// Parses a single padding byte from a hexadecimal (`0x20`), single-character, or decimal string.
fn parse_pad_byte(s: &str) -> Result<u8, String> {
    let trimmed = s.trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u8::from_str_radix(hex, 16).map_err(|e| format!("invalid hex byte '{s}': {e}"))
    } else if trimmed.len() == 1 && !trimmed.chars().next().unwrap().is_ascii_digit() {
        Ok(trimmed.as_bytes()[0])
    } else {
        trimmed
            .parse::<u8>()
            .map_err(|e| format!("invalid byte value '{s}': {e}"))
    }
}

/// Command-line arguments for the `fuse-binwalk` executable.
#[derive(Debug, Parser)]
#[command(
    name = "fuse-binwalk",
    version,
    about = "Mount any arbitrary binary as a FUSE filesystem using Binwalk v3"
)]
struct Cli {
    /// Path to the binary image to analyze and mount.
    #[arg(value_name = "BINARY_PATH")]
    binary_path: PathBuf,

    /// Directory where the FUSE filesystem should be mounted.
    #[arg(value_name = "MOUNTPOINT")]
    mountpoint: PathBuf,

    /// Enables write support (in-place write-through to the target binary unless `--cow` is set).
    #[arg(short = 'w', long = "writable")]
    writable: bool,

    /// Clones the input binary to `<PATH>` before mounting and writes modifications there.
    #[arg(short = 'o', long = "output", value_name = "PATH")]
    output: Option<PathBuf>,

    /// Buffers writes in a Copy-on-Write memory overlay until `fsync` or clean unmount.
    #[arg(long)]
    cow: bool,

    /// Explicit padding byte (e.g., `0x00`, `0xFF`, `0x20`) when a replacement is smaller than its span.
    ///
    /// Defaults to smart padding (`0x20` space for text/SVG/XML/PEM, `0x00` for binary).
    #[arg(long, value_parser = parse_pad_byte, value_name = "BYTE")]
    pad_byte: Option<u8>,

    /// Rejects replacements that are smaller than the original span unless `--pad-byte` is explicitly provided.
    #[arg(long)]
    strict_size: bool,

    /// Minimum signature confidence threshold to include.
    #[arg(long, value_enum, default_value_t = ConfidenceLevel::Low)]
    min_confidence: ConfidenceLevel,

    /// Only scans for these Binwalk signature names (comma-separated or repeated).
    #[arg(long, value_delimiter = ',')]
    include: Option<Vec<String>>,

    /// Excludes these Binwalk signature names from scanning (comma-separated or repeated).
    #[arg(long, value_delimiter = ',')]
    exclude: Option<Vec<String>>,

    /// Scans for short signatures throughout the entire file rather than only at offset 0.
    #[arg(long)]
    full_search: bool,

    /// Runs as a background daemon instead of staying in the foreground.
    #[arg(short = 'd', long = "daemon")]
    daemon: bool,

    /// Allows other users on the system to access the mounted filesystem.
    #[arg(long)]
    allow_other: bool,
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();

    let source_binary_path = std::fs::canonicalize(&cli.binary_path).with_context(|| {
        format!(
            "Failed to resolve binary path '{}'",
            cli.binary_path.display()
        )
    })?;

    let target_binary_path = if let Some(out_path) = &cli.output {
        if let Some(parent) = out_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).with_context(|| {
                    format!("Failed to create output directory '{}'", parent.display())
                })?;
            }
        }
        info!(
            "Cloning '{}' -> '{}' for writable mounting",
            source_binary_path.display(),
            out_path.display()
        );
        std::fs::copy(&source_binary_path, out_path).with_context(|| {
            format!(
                "Failed to copy '{}' to '{}'",
                source_binary_path.display(),
                out_path.display()
            )
        })?;
        std::fs::canonicalize(out_path).map_err(|e| {
            anyhow!(
                "Failed to resolve output path '{}': {e}",
                out_path.display()
            )
        })?
    } else {
        source_binary_path
    };

    let is_writable = cli.writable || cli.output.is_some() || cli.cow;
    let write_policy = if !is_writable {
        WritePolicy::ReadOnly
    } else if cli.cow {
        WritePolicy::CopyOnWriteOverlay {
            pad_byte: cli.pad_byte,
        }
    } else {
        WritePolicy::InPlaceBounded {
            pad_byte: cli.pad_byte,
            write_through: true,
        }
    };

    // If the mountpoint has an active or stale FUSE mount from a previous run, unmount it cleanly first
    let _ = std::process::Command::new("fusermount3")
        .args(["-u", "-z"])
        .arg(&cli.mountpoint)
        .status()
        .or_else(|_| {
            std::process::Command::new("fusermount")
                .args(["-u", "-z"])
                .arg(&cli.mountpoint)
                .status()
        });

    let mountpoint = std::fs::canonicalize(&cli.mountpoint).with_context(|| {
        format!(
            "Failed to resolve mountpoint '{}'",
            cli.mountpoint.display()
        )
    })?;

    info!(
        "Loading binary '{}' (write_policy: {:?})",
        target_binary_path.display(),
        write_policy
    );
    let store = Arc::new(
        OverlayBinaryStore::from_file(&target_binary_path, write_policy)
            .with_context(|| format!("Failed to read '{}'", target_binary_path.display()))?,
    );

    let scan_config = ScanConfig {
        min_confidence: Some(cli.min_confidence),
        include: cli.include,
        exclude: cli.exclude,
        full_search: cli.full_search,
    };

    info!(
        "Scanning {} bytes for signatures with known start and end offsets...",
        store.base_bytes().len()
    );
    let entries = scan_bounded_signatures(store.base_bytes(), &scan_config)?;
    let extractable_count = entries.iter().filter(|e| e.has_extractor()).count();

    info!(
        "Discovered {} bounded signature(s) ({} with extractors)",
        entries.len(),
        extractable_count
    );

    if cli.daemon {
        info!("Daemonizing fuse-binwalk in background...");
        let daemonize = daemonize::Daemonize::new().working_directory("/");
        daemonize
            .start()
            .context("Failed to daemonize fuse-binwalk process")?;
    }

    let fs = BinwalkFs::new(store, entries)?.with_strict_size(cli.strict_size);

    let mut options = vec![
        if is_writable {
            MountOption::RW
        } else {
            MountOption::RO
        },
        MountOption::FSName("fuse-binwalk".to_string()),
        MountOption::Subtype("binwalk".to_string()),
    ];
    if cli.allow_other {
        options.push(MountOption::AllowOther);
    }

    info!(
        "Mounting '{}' at '{}' ({}, Ctrl+C to unmount)",
        target_binary_path.display(),
        mountpoint.display(),
        if is_writable {
            "read-write"
        } else {
            "read-only"
        }
    );

    let session = fuser::spawn_mount2(fs, &mountpoint, &options).with_context(|| {
        format!(
            "Failed to mount FUSE filesystem at '{}'",
            mountpoint.display()
        )
    })?;

    let (tx, rx) = channel();
    ctrlc::set_handler(move || {
        let _ = tx.send(());
    })
    .context("Failed to install Ctrl+C signal handler")?;

    let _ = rx.recv();
    info!("Unmounting '{}'...", mountpoint.display());
    drop(session);

    Ok(())
}
