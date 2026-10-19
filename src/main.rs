use anyhow::{Context, Result};
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

#[derive(Debug, Parser)]
#[command(
    name = "fuse-binwalk",
    version,
    about = "Mount any arbitrary binary as a FUSE filesystem using Binwalk v3"
)]
struct Cli {
    /// Path to the binary image to analyze and mount
    #[arg(value_name = "BINARY_PATH")]
    binary_path: PathBuf,

    /// Directory where the FUSE filesystem should be mounted
    #[arg(value_name = "MOUNTPOINT")]
    mountpoint: PathBuf,

    /// Minimum signature confidence threshold to include
    #[arg(long, value_enum, default_value_t = ConfidenceLevel::Low)]
    min_confidence: ConfidenceLevel,

    /// Only scan for these Binwalk signature names (comma-separated or repeated)
    #[arg(long, value_delimiter = ',')]
    include: Option<Vec<String>>,

    /// Exclude these Binwalk signature names from scanning (comma-separated or repeated)
    #[arg(long, value_delimiter = ',')]
    exclude: Option<Vec<String>>,

    /// Scan for short signatures throughout the entire file rather than only at offset 0
    #[arg(long)]
    full_search: bool,

    /// Run as a background daemon instead of staying in the foreground
    #[arg(short = 'd', long = "daemon")]
    daemon: bool,

    /// Allow other users on the system to access the mounted filesystem
    #[arg(long)]
    allow_other: bool,
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();

    let binary_path = std::fs::canonicalize(&cli.binary_path).with_context(|| {
        format!(
            "Failed to resolve binary path '{}'",
            cli.binary_path.display()
        )
    })?;
    let mountpoint = std::fs::canonicalize(&cli.mountpoint).with_context(|| {
        format!(
            "Failed to resolve mountpoint '{}'",
            cli.mountpoint.display()
        )
    })?;

    info!("Loading binary '{}'", binary_path.display());
    let store = Arc::new(
        OverlayBinaryStore::from_file(&binary_path, WritePolicy::ReadOnly)
            .with_context(|| format!("Failed to read '{}'", binary_path.display()))?,
    );

    let scan_config = ScanConfig {
        min_confidence: Some(cli.min_confidence),
        include: cli.include,
        exclude: cli.exclude,
        full_search: cli.full_search,
    };

    info!(
        "Scanning {} bytes for signatures with known start and end offsets...",
        store. base_bytes().len()
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

    let fs = BinwalkFs::new(store, entries)?;

    let mut options = vec![
        MountOption::RO,
        MountOption::FSName("fuse-binwalk".to_string()),
        MountOption::Subtype("binwalk".to_string()),
    ];
    if cli.allow_other {
        options.push(MountOption::AllowOther);
    }

    info!(
        "Mounting '{}' at '{}' (Ctrl+C to unmount)",
        binary_path.display(),
        mountpoint.display()
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
