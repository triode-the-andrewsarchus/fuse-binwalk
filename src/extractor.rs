//! On-demand bounded extraction and container repacking for `/extracted/` entries.
//!
//! This module provides [`ExtractionManager`] for lazily extracting [`CarvedEntry`] slices
//! into isolated temporary directories upon first access, and [`RegionRepacker`] /
//! [`RepackerRegistry`] for re-serializing modified extraction trees back into their
//! parent [`ByteSpan`] in a [`BinaryStore`].

use crate::scanner::CarvedEntry;
use crate::storage::{smart_pad_byte, BinaryStore, ByteSpan, StorageError};
use anyhow::{anyhow, Result};
use binwalk::extractors::common::{self as bw_extractors, ExtractorType};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use tempfile::TempDir;

/// Serializes a modified `/extracted/<entry>/` directory back into a raw binary payload
/// so it can replace its parent [`ByteSpan`] in a [`BinaryStore`].
pub trait RegionRepacker: Send + Sync {
    /// Returns the Binwalk signature name handled by this repacker (such as `"zip"`, `"gzip"`, or `"tar"`).
    fn signature_name(&self) -> &str;

    /// Returns `true` if this repacker is currently available on the host system.
    ///
    /// Built-in pure-Rust repackers always return `true`, whereas external command repackers
    /// check whether their required executable exists in `PATH`.
    fn is_available(&self) -> bool {
        true
    }

    /// Repacks the contents of `extracted_dir` into a serialized byte vector.
    ///
    /// # Errors
    ///
    /// Returns an error if reading `extracted_dir` or encoding the container format fails.
    fn repack(&self, extracted_dir: &Path, entry: &CarvedEntry) -> Result<Vec<u8>>;

    /// Repacks the contents of `extracted_dir` with access to the underlying [`BinaryStore`].
    ///
    /// Delta-aware repackers (such as [`crate::repackers::ZipRepacker`]) override this method
    /// to inspect the original carved slice in `store` and preserve unmodified entries verbatim.
    ///
    /// # Errors
    ///
    /// Returns an error if reading `extracted_dir`, reading from `store`, or encoding fails.
    fn repack_with_store(
        &self,
        extracted_dir: &Path,
        entry: &CarvedEntry,
        _store: &dyn BinaryStore,
    ) -> Result<Vec<u8>> {
        self.repack(extracted_dir, entry)
    }
}

/// Thread-safe registry mapping Binwalk signature names to [`RegionRepacker`] implementations.
///
/// # Examples
///
/// ```
/// use fuse_binwalk::RepackerRegistry;
/// use fuse_binwalk::repackers::register_builtin_repackers;
///
/// let registry = RepackerRegistry::new();
/// register_builtin_repackers(&registry);
/// assert!(registry.can_repack("zip"));
/// assert!(registry.can_repack("gzip"));
/// ```
#[derive(Default)]
pub struct RepackerRegistry {
    repackers: RwLock<HashMap<String, Arc<dyn RegionRepacker>>>,
}

impl RepackerRegistry {
    /// Creates an empty [`RepackerRegistry`].
    pub fn new() -> Self {
        Self {
            repackers: RwLock::new(HashMap::new()),
        }
    }

    /// Registers a [`RegionRepacker`] under its [`RegionRepacker::signature_name`].
    pub fn register(&self, repacker: Arc<dyn RegionRepacker>) {
        self.repackers
            .write()
            .expect("repackers lock poisoned")
            .insert(repacker.signature_name().to_string(), repacker);
    }

    /// Looks up an available [`RegionRepacker`] for `signature_name`.
    ///
    /// Returns [`None`] if no repacker is registered for `signature_name` or if
    /// [`RegionRepacker::is_available`] returns `false`.
    pub fn get(&self, signature_name: &str) -> Option<Arc<dyn RegionRepacker>> {
        self.repackers
            .read()
            .expect("repackers lock poisoned")
            .get(signature_name)
            .cloned()
            .filter(|r| r.is_available())
    }

    /// Returns `true` if an available [`RegionRepacker`] is registered for `signature_name`.
    pub fn can_repack(&self, signature_name: &str) -> bool {
        self.get(signature_name).is_some()
    }
}

/// Metadata describing the state of a lazily extracted [`CarvedEntry`].
#[derive(Debug, Clone)]
pub struct ExtractionRecord {
    /// Host filesystem directory containing the extracted files (or `_extraction_status.txt`).
    pub output_dir: PathBuf,
    /// Whether the Binwalk extractor succeeded and produced output.
    pub success: bool,
    /// Name or description of the extractor utility that ran.
    pub extractor_name: String,
    /// Whether any files inside `output_dir` have been modified since extraction.
    pub dirty: bool,
}

/// Manages lazy on-demand extraction into a temporary workspace and coordinates container repacking.
pub struct ExtractionManager {
    temp_dir: TempDir,
    records: Mutex<HashMap<usize, ExtractionRecord>>,
    repackers: RepackerRegistry,
}

impl ExtractionManager {
    /// Creates a new [`ExtractionManager`] backed by a temporary directory and pre-populated
    /// with all built-in [`RegionRepacker`] implementations.
    ///
    /// # Errors
    ///
    /// Returns an error if the temporary workspace directory cannot be created.
    pub fn new() -> Result<Self> {
        let temp_dir = tempfile::Builder::new().prefix("fuse-binwalk-").tempdir()?;
        let repackers = RepackerRegistry::new();
        crate::repackers::register_builtin_repackers(&repackers);
        Ok(Self {
            temp_dir,
            records: Mutex::new(HashMap::new()),
            repackers,
        })
    }

    /// Returns a reference to the underlying [`RepackerRegistry`].
    pub fn repackers(&self) -> &RepackerRegistry {
        &self.repackers
    }

    /// Returns the cached [`ExtractionRecord`] for `entry_index` without triggering extraction.
    pub fn get_cached(&self, entry_index: usize) -> Option<ExtractionRecord> {
        self.records
            .lock()
            .expect("extraction records lock poisoned")
            .get(&entry_index)
            .cloned()
    }

    /// Marks the cached extraction tree for `entry_index` as modified.
    pub fn mark_dirty(&self, entry_index: usize) {
        if let Some(rec) = self
            .records
            .lock()
            .expect("extraction records lock poisoned")
            .get_mut(&entry_index)
        {
            rec.dirty = true;
        }
    }

    /// Invalidates cached extractions whose spans overlap `modified_span` (excluding `except_entry_idx`).
    ///
    /// Returns the `entry_index` values that were evicted so the caller can clear corresponding
    /// virtual inode mappings.
    pub fn invalidate_overlapping(
        &self,
        modified_span: ByteSpan,
        entries: &[CarvedEntry],
        except_entry_idx: Option<usize>,
    ) -> Vec<usize> {
        let mut guard = self
            .records
            .lock()
            .expect("extraction records lock poisoned");
        let mut invalidated = Vec::new();
        for entry in entries {
            if Some(entry.index) == except_entry_idx {
                continue;
            }
            if entry.span.overlaps(&modified_span) {
                if let Some(rec) = guard.remove(&entry.index) {
                    let _ = fs::remove_dir_all(&rec.output_dir);
                    invalidated.push(entry.index);
                }
            }
        }
        invalidated
    }

    /// Lazily extracts `entry` strictly from `[entry.span.start .. entry.span.end)` on first access.
    ///
    /// If extraction fails or produces no files, populates the output directory with an
    /// `_extraction_status.txt` diagnostic file explaining the failure.
    ///
    /// # Errors
    ///
    /// Returns an error if reading `entry.span` from `store` or creating the working directory fails.
    pub fn ensure_extracted(
        &self,
        entry: &CarvedEntry,
        store: &dyn BinaryStore,
    ) -> Result<ExtractionRecord> {
        {
            let guard = self
                .records
                .lock()
                .expect("extraction records lock poisoned");
            if let Some(existing) = guard.get(&entry.index) {
                return Ok(existing.clone());
            }
        }

        let record = self.run_bounded_extraction(entry, store)?;

        let mut guard = self
            .records
            .lock()
            .expect("extraction records lock poisoned");
        let final_rec = guard
            .entry(entry.index)
            .or_insert_with(|| record.clone())
            .clone();
        Ok(final_rec)
    }

    fn run_bounded_extraction(
        &self,
        entry: &CarvedEntry,
        store: &dyn BinaryStore,
    ) -> Result<ExtractionRecord> {
        let work_dir = self
            .temp_dir
            .path()
            .join(format!("entry_{:04}", entry.index));
        fs::create_dir_all(&work_dir)?;

        let slice_bytes = store
            .read_slice(entry.span)
            .map_err(|e| anyhow!("Failed to read slice for extraction: {e}"))?;

        let slice_file_path = work_dir.join(&entry.raw_filename);
        fs::write(&slice_file_path, &slice_bytes)?;
        let slice_file_str = slice_file_path.to_string_lossy().to_string();

        // Create a bounded SignatureResult relative to the carved slice [0..slice_bytes.len()]
        // so Binwalk's extractor cannot read a single byte past entry.span.end.
        let mut bounded_sig = entry.signature_result.clone();
        bounded_sig.offset = 0;
        bounded_sig.size = slice_bytes.len();

        let utility_desc = match entry.extractor.as_ref().map(|e| &e.utility) {
            Some(ExtractorType::Internal(_)) => {
                format!("{}_built_in (internal)", entry.signature_result.name)
            }
            Some(ExtractorType::External(cmd)) => format!("{cmd} (external command)"),
            _ => "none".to_string(),
        };

        let result = bw_extractors::execute(
            &slice_bytes,
            &slice_file_str,
            &bounded_sig,
            &entry.extractor,
        );

        let _ = fs::remove_file(&slice_file_path);

        let output_dir = if result.output_directory.is_empty() {
            work_dir.join("output")
        } else {
            PathBuf::from(&result.output_directory)
        };

        if result.success && output_dir.exists() {
            Ok(ExtractionRecord {
                output_dir,
                success: true,
                extractor_name: result.extractor,
                dirty: false,
            })
        } else {
            fs::create_dir_all(&output_dir)?;
            let status_path = output_dir.join("_extraction_status.txt");
            let status_text = format!(
                "Extraction status: FAILED\n\
                 Signature Name:    {}\n\
                 Description:       {}\n\
                 Byte Range:        0x{:08X} .. 0x{:08X} ({} bytes)\n\
                 Extractor Utility: {}\n\
                 Reason:            Extractor command failed, was not installed on host, or produced no non-empty files from the bounded slice.\n",
                entry.signature_result.name,
                entry.signature_result.description,
                entry.span.start,
                entry.span.end,
                entry.span.len(),
                utility_desc,
            );
            fs::write(&status_path, status_text)?;

            Ok(ExtractionRecord {
                output_dir,
                success: false,
                extractor_name: utility_desc,
                dirty: false,
            })
        }
    }

    /// Repacks a modified `/extracted/<entry>/` directory and writes the new bytes into
    /// `entry.span` in `store` with smart signature padding enabled.
    ///
    /// # Errors
    ///
    /// Returns an error if `store` is read-only, if no [`RegionRepacker`] is available for
    /// `entry`, or if the repacked payload exceeds `entry.span.len()`.
    pub fn repack_entry_into_store(
        &self,
        entry: &CarvedEntry,
        store: &dyn BinaryStore,
    ) -> Result<()> {
        self.repack_entry_with_padding(entry, store, true)
    }

    /// Repacks a modified `/extracted/<entry>/` directory and writes the new bytes into
    /// `entry.span` in `store`, using [`smart_pad_byte`] as a fallback when `use_smart_pad` is `true`.
    ///
    /// # Errors
    ///
    /// Returns an error if `store` is read-only, if no [`RegionRepacker`] is available for
    /// `entry`, or if replacing `entry.span` fails.
    pub fn repack_entry_with_padding(
        &self,
        entry: &CarvedEntry,
        store: &dyn BinaryStore,
        use_smart_pad: bool,
    ) -> Result<()> {
        if matches!(store.write_policy(), crate::storage::WritePolicy::ReadOnly) {
            return Err(StorageError::ReadOnly.into());
        }

        let record = self
            .get_cached(entry.index)
            .ok_or_else(|| anyhow!("Entry {} has not been extracted", entry.index))?;

        if !record.dirty {
            return Ok(());
        }

        let repacker = self
            .repackers
            .get(&entry.signature_result.name)
            .ok_or_else(|| {
                anyhow!(
                    "No RegionRepacker registered for signature '{}'",
                    entry.signature_result.name
                )
            })?;

        let new_blob = repacker.repack_with_store(&record.output_dir, entry, store)?;
        let fallback_pad = if use_smart_pad {
            Some(smart_pad_byte(&entry.signature_result.name))
        } else {
            None
        };
        store.replace_span_with_fallback_pad(entry.span, &new_blob, fallback_pad)?;

        if let Some(rec) = self
            .records
            .lock()
            .expect("extraction records lock poisoned")
            .get_mut(&entry.index)
        {
            rec.dirty = false;
        }

        Ok(())
    }
}
