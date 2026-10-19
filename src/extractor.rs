use crate::scanner::CarvedEntry;
use crate::storage::{BinaryStore, StorageError};
use anyhow::{anyhow, Result};
use binwalk::extractors::common::{self as bw_extractors, ExtractorType};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use tempfile::TempDir;

/// Trait for repacking a modified `/extracted/<entry>/` directory back into a raw binary blob
/// so it can be written back to its parent `ByteSpan` in the `BinaryStore`.
pub trait RegionRepacker: Send + Sync {
    /// Signature name handled by this repacker (e.g., `"gzip"`, `"tar"`, `"squashfs"`).
    fn signature_name(&self) -> &str;

    /// Repack the contents of `extracted_dir` into a new serialized byte buffer.
    fn repack(&self, extracted_dir: &Path, entry: &CarvedEntry) -> Result<Vec<u8>>;
}

/// Registry of `RegionRepacker` implementations for future write-back from `/extracted/`.
#[derive(Default)]
pub struct RepackerRegistry {
    repackers: RwLock<HashMap<String, Arc<dyn RegionRepacker>>>,
}

impl RepackerRegistry {
    pub fn new() -> Self {
        Self {
            repackers: RwLock::new(HashMap::new()),
        }
    }

    pub fn register(&self, repacker: Arc<dyn RegionRepacker>) {
        self.repackers
            .write()
            .expect("repackers lock poisoned")
            .insert(repacker.signature_name().to_string(), repacker);
    }

    pub fn get(&self, signature_name: &str) -> Option<Arc<dyn RegionRepacker>> {
        self.repackers
            .read()
            .expect("repackers lock poisoned")
            .get(signature_name)
            .cloned()
    }
}

#[derive(Debug, Clone)]
pub struct ExtractionRecord {
    /// Directory on the host filesystem holding the extracted files (or `_extraction_status.txt`).
    pub output_dir: PathBuf,
    /// Whether the Binwalk extractor succeeded.
    pub success: bool,
    /// Name of the extractor utility that ran.
    pub extractor_name: String,
    /// Tracks whether any files inside `output_dir` have been modified since extraction.
    pub dirty: bool,
}

/// Manages lazy on-demand extraction into a temporary workspace and supports future repacking.
pub struct ExtractionManager {
    temp_dir: TempDir,
    records: Mutex<HashMap<usize, ExtractionRecord>>,
    repackers: RepackerRegistry,
}

impl ExtractionManager {
    pub fn new() -> Result<Self> {
        let temp_dir = tempfile::Builder::new()
            .prefix("fuse-binwalk-")
            .tempdir()?;
        Ok(Self {
            temp_dir,
            records: Mutex::new(HashMap::new()),
            repackers: RepackerRegistry::new(),
        })
    }

    pub fn repackers(&self) -> &RepackerRegistry {
        &self.repackers
    }

    /// Checks if an entry has already been extracted without triggering extraction.
    pub fn get_cached(&self, entry_index: usize) -> Option<ExtractionRecord> {
        self.records
            .lock()
            .expect("extraction records lock poisoned")
            .get(&entry_index)
            .cloned()
    }

    /// Marks an extracted tree as dirty (used when files under `/extracted/<entry>/` are modified).
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

    /// Lazily extracts `entry` strictly from `[entry.span.start .. entry.span.end]` on first access.
    /// If extraction fails, populates the directory with `_extraction_status.txt` explaining why.
    pub fn ensure_extracted(
        &self,
        entry: &CarvedEntry,
        store: &dyn BinaryStore,
    ) -> Result<ExtractionRecord> {
        {
            let guard = self.records.lock().expect("extraction records lock poisoned");
            if let Some(existing) = guard.get(&entry.index) {
                return Ok(existing.clone());
            }
        }

        // Perform extraction strictly bounded to entry.span
        let record = self.run_bounded_extraction(entry, store)?;

        let mut guard = self.records.lock().expect("extraction records lock poisoned");
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
        let work_dir = self.temp_dir.path().join(format!("entry_{:04}", entry.index));
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

        // Clean up the temporary input slice file to save space
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
            // Ensure directory exists and write `_extraction_status.txt` detailing the failure
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

    /// Repacks a modified `/extracted/<entry>/` directory and writes the new bytes back into
    /// `entry.span` in `store` (respecting `store.write_policy()`).
    pub fn repack_entry_into_store(
        &self,
        entry: &CarvedEntry,
        store: &dyn BinaryStore,
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

        let new_blob = repacker.repack(&record.output_dir, entry)?;
        store.replace_span(entry.span, &new_blob)?;

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
