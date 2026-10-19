use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use thiserror::Error;

/// Represents a known half-open byte interval `[start, end)` within the binary image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub struct ByteSpan {
    pub start: usize,
    pub end: usize,
}

impl ByteSpan {
    pub fn new(start: usize, end: usize) -> Option<Self> {
        if start < end {
            Some(Self { start, end })
        } else {
            None
        }
    }

    pub fn from_offset_size(offset: usize, size: usize) -> Option<Self> {
        let end = offset.checked_add(size)?;
        Self::new(offset, end)
    }

    pub fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn overlaps(&self, other: &ByteSpan) -> bool {
        self.start < other.end && other.start < self.end
    }

    pub fn contains_range(&self, start: usize, end: usize) -> bool {
        start >= self.start && end <= self.end && start <= end
    }
}

/// Defines how write operations are handled by the underlying storage engine.
///
/// The initial milestone uses `WritePolicy::ReadOnly`, while the storage architecture
/// natively supports bounded in-place writes, region replacement (for repacking `/extracted/`),
/// and copy-on-write overlays with explicit commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WritePolicy {
    /// Rejects all modifications with `EROFS`.
    ReadOnly,
    /// Allows writes to a `ByteSpan` as long as they stay within `[span.start, span.end)`.
    /// When replacing an entire span (e.g., repacking an extracted archive), if the new payload
    /// is smaller than `span.len()`, the remainder is filled with `pad_byte` (if specified).
    InPlaceBounded {
        pad_byte: Option<u8>,
        write_through: bool,
    },
    /// Buffers all bounded modifications in a Copy-on-Write memory overlay without modifying
    /// the backing file until `commit()` is explicitly invoked.
    CopyOnWriteOverlay {
        pad_byte: Option<u8>,
    },
}

impl Default for WritePolicy {
    fn default() -> Self {
        Self::ReadOnly
    }
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("filesystem is mounted read-only")]
    ReadOnly,
    #[error("write at offset {offset} of length {len} exceeds span bounds [0..{span_len})")]
    OutOfSpanBounds {
        offset: usize,
        len: usize,
        span_len: usize,
    },
    #[error("replacement payload ({new_len} bytes) cannot fit in span ({span_len} bytes)")]
    ReplacementTooLarge {
        new_len: usize,
        span_len: usize,
    },
    #[error("replacement payload ({new_len} bytes) is smaller than span ({span_len} bytes) and no padding byte is configured")]
    ReplacementUnderflow {
        new_len: usize,
        span_len: usize,
    },
    #[error("span [{start:#x}..{end:#x}) exceeds backing binary size ({total_len:#x})")]
    SpanOutOfRange {
        start: usize,
        end: usize,
        total_len: usize,
    },
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl StorageError {
    pub fn to_errno(&self) -> libc::c_int {
        match self {
            StorageError::ReadOnly => libc::EROFS,
            StorageError::OutOfSpanBounds { .. }
            | StorageError::ReplacementTooLarge { .. }
            | StorageError::SpanOutOfRange { .. } => libc::ENOSPC,
            StorageError::ReplacementUnderflow { .. } => libc::EINVAL,
            StorageError::Io(e) => e.raw_os_error().unwrap_or(libc::EIO),
        }
    }
}

/// Abstract storage trait for reading and (in future modes) mutating binary spans.
pub trait BinaryStore: Send + Sync {
    /// Total byte length of the binary image.
    fn total_len(&self) -> usize;

    /// Path to the original binary on disk, if backed by a file.
    fn backing_path(&self) -> Option<&Path>;

    /// Current write policy.
    fn write_policy(&self) -> WritePolicy;

    /// Read bytes from absolute offset in the binary into `buf`. Returns number of bytes read.
    fn read_at(&self, offset: usize, buf: &mut [u8]) -> Result<usize, StorageError>;

    /// Read bytes from a specific `ByteSpan` at `offset_in_span` into `buf`.
    fn read_in_span(
        &self,
        span: ByteSpan,
        offset_in_span: usize,
        buf: &mut [u8],
    ) -> Result<usize, StorageError> {
        if span.end > self.total_len() {
            return Err(StorageError::SpanOutOfRange {
                start: span.start,
                end: span.end,
                total_len: self.total_len(),
            });
        }
        if offset_in_span >= span.len() || buf.is_empty() {
            return Ok(0);
        }
        let max_read = (span.len() - offset_in_span).min(buf.len());
        self.read_at(span.start + offset_in_span, &mut buf[..max_read])
    }

    /// Convenience helper to read an entire `ByteSpan` into a `Vec<u8>`.
    fn read_slice(&self, span: ByteSpan) -> Result<Vec<u8>, StorageError> {
        if span.end > self.total_len() {
            return Err(StorageError::SpanOutOfRange {
                start: span.start,
                end: span.end,
                total_len: self.total_len(),
            });
        }
        let mut buf = vec![0u8; span.len()];
        let n = self.read_in_span(span, 0, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Write `data` into `span` at relative offset `offset_in_span`.
    /// Enforces `WritePolicy` and ensures writes never cross `span.end`.
    fn write_in_span(
        &self,
        span: ByteSpan,
        offset_in_span: usize,
        data: &[u8],
    ) -> Result<usize, StorageError>;

    /// Atomically replace the contents of `span` with `new_blob` (e.g., after repacking `/extracted/`).
    /// Checks size constraints and applies padding if configured in `WritePolicy`.
    fn replace_span(&self, span: ByteSpan, new_blob: &[u8]) -> Result<(), StorageError>;

    /// Returns true if the CoW overlay holds uncommitted modifications.
    fn is_dirty(&self) -> bool;

    /// Flushes any buffered Copy-on-Write modifications back to the underlying file on disk.
    fn commit(&self) -> Result<(), StorageError>;
}

/// Concrete storage implementation supporting zero-overhead immutable reads as well as
/// Copy-on-Write (CoW) byte-range overlays and bounded write-through.
pub struct OverlayBinaryStore {
    backing_path: Option<PathBuf>,
    base_data: Arc<Vec<u8>>,
    policy: WritePolicy,
    /// CoW overlay mapping absolute byte offset -> modified byte value (or contiguous chunks).
    /// Using chunked segments keyed by start offset for efficient range reads/writes.
    overlay: RwLock<BTreeMap<usize, Vec<u8>>>,
}

impl OverlayBinaryStore {
    pub fn from_file(path: impl AsRef<Path>, policy: WritePolicy) -> Result<Self, StorageError> {
        let path_buf = path.as_ref().to_path_buf();
        let data = std::fs::read(&path_buf)?;
        Ok(Self {
            backing_path: Some(path_buf),
            base_data: Arc::new(data),
            policy,
            overlay: RwLock::new(BTreeMap::new()),
        })
    }

    pub fn from_bytes(
        data: Vec<u8>,
        backing_path: Option<PathBuf>,
        policy: WritePolicy,
    ) -> Self {
        Self {
            backing_path,
            base_data: Arc::new(data),
            policy,
            overlay: RwLock::new(BTreeMap::new()),
        }
    }

    /// Access the raw underlying immutable base buffer (fast path when `!is_dirty()`).
    pub fn base_bytes(&self) -> &[u8] {
        &self.base_data
    }

    fn apply_overlay_write(&self, abs_offset: usize, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let mut map = self.overlay.write().expect("overlay lock poisoned");
        // To keep the overlay simple and exact even with arbitrary overlapping writes,
        // coalesce or split existing chunks that overlap [abs_offset, abs_offset + data.len()).
        let write_start = abs_offset;
        let write_end = abs_offset + data.len();

        let overlapping_keys: Vec<usize> = map
            .range(..write_end)
            .filter_map(|(&seg_start, seg_data)| {
                let seg_end = seg_start + seg_data.len();
                if seg_end >= write_start {
                    Some(seg_start)
                } else {
                    None
                }
            })
            .collect();

        if overlapping_keys.is_empty() {
            map.insert(write_start, data.to_vec());
            return;
        }

        let first_key = overlapping_keys[0];
        let last_key = *overlapping_keys.last().unwrap();
        let last_end = last_key + map[&last_key].len();

        let merged_start = first_key.min(write_start);
        let merged_end = last_end.max(write_end);
        let mut merged = self.base_data[merged_start..merged_end].to_vec();

        for key in overlapping_keys {
            if let Some(seg) = map.remove(&key) {
                let rel = key - merged_start;
                merged[rel..rel + seg.len()].copy_from_slice(&seg);
            }
        }

        let write_rel = write_start - merged_start;
        merged[write_rel..write_rel + data.len()].copy_from_slice(data);
        map.insert(merged_start, merged);
    }

    fn write_through_disk(&self, abs_offset: usize, data: &[u8]) -> Result<(), StorageError> {
        let Some(path) = &self.backing_path else {
            return Ok(());
        };
        let mut file = OpenOptions::new().write(true).open(path)?;
        file.seek(SeekFrom::Start(abs_offset as u64))?;
        file.write_all(data)?;
        file.flush()?;
        Ok(())
    }
}

impl BinaryStore for OverlayBinaryStore {
    fn total_len(&self) -> usize {
        self.base_data.len()
    }

    fn backing_path(&self) -> Option<&Path> {
        self.backing_path.as_deref()
    }

    fn write_policy(&self) -> WritePolicy {
        self.policy
    }

    fn read_at(&self, offset: usize, buf: &mut [u8]) -> Result<usize, StorageError> {
        let total = self.base_data.len();
        if offset >= total || buf.is_empty() {
            return Ok(0);
        }
        let read_len = (total - offset).min(buf.len());
        let read_end = offset + read_len;

        buf[..read_len].copy_from_slice(&self.base_data[offset..read_end]);

        let map = self.overlay.read().expect("overlay lock poisoned");
        if !map.is_empty() {
            for (&seg_start, seg_data) in map.range(..read_end) {
                let seg_end = seg_start + seg_data.len();
                if seg_end <= offset {
                    continue;
                }
                let overlap_start = seg_start.max(offset);
                let overlap_end = seg_end.min(read_end);
                let dst_start = overlap_start - offset;
                let dst_end = overlap_end - offset;
                let src_start = overlap_start - seg_start;
                let src_end = overlap_end - seg_start;
                buf[dst_start..dst_end].copy_from_slice(&seg_data[src_start..src_end]);
            }
        }

        Ok(read_len)
    }

    fn write_in_span(
        &self,
        span: ByteSpan,
        offset_in_span: usize,
        data: &[u8],
    ) -> Result<usize, StorageError> {
        if span.end > self.total_len() {
            return Err(StorageError::SpanOutOfRange {
                start: span.start,
                end: span.end,
                total_len: self.total_len(),
            });
        }

        let write_through = match self.policy {
            WritePolicy::ReadOnly => return Err(StorageError::ReadOnly),
            WritePolicy::InPlaceBounded { write_through, .. } => write_through,
            WritePolicy::CopyOnWriteOverlay { .. } => false,
        };

        let end_in_span = offset_in_span
            .checked_add(data.len())
            .ok_or(StorageError::OutOfSpanBounds {
                offset: offset_in_span,
                len: data.len(),
                span_len: span.len(),
            })?;

        if end_in_span > span.len() {
            return Err(StorageError::OutOfSpanBounds {
                offset: offset_in_span,
                len: data.len(),
                span_len: span.len(),
            });
        }

        let abs_offset = span.start + offset_in_span;
        self.apply_overlay_write(abs_offset, data);

        if write_through {
            self.write_through_disk(abs_offset, data)?;
        }

        Ok(data.len())
    }

    fn replace_span(&self, span: ByteSpan, new_blob: &[u8]) -> Result<(), StorageError> {
        if span.end > self.total_len() {
            return Err(StorageError::SpanOutOfRange {
                start: span.start,
                end: span.end,
                total_len: self.total_len(),
            });
        }

        let (pad_byte, write_through) = match self.policy {
            WritePolicy::ReadOnly => return Err(StorageError::ReadOnly),
            WritePolicy::InPlaceBounded {
                pad_byte,
                write_through,
            } => (pad_byte, write_through),
            WritePolicy::CopyOnWriteOverlay { pad_byte } => (pad_byte, false),
        };

        let span_len = span.len();
        if new_blob.len() > span_len {
            return Err(StorageError::ReplacementTooLarge {
                new_len: new_blob.len(),
                span_len,
            });
        }

        let payload: Vec<u8> = if new_blob.len() < span_len {
            let Some(pad) = pad_byte else {
                return Err(StorageError::ReplacementUnderflow {
                    new_len: new_blob.len(),
                    span_len,
                });
            };
            let mut buf = Vec::with_capacity(span_len);
            buf.extend_from_slice(new_blob);
            buf.resize(span_len, pad);
            buf
        } else {
            new_blob.to_vec()
        };

        self.apply_overlay_write(span.start, &payload);
        if write_through {
            self.write_through_disk(span.start, &payload)?;
        }
        Ok(())
    }

    fn is_dirty(&self) -> bool {
        !self.overlay.read().expect("overlay lock poisoned").is_empty()
    }

    fn commit(&self) -> Result<(), StorageError> {
        if matches!(self.policy, WritePolicy::ReadOnly) {
            return Err(StorageError::ReadOnly);
        }
        let Some(path) = &self.backing_path else {
            return Ok(());
        };
        let map = self.overlay.read().expect("overlay lock poisoned");
        if map.is_empty() {
            return Ok(());
        }
        let mut file = OpenOptions::new().write(true).open(path)?;
        for (&offset, seg) in map.iter() {
            file.seek(SeekFrom::Start(offset as u64))?;
            file.write_all(seg)?;
        }
        file.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_only_rejects_writes() {
        let store = OverlayBinaryStore::from_bytes(vec![0, 1, 2, 3, 4, 5], None, WritePolicy::ReadOnly);
        let span = ByteSpan::new(1, 4).unwrap();
        assert_eq!(store.read_slice(span).unwrap(), vec![1, 2, 3]);
        assert!(matches!(
            store.write_in_span(span, 0, &[9, 9]),
            Err(StorageError::ReadOnly)
        ));
    }

    #[test]
    fn test_cow_overlay_writes_and_bounds() {
        let store = OverlayBinaryStore::from_bytes(
            vec![10, 20, 30, 40, 50, 60],
            None,
            WritePolicy::CopyOnWriteOverlay { pad_byte: Some(0xFF) },
        );
        let span = ByteSpan::new(1, 5).unwrap();
        assert_eq!(store.write_in_span(span, 1, &[99, 88]).unwrap(), 2);
        assert!(store.is_dirty());
        assert_eq!(store.read_slice(span).unwrap(), vec![20, 99, 88, 50]);

        // Writing beyond span.end fails
        assert!(matches!(
            store.write_in_span(span, 3, &[1, 2]),
            Err(StorageError::OutOfSpanBounds { .. })
        ));

        // Replacing span with shorter data pads with 0xFF
        store.replace_span(span, &[7, 8]).unwrap();
        assert_eq!(store.read_slice(span).unwrap(), vec![7, 8, 0xFF, 0xFF]);
    }
}
