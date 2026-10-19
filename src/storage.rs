//! Bounded byte intervals, write policies, and Copy-on-Write storage for binary images.
//!
//! This module provides [`ByteSpan`] for representing non-empty half-open intervals `[start, end)`
//! and [`BinaryStore`] (implemented by [`OverlayBinaryStore`]) for reading and mutating carved
//! spans under a configured [`WritePolicy`].

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use thiserror::Error;

/// Represents a non-empty half-open byte interval `[start, end)` within a binary image.
///
/// # Examples
///
/// ```
/// use fuse_binwalk::ByteSpan;
///
/// let span = ByteSpan::from_offset_size(0x100, 0x40).unwrap();
/// assert_eq!(span.start, 0x100);
/// assert_eq!(span.end, 0x140);
/// assert_eq!(span.len(), 0x40);
/// assert!(span.contains_range(0x110, 0x130));
/// ```
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct ByteSpan {
    /// Inclusive starting byte offset of the span.
    pub start: usize,
    /// Exclusive ending byte offset of the span (`end > start`).
    pub end: usize,
}

impl ByteSpan {
    /// Creates a new [`ByteSpan`] covering `[start, end)` if `start < end`.
    ///
    /// Returns [`None`] if `start >= end`.
    ///
    /// # Examples
    ///
    /// ```
    /// use fuse_binwalk::ByteSpan;
    ///
    /// assert!(ByteSpan::new(10, 20).is_some());
    /// assert!(ByteSpan::new(20, 20).is_none());
    /// assert!(ByteSpan::new(30, 20).is_none());
    /// ```
    pub fn new(start: usize, end: usize) -> Option<Self> {
        if start < end {
            Some(Self { start, end })
        } else {
            None
        }
    }

    /// Creates a new [`ByteSpan`] from a starting `offset` and byte `size`.
    ///
    /// Returns [`None`] if `size == 0` or if `offset + size` overflows [`usize`].
    pub fn from_offset_size(offset: usize, size: usize) -> Option<Self> {
        let end = offset.checked_add(size)?;
        Self::new(offset, end)
    }

    /// Returns the length of the byte span in bytes (`end - start`).
    pub fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// Returns `true` if the byte span has zero length.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns `true` if `self` and `other` share at least one byte.
    pub fn overlaps(&self, other: &ByteSpan) -> bool {
        self.start < other.end && other.start < self.end
    }

    /// Returns `true` if the sub-interval `[start, end)` lies completely within `self`.
    pub fn contains_range(&self, start: usize, end: usize) -> bool {
        start >= self.start && end <= self.end && start <= end
    }
}

/// Returns the default smart padding byte for a given Binwalk signature name.
///
/// Text-oriented formats (such as `"svg"`, `"xml"`, `"html"`, `"json"`, and PEM keys) use
/// ASCII space (`b' '`, `0x20`) so trailing padding remains valid markup, whereas binary
/// formats use `0x00`.
///
/// # Examples
///
/// ```
/// use fuse_binwalk::smart_pad_byte;
///
/// assert_eq!(smart_pad_byte("svg"), b' ');
/// assert_eq!(smart_pad_byte("png"), 0x00);
/// ```
pub fn smart_pad_byte(signature_name: &str) -> u8 {
    match signature_name {
        "svg"
        | "xml"
        | "html"
        | "json"
        | "pem_public_key"
        | "pem_private_key"
        | "pem_certificate"
        | "openssh_private_key"
        | "pgp"
        | "copyright"
        | "sh"
        | "lua"
        | "python" => b' ',
        _ => 0x00,
    }
}

/// Configures how write operations are handled by a [`BinaryStore`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WritePolicy {
    /// Rejects all modifications with [`StorageError::ReadOnly`] (`EROFS`).
    #[default]
    ReadOnly,
    /// Allows writes to a [`ByteSpan`] as long as they stay within `[span.start, span.end)`.
    ///
    /// When replacing an entire span via [`BinaryStore::replace_span`], payloads smaller than
    /// `span.len()` are padded with `pad_byte` (if [`Some`]) or a caller-provided fallback pad byte.
    InPlaceBounded {
        /// Optional explicit byte value used to pad shorter span replacements.
        pad_byte: Option<u8>,
        /// Whether writes are immediately flushed to the backing file on disk.
        write_through: bool,
    },
    /// Buffers all bounded modifications in a Copy-on-Write memory overlay without modifying
    /// the backing file until [`BinaryStore::commit`] is invoked.
    CopyOnWriteOverlay {
        /// Optional explicit byte value used to pad shorter span replacements.
        pad_byte: Option<u8>,
    },
}

/// Errors returned by [`BinaryStore`] read, write, span replacement, and commit operations.
#[derive(Debug, Error)]
pub enum StorageError {
    /// The storage engine is configured with [`WritePolicy::ReadOnly`].
    #[error("filesystem is mounted read-only")]
    ReadOnly,
    /// A partial write exceeded the end boundary of the target [`ByteSpan`].
    #[error("write at offset {offset} of length {len} exceeds span bounds [0..{span_len})")]
    OutOfSpanBounds {
        /// Relative offset within the span where the write started.
        offset: usize,
        /// Number of bytes attempted to write.
        len: usize,
        /// Total length of the target span.
        span_len: usize,
    },
    /// A full-span replacement payload is larger than the target [`ByteSpan`].
    #[error("replacement payload ({new_len} bytes) cannot fit in span ({span_len} bytes)")]
    ReplacementTooLarge {
        /// Byte length of the new replacement payload.
        new_len: usize,
        /// Maximum capacity of the target span.
        span_len: usize,
    },
    /// A full-span replacement payload is smaller than the target [`ByteSpan`] and padding is disabled.
    #[error("replacement payload ({new_len} bytes) is smaller than span ({span_len} bytes) and no padding byte is configured")]
    ReplacementUnderflow {
        /// Byte length of the new replacement payload.
        new_len: usize,
        /// Required byte length of the target span.
        span_len: usize,
    },
    /// The requested [`ByteSpan`] extends past the end of the binary image.
    #[error("span [{start:#x}..{end:#x}) exceeds backing binary size ({total_len:#x})")]
    SpanOutOfRange {
        /// Inclusive start offset of the invalid span.
        start: usize,
        /// Exclusive end offset of the invalid span.
        end: usize,
        /// Total byte length of the binary image.
        total_len: usize,
    },
    /// An underlying filesystem I/O error occurred.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl StorageError {
    /// Maps this [`StorageError`] to its corresponding POSIX `errno` constant (`libc::c_int`).
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

/// Abstract storage interface for reading and mutating bounded binary spans.
pub trait BinaryStore: Send + Sync {
    /// Returns the total byte length of the binary image.
    fn total_len(&self) -> usize;

    /// Returns the path to the backing binary file on disk, if backed by a file.
    fn backing_path(&self) -> Option<&Path>;

    /// Returns the active [`WritePolicy`] for this store.
    fn write_policy(&self) -> WritePolicy;

    /// Reads bytes starting at absolute `offset` in the binary into `buf`.
    ///
    /// Returns the number of bytes read (`0` if `offset >= self.total_len()`).
    ///
    /// # Errors
    ///
    /// Returns a [`StorageError`] if an underlying read failure occurs.
    fn read_at(&self, offset: usize, buf: &mut [u8]) -> Result<usize, StorageError>;

    /// Reads bytes from `span` starting at relative offset `offset_in_span` into `buf`.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::SpanOutOfRange`] if `span.end > self.total_len()`.
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

    /// Reads the entire contents of `span` into a newly allocated `Vec<u8>`.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::SpanOutOfRange`] if `span.end > self.total_len()`.
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

    /// Writes `data` into `span` at relative offset `offset_in_span`.
    ///
    /// # Errors
    ///
    /// - Returns [`StorageError::ReadOnly`] if the policy is [`WritePolicy::ReadOnly`].
    /// - Returns [`StorageError::OutOfSpanBounds`] if `offset_in_span + data.len() > span.len()`.
    /// - Returns [`StorageError::SpanOutOfRange`] if `span.end > self.total_len()`.
    /// - Returns [`StorageError::Io`] if write-through to the backing file fails.
    fn write_in_span(
        &self,
        span: ByteSpan,
        offset_in_span: usize,
        data: &[u8],
    ) -> Result<usize, StorageError>;

    /// Replaces the entire contents of `span` with `new_blob` using the policy's configured padding.
    ///
    /// # Errors
    ///
    /// - Returns [`StorageError::ReadOnly`] if the policy is [`WritePolicy::ReadOnly`].
    /// - Returns [`StorageError::ReplacementTooLarge`] if `new_blob.len() > span.len()`.
    /// - Returns [`StorageError::ReplacementUnderflow`] if `new_blob.len() < span.len()` and no
    ///   `pad_byte` is configured in the [`WritePolicy`].
    fn replace_span(&self, span: ByteSpan, new_blob: &[u8]) -> Result<(), StorageError> {
        self.replace_span_with_fallback_pad(span, new_blob, None)
    }

    /// Replaces the contents of `span` with `new_blob`, using the policy's `pad_byte` if set,
    /// or `fallback_pad` (such as [`smart_pad_byte`]) when `new_blob.len() < span.len()`.
    ///
    /// # Errors
    ///
    /// - Returns [`StorageError::ReadOnly`] if the policy is [`WritePolicy::ReadOnly`].
    /// - Returns [`StorageError::ReplacementTooLarge`] if `new_blob.len() > span.len()`.
    /// - Returns [`StorageError::ReplacementUnderflow`] if `new_blob.len() < span.len()` and both
    ///   the policy's `pad_byte` and `fallback_pad` are [`None`].
    fn replace_span_with_fallback_pad(
        &self,
        span: ByteSpan,
        new_blob: &[u8],
        fallback_pad: Option<u8>,
    ) -> Result<(), StorageError>;

    /// Returns `true` if the Copy-on-Write overlay holds modifications not yet committed.
    fn is_dirty(&self) -> bool;

    /// Flushes buffered Copy-on-Write modifications back to the backing file on disk.
    ///
    /// # Errors
    ///
    /// - Returns [`StorageError::ReadOnly`] if the policy is [`WritePolicy::ReadOnly`].
    /// - Returns [`StorageError::Io`] if writing to the backing file fails.
    fn commit(&self) -> Result<(), StorageError>;
}

/// Thread-safe [`BinaryStore`] implementation supporting zero-overhead immutable reads,
/// Copy-on-Write byte-range overlays, and bounded write-through.
///
/// # Examples
///
/// ```
/// use fuse_binwalk::{BinaryStore, ByteSpan, OverlayBinaryStore, WritePolicy};
///
/// let store = OverlayBinaryStore::from_bytes(
///     vec![10, 20, 30, 40, 50],
///     None,
///     WritePolicy::CopyOnWriteOverlay { pad_byte: Some(0xFF) },
/// );
/// let span = ByteSpan::new(1, 4).unwrap();
/// store.replace_span(span, &[99])?;
/// assert_eq!(store.read_slice(span)?, vec![99, 0xFF, 0xFF]);
/// # Ok::<(), fuse_binwalk::StorageError>(())
/// ```
pub struct OverlayBinaryStore {
    backing_path: Option<PathBuf>,
    base_data: Arc<Vec<u8>>,
    policy: WritePolicy,
    /// Chunked CoW overlay keyed by absolute starting byte offset.
    overlay: RwLock<BTreeMap<usize, Vec<u8>>>,
}

impl OverlayBinaryStore {
    /// Loads a binary file from `path` into memory with the specified [`WritePolicy`].
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Io`] if `path` cannot be read.
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

    /// Creates an [`OverlayBinaryStore`] from an in-memory byte vector `data` and optional `backing_path`.
    pub fn from_bytes(data: Vec<u8>, backing_path: Option<PathBuf>, policy: WritePolicy) -> Self {
        Self {
            backing_path,
            base_data: Arc::new(data),
            policy,
            overlay: RwLock::new(BTreeMap::new()),
        }
    }

    /// Returns a slice of the original unmodified base binary image.
    pub fn base_bytes(&self) -> &[u8] {
        &self.base_data
    }

    fn apply_overlay_write(&self, abs_offset: usize, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let mut map = self.overlay.write().expect("overlay lock poisoned");
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

        let end_in_span =
            offset_in_span
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

    fn replace_span_with_fallback_pad(
        &self,
        span: ByteSpan,
        new_blob: &[u8],
        fallback_pad: Option<u8>,
    ) -> Result<(), StorageError> {
        if span.end > self.total_len() {
            return Err(StorageError::SpanOutOfRange {
                start: span.start,
                end: span.end,
                total_len: self.total_len(),
            });
        }

        let (policy_pad, write_through) = match self.policy {
            WritePolicy::ReadOnly => return Err(StorageError::ReadOnly),
            WritePolicy::InPlaceBounded {
                pad_byte,
                write_through,
            } => (pad_byte, write_through),
            WritePolicy::CopyOnWriteOverlay { pad_byte } => (pad_byte, false),
        };

        let effective_pad = policy_pad.or(fallback_pad);

        let span_len = span.len();
        if new_blob.len() > span_len {
            return Err(StorageError::ReplacementTooLarge {
                new_len: new_blob.len(),
                span_len,
            });
        }

        let payload: Vec<u8> = if new_blob.len() < span_len {
            let Some(pad) = effective_pad else {
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
        !self
            .overlay
            .read()
            .expect("overlay lock poisoned")
            .is_empty()
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
        let store =
            OverlayBinaryStore::from_bytes(vec![0, 1, 2, 3, 4, 5], None, WritePolicy::ReadOnly);
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
            WritePolicy::CopyOnWriteOverlay {
                pad_byte: Some(0xFF),
            },
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
