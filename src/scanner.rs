//! Signature scanning, boundary validation, and manifest generation using Binwalk v3.
//!
//! This module drives Binwalk v3's signature table and parsers across a binary image,
//! filtering for signatures with known start and end byte offsets (`size > 0` and
//! `offset + size <= file_data.len()`) and producing [`CarvedEntry`] records and
//! [`ManifestDocument`] summaries.

use crate::storage::ByteSpan;
use aho_corasick::AhoCorasick;
use anyhow::{anyhow, Result};
use binwalk::extractors::common::{Extractor, ExtractorType};
use binwalk::signatures::common::{
    Signature, SignatureResult, CONFIDENCE_HIGH, CONFIDENCE_LOW, CONFIDENCE_MEDIUM,
};
use binwalk::Binwalk;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Represents the minimum or reported confidence tier for a Binwalk signature match.
///
/// # Examples
///
/// ```
/// use fuse_binwalk::ConfidenceLevel;
///
/// let level = ConfidenceLevel::from_binwalk_u8(250);
/// assert_eq!(level, ConfidenceLevel::High);
/// assert!(level.to_binwalk_u8() >= ConfidenceLevel::Medium.to_binwalk_u8());
/// ```
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum ConfidenceLevel {
    /// Low confidence threshold (`CONFIDENCE_LOW`).
    Low,
    /// Medium confidence threshold (`CONFIDENCE_MEDIUM`).
    Medium,
    /// High confidence threshold (`CONFIDENCE_HIGH`).
    High,
}

impl ConfidenceLevel {
    /// Converts this [`ConfidenceLevel`] into Binwalk's raw `u8` confidence constant.
    pub fn to_binwalk_u8(self) -> u8 {
        match self {
            ConfidenceLevel::Low => CONFIDENCE_LOW,
            ConfidenceLevel::Medium => CONFIDENCE_MEDIUM,
            ConfidenceLevel::High => CONFIDENCE_HIGH,
        }
    }

    /// Maps a raw Binwalk `u8` confidence score to its corresponding [`ConfidenceLevel`].
    pub fn from_binwalk_u8(val: u8) -> Self {
        if val >= CONFIDENCE_HIGH {
            ConfidenceLevel::High
        } else if val >= CONFIDENCE_MEDIUM {
            ConfidenceLevel::Medium
        } else {
            ConfidenceLevel::Low
        }
    }
}

/// Configures signature filtering and search behavior for [`scan_bounded_signatures`].
#[derive(Debug, Clone, Default)]
pub struct ScanConfig {
    /// Minimum confidence level required for a signature to be included.
    pub min_confidence: Option<ConfidenceLevel>,
    /// Optional allow-list of Binwalk signature names to scan for.
    pub include: Option<Vec<String>>,
    /// Optional deny-list of Binwalk signature names to exclude.
    pub exclude: Option<Vec<String>>,
    /// Whether short signatures should be searched across the entire binary instead of only offset `0`.
    pub full_search: bool,
}

/// Represents a validated signature region in the binary with known start and end byte offsets.
#[derive(Debug, Clone)]
pub struct CarvedEntry {
    /// Zero-based index of this entry in the discovered catalog.
    pub index: usize,
    /// Half-open byte range `[start, end)` in the binary.
    pub span: ByteSpan,
    /// Virtual filename exposed under `/raw/` (for example, `0x00001000_0x00002400_squashfs.sqsh`).
    pub raw_filename: String,
    /// Directory name exposed under `/extracted/` when [`Self::has_extractor`] is `true`.
    pub extracted_dirname: String,
    /// Underlying Binwalk [`SignatureResult`] containing the signature's name, description, and metadata.
    pub signature_result: SignatureResult,
    /// Associated Binwalk [`Extractor`] when the signature supports container or stream extraction.
    pub extractor: Option<Extractor>,
}

impl CarvedEntry {
    /// Returns `true` if this entry has an associated container or stream extractor for `/extracted/`.
    pub fn has_extractor(&self) -> bool {
        self.extractor.is_some()
    }
}

/// Represents a single serializable entry inside a [`ManifestDocument`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
    /// Zero-based catalog index.
    pub index: usize,
    /// Unique identifier string for the signature match.
    pub id: String,
    /// Binwalk signature short name (such as `"zip"`, `"svg"`, or `"png"`).
    pub name: String,
    /// Human-readable description reported by the Binwalk parser.
    pub description: String,
    /// Categorized confidence tier.
    pub confidence: ConfidenceLevel,
    /// Raw numeric confidence score (`0..=255`).
    pub confidence_raw: u8,
    /// Inclusive starting byte offset.
    pub start_offset: usize,
    /// Exclusive ending byte offset.
    pub end_offset: usize,
    /// Formatted hexadecimal start offset (`"0x..."`).
    pub start_hex: String,
    /// Formatted hexadecimal end offset (`"0x..."`).
    pub end_hex: String,
    /// Total byte length of the region.
    pub size: usize,
    /// Current unpadded payload size in bytes (`<= size`).
    pub payload_size: usize,
    /// Remaining free-space budget (`size - payload_size`) in bytes before exceeding the span.
    pub slack_bytes: usize,
    /// Whether this entry has been modified in the current session.
    pub modified: bool,
    /// Virtual path under `/raw/`.
    pub raw_path: String,
    /// Virtual directory path under `/extracted/`, or [`None`] for carve-only entries.
    pub extracted_path: Option<String>,
    /// Whether this entry is exposed under `/extracted/`.
    pub extractable: bool,
}

/// Represents the top-level JSON manifest exposed at `/manifest.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestDocument {
    /// Total size of the underlying binary image in bytes.
    pub binary_size: usize,
    /// Total number of bounded signatures discovered in the binary.
    pub total_bounded_entries: usize,
    /// Number of bounded signatures that also expose an `/extracted/` directory.
    pub total_extractable_entries: usize,
    /// Ordered list of discovered [`ManifestEntry`] records.
    pub entries: Vec<ManifestEntry>,
}

/// Scans `file_data` using Binwalk v3's signature definitions and parsers, returning all
/// valid signatures that report a known non-zero size (`size > 0` and `offset + size <= file_data.len()`).
///
/// Overlapping and nested signatures of distinct types (such as an `"svg"` or `"png"` stored inside
/// a `"zip"` or `"tarball"` container) are preserved in the returned list, ordered by
/// `(start_offset, end_offset, signature_name)`.
///
/// # Errors
///
/// Returns an error if Binwalk fails to initialize its signature tables or if the Aho-Corasick
/// automaton cannot be constructed.
///
/// # Examples
///
/// ```
/// use fuse_binwalk::{scan_bounded_signatures, ScanConfig};
///
/// let svg_blob = b"<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>";
/// let entries = scan_bounded_signatures(svg_blob, &ScanConfig::default())?;
/// assert_eq!(entries.len(), 1);
/// assert_eq!(entries[0].signature_result.name, "svg");
/// assert_eq!(entries[0].span.len(), svg_blob.len());
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn scan_bounded_signatures(file_data: &[u8], config: &ScanConfig) -> Result<Vec<CarvedEntry>> {
    let binwalker = Binwalk::configure(
        None,
        None,
        config.include.clone(),
        config.exclude.clone(),
        None,
        config.full_search,
    )
    .map_err(|_| anyhow!("Failed to configure Binwalk instance"))?;

    let min_conf = config
        .min_confidence
        .unwrap_or(ConfidenceLevel::Low)
        .to_binwalk_u8();
    let available_data = file_data.len();

    let mut raw_matches: Vec<(SignatureResult, Option<Extractor>)> = Vec::new();
    let mut seen_keys: HashSet<(usize, usize, String)> = HashSet::new();

    // 1. Evaluate short signatures that are only checked at offset 0 (unless full_search included them in patterns)
    for signature in &binwalker.short_signatures {
        for magic in &signature.magic {
            let magic_start = signature.magic_offset;
            let Some(magic_end) = magic_start.checked_add(magic.len()) else {
                continue;
            };
            if available_data >= magic_end && &file_data[magic_start..magic_end] == magic.as_slice()
            {
                if let Ok(mut sig_result) = (signature.parser)(file_data, magic_start) {
                    if let Some(accepted) = validate_and_populate(
                        &mut sig_result,
                        signature,
                        &binwalker,
                        file_data,
                        min_conf,
                    ) {
                        let key = (sig_result.offset, sig_result.size, sig_result.name.clone());
                        if seen_keys.insert(key) {
                            raw_matches.push((sig_result, accepted));
                        }
                    }
                    break;
                }
            }
        }
    }

    // 2. Run Aho-Corasick overlapping pattern search across the entire binary.
    // Track the active end offset per signature type so multi-record containers (like `zip` or `tarball`)
    // don't redundantly re-parse every internal record as a truncated copy of the outer container,
    // while still allowing all OTHER signature types (like `png`, `jpeg`, `gzip`, etc.) inside the container to be found!
    if !binwalker.patterns.is_empty() {
        let ac = AhoCorasick::new(&binwalker.patterns)
            .map_err(|e| anyhow!("Failed to build Aho-Corasick automaton: {e}"))?;

        let mut active_end_by_sig: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();

        // Binwalk's `zip` parser scans from `offset` to EOF looking for `PK\x05\x06\x00\x00\x00\x00` on every `PK\x03\x04`.
        // Pre-compute the last offset of `PK\x05\x06\x00\x00\x00\x00` so we don't do O(N^2) scans when a file (like Firefox's omni.ja)
        // has thousands of `PK\x03\x04` entries without standard EOCD magic.
        const ZIP_EOCD_MAGIC: &[u8; 8] = b"PK\x05\x06\x00\x00\x00\x00";
        let last_zip_eocd_offset: Option<usize> = file_data
            .windows(ZIP_EOCD_MAGIC.len())
            .rposition(|w| w == ZIP_EOCD_MAGIC);

        for mat in ac.find_overlapping_iter(file_data) {
            let magic_offset = mat.start();
            let pattern_idx = mat.pattern().as_usize();
            let Some(signature) = binwalker.pattern_signature_table.get(&pattern_idx) else {
                continue;
            };

            if let Some(&active_end) = active_end_by_sig.get(&signature.name) {
                if magic_offset < active_end {
                    continue;
                }
            }

            if signature.name == "zip" {
                match last_zip_eocd_offset {
                    None => continue,
                    Some(last_eocd) if magic_offset > last_eocd => continue,
                    _ => {}
                }
            }

            if let Ok(mut sig_result) = (signature.parser)(file_data, magic_offset) {
                if let Some(extractor) = validate_and_populate(
                    &mut sig_result,
                    signature,
                    &binwalker,
                    file_data,
                    min_conf,
                ) {
                    let sig_end = sig_result.offset.saturating_add(sig_result.size);
                    let prev_end = active_end_by_sig
                        .entry(sig_result.name.clone())
                        .or_insert(0);
                    if sig_end > *prev_end {
                        *prev_end = sig_end;
                    }

                    let key = (sig_result.offset, sig_result.size, sig_result.name.clone());
                    if seen_keys.insert(key) {
                        raw_matches.push((sig_result, extractor));
                    }
                }
            }
        }
    }

    // Sort by (start_offset, end_offset, signature_name)
    raw_matches.sort_by(|(a, _), (b, _)| {
        let a_end = a.offset.saturating_add(a.size);
        let b_end = b.offset.saturating_add(b.size);
        a.offset
            .cmp(&b.offset)
            .then_with(|| a_end.cmp(&b_end))
            .then_with(|| a.name.cmp(&b.name))
    });

    // Build CarvedEntry list with disambiguated names if needed
    let mut used_dirnames: HashSet<String> = HashSet::new();
    let mut entries = Vec::with_capacity(raw_matches.len());

    for (idx, (mut sig_result, extractor)) in raw_matches.into_iter().enumerate() {
        let span = ByteSpan::from_offset_size(sig_result.offset, sig_result.size)
            .expect("validated size > 0");
        sig_result.id = format!("sig-{idx:04}-{:08x}-{:08x}", span.start, span.end);

        let sanitized_name = sanitize_component(&sig_result.name);
        let base_stem = format!("0x{:08X}_0x{:08X}_{}", span.start, span.end, sanitized_name);

        let mut stem = base_stem.clone();
        let mut suffix = 2usize;
        while !used_dirnames.insert(stem.clone()) {
            stem = format!("{base_stem}_{suffix}");
            suffix += 1;
        }

        let ext = infer_extension(
            &sig_result.name,
            &sig_result.description,
            extractor.as_ref(),
        );
        let raw_filename = format!("{stem}.{ext}");
        let extracted_dirname = stem;

        entries.push(CarvedEntry {
            index: idx,
            span,
            raw_filename,
            extracted_dirname,
            signature_result: sig_result,
            extractor,
        });
    }

    Ok(entries)
}

/// Returns true for leaf formats whose Binwalk "extractor" merely carves the raw `[start..end]`
/// slice to disk without unpacking, decompressing, or transforming it (which is redundant with `/raw/`).
fn is_carve_only_signature(sig_name: &str) -> bool {
    matches!(
        sig_name,
        "png"
            | "jpeg"
            | "gif"
            | "svg"
            | "riff"
            | "pcapng"
            | "pem_certificate"
            | "pem_public_key"
            | "pem_private_key"
    )
}

fn validate_and_populate(
    sig_result: &mut SignatureResult,
    signature: &Signature,
    binwalker: &Binwalk,
    file_data: &[u8],
    min_conf: u8,
) -> Option<Option<Extractor>> {
    let available_data = file_data.len();

    // Binwalk's built-in `elf` parser validates the ELF header but leaves `size = 0`;
    // compute the exact ELF boundary from its program/section header tables when available.
    if sig_result.size == 0 && signature.name == "elf" {
        if let Some(elf_size) = infer_elf_size(file_data.get(sig_result.offset..)?) {
            sig_result.size = elf_size;
        }
    }

    // Must have an explicitly known non-zero size
    if sig_result.size == 0 {
        return None;
    }

    // Verify start + size does not overflow or exceed the binary length
    let end_offset = sig_result.offset.checked_add(sig_result.size)?;
    if end_offset > available_data || (end_offset as isize) < 0 {
        return None;
    }

    if sig_result.confidence < min_conf {
        return None;
    }

    sig_result.name = signature.name.clone();
    sig_result.always_display = signature.always_display;

    let extractor = if sig_result.extraction_declined || is_carve_only_signature(&signature.name) {
        None
    } else if let Some(pref) = &sig_result.preferred_extractor {
        if matches!(pref.utility, ExtractorType::None) {
            None
        } else {
            Some(pref.clone())
        }
    } else {
        binwalker
            .extractor_lookup_table
            .get(&signature.name)
            .and_then(|opt| opt.clone())
            .filter(|ext| !matches!(ext.utility, ExtractorType::None))
    };

    Some(extractor)
}

/// Computes the exact byte length of an ELF binary from its ELF header, program headers, and section headers.
fn infer_elf_size(slice: &[u8]) -> Option<usize> {
    if slice.len() < 64 || &slice[0..4] != b"\x7FELF" {
        return None;
    }
    let class = slice[4];
    let endian = slice[5];
    let is_le = match endian {
        1 => true,
        2 => false,
        _ => return None,
    };

    let read_u16 = |off: usize| -> Option<u16> {
        let b: [u8; 2] = slice.get(off..off + 2)?.try_into().ok()?;
        Some(if is_le {
            u16::from_le_bytes(b)
        } else {
            u16::from_be_bytes(b)
        })
    };
    let read_u32 = |off: usize| -> Option<u32> {
        let b: [u8; 4] = slice.get(off..off + 4)?.try_into().ok()?;
        Some(if is_le {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        })
    };
    let read_u64 = |off: usize| -> Option<u64> {
        let b: [u8; 8] = slice.get(off..off + 8)?.try_into().ok()?;
        Some(if is_le {
            u64::from_le_bytes(b)
        } else {
            u64::from_be_bytes(b)
        })
    };

    const SHT_NOBITS: u32 = 8;

    let mut max_end: usize = 0;

    if class == 1 {
        // 32-bit ELF
        let phoff = read_u32(28)? as usize;
        let shoff = read_u32(32)? as usize;
        let ehsize = read_u16(40)? as usize;
        let phentsize = read_u16(42)? as usize;
        let phnum = read_u16(44)? as usize;
        let shentsize = read_u16(46)? as usize;
        let shnum = read_u16(48)? as usize;

        max_end = max_end.max(ehsize);
        if phoff > 0 && phnum > 0 {
            max_end = max_end.max(phoff.checked_add(phentsize.checked_mul(phnum)?)?);
            for i in 0..phnum {
                let p_base = phoff.checked_add(i.checked_mul(phentsize)?)?;
                let p_offset = read_u32(p_base + 4)? as usize;
                let p_filesz = read_u32(p_base + 16)? as usize;
                max_end = max_end.max(p_offset.checked_add(p_filesz)?);
            }
        }
        if shoff > 0 && shnum > 0 {
            max_end = max_end.max(shoff.checked_add(shentsize.checked_mul(shnum)?)?);
            for i in 0..shnum {
                let s_base = shoff.checked_add(i.checked_mul(shentsize)?)?;
                let sh_type = read_u32(s_base + 4)?;
                if sh_type != SHT_NOBITS {
                    let sh_offset = read_u32(s_base + 16)? as usize;
                    let sh_size = read_u32(s_base + 20)? as usize;
                    max_end = max_end.max(sh_offset.checked_add(sh_size)?);
                }
            }
        }
    } else if class == 2 {
        // 64-bit ELF
        let phoff = usize::try_from(read_u64(32)?).ok()?;
        let shoff = usize::try_from(read_u64(40)?).ok()?;
        let ehsize = read_u16(52)? as usize;
        let phentsize = read_u16(54)? as usize;
        let phnum = read_u16(56)? as usize;
        let shentsize = read_u16(58)? as usize;
        let shnum = read_u16(60)? as usize;

        max_end = max_end.max(ehsize);
        if phoff > 0 && phnum > 0 {
            max_end = max_end.max(phoff.checked_add(phentsize.checked_mul(phnum)?)?);
            for i in 0..phnum {
                let p_base = phoff.checked_add(i.checked_mul(phentsize)?)?;
                let p_offset = usize::try_from(read_u64(p_base + 8)?).ok()?;
                let p_filesz = usize::try_from(read_u64(p_base + 32)?).ok()?;
                max_end = max_end.max(p_offset.checked_add(p_filesz)?);
            }
        }
        if shoff > 0 && shnum > 0 {
            max_end = max_end.max(shoff.checked_add(shentsize.checked_mul(shnum)?)?);
            for i in 0..shnum {
                let s_base = shoff.checked_add(i.checked_mul(shentsize)?)?;
                let sh_type = read_u32(s_base + 4)?;
                if sh_type != SHT_NOBITS {
                    let sh_offset = usize::try_from(read_u64(s_base + 24)?).ok()?;
                    let sh_size = usize::try_from(read_u64(s_base + 32)?).ok()?;
                    max_end = max_end.max(sh_offset.checked_add(sh_size)?);
                }
            }
        }
    } else {
        return None;
    }

    if max_end > 0 && max_end <= slice.len() {
        Some(max_end)
    } else {
        None
    }
}

fn sanitize_component(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "data".to_string()
    } else {
        out
    }
}

fn infer_extension(sig_name: &str, description: &str, extractor: Option<&Extractor>) -> String {
    match sig_name {
        "png" => return "png".to_string(),
        "jpeg" => return "jpg".to_string(),
        "gif" => return "gif".to_string(),
        "svg" => return "svg".to_string(),
        "riff" => {
            if description.contains("WEBP") {
                return "webp".to_string();
            } else if description.contains("WAVE") {
                return "wav".to_string();
            } else if description.contains("AVI") {
                return "avi".to_string();
            }
            return "riff".to_string();
        }
        "pcapng" => return "pcapng".to_string(),
        "pem_certificate" => return "crt".to_string(),
        "pem_public_key" | "pem_private_key" | "pem_key" => return "pem".to_string(),
        "gzip" => return "gz".to_string(),
        "bzip2" => return "bz2".to_string(),
        "xz" => return "xz".to_string(),
        "zstd" => return "zst".to_string(),
        "lz4" => return "lz4".to_string(),
        "lzfse" => return "lzfse".to_string(),
        "lzma" => return "lzma".to_string(),
        "lzop" => return "lzo".to_string(),
        "zlib" => return "zlib".to_string(),
        "zip" => return "zip".to_string(),
        "7zip" => return "7z".to_string(),
        "rar" => return "rar".to_string(),
        "cab" => return "cab".to_string(),
        "dmg" => return "dmg".to_string(),
        "tar" | "tarball" => return "tar".to_string(),
        "cpio" => return "cpio".to_string(),
        "squashfs" => return "sqsh".to_string(),
        "cramfs" => return "cramfs".to_string(),
        "romfs" => return "romfs".to_string(),
        "jffs2" => return "jffs2".to_string(),
        "yaffs" => return "yaffs".to_string(),
        "ubi" => return "ubi".to_string(),
        "ubifs" => return "ubifs".to_string(),
        "ext" => return "ext".to_string(),
        "fat" => return "fat".to_string(),
        "ntfs" => return "ntfs".to_string(),
        "apfs" => return "apfs".to_string(),
        "btrfs" => return "btrfs".to_string(),
        "iso9660" => return "iso".to_string(),
        "elf" => return "elf".to_string(),
        "pe" => return "exe".to_string(),
        "dtb" => return "dtb".to_string(),
        "uimage" | "fit" | "mbr" | "efigpt" | "android_sparse" => return "img".to_string(),
        "pdf" => return "pdf".to_string(),
        "xml" => return "xml".to_string(),
        "srecord" | "srecord_generic" => return "srec".to_string(),
        "openssl" | "openssl_crypt" => return "enc".to_string(),
        _ => {}
    }

    if let Some(ext) = extractor {
        let trimmed = ext.extension.trim().trim_start_matches('.');
        if !trimmed.is_empty() {
            return sanitize_component(trimmed);
        }
    }

    "bin".to_string()
}

/// Builds a serializable [`ManifestDocument`] from the discovered [`CarvedEntry`] slice.
///
/// # Examples
///
/// ```
/// use fuse_binwalk::{build_manifest, scan_bounded_signatures, ScanConfig};
///
/// let data = b"<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>";
/// let entries = scan_bounded_signatures(data, &ScanConfig::default())?;
/// let manifest = build_manifest(data.len(), &entries);
/// assert_eq!(manifest.binary_size, data.len());
/// assert_eq!(manifest.total_bounded_entries, 1);
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn build_manifest(binary_size: usize, entries: &[CarvedEntry]) -> ManifestDocument {
    let mut extractable_count = 0;
    let manifest_entries = entries
        .iter()
        .map(|entry| {
            let extractable = entry.has_extractor();
            if extractable {
                extractable_count += 1;
            }
            ManifestEntry {
                index: entry.index,
                id: entry.signature_result.id.clone(),
                name: entry.signature_result.name.clone(),
                description: entry.signature_result.description.clone(),
                confidence: ConfidenceLevel::from_binwalk_u8(entry.signature_result.confidence),
                confidence_raw: entry.signature_result.confidence,
                start_offset: entry.span.start,
                end_offset: entry.span.end,
                start_hex: format!("0x{:08X}", entry.span.start),
                end_hex: format!("0x{:08X}", entry.span.end),
                size: entry.span.len(),
                payload_size: entry.span.len(),
                slack_bytes: 0,
                modified: false,
                raw_path: format!("/raw/{}", entry.raw_filename),
                extracted_path: if extractable {
                    Some(format!("/extracted/{}", entry.extracted_dirname))
                } else {
                    None
                },
                extractable,
            }
        })
        .collect();

    ManifestDocument {
        binary_size,
        total_bounded_entries: entries.len(),
        total_extractable_entries: extractable_count,
        entries: manifest_entries,
    }
}
