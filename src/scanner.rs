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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConfidenceLevel {
    Low,
    Medium,
    High,
}

impl ConfidenceLevel {
    pub fn to_binwalk_u8(self) -> u8 {
        match self {
            ConfidenceLevel::Low => CONFIDENCE_LOW,
            ConfidenceLevel::Medium => CONFIDENCE_MEDIUM,
            ConfidenceLevel::High => CONFIDENCE_HIGH,
        }
    }

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

#[derive(Debug, Clone, Default)]
pub struct ScanConfig {
    pub min_confidence: Option<ConfidenceLevel>,
    pub include: Option<Vec<String>>,
    pub exclude: Option<Vec<String>>,
    pub full_search: bool,
}

/// A validated signature region in the binary with known start and end byte offsets.
#[derive(Debug, Clone)]
pub struct CarvedEntry {
    /// Index in the catalog (0-based).
    pub index: usize,
    /// Known half-open byte range `[start, end)` in the binary.
    pub span: ByteSpan,
    /// Filename under `/raw/`, e.g., `0x00001000_0x00002400_squashfs.sqsh`
    pub raw_filename: String,
    /// Directory name under `/extracted/` (if `has_extractor` is true), e.g., `0x00001000_0x00002400_squashfs`
    pub extracted_dirname: String,
    /// Underlying Binwalk `SignatureResult` (populated with `id`, `name`, `offset`, `size`, etc.).
    pub signature_result: SignatureResult,
    /// Associated Binwalk `Extractor` (if this signature supports extraction and did not decline it).
    pub extractor: Option<Extractor>,
}

impl CarvedEntry {
    pub fn has_extractor(&self) -> bool {
        self.extractor.is_some()
    }
}

/// Serializable manifest entry exposed in `/manifest.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub index: usize,
    pub id: String,
    pub name: String,
    pub description: String,
    pub confidence: ConfidenceLevel,
    pub confidence_raw: u8,
    pub start_offset: usize,
    pub end_offset: usize,
    pub start_hex: String,
    pub end_hex: String,
    pub size: usize,
    pub raw_path: String,
    pub extracted_path: Option<String>,
    pub extractable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestDocument {
    pub binary_size: usize,
    pub total_bounded_entries: usize,
    pub total_extractable_entries: usize,
    pub entries: Vec<ManifestEntry>,
}

/// Scans `file_data` using Binwalk v3's signature definitions and parsers, returning all
/// valid signatures that explicitly report a known non-zero size (`size > 0` and `offset + size <= file_data.len()`),
/// including overlapping or nested signatures.
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
                        available_data,
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

    // 2. Run Aho-Corasick overlapping pattern search across the entire binary without skipping
    // over matched spans, so nested and overlapping bounded files are all discovered.
    if !binwalker.patterns.is_empty() {
        let ac = AhoCorasick::new(&binwalker.patterns)
            .map_err(|e| anyhow!("Failed to build Aho-Corasick automaton: {e}"))?;

        for mat in ac.find_overlapping_iter(file_data) {
            let magic_offset = mat.start();
            let pattern_idx = mat.pattern().as_usize();
            let Some(signature) = binwalker.pattern_signature_table.get(&pattern_idx) else {
                continue;
            };

            if let Ok(mut sig_result) = (signature.parser)(file_data, magic_offset) {
                if let Some(extractor) = validate_and_populate(
                    &mut sig_result,
                    signature,
                    &binwalker,
                    available_data,
                    min_conf,
                ) {
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

        let ext = infer_extension(&sig_result.name, extractor.as_ref());
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

fn validate_and_populate(
    sig_result: &mut SignatureResult,
    signature: &Signature,
    binwalker: &Binwalk,
    available_data: usize,
    min_conf: u8,
) -> Option<Option<Extractor>> {
    // Must have an explicitly known non-zero size from the signature parser itself
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

    let extractor = if sig_result.extraction_declined {
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

fn infer_extension(sig_name: &str, extractor: Option<&Extractor>) -> String {
    if let Some(ext) = extractor {
        let trimmed = ext.extension.trim().trim_start_matches('.');
        if !trimmed.is_empty() {
            return sanitize_component(trimmed);
        }
    }
    match sig_name {
        "png" => "png",
        "jpeg" => "jpg",
        "gif" => "gif",
        "gzip" => "gz",
        "bzip2" => "bz2",
        "xz" => "xz",
        "zstd" => "zst",
        "lz4" => "lz4",
        "lzma" => "lzma",
        "zip" => "zip",
        "tar" | "tarball" => "tar",
        "cpio" => "cpio",
        "squashfs" => "sqsh",
        "cramfs" => "cramfs",
        "romfs" => "romfs",
        "jffs2" => "jffs2",
        "ubifs" => "ubifs",
        "ext" => "ext",
        "iso9660" => "iso",
        "elf" => "elf",
        "pe" => "exe",
        "dtb" => "dtb",
        "uimage" | "fit" => "img",
        "pdf" => "pdf",
        "xml" => "xml",
        "openssl_crypt" => "enc",
        "pem_certificate" | "pem_key" => "pem",
        _ => "bin",
    }
    .to_string()
}

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
