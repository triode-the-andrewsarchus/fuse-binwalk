use crate::extractor::{RegionRepacker, RepackerRegistry};
use crate::scanner::CarvedEntry;
use crate::storage::{BinaryStore, ByteSpan};
use anyhow::{anyhow, bail, Context, Result};
use bzip2::write::BzEncoder;
use flate2::write::{DeflateEncoder, GzEncoder, ZlibEncoder};
use flate2::Compression;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use walkdir::WalkDir;
use xz2::stream::{LzmaOptions, Stream};
use xz2::write::XzEncoder;

/// Registers all built-in container and compression repackers into `registry`.
pub fn register_builtin_repackers(registry: &RepackerRegistry) {
    registry.register(Arc::new(ZipRepacker));
    registry.register(Arc::new(TarRepacker::new("tar")));
    registry.register(Arc::new(TarRepacker::new("tarball")));
    registry.register(Arc::new(GzipRepacker));
    registry.register(Arc::new(ZlibRepacker));
    registry.register(Arc::new(Bzip2Repacker));
    registry.register(Arc::new(XzRepacker::new_xz()));
    registry.register(Arc::new(XzRepacker::new_lzma()));
    registry.register(Arc::new(CpioRepacker));
    registry.register(Arc::new(ExternalCommandRepacker::new_zstd()));
    registry.register(Arc::new(ExternalCommandRepacker::new_lz4()));
    registry.register(Arc::new(SquashfsRepacker));
}

/// Checks if a binary executable exists in the current `PATH`.
pub fn command_exists_in_path(binary_name: &str) -> bool {
    if binary_name.contains('/') {
        return Path::new(binary_name).is_file();
    }
    let Some(path_var) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path_var).any(|dir| {
        let candidate = dir.join(binary_name);
        candidate.is_file()
    })
}

/// Collects regular files, directories, and symlinks inside `dir` (excluding `_extraction_status.txt`)
/// in deterministic lexicographical order of relative paths.
fn collect_extracted_entries(root: &Path) -> Result<Vec<(String, PathBuf)>> {
    let mut items = Vec::new();
    for entry in WalkDir::new(root).follow_links(false) {
        let entry = entry?;
        let path = entry.path();
        if path == root {
            continue;
        }
        let rel = path
            .strip_prefix(root)
            .map_err(|e| anyhow!("strip_prefix failed: {e}"))?;
        let rel_str = rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        if rel_str == "_extraction_status.txt" {
            continue;
        }
        items.push((rel_str, path.to_path_buf()));
    }
    items.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(items)
}

/// Helper: If `extracted_dir` contains_only one regular file (and no subdirectories),
/// returns the bytes of that single file. Otherwise packs `extracted_dir` into a TAR archive
/// and returns the TAR bytes.
fn read_single_file_or_tar(extracted_dir: &Path) -> Result<Vec<u8>> {
    let items = collect_extracted_entries(extracted_dir)?;
    let regular_files: Vec<&PathBuf> = items
        .iter()
        .filter_map(|(_, p)| {
            fs::symlink_metadata(p)
                .ok()
                .filter(|m| m.is_file())
                .map(|_| p)
        })
        .collect();

    if items.len() == 1 && regular_files.len() == 1 {
        Ok(fs::read(regular_files[0])?)
    } else {
        pack_directory_to_tar(extracted_dir)
    }
}

/// Packs `extracted_dir` into a deterministic uncompressed TAR byte buffer.
pub fn pack_directory_to_tar(extracted_dir: &Path) -> Result<Vec<u8>> {
    let mut tar_buf = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_buf);
        builder.follow_symlinks(false);
        let items = collect_extracted_entries(extracted_dir)?;
        for (rel_str, full_path) in items {
            builder
                .append_path_with_name(&full_path, &rel_str)
                .with_context(|| format!("Failed to append '{rel_str}' to tar archive"))?;
        }
        builder.finish()?;
    }
    Ok(tar_buf)
}

// ============================================================================
// 1. TAR Repacker
// ============================================================================

pub struct TarRepacker {
    sig_name: &'static str,
}

impl TarRepacker {
    pub fn new(sig_name: &'static str) -> Self {
        Self { sig_name }
    }
}

impl RegionRepacker for TarRepacker {
    fn signature_name(&self) -> &str {
        self.sig_name
    }

    fn repack(&self, extracted_dir: &Path, _entry: &CarvedEntry) -> Result<Vec<u8>> {
        pack_directory_to_tar(extracted_dir)
    }
}

// ============================================================================
// 2. GZIP Repacker
// ============================================================================

pub struct GzipRepacker;

impl RegionRepacker for GzipRepacker {
    fn signature_name(&self) -> &str {
        "gzip"
    }

    fn repack(&self, extracted_dir: &Path, _entry: &CarvedEntry) -> Result<Vec<u8>> {
        let payload = read_single_file_or_tar(extracted_dir)?;
        let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&payload)?;
        Ok(encoder.finish()?)
    }
}

// ============================================================================
// 3. ZLIB Repacker
// ============================================================================

pub struct ZlibRepacker;

impl RegionRepacker for ZlibRepacker {
    fn signature_name(&self) -> &str {
        "zlib"
    }

    fn repack(&self, extracted_dir: &Path, _entry: &CarvedEntry) -> Result<Vec<u8>> {
        let payload = read_single_file_or_tar(extracted_dir)?;
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&payload)?;
        Ok(encoder.finish()?)
    }
}

// ============================================================================
// 4. BZIP2 Repacker
// ============================================================================

pub struct Bzip2Repacker;

impl RegionRepacker for Bzip2Repacker {
    fn signature_name(&self) -> &str {
        "bzip2"
    }

    fn repack(&self, extracted_dir: &Path, _entry: &CarvedEntry) -> Result<Vec<u8>> {
        let payload = read_single_file_or_tar(extracted_dir)?;
        let mut encoder = BzEncoder::new(Vec::new(), bzip2::Compression::best());
        encoder.write_all(&payload)?;
        Ok(encoder.finish()?)
    }
}

// ============================================================================
// 5. XZ / LZMA Repacker
// ============================================================================

pub struct XzRepacker {
    sig_name: &'static str,
    is_lzma: bool,
}

impl XzRepacker {
    pub fn new_xz() -> Self {
        Self {
            sig_name: "xz",
            is_lzma: false,
        }
    }

    pub fn new_lzma() -> Self {
        Self {
            sig_name: "lzma",
            is_lzma: true,
        }
    }
}

impl RegionRepacker for XzRepacker {
    fn signature_name(&self) -> &str {
        self.sig_name
    }

    fn repack(&self, extracted_dir: &Path, _entry: &CarvedEntry) -> Result<Vec<u8>> {
        let payload = read_single_file_or_tar(extracted_dir)?;
        if self.is_lzma {
            let opts = LzmaOptions::new_preset(6)?;
            let stream = Stream::new_lzma_encoder(&opts)?;
            let mut encoder = XzEncoder::new_stream(Vec::new(), stream);
            encoder.write_all(&payload)?;
            Ok(encoder.finish()?)
        } else {
            let mut encoder = XzEncoder::new(Vec::new(), 6);
            encoder.write_all(&payload)?;
            Ok(encoder.finish()?)
        }
    }
}

// ============================================================================
// 6. CPIO (SVR4 newc 070701) Repacker
// ============================================================================

pub struct CpioRepacker;

impl RegionRepacker for CpioRepacker {
    fn signature_name(&self) -> &str {
        "cpio"
    }

    fn repack(&self, extracted_dir: &Path, _entry: &CarvedEntry) -> Result<Vec<u8>> {
        let items = collect_extracted_entries(extracted_dir)?;
        let mut out = Vec::new();
        let mut ino: u32 = 1;

        for (rel_str, full_path) in items {
            let md = fs::symlink_metadata(&full_path)?;
            let ft = md.file_type();
            let (mode, body): (u32, Vec<u8>) = if ft.is_dir() {
                (0o040000 | (md.permissions().mode() & 0o7777), Vec::new())
            } else if ft.is_symlink() {
                let target = fs::read_link(&full_path)?;
                (
                    0o120777,
                    target.as_os_str().to_string_lossy().as_bytes().to_vec(),
                )
            } else if ft.is_file() {
                (
                    0o100000 | (md.permissions().mode() & 0o7777),
                    fs::read(&full_path)?,
                )
            } else {
                continue;
            };

            let nlink: u32 = if ft.is_dir() { 2 } else { 1 };
            let mtime = md.mtime().max(0) as u32;
            write_cpio_newc_entry(&mut out, ino, mode, nlink, mtime, &rel_str, &body);
            ino += 1;
        }

        // Write TRAILER!!!
        write_cpio_newc_entry(&mut out, 0, 0, 1, 0, "TRAILER!!!", &[]);
        // Pad archive to 512-byte boundary
        while out.len() % 512 != 0 {
            out.push(0);
        }
        Ok(out)
    }
}

fn write_cpio_newc_entry(
    out: &mut Vec<u8>,
    ino: u32,
    mode: u32,
    nlink: u32,
    mtime: u32,
    name: &str,
    body: &[u8],
) {
    let name_bytes = name.as_bytes();
    let namesize = (name_bytes.len() + 1) as u32;
    let filesize = body.len() as u32;
    let header = format!(
        "070701{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}",
        ino,
        mode,
        0u32, // uid
        0u32, // gid
        nlink,
        mtime,
        filesize,
        0u32, // devmajor
        0u32, // devminor
        0u32, // rdevmajor
        0u32, // rdevminor
        namesize,
        0u32 // check
    );
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(name_bytes);
    out.push(0); // NUL terminator for name
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out.extend_from_slice(body);
    while out.len() % 4 != 0 {
        out.push(0);
    }
}

// ============================================================================
// 7. External Command Repackers (zstd, lz4, squashfs)
// ============================================================================

pub struct ExternalCommandRepacker {
    sig_name: &'static str,
    binary: &'static str,
    args: &'static [&'static str],
}

impl ExternalCommandRepacker {
    pub fn new_zstd() -> Self {
        Self {
            sig_name: "zstd",
            binary: "zstd",
            args: &["-19", "-q", "-c"],
        }
    }

    pub fn new_lz4() -> Self {
        Self {
            sig_name: "lz4",
            binary: "lz4",
            args: &["-9", "-q", "-c"],
        }
    }
}

impl RegionRepacker for ExternalCommandRepacker {
    fn signature_name(&self) -> &str {
        self.sig_name
    }

    fn is_available(&self) -> bool {
        command_exists_in_path(self.binary)
    }

    fn repack(&self, extracted_dir: &Path, _entry: &CarvedEntry) -> Result<Vec<u8>> {
        let payload = read_single_file_or_tar(extracted_dir)?;
        let mut child = Command::new(self.binary)
            .args(self.args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .with_context(|| format!("Failed to spawn '{}'", self.binary))?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(&payload)?;
        }
        let output = child.wait_with_output()?;
        if !output.status.success() {
            bail!(
                "'{}' failed: {}",
                self.binary,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(output.stdout)
    }
}

pub struct SquashfsRepacker;

impl RegionRepacker for SquashfsRepacker {
    fn signature_name(&self) -> &str {
        "squashfs"
    }

    fn is_available(&self) -> bool {
        command_exists_in_path("mksquashfs")
    }

    fn repack(&self, extracted_dir: &Path, _entry: &CarvedEntry) -> Result<Vec<u8>> {
        let tmp = tempfile::NamedTempFile::new()?;
        let out_path = tmp.path().to_path_buf();
        let _ = fs::remove_file(&out_path);

        let output = Command::new("mksquashfs")
            .arg(extracted_dir)
            .arg(&out_path)
            .arg("-noappend")
            .arg("-quiet")
            .output()
            .context("Failed to execute mksquashfs")?;

        if !output.status.success() {
            bail!(
                "mksquashfs failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let bytes = fs::read(&out_path)?;
        let _ = fs::remove_file(&out_path);
        Ok(bytes)
    }
}

// ============================================================================
// 8. Delta-Aware Pure-Rust ZIP Repacker & Nested Slice CRC32 Synchronizer
// ============================================================================

const ZIP_LFH_SIG: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];
const ZIP_CDH_SIG: [u8; 4] = [0x50, 0x4b, 0x01, 0x02];
const ZIP_EOCD_SIG: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];

#[derive(Debug, Clone)]
struct ParsedZipEntry {
    name: String,
    version_made_by: u16,
    version_needed: u16,
    flags: u16,
    method: u16,
    mod_time: u16,
    mod_date: u16,
    crc32: u32,
    comp_size: u32,
    uncomp_size: u32,
    internal_attr: u16,
    external_attr: u32,
    lfh_extra: Vec<u8>,
    cdh_extra: Vec<u8>,
    comment: Vec<u8>,
    compressed_data: Vec<u8>,
}

/// Parses an existing ZIP slice to extract original entry metadata and raw compressed streams
/// for delta-aware repacking.
fn parse_existing_zip(zip_bytes: &[u8]) -> Option<Vec<ParsedZipEntry>> {
    // Locate EOCD near the end of zip_bytes
    let search_start = zip_bytes.len().saturating_sub(65558);
    let mut eocd_pos = None;
    for i in (search_start..=zip_bytes.len().saturating_sub(22)).rev() {
        if zip_bytes[i..i + 4] == ZIP_EOCD_SIG {
            eocd_pos = Some(i);
            break;
        }
    }
    let eocd_offset = eocd_pos?;
    let total_entries =
        u16::from_le_bytes(zip_bytes[eocd_offset + 10..eocd_offset + 12].try_into().ok()?)
            as usize;
    let cd_size =
        u32::from_le_bytes(zip_bytes[eocd_offset + 12..eocd_offset + 16].try_into().ok()?)
            as usize;
    let cd_offset_raw =
        u32::from_le_bytes(zip_bytes[eocd_offset + 16..eocd_offset + 20].try_into().ok()?)
            as usize;

    // Note: If the ZIP was carved starting at the first LFH (`0x00097FAA` in omni.ja),
    // `cd_offset_raw` in EOCD might be relative to the start of the whole binary rather than
    // `zip_bytes[0]`, OR `eocd_offset - cd_size` gives the exact start of the Central Directory!
    let cd_start = if cd_offset_raw + cd_size <= eocd_offset
        && zip_bytes.get(cd_offset_raw..cd_offset_raw + 4) == Some(&ZIP_CDH_SIG)
    {
        cd_offset_raw
    } else if eocd_offset >= cd_size
        && zip_bytes.get(eocd_offset - cd_size..eocd_offset - cd_size + 4) == Some(&ZIP_CDH_SIG)
    {
        eocd_offset - cd_size
    } else {
        return None;
    };

    // Index all Local File Headers in `zip_bytes` by their offset and by filename
    // so we can match CDHs even if `lfh_offset` had a prefix bias.
    let mut lfh_by_offset: HashMap<usize, (u16, Vec<u8>, usize)> = HashMap::new();
    let mut lfh_by_name: HashMap<String, Vec<(usize, u16, Vec<u8>, usize)>> = HashMap::new();

    let mut scan_pos = 0usize;
    while scan_pos + 30 <= cd_start {
        if zip_bytes[scan_pos..scan_pos + 4] == ZIP_LFH_SIG {
            let flags = u16::from_le_bytes(zip_bytes[scan_pos + 6..scan_pos + 8].try_into().ok()?);
            let name_len =
                u16::from_le_bytes(zip_bytes[scan_pos + 26..scan_pos + 28].try_into().ok()?)
                    as usize;
            let extra_len =
                u16::from_le_bytes(zip_bytes[scan_pos + 28..scan_pos + 30].try_into().ok()?)
                    as usize;
            let data_start = scan_pos + 30 + name_len + extra_len;
            if data_start <= zip_bytes.len() {
                let name =
                    String::from_utf8_lossy(&zip_bytes[scan_pos + 30..scan_pos + 30 + name_len])
                        .to_string();
                let lfh_extra =
                    zip_bytes[scan_pos + 30 + name_len..data_start].to_vec();
                lfh_by_offset.insert(scan_pos, (flags, lfh_extra.clone(), data_start));
                lfh_by_name
                    .entry(name)
                    .or_default()
                    .push((scan_pos, flags, lfh_extra, data_start));
            }
            scan_pos = data_start.max(scan_pos + 1);
        } else {
            scan_pos += 1;
        }
    }

    let mut entries = Vec::with_capacity(total_entries);
    let mut pos = cd_start;
    while pos + 46 <= eocd_offset && zip_bytes[pos..pos + 4] == ZIP_CDH_SIG {
        let version_made_by = u16::from_le_bytes(zip_bytes[pos + 4..pos + 6].try_into().ok()?);
        let version_needed = u16::from_le_bytes(zip_bytes[pos + 6..pos + 8].try_into().ok()?);
        let flags = u16::from_le_bytes(zip_bytes[pos + 8..pos + 10].try_into().ok()?);
        let method = u16::from_le_bytes(zip_bytes[pos + 10..pos + 12].try_into().ok()?);
        let mod_time = u16::from_le_bytes(zip_bytes[pos + 12..pos + 14].try_into().ok()?);
        let mod_date = u16::from_le_bytes(zip_bytes[pos + 14..pos + 16].try_into().ok()?);
        let crc32 = u32::from_le_bytes(zip_bytes[pos + 16..pos + 20].try_into().ok()?);
        let comp_size = u32::from_le_bytes(zip_bytes[pos + 20..pos + 24].try_into().ok()?);
        let uncomp_size = u32::from_le_bytes(zip_bytes[pos + 24..pos + 28].try_into().ok()?);
        let name_len =
            u16::from_le_bytes(zip_bytes[pos + 28..pos + 30].try_into().ok()?) as usize;
        let extra_len =
            u16::from_le_bytes(zip_bytes[pos + 30..pos + 32].try_into().ok()?) as usize;
        let comment_len =
            u16::from_le_bytes(zip_bytes[pos + 32..pos + 34].try_into().ok()?) as usize;
        let internal_attr = u16::from_le_bytes(zip_bytes[pos + 36..pos + 38].try_into().ok()?);
        let external_attr = u32::from_le_bytes(zip_bytes[pos + 38..pos + 42].try_into().ok()?);
        let lfh_offset_raw =
            u32::from_le_bytes(zip_bytes[pos + 42..pos + 46].try_into().ok()?) as usize;

        let cdh_end = pos + 46 + name_len + extra_len + comment_len;
        if cdh_end > eocd_offset {
            break;
        }
        let name = String::from_utf8_lossy(&zip_bytes[pos + 46..pos + 46 + name_len]).to_string();
        let cdh_extra = zip_bytes[pos + 46 + name_len..pos + 46 + name_len + extra_len].to_vec();
        let comment =
            zip_bytes[pos + 46 + name_len + extra_len..cdh_end].to_vec();

        // Find matching LFH
        let lfh_match = lfh_by_offset
            .get(&lfh_offset_raw)
            .cloned()
            .or_else(|| {
                lfh_by_name
                    .get(&name)
                    .and_then(|list| list.first())
                    .map(|(_, f, ex, ds)| (*f, ex.clone(), *ds))
            })?;

        let (_lfh_flags, lfh_extra, data_start) = lfh_match;
        let data_end = data_start.checked_add(comp_size as usize)?;
        if data_end > zip_bytes.len() {
            return None;
        }
        let compressed_data = zip_bytes[data_start..data_end].to_vec();

        entries.push(ParsedZipEntry {
            name,
            version_made_by,
            version_needed,
            flags: flags & !0x0008, // Clear data-descriptor flag on repack since sizes/CRCs are known
            method,
            mod_time,
            mod_date,
            crc32,
            comp_size,
            uncomp_size,
            internal_attr,
            external_attr,
            lfh_extra,
            cdh_extra,
            comment,
            compressed_data,
        });

        pos = cdh_end;
    }

    if entries.is_empty() {
        None
    } else {
        Some(entries)
    }
}

pub struct ZipRepacker;

impl RegionRepacker for ZipRepacker {
    fn signature_name(&self) -> &str {
        "zip"
    }

    fn repack(&self, extracted_dir: &Path, _entry: &CarvedEntry) -> Result<Vec<u8>> {
        repack_zip_directory(extracted_dir, None)
    }

    fn repack_with_store(
        &self,
        extracted_dir: &Path,
        entry: &CarvedEntry,
        store: &dyn BinaryStore,
    ) -> Result<Vec<u8>> {
        let orig_slice = store.read_slice(entry.span).ok();
        repack_zip_directory(extracted_dir, orig_slice.as_deref())
    }
}

fn encode_zip_payload(raw_bytes: &[u8], method: u16) -> Result<(u16, u32, Vec<u8>)> {
    let crc = crc32fast::hash(raw_bytes);
    if method == 0 || raw_bytes.is_empty() {
        Ok((0, crc, raw_bytes.to_vec()))
    } else {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(raw_bytes)?;
        let compressed = encoder.finish()?;
        Ok((8, crc, compressed))
    }
}

fn repack_zip_directory(extracted_dir: &Path, orig_zip_bytes: Option<&[u8]>) -> Result<Vec<u8>> {
    let fs_items = collect_extracted_entries(extracted_dir)?;
    let mut fs_files: BTreeMap<String, PathBuf> = BTreeMap::new();
    for (rel_str, full_path) in fs_items {
        let md = fs::symlink_metadata(&full_path)?;
        if md.is_file() {
            fs_files.insert(rel_str, full_path);
        }
    }

    let mut final_entries: Vec<ParsedZipEntry> = Vec::new();
    let mut handled_names: HashSet<String> = HashSet::new();

    if let Some(orig_bytes) = orig_zip_bytes {
        if let Some(orig_entries) = parse_existing_zip(orig_bytes) {
            for mut orig in orig_entries {
                // Keep explicit directory entries if directory still exists
                if orig.name.ends_with('/') {
                    let dir_rel = orig.name.trim_end_matches('/');
                    if extracted_dir.join(dir_rel).is_dir() {
                        final_entries.push(orig);
                    }
                    continue;
                }

                if let Some(host_path) = fs_files.get(&orig.name) {
                    handled_names.insert(orig.name.clone());
                    let raw_bytes = fs::read(host_path)?;
                    let new_crc = crc32fast::hash(&raw_bytes);
                    let new_uncomp_len = raw_bytes.len() as u32;

                    if new_crc == orig.crc32 && new_uncomp_len == orig.uncomp_size {
                        // Unmodified file! Preserve exact compressed stream and metadata
                        final_entries.push(orig);
                    } else {
                        // Modified file! Re-encode using original method (STORE or DEFLATE)
                        let target_method = if orig.method == 0 { 0 } else { 8 };
                        let (method, crc32, comp_data) =
                            encode_zip_payload(&raw_bytes, target_method)?;
                        orig.method = method;
                        orig.crc32 = crc32;
                        orig.comp_size = comp_data.len() as u32;
                        orig.uncomp_size = new_uncomp_len;
                        orig.compressed_data = comp_data;
                        final_entries.push(orig);
                    }
                }
                // If not in `fs_files`, the file was deleted in `/extracted/`, so omit it.
            }
        }
    }

    // Append any newly created files in `extracted_dir`
    for (rel_name, host_path) in &fs_files {
        if handled_names.contains(rel_name) {
            continue;
        }
        let raw_bytes = fs::read(host_path)?;
        let (method, crc32, comp_data) = encode_zip_payload(&raw_bytes, 8)?;
        let mode = fs::symlink_metadata(host_path)
            .map(|m| m.permissions().mode())
            .unwrap_or(0o100644);
        final_entries.push(ParsedZipEntry {
            name: rel_name.clone(),
            version_made_by: 0x0314, // Unix, ZIP 2.0
            version_needed: 20,
            flags: 0,
            method,
            mod_time: 0,
            mod_date: 0x21,
            crc32,
            comp_size: comp_data.len() as u32,
            uncomp_size: raw_bytes.len() as u32,
            internal_attr: 0,
            external_attr: mode << 16,
            lfh_extra: Vec::new(),
            cdh_extra: Vec::new(),
            comment: Vec::new(),
            compressed_data: comp_data,
        });
    }

    serialize_zip_entries(&final_entries)
}

fn serialize_zip_entries(entries: &[ParsedZipEntry]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut lfh_offsets = Vec::with_capacity(entries.len());

    // 1. Write Local File Headers + Compressed Payloads
    for entry in entries {
        lfh_offsets.push(out.len() as u32);
        let name_bytes = entry.name.as_bytes();
        out.extend_from_slice(&ZIP_LFH_SIG);
        out.extend_from_slice(&entry.version_needed.to_le_bytes());
        out.extend_from_slice(&entry.flags.to_le_bytes());
        out.extend_from_slice(&entry.method.to_le_bytes());
        out.extend_from_slice(&entry.mod_time.to_le_bytes());
        out.extend_from_slice(&entry.mod_date.to_le_bytes());
        out.extend_from_slice(&entry.crc32.to_le_bytes());
        out.extend_from_slice(&entry.comp_size.to_le_bytes());
        out.extend_from_slice(&entry.uncomp_size.to_le_bytes());
        out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(&(entry.lfh_extra.len() as u16).to_le_bytes());
        out.extend_from_slice(name_bytes);
        out.extend_from_slice(&entry.lfh_extra);
        out.extend_from_slice(&entry.compressed_data);
    }

    // 2. Write Central Directory Headers
    let cd_start = out.len() as u32;
    for (idx, entry) in entries.iter().enumerate() {
        let name_bytes = entry.name.as_bytes();
        out.extend_from_slice(&ZIP_CDH_SIG);
        out.extend_from_slice(&entry.version_made_by.to_le_bytes());
        out.extend_from_slice(&entry.version_needed.to_le_bytes());
        out.extend_from_slice(&entry.flags.to_le_bytes());
        out.extend_from_slice(&entry.method.to_le_bytes());
        out.extend_from_slice(&entry.mod_time.to_le_bytes());
        out.extend_from_slice(&entry.mod_date.to_le_bytes());
        out.extend_from_slice(&entry.crc32.to_le_bytes());
        out.extend_from_slice(&entry.comp_size.to_le_bytes());
        out.extend_from_slice(&entry.uncomp_size.to_le_bytes());
        out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(&(entry.cdh_extra.len() as u16).to_le_bytes());
        out.extend_from_slice(&(entry.comment.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // disk number start
        out.extend_from_slice(&entry.internal_attr.to_le_bytes());
        out.extend_from_slice(&entry.external_attr.to_le_bytes());
        out.extend_from_slice(&lfh_offsets[idx].to_le_bytes());
        out.extend_from_slice(name_bytes);
        out.extend_from_slice(&entry.cdh_extra);
        out.extend_from_slice(&entry.comment);
    }
    let cd_size = (out.len() as u32) - cd_start;

    // 3. Write End of Central Directory (EOCD)
    let count_u16 = entries.len().min(u16::MAX as usize) as u16;
    out.extend_from_slice(&ZIP_EOCD_SIG);
    out.extend_from_slice(&0u16.to_le_bytes()); // disk number
    out.extend_from_slice(&0u16.to_le_bytes()); // disk with CD
    out.extend_from_slice(&count_u16.to_le_bytes());
    out.extend_from_slice(&count_u16.to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_start.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment length

    Ok(out)
}

/// Inspects the binary in `store` to see if `modified_span` lies inside an uncompressed (`STORE`,
/// method 0) entry of any ZIP archive (including standard ZIPs and Firefox `omni.ja`).
/// If so, recomputes the CRC32 of the enclosing ZIP member and updates both its Local File Header
/// (`PK\x03\x04`) and Central Directory Header (`PK\x01\x02`) in `store`.
pub fn sync_parent_zip_crc32_for_span(
    modified_span: ByteSpan,
    entries: &[CarvedEntry],
    store: &dyn BinaryStore,
) -> Result<usize> {
    // Only scan if there is a `zip` entry in the image or if the binary contains ZIP structures
    let zip_spans: Vec<ByteSpan> = entries
        .iter()
        .filter(|e| e.signature_result.name == "zip")
        .map(|e| {
            // Note: In optimized JARs like Firefox's omni.ja, LFH entries can start before the
            // first standard LFH matched by Binwalk, so include `[0 .. e.span.end]`.
            ByteSpan {
                start: 0,
                end: e.span.end,
            }
        })
        .collect();

    if zip_spans.is_empty() {
        return Ok(0);
    }

    let mut updated_count = 0;

    for zip_span in zip_spans {
        if !zip_span.contains_range(modified_span.start, modified_span.end) {
            continue;
        }

        let image = store.read_slice(zip_span)?;
        let rel_mod_start = modified_span.start - zip_span.start;
        let rel_mod_end = modified_span.end - zip_span.start;

        // Search backwards from `rel_mod_start` (up to 64KB + member size or from 0) for an enclosing LFH `PK\x03\x04`
        // To be fast on 55MB images, scan forward for `PK\x03\x04` up to `rel_mod_start`.
        let mut matched_lfh: Option<(usize, Vec<u8>, u32, u32)> = None;
        let mut pos = 0usize;
        while pos + 30 <= rel_mod_start {
            if image[pos..pos + 4] == ZIP_LFH_SIG {
                let method = u16::from_le_bytes([image[pos + 8], image[pos + 9]]);
                let old_crc = u32::from_le_bytes([
                    image[pos + 14],
                    image[pos + 15],
                    image[pos + 16],
                    image[pos + 17],
                ]);
                let comp_size = u32::from_le_bytes([
                    image[pos + 18],
                    image[pos + 19],
                    image[pos + 20],
                    image[pos + 21],
                ]) as usize;
                let name_len = u16::from_le_bytes([image[pos + 26], image[pos + 27]]) as usize;
                let extra_len = u16::from_le_bytes([image[pos + 28], image[pos + 29]]) as usize;
                let data_start = pos + 30 + name_len + extra_len;
                let data_end = data_start.saturating_add(comp_size);

                if method == 0
                    && comp_size > 0
                    && data_end <= image.len()
                    && rel_mod_start >= data_start
                    && rel_mod_end <= data_end
                {
                    let name_bytes = image[pos + 30..pos + 30 + name_len].to_vec();
                    let new_crc = crc32fast::hash(&image[data_start..data_end]);
                    matched_lfh = Some((pos, name_bytes, old_crc, new_crc));
                    break;
                }

                if comp_size > 0 && data_end > pos {
                    pos = data_end;
                    continue;
                }
            }
            pos += 1;
        }

        let Some((lfh_pos, name_bytes, _old_crc, new_crc)) = matched_lfh else {
            continue;
        };

        // 1. Patch Local File Header CRC32 at `lfh_pos + 14..lfh_pos + 18`
        let lfh_crc_abs = zip_span.start + lfh_pos + 14;
        if let Some(crc_span) = ByteSpan::from_offset_size(lfh_crc_abs, 4) {
            store.write_in_span(crc_span, 0, &new_crc.to_le_bytes())?;
            updated_count += 1;
        }

        // 2. Locate matching Central Directory Header `PK\x01\x02` and patch its CRC32 at `+16..+20`
        let mut cd_pos = lfh_pos + 30;
        while cd_pos + 46 + name_bytes.len() <= image.len() {
            if image[cd_pos..cd_pos + 4] == ZIP_CDH_SIG {
                let cd_name_len =
                    u16::from_le_bytes([image[cd_pos + 28], image[cd_pos + 29]]) as usize;
                let cd_extra_len =
                    u16::from_le_bytes([image[cd_pos + 30], image[cd_pos + 31]]) as usize;
                let cd_comment_len =
                    u16::from_le_bytes([image[cd_pos + 32], image[cd_pos + 33]]) as usize;

                if cd_name_len == name_bytes.len()
                    && cd_pos + 46 + cd_name_len <= image.len()
                    && &image[cd_pos + 46..cd_pos + 46 + cd_name_len] == name_bytes.as_slice()
                {
                    let cdh_crc_abs = zip_span.start + cd_pos + 16;
                    if let Some(crc_span) = ByteSpan::from_offset_size(cdh_crc_abs, 4) {
                        store.write_in_span(crc_span, 0, &new_crc.to_le_bytes())?;
                    }
                    break;
                }

                let step = 46 + cd_name_len + cd_extra_len + cd_comment_len;
                cd_pos += step.max(1);
            } else {
                cd_pos += 1;
            }
        }
    }

    Ok(updated_count)
}
