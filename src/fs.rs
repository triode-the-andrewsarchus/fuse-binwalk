use crate::extractor::ExtractionManager;
use crate::scanner::{build_manifest, CarvedEntry};
use crate::storage::{smart_pad_byte, BinaryStore, WritePolicy};
use filetime::FileTime;
use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, Request, TimeOrNow, FUSE_ROOT_ID,
};
use std::collections::{BTreeMap, HashMap};
use std::ffi::OsStr;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const ROOT_INO: u64 = FUSE_ROOT_ID; // 1
pub const RAW_DIR_INO: u64 = 2;
pub const EXTRACTED_DIR_INO: u64 = 3;
pub const MANIFEST_INO: u64 = 4;
const FIRST_DYNAMIC_INO: u64 = 100;

const TTL: Duration = Duration::from_secs(1);
const BLOCK_SIZE: u32 = 512;

#[derive(Debug, Clone)]
pub enum InodeKind {
    /// `/`
    RootDir,
    /// `/raw`
    RawDir,
    /// `/extracted`
    ExtractedTopDir,
    /// `/manifest.json`
    ManifestFile,
    /// `/raw/<0xSTART_0xEND_name.ext>`
    RawSlice { entry_idx: usize },
    /// Ephemeral scratch file inside `/raw/` (supports atomic-save editors like `vim`, `sed -i`, GUI apps)
    RawScratchFile { data: Vec<u8>, perm: u16 },
    /// `/extracted/<0xSTART_0xEND_name>` (triggers lazy extraction when accessed)
    ExtractedEntryRoot { entry_idx: usize },
    /// Any file, directory, or symlink inside `/extracted/<0xSTART_0xEND_name>/...`
    ExtractedHostNode {
        entry_idx: usize,
        host_path: PathBuf,
    },
}

#[derive(Debug, Clone)]
pub struct InodeNode {
    pub ino: u64,
    pub parent: u64,
    pub name: String,
    pub kind: InodeKind,
    /// Maps child filename -> child inode number for directory nodes.
    pub children: BTreeMap<String, u64>,
    /// Whether a directory backing a host path has been indexed into `children`.
    pub children_loaded: bool,
}

#[derive(Debug, Clone)]
pub struct DirListingEntry {
    pub ino: u64,
    pub name: String,
    pub file_type: FileType,
}

pub struct BinwalkFs {
    store: Arc<dyn BinaryStore>,
    entries: Vec<CarvedEntry>,
    manifest_bytes: Vec<u8>,
    extractor: ExtractionManager,
    inodes: HashMap<u64, InodeNode>,
    host_path_to_ino: HashMap<PathBuf, u64>,
    /// Staging buffers for `/raw/<entry>` files that were truncated (`O_TRUNC` / `setattr(size)`)
    /// and are being rewritten prior to `flush`/`release`.
    raw_write_buffers: HashMap<usize, Vec<u8>>,
    /// When true, underflow replacements are rejected with `EINVAL` unless an explicit `pad_byte`
    /// is configured in `WritePolicy`. When false (default), smart signature padding is used.
    strict_size: bool,
    next_ino: u64,
    mount_time: SystemTime,
    uid: u32,
    gid: u32,
}

impl BinwalkFs {
    pub fn new(store: Arc<dyn BinaryStore>, entries: Vec<CarvedEntry>) -> anyhow::Result<Self> {
        let manifest_doc = build_manifest(store.total_len(), &entries);
        let mut manifest_bytes = serde_json::to_vec_pretty(&manifest_doc)?;
        manifest_bytes.push(b'\n');

        let extractor = ExtractionManager::new()?;
        let mount_time = SystemTime::now();
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };

        let mut fs = Self {
            store,
            entries,
            manifest_bytes,
            extractor,
            inodes: HashMap::new(),
            host_path_to_ino: HashMap::new(),
            raw_write_buffers: HashMap::new(),
            strict_size: false,
            next_ino: FIRST_DYNAMIC_INO,
            mount_time,
            uid,
            gid,
        };

        fs.init_static_tree();
        Ok(fs)
    }

    pub fn with_strict_size(mut self, strict_size: bool) -> Self {
        self.strict_size = strict_size;
        self
    }

    pub fn store(&self) -> &Arc<dyn BinaryStore> {
        &self.store
    }

    pub fn entries(&self) -> &[CarvedEntry] {
        &self.entries
    }

    pub fn extractor_manager(&self) -> &ExtractionManager {
        &self.extractor
    }

    fn alloc_ino(&mut self) -> u64 {
        let ino = self.next_ino;
        self.next_ino += 1;
        ino
    }

    fn init_static_tree(&mut self) {
        let mut root_children = BTreeMap::new();
        root_children.insert("raw".to_string(), RAW_DIR_INO);
        root_children.insert("extracted".to_string(), EXTRACTED_DIR_INO);
        root_children.insert("manifest.json".to_string(), MANIFEST_INO);

        self.inodes.insert(
            ROOT_INO,
            InodeNode {
                ino: ROOT_INO,
                parent: ROOT_INO,
                name: String::new(),
                kind: InodeKind::RootDir,
                children: root_children,
                children_loaded: true,
            },
        );

        self.inodes.insert(
            MANIFEST_INO,
            InodeNode {
                ino: MANIFEST_INO,
                parent: ROOT_INO,
                name: "manifest.json".to_string(),
                kind: InodeKind::ManifestFile,
                children: BTreeMap::new(),
                children_loaded: true,
            },
        );

        let mut raw_children = BTreeMap::new();
        let mut extracted_children = BTreeMap::new();

        for idx in 0..self.entries.len() {
            let raw_name = self.entries[idx].raw_filename.clone();
            let extracted_name = self.entries[idx].extracted_dirname.clone();
            let has_extractor = self.entries[idx].has_extractor();

            let raw_ino = self.alloc_ino();
            self.inodes.insert(
                raw_ino,
                InodeNode {
                    ino: raw_ino,
                    parent: RAW_DIR_INO,
                    name: raw_name.clone(),
                    kind: InodeKind::RawSlice { entry_idx: idx },
                    children: BTreeMap::new(),
                    children_loaded: true,
                },
            );
            raw_children.insert(raw_name, raw_ino);

            if has_extractor {
                let ext_ino = self.alloc_ino();
                self.inodes.insert(
                    ext_ino,
                    InodeNode {
                        ino: ext_ino,
                        parent: EXTRACTED_DIR_INO,
                        name: extracted_name.clone(),
                        kind: InodeKind::ExtractedEntryRoot { entry_idx: idx },
                        children: BTreeMap::new(),
                        children_loaded: false,
                    },
                );
                extracted_children.insert(extracted_name, ext_ino);
            }
        }

        self.inodes.insert(
            RAW_DIR_INO,
            InodeNode {
                ino: RAW_DIR_INO,
                parent: ROOT_INO,
                name: "raw".to_string(),
                kind: InodeKind::RawDir,
                children: raw_children,
                children_loaded: true,
            },
        );

        self.inodes.insert(
            EXTRACTED_DIR_INO,
            InodeNode {
                ino: EXTRACTED_DIR_INO,
                parent: ROOT_INO,
                name: "extracted".to_string(),
                kind: InodeKind::ExtractedTopDir,
                children: extracted_children,
                children_loaded: true,
            },
        );
    }

    pub fn is_writable(&self) -> bool {
        !matches!(self.store.write_policy(), WritePolicy::ReadOnly)
    }

    /// Returns true if `/extracted/<entry>/` is writable (filesystem is mounted writable AND
    /// a `RegionRepacker` is available for this entry's signature).
    pub fn is_extracted_entry_writable(&self, entry_idx: usize) -> bool {
        self.is_writable()
            && self
                .extractor
                .repackers()
                .can_repack(&self.entries[entry_idx].signature_result.name)
    }

    fn default_dir_perm(&self, writable: bool) -> u16 {
        if writable {
            0o755
        } else {
            0o555
        }
    }

    fn default_file_perm(&self, writable: bool) -> u16 {
        if writable {
            0o644
        } else {
            0o444
        }
    }

    /// Resolves a directory inode inside `/extracted/` to `(entry_idx, host_dir_path)`.
    fn resolve_extracted_dir(&mut self, dir_ino: u64) -> Result<(usize, PathBuf), libc::c_int> {
        self.ensure_directory_populated(dir_ino)?;
        let Some(node) = self.inodes.get(&dir_ino) else {
            return Err(libc::ENOENT);
        };
        match &node.kind {
            InodeKind::ExtractedEntryRoot { entry_idx } => {
                let entry = self.entries[*entry_idx].clone();
                let rec = self
                    .extractor
                    .ensure_extracted(&entry, &*self.store)
                    .map_err(|_| libc::EIO)?;
                Ok((*entry_idx, rec.output_dir))
            }
            InodeKind::ExtractedHostNode {
                entry_idx,
                host_path,
            } => {
                let md = fs::symlink_metadata(host_path).map_err(|_| libc::ENOENT)?;
                if !md.is_dir() {
                    return Err(libc::ENOTDIR);
                }
                Ok((*entry_idx, host_path.clone()))
            }
            _ => Err(libc::EACCES),
        }
    }

    /// Ensures that if `dir_ino` is an `ExtractedEntryRoot` or an `ExtractedHostNode` directory,
    /// lazy extraction has completed and its direct children are registered in `self.inodes`.
    pub fn ensure_directory_populated(&mut self, dir_ino: u64) -> Result<(), libc::c_int> {
        let (kind, already_loaded) = {
            let Some(node) = self.inodes.get(&dir_ino) else {
                return Err(libc::ENOENT);
            };
            (node.kind.clone(), node.children_loaded)
        };

        let (entry_idx, host_dir) = match kind {
            InodeKind::ExtractedEntryRoot { entry_idx } => {
                let entry = self.entries[entry_idx].clone();
                let record = self
                    .extractor
                    .ensure_extracted(&entry, &*self.store)
                    .map_err(|_| libc::EIO)?;
                (entry_idx, record.output_dir)
            }
            InodeKind::ExtractedHostNode {
                entry_idx,
                host_path,
            } => {
                let md = fs::symlink_metadata(&host_path).map_err(|_| libc::ENOENT)?;
                if !md.is_dir() {
                    return Err(libc::ENOTDIR);
                }
                (entry_idx, host_path)
            }
            InodeKind::RootDir | InodeKind::RawDir | InodeKind::ExtractedTopDir => {
                return Ok(());
            }
            _ => return Err(libc::ENOTDIR),
        };

        if already_loaded {
            self.sync_host_directory_children(dir_ino, entry_idx, &host_dir)?;
            return Ok(());
        }

        self.sync_host_directory_children(dir_ino, entry_idx, &host_dir)?;
        if let Some(node) = self.inodes.get_mut(&dir_ino) {
            node.children_loaded = true;
        }
        Ok(())
    }

    fn sync_host_directory_children(
        &mut self,
        parent_ino: u64,
        entry_idx: usize,
        host_dir: &Path,
    ) -> Result<(), libc::c_int> {
        let read_dir = fs::read_dir(host_dir).map_err(|_| libc::EIO)?;
        let mut discovered: Vec<(String, PathBuf)> = Vec::new();
        for dir_entry in read_dir.flatten() {
            let name = dir_entry.file_name().to_string_lossy().to_string();
            let path = dir_entry.path();
            discovered.push((name, path));
        }

        let mut new_children_map = BTreeMap::new();
        for (name, path) in discovered {
            let child_ino = if let Some(&existing_ino) = self.host_path_to_ino.get(&path) {
                existing_ino
            } else {
                let new_ino = self.alloc_ino();
                self.host_path_to_ino.insert(path.clone(), new_ino);
                self.inodes.insert(
                    new_ino,
                    InodeNode {
                        ino: new_ino,
                        parent: parent_ino,
                        name: name.clone(),
                        kind: InodeKind::ExtractedHostNode {
                            entry_idx,
                            host_path: path,
                        },
                        children: BTreeMap::new(),
                        children_loaded: false,
                    },
                );
                new_ino
            };
            new_children_map.insert(name, child_ino);
        }

        if let Some(parent_node) = self.inodes.get_mut(&parent_ino) {
            parent_node.children = new_children_map;
        }

        Ok(())
    }

    /// Evicts cached child inodes for an extracted entry after its extraction cache is invalidated.
    fn clear_extracted_inodes_for_entry(&mut self, target_entry_idx: usize) {
        let mut to_remove_inos = Vec::new();
        let mut root_ino_opt = None;

        for (&ino, node) in &self.inodes {
            match &node.kind {
                InodeKind::ExtractedEntryRoot { entry_idx } if *entry_idx == target_entry_idx => {
                    root_ino_opt = Some(ino);
                }
                InodeKind::ExtractedHostNode { entry_idx, .. }
                    if *entry_idx == target_entry_idx =>
                {
                    to_remove_inos.push(ino);
                }
                _ => {}
            }
        }

        for ino in to_remove_inos {
            if let Some(removed) = self.inodes.remove(&ino) {
                if let InodeKind::ExtractedHostNode { host_path, .. } = removed.kind {
                    self.host_path_to_ino.remove(&host_path);
                }
            }
        }

        if let Some(root_ino) = root_ino_opt {
            if let Some(root_node) = self.inodes.get_mut(&root_ino) {
                root_node.children.clear();
                root_node.children_loaded = false;
            }
        }
    }

    /// Post-write hook whenever a `/raw/<entry>` byte span is modified:
    /// 1. Invalidates any cached `/extracted/` directories whose span overlaps `entry.span`.
    /// 2. Updates parent ZIP Local/Central Directory CRC32 headers if `entry.span` lies inside
    ///    an uncompressed (`STORE`) ZIP archive entry.
    fn on_raw_span_modified(&mut self, entry_idx: usize) {
        let span = self.entries[entry_idx].span;
        let invalidated = self
            .extractor
            .invalidate_overlapping(span, &self.entries, None);
        for inv_idx in invalidated {
            self.clear_extracted_inodes_for_entry(inv_idx);
        }
        let _ = crate::repackers::sync_parent_zip_crc32_for_span(
            span,
            &self.entries,
            &*self.store,
        );
    }

    /// Replaces the entire span of a `/raw/<entry>` slice, applying smart padding (unless `strict_size`
    /// is enabled) and running post-write synchronization hooks.
    fn apply_raw_slice_replacement(
        &mut self,
        entry_idx: usize,
        new_bytes: &[u8],
    ) -> Result<(), libc::c_int> {
        let span = self.entries[entry_idx].span;
        let sig_name = &self.entries[entry_idx].signature_result.name;
        let fallback_pad = if self.strict_size {
            None
        } else {
            Some(smart_pad_byte(sig_name))
        };
        self.store
            .replace_span_with_fallback_pad(span, new_bytes, fallback_pad)
            .map_err(|e| e.to_errno())?;
        self.on_raw_span_modified(entry_idx);
        Ok(())
    }

    /// Flushes any staged truncated `/raw/<entry>` buffer into `self.store`.
    pub fn flush_raw_entry(&mut self, entry_idx: usize) -> Result<(), libc::c_int> {
        if let Some(staged) = self.raw_write_buffers.remove(&entry_idx) {
            if let Err(errno) = self.apply_raw_slice_replacement(entry_idx, &staged) {
                // Restore buffer on error so state isn't lost if caller inspects it
                self.raw_write_buffers.insert(entry_idx, staged);
                return Err(errno);
            }
        }
        Ok(())
    }

    /// Repacks a modified `/extracted/<entry>/` directory into its parent span in `self.store`
    /// and invalidates any other overlapping cached extractions.
    pub fn repack_and_sync_extracted(&mut self, entry_idx: usize) -> Result<(), libc::c_int> {
        let entry = self.entries[entry_idx].clone();
        if !self.is_extracted_entry_writable(entry_idx) {
            return Err(libc::EACCES);
        }
        self.extractor
            .repack_entry_with_padding(&entry, &*self.store, !self.strict_size)
            .map_err(|e| {
                if let Some(se) = e.downcast_ref::<crate::storage::StorageError>() {
                    se.to_errno()
                } else {
                    libc::EIO
                }
            })?;

        let invalidated =
            self.extractor
                .invalidate_overlapping(entry.span, &self.entries, Some(entry_idx));
        for inv_idx in invalidated {
            self.clear_extracted_inodes_for_entry(inv_idx);
        }
        Ok(())
    }

    pub fn compute_attr(&self, ino: u64) -> Result<FileAttr, libc::c_int> {
        let Some(node) = self.inodes.get(&ino) else {
            return Err(libc::ENOENT);
        };

        let writable = self.is_writable();

        match &node.kind {
            InodeKind::RootDir => Ok(self.make_attr(ino, FileType::Directory, 0, 0o555, 4)),
            InodeKind::RawDir => {
                let nlink = 2;
                Ok(self.make_attr(
                    ino,
                    FileType::Directory,
                    0,
                    self.default_dir_perm(writable),
                    nlink,
                ))
            }
            InodeKind::ExtractedTopDir => {
                let nlink = (2 + node.children.len()) as u32;
                Ok(self.make_attr(ino, FileType::Directory, 0, 0o555, nlink))
            }
            InodeKind::ManifestFile => Ok(self.make_attr(
                ino,
                FileType::RegularFile,
                self.manifest_bytes.len() as u64,
                0o444,
                1,
            )),
            InodeKind::RawSlice { entry_idx } => {
                let size = if let Some(buf) = self.raw_write_buffers.get(entry_idx) {
                    buf.len() as u64
                } else {
                    self.entries[*entry_idx].span.len() as u64
                };
                Ok(self.make_attr(
                    ino,
                    FileType::RegularFile,
                    size,
                    self.default_file_perm(writable),
                    1,
                ))
            }
            InodeKind::RawScratchFile { data, perm } => Ok(self.make_attr(
                ino,
                FileType::RegularFile,
                data.len() as u64,
                *perm,
                1,
            )),
            InodeKind::ExtractedEntryRoot { entry_idx } => {
                let entry_writable = self.is_extracted_entry_writable(*entry_idx);
                let nlink = 2 + node.children.len() as u32;
                Ok(self.make_attr(
                    ino,
                    FileType::Directory,
                    0,
                    self.default_dir_perm(entry_writable),
                    nlink,
                ))
            }
            InodeKind::ExtractedHostNode {
                entry_idx,
                host_path,
            } => {
                let entry_writable = self.is_extracted_entry_writable(*entry_idx);
                let md = fs::symlink_metadata(host_path).map_err(|_| libc::ENOENT)?;
                let ft = metadata_to_filetype(&md);
                let size = if ft == FileType::Directory { 0 } else { md.len() };
                let perm = match ft {
                    FileType::Directory => self.default_dir_perm(entry_writable),
                    FileType::Symlink => 0o777,
                    _ => {
                        let base = self.default_file_perm(entry_writable);
                        if md.mode() & 0o111 != 0 {
                            base | 0o111
                        } else {
                            base
                        }
                    }
                };
                let nlink = md.nlink().max(1) as u32;
                Ok(self.make_attr(ino, ft, size, perm, nlink))
            }
        }
    }

    fn make_attr(
        &self,
        ino: u64,
        kind: FileType,
        size: u64,
        perm: u16,
        nlink: u32,
    ) -> FileAttr {
        let blocks = size.div_ceil(u64::from(BLOCK_SIZE));
        FileAttr {
            ino,
            size,
            blocks,
            atime: self.mount_time,
            mtime: self.mount_time,
            ctime: self.mount_time,
            crtime: self.mount_time,
            kind,
            perm,
            nlink,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: BLOCK_SIZE,
            flags: 0,
        }
    }

    /// High-level lookup helper (also usable directly in integration tests).
    pub fn lookup_node(&mut self, parent: u64, name: &str) -> Result<FileAttr, libc::c_int> {
        self.ensure_directory_populated(parent)?;

        let child_ino = {
            let Some(parent_node) = self.inodes.get(&parent) else {
                return Err(libc::ENOENT);
            };
            if name == "." {
                parent
            } else if name == ".." {
                parent_node.parent
            } else {
                *parent_node.children.get(name).ok_or(libc::ENOENT)?
            }
        };

        self.compute_attr(child_ino)
    }

    /// High-level directory listing helper (also usable directly in integration tests).
    pub fn list_directory(&mut self, ino: u64) -> Result<Vec<DirListingEntry>, libc::c_int> {
        self.ensure_directory_populated(ino)?;

        let (parent_ino, children) = {
            let Some(node) = self.inodes.get(&ino) else {
                return Err(libc::ENOENT);
            };
            (node.parent, node.children.clone())
        };

        let mut list = Vec::with_capacity(2 + children.len());
        list.push(DirListingEntry {
            ino,
            name: ".".to_string(),
            file_type: FileType::Directory,
        });
        list.push(DirListingEntry {
            ino: parent_ino,
            name: "..".to_string(),
            file_type: FileType::Directory,
        });

        for (name, child_ino) in children {
            if let Ok(attr) = self.compute_attr(child_ino) {
                list.push(DirListingEntry {
                    ino: child_ino,
                    name,
                    file_type: attr.kind,
                });
            }
        }

        Ok(list)
    }

    /// High-level read helper (also usable directly in integration tests).
    pub fn read_node(&self, ino: u64, offset: u64, size: u32) -> Result<Vec<u8>, libc::c_int> {
        let Some(node) = self.inodes.get(&ino) else {
            return Err(libc::ENOENT);
        };

        match &node.kind {
            InodeKind::ManifestFile => {
                let start = (offset as usize).min(self.manifest_bytes.len());
                let end = start
                    .saturating_add(size as usize)
                    .min(self.manifest_bytes.len());
                Ok(self.manifest_bytes[start..end].to_vec())
            }
            InodeKind::RawSlice { entry_idx } => {
                if let Some(staged) = self.raw_write_buffers.get(entry_idx) {
                    let start = (offset as usize).min(staged.len());
                    let end = start.saturating_add(size as usize).min(staged.len());
                    return Ok(staged[start..end].to_vec());
                }
                let span = self.entries[*entry_idx].span;
                let off_usize = usize::try_from(offset).unwrap_or(usize::MAX);
                if off_usize >= span.len() || size == 0 {
                    return Ok(Vec::new());
                }
                let to_read = (span.len() - off_usize).min(size as usize);
                let mut buf = vec![0u8; to_read];
                let n = self
                    .store
                    .read_in_span(span, off_usize, &mut buf)
                    .map_err(|e| e.to_errno())?;
                buf.truncate(n);
                Ok(buf)
            }
            InodeKind::RawScratchFile { data, .. } => {
                let start = (offset as usize).min(data.len());
                let end = start.saturating_add(size as usize).min(data.len());
                Ok(data[start..end].to_vec())
            }
            InodeKind::ExtractedHostNode { host_path, .. } => {
                let mut file = fs::File::open(host_path).map_err(|_| libc::EIO)?;
                let file_len = file.metadata().map(|m| m.len()).unwrap_or(0);
                if offset >= file_len || size == 0 {
                    return Ok(Vec::new());
                }
                let to_read = ((file_len - offset) as usize).min(size as usize);
                file.seek(SeekFrom::Start(offset)).map_err(|_| libc::EIO)?;
                let mut buf = vec![0u8; to_read];
                let n = file.read(&mut buf).map_err(|_| libc::EIO)?;
                buf.truncate(n);
                Ok(buf)
            }
            _ => Err(libc::EISDIR),
        }
    }

    /// High-level truncate / size change helper (usable in FUSE `setattr` / `open(O_TRUNC)` and tests).
    pub fn truncate_node(&mut self, ino: u64, new_size: u64) -> Result<FileAttr, libc::c_int> {
        if !self.is_writable() {
            return Err(libc::EROFS);
        }
        let Some(node) = self.inodes.get(&ino) else {
            return Err(libc::ENOENT);
        };

        match node.kind.clone() {
            InodeKind::RawSlice { entry_idx } => {
                let span = self.entries[entry_idx].span;
                let new_len = usize::try_from(new_size).map_err(|_| libc::ENOSPC)?;
                if new_len > span.len() {
                    return Err(libc::ENOSPC);
                }
                let mut current = if let Some(staged) = self.raw_write_buffers.remove(&entry_idx) {
                    staged
                } else {
                    self.store
                        .read_slice(span)
                        .map_err(|e| e.to_errno())?
                };
                current.resize(new_len, 0);
                self.raw_write_buffers.insert(entry_idx, current);
            }
            InodeKind::RawScratchFile { .. } => {
                let new_len = usize::try_from(new_size).map_err(|_| libc::ENOSPC)?;
                if let Some(node_mut) = self.inodes.get_mut(&ino) {
                    if let InodeKind::RawScratchFile { data, .. } = &mut node_mut.kind {
                        data.resize(new_len, 0);
                    }
                }
            }
            InodeKind::ExtractedHostNode {
                entry_idx,
                host_path,
            } => {
                if !self.is_extracted_entry_writable(entry_idx) {
                    return Err(libc::EACCES);
                }
                let file = fs::OpenOptions::new()
                    .write(true)
                    .open(&host_path)
                    .map_err(|_| libc::EIO)?;
                file.set_len(new_size).map_err(|_| libc::EIO)?;
                self.extractor.mark_dirty(entry_idx);
            }
            _ => return Err(libc::EACCES),
        }

        self.compute_attr(ino)
    }

    /// High-level write helper supporting `InPlaceBounded`, `CopyOnWriteOverlay`, staged `/raw/`
    /// replacement buffers, scratch files, and extracted file modifications.
    pub fn write_node(&mut self, ino: u64, offset: u64, data: &[u8]) -> Result<usize, libc::c_int> {
        if !self.is_writable() {
            return Err(libc::EROFS);
        }

        let Some(node) = self.inodes.get(&ino) else {
            return Err(libc::ENOENT);
        };

        match node.kind.clone() {
            InodeKind::RawSlice { entry_idx } => {
                let span = self.entries[entry_idx].span;
                let off_usize = usize::try_from(offset).map_err(|_| libc::EINVAL)?;
                let end_usize = off_usize.checked_add(data.len()).ok_or(libc::ENOSPC)?;
                if end_usize > span.len() {
                    return Err(libc::ENOSPC);
                }

                if let Some(staged) = self.raw_write_buffers.get_mut(&entry_idx) {
                    if staged.len() < end_usize {
                        staged.resize(end_usize, 0);
                    }
                    staged[off_usize..end_usize].copy_from_slice(data);
                    Ok(data.len())
                } else {
                    let written = self
                        .store
                        .write_in_span(span, off_usize, data)
                        .map_err(|e| e.to_errno())?;
                    self.on_raw_span_modified(entry_idx);
                    Ok(written)
                }
            }
            InodeKind::RawScratchFile { .. } => {
                let off_usize = usize::try_from(offset).map_err(|_| libc::EINVAL)?;
                let end_usize = off_usize.checked_add(data.len()).ok_or(libc::ENOSPC)?;
                if let Some(node_mut) = self.inodes.get_mut(&ino) {
                    if let InodeKind::RawScratchFile {
                        data: scratch_buf, ..
                    } = &mut node_mut.kind
                    {
                        if scratch_buf.len() < end_usize {
                            scratch_buf.resize(end_usize, 0);
                        }
                        scratch_buf[off_usize..end_usize].copy_from_slice(data);
                    }
                }
                Ok(data.len())
            }
            InodeKind::ExtractedHostNode {
                entry_idx,
                host_path,
            } => {
                if !self.is_extracted_entry_writable(entry_idx) {
                    return Err(libc::EACCES);
                }
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .open(&host_path)
                    .map_err(|_| libc::EIO)?;
                file.seek(SeekFrom::Start(offset)).map_err(|_| libc::EIO)?;
                file.write_all(data).map_err(|_| libc::EIO)?;
                file.flush().map_err(|_| libc::EIO)?;
                self.extractor.mark_dirty(entry_idx);
                Ok(data.len())
            }
            InodeKind::ManifestFile => Err(libc::EACCES),
            _ => Err(libc::EISDIR),
        }
    }

    /// High-level file creation helper (supports `/extracted/` files and `/raw/` scratch files).
    pub fn create_node(
        &mut self,
        parent: u64,
        name: &str,
        mode: u32,
        flags: i32,
    ) -> Result<FileAttr, libc::c_int> {
        if !self.is_writable() {
            return Err(libc::EROFS);
        }
        if name.is_empty() || name == "." || name == ".." || name.contains('/') {
            return Err(libc::EINVAL);
        }

        if parent == RAW_DIR_INO {
            let existing_ino = self
                .inodes
                .get(&RAW_DIR_INO)
                .and_then(|n| n.children.get(name).copied());

            if let Some(ino) = existing_ino {
                if (flags & libc::O_EXCL) != 0 {
                    return Err(libc::EEXIST);
                }
                return self.truncate_node(ino, 0);
            }

            let perm = ((mode as u16) & 0o777).max(0o644);
            let new_ino = self.alloc_ino();
            self.inodes.insert(
                new_ino,
                InodeNode {
                    ino: new_ino,
                    parent: RAW_DIR_INO,
                    name: name.to_string(),
                    kind: InodeKind::RawScratchFile {
                        data: Vec::new(),
                        perm,
                    },
                    children: BTreeMap::new(),
                    children_loaded: true,
                },
            );
            if let Some(raw_dir) = self.inodes.get_mut(&RAW_DIR_INO) {
                raw_dir.children.insert(name.to_string(), new_ino);
            }
            return self.compute_attr(new_ino);
        }

        let (entry_idx, host_dir) = self.resolve_extracted_dir(parent)?;
        if !self.is_extracted_entry_writable(entry_idx) {
            return Err(libc::EACCES);
        }

        let child_path = host_dir.join(name);
        if (flags & libc::O_EXCL) != 0 && child_path.exists() {
            return Err(libc::EEXIST);
        }

        let file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&child_path)
            .map_err(|_| libc::EIO)?;
        let perm_bits = (mode & 0o7777).max(0o644);
        let _ = file.set_permissions(fs::Permissions::from_mode(perm_bits));
        drop(file);

        self.sync_host_directory_children(parent, entry_idx, &host_dir)?;
        self.extractor.mark_dirty(entry_idx);

        let child_ino = self
            .inodes
            .get(&parent)
            .and_then(|n| n.children.get(name).copied())
            .ok_or(libc::EIO)?;
        self.compute_attr(child_ino)
    }

    /// High-level directory creation helper inside `/extracted/`.
    pub fn mkdir_node(
        &mut self,
        parent: u64,
        name: &str,
        mode: u32,
    ) -> Result<FileAttr, libc::c_int> {
        if !self.is_writable() {
            return Err(libc::EROFS);
        }
        if name.is_empty() || name == "." || name == ".." || name.contains('/') {
            return Err(libc::EINVAL);
        }

        let (entry_idx, host_dir) = self.resolve_extracted_dir(parent)?;
        if !self.is_extracted_entry_writable(entry_idx) {
            return Err(libc::EACCES);
        }

        let child_path = host_dir.join(name);
        if child_path.exists() {
            return Err(libc::EEXIST);
        }
        fs::create_dir(&child_path).map_err(|_| libc::EIO)?;
        let perm_bits = (mode & 0o7777).max(0o755);
        let _ = fs::set_permissions(&child_path, fs::Permissions::from_mode(perm_bits));

        self.sync_host_directory_children(parent, entry_idx, &host_dir)?;
        self.extractor.mark_dirty(entry_idx);

        let child_ino = self
            .inodes
            .get(&parent)
            .and_then(|n| n.children.get(name).copied())
            .ok_or(libc::EIO)?;
        self.compute_attr(child_ino)
    }

    /// High-level unlink helper (supports `/extracted/` files and `/raw/` scratch files).
    pub fn unlink_node(&mut self, parent: u64, name: &str) -> Result<(), libc::c_int> {
        if !self.is_writable() {
            return Err(libc::EROFS);
        }

        if parent == RAW_DIR_INO {
            let child_ino = self
                .inodes
                .get(&RAW_DIR_INO)
                .and_then(|n| n.children.get(name).copied())
                .ok_or(libc::ENOENT)?;

            let is_scratch = matches!(
                self.inodes.get(&child_ino).map(|n| &n.kind),
                Some(InodeKind::RawScratchFile { .. })
            );
            if !is_scratch {
                return Err(libc::EACCES);
            }
            if let Some(raw_dir) = self.inodes.get_mut(&RAW_DIR_INO) {
                raw_dir.children.remove(name);
            }
            self.inodes.remove(&child_ino);
            return Ok(());
        }

        let (entry_idx, host_dir) = self.resolve_extracted_dir(parent)?;
        if !self.is_extracted_entry_writable(entry_idx) {
            return Err(libc::EACCES);
        }

        let child_path = host_dir.join(name);
        let md = fs::symlink_metadata(&child_path).map_err(|_| libc::ENOENT)?;
        if md.is_dir() {
            return Err(libc::EISDIR);
        }
        fs::remove_file(&child_path).map_err(|_| libc::EIO)?;

        if let Some(removed_ino) = self.host_path_to_ino.remove(&child_path) {
            self.inodes.remove(&removed_ino);
        }
        if let Some(parent_node) = self.inodes.get_mut(&parent) {
            parent_node.children.remove(name);
        }

        self.extractor.mark_dirty(entry_idx);
        self.repack_and_sync_extracted(entry_idx)
    }

    /// High-level rmdir helper inside `/extracted/`.
    pub fn rmdir_node(&mut self, parent: u64, name: &str) -> Result<(), libc::c_int> {
        if !self.is_writable() {
            return Err(libc::EROFS);
        }

        let (entry_idx, host_dir) = self.resolve_extracted_dir(parent)?;
        if !self.is_extracted_entry_writable(entry_idx) {
            return Err(libc::EACCES);
        }

        let child_path = host_dir.join(name);
        let md = fs::symlink_metadata(&child_path).map_err(|_| libc::ENOENT)?;
        if !md.is_dir() {
            return Err(libc::ENOTDIR);
        }
        fs::remove_dir(&child_path).map_err(|_| libc::ENOTEMPTY)?;

        if let Some(removed_ino) = self.host_path_to_ino.remove(&child_path) {
            self.inodes.remove(&removed_ino);
        }
        if let Some(parent_node) = self.inodes.get_mut(&parent) {
            parent_node.children.remove(name);
        }

        self.extractor.mark_dirty(entry_idx);
        self.repack_and_sync_extracted(entry_idx)
    }

    /// High-level symlink creation helper inside `/extracted/`.
    pub fn symlink_node(
        &mut self,
        parent: u64,
        name: &str,
        link_target: &Path,
    ) -> Result<FileAttr, libc::c_int> {
        if !self.is_writable() {
            return Err(libc::EROFS);
        }

        let (entry_idx, host_dir) = self.resolve_extracted_dir(parent)?;
        if !self.is_extracted_entry_writable(entry_idx) {
            return Err(libc::EACCES);
        }

        let child_path = host_dir.join(name);
        if child_path.exists() {
            return Err(libc::EEXIST);
        }
        std::os::unix::fs::symlink(link_target, &child_path).map_err(|_| libc::EIO)?;

        self.sync_host_directory_children(parent, entry_idx, &host_dir)?;
        self.extractor.mark_dirty(entry_idx);
        self.repack_and_sync_extracted(entry_idx)?;

        let child_ino = self
            .inodes
            .get(&parent)
            .and_then(|n| n.children.get(name).copied())
            .ok_or(libc::EIO)?;
        self.compute_attr(child_ino)
    }

    /// High-level rename helper supporting both `/extracted/` file/dir moves and `/raw/` atomic-save replacements.
    pub fn rename_node(
        &mut self,
        parent: u64,
        name: &str,
        newparent: u64,
        newname: &str,
    ) -> Result<(), libc::c_int> {
        if !self.is_writable() {
            return Err(libc::EROFS);
        }

        // Case 1: Rename within `/raw/` (atomic-save editors: scratch temp file -> existing RawSlice target)
        if parent == RAW_DIR_INO && newparent == RAW_DIR_INO {
            let src_ino = self
                .inodes
                .get(&RAW_DIR_INO)
                .and_then(|n| n.children.get(name).copied())
                .ok_or(libc::ENOENT)?;

            let dst_ino_opt = self
                .inodes
                .get(&RAW_DIR_INO)
                .and_then(|n| n.children.get(newname).copied());

            let src_kind = self
                .inodes
                .get(&src_ino)
                .map(|n| n.kind.clone())
                .ok_or(libc::ENOENT)?;

            match src_kind {
                InodeKind::RawScratchFile { data, perm } => {
                    if let Some(dst_ino) = dst_ino_opt {
                        let dst_kind = self
                            .inodes
                            .get(&dst_ino)
                            .map(|n| n.kind.clone())
                            .ok_or(libc::ENOENT)?;
                        match dst_kind {
                            InodeKind::RawSlice { entry_idx } => {
                                // Atomic save onto a carved `/raw/<entry>` target!
                                self.raw_write_buffers.remove(&entry_idx);
                                self.apply_raw_slice_replacement(entry_idx, &data)?;
                                if let Some(raw_dir) = self.inodes.get_mut(&RAW_DIR_INO) {
                                    raw_dir.children.remove(name);
                                }
                                self.inodes.remove(&src_ino);
                                return Ok(());
                            }
                            InodeKind::RawScratchFile { .. } => {
                                if let Some(dst_node) = self.inodes.get_mut(&dst_ino) {
                                    dst_node.kind = InodeKind::RawScratchFile { data, perm };
                                }
                                if let Some(raw_dir) = self.inodes.get_mut(&RAW_DIR_INO) {
                                    raw_dir.children.remove(name);
                                }
                                self.inodes.remove(&src_ino);
                                return Ok(());
                            }
                            _ => return Err(libc::EACCES),
                        }
                    } else {
                        // Rename scratch file to another scratch filename in `/raw/`
                        if let Some(src_node) = self.inodes.get_mut(&src_ino) {
                            src_node.name = newname.to_string();
                        }
                        if let Some(raw_dir) = self.inodes.get_mut(&RAW_DIR_INO) {
                            raw_dir.children.remove(name);
                            raw_dir.children.insert(newname.to_string(), src_ino);
                        }
                        return Ok(());
                    }
                }
                InodeKind::RawSlice { entry_idx } => {
                    // When an editor creates a backup by renaming `0x..._svg.svg` -> `0x..._svg.svg~`
                    // before writing the new `0x..._svg.svg`, clone the current slice into a scratch
                    // backup file at `newname` while keeping `RawSlice` in place for the save.
                    if dst_ino_opt.is_none() {
                        let slice_bytes = self
                            .store
                            .read_slice(self.entries[entry_idx].span)
                            .map_err(|e| e.to_errno())?;
                        let backup_ino = self.alloc_ino();
                        self.inodes.insert(
                            backup_ino,
                            InodeNode {
                                ino: backup_ino,
                                parent: RAW_DIR_INO,
                                name: newname.to_string(),
                                kind: InodeKind::RawScratchFile {
                                    data: slice_bytes,
                                    perm: 0o644,
                                },
                                children: BTreeMap::new(),
                                children_loaded: true,
                            },
                        );
                        if let Some(raw_dir) = self.inodes.get_mut(&RAW_DIR_INO) {
                            raw_dir.children.insert(newname.to_string(), backup_ino);
                        }
                        return Ok(());
                    }
                    return Err(libc::EACCES);
                }
                _ => return Err(libc::EACCES),
            }
        }

        // Case 2: Rename within `/extracted/<entry>/`
        let (src_entry_idx, src_host_dir) = self.resolve_extracted_dir(parent)?;
        let (dst_entry_idx, dst_host_dir) = self.resolve_extracted_dir(newparent)?;
        if src_entry_idx != dst_entry_idx {
            return Err(libc::EXDEV);
        }
        if !self.is_extracted_entry_writable(src_entry_idx) {
            return Err(libc::EACCES);
        }

        let src_path = src_host_dir.join(name);
        let dst_path = dst_host_dir.join(newname);
        if !src_path.exists() && fs::symlink_metadata(&src_path).is_err() {
            return Err(libc::ENOENT);
        }

        fs::rename(&src_path, &dst_path).map_err(|_| libc::EIO)?;

        // Refresh inode mappings for the extracted entry
        self.clear_extracted_inodes_for_entry(src_entry_idx);
        let _ = self.ensure_directory_populated(parent);
        if newparent != parent {
            let _ = self.ensure_directory_populated(newparent);
        }

        self.extractor.mark_dirty(src_entry_idx);
        self.repack_and_sync_extracted(src_entry_idx)
    }
}

fn metadata_to_filetype(md: &fs::Metadata) -> FileType {
    let ft = md.file_type();
    if ft.is_dir() {
        FileType::Directory
    } else if ft.is_symlink() {
        FileType::Symlink
    } else {
        FileType::RegularFile
    }
}

fn time_or_now_to_system_time(ton: TimeOrNow) -> SystemTime {
    match ton {
        TimeOrNow::SpecificTime(st) => st,
        TimeOrNow::Now => SystemTime::now(),
    }
}

impl Filesystem for BinwalkFs {
    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let Some(name_str) = name.to_str() else {
            reply.error(libc::ENOENT);
            return;
        };
        match self.lookup_node(parent, name_str) {
            Ok(attr) => reply.entry(&TTL, &attr, 0),
            Err(errno) => reply.error(errno),
        }
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyAttr) {
        match self.compute_attr(ino) {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(errno) => reply.error(errno),
        }
    }

    fn setattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        if !self.is_writable() {
            reply.error(libc::EROFS);
            return;
        }

        if let Some(new_size) = size {
            if let Err(errno) = self.truncate_node(ino, new_size) {
                reply.error(errno);
                return;
            }
        }

        if mode.is_some() || atime.is_some() || mtime.is_some() {
            let Some(node) = self.inodes.get_mut(&ino) else {
                reply.error(libc::ENOENT);
                return;
            };
            match &mut node.kind {
                InodeKind::RawScratchFile { perm, .. } => {
                    if let Some(m) = mode {
                        *perm = (m as u16) & 0o777;
                    }
                }
                InodeKind::ExtractedHostNode {
                    entry_idx,
                    host_path,
                } => {
                    let e_idx = *entry_idx;
                    let h_path = host_path.clone();
                    if !self.is_extracted_entry_writable(e_idx) {
                        reply.error(libc::EACCES);
                        return;
                    }
                    if let Some(m) = mode {
                        let _ = fs::set_permissions(&h_path, fs::Permissions::from_mode(m & 0o7777));
                    }
                    if atime.is_some() || mtime.is_some() {
                        let st_a = atime
                            .map(time_or_now_to_system_time)
                            .unwrap_or_else(SystemTime::now);
                        let st_m = mtime
                            .map(time_or_now_to_system_time)
                            .unwrap_or_else(SystemTime::now);
                        let _ = filetime::set_symlink_file_times(
                            &h_path,
                            FileTime::from_system_time(st_a),
                            FileTime::from_system_time(st_m),
                        );
                    }
                    self.extractor.mark_dirty(e_idx);
                }
                InodeKind::RawSlice { .. } => {
                    // Ignore chmod/utimens on virtual `/raw/` slice files so editors/cp -p succeed
                }
                _ => {
                    reply.error(libc::EACCES);
                    return;
                }
            }
        }

        match self.compute_attr(ino) {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(errno) => reply.error(errno),
        }
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        match self.list_directory(ino) {
            Ok(entries) => {
                for (idx, item) in entries.into_iter().enumerate().skip(offset as usize) {
                    let next_offset = (idx + 1) as i64;
                    if reply.add(item.ino, next_offset, item.file_type, &item.name) {
                        break;
                    }
                }
                reply.ok();
            }
            Err(errno) => reply.error(errno),
        }
    }

    fn open(&mut self, _req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        let Some(node_kind) = self.inodes.get(&ino).map(|n| n.kind.clone()) else {
            reply.error(libc::ENOENT);
            return;
        };

        let access_mode = flags & libc::O_ACCMODE;
        let wants_write =
            access_mode == libc::O_WRONLY || access_mode == libc::O_RDWR || (flags & libc::O_TRUNC) != 0;

        if wants_write {
            if !self.is_writable() {
                reply.error(libc::EROFS);
                return;
            }
            if let InodeKind::ExtractedHostNode { entry_idx, .. } = node_kind {
                if !self.is_extracted_entry_writable(entry_idx) {
                    reply.error(libc::EACCES);
                    return;
                }
            }
            if matches!(node_kind, InodeKind::ManifestFile) {
                reply.error(libc::EACCES);
                return;
            }
            if (flags & libc::O_TRUNC) != 0 {
                if let Err(errno) = self.truncate_node(ino, 0) {
                    reply.error(errno);
                    return;
                }
            }
        }

        reply.opened(0, 0);
    }

    fn create(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        let Some(name_str) = name.to_str() else {
            reply.error(libc::EINVAL);
            return;
        };
        match self.create_node(parent, name_str, mode & !umask, flags) {
            Ok(attr) => reply.created(&TTL, &attr, 0, 0, 0),
            Err(errno) => reply.error(errno),
        }
    }

    fn mkdir(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        umask: u32,
        reply: ReplyEntry,
    ) {
        let Some(name_str) = name.to_str() else {
            reply.error(libc::EINVAL);
            return;
        };
        match self.mkdir_node(parent, name_str, mode & !umask) {
            Ok(attr) => reply.entry(&TTL, &attr, 0),
            Err(errno) => reply.error(errno),
        }
    }

    fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let Some(name_str) = name.to_str() else {
            reply.error(libc::ENOENT);
            return;
        };
        match self.unlink_node(parent, name_str) {
            Ok(()) => reply.ok(),
            Err(errno) => reply.error(errno),
        }
    }

    fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let Some(name_str) = name.to_str() else {
            reply.error(libc::ENOENT);
            return;
        };
        match self.rmdir_node(parent, name_str) {
            Ok(()) => reply.ok(),
            Err(errno) => reply.error(errno),
        }
    }

    fn symlink(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        link: &Path,
        reply: ReplyEntry,
    ) {
        let Some(name_str) = name.to_str() else {
            reply.error(libc::EINVAL);
            return;
        };
        match self.symlink_node(parent, name_str, link) {
            Ok(attr) => reply.entry(&TTL, &attr, 0),
            Err(errno) => reply.error(errno),
        }
    }

    fn rename(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        _flags: u32,
        reply: ReplyEmpty,
    ) {
        let (Some(name_str), Some(newname_str)) = (name.to_str(), newname.to_str()) else {
            reply.error(libc::EINVAL);
            return;
        };
        match self.rename_node(parent, name_str, newparent, newname_str) {
            Ok(()) => reply.ok(),
            Err(errno) => reply.error(errno),
        }
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        if offset < 0 {
            reply.error(libc::EINVAL);
            return;
        }
        match self.read_node(ino, offset as u64, size) {
            Ok(data) => reply.data(&data),
            Err(errno) => reply.error(errno),
        }
    }

    fn write(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        if offset < 0 {
            reply.error(libc::EINVAL);
            return;
        }
        match self.write_node(ino, offset as u64, data) {
            Ok(written) => reply.written(written as u32),
            Err(errno) => reply.error(errno),
        }
    }

    fn flush(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        _lock_owner: u64,
        reply: ReplyEmpty,
    ) {
        if !self.is_writable() {
            reply.ok();
            return;
        }
        let Some(node_kind) = self.inodes.get(&ino).map(|n| n.kind.clone()) else {
            reply.ok();
            return;
        };
        match node_kind {
            InodeKind::RawSlice { entry_idx } => {
                if let Err(errno) = self.flush_raw_entry(entry_idx) {
                    reply.error(errno);
                    return;
                }
            }
            InodeKind::ExtractedHostNode { entry_idx, .. } => {
                if self.is_extracted_entry_writable(entry_idx) {
                    if let Err(errno) = self.repack_and_sync_extracted(entry_idx) {
                        reply.error(errno);
                        return;
                    }
                }
            }
            _ => {}
        }
        reply.ok();
    }

    fn release(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        if self.is_writable() {
            if let Some(node_kind) = self.inodes.get(&ino).map(|n| n.kind.clone()) {
                match node_kind {
                    InodeKind::RawSlice { entry_idx } => {
                        let _ = self.flush_raw_entry(entry_idx);
                    }
                    InodeKind::ExtractedHostNode { entry_idx, .. } => {
                        if self.is_extracted_entry_writable(entry_idx) {
                            let _ = self.repack_and_sync_extracted(entry_idx);
                        }
                    }
                    _ => {}
                }
            }
        }
        reply.ok();
    }

    fn fsync(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        if !self.is_writable() {
            reply.ok();
            return;
        }
        if let Some(node_kind) = self.inodes.get(&ino).map(|n| n.kind.clone()) {
            match node_kind {
                InodeKind::RawSlice { entry_idx } => {
                    if let Err(errno) = self.flush_raw_entry(entry_idx) {
                        reply.error(errno);
                        return;
                    }
                }
                InodeKind::ExtractedHostNode { entry_idx, .. } => {
                    if self.is_extracted_entry_writable(entry_idx) {
                        if let Err(errno) = self.repack_and_sync_extracted(entry_idx) {
                            reply.error(errno);
                            return;
                        }
                    }
                }
                _ => {}
            }
        }
        match self.store.commit() {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e.to_errno()),
        }
    }

    fn destroy(&mut self) {
        if !self.is_writable() {
            return;
        }
        let staged_indices: Vec<usize> = self.raw_write_buffers.keys().copied().collect();
        for idx in staged_indices {
            let _ = self.flush_raw_entry(idx);
        }
        for idx in 0..self.entries.len() {
            if self.is_extracted_entry_writable(idx) {
                let _ = self.repack_and_sync_extracted(idx);
            }
        }
        if self.store.is_dirty() {
            if let Err(e) = self.store.commit() {
                log::error!("Failed to commit Copy-on-Write overlay on unmount: {e}");
            }
        }
    }

    fn readlink(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyData) {
        let Some(node) = self.inodes.get(&ino) else {
            reply.error(libc::ENOENT);
            return;
        };
        match &node.kind {
            InodeKind::ExtractedHostNode { host_path, .. } => match fs::read_link(host_path) {
                Ok(target) => reply.data(target.as_os_str().as_encoded_bytes()),
                Err(_) => reply.error(libc::EIO),
            },
            _ => reply.error(libc::EINVAL),
        }
    }

    fn statfs(&mut self, _req: &Request<'_>, _ino: u64, reply: ReplyStatfs) {
        let total_bytes = self.store.total_len() as u64;
        let blocks = total_bytes.div_ceil(u64::from(BLOCK_SIZE));
        let files = self.inodes.len() as u64;
        let _ = UNIX_EPOCH;
        reply.statfs(blocks, 0, 0, files, 0, BLOCK_SIZE, 255, BLOCK_SIZE);
    }
}
