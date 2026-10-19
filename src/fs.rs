use crate::extractor::ExtractionManager;
use crate::scanner::{build_manifest, CarvedEntry};
use crate::storage::{BinaryStore, WritePolicy};
use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry,
    ReplyOpen, ReplyStatfs, ReplyWrite, Request, TimeOrNow, FUSE_ROOT_ID,
};
use std::collections::{BTreeMap, HashMap};
use std::ffi::OsStr;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const ROOT_INO: u64 = FUSE_ROOT_ID; // 1
pub const RAW_DIR_INO: u64 = 2;
pub const EXTRACTED_DIR_INO: u64 = 3;
pub const MANIFEST_INO: u64 = 4;
const FIRST_DYNAMIC_INO: u64 = 100;

const TTL: Duration = Duration::from_secs(60);
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
            next_ino: FIRST_DYNAMIC_INO,
            mount_time,
            uid,
            gid,
        };

        fs.init_static_tree();
        Ok(fs)
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

    fn is_writable(&self) -> bool {
        !matches!(self.store.write_policy(), WritePolicy::ReadOnly)
    }

    fn default_dir_perm(&self) -> u16 {
        if self.is_writable() {
            0o755
        } else {
            0o555
        }
    }

    fn default_file_perm(&self) -> u16 {
        if self.is_writable() {
            0o644
        } else {
            0o444
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
            // Re-scan host_dir in case new files were created or modified
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

            if let Some(parent_node) = self.inodes.get_mut(&parent_ino) {
                parent_node.children.insert(name, child_ino);
            }
        }

        Ok(())
    }

    pub fn compute_attr(&self, ino: u64) -> Result<FileAttr, libc::c_int> {
        let Some(node) = self.inodes.get(&ino) else {
            return Err(libc::ENOENT);
        };

        match &node.kind {
            InodeKind::RootDir => Ok(self.make_attr(ino, FileType::Directory, 0, self.default_dir_perm(), 4)),
            InodeKind::RawDir => {
                let nlink = 2;
                Ok(self.make_attr(ino, FileType::Directory, 0, self.default_dir_perm(), nlink))
            }
            InodeKind::ExtractedTopDir => {
                let nlink = (2 + node.children.len()) as u32;
                Ok(self.make_attr(ino, FileType::Directory, 0, self.default_dir_perm(), nlink))
            }
            InodeKind::ManifestFile => Ok(self.make_attr(
                ino,
                FileType::RegularFile,
                self.manifest_bytes.len() as u64,
                0o444,
                1,
            )),
            InodeKind::RawSlice { entry_idx } => {
                let span = self.entries[*entry_idx].span;
                Ok(self.make_attr(
                    ino,
                    FileType::RegularFile,
                    span.len() as u64,
                    self.default_file_perm(),
                    1,
                ))
            }
            InodeKind::ExtractedEntryRoot { .. } => {
                let nlink = 2 + node.children.len() as u32;
                Ok(self.make_attr(ino, FileType::Directory, 0, self.default_dir_perm(), nlink))
            }
            InodeKind::ExtractedHostNode { host_path, .. } => {
                let md = fs::symlink_metadata(host_path).map_err(|_| libc::ENOENT)?;
                let ft = metadata_to_filetype(&md);
                let size = if ft == FileType::Directory { 0 } else { md.len() };
                let perm = match ft {
                    FileType::Directory => self.default_dir_perm(),
                    FileType::Symlink => 0o777,
                    _ => {
                        let base = self.default_file_perm();
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

    /// High-level write helper supporting future write policies (`InPlaceBounded`, `CopyOnWriteOverlay`)
    /// and extracted file modifications.
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
                self.store
                    .write_in_span(span, off_usize, data)
                    .map_err(|e| e.to_errno())
            }
            InodeKind::ExtractedHostNode {
                entry_idx,
                host_path,
            } => {
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
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
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
            let Some(node) = self.inodes.get(&ino) else {
                reply.error(libc::ENOENT);
                return;
            };
            match &node.kind {
                InodeKind::RawSlice { entry_idx } => {
                    let span = self.entries[*entry_idx].span;
                    if new_size as usize > span.len() {
                        reply.error(libc::ENOSPC);
                        return;
                    }
                }
                InodeKind::ExtractedHostNode {
                    entry_idx,
                    host_path,
                } => {
                    if let Ok(file) = fs::OpenOptions::new().write(true).open(host_path) {
                        if file.set_len(new_size).is_err() {
                            reply.error(libc::EIO);
                            return;
                        }
                        self.extractor.mark_dirty(*entry_idx);
                    } else {
                        reply.error(libc::EIO);
                        return;
                    }
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
        if !self.inodes.contains_key(&ino) {
            reply.error(libc::ENOENT);
            return;
        }
        let access_mode = flags & libc::O_ACCMODE;
        if (access_mode == libc::O_WRONLY || access_mode == libc::O_RDWR || (flags & libc::O_TRUNC) != 0)
            && !self.is_writable()
        {
            reply.error(libc::EROFS);
            return;
        }
        reply.opened(0, 0);
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
        if let Some(node) = self.inodes.get(&ino) {
            if let InodeKind::ExtractedHostNode { entry_idx, .. } = node.kind {
                let entry = self.entries[entry_idx].clone();
                if self.extractor.repackers().get(&entry.signature_result.name).is_some() {
                    if let Err(_) = self.extractor.repack_entry_into_store(&entry, &*self.store) {
                        reply.error(libc::EIO);
                        return;
                    }
                }
            }
        }
        reply.ok();
    }

    fn fsync(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        if !self.is_writable() {
            reply.ok();
            return;
        }
        match self.store.commit() {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e.to_errno()),
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
