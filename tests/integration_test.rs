use fuse_binwalk::{
    scan_bounded_signatures, BinwalkFs, CarvedEntry, ManifestDocument, OverlayBinaryStore,
    RegionRepacker, ScanConfig, WritePolicy, EXTRACTED_DIR_INO, MANIFEST_INO, RAW_DIR_INO,
    ROOT_INO,
};
use std::path::Path;
use std::sync::Arc;

/// Builds a valid minimal 1x1 PNG image (67 bytes) with a known start and IEND end marker.
fn make_valid_png() -> Vec<u8> {
    vec![
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
        0x00, 0x00, 0x00, 0x0D, // IHDR length = 13
        0x49, 0x48, 0x44, 0x52, // "IHDR"
        0x00, 0x00, 0x00, 0x01, // width = 1
        0x00, 0x00, 0x00, 0x01, // height = 1
        0x08, 0x02, 0x00, 0x00, 0x00, // bit depth=8, color=2, comp=0, filter=0, interlace=0
        0x90, 0x77, 0x53, 0xDE, // IHDR CRC
        0x00, 0x00, 0x00, 0x0C, // IDAT length = 12
        0x49, 0x44, 0x41, 0x54, // "IDAT"
        0x08, 0xD7, 0x63, 0xF8, 0xCF, 0xC0, 0x00, 0x00, 0x03, 0x01, 0x01, 0x00, 0x18, 0xDD, 0x8D,
        0xB0, // IDAT CRC
        0x00, 0x00, 0x00, 0x00, // IEND length = 0
        0x49, 0x45, 0x4E, 0x44, // "IEND"
        0xAE, 0x42, 0x60, 0x82, // IEND CRC
    ]
}

/// Builds a valid SVG document with `<svg ...>...</svg>` markers recognized by Binwalk.
fn make_valid_svg() -> Vec<u8> {
    b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"16\" height=\"16\"><rect width=\"16\" height=\"16\" fill=\"red\"/></svg>".to_vec()
}

/// Builds a valid ZIP archive containing a stored (`method = 0`) SVG file `icon.svg`
/// and a stored text file `readme.txt`.
fn make_zip_with_stored_svg(svg_bytes: &[u8]) -> (Vec<u8>, usize, usize) {
    let name = b"icon.svg";
    let crc = crc32fast::hash(svg_bytes);
    let size = svg_bytes.len() as u32;

    let mut out = Vec::new();
    // 1. Local File Header (PK\x03\x04)
    let lfh_offset = out.len();
    out.extend_from_slice(&[0x50, 0x4b, 0x03, 0x04]);
    out.extend_from_slice(&20u16.to_le_bytes()); // version needed
    out.extend_from_slice(&0u16.to_le_bytes()); // flags
    out.extend_from_slice(&0u16.to_le_bytes()); // method = 0 (STORE)
    out.extend_from_slice(&0u16.to_le_bytes()); // mod_time
    out.extend_from_slice(&0x21u16.to_le_bytes()); // mod_date
    out.extend_from_slice(&crc.to_le_bytes()); // crc32 at lfh_offset + 14
    out.extend_from_slice(&size.to_le_bytes()); // comp_size
    out.extend_from_slice(&size.to_le_bytes()); // uncomp_size
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // extra len
    out.extend_from_slice(name);
    out.extend_from_slice(svg_bytes);

    // 2. Central Directory Header (PK\x01\x02)
    let cd_offset = out.len();
    out.extend_from_slice(&[0x50, 0x4b, 0x01, 0x02]);
    out.extend_from_slice(&0x0314u16.to_le_bytes()); // version made by
    out.extend_from_slice(&20u16.to_le_bytes()); // version needed
    out.extend_from_slice(&0u16.to_le_bytes()); // flags
    out.extend_from_slice(&0u16.to_le_bytes()); // method = 0 (STORE)
    out.extend_from_slice(&0u16.to_le_bytes()); // mod_time
    out.extend_from_slice(&0x21u16.to_le_bytes()); // mod_date
    out.extend_from_slice(&crc.to_le_bytes()); // crc32 at cd_offset + 16
    out.extend_from_slice(&size.to_le_bytes()); // comp_size
    out.extend_from_slice(&size.to_le_bytes()); // uncomp_size
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // extra len
    out.extend_from_slice(&0u16.to_le_bytes()); // comment len
    out.extend_from_slice(&0u16.to_le_bytes()); // disk number
    out.extend_from_slice(&0u16.to_le_bytes()); // internal attr
    out.extend_from_slice(&(0o100644u32 << 16).to_le_bytes()); // external attr
    out.extend_from_slice(&(lfh_offset as u32).to_le_bytes()); // lfh offset
    out.extend_from_slice(name);
    let cd_size = out.len() - cd_offset;

    // 3. End of Central Directory (PK\x05\x06)
    out.extend_from_slice(&[0x50, 0x4b, 0x05, 0x06]);
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&(cd_size as u32).to_le_bytes());
    out.extend_from_slice(&(cd_offset as u32).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());

    (out, lfh_offset, cd_offset)
}

/// Builds a valid POSIX ustar archive containing `hello.txt` and `nested.png` (so `nested.png`
/// overlaps with the enclosing TAR archive!).
fn make_tar_with_nested_png(png_bytes: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut buf);

        let hello_data = b"Hello from inside a bounded TAR archive!\n";
        let mut header = tar::Header::new_ustar();
        header.set_path("hello.txt").unwrap();
        header.set_size(hello_data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append(&header, &hello_data[..]).unwrap();

        let mut png_header = tar::Header::new_ustar();
        png_header.set_path("nested.png").unwrap();
        png_header.set_size(png_bytes.len() as u64);
        png_header.set_mode(0o644);
        png_header.set_cksum();
        builder.append(&png_header, png_bytes).unwrap();

        builder.finish().unwrap();
    }
    buf
}

#[test]
fn test_scanner_and_fuse_vfs_end_to_end() {
    let png = make_valid_png();
    let tar_archive = make_tar_with_nested_png(&png);

    // Construct a synthetic firmware binary:
    // [0..256]: padding
    // [256..256 + png.len()]: standalone PNG #1
    // [512..512 + tar_archive.len()]: TAR archive containing hello.txt and nested PNG #2
    // [trailing]: padding
    let mut firmware = vec![0xAAu8; 256];
    let png1_start = firmware.len();
    firmware.extend_from_slice(&png);
    let png1_end = firmware.len();

    firmware.resize(512, 0xBB);
    let tar_start = firmware.len();
    firmware.extend_from_slice(&tar_archive);
    let tar_end = firmware.len();

    firmware.extend_from_slice(&[0xCC; 128]);

    let entries = scan_bounded_signatures(&firmware, &ScanConfig::default())
        .expect("scan_bounded_signatures should succeed");

    // Every discovered entry must have size > 0 and valid [start..end] within firmware
    assert!(
        !entries.is_empty(),
        "Expected bounded signatures to be found"
    );
    for e in &entries {
        assert!(e.span.len() > 0);
        assert!(e.span.end <= firmware.len());
    }

    // Verify standalone PNG #1 was found with exact start and end bytes, and filtered out of /extracted/
    let found_png1 = entries
        .iter()
        .find(|e| e.signature_result.name == "png" && e.span.start == png1_start)
        .expect("Standalone PNG #1 should be detected");
    assert_eq!(found_png1.span.end, png1_end);
    assert!(
        !found_png1.has_extractor(),
        "Carve-only PNG should not create a folder in /extracted/"
    );

    // Verify TAR archive was found AND nested PNG inside the TAR archive was also found (overlapping!)
    let found_tar = entries
        .iter()
        .find(|e| e.signature_result.name == "tarball" && e.span.start == tar_start)
        .expect("TAR archive should be detected");
    assert!(found_tar.span.end <= tar_end && found_tar.span.len() >= 1024);
    assert!(
        found_tar.has_extractor(),
        "TAR signature should have an extractor"
    );

    let found_nested_png = entries
        .iter()
        .find(|e| {
            e.signature_result.name == "png"
                && e.span.start > tar_start
                && e.span.end <= found_tar.span.end
        })
        .expect("Nested PNG inside TAR archive should also be detected");
    assert_eq!(found_nested_png.span.len(), png.len());

    // Mount into BinwalkFs (Read-Only mode)
    let store = Arc::new(OverlayBinaryStore::from_bytes(
        firmware.clone(),
        None,
        WritePolicy::ReadOnly,
    ));
    let mut fs = BinwalkFs::new(store, entries.clone()).expect("BinwalkFs::new should succeed");

    // 1. Check root directory listing: `/raw`, `/extracted`, `/manifest.json`
    let root_list = fs.list_directory(ROOT_INO).unwrap();
    let root_names: Vec<&str> = root_list.iter().map(|d| d.name.as_str()).collect();
    assert!(root_names.contains(&"raw"));
    assert!(root_names.contains(&"extracted"));
    assert!(root_names.contains(&"manifest.json"));

    // 2. Read `/manifest.json` and validate JSON structure
    let manifest_attr = fs.lookup_node(ROOT_INO, "manifest.json").unwrap();
    assert_eq!(manifest_attr.ino, MANIFEST_INO);
    let manifest_raw = fs
        .read_node(MANIFEST_INO, 0, manifest_attr.size as u32)
        .unwrap();
    let manifest: ManifestDocument = serde_json::from_slice(&manifest_raw).unwrap();
    assert_eq!(manifest.binary_size, firmware.len());
    assert!(manifest.total_bounded_entries >= 3);

    // 3. Read `/raw/<png1>` and verify exact byte-for-byte match with `png`
    let png1_attr = fs
        .lookup_node(RAW_DIR_INO, &found_png1.raw_filename)
        .expect("PNG #1 should exist in /raw");
    assert_eq!(png1_attr.size as usize, png.len());
    let png1_read = fs
        .read_node(png1_attr.ino, 0, png1_attr.size as u32)
        .unwrap();
    assert_eq!(png1_read, png);

    // Verify read-only enforcement on `/raw/<png1>`
    assert_eq!(fs.write_node(png1_attr.ino, 0, b"nope"), Err(libc::EROFS));

    // 4. Verify `/extracted/` lazy on-demand extraction
    assert!(fs.extractor_manager().get_cached(found_tar.index).is_none());

    let tar_ext_attr = fs
        .lookup_node(EXTRACTED_DIR_INO, &found_tar.extracted_dirname)
        .expect("TAR directory should exist under /extracted");

    // Listing `/extracted/<tar_dir>` triggers lazy bounded extraction
    let extracted_children = fs.list_directory(tar_ext_attr.ino).unwrap();
    assert!(
        fs.extractor_manager().get_cached(found_tar.index).is_some(),
        "Accessing /extracted/<tar_dir> should lazily trigger extraction"
    );

    let child_names: Vec<&str> = extracted_children.iter().map(|c| c.name.as_str()).collect();
    if child_names.contains(&"hello.txt") {
        let hello_attr = fs.lookup_node(tar_ext_attr.ino, "hello.txt").unwrap();
        let hello_bytes = fs
            .read_node(hello_attr.ino, 0, hello_attr.size as u32)
            .unwrap();
        assert_eq!(hello_bytes, b"Hello from inside a bounded TAR archive!\n");
    } else {
        assert!(child_names.contains(&"_extraction_status.txt"));
    }
}

struct MockTarballRepacker;

impl RegionRepacker for MockTarballRepacker {
    fn signature_name(&self) -> &str {
        "tarball"
    }

    fn repack(&self, extracted_dir: &Path, _entry: &CarvedEntry) -> anyhow::Result<Vec<u8>> {
        let modified = std::fs::read(extracted_dir.join("hello.txt"))?;
        Ok(modified)
    }
}

#[test]
fn test_future_write_and_repack_architecture() {
    let png = make_valid_png();
    let tar_archive = make_tar_with_nested_png(&png);

    let mut firmware = vec![0x00u8; 128];
    let png_start = firmware.len();
    firmware.extend_from_slice(&png);
    firmware.resize(256, 0x00);
    let tar_start = firmware.len();
    firmware.extend_from_slice(&tar_archive);
    let tar_end = firmware.len();

    let entries = scan_bounded_signatures(&firmware, &ScanConfig::default()).unwrap();
    let png_entry = entries
        .iter()
        .find(|e| e.signature_result.name == "png" && e.span.start == png_start)
        .unwrap()
        .clone();
    let tar_entry = entries
        .iter()
        .find(|e| e.signature_result.name == "tarball" && e.span.start == tar_start)
        .unwrap()
        .clone();

    let temp_backing = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(temp_backing.path(), &firmware).unwrap();

    // Mount with CopyOnWriteOverlay policy and 0x00 padding
    let store = Arc::new(
        OverlayBinaryStore::from_file(
            temp_backing.path(),
            WritePolicy::CopyOnWriteOverlay {
                pad_byte: Some(0x00),
            },
        )
        .unwrap(),
    );

    let mut fs = BinwalkFs::new(store.clone(), entries).unwrap();
    fs.extractor_manager()
        .repackers()
        .register(Arc::new(MockTarballRepacker));

    // 1. Test bounded in-place write to `/raw/<png>`
    let raw_png_attr = fs
        .lookup_node(RAW_DIR_INO, &png_entry.raw_filename)
        .unwrap();
    assert_eq!(fs.write_node(raw_png_attr.ino, 0, b"PATCHED!").unwrap(), 8);
    assert_eq!(&fs.read_node(raw_png_attr.ino, 0, 8).unwrap(), b"PATCHED!");

    // Writing past the end of `/raw/<png>` is rejected with ENOSPC
    assert_eq!(
        fs.write_node(raw_png_attr.ino, png.len() as u64 - 2, b"TOO_LONG"),
        Err(libc::ENOSPC)
    );

    // Backing file on disk is still unmodified until commit()
    let on_disk_before = std::fs::read(temp_backing.path()).unwrap();
    assert_eq!(&on_disk_before[png_start..png_start + 8], &png[..8]);

    // 2. Test modifying a file inside `/extracted/<tar>` and repacking into parent span
    let tar_dir_attr = fs
        .lookup_node(EXTRACTED_DIR_INO, &tar_entry.extracted_dirname)
        .unwrap();
    if let Ok(hello_attr) = fs.lookup_node(tar_dir_attr.ino, "hello.txt") {
        let new_msg = b"Repacked payload!";
        fs.write_node(hello_attr.ino, 0, new_msg).unwrap();
        fs.extractor_manager()
            .repack_entry_into_store(&tar_entry, &*store)
            .unwrap();

        let raw_tar_attr = fs
            .lookup_node(RAW_DIR_INO, &tar_entry.raw_filename)
            .unwrap();
        let repacked_head = fs
            .read_node(raw_tar_attr.ino, 0, new_msg.len() as u32)
            .unwrap();
        assert_eq!(repacked_head, new_msg);
        let _ = tar_end;
    }

    // 3. Commit CoW overlay back to backing file
    use fuse_binwalk::BinaryStore;
    store.commit().unwrap();
    let on_disk_after = std::fs::read(temp_backing.path()).unwrap();
    assert_eq!(&on_disk_after[png_start..png_start + 8], b"PATCHED!");
}

#[test]
fn test_raw_smart_padding_atomic_rename_and_zip_crc32_sync() {
    let svg = make_valid_svg();
    let (zip_bytes, lfh_rel, cd_rel) = make_zip_with_stored_svg(&svg);

    let mut image = vec![0x99u8; 64];
    let zip_start = image.len();
    image.extend_from_slice(&zip_bytes);

    let entries = scan_bounded_signatures(&image, &ScanConfig::default()).unwrap();
    let zip_entry = entries
        .iter()
        .find(|e| e.signature_result.name == "zip" && e.span.start == zip_start)
        .expect("ZIP container should be detected")
        .clone();
    let svg_entry = entries
        .iter()
        .find(|e| e.signature_result.name == "svg")
        .expect("Nested SVG inside stored ZIP should be detected")
        .clone();

    let store = Arc::new(OverlayBinaryStore::from_bytes(
        image.clone(),
        None,
        WritePolicy::InPlaceBounded {
            pad_byte: None, // Uses smart padding!
            write_through: false,
        },
    ));
    let mut fs = BinwalkFs::new(store.clone(), entries).unwrap();

    // 1. Test atomic-save editor workflow in `/raw/`:
    // Create temporary scratch file `.icon.svg.tmp` in `/raw/`, write a shorter SVG to it,
    // and `rename` it onto `/raw/<svg_entry.raw_filename>`.
    let shorter_svg = b"<svg xmlns=\"http://www.w3.org/2000/svg\"><circle r=\"5\"/></svg>";
    assert!(shorter_svg.len() < svg.len());

    let scratch_attr = fs
        .create_node(
            RAW_DIR_INO,
            ".icon.svg.tmp",
            0o644,
            libc::O_CREAT | libc::O_WRONLY,
        )
        .unwrap();
    fs.write_node(scratch_attr.ino, 0, shorter_svg).unwrap();
    fs.rename_node(
        RAW_DIR_INO,
        ".icon.svg.tmp",
        RAW_DIR_INO,
        &svg_entry.raw_filename,
    )
    .unwrap();

    // Verify smart padding (`0x20` ASCII space for SVG) filled the remainder of the SVG span
    let svg_attr = fs
        .lookup_node(RAW_DIR_INO, &svg_entry.raw_filename)
        .unwrap();
    let updated_svg_slice = fs.read_node(svg_attr.ino, 0, svg_attr.size as u32).unwrap();
    assert_eq!(updated_svg_slice.len(), svg_entry.span.len());
    assert_eq!(&updated_svg_slice[..shorter_svg.len()], shorter_svg);
    assert!(
        updated_svg_slice[shorter_svg.len()..]
            .iter()
            .all(|&b| b == b' '),
        "Trailing bytes of shorter SVG replacement should be smart-padded with ASCII space (0x20)"
    );

    // 2. Verify that the enclosing ZIP's Local File Header (+14) and Central Directory Header (+16)
    // CRC32 checksums were automatically updated to match the modified full `icon.svg` member
    // (which consists of the 39-byte `<?xml ...?>\n` prefix + the 110-byte `<svg>...</svg>` span)!
    use fuse_binwalk::BinaryStore;
    let mut expected_full_member = svg[..39].to_vec();
    expected_full_member.extend_from_slice(&updated_svg_slice);
    let expected_new_crc = crc32fast::hash(&expected_full_member);
    let updated_zip_slice = store.read_slice(zip_entry.span).unwrap();

    let lfh_crc = u32::from_le_bytes(
        updated_zip_slice[lfh_rel + 14..lfh_rel + 18]
            .try_into()
            .unwrap(),
    );
    let cd_crc = u32::from_le_bytes(
        updated_zip_slice[cd_rel + 16..cd_rel + 20]
            .try_into()
            .unwrap(),
    );
    assert_eq!(
        lfh_crc, expected_new_crc,
        "ZIP Local File Header CRC32 should be automatically updated after /raw/ SVG edit"
    );
    assert_eq!(
        cd_crc, expected_new_crc,
        "ZIP Central Directory Header CRC32 should be automatically updated after /raw/ SVG edit"
    );
}

#[test]
fn test_builtin_zip_repacker_and_truncate_workflow() {
    let svg = make_valid_svg();
    let (zip_bytes, lfh_rel, _cd_rel) = make_zip_with_stored_svg(&svg);

    let mut image = vec![0x11u8; 64];
    let zip_start = image.len();
    image.extend_from_slice(&zip_bytes);

    let entries = scan_bounded_signatures(&image, &ScanConfig::default()).unwrap();
    let zip_entry = entries
        .iter()
        .find(|e| e.signature_result.name == "zip" && e.span.start == zip_start)
        .unwrap()
        .clone();
    let svg_entry = entries
        .iter()
        .find(|e| e.signature_result.name == "svg")
        .unwrap()
        .clone();

    let store = Arc::new(OverlayBinaryStore::from_bytes(
        image,
        None,
        WritePolicy::InPlaceBounded {
            pad_byte: None,
            write_through: false,
        },
    ));
    let mut fs = BinwalkFs::new(store.clone(), entries).unwrap();

    // Verify that `zip` has a built-in repacker registered by default
    assert!(fs.is_extracted_entry_writable(zip_entry.index));

    // Test standard truncate(0) -> write -> flush_raw_entry workflow on `/raw/<svg>`
    let svg_attr = fs
        .lookup_node(RAW_DIR_INO, &svg_entry.raw_filename)
        .unwrap();
    let replacement = b"<svg><path d=\"M0 0\"/></svg>";
    fs.truncate_node(svg_attr.ino, 0).unwrap();
    fs.write_node(svg_attr.ino, 0, replacement).unwrap();
    fs.flush_raw_entry(svg_entry.index).unwrap();

    let read_back = fs
        .read_node(svg_attr.ino, 0, svg_entry.span.len() as u32)
        .unwrap();
    assert_eq!(&read_back[..replacement.len()], replacement);
    assert!(read_back[replacement.len()..].iter().all(|&b| b == b' '));

    // Also test modifying inside `/extracted/<zip>` if `7z` extracted `icon.svg`
    let zip_dir_attr = fs
        .lookup_node(EXTRACTED_DIR_INO, &zip_entry.extracted_dirname)
        .unwrap();
    if let Ok(icon_attr) = fs.lookup_node(zip_dir_attr.ino, "icon.svg") {
        let shorter_icon = b"<svg>repacked-from-extracted</svg>";
        fs.truncate_node(icon_attr.ino, 0).unwrap();
        fs.write_node(icon_attr.ino, 0, shorter_icon).unwrap();
        fs.repack_and_sync_extracted(zip_entry.index).unwrap();

        use fuse_binwalk::BinaryStore;
        let repacked_zip = store.read_slice(zip_entry.span).unwrap();
        let expected_crc = crc32fast::hash(shorter_icon);
        let actual_lfh_crc =
            u32::from_le_bytes(repacked_zip[lfh_rel + 14..lfh_rel + 18].try_into().unwrap());
        assert_eq!(actual_lfh_crc, expected_crc);
    }

    // Verify extended attributes (`listxattr_node` / `getxattr_node`) on `/raw/` and `/extracted/`
    let xattr_names = fs.listxattr_node(svg_attr.ino).unwrap();
    assert!(xattr_names.contains(&"user.binwalk.name".to_string()));
    assert!(xattr_names.contains(&"user.binwalk.description".to_string()));
    assert!(xattr_names.contains(&"user.binwalk.offset".to_string()));
    assert!(xattr_names.contains(&"user.binwalk.writable".to_string()));
    assert_eq!(
        fs.getxattr_node(svg_attr.ino, "user.binwalk.name").unwrap(),
        b"svg"
    );
    assert_eq!(
        fs.getxattr_node(svg_attr.ino, "user.binwalk.writable")
            .unwrap(),
        b"true"
    );
    assert_eq!(
        fs.getxattr_node(svg_attr.ino, "user.binwalk.payload_size")
            .unwrap(),
        replacement.len().to_string().as_bytes()
    );
    assert_eq!(
        fs.getxattr_node(svg_attr.ino, "user.binwalk.slack_bytes")
            .unwrap(),
        (svg_entry.span.len() - replacement.len())
            .to_string()
            .as_bytes()
    );
    assert_eq!(
        fs.getxattr_node(svg_attr.ino, "user.binwalk.modified")
            .unwrap(),
        b"true"
    );

    // Verify `/manifest.json` reflects live `payload_size`, `slack_bytes`, and `modified`
    let manifest_raw = fs.read_node(MANIFEST_INO, 0, 65536).unwrap();
    let live_manifest: ManifestDocument = serde_json::from_slice(&manifest_raw).unwrap();
    let live_svg_item = live_manifest
        .entries
        .iter()
        .find(|e| e.index == svg_entry.index)
        .unwrap();
    assert!(live_svg_item.modified);
    assert_eq!(live_svg_item.payload_size, replacement.len());
    assert_eq!(
        live_svg_item.slack_bytes,
        svg_entry.span.len() - replacement.len()
    );

    assert_eq!(
        fs.getxattr_node(svg_attr.ino, "user.binwalk.nonexistent")
            .unwrap_err(),
        libc::ENODATA
    );
}
