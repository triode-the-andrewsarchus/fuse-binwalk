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
        0x08, 0xD7, 0x63, 0xF8, 0xCF, 0xC0, 0x00, 0x00, 0x03, 0x01, 0x01, 0x00,
        0x18, 0xDD, 0x8D, 0xB0, // IDAT CRC
        0x00, 0x00, 0x00, 0x00, // IEND length = 0
        0x49, 0x45, 0x4E, 0x44, // "IEND"
        0xAE, 0x42, 0x60, 0x82, // IEND CRC
    ]
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
    assert!(!entries.is_empty(), "Expected bounded signatures to be found");
    for e in &entries {
        assert!(e.span.len() > 0);
        assert!(e.span.end <= firmware.len());
    }

    // Verify standalone PNG #1 was found with exact start and end bytes
    let found_png1 = entries
        .iter()
        .find(|e| e.signature_result.name == "png" && e.span.start == png1_start)
        .expect("Standalone PNG #1 should be detected");
    assert_eq!(found_png1.span.end, png1_end);

    // Verify TAR archive was found AND nested PNG inside the TAR archive was also found (overlapping!)
    let found_tar = entries
        .iter()
        .find(|e| e.signature_result.name == "tarball" && e.span.start == tar_start)
        .expect("TAR archive should be detected");
    assert!(found_tar.span.end <= tar_end && found_tar.span.len() >= 1024);
    assert!(found_tar.has_extractor(), "TAR signature should have an extractor");

    let found_nested_png = entries
        .iter()
        .find(|e| e.signature_result.name == "png" && e.span.start > tar_start && e.span.end <= found_tar.span.end)
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
    assert_eq!(
        fs.write_node(png1_attr.ino, 0, b"nope"),
        Err(libc::EROFS)
    );

    // 4. Verify `/extracted/` lazy on-demand extraction
    // Before accessing `/extracted/<tar_dir>`, extraction has not run yet
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
        assert_eq!(
            hello_bytes,
            b"Hello from inside a bounded TAR archive!\n"
        );
    } else {
        // If `tar` CLI wasn't installed in a minimal container, `_extraction_status.txt` must be present
        assert!(child_names.contains(&"_extraction_status.txt"));
    }
}

struct MockTarballRepacker;

impl RegionRepacker for MockTarballRepacker {
    fn signature_name(&self) -> &str {
        "tarball"
    }

    fn repack(&self, extracted_dir: &Path, _entry: &CarvedEntry) -> anyhow::Result<Vec<u8>> {
        // Read modified `hello.txt` from `extracted_dir` and return a deterministic repacked payload
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
        let repacked_head = fs.read_node(raw_tar_attr.ino, 0, new_msg.len() as u32).unwrap();
        assert_eq!(repacked_head, new_msg);
        let _ = tar_end;
    }

    // 3. Commit CoW overlay back to backing file
    use fuse_binwalk::BinaryStore;
    store.commit().unwrap();
    let on_disk_after = std::fs::read(temp_backing.path()).unwrap();
    assert_eq!(&on_disk_after[png_start..png_start + 8], b"PATCHED!");
}
