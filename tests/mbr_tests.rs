//! Integration tests for mbr-forensic.
//! All tests use in-memory byte slices or Cursor<Vec<u8>> — no temp files needed.

use mbr_forensic::{
    analyse, entropy,
    findings::{AnomalyKind, Severity},
    gap::{compute_gaps, GapKind},
    parse_mbr_sector,
    partition::{Chs, PartitionFamily, TypeCode},
    signature, BootCodeId, DetectedFs, Error,
};
use std::io::Cursor;

// ── MBR sector builder helpers ───────────────────────────────────────────────

/// Build a valid 512-byte MBR sector with the given entries.
/// Boots signature 0x55AA is always set.
fn make_sector(entries: &[(&[u8; 16], usize)]) -> [u8; 512] {
    let mut s = [0u8; 512];
    s[510] = 0x55;
    s[511] = 0xAA;
    for (entry_bytes, index) in entries {
        let off = 446 + index * 16;
        s[off..off + 16].copy_from_slice(*entry_bytes);
    }
    s
}

/// Build a 16-byte partition entry.
fn make_entry(status: u8, type_code: u8, lba_start: u32, lba_count: u32) -> [u8; 16] {
    let mut e = [0u8; 16];
    e[0] = status;
    e[4] = type_code;
    e[8..12].copy_from_slice(&lba_start.to_le_bytes());
    e[12..16].copy_from_slice(&lba_count.to_le_bytes());
    e
}

/// Build a minimal disk image of `total_sectors` 512-byte sectors with an MBR.
fn make_disk(total_sectors: u64, entries: &[(&[u8; 16], usize)]) -> Vec<u8> {
    let mut disk = vec![0u8; (total_sectors * 512) as usize];
    let mbr = make_sector(entries);
    disk[..512].copy_from_slice(&mbr);
    disk
}

// ── parse_mbr_sector ──────────────────────────────────────────────────────────

#[test]
fn parse_valid_sector_succeeds() {
    let s = make_sector(&[]);
    assert!(parse_mbr_sector(&s).is_ok());
}

#[test]
fn parse_too_short_returns_error() {
    let s = [0u8; 256];
    assert!(matches!(parse_mbr_sector(&s), Err(Error::TooShort(256))));
}

#[test]
fn parse_bad_signature_returns_error() {
    let mut s = [0u8; 512];
    s[510] = 0xDE;
    s[511] = 0xAD;
    assert!(matches!(
        parse_mbr_sector(&s),
        Err(Error::BadSignature(0xDEAD))
    ));
}

#[test]
fn disk_serial_read_correctly() {
    let mut s = make_sector(&[]);
    s[440..444].copy_from_slice(&0x12345678u32.to_le_bytes());
    let mbr = parse_mbr_sector(&s).unwrap();
    assert_eq!(mbr.disk_serial, 0x12345678);
}

#[test]
fn reserved_bytes_parsed() {
    let mut s = make_sector(&[]);
    s[444] = 0xAB;
    s[445] = 0xCD;
    let mbr = parse_mbr_sector(&s).unwrap();
    assert_eq!(mbr.reserved, [0xAB, 0xCD]);
}

#[test]
fn empty_entries_are_all_zero() {
    let s = make_sector(&[]);
    let mbr = parse_mbr_sector(&s).unwrap();
    for e in &mbr.entries {
        assert!(e.is_empty());
    }
}

#[test]
fn partition_entry_fields_parsed_correctly() {
    let entry = make_entry(0x80, 0x83, 2048, 1024 * 1024 / 512);
    let s = make_sector(&[(&entry, 0)]);
    let mbr = parse_mbr_sector(&s).unwrap();
    let e = &mbr.entries[0];
    assert_eq!(e.status, 0x80);
    assert_eq!(e.type_code, TypeCode(0x83));
    assert_eq!(e.lba_start, 2048);
    assert!(e.is_bootable());
    assert!(!e.is_empty());
}

#[test]
fn lba_end_is_start_plus_count_minus_one() {
    let entry = make_entry(0x00, 0x83, 100, 50);
    let s = make_sector(&[(&entry, 0)]);
    let mbr = parse_mbr_sector(&s).unwrap();
    assert_eq!(mbr.entries[0].lba_end(), 149);
}

// ── CHS ───────────────────────────────────────────────────────────────────────

#[test]
fn chs_from_bytes_decodes_correctly() {
    // head=1, sector=63, cylinder=0
    let chs = Chs::from_bytes([1, 63, 0]);
    assert_eq!(chs.head, 1);
    assert_eq!(chs.sector, 63);
    assert_eq!(chs.cylinder, 0);
}

#[test]
fn chs_high_cylinder_bits_in_byte1() {
    // byte1 bits 7:6 = cylinder high bits, byte2 = cylinder low
    // cylinder = 0b11_0000_0001 = 769, head=0, sector=1
    let chs = Chs::from_bytes([0, 0b1100_0001, 0b0000_0001]);
    assert_eq!(chs.cylinder, 769);
    assert_eq!(chs.sector, 1);
}

#[test]
fn chs_zero_sector_to_lba_returns_none() {
    let chs = Chs {
        cylinder: 0,
        head: 0,
        sector: 0,
    };
    assert!(chs.to_lba(255, 63).is_none());
}

// ── TypeCode ──────────────────────────────────────────────────────────────────

#[test]
fn type_code_linux_is_0x83() {
    assert_eq!(TypeCode(0x83).family(), PartitionFamily::Linux);
    assert_eq!(TypeCode(0x83).name(), "Linux");
}

#[test]
fn type_code_ntfs_is_0x07() {
    assert_eq!(TypeCode(0x07).family(), PartitionFamily::Ntfs);
}

#[test]
fn type_code_fat32_lba_is_0x0c() {
    assert_eq!(TypeCode(0x0C).family(), PartitionFamily::Fat32);
}

#[test]
fn type_code_gpt_protective_is_0xee() {
    assert_eq!(TypeCode(0xEE).family(), PartitionFamily::GptProtective);
    assert!(!TypeCode(0xEE).is_extended());
}

#[test]
fn type_code_extended_0x05_is_extended() {
    assert!(TypeCode(0x05).is_extended());
    assert!(TypeCode(0x0F).is_extended());
    assert!(TypeCode(0x85).is_extended());
}

#[test]
fn type_code_0x00_is_empty() {
    assert!(TypeCode(0x00).is_empty());
    assert!(!TypeCode(0x83).is_empty());
}

// ── BootCodeId ────────────────────────────────────────────────────────────────

#[test]
fn identify_all_zeros_boot_code() {
    let code = [0u8; 446];
    assert_eq!(
        mbr_forensic::boot_code::identify(&code),
        BootCodeId::AllZeros
    );
}

#[test]
fn identify_all_ff_boot_code() {
    let code = [0xFF; 446];
    assert_eq!(
        mbr_forensic::boot_code::identify(&code),
        BootCodeId::AllOnes
    );
}

#[test]
fn identify_unknown_boot_code() {
    let mut code = [0u8; 446];
    code[0] = 0xAA; // Not matching any known pattern.
    assert_eq!(
        mbr_forensic::boot_code::identify(&code),
        BootCodeId::Unknown
    );
}

#[test]
fn identify_grub2_by_jmp_opcode() {
    let mut code = [0u8; 446];
    code[0] = 0xEB; // JMP short
    code[1] = 0x63;
    code[2] = 0x90; // NOP
    assert_eq!(mbr_forensic::boot_code::identify(&code), BootCodeId::Grub2);
}

#[test]
fn identify_windows7_by_pattern() {
    let mut code = [0u8; 446];
    // Windows 7+ start: xor ax,ax; mov ss,ax; mov sp,7C00h
    code[0..7].copy_from_slice(&[0x33, 0xC0, 0x8E, 0xD0, 0xBC, 0x00, 0x7C]);
    // "BOOTMGR" at offset 418
    code[418..425].copy_from_slice(b"BOOTMGR");
    assert_eq!(
        mbr_forensic::boot_code::identify(&code),
        BootCodeId::Windows7Plus
    );
}

// ── Shannon entropy ───────────────────────────────────────────────────────────

#[test]
fn entropy_all_zeros_is_zero() {
    assert_eq!(entropy::shannon(&[0u8; 512]), 0.0);
}

#[test]
fn entropy_all_same_byte_is_zero() {
    assert_eq!(entropy::shannon(&[0xAA; 512]), 0.0);
}

#[test]
fn entropy_two_values_is_one() {
    // 128 zeros + 128 ones = 50/50 = entropy 1.0
    let mut d = vec![0u8; 128];
    d.extend_from_slice(&[1u8; 128]);
    let e = entropy::shannon(&d);
    assert!((e - 1.0).abs() < 1e-9, "expected 1.0, got {e}");
}

#[test]
fn entropy_uniform_all_256_values_is_eight() {
    let data: Vec<u8> = (0u8..=255).collect();
    let e = entropy::shannon(&data);
    assert!((e - 8.0).abs() < 1e-9, "expected 8.0, got {e}");
}

#[test]
fn entropy_empty_slice_is_zero() {
    assert_eq!(entropy::shannon(&[]), 0.0);
}

// ── Filesystem signature detection ───────────────────────────────────────────

#[test]
fn detect_unknown_on_zeros() {
    assert_eq!(signature::detect(&[0u8; 512]), DetectedFs::AllZeros);
}

#[test]
fn detect_luks_magic() {
    let mut s = [0u8; 512];
    s[0..6].copy_from_slice(b"LUKS\xba\xbe");
    assert_eq!(signature::detect(&s), DetectedFs::Luks);
}

#[test]
fn detect_ntfs_oem_id() {
    let mut s = [0u8; 512];
    s[3..11].copy_from_slice(b"NTFS    ");
    assert_eq!(signature::detect(&s), DetectedFs::Ntfs);
}

#[test]
fn detect_fat_msdos_oem() {
    let mut s = [0u8; 512];
    s[3..11].copy_from_slice(b"MSDOS5.0");
    assert_eq!(signature::detect(&s), DetectedFs::Fat);
}

#[test]
fn detect_apfs_magic() {
    let mut s = [0u8; 512];
    s[0..4].copy_from_slice(b"NXSB");
    assert_eq!(signature::detect(&s), DetectedFs::Apfs);
}

#[test]
fn detect_xfs_magic() {
    let mut s = [0u8; 512];
    s[0..4].copy_from_slice(b"XFSB");
    assert_eq!(signature::detect(&s), DetectedFs::Xfs);
}

#[test]
fn detect_ext_superblock_magic() {
    let mut s = vec![0u8; 1100]; // needs > 1082 bytes
    s[1080] = 0x53;
    s[1081] = 0xEF;
    assert_eq!(signature::detect(&s), DetectedFs::Ext);
}

#[test]
fn detect_exfat_oem() {
    let mut s = [0u8; 512];
    s[3..11].copy_from_slice(b"EXFAT   ");
    assert_eq!(signature::detect(&s), DetectedFs::ExFat);
}

// ── Gap analysis ─────────────────────────────────────────────────────────────

#[test]
fn no_gaps_when_fully_partitioned() {
    // Single partition from LBA 1 to 999 on a 1000-sector disk.
    let extents = [(1u64, 999u64)];
    let gaps = compute_gaps(&extents, 1, 999, 512);
    assert!(gaps.is_empty(), "expected no gaps, got {gaps:?}");
}

#[test]
fn pre_partition_gap_detected() {
    // Disk LBA 0–999; partition at LBA 64–999 → gap at LBA 1–63.
    let extents = [(64u64, 999u64)];
    let gaps = compute_gaps(&extents, 1, 999, 512);
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0].kind, GapKind::PrePartition);
    assert_eq!(gaps[0].lba_start, 1);
    assert_eq!(gaps[0].lba_end, 63);
}

#[test]
fn inter_partition_gap_detected() {
    // Two partitions with a gap between them.
    let extents = [(1u64, 499u64), (600u64, 999u64)];
    let gaps = compute_gaps(&extents, 1, 999, 512);
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0].kind, GapKind::Between);
    assert_eq!(gaps[0].lba_start, 500);
    assert_eq!(gaps[0].lba_end, 599);
}

#[test]
fn post_partition_gap_detected() {
    let extents = [(1u64, 499u64)];
    let gaps = compute_gaps(&extents, 1, 999, 512);
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0].kind, GapKind::PostPartition);
    assert_eq!(gaps[0].lba_start, 500);
    assert_eq!(gaps[0].lba_end, 999);
}

#[test]
fn gap_byte_size_is_correct() {
    let extents = [(64u64, 999u64)];
    let gaps = compute_gaps(&extents, 1, 999, 512);
    assert_eq!(gaps[0].byte_size, 63 * 512); // LBA 1–63 = 63 sectors
}

// ── analyse: anomaly detection ────────────────────────────────────────────────

fn disk_with_single_partition(lba_start: u32, lba_count: u32, type_code: u8) -> Vec<u8> {
    let total_sectors = lba_start as u64 + lba_count as u64 + 10;
    let entry = make_entry(0x80, type_code, lba_start, lba_count);
    let mut disk = make_disk(total_sectors, &[(&entry, 0)]);
    // Inject GRUB 2 boot code pattern so we don't trigger WipedBootCode.
    disk[0] = 0xEB;
    disk[1] = 0x63;
    disk[2] = 0x90;
    disk
}

#[test]
fn analyse_clean_disk_has_no_high_anomalies() {
    let disk = disk_with_single_partition(2048, 4096, 0x83);
    let mut c = Cursor::new(disk);
    let total_size = c.get_ref().len() as u64;
    let analysis = analyse(&mut c, total_size).unwrap();
    let high_or_above: Vec<_> = analysis
        .anomalies
        .iter()
        .filter(|a| a.severity >= Severity::High)
        .collect();
    assert!(
        high_or_above.is_empty(),
        "expected no high+ anomalies, got: {high_or_above:#?}"
    );
}

#[test]
fn analyse_detects_non_zero_reserved() {
    let mut disk = make_disk(100, &[]);
    disk[444] = 0x01; // reserved byte
    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, 100 * 512).unwrap();
    assert!(analysis
        .anomalies
        .iter()
        .any(|a| a.kind == AnomalyKind::NonZeroReserved));
}

#[test]
fn analyse_detects_multiple_bootable() {
    let e0 = make_entry(0x80, 0x83, 2048, 1024);
    let e1 = make_entry(0x80, 0x83, 4096, 1024); // second bootable
    let disk = make_disk(10000, &[(&e0, 0), (&e1, 1)]);
    let size = disk.len() as u64;
    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, size).unwrap();
    assert!(analysis
        .anomalies
        .iter()
        .any(|a| a.kind == AnomalyKind::MultipleBootable));
}

#[test]
fn analyse_detects_residual_entry() {
    // type_code=0, but lba_start and lba_count are non-zero
    let entry = make_entry(0x00, 0x00, 100, 50);
    let disk = make_disk(1000, &[(&entry, 0)]);
    let size = disk.len() as u64;
    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, size).unwrap();
    assert!(analysis
        .anomalies
        .iter()
        .any(|a| matches!(a.kind, AnomalyKind::ResidualEntry { index: 0 })));
}

#[test]
fn analyse_detects_out_of_bounds_partition() {
    let total_sectors = 1000u64;
    // Partition that extends past end of disk
    let entry = make_entry(0x80, 0x83, 500, 1000); // end = LBA 1499, disk end = LBA 999
    let disk = make_disk(total_sectors, &[(&entry, 0)]);
    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, total_sectors * 512).unwrap();
    assert!(analysis
        .anomalies
        .iter()
        .any(|a| matches!(a.kind, AnomalyKind::OutOfBounds { index: 0 })));
}

#[test]
fn analyse_detects_overlapping_partitions() {
    let e0 = make_entry(0x80, 0x83, 100, 500); // LBA 100–599
    let e1 = make_entry(0x00, 0x83, 400, 500); // LBA 400–899 — overlaps
    let disk = make_disk(2000, &[(&e0, 0), (&e1, 1)]);
    let size = disk.len() as u64;
    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, size).unwrap();
    assert!(analysis
        .anomalies
        .iter()
        .any(|a| matches!(a.kind, AnomalyKind::OverlappingPartitions { .. })));
}

#[test]
fn analyse_detects_pre_partition_space() {
    // First partition starts at LBA 128 (not LBA 1) — gap of 127 sectors
    let entry = make_entry(0x80, 0x83, 128, 1000);
    let disk = make_disk(2000, &[(&entry, 0)]);
    let size = disk.len() as u64;
    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, size).unwrap();
    assert!(analysis
        .anomalies
        .iter()
        .any(|a| matches!(a.kind, AnomalyKind::PrePartitionSpace { .. })));
}

#[test]
fn analyse_detects_post_partition_space() {
    // Disk has 2000 sectors; partition ends at LBA 999 — 1000 sectors trailing
    let entry = make_entry(0x80, 0x83, 1, 999);
    let disk = make_disk(2000, &[(&entry, 0)]);
    let size = disk.len() as u64;
    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, size).unwrap();
    assert!(analysis
        .anomalies
        .iter()
        .any(|a| matches!(a.kind, AnomalyKind::PostPartitionSpace { .. })));
}

#[test]
fn analyse_detects_wiped_boot_code() {
    let disk = make_disk(100, &[]); // all-zero boot code
    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, 100 * 512).unwrap();
    assert!(analysis
        .anomalies
        .iter()
        .any(|a| a.kind == AnomalyKind::WipedBootCode));
}

#[test]
fn analyse_identifies_boot_code() {
    let mut disk = make_disk(100, &[]);
    // Inject GRUB 2 pattern
    disk[0] = 0xEB;
    disk[1] = 0x63;
    disk[2] = 0x90;
    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, 100 * 512).unwrap();
    assert_eq!(analysis.boot_code_id, BootCodeId::Grub2);
}

#[test]
fn analyse_returns_partition_summary() {
    let entry = make_entry(0x80, 0x83, 2048, 4096);
    let disk = make_disk(10000, &[(&entry, 0)]);
    let size = disk.len() as u64;
    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, size).unwrap();
    assert_eq!(analysis.partitions.len(), 1);
    assert_eq!(analysis.partitions[0].lba_start, 2048);
    assert_eq!(analysis.partitions[0].declared_type, TypeCode(0x83));
}

#[test]
fn analyse_disk_serial_populated() {
    let mut disk = make_disk(100, &[]);
    disk[440..444].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, 100 * 512).unwrap();
    assert_eq!(analysis.mbr.disk_serial, 0xDEADBEEF);
}

#[test]
fn analyse_signature_mismatch_detected() {
    // Declare partition as NTFS (0x07) but write LUKS magic in its first sector.
    // LUKS magic is in the first 6 bytes — detectable from a single 512-byte read.
    let total_sectors = 10000u64;
    let lba_start = 128u32;
    let entry = make_entry(0x80, 0x07, lba_start, 1000); // declared NTFS
    let mut disk = make_disk(total_sectors, &[(&entry, 0)]);
    // Write LUKS magic at the start of the partition's first sector.
    let part_offset = lba_start as usize * 512;
    disk[part_offset..part_offset + 6].copy_from_slice(b"LUKS\xba\xbe");
    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, total_sectors * 512).unwrap();
    // declared NTFS, detected LUKS → mismatch
    assert!(
        analysis.anomalies.iter().any(|a| matches!(
            &a.kind,
            AnomalyKind::SignatureMismatch { declared, detected, .. }
            if *declared == TypeCode(0x07) && *detected == DetectedFs::Luks
        )),
        "expected SignatureMismatch NTFS/LUKS, got: {:#?}",
        analysis.anomalies
    );
}

// ── Coverage: partition.rs uncovered paths ────────────────────────────────────

#[test]
fn chs_to_lba_valid_returns_some() {
    let chs = Chs {
        cylinder: 0,
        head: 1,
        sector: 1,
    };
    // LBA = 0 * 255 * 63 + 1 * 63 + (1 - 1) = 63
    assert_eq!(chs.to_lba(255, 63), Some(63));
}

#[test]
fn chs_to_lba_zero_hpc_returns_none() {
    let chs = Chs {
        cylinder: 0,
        head: 0,
        sector: 1,
    };
    assert!(chs.to_lba(0, 63).is_none());
}

#[test]
fn chs_to_lba_zero_spt_returns_none() {
    let chs = Chs {
        cylinder: 0,
        head: 0,
        sector: 1,
    };
    assert!(chs.to_lba(255, 0).is_none());
}

#[test]
fn partition_family_linux_swap() {
    assert_eq!(TypeCode(0x82).family(), PartitionFamily::LinuxSwap);
}

#[test]
fn partition_family_linux_lvm() {
    assert_eq!(TypeCode(0x8E).family(), PartitionFamily::LinuxLvm);
}

#[test]
fn partition_family_linux_raid() {
    assert_eq!(TypeCode(0xFD).family(), PartitionFamily::LinuxRaid);
}

#[test]
fn partition_family_freebsd() {
    assert_eq!(TypeCode(0xA5).family(), PartitionFamily::FreeBsd);
}

#[test]
fn partition_family_openbsd() {
    assert_eq!(TypeCode(0xA6).family(), PartitionFamily::OpenBsd);
}

#[test]
fn partition_family_netbsd() {
    assert_eq!(TypeCode(0xA9).family(), PartitionFamily::NetBsd);
}

#[test]
fn partition_family_hfs() {
    assert_eq!(TypeCode(0xAF).family(), PartitionFamily::Hfs);
    assert_eq!(TypeCode(0xAB).family(), PartitionFamily::Hfs);
}

#[test]
fn partition_family_efi_system() {
    assert_eq!(TypeCode(0xEF).family(), PartitionFamily::EfiSystem);
}

#[test]
fn partition_family_vmware() {
    assert_eq!(TypeCode(0xFB).family(), PartitionFamily::Vmware);
    assert_eq!(TypeCode(0xFC).family(), PartitionFamily::Vmware);
}

#[test]
fn partition_family_windows_recovery() {
    assert_eq!(TypeCode(0x27).family(), PartitionFamily::WindowsRecovery);
}

#[test]
fn partition_family_windows_dynamic() {
    assert_eq!(TypeCode(0x42).family(), PartitionFamily::WindowsDynamic);
}

#[test]
fn partition_family_unknown() {
    assert_eq!(TypeCode(0xCC).family(), PartitionFamily::Unknown(0xCC));
}

#[test]
fn type_code_name_known_values() {
    assert_eq!(TypeCode(0x00).name(), "Empty");
    assert_eq!(TypeCode(0x07).name(), "NTFS / exFAT / IFS");
    assert_eq!(TypeCode(0x83).name(), "Linux");
    assert_eq!(TypeCode(0xEE).name(), "GPT Protective MBR");
}

#[test]
fn type_code_name_unknown() {
    assert_eq!(TypeCode(0xCC).name(), "Unknown");
}

#[test]
fn lba_end_saturates_on_overflow() {
    // lba_start = u32::MAX, lba_count = u32::MAX → saturating result
    let entry = make_entry(0x00, 0x83, u32::MAX, u32::MAX);
    let s = make_sector(&[(&entry, 0)]);
    let mbr = parse_mbr_sector(&s).unwrap();
    // Should not panic — saturating arithmetic
    let _ = mbr.entries[0].lba_end();
}

// ── Coverage: boot_code.rs uncovered paths ────────────────────────────────────

#[test]
fn identify_grub_legacy_by_jmp_opcode() {
    let mut code = [0u8; 446];
    code[0] = 0xEB;
    code[1] = 0x48;
    code[2] = 0x90;
    assert_eq!(
        mbr_forensic::boot_code::identify(&code),
        BootCodeId::GrubLegacy
    );
}

#[test]
fn identify_syslinux_by_name() {
    let mut code = [0u8; 446];
    code[3..11].copy_from_slice(b"SYSLINUX");
    assert_eq!(
        mbr_forensic::boot_code::identify(&code),
        BootCodeId::Syslinux
    );
}

#[test]
fn identify_windows_vista_by_pattern() {
    let mut code = [0u8; 446];
    code[0..7].copy_from_slice(&[0x33, 0xC0, 0x8E, 0xD0, 0xBC, 0x00, 0x7C]);
    code[424..431].copy_from_slice(b"BOOTMGR");
    assert_eq!(
        mbr_forensic::boot_code::identify(&code),
        BootCodeId::WindowsVista
    );
}

// ── Coverage: entropy.rs uncovered paths ─────────────────────────────────────

#[test]
fn is_uniform_true_for_same_bytes() {
    assert!(entropy::is_uniform(&[0xABu8; 64]));
}

#[test]
fn is_uniform_false_for_mixed_bytes() {
    assert!(!entropy::is_uniform(&[0, 1, 0, 1]));
}

#[test]
fn is_uniform_true_for_single_byte() {
    assert!(entropy::is_uniform(&[0x42]));
}

// ── Coverage: signature.rs uncovered paths ────────────────────────────────────

#[test]
fn detect_unknown_on_nonzero_unrecognised() {
    let mut s = [0u8; 512];
    s[0] = 0xCC; // something that matches no pattern
    assert_eq!(signature::detect(&s), DetectedFs::Unknown);
}

#[test]
fn detect_empty_slice_is_unknown() {
    assert_eq!(signature::detect(&[]), DetectedFs::Unknown);
}

#[test]
fn detect_linux_swap_magic() {
    let mut s = vec![1u8; 4096]; // non-zero so not AllZeros
    s[4086..4096].copy_from_slice(b"SWAPSPACE2");
    assert_eq!(signature::detect(&s), DetectedFs::LinuxSwap);
}

#[test]
fn detect_linux_swap_pagespace() {
    let mut s = vec![1u8; 4096];
    s[4086..4096].copy_from_slice(b"PAGESPACE1");
    assert_eq!(signature::detect(&s), DetectedFs::LinuxSwap);
}

#[test]
fn detect_lvm2_label() {
    let mut s = vec![0u8; 512];
    s[8..16].copy_from_slice(b"LABELONE");
    s[0] = 1; // make it non-zero so AllZeros check passes
    assert_eq!(signature::detect(&s), DetectedFs::LinuxLvm);
}

#[test]
fn detect_fat_mswin41() {
    let mut s = [0u8; 512];
    s[3..11].copy_from_slice(b"MSWIN4.1");
    assert_eq!(signature::detect(&s), DetectedFs::Fat);
}

#[test]
fn detect_fat_mkdosfs() {
    let mut s = [0u8; 512];
    s[3..11].copy_from_slice(b"mkdosfs ");
    assert_eq!(signature::detect(&s), DetectedFs::Fat);
}

// ── Coverage: gap.rs uncovered paths ─────────────────────────────────────────

#[test]
fn gap_no_extents_is_single_post_partition_space() {
    let gaps = compute_gaps(&[], 1, 999, 512);
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0].kind, GapKind::PostPartition);
    assert_eq!(gaps[0].lba_start, 1);
    assert_eq!(gaps[0].lba_end, 999);
}

#[test]
fn gap_partition_starts_at_first_usable_no_pre_gap() {
    let extents = [(1u64, 999u64)];
    let gaps = compute_gaps(&extents, 1, 999, 512);
    assert!(gaps.is_empty());
}

#[test]
fn gap_multiple_inter_partition_gaps() {
    let extents = [(1u64, 100u64), (200u64, 300u64), (400u64, 499u64)];
    let gaps = compute_gaps(&extents, 1, 999, 512);
    // Between 100-199, between 300-399, after 499-999
    assert_eq!(gaps.len(), 3);
    assert_eq!(gaps[0].kind, GapKind::Between);
    assert_eq!(gaps[1].kind, GapKind::Between);
    assert_eq!(gaps[2].kind, GapKind::PostPartition);
}

// ── Coverage: analyse.rs uncovered paths ─────────────────────────────────────

#[test]
fn analyse_no_bootable_flagged_as_info() {
    // Active partitions but none bootable
    let entry = make_entry(0x00, 0x83, 2048, 1000); // status=0x00 (not bootable)
    let mut disk = make_disk(5000, &[(&entry, 0)]);
    disk[0] = 0xEB;
    disk[1] = 0x63;
    disk[2] = 0x90; // GRUB2 boot code
    let size = disk.len() as u64;
    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, size).unwrap();
    assert!(analysis
        .anomalies
        .iter()
        .any(|a| a.kind == AnomalyKind::NoBootablePartition));
}

#[test]
fn analyse_detects_erased_boot_code() {
    let mut disk = make_disk(100, &[]);
    // All 0xFF in boot code area
    disk[..446].fill(0xFF);
    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, 100 * 512).unwrap();
    assert!(analysis
        .anomalies
        .iter()
        .any(|a| a.kind == AnomalyKind::ErasedBootCode));
}

#[test]
fn analyse_detects_unknown_boot_code() {
    let mut disk = make_disk(100, &[]);
    // Non-zero, non-matching boot code (but also not all-ones/zeros)
    disk[0] = 0xCC;
    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, 100 * 512).unwrap();
    assert!(analysis
        .anomalies
        .iter()
        .any(|a| a.kind == AnomalyKind::UnknownBootCode));
}

#[test]
fn analyse_disk_size_zero_skips_gap_analysis() {
    let entry = make_entry(0x80, 0x83, 2048, 4096);
    let mut disk = make_disk(10000, &[(&entry, 0)]);
    disk[0] = 0xEB;
    disk[1] = 0x63;
    disk[2] = 0x90;
    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, 0).unwrap(); // disk_size=0 → skip gaps
    assert!(
        analysis.gaps.is_empty(),
        "gaps should be empty when disk_size=0"
    );
}

#[test]
fn analyse_inter_partition_gap_detected() {
    let e0 = make_entry(0x80, 0x83, 100, 100); // ends at LBA 199
    let e1 = make_entry(0x00, 0x83, 400, 100); // starts at LBA 400 — gap 200-399
    let mut disk = make_disk(2000, &[(&e0, 0), (&e1, 1)]);
    disk[0] = 0xEB;
    disk[1] = 0x63;
    disk[2] = 0x90;
    let size = disk.len() as u64;
    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, size).unwrap();
    assert!(analysis.anomalies.iter().any(|a| matches!(
        &a.kind, AnomalyKind::InterPartitionGap { lba_start, lba_end }
        if *lba_start == 200 && *lba_end == 399
    )));
}

#[test]
fn analyse_no_signature_mismatch_when_types_match() {
    // Declare FAT32, write FAT signature — no mismatch expected
    let lba_start = 128u32;
    let entry = make_entry(0x80, 0x0C, lba_start, 1000); // FAT32 LBA
    let mut disk = make_disk(5000, &[(&entry, 0)]);
    disk[0] = 0xEB;
    disk[1] = 0x63;
    disk[2] = 0x90;
    let part_off = lba_start as usize * 512;
    disk[part_off + 3..part_off + 11].copy_from_slice(b"MSDOS5.0");
    let size = disk.len() as u64;
    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, size).unwrap();
    assert!(!analysis
        .anomalies
        .iter()
        .any(|a| matches!(&a.kind, AnomalyKind::SignatureMismatch { .. })));
}

// ── Coverage: EBR chain paths ─────────────────────────────────────────────────

fn make_ebr_sector(
    logical_type: u8,
    logical_start: u32,
    logical_count: u32,
    next_lba_rel: u32, // relative to ext_start; 0 = end of chain
    slack_byte: u8,
) -> Vec<u8> {
    let mut s = vec![0u8; 512];
    s[510] = 0x55;
    s[511] = 0xAA;
    // entry 0: logical partition
    s[446] = 0x00;
    s[450] = logical_type;
    s[454..458].copy_from_slice(&logical_start.to_le_bytes());
    s[458..462].copy_from_slice(&logical_count.to_le_bytes());
    // entry 1: next EBR
    s[462..466].fill(0);
    s[462 + 4] = 0; // type=0
    s[462 + 8..462 + 12].copy_from_slice(&next_lba_rel.to_le_bytes());
    s[462 + 12..462 + 16].copy_from_slice(&1u32.to_le_bytes()); // count=1
                                                                // slack bytes at 478-509
    if slack_byte != 0 {
        s[478] = slack_byte;
    }
    s
}

#[test]
fn analyse_ebr_chain_traversal() {
    // Extended partition at LBA 1000; EBR at LBA 1000 with one logical partition
    let ext_lba = 1000u32;
    let ext_count = 2000u32;
    let ext_entry = make_entry(0x80, 0x05, ext_lba, ext_count);

    // Disk: 5000 sectors; EBR sector at LBA 1000
    let mut disk = vec![0u8; 5000 * 512];
    // Write MBR
    let mbr_sec = make_sector(&[(&ext_entry, 0)]);
    disk[0..512].copy_from_slice(&mbr_sec);
    disk[0] = 0xEB;
    disk[1] = 0x63;
    disk[2] = 0x90; // GRUB2 bootcode

    // Write EBR at LBA 1000 (end of chain — next_lba_rel=0)
    let ebr = make_ebr_sector(0x83, 1, 100, 0, 0);
    let ebr_off = ext_lba as usize * 512;
    disk[ebr_off..ebr_off + 512].copy_from_slice(&ebr);

    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, 5000 * 512).unwrap();
    assert!(
        !analysis.ebr_chain.entries.is_empty(),
        "EBR chain should have one entry"
    );
    assert!(!analysis.ebr_chain.had_cycle);
    assert!(!analysis.ebr_chain.depth_exceeded);
}

#[test]
fn analyse_ebr_bad_signature_terminates_cleanly() {
    // Extended partition at LBA 100; EBR at LBA 100 with BAD signature
    let ext_entry = make_entry(0x80, 0x05, 100, 200);
    let mut disk = vec![0u8; 1000 * 512];
    let mbr_sec = make_sector(&[(&ext_entry, 0)]);
    disk[0..512].copy_from_slice(&mbr_sec);
    disk[0] = 0xEB;
    disk[1] = 0x63;
    disk[2] = 0x90;
    // EBR at LBA 100: DO NOT write 0x55AA — bad signature
    // Leave as all-zeros (no signature)

    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, 1000 * 512).unwrap();
    // EBR chain should be empty (bad sig → terminated)
    assert!(analysis.ebr_chain.entries.is_empty());
}

#[test]
fn analyse_ebr_slack_data_detected() {
    let ext_lba = 100u32;
    let ext_entry = make_entry(0x80, 0x05, ext_lba, 500);
    let mut disk = vec![0u8; 2000 * 512];
    let mbr_sec = make_sector(&[(&ext_entry, 0)]);
    disk[0..512].copy_from_slice(&mbr_sec);
    disk[0] = 0xEB;
    disk[1] = 0x63;
    disk[2] = 0x90;

    // EBR with slack data (byte 0xAB in the slack area)
    let ebr = make_ebr_sector(0x83, 1, 50, 0, 0xAB);
    let ebr_off = ext_lba as usize * 512;
    disk[ebr_off..ebr_off + 512].copy_from_slice(&ebr);

    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, 2000 * 512).unwrap();
    assert!(
        analysis
            .anomalies
            .iter()
            .any(|a| matches!(&a.kind, AnomalyKind::EbrSlackData { .. })),
        "expected EbrSlackData anomaly"
    );
}

#[test]
fn analyse_ebr_cycle_detected() {
    // EBR at LBA 100 → next relative = 0 should terminate, but let's set it to 0 (self)
    // actually to create a cycle: EBR at 100, next = 100 (rel to ext_start=100, so abs=200)
    // Then EBR at 200 points back to 100 (rel=0 from ext_start=100 = LBA 100, already visited)
    let ext_lba = 100u32;
    let ext_entry = make_entry(0x80, 0x05, ext_lba, 1000);
    let mut disk = vec![0u8; 5000 * 512];
    let mbr_sec = make_sector(&[(&ext_entry, 0)]);
    disk[0..512].copy_from_slice(&mbr_sec);
    disk[0] = 0xEB;
    disk[1] = 0x63;
    disk[2] = 0x90;

    // EBR at LBA 100: next_lba_rel = 100 → abs = 100 + 100 = 200
    let ebr1 = make_ebr_sector(0x83, 1, 50, 100, 0);
    disk[100 * 512..101 * 512].copy_from_slice(&ebr1);

    // EBR at LBA 200: next_lba_rel = 0 → abs = 100 + 0 = 100 (already visited!)
    let ebr2 = make_ebr_sector(0x83, 1, 50, 0, 0);
    // Override entry1 to point back: next_lba_rel = 0 → abs = ext(100) + 0 = 100
    // Actually with next_lba_rel=0 it terminates (lba_start=0 breaks). Let me use a
    // non-zero that wraps: next_lba_rel pointing to 100 → lba_start = 100 - 100 = 0... nope
    // Better: EBR at 200, next points to abs 100: relative to ext_start=100 → lba_start=0
    // That terminates. Let me instead make EBR at 100 point to itself directly.
    // EBR at 100, next_lba_rel = 0 (self-referential when ext_start+0 = ext_start = 100)
    // ... but lba_start=0 is the "end of chain" sentinel. Use 100 as next_lba_rel:
    // abs = ext_start(100) + 100 = 200 → EBR at 200 → visited = {100, 200}
    // EBR at 200 with next_lba_rel = 0 (abs=100) → lba_start=0 → break (sentinel)
    // To get a cycle: EBR at 200, next_lba_rel = 100 → abs = 300; EBR at 300 → next_lba_rel = 100 → abs = 200 (visited!)
    let ebr2_cycle = make_ebr_sector(0x83, 1, 50, 100, 0); // next abs = 100+100=200 (visited)
    disk[200 * 512..201 * 512].copy_from_slice(&ebr2_cycle);

    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, 5000 * 512).unwrap();
    assert!(
        analysis
            .anomalies
            .iter()
            .any(|a| a.kind == AnomalyKind::EbrCycle),
        "expected EbrCycle anomaly, got: {:#?}",
        analysis.anomalies
    );
}

// ── Defensive: crafted/malicious/corrupted inputs ────────────────────────────

#[test]
fn parse_mbr_larger_than_512_bytes_succeeds() {
    // Input larger than 512 bytes — should read only first 512
    let mut s = vec![0u8; 1024];
    s[510] = 0x55;
    s[511] = 0xAA;
    assert!(parse_mbr_sector(&s).is_ok());
}

#[test]
fn parse_mbr_empty_slice_returns_too_short() {
    assert!(matches!(parse_mbr_sector(&[]), Err(Error::TooShort(0))));
}

#[test]
fn analyse_partition_lba_max_does_not_panic() {
    // Adversarial: lba_start + lba_count = u32::MAX — should not panic
    let entry = make_entry(0x80, 0x83, 0, u32::MAX);
    let mut disk = make_disk(100, &[(&entry, 0)]);
    disk[0] = 0xEB;
    disk[1] = 0x63;
    disk[2] = 0x90;
    let mut c = Cursor::new(disk);
    let _ = analyse(&mut c, 100 * 512).unwrap(); // must not panic
}

#[test]
fn analyse_all_entries_residual_does_not_panic() {
    // Four residual entries (type=0 but non-zero LBA)
    let e: [u8; 16] = make_entry(0x00, 0x00, u32::MAX, u32::MAX);
    let mut disk = make_disk(100, &[(&e, 0), (&e, 1), (&e, 2), (&e, 3)]);
    disk[0] = 0xEB;
    disk[1] = 0x63;
    disk[2] = 0x90;
    let mut c = Cursor::new(disk);
    let analysis = analyse(&mut c, 100 * 512).unwrap();
    assert_eq!(
        analysis
            .anomalies
            .iter()
            .filter(|a| matches!(&a.kind, AnomalyKind::ResidualEntry { .. }))
            .count(),
        4
    );
}

#[test]
fn ebr_chain_overflow_next_lba_terminates() {
    // EBR at ext_start = u64::MAX / 2; next_lba_rel = u32::MAX
    // ext_start + next_lba_rel would overflow — walk must terminate, not panic
    let ext_lba = 100u32;
    let ext_entry = make_entry(0x80, 0x05, ext_lba, 500);
    let mut disk = vec![0u8; 5000 * 512];
    let mbr_sec = make_sector(&[(&ext_entry, 0)]);
    disk[0..512].copy_from_slice(&mbr_sec);
    disk[0] = 0xEB;
    disk[1] = 0x63;
    disk[2] = 0x90;

    // EBR at LBA 100: next_lba_rel = u32::MAX → abs = 100 + u32::MAX overflows
    let mut ebr = make_ebr_sector(0x83, 1, 50, 0, 0);
    // Patch entry1 lba_start to u32::MAX
    ebr[462 + 8..462 + 12].copy_from_slice(&u32::MAX.to_le_bytes());
    ebr[462 + 12..462 + 16].copy_from_slice(&1u32.to_le_bytes());
    ebr[462 + 4] = 0x83; // non-zero type so it's not skipped
    disk[100 * 512..101 * 512].copy_from_slice(&ebr);

    let mut c = Cursor::new(disk);
    let _ = analyse(&mut c, 5000 * 512).unwrap(); // must not panic
}

#[test]
fn analyse_truncated_disk_reader_does_not_panic() {
    // Disk claims 10000 sectors but reader has only 512 bytes (MBR only)
    let entry = make_entry(0x80, 0x83, 1000, 5000);
    let mbr = make_sector(&[(&entry, 0)]);
    let mut c = Cursor::new(mbr.to_vec());
    // disk_size = 10000 * 512 but reader has only 512 bytes
    // read_partition_first_sector will fail, but analyse should handle gracefully
    let result = analyse(&mut c, 10000 * 512);
    // May succeed (detected_fs=None) or fail with Io; must not panic
    let _ = result;
}
