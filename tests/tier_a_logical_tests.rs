//! Tier A — full forensic scrutiny of EBR logical partitions.
//!
//! Logical partitions inside an extended partition must receive the same checks
//! as primaries: overlap detection (a logical overlapping another partition is a
//! hiding/tamper signal), filesystem-signature mismatch, and BPB hidden-sectors
//! relocation mismatch. A logical living *inside* its own extended container is
//! expected and must NOT be reported as an overlap.

use mbr_forensic::{analyse, findings::AnomalyKind, DetectedFs};
use std::io::Cursor;

fn mbr_entry(status: u8, type_code: u8, lba_start: u32, lba_count: u32) -> [u8; 16] {
    let mut e = [0u8; 16];
    e[0] = status;
    e[4] = type_code;
    e[8..12].copy_from_slice(&lba_start.to_le_bytes());
    e[12..16].copy_from_slice(&lba_count.to_le_bytes());
    e
}

/// One EBR sector: logical entry (rel to this EBR) + next-EBR pointer (rel to
/// the extended-partition start). `next_rel == 0` ends the chain.
fn ebr(logical_type: u8, logical_rel_start: u32, logical_count: u32, next_rel: u32) -> [u8; 512] {
    let mut s = [0u8; 512];
    s[510] = 0x55;
    s[511] = 0xAA;
    s[450] = logical_type; // entry0 type (status at 446 left 0)
    s[454..458].copy_from_slice(&logical_rel_start.to_le_bytes());
    s[458..462].copy_from_slice(&logical_count.to_le_bytes());
    s[470..474].copy_from_slice(&next_rel.to_le_bytes()); // entry1 lba_start
    s[474..478].copy_from_slice(&1u32.to_le_bytes()); // entry1 count
    s
}

const SECTORS: u64 = 5000;
const EXT_LBA: u32 = 1000;

/// Disk with a GRUB2 boot stub and an extended container at LBA 1000 (count
/// 3000), plus the given EBR sectors written at absolute LBAs.
fn disk_with_ebrs(ebrs: &[(u32, [u8; 512])]) -> Vec<u8> {
    let mut disk = vec![0u8; (SECTORS * 512) as usize];
    disk[0] = 0xEB;
    disk[1] = 0x63;
    disk[2] = 0x90; // GRUB2 stub → avoids WipedBootCode noise
    disk[510] = 0x55;
    disk[511] = 0xAA;
    let ext = mbr_entry(0x00, 0x05, EXT_LBA, 3000);
    disk[446..462].copy_from_slice(&ext);
    for (lba, sector) in ebrs {
        let off = (*lba as usize) * 512;
        disk[off..off + 512].copy_from_slice(sector);
    }
    disk
}

fn kinds(disk: Vec<u8>) -> Vec<AnomalyKind> {
    analyse(&mut Cursor::new(disk), SECTORS * 512)
        .unwrap()
        .anomalies
        .into_iter()
        .map(|a| a.kind)
        .collect()
}

// ── A1: overlap detection includes logicals ──────────────────────────────────

#[test]
fn overlapping_logical_partitions_are_flagged() {
    // EBR1@1000: logical abs 1100..=2099; chain to EBR2@1200.
    // EBR2@1200: logical abs 1300..=2299 → overlaps the first logical.
    let k = kinds(disk_with_ebrs(&[
        (1000, ebr(0x83, 100, 1000, 200)),
        (1200, ebr(0x83, 100, 1000, 0)),
    ]));
    assert!(
        k.iter()
            .any(|a| matches!(a, AnomalyKind::OverlappingPartitions { .. })),
        "expected overlap between two logical partitions; got {k:?}"
    );
}

#[test]
fn logical_inside_its_container_is_not_an_overlap() {
    // A single logical living inside the extended container must NOT be reported
    // as overlapping the container (false-positive guard).
    let k = kinds(disk_with_ebrs(&[(1000, ebr(0x83, 100, 1000, 0))]));
    assert!(
        !k.iter()
            .any(|a| matches!(a, AnomalyKind::OverlappingPartitions { .. })),
        "a logical inside its container is not an overlap; got {k:?}"
    );
}

// ── A2: logical FS fingerprint + signature mismatch ──────────────────────────

#[test]
fn logical_signature_mismatch_is_flagged() {
    // Logical declared NTFS (0x07) but its first sector is an ext superblock.
    let mut disk = disk_with_ebrs(&[(1000, ebr(0x07, 100, 1000, 0))]);
    let logical_byte = (EXT_LBA as usize + 100) * 512; // abs LBA 1100
    disk[logical_byte + 1080] = 0x53;
    disk[logical_byte + 1081] = 0xEF;
    let k = kinds(disk);
    assert!(
        k.iter().any(|a| matches!(
            a,
            AnomalyKind::SignatureMismatch {
                detected: DetectedFs::Ext,
                ..
            }
        )),
        "expected SignatureMismatch(Ext) on the logical partition; got {k:?}"
    );
}

// ── A2: logical VBR hidden-sectors mismatch ──────────────────────────────────

#[test]
fn logical_vbr_hidden_sectors_mismatch_is_flagged() {
    // Logical at abs LBA 1100 whose NTFS BPB still records a stale hidden=63.
    let mut disk = disk_with_ebrs(&[(1000, ebr(0x07, 100, 1000, 0))]);
    let logical_byte = (EXT_LBA as usize + 100) * 512;
    let v = &mut disk[logical_byte..logical_byte + 512];
    v[3..11].copy_from_slice(b"NTFS    ");
    v[11..13].copy_from_slice(&512u16.to_le_bytes());
    v[13] = 8;
    v[28..32].copy_from_slice(&63u32.to_le_bytes()); // hidden sectors (stale)
    v[510] = 0x55;
    v[511] = 0xAA;
    let k = kinds(disk);
    assert!(
        k.iter()
            .any(|a| matches!(a, AnomalyKind::VbrHiddenSectorsMismatch { .. })),
        "expected VbrHiddenSectorsMismatch on the logical partition; got {k:?}"
    );
}
