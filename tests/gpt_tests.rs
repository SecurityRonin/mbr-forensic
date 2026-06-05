//! Tier 1 — GPT/MBR cross-validation.
//!
//! A genuine GPT disk carries a single protective MBR entry (type 0xEE at LBA 1
//! spanning the whole disk) AND an "EFI PART" header at LBA 1. Deviations are
//! data-hiding or tampering indicators:
//!   * hybrid MBR     — 0xEE plus real partitions (legacy-visible, GPT-invisible)
//!   * undersized 0xEE — protective entry that leaves a tail hidden from GPT tools
//!   * hidden GPT      — EFI PART present but no 0xEE advertising it
//!   * spoofed 0xEE    — 0xEE present but no EFI PART backing it

use mbr_forensic::{analyse, findings::AnomalyKind, gpt::has_gpt_header};
use std::io::Cursor;

const SECTORS: u64 = 4096;

fn make_entry(type_code: u8, lba_start: u32, lba_count: u32) -> [u8; 16] {
    let mut e = [0u8; 16];
    e[4] = type_code;
    e[8..12].copy_from_slice(&lba_start.to_le_bytes());
    e[12..16].copy_from_slice(&lba_count.to_le_bytes());
    e
}

/// Build a disk, place entries, and optionally write an "EFI PART" GPT header
/// at LBA 1.
fn build(entries: &[(usize, [u8; 16])], gpt_header: bool) -> Vec<u8> {
    let mut disk = vec![0u8; (SECTORS * 512) as usize];
    disk[510] = 0x55;
    disk[511] = 0xAA;
    for (slot, e) in entries {
        let off = 446 + slot * 16;
        disk[off..off + 16].copy_from_slice(e);
    }
    if gpt_header {
        disk[512..520].copy_from_slice(b"EFI PART");
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

#[test]
fn has_gpt_header_detects_magic() {
    let mut lba1 = [0u8; 512];
    lba1[0..8].copy_from_slice(b"EFI PART");
    assert!(has_gpt_header(&lba1));
    assert!(!has_gpt_header(&[0u8; 512]));
    assert!(!has_gpt_header(&[]));
}

#[test]
fn valid_protective_mbr_is_clean() {
    // Single 0xEE at LBA 1 covering the whole disk + real GPT header.
    let ee = make_entry(0xEE, 1, (SECTORS - 1) as u32);
    let k = kinds(build(&[(0, ee)], true));
    assert!(
        !k.iter().any(|a| matches!(
            a,
            AnomalyKind::HybridMbr { .. }
                | AnomalyKind::ProtectiveMbrUndersized { .. }
                | AnomalyKind::HiddenGpt
                | AnomalyKind::SpoofedProtectiveMbr
        )),
        "unexpected GPT anomaly: {k:?}"
    );
}

#[test]
fn hybrid_mbr_flagged() {
    let ee = make_entry(0xEE, 1, (SECTORS - 1) as u32);
    let ntfs = make_entry(0x07, 2048, 1000);
    let k = kinds(build(&[(0, ee), (1, ntfs)], true));
    assert!(
        k.iter().any(|a| matches!(a, AnomalyKind::HybridMbr { .. })),
        "got {k:?}"
    );
}

#[test]
fn undersized_protective_mbr_flagged() {
    // 0xEE covers only LBA 1..=1000, leaving ~3000 sectors hidden.
    let ee = make_entry(0xEE, 1, 1000);
    let k = kinds(build(&[(0, ee)], true));
    assert!(
        k.iter()
            .any(|a| matches!(a, AnomalyKind::ProtectiveMbrUndersized { .. })),
        "got {k:?}"
    );
}

#[test]
fn hidden_gpt_flagged() {
    // EFI PART present at LBA 1 but the MBR advertises no 0xEE — only a normal
    // partition. GPT-unaware analysis would miss the real GPT layout.
    let ntfs = make_entry(0x07, 2048, 1000);
    let k = kinds(build(&[(0, ntfs)], true));
    assert!(
        k.iter().any(|a| matches!(a, AnomalyKind::HiddenGpt)),
        "got {k:?}"
    );
}

#[test]
fn spoofed_protective_mbr_flagged() {
    // 0xEE present but no EFI PART backing it.
    let ee = make_entry(0xEE, 1, (SECTORS - 1) as u32);
    let k = kinds(build(&[(0, ee)], false));
    assert!(
        k.iter()
            .any(|a| matches!(a, AnomalyKind::SpoofedProtectiveMbr)),
        "got {k:?}"
    );
}
