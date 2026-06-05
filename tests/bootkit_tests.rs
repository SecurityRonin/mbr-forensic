//! Tier 2 — known-bootkit / boot-sector-malware marker detection.
//!
//! Boot-sector malware frequently embeds plaintext markers in the MBR code
//! area. The engine scans the 446-byte boot code for an extensible table of
//! documented markers; a match is a definitive tampering indicator.
//!
//! The seed set uses only publicly-documented historical markers (the 1987
//! "Stoned" boot virus) so no byte pattern here is fabricated.

use mbr_forensic::{
    analyse,
    bootkit::{scan, KNOWN_SIGNATURES},
    findings::AnomalyKind,
};
use std::io::Cursor;

#[test]
fn scan_clean_boot_code_finds_nothing() {
    assert!(scan(&[0u8; 446]).is_empty());
}

#[test]
fn scan_detects_stoned_marker() {
    let mut boot = vec![0u8; 446];
    let marker = b"Your PC is now Stoned!";
    boot[0x100..0x100 + marker.len()].copy_from_slice(marker);
    let hits = scan(&boot);
    assert!(hits.contains(&"Stoned"), "got {hits:?}");
}

#[test]
fn scan_dedups_repeated_family_markers() {
    // A boot record containing two Stoned markers reports the family once.
    let mut boot = vec![0u8; 446];
    boot[0x10..0x10 + 22].copy_from_slice(b"Your PC is now Stoned!");
    boot[0x80..0x80 + 18].copy_from_slice(b"LEGALISE MARIJUANA");
    let hits = scan(&boot);
    assert_eq!(
        hits.iter().filter(|&&n| n == "Stoned").count(),
        1,
        "got {hits:?}"
    );
}

#[test]
fn signature_table_is_non_empty() {
    assert!(!KNOWN_SIGNATURES.is_empty());
}

#[test]
fn analyse_flags_known_bootkit() {
    let mut disk = vec![0u8; 4096 * 512];
    let marker = b"Your PC is now Stoned!";
    disk[0x20..0x20 + marker.len()].copy_from_slice(marker);
    disk[510] = 0x55;
    disk[511] = 0xAA;
    let analysis = analyse(&mut Cursor::new(disk), 4096 * 512).unwrap();
    assert!(
        analysis
            .anomalies
            .iter()
            .any(|a| matches!(a.kind, AnomalyKind::KnownBootkit { name: "Stoned" })),
        "got: {:?}",
        analysis
            .anomalies
            .iter()
            .map(|a| a.code)
            .collect::<Vec<_>>()
    );
}
