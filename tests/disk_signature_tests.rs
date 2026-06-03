//! Tier 1 — NT disk-signature forensics.
//!
//! The 4-byte signature at MBR offset 440 keys Windows `MountedDevices`/BCD.
//! Two disks sharing the same non-zero signature indicates one was cloned or
//! imaged from the other (Windows marks the duplicate offline). A Windows MBR
//! whose signature is zero is consistent with a wiped/re-created boot record.

use mbr_forensic::{
    analyse,
    disk_signature::{find_signature_collisions, SignatureCollision},
    findings::AnomalyKind,
};
use std::io::Cursor;

// ── Cross-disk collision detection (pure utility) ────────────────────────────

#[test]
fn distinct_signatures_have_no_collisions() {
    assert!(find_signature_collisions(&[0x11111111, 0x22222222, 0x33333333]).is_empty());
}

#[test]
fn duplicate_signature_is_a_collision() {
    let collisions = find_signature_collisions(&[0xAABBCCDD, 0x22222222, 0xAABBCCDD]);
    assert_eq!(collisions.len(), 1);
    let c: &SignatureCollision = &collisions[0];
    assert_eq!(c.signature, 0xAABBCCDD);
    assert_eq!(c.members, vec![0, 2]);
}

#[test]
fn zero_signatures_never_collide() {
    // Zero is the "unset" convention, not a real shared identity.
    assert!(find_signature_collisions(&[0, 0, 0]).is_empty());
}

#[test]
fn three_way_collision_lists_all_members() {
    let collisions = find_signature_collisions(&[7, 7, 9, 7]);
    assert_eq!(collisions.len(), 1);
    assert_eq!(collisions[0].members, vec![0, 1, 3]);
}

// ── Single-disk: Windows MBR with zeroed signature ───────────────────────────

fn disk_with_boot_and_serial(boot: &[u8], serial: u32) -> Vec<u8> {
    let mut disk = vec![0u8; 4096 * 512];
    let n = boot.len().min(446);
    disk[..n].copy_from_slice(&boot[..n]);
    disk[440..444].copy_from_slice(&serial.to_le_bytes());
    disk[510] = 0x55;
    disk[511] = 0xAA;
    disk
}

fn windows7_boot() -> Vec<u8> {
    let mut boot = vec![0u8; 446];
    boot[0..7].copy_from_slice(&[0x33, 0xC0, 0x8E, 0xD0, 0xBC, 0x00, 0x7C]);
    boot[418..425].copy_from_slice(b"BOOTMGR");
    boot
}

#[test]
fn windows_mbr_with_zero_signature_is_flagged() {
    let analysis = analyse(
        &mut Cursor::new(disk_with_boot_and_serial(&windows7_boot(), 0)),
        4096 * 512,
    )
    .unwrap();
    assert!(
        analysis
            .anomalies
            .iter()
            .any(|a| matches!(a.kind, AnomalyKind::ZeroDiskSignature)),
        "expected ZeroDiskSignature, got: {:?}",
        analysis.anomalies.iter().map(|a| a.code).collect::<Vec<_>>()
    );
}

#[test]
fn windows_mbr_with_signature_is_not_flagged() {
    let analysis = analyse(
        &mut Cursor::new(disk_with_boot_and_serial(&windows7_boot(), 0xDEADBEEF)),
        4096 * 512,
    )
    .unwrap();
    assert!(!analysis
        .anomalies
        .iter()
        .any(|a| matches!(a.kind, AnomalyKind::ZeroDiskSignature)));
}

#[test]
fn non_windows_zero_signature_is_not_flagged() {
    // Linux/unknown MBRs routinely have a zero signature — not anomalous.
    let analysis = analyse(
        &mut Cursor::new(disk_with_boot_and_serial(&[0xEBu8, 0x63, 0x90], 0)),
        4096 * 512,
    )
    .unwrap();
    assert!(!analysis
        .anomalies
        .iter()
        .any(|a| matches!(a.kind, AnomalyKind::ZeroDiskSignature)));
}
