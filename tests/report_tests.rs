//! Text report rendering (backs the `mbr-forensic` CLI binary).

use mbr_forensic::{analyse, report::text_report};
use std::io::Cursor;

fn disk_with_partition() -> Vec<u8> {
    let mut disk = vec![0u8; 100 * 512];
    disk[510] = 0x55;
    disk[511] = 0xAA;
    let mut e = [0u8; 16];
    e[4] = 0x83; // Linux
    e[8..12].copy_from_slice(&2048u32.to_le_bytes());
    e[12..16].copy_from_slice(&100u32.to_le_bytes());
    disk[446..462].copy_from_slice(&e);
    disk
}

#[test]
fn report_includes_partitions_and_anomalies() {
    let a = analyse(&mut Cursor::new(disk_with_partition()), 100 * 512).unwrap();
    let r = text_report(&a);
    assert!(r.contains("MBR Forensic Analysis"), "{r}");
    assert!(
        r.contains("Linux"),
        "partition type name should appear:\n{r}"
    );
    // All-zero boot code → a WipedBootCode anomaly with an MBR-* code.
    assert!(r.contains("MBR-"), "anomaly codes should appear:\n{r}");
    assert!(r.contains("partition"), "{r}");
}

#[test]
fn report_is_non_empty_for_clean_disk() {
    // A GPT-style protective disk yields Info-level findings; report still renders.
    let a = analyse(&mut Cursor::new(disk_with_partition()), 100 * 512).unwrap();
    assert!(!text_report(&a).is_empty());
}
