//! Serialization of the analysis result to JSON (feature = "serde").
#![cfg(feature = "serde")]

use mbr_forensic::analyse;
use std::io::Cursor;

#[test]
fn analysis_serializes_to_json() {
    // A disk with at least one anomaly (all-zero boot code → WipedBootCode).
    let mut disk = vec![0u8; 100 * 512];
    disk[510] = 0x55;
    disk[511] = 0xAA;
    disk[446..462].copy_from_slice(&{
        let mut e = [0u8; 16];
        e[4] = 0x83;
        e[8..12].copy_from_slice(&2048u32.to_le_bytes());
        e[12..16].copy_from_slice(&100u32.to_le_bytes());
        e
    });

    let analysis = analyse(&mut Cursor::new(disk), 100 * 512).unwrap();
    let json = serde_json::to_string(&analysis).expect("MbrAnalysis must serialize");

    assert!(json.contains("\"anomalies\""), "json: {json}");
    assert!(json.contains("MBR-"), "anomaly codes should appear: {json}");
    assert!(json.contains("\"era\""));
}
