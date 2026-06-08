//! Fuzz target: feed arbitrary bytes as a disk image to `analyse`.
//!
//! This tests the full analysis pipeline including EBR traversal,
//! gap analysis, and filesystem fingerprinting.
//!
//! Invariants enforced:
//! - Never panics.
//! - Returns `Ok` or a well-typed `Err` — no unwrap panics.
//! - All fields of `MbrAnalysis` are accessible without panic.
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    // Clamp disk_size to the actual data length to avoid trivially large gap analysis.
    let disk_size = data.len() as u64;
    let mut cursor = Cursor::new(data);

    let result = mbr_partition_forensic::analyse(&mut cursor, disk_size);

    match result {
        Ok(analysis) => {
            // Access all fields — any panic is a bug.
            let _ = &analysis.anomalies;
            let _ = &analysis.partitions;
            let _ = &analysis.gaps;
            let _ = analysis.disk_serial;
            let _ = analysis.boot_code_id;
            let _ = analysis.ebr_chain.had_cycle;
            let _ = analysis.ebr_chain.depth_exceeded;

            for anomaly in &analysis.anomalies {
                let _ = anomaly.severity;
                let _ = &anomaly.note;
                let _ = anomaly.offset;
            }
            for part in &analysis.partitions {
                let _ = part.lba_start;
                let _ = part.lba_end;
                let _ = part.byte_size;
            }
            for gap in &analysis.gaps {
                let _ = gap.lba_start;
                let _ = gap.lba_end;
                let _ = gap.byte_size;
            }
        }
        Err(mbr_partition_forensic::Error::TooShort(_)) => {}
        Err(mbr_partition_forensic::Error::BadSignature(_)) => {}
        Err(mbr_partition_forensic::Error::Io(_)) => {}
    }
});
