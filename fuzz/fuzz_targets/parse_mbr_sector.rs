//! Fuzz target: feed arbitrary bytes to `parse_mbr_sector`.
//!
//! Invariants enforced:
//! - Never panics, regardless of input.
//! - Returns `Err` for inputs shorter than 512 bytes.
//! - Returns `Err(BadSignature)` when bytes 510-511 ≠ 0x55AA.
//! - On `Ok`, all field accesses are safe (no bounds panics).
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Must never panic.
    let result = mbr_forensic::parse_mbr_sector(data);

    if data.len() < 512 {
        assert!(
            matches!(result, Err(mbr_forensic::Error::TooShort(_))),
            "expected TooShort for input of len {}",
            data.len()
        );
        return;
    }

    match result {
        Ok(sector) => {
            // Exercise all field accessors — any panic here is a bug.
            let _ = sector.disk_serial;
            let _ = sector.reserved;
            let _ = sector.signature;
            for entry in &sector.entries {
                let _ = entry.is_empty();
                let _ = entry.is_bootable();
                let _ = entry.is_extended();
                let _ = entry.lba_end();
                let _ = entry.chs_first.to_lba(255, 63);
                let _ = entry.chs_last.to_lba(255, 63);
                let _ = entry.type_code.name();
                let _ = entry.type_code.family();
            }
            let _ = mbr_forensic::boot_code::identify(&sector.boot_code);
        }
        Err(mbr_forensic::Error::BadSignature(_)) => {
            // Bytes 510-511 ≠ 0x55AA — expected.
        }
        Err(mbr_forensic::Error::TooShort(_)) => {
            // Should not happen since we checked len >= 512 above.
            panic!("unexpected TooShort for 512+ byte input");
        }
        Err(mbr_forensic::Error::Io(_)) => {
            // parse_mbr_sector is pure — no I/O possible.
            panic!("unexpected Io error from parse_mbr_sector");
        }
    }
});
