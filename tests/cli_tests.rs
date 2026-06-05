//! End-to-end tests for the `mbr-forensic` binary.
//!
//! Spawns the compiled binary (via `CARGO_BIN_EXE_*`) so the CLI's `main` is
//! exercised end-to-end, including argument parsing, output, and exit codes.

use std::path::PathBuf;
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_mbr-forensic"))
}

/// A minimal MBR with one Linux partition and an all-zero boot region (which
/// yields Info/Low anomalies — enough to exercise the report path).
fn synthetic_disk() -> Vec<u8> {
    let mut d = vec![0u8; 100 * 512];
    d[510] = 0x55;
    d[511] = 0xAA;
    d[446 + 4] = 0x83; // Linux partition type
    d[446 + 8..446 + 12].copy_from_slice(&2048u32.to_le_bytes());
    d[446 + 12..446 + 16].copy_from_slice(&100u32.to_le_bytes());
    d
}

fn write_tmp(tag: &str, bytes: &[u8]) -> PathBuf {
    let p = std::env::temp_dir().join(format!("mbr_e2e_{}_{tag}.img", std::process::id()));
    std::fs::write(&p, bytes).unwrap();
    p
}

#[test]
fn analyses_disk_as_text() {
    let p = write_tmp("text", &synthetic_disk());
    let out = bin().arg(&p).output().unwrap();
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("MBR Forensic Analysis"), "{s}");
    assert!(s.contains("Linux"), "{s}");
    let _ = std::fs::remove_file(&p);
}

#[cfg(feature = "serde")]
#[test]
fn json_output_emits_structure() {
    let p = write_tmp("json", &synthetic_disk());
    let out = bin()
        .args(["--json", p.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success() || out.status.code() == Some(1));
    assert!(String::from_utf8_lossy(&out.stdout).contains("disk_serial"));
    let _ = std::fs::remove_file(&p);
}

#[test]
fn no_args_prints_usage() {
    let out = bin().output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("usage"));
}

#[test]
fn help_flag_prints_usage() {
    let out = bin().arg("--help").output().unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn missing_file_errors() {
    let out = bin().arg("/nonexistent/nope.img").output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("cannot open"));
}
