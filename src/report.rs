//! Human-readable text rendering of an [`MbrAnalysis`].
//!
//! Kept dependency-free (plain `String` building) so the `mbr-forensic` binary
//! needs no argument-parsing or formatting crates. Machine-readable output is
//! available via the `serde` feature (`serde_json::to_string(&analysis)`).

use core::fmt::Write as _;

use crate::findings::MbrAnalysis;

/// Render a forensic analysis as a multi-line text report.
///
/// The format is stable enough to grep but is intended for human eyes; programs
/// should consume the typed [`MbrAnalysis`] or its JSON serialization instead.
#[must_use]
pub fn text_report(a: &MbrAnalysis) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "MBR Forensic Analysis");
    let _ = writeln!(
        s,
        "  disk signature : {:#010x}",
        a.disk_serial
    );
    let _ = writeln!(s, "  boot code      : {:?}", a.boot_code_id);
    let _ = writeln!(s, "  partitioning   : {:?}", a.era);

    let _ = writeln!(s, "\nPartition table ({} entries):", a.partitions.len());
    if a.partitions.is_empty() {
        let _ = writeln!(s, "  (no primary partitions)");
    }
    for p in &a.partitions {
        let fs = match p.detected_fs {
            Some(fs) => format!("{fs:?}"),
            None => "-".to_string(),
        };
        let _ = writeln!(
            s,
            "  [{}] {:<24} LBA {:>12}..={:<12}  fs={}",
            p.index,
            p.declared_type.name(),
            p.lba_start,
            p.lba_end,
            fs,
        );
    }

    if a.anomalies.is_empty() {
        let _ = writeln!(s, "\nAnomalies: none");
    } else {
        let _ = writeln!(s, "\nAnomalies ({}):", a.anomalies.len());
        for an in &a.anomalies {
            let _ = writeln!(s, "  {an}");
        }
    }

    #[cfg(feature = "gpt")]
    if let Some(gpt) = &a.gpt {
        let _ = writeln!(
            s,
            "\nGPT cross-check: {} partition entries, {} GPT anomalies",
            gpt.partitions.len(),
            gpt.anomalies.len(),
        );
    }

    match a.max_severity() {
        Some(sev) => {
            let _ = writeln!(s, "\nHighest severity: {sev}");
        }
        None => {
            let _ = writeln!(s, "\nHighest severity: none (clean)");
        }
    }
    s
}
