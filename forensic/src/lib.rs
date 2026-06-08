//! # mbr-partition-forensic
//!
//! Forensic-grade Master Boot Record (MBR) analyzer. Goes beyond partition
//! enumeration to surface structural anomalies, slack-space content,
//! anti-forensic indicators, and cross-field inconsistencies that other MBR
//! crates silently ignore.
//!
//! The pure on-disk parser lives in the sibling [`mbr`] crate
//! (`mbr-partition-core`); this crate layers anomaly detection on top and
//! re-exports every parser type so callers need only one dependency.
//!
//! ## Entry points
//!
//! ```no_run
//! use mbr_partition_forensic::{parse_mbr_sector, analyse};
//! use std::fs::File;
//!
//! // Pure parsing from a 512-byte buffer (no I/O required):
//! let buf = [0u8; 512];
//! let sector = parse_mbr_sector(&buf)?;
//!
//! // Full forensic analysis from a seekable reader:
//! let mut f = File::open("disk.img")?;
//! let analysis = analyse(&mut f, 1 << 30)?;
//! for anomaly in &analysis.anomalies {
//!     println!("[{:?}] {}", anomaly.severity, anomaly.note);
//! }
//! # Ok::<(), mbr_partition_forensic::Error>(())
//! ```
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

// Re-export the parser layer so the analyzer presents a single crate surface.
// Existing call sites such as `mbr_partition_forensic::partition::TypeCode` and
// `mbr_partition_forensic::Error` keep working against the parser types.
pub use mbr::{boot_code, carve, disk_signature, ebr, gpt, partition, signature, vbr, Error};

pub mod bootkit;
pub mod entropy;
pub mod findings;
pub mod gap;
pub mod provenance;
pub mod wipe;

mod analyse;
mod diag;

pub use analyse::{analyse, analyse_with_options, AnalyseOptions};
pub use boot_code::BootCodeId;
pub use disk_signature::{find_signature_collisions, SignatureCollision};
pub use ebr::{EbrChain, EbrEntry};
pub use findings::{Anomaly, AnomalyKind, MbrAnalysis, PartitionSummary, Severity};
pub use gap::Gap;
pub use mbr::{parse_mbr_sector, MbrSector};
pub use partition::{Chs, PartitionEntry, PartitionFamily, TypeCode};
pub use provenance::{Alignment, PartitioningEra};
pub use signature::DetectedFs;
