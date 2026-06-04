//! Known boot-sector-malware marker detection.
//!
//! The marker data and the matching logic are centralized in the
//! `forensicnomicon` knowledge crate ([`forensicnomicon::bootkit`]); this module
//! re-exports them so existing `mbr_forensic::bootkit::{scan, KNOWN_SIGNATURES}`
//! call sites keep working. A match raises [`crate::AnomalyKind::KnownBootkit`].

pub use forensicnomicon::bootkit::{scan, BootkitMarker, BOOTKIT_MARKERS as KNOWN_SIGNATURES};
