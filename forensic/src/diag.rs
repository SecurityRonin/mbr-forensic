//! Forensic-layer diagnostics.
//!
//! Re-exports the parser-layer trace events from [`mbr::diag`] and adds the
//! anomaly-level event that depends on this crate's [`Anomaly`] type. By default
//! every event is a zero-cost no-op; enable the `trace` feature to forward them
//! to the [`tracing`](https://docs.rs/tracing) ecosystem.

pub(crate) use mbr::diag::{analysis_complete, ebr_walk_failed, partition_read_failed};

use crate::findings::Anomaly;

/// An anomaly was recorded by the analysis.
#[cfg(feature = "trace")]
pub(crate) fn anomaly_recorded(a: &Anomaly) {
    tracing::debug!(
        code = a.code,
        severity = %a.severity,
        offset = a.offset,
        note = %a.note,
        "anomaly recorded"
    );
}
#[cfg(not(feature = "trace"))]
#[inline]
pub(crate) fn anomaly_recorded(_a: &Anomaly) {}
