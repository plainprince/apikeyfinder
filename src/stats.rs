use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Shared, lock-free pipeline counters for progress logging and the final summary.
#[derive(Default)]
pub struct Stats {
    pub warcs_total: AtomicUsize,
    pub warcs_downloaded: AtomicUsize,
    pub warcs_failed: AtomicUsize,
    /// WARC files skipped because the checkpoint says they are already done.
    pub warcs_cached: AtomicUsize,
    pub download_bytes: AtomicU64,
    pub split_done: AtomicUsize,
    pub chunks_written: AtomicUsize,
    pub chunk_bytes: AtomicU64,
    pub records_kept: AtomicU64,
    pub records_skipped: AtomicU64,
    pub records_invalid: AtomicU64,
    pub scans_done: AtomicUsize,
    pub scans_failed: AtomicUsize,
    pub findings_inserted: AtomicU64,
    pub unparsed_findings: AtomicU64,
    pub spill_events: AtomicU64,
    pub spilled_findings: AtomicU64,
    pub spilled_bytes: AtomicU64,
    pub downloads_selected_bytes: AtomicU64,
    /// Findings whose source WARC record was extracted (`artifact` field set).
    pub artifacts_attached: AtomicU64,
}

impl Stats {
    pub fn add(&self, field: &AtomicU64, n: u64) {
        field.fetch_add(n, Ordering::Relaxed);
    }

    pub fn inc_usize(&self, field: &AtomicUsize) {
        field.fetch_add(1, Ordering::Relaxed);
    }
}
