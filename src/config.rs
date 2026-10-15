use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

pub const GIB: u64 = 1024 * 1024 * 1024;

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub targets: TargetsCfg,
    pub filter: FilterCfg,
    pub download: DownloadCfg,
    pub split: SplitCfg,
    pub scan: ScanCfg,
    pub cache: CacheCfg,
    pub queues: QueuesCfg,
    pub paths: PathsCfg,
    pub progress_interval_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TargetsCfg {
    pub index_collection: String,
    pub index_base_url: String,
    pub data_base_url: String,
    pub url_patterns: Vec<String>,
    pub per_pattern_limit: usize,
    pub min_candidate_files: usize,
    pub target_bytes: u64,
    pub max_index_response_bytes: u64,
    /// Delay between firing individual pattern queries (some CDX frontends 503 under burst load).
    pub pattern_stagger_ms: u64,
    /// Whole-query retry rounds over patterns that failed at the transport level.
    pub max_select_rounds: usize,
    /// Base cool-down between query rounds (multiplied by the round number).
    pub round_cooldown_secs: u64,
    /// Give up after this many consecutive HEAD probes with no usable size
    /// (all-refused or all-zero responses mean we're blocked or misconfigured).
    pub head_probe_abort_after: u32,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FilterCfg {
    pub index: IndexFilterCfg,
    pub records: RecordsFilterCfg,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IndexFilterCfg {
    pub mime_regex: String,
    pub status_regex: String,
    /// Send the mime regex to the CDX server too. Many pywb frontends 404 on
    /// regex-heavy filter values, so this stays off: client-side filtering
    /// below is authoritative either way.
    pub server_mime_filter: bool,
    pub extra_cdx_filters: Vec<String>,
    pub only_warc_path: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RecordsFilterCfg {
    pub warc_type_regex: String,
    pub content_type_regex: String,
    pub min_payload_bytes: u64,
    pub max_payload_bytes: u64,
    pub payload_include_regex: String,
    pub drop_invalid_records: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DownloadCfg {
    pub parallel_fetches: usize,
    pub max_bytes_per_file: u64,
    pub max_retries: u32,
    pub retry_backoff_ms: u64,
    pub connect_timeout_secs: u64,
    pub request_timeout_secs: u64,
    /// Size-probe (HEAD) timeout — kept short so a dead CDN edge fails fast
    /// and the retry picks a fresh connection/DNS answer.
    pub head_timeout_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SplitCfg {
    pub records_per_chunk: usize,
    pub max_chunk_bytes: usize,
    pub max_concurrent: usize,
    pub awk_binary: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScanCfg {
    pub binary: String,
    pub only_verified: bool,
    pub no_update: bool,
    pub log_level: i32,
    pub trufflehog_concurrency: u32,
    pub workers: usize,
    pub extra_args: Vec<String>,
    /// Characters kept on each side of the secret when building the stored
    /// `context` snippet (the whole line is flattened to one line first).
    pub snippet_window_chars: usize,
    /// Skip extracting a source record (`paths.artifacts_dir`) when it is
    /// bigger than this (0 = unlimited; chunks already cap at split.max_chunk_bytes).
    pub artifact_max_bytes: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CacheCfg {
    pub mem_limit_bytes: u64,
    pub spill_dir: PathBuf,
    pub spill_file_bytes: u64,
    pub final_output: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct QueuesCfg {
    pub network_capacity: usize,
    pub network_min_workers: usize,
    pub network_scale_threshold: usize,
    pub network_idle_retire_ms: u64,
    pub network_pool_tick_ms: u64,
    pub disk_workers: usize,
    pub disk_capacity: usize,
    pub ram_capacity: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PathsCfg {
    pub workdir: PathBuf,
    pub keep_warcs: bool,
    pub keep_chunks: bool,
    /// Resume state: download plan + per-WARC completion. Delete it (and
    /// `partials_dir`) to start a completely fresh scan.
    pub checkpoint_file: PathBuf,
    /// Durable per-WARC findings (`<warc>.jsonl`); assembled into
    /// `cache.final_output` at the end of every run.
    pub partials_dir: PathBuf,
    /// The WARC record each finding was found in, saved as plain text
    /// (`<warc>/<chunk>-L<line>.txt`) and referenced by the finding's
    /// `artifact` field. Never purged — findings keep pointing at it.
    pub artifacts_dir: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            targets: TargetsCfg::default(),
            filter: FilterCfg::default(),
            download: DownloadCfg::default(),
            split: SplitCfg::default(),
            scan: ScanCfg::default(),
            cache: CacheCfg::default(),
            queues: QueuesCfg::default(),
            paths: PathsCfg::default(),
            progress_interval_secs: 10,
        }
    }
}

impl Default for TargetsCfg {
    fn default() -> Self {
        Self {
            index_collection: "CC-MAIN-2026-39".into(),
            index_base_url: "https://index.commoncrawl.org".into(),
            data_base_url: "https://data.commoncrawl.org".into(),
            url_patterns: vec![
                "*.org/*".into(),
                "*.com/*".into(),
                "*.net/*".into(),
                "*.io/*".into(),
                "*.dev/*".into(),
                "*.info/*".into(),
                "*.co/*".into(),
            ],
            per_pattern_limit: 5000,
            min_candidate_files: 12,
            target_bytes: 4 * GIB,
            max_index_response_bytes: 512 * 1024 * 1024,
            pattern_stagger_ms: 200,
            max_select_rounds: 3,
            round_cooldown_secs: 20,
            head_probe_abort_after: 30,
        }
    }
}

impl Default for IndexFilterCfg {
    fn default() -> Self {
        Self {
            mime_regex: ".*(text/.*|javascript|json|xml).*".into(),
            status_regex: "200".into(),
            server_mime_filter: false,
            extra_cdx_filters: Vec::new(),
            only_warc_path: true,
        }
    }
}

impl Default for RecordsFilterCfg {
    fn default() -> Self {
        Self {
            warc_type_regex: "^response$".into(),
            content_type_regex: "^(text/|application/(json|javascript|xml))".into(),
            min_payload_bytes: 64,
            max_payload_bytes: 0,
            payload_include_regex: String::new(),
            drop_invalid_records: true,
        }
    }
}

impl Default for DownloadCfg {
    fn default() -> Self {
        Self {
            parallel_fetches: 3,
            max_bytes_per_file: 0,
            max_retries: 4,
            retry_backoff_ms: 1500,
            connect_timeout_secs: 30,
            request_timeout_secs: 900,
            head_timeout_secs: 45,
        }
    }
}

impl Default for SplitCfg {
    fn default() -> Self {
        Self {
            records_per_chunk: 256,
            max_chunk_bytes: 8 * 1024 * 1024,
            max_concurrent: 2,
            awk_binary: "awk".into(),
        }
    }
}

impl Default for ScanCfg {
    fn default() -> Self {
        Self {
            binary: "trufflehog".into(),
            only_verified: true,
            no_update: true,
            log_level: -1,
            trufflehog_concurrency: 8,
            workers: 2,
            extra_args: Vec::new(),
            snippet_window_chars: 512,
            artifact_max_bytes: 0,
        }
    }
}

impl Default for CacheCfg {
    fn default() -> Self {
        Self {
            mem_limit_bytes: 2 * GIB,
            spill_dir: PathBuf::from("results/spill"),
            spill_file_bytes: GIB,
            final_output: PathBuf::from("results/findings.jsonl"),
        }
    }
}

impl Default for QueuesCfg {
    fn default() -> Self {
        Self {
            network_capacity: 64,
            network_min_workers: 1,
            network_scale_threshold: 2,
            network_idle_retire_ms: 10_000,
            network_pool_tick_ms: 100,
            disk_workers: 4,
            disk_capacity: 128,
            ram_capacity: 16384,
        }
    }
}

impl Default for PathsCfg {
    fn default() -> Self {
        Self {
            workdir: PathBuf::from("work"),
            keep_warcs: false,
            keep_chunks: false,
            checkpoint_file: PathBuf::from("results/checkpoint.json"),
            partials_dir: PathBuf::from("results/partials"),
            artifacts_dir: PathBuf::from("results/artifacts"),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let cfg: Config =
            toml::from_str(&raw).with_context(|| format!("parsing config {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(self.download.parallel_fetches >= 1, "download.parallel_fetches must be >= 1");
        anyhow::ensure!(self.queues.network_min_workers >= 1, "queues.network_min_workers must be >= 1");
        anyhow::ensure!(self.queues.disk_workers >= 1, "queues.disk_workers must be >= 1");
        anyhow::ensure!(self.queues.network_capacity >= 1, "queues.network_capacity must be >= 1");
        anyhow::ensure!(self.queues.disk_capacity >= 1, "queues.disk_capacity must be >= 1");
        anyhow::ensure!(self.queues.ram_capacity >= 1, "queues.ram_capacity must be >= 1");
        anyhow::ensure!(self.split.records_per_chunk >= 1, "split.records_per_chunk must be >= 1");
        anyhow::ensure!(self.split.max_concurrent >= 1, "split.max_concurrent must be >= 1");
        anyhow::ensure!(self.scan.workers >= 1, "scan.workers must be >= 1");
        anyhow::ensure!(
            self.scan.snippet_window_chars >= 16,
            "scan.snippet_window_chars must be >= 16"
        );
        anyhow::ensure!(self.cache.mem_limit_bytes >= 1024, "cache.mem_limit_bytes must be >= 1024");
        anyhow::ensure!(!self.targets.url_patterns.is_empty(), "targets.url_patterns must not be empty");
        anyhow::ensure!(
            self.targets.max_select_rounds >= 1,
            "targets.max_select_rounds must be >= 1"
        );
        anyhow::ensure!(
            self.targets.head_probe_abort_after >= 1,
            "targets.head_probe_abort_after must be >= 1"
        );
        regex::Regex::new(&self.filter.index.mime_regex).context("filter.index.mime_regex is not a valid regex")?;
        regex::Regex::new(&self.filter.index.status_regex).context("filter.index.status_regex is not a valid regex")?;
        regex::Regex::new(&self.filter.records.warc_type_regex)
            .context("filter.records.warc_type_regex is not a valid regex")?;
        regex::Regex::new(&self.filter.records.content_type_regex)
            .context("filter.records.content_type_regex is not a valid regex")?;
        if !self.filter.records.payload_include_regex.is_empty() {
            regex::Regex::new(&self.filter.records.payload_include_regex)
                .context("filter.records.payload_include_regex is not a valid regex")?;
        }
        Ok(())
    }

    /// Effective max concurrent fetches: the network pool never exceeds this.
    pub fn network_max_workers(&self) -> usize {
        self.download.parallel_fetches.max(self.queues.network_min_workers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_parse_from_empty_config() {
        let cfg: Config = toml::from_str("").unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.targets.target_bytes, 4 * GIB);
        assert_eq!(cfg.cache.mem_limit_bytes, 2 * GIB);
        assert_eq!(cfg.download.parallel_fetches, 3);
        assert!(cfg.scan.only_verified);
        assert_eq!(
            cfg.paths.checkpoint_file,
            PathBuf::from("results/checkpoint.json")
        );
        assert_eq!(cfg.paths.partials_dir, PathBuf::from("results/partials"));
        assert_eq!(cfg.paths.artifacts_dir, PathBuf::from("results/artifacts"));
        assert_eq!(cfg.scan.artifact_max_bytes, 0);
    }

    #[test]
    fn overrides_and_unknown_keys() {
        let cfg: Config = toml::from_str(
            r#"
            [targets]
            target_bytes = 67108864
            [cache]
            mem_limit_bytes = 20000
            [scan]
            only_verified = false
            "#,
        )
        .unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.targets.target_bytes, 67108864);
        assert_eq!(cfg.cache.mem_limit_bytes, 20000);
        assert!(!cfg.scan.only_verified);

        let bad = toml::from_str::<Config>("[targets]\nbogus_key = 1\n");
        assert!(bad.is_err());
    }

    #[test]
    fn invalid_regex_rejected() {
        let mut cfg = Config::default();
        cfg.filter.index.mime_regex = "(".into();
        assert!(cfg.validate().is_err());
    }
}
