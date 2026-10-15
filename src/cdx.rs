//! Stage 1 — high-performance "good content" pre-filter.
//!
//! Fans CDX index queries (mime/status/url-pattern filters) out through the
//! central network queue, aggregates which WARC files contain matching
//! records, re-applies the filters client-side (so a silently-ignored server
//! filter can't weaken them), then probes candidate file sizes with HEAD
//! requests until `targets.target_bytes` of downloads is scheduled.

use std::collections::HashMap;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::queues::network::NetworkQueue;
use crate::stats::Stats;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarcTarget {
    /// Path inside the bucket, e.g. `crawl-data/CC-MAIN-.../warc/....warc.gz`
    pub path: String,
    pub url: String,
    pub hits: usize,
    pub size: u64,
}

#[derive(Debug, Deserialize)]
struct CdxLine {
    filename: Option<String>,
    mime: Option<String>,
    status: Option<String>,
    length: Option<String>,
}

/// Minimal percent-encoding for query values (keeps `*`, `/`, `:` readable).
fn qenc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '%' | ' ' | '&' | '+' | '#' | '"' | '<' | '>' | '{' | '}' | '|' | '\\' | '^' | '`'
            | '[' | ']' => {
                out.push('%');
                for b in c.encode_utf8(&mut [0u8; 4]).bytes() {
                    out.push(char::from_digit((b >> 4) as u32, 16).unwrap().to_ascii_uppercase());
                    out.push(char::from_digit((b & 0xf) as u32, 16).unwrap().to_ascii_uppercase());
                }
            }
            c => out.push(c),
        }
    }
    out
}

fn build_index_url(cfg: &Config, pattern: &str) -> String {
    let t = &cfg.targets;
    let f = &cfg.filter.index;
    let mut url = format!(
        "{base}/{coll}-index?url={pat}&output=json&limit={limit}",
        base = t.index_base_url.trim_end_matches('/'),
        coll = t.index_collection,
        pat = qenc(pattern),
        limit = t.per_pattern_limit,
    );
    if !f.status_regex.is_empty() {
        url.push_str(&format!("&filter=status:{}", qenc(&f.status_regex)));
    }
    if f.server_mime_filter && !f.mime_regex.is_empty() {
        url.push_str(&format!("&filter=mime:{}", qenc(&f.mime_regex)));
    }
    for extra in &f.extra_cdx_filters {
        url.push('&');
        url.push_str(extra);
    }
    url
}

pub fn parse_cdx(
    body: &str,
    cfg: &Config,
    mime_re: &regex::Regex,
    status_re: &regex::Regex,
    agg: &mut HashMap<String, (usize, u64)>,
) -> usize {
    let f = &cfg.filter.index;
    let mut accepted = 0usize;
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || !line.starts_with('{') {
            continue;
        }
        let Ok(rec) = serde_json::from_str::<CdxLine>(line) else {
            continue;
        };
        let (Some(filename), Some(mime), Some(status)) = (rec.filename, rec.mime, rec.status)
        else {
            continue;
        };
        if f.only_warc_path && !filename.contains("/warc/") {
            continue;
        }
        if !status_re.is_match(&status) || !mime_re.is_match(&mime) {
            continue;
        }
        let rec_len: u64 = rec.length.and_then(|l| l.parse().ok()).unwrap_or(0);
        let entry = agg.entry(filename).or_insert((0, 0));
        entry.0 += 1;
        entry.1 += rec_len;
        accepted += 1;
    }
    accepted
}

/// One round of pattern queries through the network queue. Patterns run
/// **sequentially**: the public CDX frontend is a single pywb instance and
/// parallel bursts are what make it 503/refuse connections. Returns patterns
/// that failed at the transport level (worth retrying) and how many patterns
/// returned at least one accepted record.
async fn query_round(
    cfg: &Config,
    net: &NetworkQueue,
    patterns: &[String],
    agg: &mut HashMap<String, (usize, u64)>,
    mime_re: &regex::Regex,
    status_re: &regex::Regex,
) -> (Vec<String>, usize) {
    let gap = std::time::Duration::from_millis(cfg.targets.pattern_stagger_ms);
    let mut failed = Vec::new();
    let mut accepted_any = 0usize;
    for (i, pattern) in patterns.iter().enumerate() {
        if i > 0 && !gap.is_zero() {
            tokio::time::sleep(gap).await;
        }
        let url = build_index_url(cfg, pattern);
        let max = cfg.targets.max_index_response_bytes;
        match net.fetch(url, max).await {
            Ok(body) => {
                let body = String::from_utf8_lossy(&body);
                let accepted = parse_cdx(&body, cfg, mime_re, status_re, agg);
                tracing::info!(pattern = %pattern, accepted, "index query done");
                if accepted > 0 {
                    accepted_any += 1;
                }
            }
            Err(e) => {
                tracing::warn!(pattern = %pattern, error = %format!("{e:#}"), "index query failed");
                failed.push(pattern.clone());
            }
        }
    }
    (failed, accepted_any)
}

pub async fn select_warcs(cfg: &Config, net: &NetworkQueue, stats: &Stats) -> Result<Vec<WarcTarget>> {
    if cfg.targets.target_bytes == 0 {
        tracing::info!("targets.target_bytes = 0 — nothing to download");
        return Ok(Vec::new());
    }

    let mime_re = regex::Regex::new(&cfg.filter.index.mime_regex)?;
    let status_re = regex::Regex::new(&cfg.filter.index.status_regex)?;

    // Query rounds: only transport-level failures are retried (the network
    // queue already backs off per-attempt inside a query).
    let mut agg: HashMap<String, (usize, u64)> = HashMap::new();
    let mut pending: Vec<String> = cfg.targets.url_patterns.clone();
    let mut round = 0usize;
    while !pending.is_empty() {
        round += 1;
        tracing::info!(round, remaining = pending.len(), "index query round");
        let (failed, _) = query_round(cfg, net, &pending, &mut agg, &mime_re, &status_re).await;
        pending = failed;
        if pending.is_empty() {
            break;
        }
        if round >= cfg.targets.max_select_rounds {
            break;
        }
        // Cool down between rounds — the frontend needs breathing room, and a
        // growing pause keeps us from hammering it right as it recovers.
        let cooldown = cfg.targets.round_cooldown_secs.saturating_mul(round as u64);
        tracing::info!(sleep_secs = cooldown, "cooling down before next index round");
        tokio::time::sleep(std::time::Duration::from_secs(cooldown)).await;
    }
    let failures = pending;
    let ok_patterns = cfg.targets.url_patterns.len().saturating_sub(failures.len());

    if agg.is_empty() {
        bail!(
            "index pre-filter selected no WARC files ({} pattern(s) still failing: {:?}); \
             relax filter.index or targets.url_patterns",
            failures.len(),
            failures
        );
    }
    if !failures.is_empty() {
        tracing::warn!(
            ok = ok_patterns,
            total = cfg.targets.url_patterns.len(),
            failed = ?failures,
            "some index patterns failed after retries; continuing with the rest"
        );
    }

    // Densest files first: files with the most matching "good content" records.
    let mut candidates: Vec<(String, usize, u64)> = agg
        .into_iter()
        .map(|(path, (hits, rec_bytes))| (path, hits, rec_bytes))
        .collect();
    candidates.sort_by(|a, b| b.1.cmp(&a.1).then(b.2.cmp(&a.2)));

    if candidates.len() < cfg.targets.min_candidate_files {
        tracing::warn!(
            found = candidates.len(),
            wanted = cfg.targets.min_candidate_files,
            "fewer candidate files than min_candidate_files; continuing anyway"
        );
    }

    // Schedule downloads until target_bytes of compressed WARC is covered.
    let mut selected: Vec<WarcTarget> = Vec::new();
    let mut total: u64 = 0;
    let mut consecutive_bad = 0u32;
    for (path, hits, _) in candidates {
        if total >= cfg.targets.target_bytes {
            break;
        }
        let url = format!(
            "{}/{}",
            cfg.targets.data_base_url.trim_end_matches('/'),
            path
        );
        tracing::debug!(path = %path, "probing size (HEAD)");
        match net.head(url.clone()).await {
            Ok(Some(size)) if size > 0 => {
                total += size;
                consecutive_bad = 0;
                tracing::info!(size, path = %path, "probe ok, scheduled");
                selected.push(WarcTarget { path, url, hits, size });
            }
            Ok(Some(_)) => {
                consecutive_bad += 1;
                tracing::debug!("skipping zero-length warc {path}");
            }
            Ok(None) => {
                consecutive_bad += 1;
                tracing::warn!(path = %path, "no content-length on HEAD; skipping file");
            }
            Err(e) => {
                consecutive_bad += 1;
                tracing::warn!(path = %path, error = %format!("{e:#}"), "HEAD failed; skipping file");
            }
        }
        if consecutive_bad >= cfg.targets.head_probe_abort_after {
            bail!(
                "aborting: {consecutive_bad} consecutive HEAD probes returned no usable size \
                 (blocked or misconfigured data_base_url?)"
            );
        }
    }

    if selected.is_empty() {
        bail!("could not determine sizes for any candidate WARC file");
    }
    if total < cfg.targets.target_bytes {
        tracing::warn!(
            scheduled = total,
            target = cfg.targets.target_bytes,
            "candidates exhausted before reaching target_bytes; downloading what we have"
        );
    }

    stats
        .downloads_selected_bytes
        .store(total, std::sync::atomic::Ordering::Relaxed);
    stats
        .warcs_total
        .store(selected.len(), std::sync::atomic::Ordering::Relaxed);
    tracing::info!(
        files = selected.len(),
        bytes = total,
        "download schedule ready (highest good-content density first)"
    );
    Ok(selected)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_cfg() -> Config {
        toml::from_str("").unwrap()
    }

    #[test]
    fn parses_and_filters_cdx_lines() {
        let cfg = default_cfg();
        let mime_re = regex::Regex::new(&cfg.filter.index.mime_regex).unwrap();
        let status_re = regex::Regex::new(&cfg.filter.index.status_regex).unwrap();
        let body = r#"
{"urlkey":"com,a)/","timestamp":"1","url":"http://a/","mime":"text/html","status":"200","length":"100","filename":"crawl-data/X/segments/1/warc/a.warc.gz"}
{"urlkey":"com,b)/","timestamp":"1","url":"http://b/","mime":"image/png","status":"200","length":"9","filename":"crawl-data/X/segments/1/warc/b.warc.gz"}
{"urlkey":"com,c)/","timestamp":"1","url":"http://c/","mime":"text/html","status":"404","length":"9","filename":"crawl-data/X/segments/1/warc/c.warc.gz"}
{"urlkey":"com,d)/","timestamp":"1","url":"http://d/","mime":"text/html","status":"200","length":"9","filename":"crawl-data/X/segments/1/robotstxt/d.warc.gz"}
"#;
        let mut agg = HashMap::new();
        let n = parse_cdx(body, &cfg, &mime_re, &status_re, &mut agg);
        assert_eq!(n, 1, "only the html+200+warc-path record survives");
        assert_eq!(agg.len(), 1);
        let (hits, bytes) = agg.values().next().unwrap();
        assert_eq!((*hits, *bytes), (1, 100));
    }

    #[test]
    fn index_url_carries_filters_and_pattern() {
        let cfg = default_cfg();
        let url = build_index_url(&cfg, "*.org/*");
        assert!(url.contains("url=%2A.org/%2A") || url.contains("url=*.org/*"), "{url}");
        assert!(url.contains("filter=status:200"), "{url}");
        assert!(url.contains("limit=5000"), "{url}");
        assert!(url.contains("/CC-MAIN-2026-39-index"), "{url}");
        // mime stays client-side by default (pywb 404s on complex regex filters)
        assert!(!url.contains("filter=mime:"), "{url}");

        let mut cfg2 = default_cfg();
        cfg2.filter.index.server_mime_filter = true;
        let url2 = build_index_url(&cfg2, "*.org/*");
        assert!(url2.contains("filter=mime:"), "{url2}");
    }
}
