//! Stage 3 — direct trufflehog wrapper (no `sh -c`).
//!
//! Spawns `trufflehog filesystem ... <dir>` via `tokio::process::Command`,
//! streams JSON findings line-by-line from stdout, and pushes each raw line
//! into the RAM cache actor. trufflehog's own logs stay on stderr.

use std::io::BufReader;
use std::path::Path;
use std::process::Stdio;

use anyhow::{bail, Context, Result};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, BufReader as AsyncBufReader};
use tokio::process::Command;

use crate::config::Config;
use crate::queues::ram::WarcRam;
use crate::stats::Stats;

#[derive(Debug, Default, Clone)]
pub struct ScanStats {
    pub findings: u64,
    pub unparsed: u64,
}

/// Where source records are retained and how big they may be (0 = unlimited).
#[derive(Debug, Clone)]
struct ArtCfg {
    dir: std::path::PathBuf,
    max_bytes: u64,
}

/// What the chunk scan recovered for one finding: page URL, code snippet and
/// (when `paths.artifacts_dir` is writable) the enclosing WARC record on disk.
#[derive(Debug, Default)]
struct ChunkHit {
    target: Option<String>,
    ctx: Option<String>,
    artifact: Option<String>,
}

/// Build the argv for a `trufflehog filesystem` run over `dir`.
pub fn build_args(cfg: &Config, dir: &Path) -> Vec<String> {
    let s = &cfg.scan;
    let mut args = vec!["filesystem".to_string()];
    if s.only_verified {
        args.push("--only-verified".into());
    }
    args.push("--json".into());
    if s.no_update {
        args.push("--no-update".into());
    }
    args.push(format!("--log-level={}", s.log_level));
    if s.trufflehog_concurrency > 0 {
        args.push(format!("--concurrency={}", s.trufflehog_concurrency));
    }
    args.extend(s.extra_args.iter().cloned());
    args.push(dir.display().to_string());
    args
}

pub async fn scan_dir(
    cfg: std::sync::Arc<Config>,
    sink: WarcRam,
    stats: std::sync::Arc<Stats>,
    dir: std::path::PathBuf,
) -> Result<ScanStats> {
    let binary = cfg.scan.binary.clone();
    let args = build_args(&cfg, &dir);

    tracing::debug!(binary = %binary, args = ?args, "spawning trufflehog");
    let mut child = Command::new(&binary)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("spawning {binary} — is trufflehog installed?"))?;

    let stdout = child.stdout.take().context("trufflehog stdout missing")?;
    let stderr = child.stderr.take().context("trufflehog stderr missing")?;

    // Drain stderr concurrently (progress logs) so the pipe never fills.
    let stderr_task: tokio::task::JoinHandle<Vec<u8>> = tokio::spawn(async move {
        let mut buf = Vec::new();
        let mut reader = AsyncBufReader::new(stderr);
        use tokio::io::AsyncReadExt;
        let _ = reader.read_to_end(&mut buf).await;
        buf
    });

    let mut out_stats = ScanStats::default();
    let art = ArtCfg {
        dir: cfg.paths.artifacts_dir.clone(),
        max_bytes: cfg.scan.artifact_max_bytes,
    };
    let mut reader = AsyncBufReader::new(stdout);
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(error = %e, "reading trufflehog stdout");
                break;
            }
        }
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            continue;
        }
        let mut v: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => {
                out_stats.unparsed += 1;
                stats.add(&stats.unparsed_findings, 1);
                tracing::debug!(line = %stderr_tail(trimmed, 200), "non-JSON trufflehog output");
                continue;
            }
        };
        let window = cfg.scan.snippet_window_chars;
        let enriched = enrich(&mut v, window, &art).await;
        if v.get("artifact").is_some() {
            stats.add(&stats.artifacts_attached, 1);
        }
        let mut bytes = if enriched {
            serde_json::to_vec(&v).unwrap_or_else(|_| trimmed.as_bytes().to_vec())
        } else {
            trimmed.as_bytes().to_vec()
        };
        bytes.push(b'\n');
        // Hand the finding to the cache actor (tagged with its WARC); the
        // whole batch is committed to a partial file when the scan finishes.
        sink.insert(bytes).await?;
        out_stats.findings += 1;
        stats.add(&stats.findings_inserted, 1);
    }

    let status = child.wait().await.context("waiting for trufflehog")?;
    let stderr_bytes = stderr_task.await.unwrap_or_default();
    let stderr_str = String::from_utf8_lossy(&stderr_bytes);

    // 183 = results found with --fail (we don't pass it, but tolerate it).
    if !status.success() && status.code() != Some(183) {
        bail!(
            "trufflehog exited with {status}; stderr: {}",
            stderr_tail(&stderr_str, 3000)
        );
    }
    if out_stats.unparsed > 0 {
        tracing::debug!(unparsed = out_stats.unparsed, "trufflehog lines that were not JSON");
    }
    tracing::info!(
        findings = out_stats.findings,
        unparsed = out_stats.unparsed,
        "scan complete"
    );
    Ok(out_stats)
}

/// Attach the original website (`url`), a code snippet (`context`) and the
/// source WARC record (`artifact`) to a filesystem finding by reading the WARC
/// chunk it points into. Must run while chunks still exist (i.e. before
/// pipeline cleanup). Returns true if anything was added. `window` is the
/// number of characters kept on each side of the secret inside the snippet
/// (`scan.snippet_window_chars`).
async fn enrich(v: &mut Value, window: usize, art: &ArtCfg) -> bool {
    let loc = &v["SourceMetadata"]["Data"]["Filesystem"];
    let (Some(file), Some(line)) = (loc["file"].as_str(), loc["line"].as_u64()) else {
        return false;
    };
    let file = file.to_owned();
    let line = line as usize;
    let needle = v["Raw"].as_str().map(str::to_owned);
    let art = art.clone();
    let res = tokio::task::spawn_blocking(move || {
        chunk_context(&file, line, needle.as_deref(), window, &art)
    })
    .await;
    match res {
        Ok(Ok(found)) => {
            let mut changed = false;
            if let Some(u) = found.target {
                v["url"] = Value::String(u);
                changed = true;
            }
            if let Some(c) = found.ctx {
                v["context"] = Value::String(c);
                changed = true;
            }
            if let Some(p) = found.artifact {
                v["artifact"] = Value::String(p);
                changed = true;
            }
            if !changed {
                tracing::debug!(
                    file = %v["SourceMetadata"]["Data"]["Filesystem"]["file"],
                    line,
                    "enrich: no WARC header/snippet/record found near line"
                );
            }
            changed
        }
        Ok(Err(e)) => {
            tracing::warn!(
                file = %v["SourceMetadata"]["Data"]["Filesystem"]["file"],
                line, error = %e,
                "enrich: cannot read chunk"
            );
            false
        }
        Err(e) => {
            tracing::warn!(line, error = %e, "enrich: blocking task failed");
            false
        }
    }
}

/// Resolve `path:line` (as reported by trufflehog) to the enclosing WARC
/// record's `WARC-Target-URI`, a flattened snippet of the matching line, and —
/// via `write_artifact` — the record itself saved under `art.dir`.
/// trufflehog's line number can be off by one around embedded records, so the
/// needle is searched within a small window around it. `window` characters of
/// context are kept on each side of the needle.
fn chunk_context(
    path: &str,
    line_n: usize,
    needle: Option<&str>,
    window: usize,
    art: &ArtCfg,
) -> std::io::Result<ChunkHit> {
    use std::io::BufRead;

    let file = std::fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut raw: Vec<u8> = Vec::new();
    let mut offset = 0usize;
    let mut i = 0usize;

    // current record as of the line just read (records start with `WARC/1.0`,
    // which is exactly how split.rs/awk re-emits them into chunks)
    let mut rec_start = 0usize;
    let mut rec_line = 1usize;
    let mut rec_uri: Option<String> = None;
    let mut last_uri: Option<String> = None;

    // candidate record: `anchor` = the record holding the reported line,
    // `hit` = the record where the needle actually matched (wins).
    let mut anchor: Option<(usize, usize, Option<String>)> = None;
    let mut anchor_end: Option<usize> = None;
    let mut hit: Option<(usize, usize, Option<String>)> = None;
    let mut hit_end: Option<usize> = None;
    let mut hit_ctx: Option<String> = None;
    let mut fallback: Option<String> = None;
    let mut window_done = false;

    loop {
        raw.clear();
        // byte-wise read: WARC payloads are arbitrary bytes, and read_line()
        // bails with InvalidData on the first non-UTF-8 chunk
        if reader.read_until(b'\n', &mut raw)? == 0 {
            break;
        }
        let line_off = offset;
        offset += raw.len();
        i += 1;

        if raw.starts_with(b"WARC/1.0") {
            // a new record starts here: close the ranges we are tracking
            if anchor.is_some() && anchor_end.is_none() {
                anchor_end = Some(line_off);
            }
            if hit.is_some() && hit_end.is_none() {
                hit_end = Some(line_off);
            }
            rec_start = line_off;
            rec_line = i;
            rec_uri = None;
        }

        let buf = String::from_utf8_lossy(&raw);
        let line = buf.trim_end_matches(['\n', '\r']);
        if let Some(rest) = line.strip_prefix("WARC-Target-URI:") {
            let uri = rest.trim().to_owned();
            rec_uri = Some(uri.clone());
            last_uri = Some(uri);
        }

        if !window_done {
            if i == line_n {
                anchor = Some((rec_start, rec_line, rec_uri.clone()));
                fallback = snippet(line, None, window);
            }
            if i >= line_n && i < line_n + 5 && needle.is_none_or(|nd| line.contains(nd)) {
                hit = Some((rec_start, rec_line, rec_uri.clone()));
                hit_ctx = snippet(line, needle, window);
                window_done = true;
            } else if i >= line_n + 5 {
                window_done = true;
            }
        }

        // stop once the chosen record's byte range is known (or the file ends)
        let settled = if hit.is_some() {
            hit_end.is_some()
        } else {
            anchor.is_none() || anchor_end.is_some()
        };
        if window_done && settled {
            break;
        }
    }

    let ctx = hit_ctx.or(fallback).filter(|s| !s.is_empty());
    let end = hit_end.or(anchor_end).unwrap_or(offset);
    let mut out = ChunkHit::default();
    match hit.or(anchor) {
        Some((start, rec_ln, uri)) => {
            out.target = uri;
            out.ctx = ctx;
            if end > start {
                out.artifact = write_artifact(&mut reader, art, path, start, end, rec_ln);
            }
        }
        // the file ended before the reported line — the last header is all we know
        None => out.target = last_uri,
    }
    Ok(out)
}

/// Copy the record's byte range `[start, end)` out of the chunk into
/// `<artifacts_dir>/<warc>/<chunk>-L<record-line>.txt`. Records are shared by
/// every finding inside them, so an existing file is reused as-is. Returns the
/// stored path (relative when `art.dir` is), or None when skipped/failed.
fn write_artifact(
    reader: &mut BufReader<std::fs::File>,
    art: &ArtCfg,
    chunk_path: &str,
    start: usize,
    end: usize,
    rec_line: usize,
) -> Option<String> {
    use std::io::{Read, Seek, SeekFrom};

    let len = end - start;
    if art.max_bytes > 0 && len as u64 > art.max_bytes {
        tracing::debug!(len, max = art.max_bytes, "artifact skipped: record too big");
        return None;
    }
    let dest = artifact_dest(chunk_path, &art.dir, rec_line);
    if dest.exists() {
        return Some(dest.display().to_string());
    }
    let mut bytes = vec![0u8; len];
    reader.seek(SeekFrom::Start(start as u64)).ok()?;
    reader.read_exact(&mut bytes).ok()?;
    let parent = dest.parent()?;
    std::fs::create_dir_all(parent).ok()?;
    // write to a temp name and rename so a crash never leaves a truncated
    // artifact that later findings would happily deduplicate onto
    let tmp = dest.with_extension("part");
    let written = std::fs::write(&tmp, &bytes).is_ok()
        && std::fs::rename(&tmp, &dest).is_ok();
    if !written {
        let _ = std::fs::remove_file(&tmp);
        tracing::warn!(dest = %dest.display(), "artifact write failed");
        return None;
    }
    Some(dest.display().to_string())
}

/// `results/artifacts/<warc>/<chunk>-L<record-line>.txt` for a chunk at
/// `work/<warc>.chunks/chunk-000042.warc` (the layout split.rs produces).
fn artifact_dest(chunk_path: &str, dir: &Path, rec_line: usize) -> std::path::PathBuf {
    let p = Path::new(chunk_path);
    let mut out = dir.to_path_buf();
    if let Some(warc) = p
        .parent()
        .and_then(Path::file_name)
        .and_then(|n| n.to_str())
        .and_then(|n| n.strip_suffix(".chunks"))
        .map(|n| {
            n.strip_suffix(".warc.gz")
                .or_else(|| n.strip_suffix(".warc"))
                .unwrap_or(n)
                .to_owned()
        })
    {
        out.push(warc);
    }
    let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("record");
    out.push(format!("{stem}-L{rec_line}.txt"));
    out
}

/// Whitespace-flattened window of `window` characters on each side of `needle`
/// (or the line start), capped. Slicing is clamped to char boundaries — WARC
/// payloads are arbitrary UTF-8 (and mojibake), and a byte-index panic here
/// used to kill enrichment for the whole finding.
fn snippet(line: &str, needle: Option<&str>, window: usize) -> Option<String> {
    let flat: String = line
        .chars()
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .collect();
    let flat = flat.trim();
    if flat.is_empty() {
        return None;
    }
    let (start, end) = match needle.and_then(|nd| flat.find(nd).map(|p| (p, nd.len()))) {
        Some((p, nlen)) => (
            p.saturating_sub(window),
            (p + nlen + window).min(flat.len()),
        ),
        None => (0, flat.len().min(2 * window)),
    };
    let start = floor_boundary(flat, start);
    let end = ceil_boundary(flat, end.max(start));
    let mut out = flat[start..end].to_string();
    if start > 0 {
        out.insert(0, '…');
    }
    if end < flat.len() {
        out.push('…');
    }
    Some(out)
}

fn floor_boundary(s: &str, mut i: usize) -> usize {
    if i >= s.len() {
        return s.len();
    }
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn ceil_boundary(s: &str, mut i: usize) -> usize {
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

fn stderr_tail(s: &str, max: usize) -> String {
    let t = s.trim();
    if t.len() <= max {
        t.to_owned()
    } else {
        format!("…{}", &t[t.len() - max..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    /// The window that used to be hard-coded before `snippet_window_chars`.
    const W: usize = 90;

    #[test]
    fn args_match_expected_flags() {
        let cfg: Config = toml::from_str("").unwrap();
        let args = build_args(&cfg, Path::new("work/x"));
        assert_eq!(args[0], "filesystem");
        assert!(args.contains(&"--only-verified".to_string()));
        assert!(args.contains(&"--json".to_string()));
        assert!(args.contains(&"--no-update".to_string()));
        assert!(args.contains(&"--log-level=-1".to_string()));
        assert!(args.contains(&"--concurrency=8".to_string()));
        assert_eq!(args.last().unwrap(), "work/x");

        let mut cfg2 = cfg;
        cfg2.scan.only_verified = false;
        cfg2.scan.extra_args = vec!["--filter-entropy=3.5".into()];
        let args2 = build_args(&cfg2, Path::new("d"));
        assert!(!args2.contains(&"--only-verified".to_string()));
        assert!(args2.contains(&"--filter-entropy=3.5".to_string()));
    }

    fn sample_chunk() -> tempfile::NamedTempFile {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        write!(
            f,
            "WARC/1.0\r\nWARC-Type: response\r\nWARC-Target-URI: https://example.com/page\r\nContent-Length: 3\r\n\r\nabc\r\n\r\nHTTP/1.1 200 OK\r\n\r\n<html>var k = \"SECRET-KEY-1\";</html>\r\n\r\nWARC/1.0\r\nWARC-Target-URI: https://other.example/\r\n\r\nend\r\n"
        )
        .unwrap();
        f
    }

    fn art_in(dir: &Path) -> ArtCfg {
        ArtCfg { dir: dir.to_path_buf(), max_bytes: 0 }
    }

    #[test]
    fn chunk_context_finds_url_and_snippet() {
        let f = sample_chunk();
        let tmp = tempfile::tempdir().unwrap();
        let path = f.path().to_str().unwrap();
        // reported line 6, needle actually at line 10 — inside the +5 window
        let hit = chunk_context(path, 6, Some("SECRET-KEY-1"), W, &art_in(tmp.path())).unwrap();
        assert_eq!(hit.target.as_deref(), Some("https://example.com/page"));
        let ctx = hit.ctx.unwrap();
        assert!(ctx.contains("SECRET-KEY-1"), "ctx={ctx}");
        assert!(!ctx.contains('\n'));
        // the whole enclosing record was retained for it
        let art = hit.artifact.unwrap();
        assert!(art.starts_with(&tmp.path().display().to_string()), "{art}");
        let body = std::fs::read_to_string(&art).unwrap();
        assert!(body.starts_with("WARC/1.0\r\n"), "body={body:?}");
        assert!(body.contains("SECRET-KEY-1") && body.contains("example.com/page"));
        assert!(!body.contains("other.example"), "leaked into next record: {body:?}");
    }

    #[test]
    fn chunk_context_window_tolerates_off_by_one_line() {
        let f = sample_chunk();
        let tmp = tempfile::tempdir().unwrap();
        let path = f.path().to_str().unwrap();
        let hit = chunk_context(path, 7, Some("SECRET-KEY-1"), W, &art_in(tmp.path())).unwrap();
        assert_eq!(hit.target.as_deref(), Some("https://example.com/page"));
        assert!(hit.ctx.unwrap().contains("SECRET-KEY-1"));
    }

    #[test]
    fn chunk_context_missing_file_errors() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(chunk_context("/nonexistent/chunk.warc", 1, None, W, &art_in(tmp.path())).is_err());
    }

    #[test]
    fn chunk_context_tolerates_non_utf8_bytes() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(
            b"WARC/1.0\r\nWARC-Target-URI: https://binary.example/\r\n\r\n\xff\xfe junk \xfd SECRET-KEY-1 \xfc\r\n",
        )
        .unwrap();
        f.flush().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let path = f.path().to_str().unwrap();
        let hit = chunk_context(path, 3, Some("SECRET-KEY-1"), W, &art_in(tmp.path())).unwrap();
        assert_eq!(hit.target.as_deref(), Some("https://binary.example/"));
        assert!(hit.ctx.unwrap().contains("SECRET-KEY-1"));
        // artifact keeps the raw bytes, invalid UTF-8 included
        let art = hit.artifact.unwrap();
        let body = std::fs::read(&art).unwrap();
        assert!(body.contains(&0xff), "raw bytes lost");
    }

    #[test]
    fn artifact_is_deduplicated_per_record() {
        let f = sample_chunk();
        let tmp = tempfile::tempdir().unwrap();
        let path = f.path().to_str().unwrap();
        let a = art_in(tmp.path());
        let first = chunk_context(path, 6, Some("SECRET-KEY-1"), W, &a).unwrap();
        let second = chunk_context(path, 10, Some("SECRET-KEY-1"), W, &a).unwrap();
        assert_eq!(first.artifact, second.artifact, "same record → same file");
        let files: Vec<_> = std::fs::read_dir(tmp.path()).unwrap().collect();
        assert_eq!(files.len(), 1, "one record → one artifact file");
    }

    #[test]
    fn artifact_skipped_when_record_exceeds_max_bytes() {
        let f = sample_chunk();
        let tmp = tempfile::tempdir().unwrap();
        let path = f.path().to_str().unwrap();
        let art = ArtCfg { dir: tmp.path().to_path_buf(), max_bytes: 16 };
        let hit = chunk_context(path, 6, Some("SECRET-KEY-1"), W, &art).unwrap();
        assert!(hit.artifact.is_none(), "over the cap → no artifact");
        assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
        // url/snippet enrichment still happens
        assert!(hit.ctx.unwrap().contains("SECRET-KEY-1"));
    }

    #[test]
    fn artifact_dest_follows_the_chunk_layout() {
        assert_eq!(
            artifact_dest(
                "work/CC-MAIN-2026-39-100.chunks/chunk-000042.warc",
                Path::new("results/artifacts"),
                7
            ),
            Path::new("results/artifacts/CC-MAIN-2026-39-100/chunk-000042-L7.txt")
        );
        // unknown layout still lands somewhere sensible
        assert_eq!(
            artifact_dest("plain.warc", Path::new("out"), 3),
            Path::new("out/plain-L3.txt")
        );
    }

    #[test]
    fn snippet_windows_around_needle() {
        let long = format!("{}SECRET-KEY-1{}", "a".repeat(300), "b".repeat(300));
        let s = snippet(&long, Some("SECRET-KEY-1"), W).unwrap();
        assert!(s.contains("SECRET-KEY-1"));
        assert!(s.starts_with('…') && s.ends_with('…'));
        assert!(s.chars().count() < 300);
    }

    #[test]
    fn snippet_never_panics_on_multibyte_boundaries() {
        // window edges land inside 3-byte chars — used to panic in spawn_blocking
        let a = format!("{}你{}SECRET{}", "a".repeat(179), "b".repeat(60), "c".repeat(400));
        assert!(snippet(&a, None, W).is_some());
        assert!(snippet(&a, Some("SECRET"), W).is_some());
        let b = format!("{}é{}", "字".repeat(80), "家".repeat(80));
        let s = snippet(&b, Some("家"), W).unwrap();
        assert!(!s.is_empty());
    }

    #[test]
    fn snippet_grows_with_configured_window() {
        let long = format!("{}SECRET-KEY-1{}", "a".repeat(3000), "b".repeat(3000));
        let small = snippet(&long, Some("SECRET-KEY-1"), 90).unwrap();
        let large = snippet(&long, Some("SECRET-KEY-1"), 512).unwrap();
        assert!(large.contains("SECRET-KEY-1"));
        assert!(
            large.chars().count() > small.chars().count() * 4,
            "small={} large={}",
            small.chars().count(),
            large.chars().count()
        );
        assert!(large.chars().count() <= 2 * 512 + "SECRET-KEY-1".len() + 2);

        // No needle: the prefix window doubles with the configured value.
        let head = snippet(&long, None, 512).unwrap();
        assert!(head.chars().count() <= 2 * 512 + 1);
    }

    #[test]
    fn scan_config_defaults_a_generous_snippet_window() {
        let cfg: Config = toml::from_str("").unwrap();
        assert!(cfg.scan.snippet_window_chars >= 512);
        cfg.validate().unwrap();
        assert!(toml::from_str::<Config>("[scan]\nsnippet_window_chars = 4\n")
            .unwrap()
            .validate()
            .is_err());
    }
}
