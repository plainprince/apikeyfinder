//! Stage 2 — decompress + split along `WARC/1.0` record headers with awk.
//!
//! A `flate2` decoder pumps the (optionally Range-capped) `.warc.gz` into one
//! `awk` child process. awk splits on WARC/1.0 boundaries, validates each
//! record against its own `Content-Length`, applies the record-level
//! "good content" filter, and emits length-framed chunks on stdout. This
//! thread (on the blocking pool) reads those frames and writes every chunk
//! through the central disk queue — backpressure propagates naturally:
//! disk queue full -> reader stalls -> awk stdout fills -> awk stalls ->
//! gzip pump stalls.

use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use anyhow::{anyhow, bail, Context, Result};
use flate2::read::MultiGzDecoder;

use crate::config::Config;
use crate::queues::disk::DiskQueue;
use crate::stats::Stats;

/// gawk program: split on WARC/1.0 headers, validate + filter records, emit
/// framed chunks ("<nbytes>\n<nbytes raw bytes>") to stdout.
/// Config arrives via ENVIRON (no `-v` escape mangling of regexes).
const AWK_PROGRAM: &str = r##"
BEGIN {
  RS = "WARC/1\\.0\r?\n"
  ORS = ""
  rec_max    = ENVIRON["AKF_RECORDS_PER_CHUNK"] + 0
  buf_max    = ENVIRON["AKF_MAX_CHUNK_BYTES"] + 0
  min_pay    = ENVIRON["AKF_MIN_PAYLOAD"] + 0
  max_pay    = ENVIRON["AKF_MAX_PAYLOAD"] + 0
  wt_re      = ENVIRON["AKF_WARC_TYPE_RE"]
  ct_re      = ENVIRON["AKF_CONTENT_TYPE_RE"]
  pay_re     = ENVIRON["AKF_PAYLOAD_RE"]
  keep_invalid = (ENVIRON["AKF_KEEP_INVALID"] == "1")
  nrec = 0; nbytes = 0; frames = 0
  kept = 0; skipped = 0; invalid = 0
}

function flushbuf(   i, total) {
  if (nrec == 0) return
  total = 0
  for (i = 1; i <= nrec; i++) total += length(recs[i])
  printf "%d\n", total
  for (i = 1; i <= nrec; i++) printf "%s", recs[i]
  delete recs
  nrec = 0; nbytes = 0; frames++
}

function keep() {
  recs[++nrec] = "WARC/1.0\r\n" $0
  nbytes += length($0) + 10
  kept++
  if (nrec >= rec_max || (buf_max > 0 && nbytes >= buf_max)) flushbuf()
}

{
  if (length($0) == 0) next

  hdr_end = index($0, "\r\n\r\n")
  if (hdr_end == 0) {
    invalid++
    if (keep_invalid) keep()
    next
  }

  hdr = substr($0, 1, hdr_end - 1)
  wt = ""; ct = ""; cl = -1
  nh = split(hdr, hlines, /\r\n/)
  for (i = 1; i <= nh; i++) {
    l = hlines[i]
    if (l ~ /^WARC-Type:[ \t]*/) { v = l; sub(/^WARC-Type:[ \t]*/, "", v); sub(/\r$/, "", v); wt = v }
    else if (l ~ /^[Cc]ontent-[Ll]ength:[ \t]*/) { v = l; sub(/^[^:]+:[ \t]*/, "", v); gsub(/[^0-9]/, "", v); if (v != "") cl = v + 0 }
  }

  valid = (wt != "" && cl >= 0)
  if (valid) {
    paylen = length($0) - hdr_end - 4
    if (paylen < cl || paylen > cl + 4) {
      invalid++
      if (!keep_invalid) next
      valid = 0
    }
  } else {
    invalid++
    if (!keep_invalid) next
  }

  if (wt_re != "" && wt !~ wt_re) { skipped++; next }

  # For response records the payload is a full HTTP message: read the HTTP
  # Content-Type (bounded window copy), not the WARC-level one.
  if (ct_re != "") {
    head1 = substr($0, hdr_end + 4, 8192)
    he = index(head1, "\r\n\r\n")
    if (he > 0) {
      nhh = split(substr(head1, 1, he - 1), hlines, /\r\n/)
      for (i = 1; i <= nhh; i++) {
        if (hlines[i] ~ /^[Cc]ontent-[Tt]ype:[ \t]*/) {
          v = hlines[i]; sub(/^[^:]+:[ \t]*/, "", v); sub(/\r$/, "", v); ct = v; break
        }
      }
    }
    if (ct != "" && ct !~ ct_re) { skipped++; next }
  }

  if (valid) {
    if (cl < min_pay) { skipped++; next }
    if (max_pay > 0 && cl > max_pay) { skipped++; next }
  }

  if (pay_re != "") {
    payload = substr($0, hdr_end + 4)
    if (payload !~ pay_re) { skipped++; next }
  }

  keep()
}

END {
  flushbuf()
  printf("AKFSTATS kept=%d skipped=%d invalid=%d frames=%d\n", kept, skipped, invalid, frames) > "/dev/stderr"
}
"##;

#[derive(Debug, Clone)]
pub struct SplitOutput {
    pub dir: PathBuf,
    pub frames: usize,
    pub chunk_bytes: u64,
    pub kept: u64,
    pub skipped: u64,
    pub invalid: u64,
    pub decompressed_bytes: u64,
}

fn spawn_awk(cfg: &Config) -> Result<Child> {
    let f = &cfg.filter.records;
    let mut cmd = Command::new(&cfg.split.awk_binary);
    cmd.arg(AWK_PROGRAM)
        .env("LC_ALL", "C")
        .env("AKF_RECORDS_PER_CHUNK", cfg.split.records_per_chunk.to_string())
        .env("AKF_MAX_CHUNK_BYTES", cfg.split.max_chunk_bytes.to_string())
        .env("AKF_MIN_PAYLOAD", f.min_payload_bytes.to_string())
        .env("AKF_MAX_PAYLOAD", f.max_payload_bytes.to_string())
        .env("AKF_WARC_TYPE_RE", &f.warc_type_regex)
        .env("AKF_CONTENT_TYPE_RE", &f.content_type_regex)
        .env("AKF_PAYLOAD_RE", &f.payload_include_regex)
        .env("AKF_KEEP_INVALID", if f.drop_invalid_records { "0" } else { "1" })
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.spawn()
        .with_context(|| format!("spawning {} — is it installed?", cfg.split.awk_binary))
}

/// Read length-framed chunks off awk's stdout, handing each to `on_chunk`.
fn pump_frames<R: Read, F>(reader: R, max_frame: usize, mut on_chunk: F) -> Result<(usize, u64)>
where
    F: FnMut(usize, Vec<u8>) -> Result<()>,
{
    let mut reader = BufReader::new(reader);
    let mut header = String::new();
    let mut frames = 0usize;
    let mut total_bytes = 0u64;
    loop {
        header.clear();
        let n = reader.read_line(&mut header)?;
        if n == 0 {
            break;
        }
        let trimmed = header.trim_end_matches(['\n', '\r']);
        if trimmed.is_empty() {
            continue;
        }
        let size: usize = trimmed
            .parse()
            .with_context(|| format!("awk frame header malformed: {trimmed:?}"))?;
        anyhow::ensure!(
            size <= max_frame,
            "awk frame too large: {size} bytes (limit {max_frame})"
        );
        if size == 0 {
            continue;
        }
        let mut data = vec![0u8; size];
        reader.read_exact(&mut data).context("truncated awk frame")?;
        frames += 1;
        total_bytes += size as u64;
        on_chunk(frames, data)?;
    }
    Ok((frames, total_bytes))
}

fn parse_awk_stats(stderr: &str) -> Option<(u64, u64, u64, usize)> {
    let line = stderr.lines().find(|l| l.starts_with("AKFSTATS "))?;
    let mut kept = 0;
    let mut skipped = 0;
    let mut invalid = 0;
    let mut frames = 0usize;
    for tok in line.split_whitespace().skip(1) {
        let Some((k, v)) = tok.split_once('=') else { continue };
        match k {
            "kept" => kept = v.parse().unwrap_or(0),
            "skipped" => skipped = v.parse().unwrap_or(0),
            "invalid" => invalid = v.parse().unwrap_or(0),
            "frames" => frames = v.parse().unwrap_or(0),
            _ => {}
        }
    }
    Some((kept, skipped, invalid, frames))
}

fn stderr_tail(s: &str, max: usize) -> String {
    let t = s.trim();
    if t.len() <= max {
        t.to_owned()
    } else {
        format!("…{}", &t[t.len() - max..])
    }
}

/// Async entry: runs the whole decompress+awk+frame-read flow on the blocking pool.
pub async fn split_warc(
    cfg: std::sync::Arc<Config>,
    disk: DiskQueue,
    stats: std::sync::Arc<Stats>,
    gz_path: PathBuf,
    out_dir: PathBuf,
) -> Result<SplitOutput> {
    tokio::task::spawn_blocking(move || split_blocking(&cfg, &disk, &stats, &gz_path, &out_dir))
        .await
        .context("split task panicked")?
}

fn split_blocking(
    cfg: &Config,
    disk: &DiskQueue,
    stats: &Stats,
    gz_path: &Path,
    out_dir: &Path,
) -> Result<SplitOutput> {
    disk.mkdir_blocking(out_dir)?;

    let mut child = spawn_awk(cfg)?;
    let awk_stdin = child.stdin.take().context("awk stdin missing")?;
    let awk_stdout = child.stdout.take().context("awk stdout missing")?;
    let awk_stderr = child.stderr.take().context("awk stderr missing")?;

    // stderr must drain concurrently or awk can block on a full pipe.
    let stderr_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let mut err = awk_stderr;
        let _ = err.read_to_end(&mut buf);
        buf
    });

    // Pump thread: stream the decompressed WARC into awk. The gz file is read
    // here (streaming read, owned by this worker); every write still goes
    // through the central disk queue.
    let cap = cfg.download.max_bytes_per_file;
    let gz_for_pump = gz_path.to_path_buf();
    let pump = std::thread::spawn(move || -> Result<(u64, Option<String>)> {
        let file = File::open(&gz_for_pump)
            .with_context(|| format!("opening {}", gz_for_pump.display()))?;
        let mut decoder = MultiGzDecoder::new(file);
        let mut stdin = std::io::BufWriter::new(awk_stdin);
        let mut buf = vec![0u8; 1024 * 1024];
        let mut total = 0u64;
        loop {
            match decoder.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    stdin.write_all(&buf[..n])?;
                    total += n as u64;
                }
                Err(e) => {
                    // With a Range-capped download the stream ends mid-member
                    // by design; everything decoded so far is valid.
                    if cap > 0 {
                        let _ = stdin.flush();
                        return Ok((total, Some(format!("gzip truncated at {total} bytes: {e}"))));
                    }
                    return Err(anyhow!("decompressing {}: {e}", gz_for_pump.display()));
                }
            }
        }
        stdin.flush()?;
        // Closing stdin signals awk EOF.
        drop(stdin);
        Ok((total, None))
    });

    let frames_max = cfg.split.max_chunk_bytes + 256 * 1024 * 1024;
    let disk_q = disk.clone();
    let (frames, chunk_bytes) = pump_frames(awk_stdout, frames_max, |idx, data| {
        let path = out_dir.join(format!("chunk-{idx:06}.warc"));
        // Blocking disk-queue round-trip: applies backpressure up the pipe chain.
        disk_q.write_path_blocking(path, vec![data]).map(|_| ()).map_err(Into::into)
    })?;

    // Frame stream ended => awk exited (or crashed). Reap and validate.
    let status = child.wait().context("waiting for awk")?;
    let pump_result = pump.join().map_err(|_| anyhow!("pump thread panicked"))?;
    let stderr_bytes = stderr_thread
        .join()
        .map_err(|_| anyhow!("stderr thread panicked"))?;
    let stderr_str = String::from_utf8_lossy(&stderr_bytes);

    let (decompressed, trunc_note) = match pump_result {
        Ok(v) => v,
        Err(e) => {
            if !status.success() {
                bail!(
                    "awk exited with {status}; stderr: {}",
                    stderr_tail(&stderr_str, 2000)
                );
            }
            return Err(e);
        }
    };
    if !status.success() {
        bail!(
            "awk exited with {status}; stderr: {}",
            stderr_tail(&stderr_str, 2000)
        );
    }
    if let Some(note) = trunc_note {
        tracing::info!(note = %note, "partial download decompressed until EOF");
    }

    let (kept, skipped, invalid, awk_frames) =
        parse_awk_stats(&stderr_str).unwrap_or((0, 0, 0, 0));
    if awk_frames != frames {
        tracing::warn!(awk_frames, reader_frames = frames, "frame count mismatch");
    }

    stats.chunks_written.fetch_add(frames, std::sync::atomic::Ordering::Relaxed);
    stats.add(&stats.chunk_bytes, chunk_bytes);
    stats.add(&stats.records_kept, kept);
    stats.add(&stats.records_skipped, skipped);
    stats.add(&stats.records_invalid, invalid);
    stats.inc_usize(&stats.split_done);

    tracing::info!(
        frames,
        kept,
        skipped,
        invalid,
        decompressed,
        "warc split complete"
    );
    Ok(SplitOutput {
        dir: out_dir.to_path_buf(),
        frames,
        chunk_bytes,
        kept,
        skipped,
        invalid,
        decompressed_bytes: decompressed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cfg() -> Config {
        let mut cfg: Config = toml::from_str("").unwrap();
        cfg.filter.records.min_payload_bytes = 0;
        cfg.split.records_per_chunk = 100;
        cfg
    }

    fn rec(fields: &[(&str, &str)], payload: &str) -> String {
        let mut s = String::from("WARC/1.0\r\n");
        for (k, v) in fields {
            s.push_str(&format!("{k}: {v}\r\n"));
        }
        s.push_str(&format!("Content-Length: {}\r\n\r\n", payload.len()));
        s.push_str(payload);
        s.push_str("\r\n\r\n");
        s
    }

    fn run_awk(cfg: &Config, input: &str) -> (Vec<Vec<u8>>, Result<(usize, u64)>, String) {
        let mut child = spawn_awk(cfg).unwrap();
        let mut stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let mut stderr = child.stderr.take().unwrap();

        let input = input.to_owned();
        let writer = std::thread::spawn(move || {
            stdin.write_all(input.as_bytes()).unwrap();
        });

        let mut chunks = Vec::new();
        let res = pump_frames(stdout, 1 << 30, |_, data| {
            chunks.push(data);
            Ok(())
        });
        writer.join().unwrap();
        let status = child.wait().unwrap();
        assert!(status.success(), "awk failed: {status}");
        let mut err = String::new();
        stderr.read_to_string(&mut err).unwrap();
        (chunks, res, err)
    }

    #[test]
    fn awk_splits_filters_and_frames() {
        if Command::new("awk").arg("--version").output().is_err() {
            eprintln!("awk not available; skipping");
            return;
        }
        let cfg = test_cfg();

        let html_payload =
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n<html>hello</html>";
        let json_payload = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"k\":1}";
        let png_payload = "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\nPNGBINARYDATA";

        let mut input = String::new();
        input += &rec(&[("WARC-Type", "warcinfo")], "software: x\r\nformat: WARC File Format 1.0");
        input += &rec(
            &[("WARC-Type", "response"), ("WARC-Target-URI", "http://a/")],
            html_payload,
        );
        input += &rec(
            &[("WARC-Type", "response"), ("WARC-Target-URI", "http://b/")],
            json_payload,
        );
        input += &rec(
            &[("WARC-Type", "response"), ("WARC-Target-URI", "http://c/")],
            png_payload,
        );
        // Separately framed record that fails validation (no WARC-Type).
        input += &rec(&[("Bogus-Header", "1")], "some payload here");

        let (chunks, res, stderr) = run_awk(&cfg, &input);
        let (frames, _bytes) = res.expect("frame pump");
        // Both kept records fit in one chunk (records_per_chunk = 100).
        assert_eq!(frames, 1, "html + json kept, png + warcinfo + bogus filtered");
        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].starts_with(b"WARC/1.0\r\nWARC-Type: response"));
        assert!(chunks[0].windows(html_payload.len()).any(|w| w == html_payload.as_bytes()));
        assert!(chunks[0].windows(json_payload.len()).any(|w| w == json_payload.as_bytes()));
        assert!(!chunks[0].windows(png_payload.len()).any(|w| w == png_payload.as_bytes()));

        let (kept, skipped, invalid, awk_frames) = parse_awk_stats(&stderr).expect("stats line");
        assert_eq!(kept, 2);
        assert_eq!(skipped, 2, "warcinfo (type) + png (mime)");
        assert_eq!(invalid, 1, "the trailing garbage record");
        assert_eq!(awk_frames, 1);
    }

    #[test]
    fn awk_chunk_grouping_respects_record_limit() {
        if Command::new("awk").arg("--version").output().is_err() {
            return;
        }
        let mut cfg = test_cfg();
        cfg.split.records_per_chunk = 2;

        let payload = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nbody-body-body";
        let mut input = String::new();
        for i in 0..5 {
            input += &rec(&[("WARC-Type", "response"), ("WARC-Target-URI", "http://x/")], &format!("{payload}-{i}"));
        }
        let (chunks, res, stderr) = run_awk(&cfg, &input);
        let (frames, _) = res.unwrap();
        assert_eq!(frames, 3, "2 + 2 + 1 records per chunk");
        assert_eq!(chunks.len(), 3);
        let (kept, _, _, _) = parse_awk_stats(&stderr).unwrap();
        assert_eq!(kept, 5);
    }

    #[test]
    fn content_length_mismatch_is_invalid() {
        if Command::new("awk").arg("--version").output().is_err() {
            return;
        }
        let cfg = test_cfg();
        // Claim Content-Length: 5 but supply a longer block.
        let input = "WARC/1.0\r\nWARC-Type: response\r\nContent-Length: 5\r\n\r\nway more than five bytes\r\n\r\n";
        let (chunks, res, stderr) = run_awk(&cfg, input);
        let (frames, _) = res.unwrap();
        assert_eq!(frames, 0);
        assert!(chunks.is_empty());
        let (kept, _, invalid, _) = parse_awk_stats(&stderr).unwrap();
        assert_eq!(kept, 0);
        assert_eq!(invalid, 1);
    }
}
