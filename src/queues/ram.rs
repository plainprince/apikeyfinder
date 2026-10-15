//! RAM queue: all in-memory cache access flows through one channel into a
//! single actor that owns the findings cache, now **keyed per WARC file**.
//!
//! Findings stay in memory until their WARC finishes scanning; `commit` then
//! writes them (plus anything previously spilled) to a per-WARC partial file
//! atomically — temp file + rename — which is what makes resume work: only
//! committed WARCs are checkpointed, and everything uncommitted is discarded
//! (and redone) on the next run. When the cache exceeds
//! `cache.mem_limit_bytes` it is drained to per-WARC spill files through the
//! central disk queue.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::{mpsc, oneshot};

use crate::config::CacheCfg;
use crate::queues::disk::{DiskQueue, OpenMode};
use crate::stats::Stats;

enum RamCmd {
    /// One finding for `warc`, raw JSON line (with trailing newline).
    Insert { warc: Arc<str>, line: Vec<u8> },
    /// Write everything buffered for `warc` to `dest` atomically.
    Commit {
        warc: Arc<str>,
        dest: PathBuf,
        resp: oneshot::Sender<Result<CommitReport>>,
    },
    /// End of run: report whatever is still uncommitted (discarded).
    Flush(oneshot::Sender<Result<FlushReport>>),
}

#[derive(Debug, Default, Clone, Copy)]
pub struct CommitReport {
    pub findings: u64,
    pub bytes: u64,
}

#[derive(Debug, Default, Clone)]
pub struct FlushReport {
    /// Findings this run pushed into the cache (committed or not).
    pub total_inserted: u64,
    /// Findings from WARCs that never finished — dropped; redone next run.
    pub discarded_findings: u64,
    pub discarded_spill_files: Vec<PathBuf>,
}

type FileHandle = Arc<std::sync::Mutex<std::fs::File>>;

#[derive(Default)]
struct WarcBuf {
    /// Uncommitted findings still in memory.
    lines: Vec<Vec<u8>>,
    bytes: u64,
    /// Findings already moved to this WARC's spill files.
    spilled: u64,
    /// Total accepted for this WARC (memory + spilled) — the commit count.
    count: u64,
    spill_files: Vec<PathBuf>,
    spill_index: usize,
    spill_used: u64,
    spill_handle: Option<FileHandle>,
}

struct Actor {
    cfg: CacheCfg,
    disk: DiskQueue,
    stats: std::sync::Arc<Stats>,
    rx: mpsc::Receiver<RamCmd>,
    bufs: HashMap<Arc<str>, WarcBuf>,
    mem_total: u64,
    total_inserted: u64,
}

impl Actor {
    async fn run(mut self) {
        while let Some(cmd) = self.rx.recv().await {
            match cmd {
                RamCmd::Insert { warc, line } => {
                    let n = line.len() as u64;
                    let buf = self.bufs.entry(warc).or_default();
                    buf.lines.push(line);
                    buf.bytes += n;
                    buf.count += 1;
                    self.mem_total += n;
                    self.total_inserted += 1;
                    if self.mem_total > self.cfg.mem_limit_bytes
                        && let Err(e) = self.drain_all().await
                    {
                        tracing::error!(error = %format!("{e:#}"), "cache spill failed");
                    }
                }
                RamCmd::Commit { warc, dest, resp } => {
                    let _ = resp.send(self.commit(warc, dest).await);
                }
                RamCmd::Flush(resp) => {
                    let _ = resp.send(self.flush().await);
                }
            }
        }
    }

    /// Drain every bucket's in-memory lines to its own spill file(s).
    async fn drain_all(&mut self) -> Result<()> {
        let warcs: Vec<Arc<str>> = self.bufs.keys().cloned().collect();
        for w in warcs {
            self.drain_one(&w).await?;
        }
        Ok(())
    }

    async fn drain_one(&mut self, warc: &Arc<str>) -> Result<()> {
        let Some(buf) = self.bufs.get_mut(warc) else {
            return Ok(());
        };
        if buf.lines.is_empty() {
            return Ok(());
        }
        let parts = std::mem::take(&mut buf.lines);
        let batch_bytes: u64 = parts.iter().map(|p| p.len() as u64).sum();
        let batch_findings = parts.len() as u64;
        buf.bytes = 0;

        let need_rotate = match &buf.spill_handle {
            None => true,
            Some(_) => buf.spill_used + batch_bytes > self.cfg.spill_file_bytes,
        };
        if need_rotate {
            buf.spill_index += 1;
            let path = self
                .cfg
                .spill_dir
                .join(format!("{warc}-{:05}.jsonl", buf.spill_index));
            let handle = self.disk.open(path.clone(), OpenMode::AppendCreate).await?;
            buf.spill_files.push(path);
            buf.spill_used = 0;
            buf.spill_handle = Some(handle);
        }
        let Some(handle) = buf.spill_handle.clone() else {
            return Ok(());
        };
        let wrote = self.disk.write_parts(&handle, parts).await?;
        buf.spill_used += wrote;
        buf.spilled += batch_findings;
        self.mem_total = self.mem_total.saturating_sub(batch_bytes);

        self.stats.add(&self.stats.spill_events, 1);
        self.stats.add(&self.stats.spilled_findings, batch_findings);
        self.stats.add(&self.stats.spilled_bytes, wrote);
        tracing::info!(
            findings = batch_findings,
            bytes = wrote,
            "cache exceeded mem_limit_bytes — spilled to disk"
        );
        Ok(())
    }

    /// Write memory lines + spill files for one WARC to `dest` atomically.
    async fn commit(&mut self, warc: Arc<str>, dest: PathBuf) -> Result<CommitReport> {
        let mut buf = self.bufs.remove(&warc).unwrap_or_default();
        self.mem_total = self.mem_total.saturating_sub(buf.bytes);
        let count = buf.count;
        let lines = std::mem::take(&mut buf.lines);
        let spills = std::mem::take(&mut buf.spill_files);
        drop(buf); // close the current spill handle before files are removed
        let bytes = tokio::task::spawn_blocking(move || write_commit(&dest, lines, &spills))
            .await
            .context("commit task join")??;
        tracing::debug!(warc = %warc, findings = count, bytes, "committed to partial file");
        Ok(CommitReport { findings: count, bytes })
    }

    /// End of run: nothing uncommitted can survive (it would be duplicated by
    /// the redo on resume), so drop it and its spill files.
    async fn flush(&mut self) -> Result<FlushReport> {
        let mut report = FlushReport {
            total_inserted: self.total_inserted,
            ..Default::default()
        };
        for (_, mut buf) in self.bufs.drain() {
            report.discarded_findings += buf.count;
            buf.lines.clear();
            for p in buf.spill_files.drain(..) {
                let _ = self.disk.remove_file(p.clone()).await;
                report.discarded_spill_files.push(p);
            }
        }
        self.mem_total = 0;
        Ok(report)
    }
}

/// Blocking write used by `commit`: memory lines, then spill files in order,
/// into `<dest>.tmp`, fsync, rename over `dest`. Spill files are removed only
/// after the rename succeeded.
fn write_commit(dest: &Path, lines: Vec<Vec<u8>>, spills: &[PathBuf]) -> Result<u64> {
    use std::io::Write as _;

    let mut tmp = dest.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    if let Some(p) = dest.parent() {
        std::fs::create_dir_all(p).with_context(|| format!("creating {}", p.display()))?;
    }
    let mut total = 0u64;
    {
        let mut f =
            std::fs::File::create(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
        for l in &lines {
            f.write_all(l)?;
            total += l.len() as u64;
        }
        for sp in spills {
            let mut sf = std::fs::File::open(sp)
                .with_context(|| format!("opening spill {}", sp.display()))?;
            total += std::io::copy(&mut sf, &mut f)?;
        }
        f.sync_all()?;
    }
    std::fs::rename(&tmp, dest).with_context(|| format!("renaming to {}", dest.display()))?;
    for sp in spills {
        let _ = std::fs::remove_file(sp);
    }
    Ok(total)
}

#[derive(Clone)]
pub struct RamQueue {
    tx: mpsc::Sender<RamCmd>,
}

/// Handle bound to one WARC file: findings inserted here are committed
/// together to that WARC's partial file.
#[derive(Clone)]
pub struct WarcRam {
    tx: mpsc::Sender<RamCmd>,
    warc: Arc<str>,
}

impl RamQueue {
    pub fn spawn(cfg: CacheCfg, disk: DiskQueue, capacity: usize, stats: std::sync::Arc<Stats>) -> Self {
        let (tx, rx) = mpsc::channel(capacity.max(1));
        let actor = Actor {
            cfg,
            disk,
            stats,
            rx,
            bufs: HashMap::new(),
            mem_total: 0,
            total_inserted: 0,
        };
        tokio::spawn(actor.run());
        Self { tx }
    }

    /// Scoped handle for one WARC's findings.
    pub fn for_warc(&self, name: &str) -> WarcRam {
        WarcRam {
            tx: self.tx.clone(),
            warc: Arc::from(name),
        }
    }

    /// Called when the run finishes: report uncommitted leftovers.
    pub async fn flush(&self) -> Result<FlushReport> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(RamCmd::Flush(tx))
            .await
            .context("ram cache actor stopped")?;
        rx.await.context("ram cache actor dropped flush response")?
    }
}

impl WarcRam {
    pub async fn insert(&self, line: Vec<u8>) -> Result<()> {
        self.tx
            .send(RamCmd::Insert { warc: self.warc.clone(), line })
            .await
            .context("ram cache actor stopped")
    }

    /// Durably write this WARC's findings; call only after its scan fully
    /// succeeded, then record it in the checkpoint.
    pub async fn commit(&self, dest: PathBuf) -> Result<CommitReport> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(RamCmd::Commit { warc: self.warc.clone(), dest, resp: tx })
            .await
            .context("ram cache actor stopped")?;
        rx.await.context("ram cache actor dropped commit response")?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn spawn_ram(cfg: CacheCfg, disk: DiskQueue, capacity: usize) -> RamQueue {
        RamQueue::spawn(cfg, disk, capacity, std::sync::Arc::new(Stats::default()))
    }

    fn cfg_in(dir: &std::path::Path, mem_limit: u64, spill_file_bytes: u64) -> CacheCfg {
        CacheCfg {
            mem_limit_bytes: mem_limit,
            spill_dir: dir.join("spill"),
            spill_file_bytes,
            final_output: dir.join("final.jsonl"),
        }
    }

    fn read_lines(p: &std::path::Path) -> Vec<String> {
        let mut s = String::new();
        std::fs::File::open(p).unwrap().read_to_string(&mut s).unwrap();
        s.lines().map(str::to_owned).collect()
    }

    fn line(i: usize) -> Vec<u8> {
        format!("{{\"n\":{i}}}\n").into_bytes()
    }

    #[tokio::test]
    async fn commit_writes_mem_lines_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let disk = DiskQueue::spawn(2, 16);
        let ram = spawn_ram(cfg_in(dir.path(), 1_000_000, 1024), disk, 64);
        let sink = ram.for_warc("w1");
        sink.insert(line(1)).await.unwrap();
        sink.insert(line(2)).await.unwrap();
        let dest = dir.path().join("partials/w1.jsonl");
        let rep = sink.commit(dest.clone()).await.unwrap();
        assert_eq!(rep.findings, 2);
        assert_eq!(read_lines(&dest).len(), 2);
        assert!(!dir.path().join("partials/w1.jsonl.tmp").exists());
        // nothing left to discard
        let flush = ram.flush().await.unwrap();
        assert_eq!(flush.total_inserted, 2);
        assert_eq!(flush.discarded_findings, 0);
    }

    #[tokio::test]
    async fn commit_of_unknown_warc_creates_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let disk = DiskQueue::spawn(1, 8);
        let ram = spawn_ram(cfg_in(dir.path(), 1_000_000, 1024), disk, 8);
        let dest = dir.path().join("empty.jsonl");
        let rep = ram.for_warc("nothing").commit(dest.clone()).await.unwrap();
        assert_eq!(rep.findings, 0);
        assert!(dest.exists());
        assert_eq!(fs_read(&dest).len(), 0);
    }

    fn fs_read(p: &std::path::Path) -> Vec<u8> {
        std::fs::read(p).unwrap()
    }

    #[tokio::test]
    async fn spill_then_commit_lands_all_lines_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let disk = DiskQueue::spawn(2, 16);
        // tiny memory limit: first insert already overflows -> spill
        let ram = spawn_ram(cfg_in(dir.path(), 10, 1024 * 1024), disk, 64);
        let sink = ram.for_warc("w1");
        for i in 0..10 {
            sink.insert(line(i)).await.unwrap();
        }
        let dest = dir.path().join("partials/w1.jsonl");
        let rep = sink.commit(dest.clone()).await.unwrap();
        assert_eq!(rep.findings, 10);
        let lines = read_lines(&dest);
        let nums: Vec<usize> = lines
            .iter()
            .map(|l| {
                let v: serde_json::Value = serde_json::from_str(l).unwrap();
                v["n"].as_u64().unwrap() as usize
            })
            .collect();
        assert_eq!(nums, (0..10).collect::<Vec<_>>(), "order preserved");
        // spill files cleaned up by commit
        let spill_left = std::fs::read_dir(dir.path().join("spill"))
            .map(|rd| rd.count())
            .unwrap_or(0);
        assert_eq!(spill_left, 0, "spill files removed after commit");
    }

    #[tokio::test]
    async fn spill_files_rotate_and_merge_on_commit() {
        let dir = tempfile::tempdir().unwrap();
        let disk = DiskQueue::spawn(2, 16);
        // 150-byte batches, rotate when a spill file would pass 300 bytes.
        let ram = spawn_ram(cfg_in(dir.path(), 50, 300), disk, 64);
        let sink = ram.for_warc("rot");
        for i in 0..6 {
            sink.insert(format!("{}\n", format!("x{i}").repeat(75)).into_bytes())
                .await
                .unwrap();
        }
        // roundtrip through the actor so all inserts (and their spills) ran
        ram.for_warc("sync").commit(dir.path().join("sync.jsonl")).await.unwrap();

        let spill_dir = dir.path().join("spill");
        let spill_count = std::fs::read_dir(&spill_dir).map(|rd| rd.count()).unwrap_or(0);
        assert!(spill_count >= 2, "expected rotation, got {spill_count}");

        let dest = dir.path().join("rot.jsonl");
        let rep = sink.commit(dest.clone()).await.unwrap();
        assert_eq!(rep.findings, 6);
        assert_eq!(read_lines(&dest).len(), 6);
        assert_eq!(std::fs::read_dir(&spill_dir).map(|rd| rd.count()).unwrap_or(0), 0);
    }

    #[tokio::test]
    async fn flush_discards_uncommitted_and_reports() {
        let dir = tempfile::tempdir().unwrap();
        let disk = DiskQueue::spawn(1, 8);
        let ram = spawn_ram(cfg_in(dir.path(), 10, 1024), disk, 8);
        let sink = ram.for_warc("failed");
        sink.insert(line(1)).await.unwrap();
        sink.insert(line(2)).await.unwrap();
        let flush = ram.flush().await.unwrap();
        assert_eq!(flush.total_inserted, 2);
        assert_eq!(flush.discarded_findings, 2);
        assert_eq!(flush.discarded_spill_files.len(), 1);
        // discarded spill files are gone
        assert!(!flush.discarded_spill_files[0].exists());
        // nothing written anywhere by flush
        assert!(!dir.path().join("final.jsonl").exists());
    }

    #[tokio::test]
    async fn concurrent_warcs_stay_isolated() {
        let dir = tempfile::tempdir().unwrap();
        let disk = DiskQueue::spawn(2, 16);
        let ram = spawn_ram(cfg_in(dir.path(), 1_000_000, 1024), disk, 64);
        let a = ram.for_warc("a");
        let b = ram.for_warc("b");
        a.insert(line(1)).await.unwrap();
        b.insert(line(2)).await.unwrap();
        a.insert(line(3)).await.unwrap();

        let dest_a = dir.path().join("a.jsonl");
        let rep = a.commit(dest_a.clone()).await.unwrap();
        assert_eq!(rep.findings, 2);
        assert_eq!(read_lines(&dest_a).len(), 2);

        let flush = ram.flush().await.unwrap();
        assert_eq!(flush.discarded_findings, 1, "b's finding is uncommitted");
        let dest_b = dir.path().join("b.jsonl");
        assert!(!dest_b.exists());
    }
}
