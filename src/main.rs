mod cdx;
mod checkpoint;
mod config;
mod queues;
mod scan;
mod split;
mod stats;

use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinSet;

use crate::checkpoint::{warc_name, Assembled, Checkpoint, Lock};
use crate::cdx::WarcTarget;
use crate::config::Config;
use crate::queues::disk::DiskQueue;
use crate::queues::network::NetworkQueue;
use crate::queues::ram::{FlushReport, RamQueue, WarcRam};
use crate::stats::Stats;

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cfg_path: PathBuf = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("config.toml"));
    let cfg = Arc::new(Config::load(&cfg_path)?);
    tracing::info!(
        config = %cfg_path.display(),
        target_bytes = cfg.targets.target_bytes,
        mem_limit_bytes = cfg.cache.mem_limit_bytes,
        parallel_fetches = cfg.download.parallel_fetches,
        "apikeyfinder starting"
    );
    preflight(&cfg).await?;

    // Single instance + crash hygiene before anything touches the workdir.
    let lock_dir = cfg
        .paths
        .checkpoint_file
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let lock = Lock::acquire(&lock_dir)?;
    match checkpoint::purge_downloads(&cfg) {
        Ok(0) => {}
        Ok(n) => tracing::warn!(
            stale_entries = n,
            "purged leftover downloads/spill files from a previous run"
        ),
        Err(e) => tracing::warn!(error = %format!("{e:#}"), "startup cleanup failed"),
    }
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    spawn_signal_cleanup(cfg.clone(), shutdown_tx);

    let stats = Arc::new(Stats::default());
    let disk = DiskQueue::spawn(cfg.queues.disk_workers, cfg.queues.disk_capacity);
    let net = NetworkQueue::new(&cfg, disk.clone(), stats.clone());
    let ram = RamQueue::spawn(cfg.cache.clone(), disk.clone(), cfg.queues.ram_capacity, stats.clone());

    disk.mkdir(&cfg.paths.workdir).await.context("creating workdir")?;
    tokio::spawn(progress_loop(stats.clone(), net.clone(), cfg.clone()));

    // Resume state: the download plan is fixed the first time targets are
    // selected and reused by every later run.
    let cp = Arc::new(Mutex::new(Checkpoint::load(&cfg)?));
    let saved: Option<Vec<WarcTarget>> = {
        let g = cp.lock().unwrap_or_else(|e| e.into_inner());
        if g.targets.is_empty() { None } else { Some(g.targets.clone()) }
    };
    let targets = match saved {
        Some(t) => {
            tracing::info!(
                warcs = t.len(),
                "resume: reusing the checkpointed download plan (no index query)"
            );
            t
        }
        None => {
            let t = cdx::select_warcs(&cfg, &net, &stats).await?;
            let mut g = cp.lock().unwrap_or_else(|e| e.into_inner());
            g.targets = t.clone();
            g.save(&cfg)?;
            t
        }
    };
    let (pending, cached) = {
        let g = cp.lock().unwrap_or_else(|e| e.into_inner());
        let mut pending = Vec::new();
        let mut cached = 0usize;
        for t in &targets {
            if g.is_complete(&warc_name(&t.path)) {
                cached += 1;
            } else {
                pending.push(t.clone());
            }
        }
        (pending, cached)
    };
    stats.warcs_total.store(pending.len(), Ordering::Relaxed);
    stats.warcs_cached.store(cached, Ordering::Relaxed);
    if targets.is_empty() {
        tracing::warn!("no download targets; finishing after cache flush");
    }
    if cached > 0 {
        tracing::info!(
            already_done = cached,
            remaining = pending.len(),
            total = targets.len(),
            "resume: skipping completed WARC(s)"
        );
    }

    // Stage 2-4, chained per remaining file: download -> awk split -> scan -> commit.
    let split_sem = Arc::new(Semaphore::new(cfg.split.max_concurrent));
    let scan_sem = Arc::new(Semaphore::new(cfg.scan.workers));
    let mut set: JoinSet<Result<()>> = JoinSet::new();
    for target in pending {
        set.spawn(run_pipeline(
            target,
            cfg.clone(),
            net.clone(),
            disk.clone(),
            ram.clone(),
            stats.clone(),
            split_sem.clone(),
            scan_sem.clone(),
            cp.clone(),
        ));
    }

    let mut ok = 0usize;
    let mut failed = 0usize;
    let mut errors: Vec<String> = Vec::new();
    let mut shutdown_rx = shutdown_rx;
    let mut interrupted = false;
    loop {
        tokio::select! {
            biased;
            changed = shutdown_rx.changed() => {
                let _ = changed;
                interrupted = true;
                break;
            }
            maybe = set.join_next() => match maybe {
                None => break,
                Some(Ok(Ok(()))) => ok += 1,
                Some(Ok(Err(e))) => {
                    failed += 1;
                    stats.inc_usize(&stats.warcs_failed);
                    errors.push(format!("{e:#}"));
                }
                Some(Err(e)) => {
                    failed += 1;
                    stats.inc_usize(&stats.warcs_failed);
                    errors.push(format!("pipeline task panicked: {e}"));
                }
            }
        }
    }

    if interrupted {
        // Stop every pipeline first so nothing re-creates files under us,
        // then purge until clean and release the lock properly.
        set.shutdown().await;
        tokio::time::sleep(Duration::from_millis(800)).await;
        cleanup_downloads_until_clean(&cfg).await;
        // Committed partials are durable — publish them before exiting so the
        // viewer shows this run's progress too.
        match checkpoint::assemble(&cfg) {
            Ok(a) => tracing::info!(
                files = a.files,
                findings = a.findings,
                "findings re-assembled from completed WARC(s)"
            ),
            Err(e) => tracing::warn!(error = %format!("{e:#}"), "assembly failed"),
        }
        drop(lock);
        tracing::warn!("cleanup complete — exiting");
        std::process::exit(130);
    }

    // End of run: discard uncommitted leftovers, then assemble the final
    // findings file from every committed partial (this run's + resumed ones).
    let leftover = ram.flush().await?;
    let assembled = checkpoint::assemble(&cfg)?;

    summary(
        &stats,
        &leftover,
        &assembled,
        ok,
        failed,
        cached,
        cfg.scan.only_verified,
    );
    for e in &errors {
        tracing::error!(error = %e, "pipeline failure");
    }
    if ok == 0 && failed > 0 {
        bail!("all {failed} pipeline task(s) failed");
    }
    Ok(())
}

/// Per-WARC pipeline. Downloads are all enqueued up front (the network queue
/// absorbs the burst); split and scan concurrency are bounded by semaphores.
/// Whatever happens — success, error, or early return — the downloaded WARC
/// and its chunk dir are removed here (a crash leaves files behind, but the
/// next start purges them).
#[allow(clippy::too_many_arguments)]
async fn run_pipeline(
    target: WarcTarget,
    cfg: Arc<Config>,
    net: NetworkQueue,
    disk: DiskQueue,
    ram: RamQueue,
    stats: Arc<Stats>,
    split_sem: Arc<Semaphore>,
    scan_sem: Arc<Semaphore>,
    cp: Arc<Mutex<Checkpoint>>,
) -> Result<()> {
    let name = warc_name(&target.path);
    let gz = cfg.paths.workdir.join(format!("{name}.warc.gz"));
    let chunks_dir = cfg.paths.workdir.join(format!("{name}.chunks"));

    let result = process_warc(
        name,
        target,
        gz.clone(),
        chunks_dir.clone(),
        cfg.clone(),
        net,
        disk.clone(),
        ram,
        stats,
        split_sem,
        scan_sem,
        cp,
    )
    .await;

    if !cfg.paths.keep_warcs {
        disk.remove_file(&gz).await.ok();
    }
    if !cfg.paths.keep_chunks {
        disk.remove_tree(&chunks_dir).await.ok();
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn process_warc(
    name: String,
    target: WarcTarget,
    gz: PathBuf,
    chunks_dir: PathBuf,
    cfg: Arc<Config>,
    net: NetworkQueue,
    disk: DiskQueue,
    ram: RamQueue,
    stats: Arc<Stats>,
    split_sem: Arc<Semaphore>,
    scan_sem: Arc<Semaphore>,
    cp: Arc<Mutex<Checkpoint>>,
) -> Result<()> {
    let outcome = net
        .download(target.url.clone(), gz.clone())
        .await
        .with_context(|| format!("downloading {}", target.path))?;
    tracing::info!(
        warc = %name,
        bytes = outcome.bytes_written,
        source_bytes = target.size,
        index_hits = target.hits,
        truncated = outcome.truncated,
        "warc ready for split"
    );
    stats.inc_usize(&stats.warcs_downloaded);

    // Split under the shared split permit (bounded decompress+awk concurrency).
    let split_permit = split_sem
        .acquire()
        .await
        .context("split semaphore closed")?;
    let out = split::split_warc(cfg.clone(), disk.clone(), stats.clone(), gz.clone(), chunks_dir.clone())
        .await
        .with_context(|| format!("splitting {}", gz.display()));
    drop(split_permit);
    let out = out?;

    tracing::debug!(
        warc = %name,
        frames = out.frames,
        chunk_bytes = out.chunk_bytes,
        records_kept = out.kept,
        records_skipped = out.skipped,
        records_invalid = out.invalid,
        decompressed = out.decompressed_bytes,
        "split stats"
    );

    if !cfg.paths.keep_warcs {
        disk.remove_file(&gz).await.ok();
    }

    let sink: WarcRam = ram.for_warc(&name);

    if out.frames == 0 {
        tracing::warn!(warc = %name, "no records survived the filters; nothing to scan");
        commit(&cfg, &cp, &name, sink).await?;
        return Ok(());
    }

    // Scan under the shared scan permit (bounded concurrent trufflehog runs).
    let scan_permit = scan_sem
        .acquire()
        .await
        .context("scan semaphore closed")?;
    let chunk_dir = out.dir.clone();
    let scan_result =
        scan::scan_dir(cfg.clone(), sink.clone(), stats.clone(), chunk_dir.clone()).await;
    drop(scan_permit);
    stats.inc_usize(&stats.scans_done);

    let scan_result = scan_result.with_context(|| format!("scanning {}", chunk_dir.display()));
    if scan_result.is_err() {
        stats.inc_usize(&stats.scans_failed);
    }
    scan_result?;

    // Scan fully succeeded — make the findings durable, then checkpoint.
    commit(&cfg, &cp, &name, sink).await
}

/// Write this WARC's findings to its partial file and mark it complete. Only
/// after both steps does the next `cargo run` consider the WARC done.
async fn commit(cfg: &Config, cp: &Arc<Mutex<Checkpoint>>, name: &str, sink: WarcRam) -> Result<()> {
    let dest = cfg.paths.partials_dir.join(format!("{name}.jsonl"));
    let report = sink
        .commit(dest.clone())
        .await
        .with_context(|| format!("committing findings for {name}"))?;
    {
        let mut g = cp.lock().unwrap_or_else(|e| e.into_inner());
        g.mark_complete(name, report.findings);
        g.save(cfg)?;
    }
    tracing::info!(
        warc = %name,
        findings = report.findings,
        bytes = report.bytes,
        partial = %dest.display(),
        "warc committed (checkpoint updated)"
    );
    Ok(())
}

async fn preflight(cfg: &Config) -> Result<()> {
    let tools: Vec<(&str, &str)> = vec![
        (cfg.split.awk_binary.as_str(), "split.awk_binary (needed before any download)"),
        (cfg.scan.binary.as_str(), "scan.binary (needed before any download)"),
    ];
    for (bin, what) in tools {
        let bin = bin.to_string();
        let present = {
            let bin_for_check = bin.clone();
            tokio::task::spawn_blocking(move || {
                std::process::Command::new(&bin_for_check)
                    .arg("--version")
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                    .is_ok()
            })
            .await
            .unwrap_or(false)
        };
        if !present {
            bail!("{bin} not runnable — check {what}");
        }
    }
    Ok(())
}

/// On SIGINT/SIGTERM/SIGHUP: tell the main flow to stop, purge downloads
/// best-effort right away, and — as a safety net if the main flow is still
/// busy elsewhere (e.g. index selection) — force the exit after a grace
/// period. Checkpoint, partials and final findings are never touched.
fn spawn_signal_cleanup(cfg: Arc<Config>, shutdown: watch::Sender<bool>) {
    tokio::spawn(async move {
        let term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate());
        let hup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup());
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = async { match term { Ok(mut s) => s.recv().await, _ => None } } => {}
            _ = async { match hup { Ok(mut s) => s.recv().await, _ => None } } => {}
        }
        tracing::warn!("interrupt signal — stopping pipelines and removing all downloaded files");
        let _ = shutdown.send(true);
        let cfg_eager = cfg.clone();
        let _ = tokio::task::spawn_blocking(move || checkpoint::purge_downloads(&cfg_eager)).await;
        // Safety net: if nothing else handled the shutdown, force it.
        tokio::time::sleep(Duration::from_secs(15)).await;
        let _ = tokio::task::spawn_blocking(move || checkpoint::purge_downloads(&cfg)).await;
        std::process::exit(130);
    });
}

/// Purge in a few passes: in-flight disk jobs can recreate directories for a
/// moment after the pipelines are stopped.
async fn cleanup_downloads_until_clean(cfg: &Config) {
    for attempt in 1..=8 {
        match checkpoint::purge_downloads(cfg) {
            Ok(0) => return,
            Ok(n) => tracing::debug!(attempt, remaining = n, "cleanup pass"),
            Err(e) => tracing::debug!(attempt, error = %format!("{e:#}"), "cleanup pass"),
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    tracing::warn!("some downloads may remain — they are purged at the next start");
}

async fn progress_loop(stats: Arc<Stats>, net: NetworkQueue, cfg: Arc<Config>) {
    let period = Duration::from_secs(cfg.progress_interval_secs.max(1));
    let mut tick = tokio::time::interval(period);
    tick.tick().await; // skip the immediate first tick
    loop {
        tick.tick().await;
        let dl = stats.download_bytes.load(Ordering::Relaxed);
        let sel = stats.downloads_selected_bytes.load(Ordering::Relaxed);
        tracing::info!(
            target: "apikeyfinder::progress",
            "download {}/{} bytes, files {}/{}, network queue {} job(s) / {} worker(s), \
             chunks {} ({} kept / {} skipped / {} invalid records), findings {} ({} spilled)"
            ,
            dl,
            sel,
            stats.warcs_downloaded.load(Ordering::Relaxed),
            stats.warcs_total.load(Ordering::Relaxed),
            net.depth(),
            net.workers(),
            stats.chunks_written.load(Ordering::Relaxed),
            stats.records_kept.load(Ordering::Relaxed),
            stats.records_skipped.load(Ordering::Relaxed),
            stats.records_invalid.load(Ordering::Relaxed),
            stats.findings_inserted.load(Ordering::Relaxed),
            stats.spilled_findings.load(Ordering::Relaxed),
        );
    }
}

fn summary(
    stats: &Stats,
    leftover: &FlushReport,
    assembled: &Assembled,
    ok: usize,
    failed: usize,
    cached: usize,
    only_verified: bool,
) {
    tracing::info!(
        "=== summary ==="
    );
    if cached > 0 || ok > 0 {
        tracing::info!(
            resumed_from_checkpoint = cached,
            warcs_ok = ok,
            warcs_failed = failed,
            "resume"
        );
    }
    tracing::info!(
        download_bytes = stats.download_bytes.load(Ordering::Relaxed),
        splits_done = stats.split_done.load(Ordering::Relaxed),
        chunks_written = stats.chunks_written.load(Ordering::Relaxed),
        chunk_bytes = stats.chunk_bytes.load(Ordering::Relaxed),
        records_kept = stats.records_kept.load(Ordering::Relaxed),
        records_skipped = stats.records_skipped.load(Ordering::Relaxed),
        records_invalid = stats.records_invalid.load(Ordering::Relaxed),
        "pipeline"
    );
    tracing::info!(
        inserted_this_run = leftover.total_inserted,
        discarded_uncommitted = leftover.discarded_findings,
        spilled_findings = stats.spilled_findings.load(Ordering::Relaxed),
        spilled_bytes = stats.spilled_bytes.load(Ordering::Relaxed),
        spill_batches = stats.spill_events.load(Ordering::Relaxed),
        "findings cache"
    );
    if leftover.discarded_findings > 0 {
        tracing::warn!(
            discarded = leftover.discarded_findings,
            "findings from WARC(s) that did not finish were discarded — they are redone on the next run"
        );
    }
    tracing::info!(
        files = assembled.files,
        findings = assembled.findings,
        bytes = assembled.bytes,
        findings_with_source_record = stats.artifacts_attached.load(Ordering::Relaxed),
        "final findings assembled from per-WARC partials"
    );
    if assembled.findings == 0 && only_verified {
        tracing::warn!(
            only_verified,
            "no findings recorded (with only_verified=true this is typical on public crawl data)"
        );
    }
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("apikeyfinder=info,reqwest=warn,rustls=warn"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .init();
}
