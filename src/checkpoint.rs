//! Resume state and download hygiene.
//!
//! Every finished WARC is committed to `partials_dir/<warc>.jsonl` and marked
//! in `checkpoint_file`; a later `cargo run` skips those and continues with
//! the remaining files of the same checkpointed download plan. At the end of
//! every run (successful or not) the partial files are assembled into
//! `cache.final_output`, so findings are always on disk and always current.
//!
//! Hygiene: `purge_downloads` wipes the workdir and spill dir on startup
//! (covering SIGKILL/crash leftovers), the signal handler wipes them on
//! Ctrl-C/SIGTERM/SIGHUP, and `run_pipeline` removes each download as soon
//! as it is consumed. The flock in `Lock` keeps two instances from ever
//! sharing a workdir.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::cdx::WarcTarget;
use crate::config::Config;

/// Basename of a WARC path: `crawl-data/.../foo.warc.gz` -> `foo`.
pub fn warc_name(path: &str) -> String {
    path.rsplit('/')
        .next()
        .unwrap_or("warc")
        .trim_end_matches(".warc.gz")
        .to_owned()
}

fn tmp_of(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".tmp");
    PathBuf::from(s)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(p) = path.parent() {
        fs::create_dir_all(p).with_context(|| format!("creating {}", p.display()))?;
    }
    let tmp = tmp_of(path);
    {
        let mut f = File::create(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path).with_context(|| format!("renaming to {}", path.display()))?;
    Ok(())
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CompletedWarc {
    pub findings: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Checkpoint {
    pub version: u32,
    /// The download plan, fixed the first time targets are selected and
    /// extended by one batch per drain when `targets.unlimited` is set.
    pub targets: Vec<WarcTarget>,
    /// WARC base name -> findings committed for it.
    pub completed: BTreeMap<String, CompletedWarc>,
}

impl Default for Checkpoint {
    fn default() -> Self {
        Self {
            version: 1,
            targets: Vec::new(),
            completed: BTreeMap::new(),
        }
    }
}

/// Findings assembled from all partial files at the end of a run.
#[derive(Debug, Default, Clone, Copy)]
pub struct Assembled {
    pub files: usize,
    pub findings: u64,
    pub bytes: u64,
}

impl Checkpoint {
    /// Load the checkpoint, migrating a legacy monolithic `final_output`
    /// (written before per-WARC commits existed) into partial files first.
    pub fn load(cfg: &Config) -> Result<Checkpoint> {
        let path = &cfg.paths.checkpoint_file;
        if !path.exists() {
            if let Some(cp) = migrate_legacy(cfg)? {
                tracing::info!(
                    warcs = cp.completed.len(),
                    "migrated legacy findings file into per-WARC partials"
                );
                cp.save(cfg)?;
                return Ok(cp);
            }
            return Ok(Checkpoint::default());
        }
        let raw = fs::read_to_string(path)
            .with_context(|| format!("reading checkpoint {}", path.display()))?;
        serde_json::from_str(&raw).with_context(|| format!("parsing checkpoint {}", path.display()))
    }

    /// Atomic write: temp file + rename, so a crash can't corrupt state.
    pub fn save(&self, cfg: &Config) -> Result<()> {
        let json = serde_json::to_string_pretty(self).context("serializing checkpoint")?;
        write_atomic(&cfg.paths.checkpoint_file, json.as_bytes())
    }

    pub fn is_complete(&self, warc: &str) -> bool {
        self.completed.contains_key(warc)
    }

    pub fn mark_complete(&mut self, warc: &str, findings: u64) {
        self.completed.insert(warc.to_owned(), CompletedWarc { findings });
    }
}

/// Concatenate `partials_dir/*.jsonl` into `cache.final_output` (atomically).
pub fn assemble(cfg: &Config) -> Result<Assembled> {
    let dir = &cfg.paths.partials_dir;
    let mut paths: Vec<PathBuf> = match fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
            .collect(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e).context("reading partials dir"),
    };
    paths.sort();

    let out = &cfg.cache.final_output;
    let tmp = tmp_of(out);
    let mut rep = Assembled::default();
    {
        let mut w =
            BufWriter::new(File::create(&tmp).with_context(|| format!("creating {}", tmp.display()))?);
        let mut buf = vec![0u8; 64 * 1024];
        for p in &paths {
            let mut r = File::open(p).with_context(|| format!("opening {}", p.display()))?;
            loop {
                let n = r.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                w.write_all(&buf[..n])?;
                rep.bytes += n as u64;
                rep.findings += buf[..n].iter().filter(|&&b| b == b'\n').count() as u64;
            }
            rep.files += 1;
        }
        w.flush()?;
        w.into_inner()
            .map_err(|e| e.into_error())?
            .sync_all()?;
    }
    fs::rename(&tmp, out).with_context(|| format!("renaming to {}", out.display()))?;
    Ok(rep)
}

/// Which WARC does this findings line belong to? (legacy-file migration)
fn warc_of_line(line: &str) -> String {
    let unknown = || "unattributed".to_string();
    let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
        return unknown();
    };
    let Some(p) = v["SourceMetadata"]["Data"]["Filesystem"]["file"].as_str() else {
        return unknown();
    };
    // paths look like `work/<name>.chunks/chunk-00001.warc`
    let seg = p.rsplit(['/', '\\']).find(|s| s.contains(".chunks")).unwrap_or("");
    if seg.is_empty() {
        unknown()
    } else {
        seg.trim_end_matches(".chunks").to_owned()
    }
}

/// One-time conversion: old `final_output` -> `partials/<warc>.jsonl` +
/// checkpoint marks. Returns `None` when there is nothing to migrate.
fn migrate_legacy(cfg: &Config) -> Result<Option<Checkpoint>> {
    let final_output = &cfg.cache.final_output;
    if !final_output.exists() {
        return Ok(None);
    }
    // Start partials from scratch — they only exist without a checkpoint when
    // this migration (or a manual deletion) removed it.
    if cfg.paths.partials_dir.exists() {
        fs::remove_dir_all(&cfg.paths.partials_dir)
            .with_context(|| format!("clearing {}", cfg.paths.partials_dir.display()))?;
    }
    let f = File::open(final_output)
        .with_context(|| format!("opening legacy {}", final_output.display()))?;
    let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for line in BufReader::new(f).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        groups.entry(warc_of_line(&line)).or_default().push(line);
    }
    let mut cp = Checkpoint::default();
    for (name, lines) in &groups {
        let dest = cfg.paths.partials_dir.join(format!("{name}.jsonl"));
        let mut body = Vec::new();
        for l in lines {
            body.extend_from_slice(l.as_bytes());
            body.push(b'\n');
        }
        write_atomic(&dest, &body)?;
        cp.mark_complete(name, lines.len() as u64);
    }
    Ok(Some(cp))
}

/// Remove every downloaded/leftover byte a previous run (or a crash) may have
/// left behind: the whole workdir, spill files, and in-progress temp files.
/// Per-WARC partials, the checkpoint and the final output are kept.
pub fn purge_downloads(cfg: &Config) -> Result<usize> {
    let mut purged = 0usize;
    let gone = |p: &Path, n: &mut usize| -> Result<()> {
        if p.exists() {
            let entries = fs::read_dir(p).map(|rd| rd.count()).unwrap_or(0);
            fs::remove_dir_all(p).with_context(|| format!("purging {}", p.display()))?;
            *n += entries;
        }
        Ok(())
    };
    gone(&cfg.paths.workdir, &mut purged)?;
    gone(&cfg.cache.spill_dir, &mut purged)?;
    let _ = fs::remove_file(tmp_of(&cfg.paths.checkpoint_file));
    let _ = fs::remove_file(tmp_of(&cfg.cache.final_output));
    fs::create_dir_all(&cfg.paths.workdir)
        .with_context(|| format!("recreating {}", cfg.paths.workdir.display()))?;
    Ok(purged)
}

/// Single-instance guard: an exclusive flock on `<results>/.lock`. Released by
/// the OS if the process dies, so a stale file never blocks a new run.
#[derive(Debug)]
pub struct Lock {
    file: File,
    path: PathBuf,
}

impl Lock {
    pub fn acquire(dir: &Path) -> Result<Lock> {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        let path = dir.join(".lock");
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)
            .with_context(|| format!("opening lock {}", path.display()))?;
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            let holder = fs::read_to_string(&path).unwrap_or_default();
            let holder = holder.trim();
            let who = if holder.is_empty() {
                String::new()
            } else {
                format!(" (pid {holder})")
            };
            bail!(
                "another apikeyfinder instance{who} is running — refusing to share {}",
                dir.display()
            );
        }
        file.set_len(0)?;
        writeln!(&file, "{}", std::process::id())?;
        Ok(Lock { file, path })
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_in(dir: &Path) -> Config {
        let mut cfg = Config::default();
        cfg.paths.workdir = dir.join("work");
        cfg.paths.checkpoint_file = dir.join("results/checkpoint.json");
        cfg.paths.partials_dir = dir.join("results/partials");
        cfg.cache.final_output = dir.join("results/findings.jsonl");
        cfg.cache.spill_dir = dir.join("results/spill");
        cfg
    }

    #[test]
    fn warc_name_strips_path_and_suffix() {
        assert_eq!(
            warc_name("crawl-data/CC-MAIN-2026-39/warc/seg-00001.warc.gz"),
            "seg-00001"
        );
        assert_eq!(warc_name("foo.warc.gz"), "foo");
    }

    #[test]
    fn save_load_roundtrip_and_marks() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg_in(dir.path());
        let mut cp = Checkpoint::default();
        cp.targets.push(WarcTarget {
            path: "crawl-data/x/a.warc.gz".into(),
            url: "https://data/a.warc.gz".into(),
            hits: 3,
            size: 42,
        });
        cp.mark_complete("a", 7);
        cp.save(&cfg).unwrap();

        let loaded = Checkpoint::load(&cfg).unwrap();
        assert_eq!(loaded.targets.len(), 1);
        assert_eq!(loaded.targets[0].size, 42);
        assert!(loaded.is_complete("a"));
        assert!(!loaded.is_complete("b"));
        assert_eq!(loaded.completed["a"].findings, 7);
        // atomic write leaves no temp file behind
        assert!(!tmp_of(&cfg.paths.checkpoint_file).exists());
    }

    #[test]
    fn assemble_concatenates_partials() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg_in(dir.path());
        fs::create_dir_all(&cfg.paths.partials_dir).unwrap();
        fs::write(cfg.paths.partials_dir.join("b.jsonl"), "{\"n\":2}\n").unwrap();
        fs::write(cfg.paths.partials_dir.join("a.jsonl"), "{\"n\":1}\n{\"n\":3}\n").unwrap();
        fs::write(cfg.paths.partials_dir.join("stray.txt"), "ignored").unwrap();

        let rep = assemble(&cfg).unwrap();
        assert_eq!(rep.files, 2);
        assert_eq!(rep.findings, 3);
        assert_eq!(rep.bytes, 24);
        let out = fs::read_to_string(&cfg.cache.final_output).unwrap();
        // sorted by name: a before b
        assert_eq!(out, "{\"n\":1}\n{\"n\":3}\n{\"n\":2}\n");
    }

    #[test]
    fn migrate_splits_legacy_final_output() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg_in(dir.path());
        fs::create_dir_all(cfg.cache.final_output.parent().unwrap()).unwrap();
        let mk = |det: &str, file: &str| {
            format!(
                r#"{{"DetectorName":"{det}","SourceMetadata":{{"Data":{{"Filesystem":{{"file":"{file}"}}}}}}}}"#
            )
        };
        let body = [
            mk("A", "work/w1.chunks/chunk-000001.warc"),
            mk("B", "work/w1.chunks/chunk-000002.warc"),
            mk("C", "work/w2.chunks/chunk-000001.warc"),
            "{\"DetectorName\":\"D\"}".to_string(), // no source info
        ]
        .join("\n");
        fs::write(&cfg.cache.final_output, body + "\n").unwrap();

        let cp = Checkpoint::load(&cfg).unwrap();
        assert!(cp.is_complete("w1"));
        assert!(cp.is_complete("w2"));
        assert!(cp.is_complete("unattributed"));
        assert_eq!(cp.completed["w1"].findings, 2);
        // partials written, legacy file untouched
        assert!(cfg.paths.partials_dir.join("w1.jsonl").exists());
        assert!(cfg.cache.final_output.exists());
        // second load uses the checkpoint, not a re-migration
        let again = Checkpoint::load(&cfg).unwrap();
        assert_eq!(again.completed.len(), 3);
        assert!(again.targets.is_empty());
    }

    #[test]
    fn purge_removes_downloads_and_spill_but_keeps_results() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg_in(dir.path());
        fs::create_dir_all(cfg.paths.workdir.join("x.chunks")).unwrap();
        fs::write(cfg.paths.workdir.join("a.warc.gz"), b"gz").unwrap();
        fs::write(cfg.paths.workdir.join("x.chunks/c1.warc"), b"c").unwrap();
        fs::create_dir_all(&cfg.cache.spill_dir).unwrap();
        fs::write(cfg.cache.spill_dir.join("spill-1.jsonl"), b"s").unwrap();
        fs::create_dir_all(&cfg.paths.partials_dir).unwrap();
        fs::write(cfg.paths.partials_dir.join("w.jsonl"), b"{}\n").unwrap();
        fs::write(&cfg.cache.final_output, b"{}\n").unwrap();

        let n = purge_downloads(&cfg).unwrap();
        assert!(n >= 2, "purged={n}");
        assert!(!cfg.paths.workdir.join("a.warc.gz").exists());
        assert!(!cfg.paths.workdir.join("x.chunks").exists());
        assert!(!cfg.cache.spill_dir.exists());
        assert!(cfg.paths.workdir.exists(), "workdir recreated");
        // results survive
        assert!(cfg.paths.partials_dir.join("w.jsonl").exists());
        assert!(cfg.cache.final_output.exists());
        // idempotent
        assert_eq!(purge_downloads(&cfg).unwrap(), 0);
    }

    #[test]
    fn lock_is_exclusive_and_releasable() {
        let dir = tempfile::tempdir().unwrap();
        let held = Lock::acquire(dir.path()).unwrap();
        let err = Lock::acquire(dir.path()).expect_err("second lock must fail");
        assert!(err.to_string().contains("another apikeyfinder"), "{err}");
        let path = held.path.clone();
        drop(held);
        assert!(!path.exists(), "lock file removed on drop");
        let again = Lock::acquire(dir.path()).expect("lock after release");
        drop(again);
    }
}
