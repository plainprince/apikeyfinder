//! Central disk queue: every Rust-initiated file write/create/remove goes
//! through one bounded channel consumed by dedicated workers running on the
//! blocking pool, so disk I/O never stalls the async runtime (and heavy
//! download writes get natural backpressure through the queue).

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use tokio::sync::{mpsc, oneshot};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMode {
    /// create + truncate (fresh file)
    CreateTruncate,
    /// create or append (spill logs)
    AppendCreate,
}

enum DiskJob {
    Open {
        path: PathBuf,
        mode: OpenMode,
        resp: oneshot::Sender<io::Result<Arc<Mutex<File>>>>,
    },
    /// Single buffer write to an already-open file.
    Write {
        file: Arc<Mutex<File>>,
        data: Vec<u8>,
        resp: oneshot::Sender<io::Result<usize>>,
    },
    /// Many buffers written to one file (chunk frames, cache spill/flush).
    WriteParts {
        file: Arc<Mutex<File>>,
        parts: Vec<Vec<u8>>,
        resp: oneshot::Sender<io::Result<u64>>,
    },
    /// Open (per mode), write all parts, close. One round-trip file write.
    WritePath {
        path: PathBuf,
        mode: OpenMode,
        parts: Vec<Vec<u8>>,
        resp: oneshot::Sender<io::Result<u64>>,
    },
    Mkdir {
        path: PathBuf,
        resp: oneshot::Sender<io::Result<()>>,
    },
    RemoveTree {
        path: PathBuf,
        resp: oneshot::Sender<io::Result<()>>,
    },
    RemoveFile {
        path: PathBuf,
        resp: oneshot::Sender<io::Result<()>>,
    },
}

fn write_parts(file: &Arc<Mutex<File>>, parts: &[Vec<u8>]) -> io::Result<u64> {
    let mut f = file.lock().unwrap_or_else(|e| e.into_inner());
    let mut total = 0u64;
    for p in parts {
        f.write_all(p)?;
        total += p.len() as u64;
    }
    Ok(total)
}

fn execute(job: DiskJob) {
    match job {
        DiskJob::Open { path, mode, resp } => {
            let _ = resp.send(open_path(&path, mode));
        }
        DiskJob::Write { file, data, resp } => {
            let r = (|| {
                let mut f = file.lock().unwrap_or_else(|e| e.into_inner());
                f.write_all(&data)?;
                Ok(data.len())
            })();
            let _ = resp.send(r);
        }
        DiskJob::WriteParts { file, parts, resp } => {
            let _ = resp.send(write_parts(&file, &parts));
        }
        DiskJob::WritePath { path, mode, parts, resp } => {
            let _ = resp.send((|| {
                let file = open_path(&path, mode)?;
                write_parts(&file, &parts)
            })());
        }
        DiskJob::Mkdir { path, resp } => {
            let _ = resp.send(std::fs::create_dir_all(&path));
        }
        DiskJob::RemoveTree { path, resp } => {
            let r = match std::fs::remove_dir_all(&path) {
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                r => r,
            };
            let _ = resp.send(r);
        }
        DiskJob::RemoveFile { path, resp } => {
            let r = match std::fs::remove_file(&path) {
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                r => r,
            };
            let _ = resp.send(r);
        }
    }
}

fn open_path(path: &Path, mode: OpenMode) -> io::Result<Arc<Mutex<File>>> {
    let mut opts = OpenOptions::new();
    opts.write(true).create(true);
    match mode {
        OpenMode::CreateTruncate => {
            opts.truncate(true);
        }
        OpenMode::AppendCreate => {
            opts.append(true);
        }
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    opts.open(path).map(|f| Arc::new(Mutex::new(f)))
}

#[derive(Clone)]
pub struct DiskQueue {
    tx: mpsc::Sender<DiskJob>,
}

impl DiskQueue {
    pub fn spawn(workers: usize, capacity: usize) -> Self {
        let (tx, rx) = mpsc::channel::<DiskJob>(capacity);
        // Shared receiver so `workers` tasks can pull concurrently.
        let rx = Arc::new(tokio::sync::Mutex::new(rx));
        for _ in 0..workers {
            let rx = rx.clone();
            tokio::spawn(async move {
                loop {
                    let job = {
                        let mut rx = rx.lock().await;
                        match rx.recv().await {
                            Some(j) => j,
                            None => return,
                        }
                    };
                    // One blocking op per worker task => `workers` concurrent
                    // disk operations, all off the async runtime.
                    if tokio::task::spawn_blocking(move || execute(job)).await.is_err() {
                        tracing::error!("disk worker blocking task join failed");
                    }
                }
            });
        }
        Self { tx }
    }

    pub async fn open(&self, path: impl Into<PathBuf>, mode: OpenMode) -> io::Result<Arc<Mutex<File>>> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(DiskJob::Open { path: path.into(), mode, resp: tx })
            .await
            .map_err(|_| io::Error::other("disk queue closed"))?;
        rx.await.map_err(|_| io::Error::other("disk worker gone"))?
    }

    pub async fn write(&self, file: &Arc<Mutex<File>>, data: Vec<u8>) -> io::Result<usize> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(DiskJob::Write { file: file.clone(), data, resp: tx })
            .await
            .map_err(|_| io::Error::other("disk queue closed"))?;
        rx.await.map_err(|_| io::Error::other("disk worker gone"))?
    }

    pub async fn write_parts(&self, file: &Arc<Mutex<File>>, parts: Vec<Vec<u8>>) -> io::Result<u64> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(DiskJob::WriteParts { file: file.clone(), parts, resp: tx })
            .await
            .map_err(|_| io::Error::other("disk queue closed"))?;
        rx.await.map_err(|_| io::Error::other("disk worker gone"))?
    }

    /// Open (per mode), write all parts, close. One round-trip file write.
    /// Only tests use this directly — production writes hold handles or go
    /// through the blocking variant.
    #[cfg(test)]
    pub async fn write_path(
        &self,
        path: impl Into<PathBuf>,
        mode: OpenMode,
        parts: Vec<Vec<u8>>,
    ) -> io::Result<u64> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(DiskJob::WritePath { path: path.into(), mode, parts, resp: tx })
            .await
            .map_err(|_| io::Error::other("disk queue closed"))?;
        rx.await.map_err(|_| io::Error::other("disk worker gone"))?
    }

    pub async fn mkdir(&self, path: impl Into<PathBuf>) -> io::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(DiskJob::Mkdir { path: path.into(), resp: tx })
            .await
            .map_err(|_| io::Error::other("disk queue closed"))?;
        rx.await.map_err(|_| io::Error::other("disk worker gone"))?
    }

    pub async fn remove_tree(&self, path: impl Into<PathBuf>) -> io::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(DiskJob::RemoveTree { path: path.into(), resp: tx })
            .await
            .map_err(|_| io::Error::other("disk queue closed"))?;
        rx.await.map_err(|_| io::Error::other("disk worker gone"))?
    }

    pub async fn remove_file(&self, path: impl Into<PathBuf>) -> io::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(DiskJob::RemoveFile { path: path.into(), resp: tx })
            .await
            .map_err(|_| io::Error::other("disk queue closed"))?;
        rx.await.map_err(|_| io::Error::other("disk worker gone"))?
    }

    // -- blocking variants, for threads already off the runtime (awk frame pump) --

    pub fn write_path_blocking(&self, path: impl Into<PathBuf>, parts: Vec<Vec<u8>>) -> io::Result<u64> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .blocking_send(DiskJob::WritePath { path: path.into(), mode: OpenMode::CreateTruncate, parts, resp: tx })
            .map_err(|_| io::Error::other("disk queue closed"))?;
        rx.blocking_recv().map_err(|_| io::Error::other("disk worker gone"))?
    }

    pub fn mkdir_blocking(&self, path: impl Into<PathBuf>) -> io::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .blocking_send(DiskJob::Mkdir { path: path.into(), resp: tx })
            .map_err(|_| io::Error::other("disk queue closed"))?;
        rx.blocking_recv().map_err(|_| io::Error::other("disk worker gone"))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[tokio::test]
    async fn write_path_roundtrip_and_remove() {
        let dir = tempfile::tempdir().unwrap();
        let q = DiskQueue::spawn(2, 16);
        let path = dir.path().join("a/b/out.bin");

        let n = q
            .write_path(&path, OpenMode::CreateTruncate, vec![b"hello ".to_vec(), b"world".to_vec()])
            .await
            .unwrap();
        assert_eq!(n, 11);

        let mut s = String::new();
        File::open(&path).unwrap().read_to_string(&mut s).unwrap();
        assert_eq!(s, "hello world");

        // append mode
        q.write_path(&path, OpenMode::AppendCreate, vec![b"!".to_vec()]).await.unwrap();
        let mut s = String::new();
        File::open(&path).unwrap().read_to_string(&mut s).unwrap();
        assert_eq!(s, "hello world!");

        // open + write share handles correctly
        let f = q.open(&path, OpenMode::CreateTruncate).await.unwrap();
        q.write(&f, b"xy".to_vec()).await.unwrap();
        q.write(&f, b"z".to_vec()).await.unwrap();
        drop(f);
        let mut s = String::new();
        File::open(&path).unwrap().read_to_string(&mut s).unwrap();
        assert_eq!(s, "xyz");

        q.remove_tree(dir.path().join("a")).await.unwrap();
        assert!(!dir.path().join("a").exists());
        // missing tree removal is not an error
        q.remove_tree(dir.path().join("a")).await.unwrap();
    }
}
