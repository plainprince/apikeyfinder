//! Central network queue: every fetch (CDX queries, HEAD probes, WARC
//! downloads) flows through one dynamic worker pool. Too many fetches just
//! queue up behind `network_max_workers`; too few and idle workers retire.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use futures_util::StreamExt;
use tokio::sync::oneshot;

use crate::config::Config;
use crate::queues::disk::{DiskQueue, OpenMode};
use crate::queues::dynpool::{spawn_dyn, DynPoolCfg, DynSender};
use crate::stats::Stats;

pub struct DownloadOutcome {
    pub bytes_written: u64,
    /// True when the transfer stopped at `download.max_bytes_per_file`.
    pub truncated: bool,
}

enum NetJob {
    Fetch {
        url: String,
        max_bytes: u64,
        resp: oneshot::Sender<Result<Vec<u8>>>,
    },
    Head {
        url: String,
        resp: oneshot::Sender<Result<Option<u64>>>,
    },
    Download {
        url: String,
        dest: PathBuf,
        resp: oneshot::Sender<Result<DownloadOutcome>>,
    },
}

#[derive(Clone)]
pub struct NetworkQueue {
    tx: DynSender<NetJob>,
}

struct Handlers {
    client_cdx: reqwest::Client,
    client_head: reqwest::Client,
    client_dl: reqwest::Client,
    disk: DiskQueue,
    stats: Arc<Stats>,
    max_bytes_per_file: u64,
    retries: u32,
    backoff: Duration,
}

/// HTTP status errors carry the response body so logs show *why* the server
/// refused (S3 XML error vs CloudFront/WAF block page), not just the code.
#[derive(Debug)]
pub struct HttpStatusError {
    pub status: reqwest::StatusCode,
    pub url: String,
    pub body: String,
}

impl std::fmt::Display for HttpStatusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HTTP {} for {} body={}", self.status, self.url, self.body)
    }
}

impl std::error::Error for HttpStatusError {}

impl HttpStatusError {
    fn non_retryable(&self) -> bool {
        let code = self.status.as_u16();
        (400..500).contains(&code) && !matches!(code, 408 | 425 | 429)
    }
}

fn truncate_body(b: &str) -> String {
    b.chars()
        .take(300)
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// 4xx (except 408/425/429) will not change on retry; everything else
/// (5xx, timeouts, connection resets, our own failures) is worth another go.
fn is_retryable(e: &anyhow::Error) -> bool {
    for cause in e.chain() {
        if let Some(re) = cause.downcast_ref::<reqwest::Error>()
            && let Some(status) = re.status()
        {
            let code = status.as_u16();
            if (400..500).contains(&code) && !matches!(code, 408 | 425 | 429) {
                return false;
            }
        }
        if let Some(hs) = cause.downcast_ref::<HttpStatusError>()
            && hs.non_retryable()
        {
            return false;
        }
    }
    true
}

/// Equal-jitter exponential backoff: attempt 1 waits ~base, each next attempt
/// doubles up to a 60s cap, with half the delay randomized so parallel retries
/// (and our own repeated rounds) never line up into a thundering herd.
fn backoff_delay(base: Duration, attempt: u32) -> Duration {
    let exp = attempt.clamp(1, 7) - 1; // 2^0 ..= 2^6
    let cap_ms = base
        .saturating_mul(1u32 << exp)
        .as_millis()
        .min(60_000) as u64;
    let half = cap_ms / 2;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::from(d.subsec_nanos()))
        .unwrap_or(0);
    let jitter = if half > 0 { nanos % (half + 1) } else { 0 };
    Duration::from_millis(half + jitter)
}

impl Handlers {
    async fn run(&self, job: NetJob) {
        match job {
            NetJob::Fetch { url, max_bytes, resp } => {
                let _ = resp.send(self.fetch(&url, max_bytes).await);
            }
            NetJob::Head { url, resp } => {
                let _ = resp.send(self.head(&url).await);
            }
            NetJob::Download { url, dest, resp } => {
                let _ = resp.send(self.download(&url, &dest).await);
            }
        }
    }

    async fn with_retries<T, F, Fut>(&self, what: &str, mut op: F) -> Result<T>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let mut attempt = 0u32;
        loop {
            match op().await {
                Ok(v) => return Ok(v),
                Err(e) if attempt < self.retries && is_retryable(&e) => {
                    attempt += 1;
                    tracing::warn!(%what, attempt, error = %format!("{e:#}"), "fetch failed, retrying");
                    tokio::time::sleep(backoff_delay(self.backoff, attempt)).await;
                }
                Err(e) if !is_retryable(&e) => {
                    return Err(e).with_context(|| format!("{what} rejected permanently"));
                }
                Err(e) => {
                    return Err(e)
                        .with_context(|| format!("{what} failed after {} attempts", attempt + 1));
                }
            }
        }
    }

    async fn fetch(&self, url: &str, max_bytes: u64) -> Result<Vec<u8>> {
        self.with_retries("index fetch", || async {
            let resp = self.client_cdx.get(url).send().await?.error_for_status()?;
            let mut out = Vec::new();
            let mut stream = resp.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk?;
                out.extend_from_slice(&chunk);
                if out.len() as u64 > max_bytes {
                    bail!("index response exceeded max_index_response_bytes ({max_bytes})");
                }
            }
            Ok(out)
        })
        .await
    }

    async fn head(&self, url: &str) -> Result<Option<u64>> {
        self.with_retries("head", || async {
            let resp = self.client_head.head(url).send().await?;
            let status = resp.status();
            if !status.is_success() {
                let final_url = resp.url().to_string();
                let body = truncate_body(&resp.text().await.unwrap_or_default());
                tracing::warn!(%status, url = %final_url, body = %body, "head refused");
                return Err(anyhow::Error::new(HttpStatusError { status, url: final_url, body }));
            }
            // reqwest::content_length() is 0 on HEAD (hyper sees an empty body);
            // the size lives in the Content-Length header instead.
            Ok(resp
                .headers()
                .get(reqwest::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<u64>().ok()))
        })
        .await
    }

    async fn download(&self, url: &str, dest: &PathBuf) -> Result<DownloadOutcome> {
        let cap = self.max_bytes_per_file;
        self.with_retries("download", || async {
            // Every attempt restarts clean; partial files never survive as "done".
            let file = self.disk.open(dest, OpenMode::CreateTruncate).await?;
            let mut req = self.client_dl.get(url);
            if cap > 0 {
                req = req.header(reqwest::header::RANGE, format!("bytes=0-{}", cap - 1));
            }
            let resp = req.send().await?;
            let status = resp.status();
            if !status.is_success() {
                let final_url = resp.url().to_string();
                let body = truncate_body(&resp.text().await.unwrap_or_default());
                tracing::warn!(%status, url = %final_url, body = %body, "download refused");
                return Err(anyhow::Error::new(HttpStatusError { status, url: final_url, body }));
            }
            let mut written: u64 = 0;
            let mut truncated = false;
            let mut stream = resp.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk?;
                let mut data = chunk.to_vec();
                if cap > 0 && written + data.len() as u64 > cap {
                    data.truncate((cap - written) as usize);
                    truncated = true;
                }
                if data.is_empty() {
                    break;
                }
                let n = data.len() as u64;
                self.disk.write(&file, data).await?;
                written += n;
                self.stats.add(&self.stats.download_bytes, n);
                if truncated {
                    break;
                }
            }
            drop(file);
            if written == 0 {
                bail!("download wrote 0 bytes");
            }
            if cap > 0 && written >= cap {
                truncated = true;
            }
            tracing::info!(bytes = written, truncated, dest = %dest.display(), "warc downloaded");
            Ok(DownloadOutcome { bytes_written: written, truncated })
        })
        .await
    }
}

impl NetworkQueue {
    pub fn new(cfg: &Config, disk: DiskQueue, stats: Arc<Stats>) -> Self {
        let cdx = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(cfg.download.connect_timeout_secs))
            .timeout(Duration::from_secs(cfg.download.request_timeout_secs))
            .user_agent(concat!("apikeyfinder/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("building cdx http client");
        let head = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(cfg.download.connect_timeout_secs))
            .timeout(Duration::from_secs(cfg.download.head_timeout_secs))
            .user_agent(concat!("apikeyfinder/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("building head http client");
        // No total request timeout for downloads (multi-GB bodies); only connect.
        let dl = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(cfg.download.connect_timeout_secs))
            .user_agent(concat!("apikeyfinder/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("building download http client");

        let handlers = Arc::new(Handlers {
            client_cdx: cdx,
            client_head: head,
            client_dl: dl,
            disk,
            stats,
            max_bytes_per_file: cfg.download.max_bytes_per_file,
            retries: cfg.download.max_retries,
            backoff: Duration::from_millis(cfg.download.retry_backoff_ms),
        });
        let pool_cfg = DynPoolCfg {
            // parallel_fetches is the hard cap on concurrent fetches: 1 = sequential.
            max_workers: cfg.network_max_workers(),
            min_workers: cfg.queues.network_min_workers,
            capacity: cfg.queues.network_capacity,
            scale_threshold: cfg.queues.network_scale_threshold,
            idle_retire: Duration::from_millis(cfg.queues.network_idle_retire_ms),
            tick: Duration::from_millis(cfg.queues.network_pool_tick_ms),
        };
        let tx = spawn_dyn(pool_cfg, move |job: NetJob| {
            let h = handlers.clone();
            async move { h.run(job).await }
        });
        Self { tx }
    }

    pub fn depth(&self) -> usize {
        self.tx.depth()
    }

    pub fn workers(&self) -> usize {
        self.tx.workers()
    }

    pub async fn fetch(&self, url: String, max_bytes: u64) -> Result<Vec<u8>> {
        self.submit(move |resp| NetJob::Fetch { url, max_bytes, resp })
            .await
    }

    pub async fn head(&self, url: String) -> Result<Option<u64>> {
        self.submit(move |resp| NetJob::Head { url, resp }).await
    }

    pub async fn download(&self, url: String, dest: PathBuf) -> Result<DownloadOutcome> {
        self.submit(move |resp| NetJob::Download { url, dest, resp })
            .await
    }

    async fn submit<T: Send + 'static>(
        &self,
        make: impl FnOnce(oneshot::Sender<Result<T>>) -> NetJob,
    ) -> Result<T> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(make(tx))
            .await
            .map_err(|_| anyhow::anyhow!("network queue closed"))?;
        rx.await
            .map_err(|_| anyhow::anyhow!("network worker dropped the response"))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status_err(code: u16) -> anyhow::Error {
        anyhow::Error::new(HttpStatusError {
            status: reqwest::StatusCode::from_u16(code).unwrap(),
            url: "https://example.invalid/x".into(),
            body: String::new(),
        })
    }

    #[test]
    fn status_errors_retry_classification() {
        assert!(!is_retryable(&status_err(403)));
        assert!(!is_retryable(&status_err(404)));
        assert!(is_retryable(&status_err(408)));
        assert!(is_retryable(&status_err(429)));
        assert!(is_retryable(&status_err(500)));
        assert!(is_retryable(&status_err(504)));
        // Context wrapping must not lose the classification.
        let wrapped = status_err(403).context("head rejected permanently");
        assert!(!is_retryable(&wrapped));
    }

    #[test]
    fn backoff_is_exponential_and_capped() {
        let base = Duration::from_millis(1000);
        for _ in 0..25 {
            let d1 = backoff_delay(base, 1);
            assert!(d1 >= Duration::from_millis(500) && d1 <= Duration::from_millis(1000));
            let d4 = backoff_delay(base, 4);
            assert!(
                d4 >= Duration::from_millis(4000) && d4 <= Duration::from_millis(8000),
                "attempt 4 should be ~4s-8s, got {d4:?}"
            );
            let d99 = backoff_delay(base, 99);
            assert!(d99 <= Duration::from_secs(60), "hard 60s cap, got {d99:?}");
        }
    }
}
