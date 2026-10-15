//! Dynamic worker pool: one central bounded queue, workers that grow on
//! demand ("too many jobs = just queue") and retire when idle ("too little
//! = shrink back to min", growing again when demand returns).

use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub struct DynPoolCfg {
    pub min_workers: usize,
    pub max_workers: usize,
    pub capacity: usize,
    /// Queue depth at which the supervisor spawns an extra worker.
    pub scale_threshold: usize,
    /// Idle time after which a worker above `min_workers` retires.
    pub idle_retire: Duration,
    /// Supervisor sampling interval.
    pub tick: Duration,
}

struct Inner<J> {
    rx: tokio::sync::Mutex<mpsc::Receiver<J>>,
    depth: AtomicUsize,
    workers: AtomicUsize,
    cfg: DynPoolCfg,
}

impl<J> Inner<J> {
    /// Retire only if current workers > min (atomic check-and-decrement).
    fn try_retire(&self) -> bool {
        self.workers
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |w| {
                if w > self.cfg.min_workers { Some(w - 1) } else { None }
            })
            .is_ok()
    }
}

/// Cloneable handle that submits jobs into the pool's central queue.
pub struct DynSender<J> {
    tx: mpsc::Sender<J>,
    inner: Arc<Inner<J>>,
}

impl<J: Send + 'static> Clone for DynSender<J> {
    fn clone(&self) -> Self {
        Self { tx: self.tx.clone(), inner: self.inner.clone() }
    }
}

impl<J: Send + 'static> DynSender<J> {
    pub async fn send(&self, job: J) -> Result<(), mpsc::error::SendError<J>> {
        self.inner.depth.fetch_add(1, Ordering::SeqCst);
        self.tx.send(job).await.inspect_err(|_| {
            self.inner.depth.fetch_sub(1, Ordering::SeqCst);
        })
    }

    /// Jobs queued but not yet picked up by a worker.
    pub fn depth(&self) -> usize {
        self.inner.depth.load(Ordering::SeqCst)
    }

    pub fn workers(&self) -> usize {
        self.inner.workers.load(Ordering::SeqCst)
    }
}

/// Spawn a dynamic pool running `handler` on each job. Returns the submit handle.
pub fn spawn_dyn<J, H, Fut>(cfg: DynPoolCfg, handler: H) -> DynSender<J>
where
    J: Send + 'static,
    H: Fn(J) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    assert!(cfg.min_workers >= 1, "min_workers must be >= 1");
    let max_workers = cfg.max_workers.max(cfg.min_workers);
    let (tx, rx) = mpsc::channel(cfg.capacity);
    let inner = Arc::new(Inner {
        rx: tokio::sync::Mutex::new(rx),
        depth: AtomicUsize::new(0),
        workers: AtomicUsize::new(0),
        cfg: DynPoolCfg { max_workers, ..cfg },
    });
    let handler = Arc::new(handler);

    for _ in 0..inner.cfg.min_workers {
        spawn_worker(inner.clone(), handler.clone());
    }
    tokio::spawn(supervisor(inner.clone(), handler.clone()));
    DynSender { tx, inner }
}

fn spawn_worker<J, H, Fut>(inner: Arc<Inner<J>>, handler: Arc<H>)
where
    J: Send + 'static,
    H: Fn(J) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    inner.workers.fetch_add(1, Ordering::SeqCst);
    tokio::spawn(async move {
        loop {
            let job = {
                // Only one worker waits on the receiver at a time; the lock is
                // released while the job is being handled so the rest can pull.
                let mut rx = inner.rx.lock().await;
                match tokio::time::timeout(inner.cfg.idle_retire, rx.recv()).await {
                    Ok(Some(job)) => {
                        inner.depth.fetch_sub(1, Ordering::SeqCst);
                        job
                    }
                    Ok(None) => {
                        // Queue closed and drained: shut this worker down.
                        inner.workers.fetch_sub(1, Ordering::SeqCst);
                        return;
                    }
                    Err(_) => {
                        if inner.try_retire() {
                            return;
                        }
                        continue;
                    }
                }
            };
            handler(job).await;
        }
    });
}

async fn supervisor<J, H, Fut>(inner: Arc<Inner<J>>, handler: Arc<H>)
where
    J: Send + 'static,
    H: Fn(J) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    loop {
        tokio::time::sleep(inner.cfg.tick).await;
        let depth = inner.depth.load(Ordering::SeqCst);
        let workers = inner.workers.load(Ordering::SeqCst);
        if depth >= inner.cfg.scale_threshold.max(1) && workers < inner.cfg.max_workers {
            tracing::debug!(
                workers,
                depth,
                max = inner.cfg.max_workers,
                "dynamic pool scaling up"
            );
            spawn_worker(inner.clone(), handler.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicI64;
    use std::sync::Mutex;

    fn cfg(min: usize, max: usize) -> DynPoolCfg {
        DynPoolCfg {
            min_workers: min,
            max_workers: max,
            capacity: 1000,
            scale_threshold: 1,
            idle_retire: Duration::from_millis(200),
            tick: Duration::from_millis(10),
        }
    }

    #[tokio::test]
    async fn processes_all_jobs_and_never_exceeds_max_workers() {
        let live = Arc::new(AtomicI64::new(0));
        let peak = Arc::new(AtomicI64::new(0));
        let sum = Arc::new(AtomicI64::new(0));
        let seen = Arc::new(Mutex::new(Vec::new()));

        let live2 = live.clone();
        let peak2 = peak.clone();
        let sum2 = sum.clone();
        let seen2 = seen.clone();
        let sender = spawn_dyn(cfg(1, 4), move |job: i64| {
            let live = live2.clone();
            let peak = peak2.clone();
            let sum = sum2.clone();
            let seen = seen2.clone();
            async move {
                let now = live.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(5)).await;
                sum.fetch_add(job, Ordering::SeqCst);
                seen.lock().unwrap().push(job);
                live.fetch_sub(1, Ordering::SeqCst);
            }
        });

        for i in 0..500 {
            sender.send(i).await.unwrap();
        }
        // Wait for drain.
        while sender.depth() > 0 || sender.workers() == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert_eq!(sum.load(Ordering::SeqCst), (0..500).sum::<i64>());
        assert_eq!(seen.lock().unwrap().len(), 500);
        assert!(peak.load(Ordering::SeqCst) <= 4, "peak {} exceeded max workers", peak.load(Ordering::SeqCst));
        assert!(peak.load(Ordering::SeqCst) >= 2, "pool never scaled up");
        assert!(sender.workers() <= 4);
    }

    #[tokio::test]
    async fn idle_workers_retire_back_to_min() {
        let sender = spawn_dyn(cfg(1, 4), |_job: ()| async move {
            tokio::time::sleep(Duration::from_millis(1)).await;
        });
        for _ in 0..10 {
            sender.send(()).await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        // Long enough for idle_retire (200ms) to fire on surplus workers.
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert_eq!(sender.workers(), 1, "workers should retire down to min");
    }
}
