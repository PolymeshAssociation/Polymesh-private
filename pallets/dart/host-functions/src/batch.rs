use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};

use crossbeam::channel::{unbounded, Receiver, Sender};

use crate::*;

lazy_static::lazy_static! {
    /// The global set of batch verifiers.
    static ref BATCH_VERIFIERS: BatchVerifiers = {
        BatchVerifiers::new(None)
    };
}

#[cfg(feature = "testing")]
lazy_static::lazy_static! {
    /// A cache of generated proofs to speed-up benchmarking runs.
    static ref CACHE_GENERATED_PROOFS: Arc<RwLock<HashMap<ReqHash, Result<BatchResponse, Error>>>> = {
        Arc::new(RwLock::new(HashMap::new()))
    };
}

#[derive(Debug)]
struct InnerBatchVerifiers {
    batches: HashMap<BatchId, BatchVerifier>,
    pool: rayon::ThreadPool,
    next_id: BatchId,
    /// Only available for benchmarking to isolate the proof verification
    /// costs from runtime costs.
    #[cfg(feature = "testing")]
    skip_verify: bool,
}

impl InnerBatchVerifiers {
    pub fn new(threads: Option<usize>) -> Self {
        let mut builder = rayon::ThreadPoolBuilder::new();
        if let Some(threads) = threads {
            builder = builder.num_threads(threads);
        }
        let pool = builder.build().unwrap();
        Self {
            batches: Default::default(),
            pool,
            next_id: 0,
            #[cfg(feature = "testing")]
            skip_verify: false,
        }
    }

    pub fn create_batch(&mut self) -> BatchId {
        let id = self.next_id;
        self.next_id = id + 1;
        self.batches.insert(id, BatchVerifier::new());
        id
    }

    pub fn batch_submit(
        &mut self,
        id: BatchId,
        req: BatchRequest,
    ) -> Result<BatchRequestExecution, Error> {
        if let Some(batch) = self.batches.get_mut(&id) {
            let (req_id, tx) = batch.next_req();
            let execution = req.execution(req_id);
            if execution.runtime_side() {
                // Fall back to runtime execution.
                return Ok(execution);
            }
            let req_hash = execution.req_hash;
            #[cfg(feature = "testing")]
            let cache_result = {
                match req.kind {
                    BatchRequestKind::VerifyProof(_) => {
                        // Only available for benchmarking to isolate the proof verification
                        // costs from runtime costs.
                        if self.skip_verify {
                            let result = req.skip_verify();
                            let _ = tx.send(BatchResult {
                                id: req_id,
                                result,
                                cache_result: None,
                            });
                            return Ok(execution);
                        }
                        None
                    }
                    BatchRequestKind::GenerateProof(_) => {
                        // If the request is a proof generation, check the cache first.
                        let cache = CACHE_GENERATED_PROOFS.read().unwrap();
                        if let Some(result) = cache.get(&req_hash) {
                            let _ = tx.send(BatchResult {
                                id: req_id,
                                result: result.clone(),
                                cache_result: None,
                            });
                            return Ok(execution);
                        }
                        // We don't have the results cached, so we will cache it after generation.
                        Some(req_hash)
                    }
                }
            };
            #[cfg(not(feature = "testing"))]
            let cache_result = None;

            self.pool.spawn(move || {
                let result = req.execute(req_hash);
                let _ = tx.send(BatchResult {
                    id: req_id,
                    result,
                    cache_result,
                });
            });
            Ok(execution)
        } else {
            Err(Error::MissingBatch)
        }
    }

    pub fn batch_finish(&mut self, id: BatchId) -> Option<BatchVerifier> {
        #[cfg(feature = "testing")]
        if self.skip_verify {
            self.skip_verify = false;
        }
        self.batches.remove(&id)
    }

    pub fn batch_cancel(&mut self, id: BatchId) {
        #[cfg(feature = "testing")]
        if self.skip_verify {
            self.skip_verify = false;
        }
        self.batches.remove(&id);
    }

    /// Only available for benchmarking to isolate the proof verification
    /// costs from runtime costs.
    #[cfg(feature = "testing")]
    pub fn set_skip_verify(&mut self, skip: bool) {
        self.skip_verify = skip;
    }
}

#[derive(Clone)]
pub struct BatchVerifiers(Arc<RwLock<InnerBatchVerifiers>>);

impl BatchVerifiers {
    pub fn new(threads: Option<usize>) -> Self {
        Self(Arc::new(RwLock::new(InnerBatchVerifiers::new(threads))))
    }

    pub fn create_batch() -> BatchId {
        let mut inner = BATCH_VERIFIERS.0.write().unwrap();
        inner.create_batch()
    }

    pub fn batch_submit(id: BatchId, req: BatchRequest) -> Result<BatchRequestExecution, Error> {
        let mut inner = BATCH_VERIFIERS.0.write().unwrap();
        inner.batch_submit(id, req)
    }

    pub fn batch_finish(id: BatchId) -> Option<BatchVerifier> {
        let mut inner = BATCH_VERIFIERS.0.write().unwrap();
        inner.batch_finish(id)
    }

    pub fn batch_cancel(id: BatchId) {
        let mut inner = BATCH_VERIFIERS.0.write().unwrap();
        inner.batch_cancel(id);
    }

    /// Only available for benchmarking to isolate the proof verification
    /// costs from runtime costs.
    #[cfg(feature = "testing")]
    pub fn set_skip_verify(skip: bool) {
        let mut inner = BATCH_VERIFIERS.0.write().unwrap();
        inner.set_skip_verify(skip);
    }
}

#[derive(Debug)]
pub struct BatchVerifier {
    pub count: BatchReqId,
    pub tx: Sender<BatchResult>,
    pub rx: Receiver<BatchResult>,
}

impl BatchVerifier {
    pub fn new() -> Self {
        let (tx, rx) = unbounded();
        Self {
            count: 0,
            tx,
            rx,
        }
    }

    pub fn next_req(&mut self) -> (BatchReqId, Sender<BatchResult>) {
        let id = self.count;
        self.count = id + 1;
        (id, self.tx.clone())
    }

    pub fn finalize(self) -> Result<BTreeMap<BatchReqId, Result<BatchResponse, Error>>, Error> {
        let Self { count, rx, tx, .. } = self;
        drop(tx);
        let mut resps = BTreeMap::new();
        for _x in 0..count {
            let res = rx.recv().map_err(|err| {
                log::warn!("Failed to recv Proof response: {err:?}");
                Error::VerifyFailed
            })?;
            resps.insert(res.id, res.result);
        }
        Ok(resps)
    }

    #[cfg(feature = "testing")]
    pub fn get_proofs(self) -> Result<Vec<GenerateDartProofResponse>, Error> {
        let Self { count, rx, tx, .. } = self;
        drop(tx);
        let mut resps = BTreeMap::new();
        let mut cache = CACHE_GENERATED_PROOFS.write().unwrap();
        for _x in 0..count {
            let res = rx.recv().map_err(|err| {
                log::warn!("Failed to recv Proof response: {err:?}");
                Error::GenerateProofFailed
            })?;
            if let Some(key) = res.cache_result {
                cache.insert(key, res.result.clone());
            }
            let proof = res.decode()?;
            resps.insert(res.id, proof);
        }
        if resps.len() == count as usize {
            Ok(resps.into_iter().map(|(_, proof)| proof).collect())
        } else {
            // Wrong number of responses.
            Err(Error::GenerateProofFailed)
        }
    }
}
