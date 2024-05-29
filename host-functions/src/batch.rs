use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};

use crossbeam::channel::{unbounded, Receiver, Sender};

#[cfg(feature = "runtime-benchmarks")]
use sp_core::hashing::twox_64;

use crate::*;

lazy_static::lazy_static! {
    static ref BATCH_VERIFIERS: BatchVerifiers = {
        BatchVerifiers::new(None)
    };
}

#[cfg(feature = "runtime-benchmarks")]
lazy_static::lazy_static! {
    static ref CACHE_PROOFS: Arc<RwLock<HashMap<Hash, GenerateProofResponse>>> = {
        Arc::new(RwLock::new(HashMap::new()))
    };
}

pub type Hash = [u8; 8];

#[derive(Debug)]
struct InnerBatchVerifiers {
    batches: HashMap<BatchId, BatchVerifier>,
    pool: rayon::ThreadPool,
    next_id: BatchId,
    /// Only available for benchmarking to isolate the proof verification
    /// costs from runtime costs.
    #[cfg(feature = "runtime-benchmarks")]
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
            #[cfg(feature = "runtime-benchmarks")]
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
        req: VerifyConfidentialProofRequest,
    ) -> Result<(), Error> {
        if let Some(batch) = self.batches.get_mut(&id) {
            let (req_id, tx) = batch.next_req();
            // Only available for benchmarking to isolate the proof verification
            // costs from runtime costs.
            #[cfg(feature = "runtime-benchmarks")]
            if self.skip_verify {
                let _ = tx.send(BatchResult {
                    id: req_id,
                    result: Ok(()),
                    proof: Err(Error::VerifyFailed),
                    key: None,
                });
                return Ok(());
            }
            self.pool.spawn(move || {
                let result = req.verify();
                let _ = tx.send(BatchResult {
                    id: req_id,
                    result,
                    proof: Err(Error::VerifyFailed),
                    key: None,
                });
            });
            Ok(())
        } else {
            Err(Error::VerifyFailed)
        }
    }

    pub fn batch_finish(&mut self, id: BatchId) -> Option<BatchVerifier> {
        #[cfg(feature = "runtime-benchmarks")]
        if self.skip_verify {
            self.skip_verify = false;
        }
        self.batches.remove(&id)
    }

    pub fn batch_cancel(&mut self, id: BatchId) {
        #[cfg(feature = "runtime-benchmarks")]
        if self.skip_verify {
            self.skip_verify = false;
        }
        self.batches.remove(&id);
    }

    /// Only available for benchmarking to isolate the proof verification
    /// costs from runtime costs.
    #[cfg(feature = "runtime-benchmarks")]
    pub fn set_skip_verify(&mut self, skip: bool) {
        self.skip_verify = skip;
    }

    #[cfg(feature = "runtime-benchmarks")]
    pub fn batch_generate_proof(
        &mut self,
        id: BatchId,
        req: GenerateProofRequest,
    ) -> Result<(), Error> {
        if let Some(batch) = self.batches.get_mut(&id) {
            let (req_id, tx) = batch.next_req();
            let key = req.using_encoded(twox_64);
            {
                let cache = CACHE_PROOFS.read().unwrap();
                if let Some(proof) = cache.get(&key) {
                    let _ = tx.send(BatchResult {
                        id: req_id,
                        result: Err(Error::VerifyFailed),
                        proof: Ok(proof.clone()),
                        key: None,
                    });
                    return Ok(());
                }
            }
            self.pool.spawn(move || {
                let proof = req.generate();
                let _ = tx.send(BatchResult {
                    id: req_id,
                    result: Err(Error::VerifyFailed),
                    proof,
                    key: Some(key),
                });
            });
            Ok(())
        } else {
            Err(Error::VerifyFailed)
        }
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

    pub fn batch_submit(id: BatchId, req: VerifyConfidentialProofRequest) -> Result<(), Error> {
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
    #[cfg(feature = "runtime-benchmarks")]
    pub fn set_skip_verify(skip: bool) {
        let mut inner = BATCH_VERIFIERS.0.write().unwrap();
        inner.set_skip_verify(skip);
    }

    #[cfg(feature = "runtime-benchmarks")]
    pub fn batch_generate_proof(id: BatchId, req: GenerateProofRequest) -> Result<(), Error> {
        let mut inner = BATCH_VERIFIERS.0.write().unwrap();
        inner.batch_generate_proof(id, req)
    }
}

#[derive(Debug)]
pub struct BatchResult {
    pub id: BatchReqId,
    pub result: Result<(), Error>,
    pub proof: Result<GenerateProofResponse, Error>,
    pub key: Option<Hash>,
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
        Self { count: 0, tx, rx }
    }

    pub fn next_req(&mut self) -> (BatchReqId, Sender<BatchResult>) {
        let id = self.count;
        self.count = id + 1;
        (id, self.tx.clone())
    }

    pub fn finalize(self) -> Result<(), Error> {
        let Self { count, rx, tx } = self;
        drop(tx);
        let mut resps = BTreeMap::new();
        for _x in 0..count {
            let res = rx.recv().map_err(|err| {
                log::warn!("Failed to recv Proof response: {err:?}");
                Error::VerifyFailed
            })?;
            if res.result.is_err() {
                // Invalid proof.
                return Err(Error::VerifyFailed);
            }
            resps.insert(res.id, true);
        }
        if resps.len() == count as usize {
            Ok(())
        } else {
            // Wrong number of responses.
            Err(Error::VerifyFailed)
        }
    }

    #[cfg(feature = "runtime-benchmarks")]
    pub fn get_proofs(self) -> Result<Vec<GenerateProofResponse>, Error> {
        let Self { count, rx, tx } = self;
        drop(tx);
        let mut resps = BTreeMap::new();
        let mut cache = CACHE_PROOFS.write().unwrap();
        for _x in 0..count {
            let res = rx.recv().map_err(|err| {
                log::warn!("Failed to recv Proof response: {err:?}");
                Error::VerifyFailed
            })?;
            let proof = res.proof?;
            if let Some(key) = res.key {
                cache.insert(key, proof.clone());
            }
            resps.insert(res.id, proof);
        }
        if resps.len() == count as usize {
            Ok(resps.into_iter().map(|(_, proof)| proof).collect())
        } else {
            // Wrong number of responses.
            Err(Error::VerifyFailed)
        }
    }
}
