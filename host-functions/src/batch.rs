use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};

use crossbeam::channel::{unbounded, Receiver, Sender};

use crate::*;

lazy_static::lazy_static! {
    static ref BATCH_VERIFIERS: BatchVerifiers = {
        BatchVerifiers::new(None)
    };
}

#[derive(Debug)]
struct InnerBatchVerifiers {
    batches: HashMap<BatchId, BatchVerifier>,
    pool: rayon::ThreadPool,
    next_id: BatchId,
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
    ) -> Result<(), ()> {
        if let Some(batch) = self.batches.get_mut(&id) {
            let (req_id, tx) = batch.next_req();
            self.pool.spawn(move || {
                let result = req.verify();
                let _ = tx.send(BatchResult {
                    id: req_id,
                    result,
                    proof: Err(()),
                });
            });
            Ok(())
        } else {
            Err(())
        }
    }

    pub fn batch_finish(&mut self, id: BatchId) -> Option<BatchVerifier> {
        self.batches.remove(&id)
    }

    #[cfg(feature = "runtime-benchmarks")]
    pub fn batch_generate_proof(
        &mut self,
        id: BatchId,
        req: GenerateProofRequest,
    ) -> Result<(), ()> {
        if let Some(batch) = self.batches.get_mut(&id) {
            let (req_id, tx) = batch.next_req();
            self.pool.spawn(move || {
                let proof = req.generate();
                let _ = tx.send(BatchResult {
                    id: req_id,
                    result: Err(()),
                    proof,
                });
            });
            Ok(())
        } else {
            Err(())
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

    pub fn batch_submit(id: BatchId, req: VerifyConfidentialProofRequest) -> Result<(), ()> {
        let mut inner = BATCH_VERIFIERS.0.write().unwrap();
        inner.batch_submit(id, req)
    }

    pub fn batch_finish(id: BatchId) -> Option<BatchVerifier> {
        let mut inner = BATCH_VERIFIERS.0.write().unwrap();
        inner.batch_finish(id)
    }

    #[cfg(feature = "runtime-benchmarks")]
    pub fn batch_generate_proof(id: BatchId, req: GenerateProofRequest) -> Result<(), ()> {
        let mut inner = BATCH_VERIFIERS.0.write().unwrap();
        inner.batch_generate_proof(id, req)
    }
}

#[derive(Debug)]
pub struct BatchResult {
    pub id: BatchReqId,
    pub result: Result<VerifyConfidentialProofResponse, ()>,
    pub proof: Result<GenerateProofResponse, ()>,
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

    pub fn finalize(self) -> Result<bool, ()> {
        let Self { count, rx, tx } = self;
        drop(tx);
        let mut resps = BTreeMap::new();
        for _x in 0..count {
            let res = rx.recv().map_err(|err| {
                log::warn!("Failed to recv Proof response: {err:?}");
                ()
            })?;
            let valid = res.result?.is_valid();
            if !valid {
                // Invalid proof.
                return Err(());
            }
            resps.insert(res.id, valid);
        }
        if resps.len() == count as usize {
            Ok(true)
        } else {
            // Wrong number of responses.
            Err(())
        }
    }

    #[cfg(feature = "runtime-benchmarks")]
    pub fn get_proofs(self) -> Result<Vec<GenerateProofResponse>, ()> {
        let Self { count, rx, tx } = self;
        drop(tx);
        let mut resps = BTreeMap::new();
        for _x in 0..count {
            let res = rx.recv().map_err(|err| {
                log::warn!("Failed to recv Proof response: {err:?}");
                ()
            })?;
            let proof = res.proof?;
            resps.insert(res.id, proof);
        }
        if resps.len() == count as usize {
            Ok(resps.into_iter().map(|(_, proof)| proof).collect())
        } else {
            // Wrong number of responses.
            Err(())
        }
    }
}
