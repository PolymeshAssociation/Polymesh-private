// This file is part of the Polymesh distribution (https://github.com/PolymeshAssociation/Polymesh).
// Copyright (c) 2023 Polymesh Association

#![cfg_attr(not(feature = "std"), no_std)]

mod verify;
pub use verify::*;

mod curve_tree;
pub use curve_tree::*;

#[cfg(feature = "std")]
mod batch;

#[cfg(feature = "testing")]
mod testing;

#[cfg(not(feature = "testing"))]
mod testing {
    use codec::{Decode, Encode};
    use sp_runtime_interface::pass_by::PassByCodec;

    /// The non-testing version of this enum is empty, as no requests are currently supported
    #[derive(PassByCodec, Encode, Decode, Clone)]
    pub enum GenerateDartProofRequest {}

    /// The non-testing version of this enum is empty, as no requests are currently supported
    #[derive(PassByCodec, Encode, Decode, Clone)]
    pub enum GenerateDartProofResponse {}
}

pub use testing::*;

use codec::{Compact, Decode, Encode};
use sp_io::hashing::blake2_256;
use sp_runtime_interface::{pass_by::PassByCodec, runtime_interface};
use sp_std::collections::btree_map::BTreeMap;
use sp_std::prelude::Vec;

use polymesh_dart::{
    ACCOUNT_TREE_L, ACCOUNT_TREE_M, ASSET_TREE_L, ASSET_TREE_M,
    curve_tree::{AccountTreeConfig, AssetTreeConfig, CompressedCurveTreeRoot},
};

pub type BatchId = u32;

pub type BatchSeed = [u8; 32];

pub type BatchReqId = u32;

/// A hash of a request.
pub type ReqHash = [u8; 32];
/// The request version number is used to force the runtime to fallback to verifying
/// the proof in `no_std` environment if the current host node does not support the request version.
pub type ReqVersion = Compact<u32>;

/// The kind of a batch request.
#[derive(Clone, Debug, Encode, Decode)]
pub enum BatchRequestKind {
    VerifyProof(ReqVersion),
    GenerateProof(ReqVersion),
}

/// Where to execute a batch request.
#[derive(Debug, Encode, Decode)]
pub struct BatchRequestExecution {
    pub req_id: BatchReqId,
    pub host_side: bool,
    pub req_hash: ReqHash,
}

impl BatchRequestExecution {
    /// Check if the request must be executed on the runtime side.
    pub fn runtime_side(&self) -> bool {
        !self.host_side
    }
}

/// A batch request.
#[derive(PassByCodec, Debug, Encode, Decode)]
pub struct BatchRequest {
    pub kind: BatchRequestKind,
    pub req: Vec<u8>,
}

impl BatchRequest {
    /// Check if the request is supported by the current host node.
    pub fn is_supported(&self) -> bool {
        match &self.kind {
            BatchRequestKind::VerifyProof(version) | BatchRequestKind::GenerateProof(version) => {
                version.0 <= 1
            }
        }
    }

    /// Create a new batch request for verifying a proof.
    pub fn new_verify(req: &VerifyDartAssetRequest) -> Self {
        Self {
            kind: BatchRequestKind::VerifyProof(Compact(1)),
            req: req.encode(),
        }
    }

    /// Create a new batch request for generating a proof.
    pub fn new_generate(req: &GenerateDartProofRequest) -> Self {
        Self {
            kind: BatchRequestKind::GenerateProof(Compact(1)),
            req: req.encode(),
        }
    }

    /// Where to execute the request.
    pub fn execution(&self, req_id: BatchReqId) -> BatchRequestExecution {
        let req_hash = blake2_256(&self.req);
        BatchRequestExecution {
            req_id,
            host_side: self.is_supported(),
            req_hash,
        }
    }

    pub fn decode<T: Decode>(&self) -> Result<T, Error> {
        T::decode(&mut &self.req[..]).map_err(|_| Error::DecodingFailed)
    }

    /// Decode and execute the batch request.
    pub fn execute(self, hash: ReqHash) -> Result<BatchResponse, Error> {
        match self.kind {
            BatchRequestKind::VerifyProof(_) => {
                let req: VerifyDartAssetRequest = self.decode()?;
                req.verify(hash)?;
                Ok(BatchResponse {
                    kind: self.kind,
                    resp: Vec::new(),
                })
            }
            BatchRequestKind::GenerateProof(_) => {
                #[cfg(feature = "testing")]
                {
                    let req: GenerateDartProofRequest = self.decode()?;
                    let proof = req.generate(hash)?;
                    Ok(BatchResponse {
                        kind: self.kind,
                        resp: proof.encode(),
                    })
                }
                #[cfg(not(feature = "testing"))]
                Err(Error::GenerateProofFailed)
            }
        }
    }

    /// Skip proof verification and return a successful response.
    /// Only available for benchmarking to isolate the proof verification
    #[cfg(feature = "testing")]
    pub fn skip_verify(self) -> Result<BatchResponse, Error> {
        match self.kind {
            BatchRequestKind::VerifyProof(_) => Ok(BatchResponse {
                kind: self.kind,
                resp: Vec::new(),
            }),
            BatchRequestKind::GenerateProof(_) => Err(Error::GenerateProofFailed),
        }
    }
}

#[derive(Clone, Debug, Encode, Decode)]
pub struct BatchResult {
    pub id: BatchReqId,
    pub result: Result<BatchResponse, Error>,
    pub cache_result: Option<ReqHash>,
}

impl BatchResult {
    pub fn decode<T: Decode>(&self) -> Result<T, Error> {
        match &self.result {
            Ok(resp) => resp.decode(),
            Err(err) => Err(err.clone()),
        }
    }
}

/// A batch response.
#[derive(Clone, Debug, Encode, Decode)]
pub struct BatchResponse {
    pub kind: BatchRequestKind,
    pub resp: Vec<u8>,
}

impl BatchResponse {
    /// Decode the response.
    pub fn decode<T: Decode>(&self) -> Result<T, Error> {
        T::decode(&mut &self.resp[..]).map_err(|_| Error::DecodingFailed)
    }
}

pub type AssetTreeRoot = CompressedCurveTreeRoot<ASSET_TREE_L, ASSET_TREE_M, AssetTreeConfig>;
pub type AccountTreeRoot =
    CompressedCurveTreeRoot<ACCOUNT_TREE_L, ACCOUNT_TREE_M, AccountTreeConfig>;

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    VerifyFailed,
    BatchClosed,
    GenerateProofFailed,
    DecodingFailed,
    MissingBatch,
}

impl From<polymesh_dart::Error> for Error {
    fn from(_e: polymesh_dart::Error) -> Self {
        Self::VerifyFailed
    }
}

/// Native interface for runtime module for DART Assets
#[runtime_interface]
pub trait NativeDARTAssets {
    fn verify_proof(request: VerifyDartAssetRequest, seed: BatchSeed) -> Result<(), Error> {
        request.verify(seed)
    }

    fn verify_mediator(request: VerifyMediatorRequest) -> Result<(), Error> {
        request.verify()
    }

    fn generate_proof(
        _request: GenerateDartProofRequest,
        _seed: BatchSeed,
    ) -> Result<GenerateDartProofResponse, Error> {
        #[cfg(feature = "testing")]
        {
            _request.generate(_seed)
        }
        #[cfg(not(feature = "testing"))]
        Err(Error::GenerateProofFailed)
    }

    fn create_batch() -> BatchId {
        batch::BatchVerifiers::create_batch()
    }

    fn batch_submit(id: BatchId, req: BatchRequest) -> Result<BatchRequestExecution, Error> {
        batch::BatchVerifiers::batch_submit(id, req)
    }

    fn batch_finish(
        id: BatchId,
    ) -> Result<BTreeMap<BatchReqId, Result<BatchResponse, Error>>, Error> {
        let batch = batch::BatchVerifiers::batch_finish(id).ok_or(Error::VerifyFailed)?;
        batch.finalize()
    }

    fn batch_cancel(id: BatchId) {
        batch::BatchVerifiers::batch_cancel(id);
    }

    fn set_skip_verify(_skip: bool) {
        #[cfg(feature = "testing")]
        batch::BatchVerifiers::set_skip_verify(_skip);
    }

    fn batch_get_proofs(_id: BatchId) -> Result<Vec<GenerateDartProofResponse>, Error> {
        #[cfg(feature = "testing")]
        {
            let batch = batch::BatchVerifiers::batch_finish(_id).ok_or(Error::VerifyFailed)?;
            batch.get_proofs()
        }
        #[cfg(not(feature = "testing"))]
        Err(Error::VerifyFailed)
    }

    fn asset_tree_update_inner_node(
        req: UpdateTreeNodeRequest<ASSET_TREE_L, ASSET_TREE_M, AssetTreeConfig>,
    ) -> Result<UpdateTreeNodeResult<ASSET_TREE_M>, Error> {
        req.update()
    }

    fn account_tree_update_inner_node(
        req: UpdateTreeNodeRequest<ACCOUNT_TREE_L, ACCOUNT_TREE_M, AccountTreeConfig>,
    ) -> Result<UpdateTreeNodeResult<ACCOUNT_TREE_M>, Error> {
        req.update()
    }
}
