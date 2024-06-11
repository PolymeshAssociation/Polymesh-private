// This file is part of the Polymesh distribution (https://github.com/PolymeshAssociation/Polymesh).
// Copyright (c) 2023 Polymesh Association

#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
use sp_runtime_interface::runtime_interface;
use sp_std::prelude::Vec;

#[cfg(feature = "std")]
mod batch;

mod proofs;
pub use proofs::*;

mod elgamal;
pub use elgamal::*;

pub type BatchId = u32;

pub type BatchSeed = [u8; 32];

pub type BatchReqId = u32;

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    VerifyFailed,
    BatchClosed,
}

/// Native interface for runtime module for Confidential Assets.
#[runtime_interface]
pub trait NativeConfidentialAssets {
    fn verify_sender_proof(
        req: &VerifyConfidentialTransferRequest,
        seed: BatchSeed,
    ) -> Result<(), Error> {
        req.verify(seed)
    }

    fn verify_burn_proof(
        req: &VerifyConfidentialBurnRequest,
        seed: BatchSeed,
    ) -> Result<(), Error> {
        req.verify(seed)
    }

    fn verify_proof(req: &VerifyConfidentialProofRequest, seed: BatchSeed) -> Result<(), Error> {
        req.verify(seed)
    }

    fn cipher_add(val1: HostCipherText, val2: HostCipherText) -> HostCipherText {
        val1 + val2
    }

    fn cipher_sub(val1: HostCipherText, val2: HostCipherText) -> HostCipherText {
        val1 - val2
    }

    fn create_batch(seed: BatchSeed) -> BatchId {
        batch::BatchVerifiers::create_batch(seed)
    }

    fn batch_submit(id: BatchId, req: VerifyConfidentialProofRequest) -> Result<(), Error> {
        batch::BatchVerifiers::batch_submit(id, req)
    }

    fn batch_finish(id: BatchId) -> Result<(), Error> {
        let batch = batch::BatchVerifiers::batch_finish(id).ok_or(Error::VerifyFailed)?;
        batch.finalize()
    }

    fn batch_cancel(id: BatchId) {
        batch::BatchVerifiers::batch_cancel(id);
    }

    fn set_skip_verify(_skip: bool) {
        #[cfg(feature = "runtime-benchmarks")]
        batch::BatchVerifiers::set_skip_verify(_skip);
    }

    fn batch_generate_proof(_id: BatchId, _req: GenerateProofRequest) -> Result<(), Error> {
        #[cfg(feature = "runtime-benchmarks")]
        {
            batch::BatchVerifiers::batch_generate_proof(_id, _req)
        }
        #[cfg(not(feature = "runtime-benchmarks"))]
        Err(Error::VerifyFailed)
    }

    fn batch_get_proofs(_id: BatchId) -> Result<Vec<GenerateProofResponse>, Error> {
        #[cfg(feature = "runtime-benchmarks")]
        {
            let batch = batch::BatchVerifiers::batch_finish(_id).ok_or(Error::VerifyFailed)?;
            batch.get_proofs()
        }
        #[cfg(not(feature = "runtime-benchmarks"))]
        Err(Error::VerifyFailed)
    }
}
