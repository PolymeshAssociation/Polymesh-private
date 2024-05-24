// This file is part of the Polymesh distribution (https://github.com/PolymeshAssociation/Polymesh).
// Copyright (c) 2023 Polymesh Association

#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
use sp_runtime_interface::runtime_interface;
use sp_std::prelude::Vec;

use confidential_assets::{
    CipherText,
};

#[cfg(feature = "std")]
mod batch;

mod proofs;
pub use proofs::*;

pub type BatchId = u32;

pub type BatchReqId = u32;

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    VerifyFailed,
    BatchClosed,
}

/// Native interface for runtime module for Confidential Assets.
#[runtime_interface]
pub trait NativeConfidentialAssets {
    fn verify_sender_proof(req: &VerifyConfidentialTransferRequest) -> Result<bool, Error> {
        req.verify()
    }

    fn verify_burn_proof(req: &VerifyConfidentialBurnRequest) -> Result<bool, Error> {
        req.verify()
    }

    fn verify_proof(
        req: &VerifyConfidentialProofRequest,
    ) -> Result<VerifyConfidentialProofResponse, Error> {
        req.verify()
    }

    fn elgamal_add(
      val1: Vec<u8>,
      val2: Vec<u8>,
    ) -> Option<Vec<u8>> {
        let val1 = CipherText::decode(&mut &val1[..]).ok()?;
        let val2 = CipherText::decode(&mut &val2[..]).ok()?;
        Some((val1 + val2).encode())
    }

    fn elgamal_sub(
      val1: Vec<u8>,
      val2: Vec<u8>,
    ) -> Option<Vec<u8>> {
        let val1 = CipherText::decode(&mut &val1[..]).ok()?;
        let val2 = CipherText::decode(&mut &val2[..]).ok()?;
        Some((val1 - val2).encode())
    }

    fn create_batch() -> BatchId {
        batch::BatchVerifiers::create_batch()
    }

    fn batch_submit(id: BatchId, req: VerifyConfidentialProofRequest) -> Result<(), Error> {
        batch::BatchVerifiers::batch_submit(id, req)
    }

    fn batch_finish(id: BatchId) -> Result<bool, Error> {
        let batch = batch::BatchVerifiers::batch_finish(id).ok_or(Error::VerifyFailed)?;
        batch.finalize()
    }

    fn batch_cancel(id: BatchId) {
        batch::BatchVerifiers::batch_cancel(id);
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
