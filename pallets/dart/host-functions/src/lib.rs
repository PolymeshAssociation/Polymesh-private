// This file is part of the Polymesh distribution (https://github.com/PolymeshAssociation/Polymesh).
// Copyright (c) 2023 Polymesh Association

#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
use sp_runtime_interface::pass_by::PassByCodec;
use sp_runtime_interface::runtime_interface;
use sp_std::prelude::Vec;

use polymesh_primitives::IdentityId;

pub type BatchId = u32;

pub type BatchSeed = [u8; 32];

pub type BatchReqId = u32;

/// Verify DART asset proof request.
#[derive(PassByCodec, Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub enum VerifyDartAssetRequest {
    AccountAssetRegistration {
        did: IdentityId,
        proof: polymesh_dart::AccountAssetRegistrationProof,
    },
}

#[cfg(feature = "std")]
impl VerifyDartAssetRequest {
    pub fn verify(&self, _seed: BatchSeed) -> Result<(), Error> {
        match self {
            Self::AccountAssetRegistration { did, proof } => {
                proof.verify(&did.0[..]).map_err(|_| Error::VerifyFailed)?;
            }
        }
        Ok(())
    }
}

#[cfg(not(feature = "std"))]
impl VerifyDartAssetRequest {
    pub fn verify(&self, seed: BatchSeed) -> Result<(), Error> {
        native_dart_assets::verify_proof(self, seed)
    }
}
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    VerifyFailed,
    BatchClosed,
}

/// Native interface for runtime module for DART Assets
#[runtime_interface]
pub trait NativeDARTAssets {
    fn verify_proof(request: &VerifyDartAssetRequest, seed: BatchSeed) -> Result<(), Error> {
        request.verify(seed)
    }
}
