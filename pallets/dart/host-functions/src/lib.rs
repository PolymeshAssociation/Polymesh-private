// This file is part of the Polymesh distribution (https://github.com/PolymeshAssociation/Polymesh).
// Copyright (c) 2023 Polymesh Association

#![cfg_attr(not(feature = "std"), no_std)]

mod verify;
pub use verify::*;

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

use codec::{Decode, Encode};
use sp_runtime_interface::runtime_interface;

use polymesh_dart::{
    ACCOUNT_TREE_L, ACCOUNT_TREE_M, ASSET_TREE_L, ASSET_TREE_M,
    curve_tree::{AccountTreeConfig, AssetTreeConfig, CurveTreeRoot},
};

pub type BatchId = u32;

pub type BatchSeed = [u8; 32];

pub type BatchReqId = u32;

pub type AssetTreeRoot = CurveTreeRoot<ASSET_TREE_L, ASSET_TREE_M, AssetTreeConfig>;
pub type AccountTreeRoot = CurveTreeRoot<ACCOUNT_TREE_L, ACCOUNT_TREE_M, AccountTreeConfig>;

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    VerifyFailed,
    BatchClosed,
    GenerateProofFailed,
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
}
