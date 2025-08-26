// This file is part of the Polymesh distribution (https://github.com/PolymeshAssociation/Polymesh).
// Copyright (c) 2023 Polymesh Association

#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
use sp_runtime_interface::pass_by::PassByCodec;
use sp_runtime_interface::runtime_interface;

#[cfg(feature = "std")]
use rand_chacha::ChaCha20Rng as Rng;
#[cfg(feature = "std")]
use rand_core::SeedableRng;

#[cfg(feature = "std")]
use polymesh_dart::curve_tree::get_account_curve_tree_parameters;
use polymesh_dart::{
    ACCOUNT_TREE_L, ACCOUNT_TREE_M, ASSET_TREE_L, ASSET_TREE_M, AccountAssetRegistrationProof,
    AssetMintingProof, LegEncrypted, MediatorAffirmationProof, PolymeshPrivateLimits,
    ReceiverAffirmationProof, ReceiverClaimProof, SenderAffirmationProof, SenderCounterUpdateProof,
    SenderReversalProof, SettlementProof,
    curve_tree::{AccountTreeConfig, AssetTreeConfig, CurveTreeRoot},
};

use polymesh_primitives::IdentityId;

pub type BatchId = u32;

pub type BatchSeed = [u8; 32];

pub type BatchReqId = u32;

pub type AssetTreeRoot = CurveTreeRoot<ASSET_TREE_L, ASSET_TREE_M, AssetTreeConfig>;
pub type AccountTreeRoot = CurveTreeRoot<ACCOUNT_TREE_L, ACCOUNT_TREE_M, AccountTreeConfig>;

/// Verify DART asset proof request.
#[derive(PassByCodec, Encode, Decode, Clone)]
pub enum VerifyDartAssetRequest {
    AccountAssetRegistration {
        did: IdentityId,
        proof: AccountAssetRegistrationProof,
    },
    MintAsset {
        root: AccountTreeRoot,
        proof: AssetMintingProof,
    },
    CreateSettlement {
        root: AssetTreeRoot,
        proof: SettlementProof<PolymeshPrivateLimits>,
    },
    SenderAffirmation {
        leg_enc: LegEncrypted,
        root: AccountTreeRoot,
        proof: SenderAffirmationProof,
    },
    ReceiverAffirmation {
        leg_enc: LegEncrypted,
        root: AccountTreeRoot,
        proof: ReceiverAffirmationProof,
    },
    SenderCounterUpdate {
        leg_enc: LegEncrypted,
        root: AccountTreeRoot,
        proof: SenderCounterUpdateProof,
    },
    SenderReversal {
        leg_enc: LegEncrypted,
        root: AccountTreeRoot,
        proof: SenderReversalProof,
    },
    ReceiverClaim {
        leg_enc: LegEncrypted,
        root: AccountTreeRoot,
        proof: ReceiverClaimProof,
    },
}

#[cfg(feature = "std")]
impl VerifyDartAssetRequest {
    pub fn verify(self, seed: BatchSeed) -> Result<(), Error> {
        let mut rng = Rng::from_seed(seed);
        match self {
            Self::AccountAssetRegistration { did, proof } => {
                let params = get_account_curve_tree_parameters();
                proof
                    .verify(&did.0[..], &params, &mut rng)
                    .map_err(|_| Error::VerifyFailed)?;
            }
            Self::MintAsset { root, proof } => {
                proof
                    .verify(root, &mut rng)
                    .map_err(|_| Error::VerifyFailed)?;
            }
            Self::CreateSettlement { root, proof } => {
                proof
                    .verify(root, &mut rng)
                    .map_err(|_| Error::VerifyFailed)?;
            }
            Self::SenderAffirmation {
                leg_enc,
                root,
                proof,
            } => {
                proof
                    .verify(&leg_enc, root, &mut rng)
                    .map_err(|_| Error::VerifyFailed)?;
            }
            Self::ReceiverAffirmation {
                leg_enc,
                root,
                proof,
            } => {
                proof
                    .verify(&leg_enc, root, &mut rng)
                    .map_err(|_| Error::VerifyFailed)?;
            }
            Self::SenderCounterUpdate {
                leg_enc,
                root,
                proof,
            } => {
                proof
                    .verify(&leg_enc, root, &mut rng)
                    .map_err(|_| Error::VerifyFailed)?;
            }
            Self::SenderReversal {
                leg_enc,
                root,
                proof,
            } => {
                proof
                    .verify(&leg_enc, root, &mut rng)
                    .map_err(|_| Error::VerifyFailed)?;
            }
            Self::ReceiverClaim {
                leg_enc,
                root,
                proof,
            } => {
                proof
                    .verify(&leg_enc, root, &mut rng)
                    .map_err(|_| Error::VerifyFailed)?;
            }
        }
        Ok(())
    }
}

#[cfg(not(feature = "std"))]
impl VerifyDartAssetRequest {
    pub fn verify(self, seed: BatchSeed) -> Result<(), Error> {
        native_dart_assets::verify_proof(self, seed)
    }
}

#[derive(PassByCodec, Encode, Decode, Clone)]
pub struct VerifyMediatorRequest {
    pub leg_enc: LegEncrypted,
    pub proof: MediatorAffirmationProof,
}

#[cfg(feature = "std")]
impl VerifyMediatorRequest {
    pub fn verify(self) -> Result<(), Error> {
        self.proof
            .verify(&self.leg_enc)
            .map_err(|_| Error::VerifyFailed)
    }
}

#[cfg(not(feature = "std"))]
impl VerifyMediatorRequest {
    pub fn verify(self) -> Result<(), Error> {
        native_dart_assets::verify_mediator(self)
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
    fn verify_proof(request: VerifyDartAssetRequest, seed: BatchSeed) -> Result<(), Error> {
        request.verify(seed)
    }

    fn verify_mediator(request: VerifyMediatorRequest) -> Result<(), Error> {
        request.verify()
    }
}
