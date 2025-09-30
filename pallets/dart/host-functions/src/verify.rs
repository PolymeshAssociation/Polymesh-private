use codec::{Decode, Encode};
#[cfg(feature = "std")]
use sp_io::hashing::blake2_256;
use sp_runtime_interface::pass_by::PassByCodec;

use rand_chacha::ChaCha20Rng as Rng;
use rand_core::SeedableRng;

use polymesh_dart::curve_tree::get_account_curve_tree_parameters;
use polymesh_dart::{
    AccountRegistrationProof, AssetMintingProof, BatchedAccountAssetRegistrationProof,
    EncryptionKeyRegistrationProof, LegEncrypted, MediatorAffirmationProof, PolymeshPrivateLimits,
    ReceiverAffirmationProof, ReceiverClaimProof, SenderAffirmationProof, SenderCounterUpdateProof,
    SenderReversalProof, SettlementProof,
};
use polymesh_primitives::IdentityId;

use crate::{
    AccountTreeRoot, AssetTreeRoot, BatchId, BatchSeed, Error, WorkRequest, WorkRequestExecution,
};

/// Verify DART asset proof request.
#[derive(PassByCodec, Encode, Decode, Clone)]
pub enum VerifyDartAssetRequest {
    AccountRegistration {
        did: IdentityId,
        proof: AccountRegistrationProof,
    },
    EncryptionKeyRegistration {
        did: IdentityId,
        proof: EncryptionKeyRegistrationProof,
    },
    BatchedAccountAssetRegistration {
        did: IdentityId,
        proof: BatchedAccountAssetRegistrationProof<PolymeshPrivateLimits>,
    },
    MintAsset {
        did: IdentityId,
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
    MediatorAffirmation {
        leg_enc: LegEncrypted,
        proof: MediatorAffirmationProof,
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

impl VerifyDartAssetRequest {
    pub fn verify_with_seed(&self, seed: BatchSeed) -> Result<VerifyDartProofResponse, Error> {
        match self {
            Self::AccountRegistration { did, proof } => {
                proof.verify(&did.0[..]).map_err(|_| Error::VerifyFailed)?;
            }
            Self::EncryptionKeyRegistration { did, proof } => {
                proof.verify(&did.0[..]).map_err(|_| Error::VerifyFailed)?;
            }
            Self::BatchedAccountAssetRegistration { did, proof } => {
                let mut rng = Rng::from_seed(seed);
                let params = get_account_curve_tree_parameters();
                proof
                    .batched_verify(&did.0[..], &params, &mut rng)
                    .map_err(|_| Error::VerifyFailed)?;
            }
            Self::MintAsset { did, root, proof } => {
                let mut rng = Rng::from_seed(seed);
                proof
                    .verify(&did.0[..], root, &mut rng)
                    .map_err(|_| Error::VerifyFailed)?;
            }
            Self::CreateSettlement { root, proof } => {
                let mut rng = Rng::from_seed(seed);
                proof
                    .verify(root, &mut rng)
                    .map_err(|_| Error::VerifyFailed)?;
            }
            Self::SenderAffirmation {
                leg_enc,
                root,
                proof,
            } => {
                let mut rng = Rng::from_seed(seed);
                proof
                    .verify(&leg_enc, root, &mut rng)
                    .map_err(|_| Error::VerifyFailed)?;
            }
            Self::ReceiverAffirmation {
                leg_enc,
                root,
                proof,
            } => {
                let mut rng = Rng::from_seed(seed);
                proof
                    .verify(&leg_enc, root, &mut rng)
                    .map_err(|_| Error::VerifyFailed)?;
            }
            Self::MediatorAffirmation { leg_enc, proof } => {
                proof.verify(&leg_enc).map_err(|_| Error::VerifyFailed)?;
            }
            Self::SenderCounterUpdate {
                leg_enc,
                root,
                proof,
            } => {
                let mut rng = Rng::from_seed(seed);
                proof
                    .verify(&leg_enc, root, &mut rng)
                    .map_err(|_| Error::VerifyFailed)?;
            }
            Self::SenderReversal {
                leg_enc,
                root,
                proof,
            } => {
                let mut rng = Rng::from_seed(seed);
                proof
                    .verify(&leg_enc, root, &mut rng)
                    .map_err(|_| Error::VerifyFailed)?;
            }
            Self::ReceiverClaim {
                leg_enc,
                root,
                proof,
            } => {
                let mut rng = Rng::from_seed(seed);
                proof
                    .verify(&leg_enc, root, &mut rng)
                    .map_err(|_| Error::VerifyFailed)?;
            }
        }
        Ok(VerifyDartProofResponse::None)
    }

    pub fn submit(&self, batch_id: BatchId) -> Result<WorkRequestExecution, Error> {
        let req = WorkRequest::new_verify(self);
        req.submit(batch_id)
    }
}

#[cfg(feature = "std")]
impl VerifyDartAssetRequest {
    pub fn verify(&self) -> Result<VerifyDartProofResponse, Error> {
        let seed = self.using_encoded(blake2_256);
        self.verify_with_seed(seed)
    }
}

#[cfg(not(feature = "std"))]
impl VerifyDartAssetRequest {
    pub fn verify(self) -> Result<VerifyDartProofResponse, Error> {
        crate::native_dart_assets::verify_proof(self)
    }
}

#[derive(PassByCodec, Encode, Decode, Clone)]
pub enum VerifyDartProofResponse {
    None,
}
