use codec::{Decode, Encode};
use sp_runtime_interface::pass_by::PassByCodec;

#[cfg(feature = "std")]
use rand_chacha::ChaCha20Rng as Rng;
#[cfg(feature = "std")]
use rand_core::SeedableRng;

#[cfg(feature = "std")]
use polymesh_dart::curve_tree::get_account_curve_tree_parameters;
use polymesh_dart::{
    ACCOUNT_TREE_L, ACCOUNT_TREE_M, ASSET_TREE_L, ASSET_TREE_M, AccountAssetRegistrationProof,
    AccountAssetState, AccountKeys, AssetId, AssetMintingProof, Balance, EncryptionKeyPair,
    LegEncrypted, LegEncryptionRandomness, LegRef, MediatorAffirmationProof, PolymeshPrivateLimits,
    ReceiverAffirmationProof, ReceiverClaimProof, SenderAffirmationProof, SenderCounterUpdateProof,
    SenderReversalProof, SettlementBuilder, SettlementProof,
    curve_tree::{AccountTreeConfig, AssetTreeConfig, LeafPathAndRoot, MultiLeafPathAndRoot},
};
use polymesh_primitives::IdentityId;

use crate::{BatchSeed, Error};

pub type AccountLeafPathAndRoot =
    LeafPathAndRoot<ACCOUNT_TREE_L, ACCOUNT_TREE_M, AccountTreeConfig>;
pub type AssetLeafPathAndRoot = LeafPathAndRoot<ASSET_TREE_L, ASSET_TREE_M, AssetTreeConfig>;

#[derive(PassByCodec, Encode, Decode, Clone)]
pub enum GenerateDartProofRequest {
    AccountAssetRegistration {
        did: IdentityId,
        keys: AccountKeys,
        asset_id: AssetId,
        counter: u16,
    },
    MintAsset {
        amount: Balance,
        path: AccountLeafPathAndRoot,
        account_state: AccountAssetState,
    },
    CreateSettlement {
        paths: MultiLeafPathAndRoot<ASSET_TREE_L, ASSET_TREE_M, AssetTreeConfig>,
        settlement: SettlementBuilder<PolymeshPrivateLimits>,
    },
    SenderAffirmation {
        leg_ref: LegRef,
        leg_enc: LegEncrypted,
        leg_enc_rand: LegEncryptionRandomness,
        amount: Balance,
        path: AccountLeafPathAndRoot,
        account_state: AccountAssetState,
    },
    ReceiverAffirmation {
        leg_ref: LegRef,
        leg_enc: LegEncrypted,
        leg_enc_rand: LegEncryptionRandomness,
        path: AccountLeafPathAndRoot,
        account_state: AccountAssetState,
    },
    MediatorAffirmation {
        leg_ref: LegRef,
        leg_enc: LegEncrypted,
        asset_id: AssetId,
        key: EncryptionKeyPair,
        key_index: u8,
        accept: bool,
    },
    ReceiverClaim {
        leg_ref: LegRef,
        leg_enc: LegEncrypted,
        leg_enc_rand: LegEncryptionRandomness,
        amount: Balance,
        path: AccountLeafPathAndRoot,
        account_state: AccountAssetState,
    },
    SenderCounterUpdate {
        leg_ref: LegRef,
        leg_enc: LegEncrypted,
        leg_enc_rand: LegEncryptionRandomness,
        path: AccountLeafPathAndRoot,
        account_state: AccountAssetState,
    },
    SenderRevert {
        leg_ref: LegRef,
        leg_enc: LegEncrypted,
        leg_enc_rand: LegEncryptionRandomness,
        amount: Balance,
        path: AccountLeafPathAndRoot,
        account_state: AccountAssetState,
    },
}

#[cfg(feature = "std")]
impl GenerateDartProofRequest {
    pub fn generate(self, seed: BatchSeed) -> Result<GenerateDartProofResponse, Error> {
        let mut rng = Rng::from_seed(seed);
        match self {
            GenerateDartProofRequest::AccountAssetRegistration {
                did,
                keys,
                asset_id,
                counter,
            } => {
                let params = get_account_curve_tree_parameters();
                let (proof, account_state) = AccountAssetRegistrationProof::new(
                    &mut rng,
                    &keys,
                    asset_id,
                    counter,
                    &did.0[..],
                    params,
                )
                .map_err(|_| Error::VerifyFailed)?;
                Ok(GenerateDartProofResponse::AccountAssetRegistration {
                    proof,
                    account_state,
                })
            }
            GenerateDartProofRequest::MintAsset {
                amount,
                path,
                mut account_state,
            } => {
                let proof = AssetMintingProof::new(&mut rng, &mut account_state, path, amount)
                    .map_err(|_| Error::VerifyFailed)?;
                Ok(GenerateDartProofResponse::MintAsset {
                    proof,
                    account_state,
                })
            }
            GenerateDartProofRequest::CreateSettlement {
                paths,
                settlement: builder,
            } => {
                let proof = builder
                    .encrypt_and_prove(&mut rng, paths)
                    .map_err(|_| Error::VerifyFailed)?;
                Ok(GenerateDartProofResponse::CreateSettlement { proof })
            }
            GenerateDartProofRequest::SenderAffirmation {
                leg_ref,
                leg_enc,
                leg_enc_rand,
                amount,
                path,
                mut account_state,
            } => {
                let proof = SenderAffirmationProof::new(
                    &mut rng,
                    &leg_ref,
                    amount,
                    &leg_enc,
                    &leg_enc_rand,
                    &mut account_state,
                    path,
                )
                .map_err(|_| Error::VerifyFailed)?;
                Ok(GenerateDartProofResponse::SenderAffirmation {
                    proof,
                    account_state,
                })
            }
            GenerateDartProofRequest::ReceiverAffirmation {
                leg_ref,
                leg_enc,
                leg_enc_rand,
                path,
                mut account_state,
            } => {
                let proof = ReceiverAffirmationProof::new(
                    &mut rng,
                    &leg_ref,
                    &leg_enc,
                    &leg_enc_rand,
                    &mut account_state,
                    path,
                )
                .map_err(|_| Error::VerifyFailed)?;
                Ok(GenerateDartProofResponse::ReceiverAffirmation {
                    proof,
                    account_state,
                })
            }
            GenerateDartProofRequest::MediatorAffirmation {
                leg_ref,
                leg_enc,
                asset_id,
                key,
                key_index,
                accept,
            } => {
                let proof = MediatorAffirmationProof::new(
                    &mut rng, &leg_ref, asset_id, &leg_enc, &key, key_index, accept,
                )
                .map_err(|_| Error::VerifyFailed)?;
                Ok(GenerateDartProofResponse::MediatorAffirmation { proof })
            }
            GenerateDartProofRequest::ReceiverClaim {
                leg_ref,
                leg_enc,
                leg_enc_rand,
                amount,
                path,
                mut account_state,
            } => {
                let proof = ReceiverClaimProof::new(
                    &mut rng,
                    &leg_ref,
                    amount,
                    &leg_enc,
                    &leg_enc_rand,
                    &mut account_state,
                    path,
                )
                .map_err(|_| Error::VerifyFailed)?;
                Ok(GenerateDartProofResponse::ReceiverClaim {
                    proof,
                    account_state,
                })
            }
            GenerateDartProofRequest::SenderCounterUpdate {
                leg_ref,
                leg_enc,
                leg_enc_rand,
                path,
                mut account_state,
            } => {
                let proof = SenderCounterUpdateProof::new(
                    &mut rng,
                    &leg_ref,
                    &leg_enc,
                    &leg_enc_rand,
                    &mut account_state,
                    path,
                )
                .map_err(|_| Error::VerifyFailed)?;
                Ok(GenerateDartProofResponse::SenderCounterUpdate {
                    proof,
                    account_state,
                })
            }
            GenerateDartProofRequest::SenderRevert {
                leg_ref,
                leg_enc,
                leg_enc_rand,
                amount,
                path,
                mut account_state,
            } => {
                let proof = SenderReversalProof::new(
                    &mut rng,
                    &leg_ref,
                    amount,
                    &leg_enc,
                    &leg_enc_rand,
                    &mut account_state,
                    path,
                )
                .map_err(|_| Error::VerifyFailed)?;
                Ok(GenerateDartProofResponse::SenderRevert {
                    proof,
                    account_state,
                })
            }
        }
    }
}

#[cfg(not(feature = "std"))]
impl GenerateDartProofRequest {
    pub fn generate(self, seed: BatchSeed) -> Result<GenerateDartProofResponse, Error> {
        crate::native_dart_assets::generate_proof(self, seed)
    }
}

#[derive(PassByCodec, Encode, Decode, Clone)]
pub enum GenerateDartProofResponse {
    AccountAssetRegistration {
        proof: AccountAssetRegistrationProof,
        account_state: AccountAssetState,
    },
    MintAsset {
        proof: AssetMintingProof,
        account_state: AccountAssetState,
    },
    CreateSettlement {
        proof: SettlementProof<PolymeshPrivateLimits>,
    },
    SenderAffirmation {
        proof: SenderAffirmationProof,
        account_state: AccountAssetState,
    },
    ReceiverAffirmation {
        proof: ReceiverAffirmationProof,
        account_state: AccountAssetState,
    },
    MediatorAffirmation {
        proof: MediatorAffirmationProof,
    },
    ReceiverClaim {
        proof: ReceiverClaimProof,
        account_state: AccountAssetState,
    },
    SenderCounterUpdate {
        proof: SenderCounterUpdateProof,
        account_state: AccountAssetState,
    },
    SenderRevert {
        proof: SenderReversalProof,
        account_state: AccountAssetState,
    },
}
