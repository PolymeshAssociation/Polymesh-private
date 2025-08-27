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
    AccountAssetState, AccountKeyPair, AssetId, AssetMintingProof, Balance, EncryptionKeyPair,
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
        key: AccountKeyPair,
        did: IdentityId,
        asset_id: AssetId,
        counter: u16,
    },
    MintAsset {
        key: AccountKeyPair,
        amount: Balance,
        path: AccountLeafPathAndRoot,
        account_state: AccountAssetState,
    },
    CreateSettlement {
        paths: MultiLeafPathAndRoot<ASSET_TREE_L, ASSET_TREE_M, AssetTreeConfig>,
        settlement: SettlementBuilder<PolymeshPrivateLimits>,
    },
    SenderAffirmation {
        key: AccountKeyPair,
        leg_ref: LegRef,
        leg_enc: LegEncrypted,
        leg_enc_rand: LegEncryptionRandomness,
        amount: Balance,
        path: AccountLeafPathAndRoot,
        account_state: AccountAssetState,
    },
    ReceiverAffirmation {
        key: AccountKeyPair,
        leg_ref: LegRef,
        leg_enc: LegEncrypted,
        leg_enc_rand: LegEncryptionRandomness,
        path: AccountLeafPathAndRoot,
        account_state: AccountAssetState,
    },
    MediatorAffirmation {
        key: EncryptionKeyPair,
        leg_ref: LegRef,
        leg_enc: LegEncrypted,
        key_index: u8,
        asset_id: AssetId,
        accept: bool,
    },
    ReceiverClaim {
        key: AccountKeyPair,
        leg_ref: LegRef,
        leg_enc: LegEncrypted,
        leg_enc_rand: LegEncryptionRandomness,
        amount: Balance,
        path: AccountLeafPathAndRoot,
        account_state: AccountAssetState,
    },
    SenderCounterUpdate {
        key: AccountKeyPair,
        leg_ref: LegRef,
        leg_enc: LegEncrypted,
        leg_enc_rand: LegEncryptionRandomness,
        path: AccountLeafPathAndRoot,
        account_state: AccountAssetState,
    },
    SenderRevert {
        key: AccountKeyPair,
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
                key,
                did,
                asset_id,
                counter,
            } => {
                let params = get_account_curve_tree_parameters();
                let (proof, account_state) = AccountAssetRegistrationProof::new(
                    &mut rng,
                    &key,
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
                key,
                amount,
                path,
                mut account_state,
            } => {
                let proof =
                    AssetMintingProof::new(&mut rng, &key, &mut account_state, path, amount)
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
                key,
                leg_ref,
                leg_enc,
                leg_enc_rand,
                amount,
                path,
                mut account_state,
            } => {
                let proof = SenderAffirmationProof::new(
                    &mut rng,
                    &key,
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
                key,
                leg_ref,
                leg_enc,
                leg_enc_rand,
                path,
                mut account_state,
            } => {
                let proof = ReceiverAffirmationProof::new(
                    &mut rng,
                    &key,
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
                key,
                leg_ref,
                leg_enc,
                key_index,
                asset_id,
                accept,
            } => {
                let proof = MediatorAffirmationProof::new(
                    &mut rng, &leg_ref, asset_id, &leg_enc, &key, key_index, accept,
                )
                .map_err(|_| Error::VerifyFailed)?;
                Ok(GenerateDartProofResponse::MediatorAffirmation { proof })
            }
            GenerateDartProofRequest::ReceiverClaim {
                key,
                leg_ref,
                leg_enc,
                leg_enc_rand,
                amount,
                path,
                mut account_state,
            } => {
                let proof = ReceiverClaimProof::new(
                    &mut rng,
                    &key,
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
                key,
                leg_ref,
                leg_enc,
                leg_enc_rand,
                path,
                mut account_state,
            } => {
                let proof = SenderCounterUpdateProof::new(
                    &mut rng,
                    &key,
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
                key,
                leg_ref,
                leg_enc,
                leg_enc_rand,
                amount,
                path,
                mut account_state,
            } => {
                let proof = SenderReversalProof::new(
                    &mut rng,
                    &key,
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
