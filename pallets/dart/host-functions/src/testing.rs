use codec::{Decode, Encode};
#[cfg(feature = "std")]
use sp_io::hashing::blake2_256;
use sp_runtime_interface::pass_by::PassByCodec;
use sp_std::vec::Vec;

use rand_chacha::ChaCha20Rng as Rng;
use rand_core::SeedableRng;

use polymesh_dart::{
    ACCOUNT_TREE_L, ACCOUNT_TREE_M, ASSET_TREE_L, ASSET_TREE_M, AccountAssetRegistrationProof,
    AccountAssetState, AccountKeyPair, AccountKeys, AccountRegistrationProof, AssetId,
    AssetMintingProof, Balance, BatchedAccountAssetRegistrationProof, EncryptionKeyPair,
    EncryptionKeyRegistrationProof, LegEncrypted, LegRef, MediatorAffirmationProof,
    PolymeshPrivateLimits, ReceiverAffirmationProof, ReceiverClaimProof, SenderAffirmationProof,
    SenderCounterUpdateProof, SenderReversalProof, SettlementBuilder, SettlementProof,
    curve_tree::{AccountTreeConfig, AssetTreeConfig, LeafPathAndRoot, MultiLeafPathAndRoot},
};
use polymesh_dart::{LegRole, curve_tree::get_account_curve_tree_parameters};
use polymesh_primitives::IdentityId;

use crate::{BatchId, BatchSeed, Error, WorkRequest, WorkRequestExecution};

pub type AccountLeafPathAndRoot =
    LeafPathAndRoot<ACCOUNT_TREE_L, ACCOUNT_TREE_M, AccountTreeConfig>;
pub type AssetLeafPathAndRoot = LeafPathAndRoot<ASSET_TREE_L, ASSET_TREE_M, AssetTreeConfig>;

#[derive(PassByCodec, Encode, Decode, Clone)]
pub enum GenerateDartProofRequest {
    AccountRegistration {
        accounts: Vec<AccountKeys>,
        did: IdentityId,
    },
    EncryptionKeyRegistration {
        keys: Vec<EncryptionKeyPair>,
        did: IdentityId,
    },
    AccountAssetRegistration {
        key: AccountKeyPair,
        did: IdentityId,
        asset_id: AssetId,
        counter: u16,
    },
    BatchedAccountAssetRegistration {
        did: IdentityId,
        account_assets: Vec<(AccountKeyPair, AssetId, u16)>,
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
        keys: AccountKeys,
        leg_ref: LegRef,
        leg_enc: LegEncrypted,
        amount: Balance,
        path: AccountLeafPathAndRoot,
        account_state: AccountAssetState,
    },
    ReceiverAffirmation {
        keys: AccountKeys,
        leg_ref: LegRef,
        leg_enc: LegEncrypted,
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
        keys: AccountKeys,
        leg_ref: LegRef,
        leg_enc: LegEncrypted,
        amount: Balance,
        path: AccountLeafPathAndRoot,
        account_state: AccountAssetState,
    },
    SenderCounterUpdate {
        keys: AccountKeys,
        leg_ref: LegRef,
        leg_enc: LegEncrypted,
        path: AccountLeafPathAndRoot,
        account_state: AccountAssetState,
    },
    SenderRevert {
        keys: AccountKeys,
        leg_ref: LegRef,
        leg_enc: LegEncrypted,
        amount: Balance,
        path: AccountLeafPathAndRoot,
        account_state: AccountAssetState,
    },
}

impl GenerateDartProofRequest {
    pub fn generate_with_seed(self, seed: BatchSeed) -> Result<GenerateDartProofResponse, Error> {
        let mut rng = Rng::from_seed(seed);
        match self {
            GenerateDartProofRequest::AccountRegistration { accounts, did } => {
                use polymesh_dart::AccountRegistrationProof;

                let proof =
                    AccountRegistrationProof::new(&mut rng, accounts.as_slice(), &did.0[..])
                        .map_err(|_| Error::GenerateProofFailed)?;
                Ok(GenerateDartProofResponse::AccountRegistration { proof })
            }
            GenerateDartProofRequest::EncryptionKeyRegistration { keys, did } => {
                use polymesh_dart::EncryptionKeyRegistrationProof;

                let proof =
                    EncryptionKeyRegistrationProof::new(&mut rng, keys.as_slice(), &did.0[..])
                        .map_err(|_| Error::GenerateProofFailed)?;
                Ok(GenerateDartProofResponse::EncryptionKeyRegistration { proof })
            }
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
                .map_err(|_| Error::GenerateProofFailed)?;
                Ok(GenerateDartProofResponse::AccountAssetRegistration {
                    proof,
                    account_state,
                })
            }
            GenerateDartProofRequest::BatchedAccountAssetRegistration {
                did,
                account_assets,
            } => {
                let params = get_account_curve_tree_parameters();
                let (proof, account_states) = BatchedAccountAssetRegistrationProof::new(
                    &mut rng,
                    &account_assets,
                    &did.0[..],
                    params,
                )
                .map_err(|_| Error::GenerateProofFailed)?;
                Ok(GenerateDartProofResponse::BatchedAccountAssetRegistration {
                    proof,
                    account_states,
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
                        .map_err(|_| Error::GenerateProofFailed)?;
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
                    .map_err(|_| Error::GenerateProofFailed)?;
                Ok(GenerateDartProofResponse::CreateSettlement { proof })
            }
            GenerateDartProofRequest::SenderAffirmation {
                keys,
                leg_ref,
                leg_enc,
                amount,
                path,
                mut account_state,
            } => {
                // Decrypt leg.
                let leg_enc_rand = leg_enc
                    .get_encryption_randomness(LegRole::Sender, &keys.enc)
                    .map_err(|_| Error::GenerateProofFailed)?;

                let proof = SenderAffirmationProof::new(
                    &mut rng,
                    &keys.acct,
                    &leg_ref,
                    amount,
                    &leg_enc,
                    &leg_enc_rand,
                    &mut account_state,
                    path,
                )
                .map_err(|_| Error::GenerateProofFailed)?;
                Ok(GenerateDartProofResponse::SenderAffirmation {
                    proof,
                    account_state,
                })
            }
            GenerateDartProofRequest::ReceiverAffirmation {
                keys,
                leg_ref,
                leg_enc,
                path,
                mut account_state,
            } => {
                // Decrypt leg.
                let leg_enc_rand = leg_enc
                    .get_encryption_randomness(LegRole::Receiver, &keys.enc)
                    .map_err(|_| Error::GenerateProofFailed)?;

                let proof = ReceiverAffirmationProof::new(
                    &mut rng,
                    &keys.acct,
                    &leg_ref,
                    &leg_enc,
                    &leg_enc_rand,
                    &mut account_state,
                    path,
                )
                .map_err(|_| Error::GenerateProofFailed)?;
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
                .map_err(|_| Error::GenerateProofFailed)?;
                Ok(GenerateDartProofResponse::MediatorAffirmation { proof })
            }
            GenerateDartProofRequest::ReceiverClaim {
                keys,
                leg_ref,
                leg_enc,
                amount,
                path,
                mut account_state,
            } => {
                // Decrypt leg.
                let leg_enc_rand = leg_enc
                    .get_encryption_randomness(LegRole::Receiver, &keys.enc)
                    .map_err(|_| Error::GenerateProofFailed)?;

                let proof = ReceiverClaimProof::new(
                    &mut rng,
                    &keys.acct,
                    &leg_ref,
                    amount,
                    &leg_enc,
                    &leg_enc_rand,
                    &mut account_state,
                    path,
                )
                .map_err(|_| Error::GenerateProofFailed)?;
                Ok(GenerateDartProofResponse::ReceiverClaim {
                    proof,
                    account_state,
                })
            }
            GenerateDartProofRequest::SenderCounterUpdate {
                keys,
                leg_ref,
                leg_enc,
                path,
                mut account_state,
            } => {
                // Decrypt leg.
                let leg_enc_rand = leg_enc
                    .get_encryption_randomness(LegRole::Sender, &keys.enc)
                    .map_err(|_| Error::GenerateProofFailed)?;

                let proof = SenderCounterUpdateProof::new(
                    &mut rng,
                    &keys.acct,
                    &leg_ref,
                    &leg_enc,
                    &leg_enc_rand,
                    &mut account_state,
                    path,
                )
                .map_err(|_| Error::GenerateProofFailed)?;
                Ok(GenerateDartProofResponse::SenderCounterUpdate {
                    proof,
                    account_state,
                })
            }
            GenerateDartProofRequest::SenderRevert {
                keys,
                leg_ref,
                leg_enc,
                amount,
                path,
                mut account_state,
            } => {
                // Decrypt leg.
                let leg_enc_rand = leg_enc
                    .get_encryption_randomness(LegRole::Sender, &keys.enc)
                    .map_err(|_| Error::GenerateProofFailed)?;

                let proof = SenderReversalProof::new(
                    &mut rng,
                    &keys.acct,
                    &leg_ref,
                    amount,
                    &leg_enc,
                    &leg_enc_rand,
                    &mut account_state,
                    path,
                )
                .map_err(|_| Error::GenerateProofFailed)?;
                Ok(GenerateDartProofResponse::SenderRevert {
                    proof,
                    account_state,
                })
            }
        }
    }

    pub fn submit(&self, batch_id: BatchId) -> Result<WorkRequestExecution, Error> {
        let req = WorkRequest::new_generate(self);
        req.submit(batch_id)
    }
}

#[cfg(feature = "std")]
impl GenerateDartProofRequest {
    pub fn generate(self) -> Result<GenerateDartProofResponse, Error> {
        let seed = self.using_encoded(blake2_256);
        self.generate_with_seed(seed)
    }
}

#[cfg(not(feature = "std"))]
impl GenerateDartProofRequest {
    pub fn generate(self) -> Result<GenerateDartProofResponse, Error> {
        crate::native_dart_assets::generate_proof(self)
    }
}

#[derive(PassByCodec, Encode, Decode, Clone)]
pub enum GenerateDartProofResponse {
    AccountRegistration {
        proof: AccountRegistrationProof,
    },
    EncryptionKeyRegistration {
        proof: EncryptionKeyRegistrationProof,
    },
    AccountAssetRegistration {
        proof: AccountAssetRegistrationProof,
        account_state: AccountAssetState,
    },
    BatchedAccountAssetRegistration {
        proof: BatchedAccountAssetRegistrationProof<PolymeshPrivateLimits>,
        account_states: Vec<AccountAssetState>,
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
