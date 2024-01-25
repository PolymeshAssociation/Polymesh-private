// This file is part of the Polymesh distribution (https://github.com/PolymeshAssociation/Polymesh).
// Copyright (c) 2023 Polymesh Association

#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
use sp_runtime_interface::{pass_by::PassByCodec, runtime_interface};
use sp_std::prelude::Vec;

#[cfg(feature = "std")]
use rand_chacha::ChaCha20Rng as Rng;
#[cfg(feature = "std")]
use rand_core::SeedableRng;
use sp_std::collections::btree_set::BTreeSet;

use confidential_assets::{
    burn::ConfidentialBurnProof, transaction::ConfidentialTransferProof,
    Balance as ConfidentialBalance, CipherText, CompressedElgamalPublicKey, ElgamalKeys,
    ElgamalPublicKey, Result,
};

#[cfg(feature = "std")]
mod batch;

pub type BatchId = u32;

pub type BatchReqId = u32;

/// Verify confidential asset transfer request.
#[derive(PassByCodec, Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub struct VerifyConfidentialTransferRequest {
    pub sender: CompressedElgamalPublicKey,
    pub sender_balance: CipherText,
    pub receiver: CompressedElgamalPublicKey,
    pub auditors: Vec<CompressedElgamalPublicKey>,
    pub proof: Vec<u8>,
    pub seed: [u8; 32],
}

#[cfg(feature = "std")]
impl VerifyConfidentialTransferRequest {
    fn sender_account(&self) -> Option<ElgamalPublicKey> {
        self.sender.into_public_key()
    }

    fn receiver_account(&self) -> Option<ElgamalPublicKey> {
        self.receiver.into_public_key()
    }

    /// Auditors are order by there compressed Elgamal public key (`MediatorAccount`).
    fn build_auditor_set(&self) -> Option<BTreeSet<ElgamalPublicKey>> {
        self.auditors
            .iter()
            .map(|account| account.into_public_key())
            .collect()
    }

    fn into_tx(&self) -> Option<ConfidentialTransferProof> {
        ConfidentialTransferProof::decode(&mut self.proof.as_slice()).ok()
    }

    pub fn verify(&self) -> Result<bool, ()> {
        let init_tx = self.into_tx().ok_or(())?;
        let sender_account = self.sender_account().ok_or(())?;
        let receiver_account = self.receiver_account().ok_or(())?;
        let auditors = self.build_auditor_set().ok_or(())?;

        // Verify the sender's proof.
        let mut rng = Rng::from_seed(self.seed);
        init_tx
            .verify(
                &sender_account,
                &self.sender_balance,
                &receiver_account,
                &auditors,
                &mut rng,
            )
            .map_err(|_| ())?;

        Ok(true)
    }
}

#[cfg(not(feature = "std"))]
impl VerifyConfidentialTransferRequest {
    pub fn verify(&self) -> Result<bool, ()> {
        native_confidential_assets::verify_sender_proof(self)
    }
}

/// Verify confidential asset burn request.
#[derive(PassByCodec, Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub struct VerifyConfidentialBurnRequest {
    pub issuer: CompressedElgamalPublicKey,
    pub issuer_balance: CipherText,
    pub amount: ConfidentialBalance,
    pub proof: ConfidentialBurnProof,
    pub seed: [u8; 32],
}

#[cfg(feature = "std")]
impl VerifyConfidentialBurnRequest {
    pub fn verify(&self) -> Result<bool, ()> {
        let issuer_account = self.issuer.into_public_key().ok_or(())?;

        // Verify the issuer's proof.
        let mut rng = Rng::from_seed(self.seed);
        self.proof
            .verify(&issuer_account, &self.issuer_balance, self.amount, &mut rng)
            .map_err(|_| ())?;

        Ok(true)
    }
}

#[cfg(not(feature = "std"))]
impl VerifyConfidentialBurnRequest {
    pub fn verify(&self) -> Result<bool, ()> {
        native_confidential_assets::verify_burn_proof(self)
    }
}

/// Confidential asset proof response.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub enum VerifyConfidentialProofResponse {
    TransferProof(bool),
    BurnProof(bool),
}

impl VerifyConfidentialProofResponse {
    pub fn is_valid(&self) -> bool {
        match self {
            Self::TransferProof(valid) | Self::BurnProof(valid) => *valid,
        }
    }
}

/// Verify confidential asset proof request.
#[derive(PassByCodec, Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub enum VerifyConfidentialProofRequest {
    TransferProof(VerifyConfidentialTransferRequest),
    BurnProof(VerifyConfidentialBurnRequest),
}

#[cfg(feature = "std")]
impl VerifyConfidentialProofRequest {
    pub fn verify(&self) -> Result<VerifyConfidentialProofResponse, ()> {
        match self {
            Self::TransferProof(req) => {
                let resp = req.verify()?;
                Ok(VerifyConfidentialProofResponse::TransferProof(resp))
            }
            Self::BurnProof(req) => {
                let resp = req.verify()?;
                Ok(VerifyConfidentialProofResponse::BurnProof(resp))
            }
        }
    }
}

#[cfg(not(feature = "std"))]
impl VerifyConfidentialProofRequest {
    pub fn verify(&self) -> Result<VerifyConfidentialProofResponse, ()> {
        native_confidential_assets::verify_proof(self)
    }
}

/// Generate confidential asset transfer request.
#[derive(PassByCodec, Encode, Decode, Clone, Debug)]
pub struct GenerateTransferProofRequest {
    pub sender_account: ElgamalKeys,
    pub sender_init_balance: CipherText,
    pub sender_balance: ConfidentialBalance,
    pub receiver_key: ElgamalPublicKey,
    pub auditors_keys: BTreeSet<ElgamalPublicKey>,
    pub amount: ConfidentialBalance,
    pub seed: [u8; 32],
}

impl GenerateTransferProofRequest {
    /// Create a confidential asset transfer proof.
    pub fn new(
        sender_account: ElgamalKeys,
        sender_init_balance: CipherText,
        sender_balance: ConfidentialBalance,
        receiver_key: ElgamalPublicKey,
        auditors_keys: BTreeSet<ElgamalPublicKey>,
        amount: ConfidentialBalance,
        seed: [u8; 32],
    ) -> Self {
        Self {
            sender_account,
            sender_init_balance,
            sender_balance,
            receiver_key,
            auditors_keys,
            amount,
            seed,
        }
    }

    #[cfg(feature = "std")]
    pub fn generate(&self) -> Result<GenerateProofResponse, ()> {
        let mut rng = Rng::from_seed(self.seed);
        let proof = ConfidentialTransferProof::new(
            &self.sender_account,
            &self.sender_init_balance,
            self.sender_balance,
            &self.receiver_key,
            &self.auditors_keys,
            self.amount,
            &mut rng,
        )
        .map_err(|_| ())?;
        Ok(GenerateProofResponse {
            proof: proof.encode(),
        })
    }
}

/// Generate confidential asset proof request.
#[derive(PassByCodec, Encode, Decode, Clone, Debug)]
pub enum GenerateProofRequest {
    TransferProof(GenerateTransferProofRequest),
}

#[cfg(feature = "std")]
impl GenerateProofRequest {
    pub fn generate(&self) -> Result<GenerateProofResponse, ()> {
        match self {
            Self::TransferProof(req) => req.generate(),
        }
    }
}

/// Generate confidential asset proof response.
#[derive(PassByCodec, Encode, Decode, Clone, Debug)]
pub struct GenerateProofResponse {
    pub proof: Vec<u8>,
}

impl GenerateProofResponse {
    pub fn transfer_proof(&self) -> Result<ConfidentialTransferProof, ()> {
        ConfidentialTransferProof::decode(&mut self.proof.as_slice()).map_err(|_| ())
    }
}

/// Batch Verify confidential asset proofs.
#[derive(Debug)]
pub struct BatchVerify {
    pub id: BatchId,
}

impl BatchVerify {
    pub fn create() -> Self {
        let id = native_confidential_assets::create_batch();
        Self { id }
    }

    pub fn submit(&self, req: VerifyConfidentialProofRequest) -> Result<(), ()> {
        native_confidential_assets::batch_submit(self.id, req)
    }

    pub fn submit_transfer_request(
        &self,
        req: VerifyConfidentialTransferRequest,
    ) -> Result<(), ()> {
        self.submit(VerifyConfidentialProofRequest::TransferProof(req))
    }

    pub fn finalize(&self) -> Result<bool, ()> {
        native_confidential_assets::batch_finish(self.id)
    }

    #[cfg(feature = "runtime-benchmarks")]
    pub fn generate_proof(&self, req: GenerateProofRequest) -> Result<(), ()> {
        native_confidential_assets::batch_generate_proof(self.id, req)
    }

    #[cfg(feature = "runtime-benchmarks")]
    pub fn generate_transfer_proof(&self, req: GenerateTransferProofRequest) -> Result<(), ()> {
        self.generate_proof(GenerateProofRequest::TransferProof(req))
    }

    #[cfg(feature = "runtime-benchmarks")]
    pub fn get_proofs(&self) -> Result<Vec<GenerateProofResponse>, ()> {
        native_confidential_assets::batch_get_proofs(self.id)
    }
}

/// Native interface for runtime module for Confidential Assets.
#[runtime_interface]
pub trait NativeConfidentialAssets {
    fn verify_sender_proof(req: &VerifyConfidentialTransferRequest) -> Result<bool, ()> {
        req.verify()
    }

    fn verify_burn_proof(req: &VerifyConfidentialBurnRequest) -> Result<bool, ()> {
        req.verify()
    }

    fn verify_proof(
        req: &VerifyConfidentialProofRequest,
    ) -> Result<VerifyConfidentialProofResponse, ()> {
        req.verify()
    }

    fn create_batch() -> BatchId {
        batch::BatchVerifiers::create_batch()
    }

    fn batch_submit(id: BatchId, req: VerifyConfidentialProofRequest) -> Result<(), ()> {
        batch::BatchVerifiers::batch_submit(id, req)
    }

    fn batch_finish(id: BatchId) -> Result<bool, ()> {
        let batch = batch::BatchVerifiers::batch_finish(id).ok_or(())?;
        batch.finalize()
    }

    fn batch_generate_proof(_id: BatchId, _req: GenerateProofRequest) -> Result<(), ()> {
        #[cfg(feature = "runtime-benchmarks")]
        {
            batch::BatchVerifiers::batch_generate_proof(_id, _req)
        }
        #[cfg(not(feature = "runtime-benchmarks"))]
        Err(())
    }

    fn batch_get_proofs(_id: BatchId) -> Result<Vec<GenerateProofResponse>, ()> {
        #[cfg(feature = "runtime-benchmarks")]
        {
            let batch = batch::BatchVerifiers::batch_finish(_id).ok_or(())?;
            batch.get_proofs()
        }
        #[cfg(not(feature = "runtime-benchmarks"))]
        Err(())
    }
}
