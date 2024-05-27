// This file is part of the Polymesh distribution (https://github.com/PolymeshAssociation/Polymesh).
// Copyright (c) 2023 Polymesh Association

use codec::{Decode, Encode};
use sp_runtime_interface::pass_by::PassByCodec;
use sp_std::prelude::Vec;

#[cfg(feature = "std")]
use rand_chacha::ChaCha20Rng as Rng;
#[cfg(feature = "std")]
use rand_core::SeedableRng;
use sp_std::collections::btree_set::BTreeSet;

use confidential_assets::{
    burn::ConfidentialBurnProof, transaction::ConfidentialTransferProof,
    Balance as ConfidentialBalance, CipherText, CompressedElgamalPublicKey, ElgamalKeys,
    ElgamalPublicKey,
};

use crate::*;

/// Verify confidential asset transfer request.
#[derive(PassByCodec, Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub struct VerifyConfidentialTransferRequest {
    pub sender: CompressedElgamalPublicKey,
    pub sender_balance: HostCipherText,
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

    pub fn verify(&self) -> Result<bool, Error> {
        let init_tx = self.into_tx().ok_or(Error::VerifyFailed)?;
        let sender_balance = self.sender_balance.0.decompress();
        let sender_account = self.sender_account().ok_or(Error::VerifyFailed)?;
        let receiver_account = self.receiver_account().ok_or(Error::VerifyFailed)?;
        let auditors = self.build_auditor_set().ok_or(Error::VerifyFailed)?;

        // Verify the sender's proof.
        let mut rng = Rng::from_seed(self.seed);
        init_tx
            .verify(
                &sender_account,
                &sender_balance,
                &receiver_account,
                &auditors,
                &mut rng,
            )
            .map_err(|_| Error::VerifyFailed)?;

        Ok(true)
    }
}

#[cfg(not(feature = "std"))]
impl VerifyConfidentialTransferRequest {
    pub fn verify(&self) -> Result<bool, Error> {
        native_confidential_assets::verify_sender_proof(self)
    }
}

/// Verify confidential asset burn request.
#[derive(PassByCodec, Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub struct VerifyConfidentialBurnRequest {
    pub issuer: CompressedElgamalPublicKey,
    pub issuer_balance: HostCipherText,
    pub amount: ConfidentialBalance,
    pub proof: ConfidentialBurnProof,
    pub seed: [u8; 32],
}

#[cfg(feature = "std")]
impl VerifyConfidentialBurnRequest {
    pub fn verify(&self) -> Result<bool, Error> {
        let issuer_balance = self.issuer_balance.0.decompress();
        let issuer_account = self.issuer.into_public_key().ok_or(Error::VerifyFailed)?;

        // Verify the issuer's proof.
        let mut rng = Rng::from_seed(self.seed);
        self.proof
            .verify(&issuer_account, &issuer_balance, self.amount, &mut rng)
            .map_err(|_| Error::VerifyFailed)?;

        Ok(true)
    }
}

#[cfg(not(feature = "std"))]
impl VerifyConfidentialBurnRequest {
    pub fn verify(&self) -> Result<bool, Error> {
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
    pub fn verify(&self) -> Result<VerifyConfidentialProofResponse, Error> {
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
    pub fn verify(&self) -> Result<VerifyConfidentialProofResponse, Error> {
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
    pub fn generate(&self) -> Result<GenerateProofResponse, Error> {
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
        .map_err(|_| Error::VerifyFailed)?;
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
    pub fn generate(&self) -> Result<GenerateProofResponse, Error> {
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
    pub fn transfer_proof(&self) -> Result<ConfidentialTransferProof, Error> {
        ConfidentialTransferProof::decode(&mut self.proof.as_slice())
            .map_err(|_| Error::VerifyFailed)
    }
}

/// Batch Verify confidential asset proofs.
#[derive(Debug)]
pub struct BatchVerify {
    pub id: Option<BatchId>,
}

impl Drop for BatchVerify {
    fn drop(&mut self) {
        if let Some(id) = self.id {
            native_confidential_assets::batch_cancel(id)
        }
    }
}

impl BatchVerify {
    /// Only available for benchmarking to isolate the proof verification
    /// costs from runtime costs.
    #[cfg(feature = "runtime-benchmarks")]
    pub fn set_skip_verify(skip: bool) {
        native_confidential_assets::set_skip_verify(skip);
    }

    pub fn create() -> Self {
        let id = native_confidential_assets::create_batch();
        Self { id: Some(id) }
    }

    fn id(&self) -> Result<BatchId, Error> {
        self.id.ok_or(Error::BatchClosed)
    }

    pub fn submit(&self, req: VerifyConfidentialProofRequest) -> Result<(), Error> {
        let id = self.id()?;
        native_confidential_assets::batch_submit(id, req)
    }

    pub fn submit_transfer_request(
        &self,
        req: VerifyConfidentialTransferRequest,
    ) -> Result<(), Error> {
        self.submit(VerifyConfidentialProofRequest::TransferProof(req))
    }

    pub fn finalize(&mut self) -> Result<bool, Error> {
        let id = self.id.take().ok_or(Error::BatchClosed)?;
        native_confidential_assets::batch_finish(id)
    }

    #[cfg(feature = "runtime-benchmarks")]
    pub fn generate_proof(&self, req: GenerateProofRequest) -> Result<(), Error> {
        let id = self.id()?;
        native_confidential_assets::batch_generate_proof(id, req)
    }

    #[cfg(feature = "runtime-benchmarks")]
    pub fn generate_transfer_proof(&self, req: GenerateTransferProofRequest) -> Result<(), Error> {
        self.generate_proof(GenerateProofRequest::TransferProof(req))
    }

    #[cfg(feature = "runtime-benchmarks")]
    pub fn get_proofs(&mut self) -> Result<Vec<GenerateProofResponse>, Error> {
        let id = self.id.take().ok_or(Error::BatchClosed)?;
        native_confidential_assets::batch_get_proofs(id)
    }
}
