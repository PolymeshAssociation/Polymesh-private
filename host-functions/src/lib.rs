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
#[cfg(feature = "std")]
use sp_std::collections::btree_set::BTreeSet;

use confidential_assets::{
    burn::ConfidentialBurnProof, Balance as ConfidentialBalance, CipherText,
    CompressedElgamalPublicKey, Result,
};
#[cfg(feature = "std")]
use confidential_assets::{transaction::ConfidentialTransferProof, ElgamalPublicKey};

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

    pub fn verify(&self) -> Result<ConfidentialTransferInfo, ()> {
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

        Ok(ConfidentialTransferInfo {
            sender_amount: init_tx.sender_amount(),
            receiver_amount: init_tx.receiver_amount(),
        })
    }
}

#[cfg(not(feature = "std"))]
impl VerifyConfidentialTransferRequest {
    pub fn verify(&self) -> Result<ConfidentialTransferInfo, ()> {
        native_confidential_assets::verify_sender_proof(self)
    }
}

/// Confidential asset transfer info.
///
/// Transaction amount encrypted with sender & receiver public keys.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub struct ConfidentialTransferInfo {
    pub sender_amount: CipherText,
    pub receiver_amount: CipherText,
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
    pub fn verify(&self) -> Result<CipherText, ()> {
        let issuer_account = self.issuer.into_public_key().ok_or(())?;

        // Verify the issuer's proof.
        let mut rng = Rng::from_seed(self.seed);
        let enc_amount = self
            .proof
            .verify(&issuer_account, &self.issuer_balance, self.amount, &mut rng)
            .map_err(|_| ())?;

        Ok(enc_amount)
    }
}

#[cfg(not(feature = "std"))]
impl VerifyConfidentialBurnRequest {
    pub fn verify(&self) -> Result<CipherText, ()> {
        native_confidential_assets::verify_burn_proof(self)
    }
}

/// Native interface for runtime module for Confidential Assets.
#[runtime_interface]
pub trait NativeConfidentialAssets {
    fn verify_sender_proof(
        req: &VerifyConfidentialTransferRequest,
    ) -> Result<ConfidentialTransferInfo, ()> {
        req.verify()
    }
    fn verify_burn_proof(req: &VerifyConfidentialBurnRequest) -> Result<CipherText, ()> {
        req.verify()
    }
}
