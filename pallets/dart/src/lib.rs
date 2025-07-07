// This file is part of the Polymesh distribution (https://github.com/PolymeshAssociation/Polymesh).
// Copyright (c) 2023 Polymesh

//! # DART asset Pallet
//!
//! The DART Asset pallet provides sender, receiver, asset and value confidentiality.
//!
//! ## Overview
//!
//! These pallets call out to the [Polymesh DART library](https://github.com/PolymeshAssociation/dart)
//! which implements the ZK-proofs for DART.
//!
//!

#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
use core::ops::{Deref, DerefMut};
use frame_support::{
    dispatch::{DispatchError, DispatchResult},
    ensure,
    traits::{Get, Randomness},
    weights::Weight,
    BoundedVec,
};
use frame_system::pallet_prelude::*;
use polymesh_primitives::{Balance, IdentityId};
use rand_core::{CryptoRng, RngCore};
use scale_info::TypeInfo;
use sp_std::convert::From;

use polymesh_dart::{
    curve_tree::{
        CurveTreeBackend, CurveTreeParameters, CurveTreeRoot, CurveTreeWithBackend, Inner,
        LeafValue, NodeLocation, ValidateCurveTreeRoot,
    },
    AccountPublicKey, AccountStateCommitment, AccountStateNullifier, AssetId as DartAssetId,
    AssetState, AuditorOrMediator, EncryptionPublicKey, Error as DartError, LeafIndex,
    LegEncrypted, LegId, LegRef, MediatorAffirmationProof, NodeLevel, PallasParameters,
    ReceiverAffirmationProof, ReceiverClaimProof, SenderAffirmationProof, SenderCounterUpdateProof,
    SenderReversalProof, SettlementId, VestaParameters, ACCOUNT_TREE_HEIGHT, ACCOUNT_TREE_L,
    ASSET_TREE_GENS, ASSET_TREE_HEIGHT, ASSET_TREE_L,
};

type PalletIdentity<T> = pallet_identity::Pallet<T>;

pub mod weights;

pub trait WeightInfo {
    fn register_account() -> Weight;
    fn create_asset() -> Weight;
    fn register_account_asset() -> Weight;
    fn mint_asset() -> Weight;
    fn create_settlement(l: u32) -> Weight;
    fn sender_affirmation() -> Weight;
    fn receiver_affirmation() -> Weight;
    fn mediator_affirmation() -> Weight;
    fn sender_update_counter() -> Weight;
    fn sender_revert() -> Weight;
    fn receiver_claim() -> Weight;
}

/// The affirmation status for each party in a DART settlement leg.
#[derive(Copy, Clone, Encode, Decode, Debug, TypeInfo, PartialEq, Eq)]
pub enum AffirmationStatus {
    Pending,
    Affirmed,
    Rejected,
    Finalized,
}

impl AffirmationStatus {
    /// Merge two affirmation statuses together.
    ///
    /// Examples:
    /// * If the sender is `Pending` and the receiver is `Affirmed`, the result will still be `Pending`.
    /// * If the sender is `Affirmed` and the receiver is `Rejected`, the result will be `Rejected`.
    /// * If the sender is `Finalized` and the receiver is `Pending`, it will return an error since a finalized leg cannot go back to pending.
    ///
    /// Returns an error for invalid state transitions.
    pub fn merge<T: Config>(
        self,
        other: AffirmationStatus,
    ) -> Result<AffirmationStatus, DispatchError> {
        use AffirmationStatus::*;
        match (self, other) {
            (Pending, Pending) => Ok(Pending),
            (Pending, Affirmed) => Ok(Pending),
            (Pending, Rejected) => Ok(Rejected),
            (Pending, Finalized) => Err(Error::<T>::CannotGoFromPendingToFinalized)?,

            (Affirmed, Pending) => Ok(Pending),
            (Affirmed, Affirmed) => Ok(Affirmed),
            (Affirmed, Rejected) => Ok(Rejected),
            (Affirmed, Finalized) => Ok(Affirmed),

            (Rejected, Pending) => Ok(Rejected),
            (Rejected, Affirmed) => Ok(Rejected),
            (Rejected, Rejected) => Ok(Rejected),
            (Rejected, Finalized) => Err(Error::<T>::CannotGoFromRejectedToFinalized)?,

            (Finalized, Pending) => Err(Error::<T>::CannotGoFromFinalizedToPending)?,
            (Finalized, Affirmed) => Ok(Affirmed),
            (Finalized, Rejected) => Err(Error::<T>::CannotGoFromFinalizedToRejected)?,
            (Finalized, Finalized) => Ok(Finalized),
        }
    }
}

/// The state of a DART settlement leg.
#[derive(Clone, Encode, Decode, Debug, TypeInfo, PartialEq, Eq)]
#[scale_info(skip_type_params(T))]
pub struct DartSettlementLeg<T: Config> {
    /// The encrypted leg data.
    pub enc: LegEncrypted,
    /// The sender's affirmation status.
    pub sender: AffirmationStatus,
    /// The receiver's affirmation status.
    pub receiver: AffirmationStatus,
    /// The mediator's affirmation status, if any.
    pub mediator: Option<AffirmationStatus>,
    /// The leg status, which is derived from the sender, receiver, and mediator statuses.
    pub status: AffirmationStatus,
    _marker: core::marker::PhantomData<T>,
}

impl<T: Config> DartSettlementLeg<T> {
    /// Try to update the status of the leg based on the current sender, receiver, and mediator statuses.
    fn update_status(&mut self) -> Result<(), DispatchError> {
        // Merge the sender and receiver statuses.
        let mut affirmation = self.sender.merge::<T>(self.receiver)?;
        // If there is a mediator, merge the mediator status as well.
        if let Some(mediator) = self.mediator {
            affirmation = affirmation.merge::<T>(mediator)?;
        }
        self.status = affirmation;
        Ok(())
    }

    /// If any leg in a settlement is rejected, then all legs are rejected.
    pub fn reject(&mut self) -> Result<(), DispatchError> {
        // If the leg is already finalized, we cannot reject it.
        ensure!(
            self.status != AffirmationStatus::Finalized,
            Error::<T>::CannotRejectFinalizedSettlement
        );
        self.status = AffirmationStatus::Rejected;
        Ok(())
    }

    /// Verify a sender affirmation proof for this leg.
    pub fn sender_affirmation<R: RngCore + CryptoRng>(
        &mut self,
        proof: &SenderAffirmationProof,
        tree_roots: impl ValidateCurveTreeRoot<ACCOUNT_TREE_L>,
        rng: &mut R,
    ) -> DispatchResult {
        // The sender can only affirm if the sender affirmation status is `Pending`.
        ensure!(
            self.sender == AffirmationStatus::Pending,
            Error::<T>::AlreadyAffirmed
        );

        // verify the proof.
        proof
            .verify(&self.enc, tree_roots, rng)
            .map_err(|_| Error::<T>::InvalidProof)?;

        // Update the leg's status.
        self.sender = AffirmationStatus::Affirmed;

        // Update the leg status.  If the other parties have already affirmed, this will update the leg's status to `Affirmed`.
        self.update_status()?;

        Ok(())
    }

    /// Verify a receiver affirmation proof for this leg.
    pub fn receiver_affirmation<R: RngCore + CryptoRng>(
        &mut self,
        proof: &ReceiverAffirmationProof,
        tree_roots: impl ValidateCurveTreeRoot<ACCOUNT_TREE_L>,
        rng: &mut R,
    ) -> DispatchResult {
        // The receiver can only affirm if the receiver affirmation status is `Pending`.
        ensure!(
            self.receiver == AffirmationStatus::Pending,
            Error::<T>::AlreadyAffirmed
        );

        // verify the proof.
        proof
            .verify(&self.enc, tree_roots, rng)
            .map_err(|_| Error::<T>::InvalidProof)?;

        // Update the leg's status.
        self.receiver = AffirmationStatus::Affirmed;

        // Update the leg status.  If the other parties have already affirmed, this will update the leg's status to `Affirmed`.
        self.update_status()?;

        Ok(())
    }

    /// Verify a mediator affirmation proof for this leg.
    pub fn mediator_affirmation(&mut self, proof: &MediatorAffirmationProof) -> DispatchResult {
        // A mediator can only affirm if the leg has a mediator.
        ensure!(self.mediator.is_some(), Error::<T>::NoMediatorForThisLeg,);
        // The mediator can only affirm if the mediator affirmation status is `Pending`.
        ensure!(
            self.mediator == Some(AffirmationStatus::Pending),
            Error::<T>::AlreadyAffirmed
        );

        // verify the proof.
        proof
            .verify(&self.enc)
            .map_err(|_| Error::<T>::InvalidProof)?;

        // Update the leg's mediator status based on the proof.
        if proof.accept {
            // The mediator is affirming the leg.
            self.mediator = Some(AffirmationStatus::Affirmed);
        } else {
            // The mediator is rejecting the leg.
            self.mediator = Some(AffirmationStatus::Rejected);
        }

        // Update the leg status.  If the other parties have already affirmed, this will update the leg's status to `Affirmed`.
        self.update_status()?;

        Ok(())
    }

    /// Verify the sender's counter update proof for this leg.
    ///
    /// The sender is only allowed to submit this proof if the settlement has been executed.
    pub fn sender_counter_update<R: RngCore + CryptoRng>(
        &mut self,
        proof: &SenderCounterUpdateProof,
        tree_roots: impl ValidateCurveTreeRoot<ACCOUNT_TREE_L>,
        rng: &mut R,
    ) -> DispatchResult {
        // The sender is only allowed to submit this proof if the settlement has been executed.
        ensure!(
            self.sender == AffirmationStatus::Affirmed,
            Error::<T>::SenderHasNotAffirmed,
        );
        // The leg must be in the `Affirmed` state.
        ensure!(
            self.status == AffirmationStatus::Affirmed,
            Error::<T>::LegNotAffirmed,
        );

        // verify the proof.
        proof
            .verify(&self.enc, tree_roots, rng)
            .map_err(|_| Error::<T>::InvalidProof)?;

        // Update the leg's status.
        self.sender = AffirmationStatus::Finalized;

        // Update the leg status.  If the other parties have finalized, this will update the leg's status to `Finalized`.
        self.update_status()?;

        Ok(())
    }

    /// Verify the sender's Reversal proof for this leg.
    ///
    /// The sender is only allowed to submit this proof if the settlement has been rejected.
    pub fn sender_reversal<R: RngCore + CryptoRng>(
        &mut self,
        proof: &SenderReversalProof,
        tree_roots: impl ValidateCurveTreeRoot<ACCOUNT_TREE_L>,
        rng: &mut R,
    ) -> DispatchResult {
        // The sender is only allowed to submit this proof if the settlement has been rejected and they have affirmed.
        ensure!(
            self.sender == AffirmationStatus::Affirmed,
            Error::<T>::SenderHasNotAffirmed,
        );
        // The leg must be in the `Rejected` state.
        ensure!(
            self.status == AffirmationStatus::Rejected,
            Error::<T>::LegNotRejected,
        );

        // verify the proof.
        proof
            .verify(&self.enc, tree_roots, rng)
            .map_err(|_| Error::<T>::InvalidProof)?;

        // Update the leg's status.
        self.sender = AffirmationStatus::Finalized;

        // Update the leg status.  If the other parties have finalized, this will update the leg's status to `Finalized`.
        self.update_status()?;

        Ok(())
    }

    /// Verify the receiver's claim proof for this leg.
    ///
    /// The receiver is only allowed to submit this proof if the settlement has been executed.
    pub fn receiver_claim<R: RngCore + CryptoRng>(
        &mut self,
        proof: &ReceiverClaimProof,
        tree_roots: impl ValidateCurveTreeRoot<ACCOUNT_TREE_L>,
        rng: &mut R,
    ) -> DispatchResult {
        // The receiver is only allowed to submit this proof if the settlement has been executed and they have affirmed.
        ensure!(
            self.receiver == AffirmationStatus::Affirmed,
            Error::<T>::ReceiverHasNotAffirmed,
        );
        // The leg must be in the `Affirmed` state.
        ensure!(
            self.status == AffirmationStatus::Affirmed,
            Error::<T>::LegNotAffirmed,
        );

        // verify the proof.
        proof
            .verify(&self.enc, tree_roots, rng)
            .map_err(|_| Error::<T>::InvalidProof)?;

        // Update the leg's status.
        self.receiver = AffirmationStatus::Finalized;

        // Update the leg status.  If the other parties have finalized, this will update the leg's status to `Finalized`.
        self.update_status()?;

        Ok(())
    }
}

/// Settlement status for a DART settlement.
#[derive(Copy, Clone, Encode, Decode, Debug, TypeInfo, PartialEq, Eq)]
pub enum SettlementStatus {
    Pending,
    Executed,
    Rejected,
    Finalized,
}

pub struct UpdateSettlementStatus<T: Config> {
    /// The settlement ID.
    pub settlement_id: SettlementId,
    /// The status of the settlement.
    pub status: SettlementStatus,
    _marker: core::marker::PhantomData<T>,
}

impl<T: Config> UpdateSettlementStatus<T> {
    /// Create a new `UpdateSettlementStatus` instance.
    pub fn new(leg_ref: LegRef) -> Result<Self, DispatchError> {
        // Get the settlement ID from the leg reference.
        let settlement_id = leg_ref
            .settlement_id()
            .ok_or(Error::<T>::SettlementNotFound)?;
        // Get the status of the settlement.
        let status =
            SettlementState::<T>::get(settlement_id).ok_or(Error::<T>::SettlementNotFound)?;

        Ok(Self {
            settlement_id,
            status,
            _marker: core::marker::PhantomData,
        })
    }

    /// Ensure the settlement is in a pending state.
    pub fn ensure_pending(&self) -> DispatchResult {
        // Ensure the settlement is in a pending state.
        ensure!(
            self.status == SettlementStatus::Pending,
            Error::<T>::SettlementNotPending
        );
        Ok(())
    }

    /// Get a specific leg from the settlement.
    fn get_leg(&self, leg_id: LegId) -> Result<DartSettlementLeg<T>, DispatchError> {
        // Ensure the leg ID is valid.
        Ok(
            SettlementLegs::<T>::get((self.settlement_id, leg_id))
                .ok_or(Error::<T>::LegNotFound)?,
        )
    }

    /// Update a specific leg in the settlement.
    fn update_leg(&mut self, leg_id: LegId, leg: DartSettlementLeg<T>) -> DispatchResult {
        SettlementLegs::<T>::insert((self.settlement_id, leg_id), leg);
        Ok(())
    }

    /// Verify a sender affirmation proof for a specific leg in the settlement.
    pub fn sender_affirmation<R: RngCore + CryptoRng>(
        &mut self,
        proof: &SenderAffirmationProof,
        tree_roots: impl ValidateCurveTreeRoot<ACCOUNT_TREE_L>,
        rng: &mut R,
    ) -> DispatchResult {
        self.ensure_pending()?;

        let leg_id = proof.leg_ref.leg_id();
        let mut leg = self.get_leg(leg_id)?;

        leg.sender_affirmation(proof, tree_roots, rng)?;

        // Update the leg in the settlement.
        self.update_leg(leg_id, leg)?;

        // If the sender has affirmed, update the status of the settlement.
        self.update_status()?;

        Ok(())
    }

    /// Verify a receiver affirmation proof for a specific leg in the settlement.
    pub fn receiver_affirmation<R: RngCore + CryptoRng>(
        &mut self,
        proof: &ReceiverAffirmationProof,
        tree_roots: impl ValidateCurveTreeRoot<ACCOUNT_TREE_L>,
        rng: &mut R,
    ) -> DispatchResult {
        self.ensure_pending()?;

        let leg_id = proof.leg_ref.leg_id();
        let mut leg = self.get_leg(leg_id)?;

        leg.receiver_affirmation(proof, tree_roots, rng)?;

        // Update the leg in the settlement.
        self.update_leg(leg_id, leg)?;

        // If the receiver has affirmed, update the status of the settlement.
        self.update_status()?;
        Ok(())
    }

    /// Verify a mediator affirmation proof for a specific leg in the settlement.
    pub fn mediator_affirmation(&mut self, proof: &MediatorAffirmationProof) -> DispatchResult {
        self.ensure_pending()?;

        let leg_id = proof.leg_ref.leg_id();
        let mut leg = self.get_leg(leg_id)?;

        leg.mediator_affirmation(proof)?;

        // Update the leg in the settlement.
        self.update_leg(leg_id, leg)?;

        if proof.accept {
            // If the mediator has accepted, update the status of the settlement.
            self.update_status()?;
        } else {
            // If the mediator has rejected, set the settlement status to rejected.
            self.reject_all_legs()?;
        }
        Ok(())
    }

    /// Verify the sender's counter update proof for a specific leg in the settlement.
    pub fn sender_counter_update<R: RngCore + CryptoRng>(
        &mut self,
        proof: &SenderCounterUpdateProof,
        tree_roots: impl ValidateCurveTreeRoot<ACCOUNT_TREE_L>,
        rng: &mut R,
    ) -> DispatchResult {
        // The sender can only update the counter if the settlement has been executed.
        ensure!(
            self.status == SettlementStatus::Executed,
            Error::<T>::SettlementNotExecuted
        );

        let leg_id = proof.leg_ref.leg_id();
        let mut leg = self.get_leg(leg_id)?;

        leg.sender_counter_update(proof, tree_roots, rng)?;

        // Update the leg in the settlement.
        self.update_leg(leg_id, leg)?;

        // If the sender has finalized the leg, update the status of the settlement.
        self.update_status()?;
        Ok(())
    }

    /// Verify the sender's reversal proof for a specific leg in the settlement.
    pub fn sender_reversal<R: RngCore + CryptoRng>(
        &mut self,
        proof: &SenderReversalProof,
        tree_roots: impl ValidateCurveTreeRoot<ACCOUNT_TREE_L>,
        rng: &mut R,
    ) -> DispatchResult {
        // The sender can only reverse if the settlement has been rejected.
        ensure!(
            self.status == SettlementStatus::Rejected,
            Error::<T>::SettlementNotRejected
        );

        let leg_id = proof.leg_ref.leg_id();
        let mut leg = self.get_leg(leg_id)?;

        leg.sender_reversal(proof, tree_roots, rng)?;

        // Update the leg in the settlement.
        self.update_leg(leg_id, leg)?;

        // If the sender has finalized the leg, update the status of the settlement.
        self.update_status()?;
        Ok(())
    }

    /// Verify the receiver's claim proof for a specific leg in the settlement.
    pub fn receiver_claim<R: RngCore + CryptoRng>(
        &mut self,
        proof: &ReceiverClaimProof,
        tree_roots: impl ValidateCurveTreeRoot<ACCOUNT_TREE_L>,
        rng: &mut R,
    ) -> DispatchResult {
        // The receiver can only claim if the settlement has been executed.
        ensure!(
            self.status == SettlementStatus::Executed,
            Error::<T>::SettlementNotExecuted
        );

        let leg_id = proof.leg_ref.leg_id();
        let mut leg = self.get_leg(leg_id)?;

        leg.receiver_claim(proof, tree_roots, rng)?;

        // Update the leg in the settlement.
        self.update_leg(leg_id, leg)?;

        // If the receiver has finalized the leg, update the status of the settlement.
        self.update_status()?;
        Ok(())
    }

    fn update_status(&mut self) -> DispatchResult {
        let updated_status = match self.status {
            SettlementStatus::Pending => {
                // If the settlement is pending, check if all legs are affirmed.
                for id in 0..T::MaxSettlementLegs::get() {
                    let leg = self.get_leg(id as LegId)?;
                    if leg.status != AffirmationStatus::Affirmed {
                        return Ok(()); // Still pending
                    }
                }
                // If all legs are affirmed, update the settlement status to executed.
                Some(SettlementStatus::Executed)
            }
            SettlementStatus::Executed | SettlementStatus::Rejected => {
                // If the settlement is in the executed or rejected state,
                // check if all legs are finalized.
                for id in 0..T::MaxSettlementLegs::get() {
                    let leg = self.get_leg(id as LegId)?;
                    if leg.status != AffirmationStatus::Finalized {
                        return Ok(()); // Still not finalized
                    }
                }
                // If all legs are finalized, update the settlement status to finalized.
                Some(SettlementStatus::Finalized)
            }
            SettlementStatus::Finalized => {
                // If the settlement is already finalized, do nothing.
                None
            }
        };

        // Store the updated status if it exists.
        if let Some(status) = updated_status {
            SettlementState::<T>::insert(self.settlement_id, status);

            // Emit an event for the settlement status update.
            Pallet::<T>::deposit_event(Event::<T>::SettlementStatusUpdated {
                settlement_id: self.settlement_id,
                status,
            });
        }

        Ok(())
    }

    fn reject_all_legs(&mut self) -> DispatchResult {
        // Reject all legs in the settlement.
        for id in 0..T::MaxSettlementLegs::get() {
            let mut leg = self.get_leg(id as LegId)?;
            leg.reject()?;
            self.update_leg(id as LegId, leg)?;
        }
        self.status = SettlementStatus::Rejected;
        Ok(())
    }
}

/// DART asset details.
#[derive(Clone, Encode, Decode, Debug, TypeInfo)]
#[scale_info(skip_type_params(T))]
pub struct DartAssetDetail<T: Config> {
    /// Asset ID.
    pub asset_id: DartAssetId,
    /// Total supply of the asset.
    pub total_supply: Balance,
    /// Asset's owner DID.
    pub owner_did: IdentityId,
    /// Asset data.
    pub data: BoundedVec<u8, T::MaxAssetDataLength>,
    /// Auditor or mediator public key.
    pub auditor_or_mediator: AuditorOrMediator,
}

pub type AssetLeaf = LeafValue<PallasParameters>;
pub type AssetInnerNode = Inner<1, PallasParameters, VestaParameters>;
pub type AssetNodeLocation = NodeLocation<ASSET_TREE_L>;

pub type AccountLeaf = LeafValue<PallasParameters>;
pub type AccountInnerNode = Inner<1, PallasParameters, VestaParameters>;
pub type AccountNodeLocation = NodeLocation<ACCOUNT_TREE_L>;

/// Asset Curve Tree Storage backend.
#[derive(Clone, Debug)]
pub struct AssetCurveTreeStorage<T: Config> {
    _marker: core::marker::PhantomData<T>,
}

impl<T: Config> CurveTreeBackend<ASSET_TREE_L, 1, PallasParameters, VestaParameters>
    for AssetCurveTreeStorage<T>
{
    type Error = Error<T>;

    fn new(_height: NodeLevel) -> Result<Self, Self::Error> {
        Ok(Self {
            _marker: core::marker::PhantomData,
        })
    }

    fn height(&self) -> NodeLevel {
        ASSET_TREE_HEIGHT
    }

    fn set_height(&mut self, _height: NodeLevel) -> Result<(), Self::Error> {
        Ok(())
    }

    fn allocate_leaf_index(&mut self) -> LeafIndex {
        let leaf_index = AssetLeaves::<T>::count() as LeafIndex;
        leaf_index
    }

    fn get_leaf(
        &self,
        leaf_index: LeafIndex,
    ) -> Result<Option<LeafValue<PallasParameters>>, Self::Error> {
        Ok(AssetLeaves::<T>::get(leaf_index))
    }

    fn set_leaf(
        &mut self,
        leaf_index: LeafIndex,
        new_leaf_value: LeafValue<PallasParameters>,
    ) -> Result<Option<LeafValue<PallasParameters>>, Self::Error> {
        // Use `mutate` to update the leaf value in the storage and return the previous value.
        Ok(AssetLeaves::<T>::mutate(leaf_index, |leaf| {
            // Get the old value, if it exists.
            let previous_value = leaf.take();
            // Set the new value.
            *leaf = Some(new_leaf_value);
            previous_value
        }))
    }

    fn leaf_count(&self) -> LeafIndex {
        AssetLeaves::<T>::count() as LeafIndex
    }

    fn get_inner_node(
        &self,
        location: NodeLocation<ASSET_TREE_L>,
    ) -> Result<Option<Inner<1, PallasParameters, VestaParameters>>, Self::Error> {
        Ok(AssetInnerNodes::<T>::get(location))
    }

    fn set_inner_node(
        &mut self,
        location: NodeLocation<ASSET_TREE_L>,
        new_node: Inner<1, PallasParameters, VestaParameters>,
    ) -> Result<(), Self::Error> {
        // set the inner node in the storage.
        AssetInnerNodes::<T>::insert(location, new_node);
        Ok(())
    }
}

/// Account Curve Tree Storage backend.
#[derive(Clone, Debug)]
pub struct AccountCurveTreeStorage<T: Config> {
    _marker: core::marker::PhantomData<T>,
}

impl<T: Config> CurveTreeBackend<ACCOUNT_TREE_L, 1, PallasParameters, VestaParameters>
    for AccountCurveTreeStorage<T>
{
    type Error = Error<T>;

    fn new(_height: NodeLevel) -> Result<Self, Self::Error> {
        Ok(Self {
            _marker: core::marker::PhantomData,
        })
    }

    fn height(&self) -> NodeLevel {
        ACCOUNT_TREE_HEIGHT
    }

    fn set_height(&mut self, _height: NodeLevel) -> Result<(), Self::Error> {
        Ok(())
    }

    fn allocate_leaf_index(&mut self) -> LeafIndex {
        let leaf_index = NextAccountLeafIndex::<T>::get();
        // Increment the next leaf index for the next call.
        NextAccountLeafIndex::<T>::put(leaf_index + 1);
        leaf_index
    }

    fn get_leaf(
        &self,
        leaf_index: LeafIndex,
    ) -> Result<Option<LeafValue<PallasParameters>>, Self::Error> {
        Ok(AccountLeaves::<T>::get(leaf_index))
    }

    fn set_leaf(
        &mut self,
        leaf_index: LeafIndex,
        new_leaf_value: LeafValue<PallasParameters>,
    ) -> Result<Option<LeafValue<PallasParameters>>, Self::Error> {
        // Use `mutate` to update the leaf value in the storage and return the previous value.
        Ok(AccountLeaves::<T>::mutate(leaf_index, |leaf| {
            // Get the old value, if it exists.
            let previous_value = leaf.take();
            // Set the new value.
            *leaf = Some(new_leaf_value);
            previous_value
        }))
    }

    fn leaf_count(&self) -> LeafIndex {
        NextAccountLeafIndex::<T>::get() as LeafIndex
    }

    fn get_inner_node(
        &self,
        location: NodeLocation<ACCOUNT_TREE_L>,
    ) -> Result<Option<Inner<1, PallasParameters, VestaParameters>>, Self::Error> {
        Ok(AccountInnerNodes::<T>::get(location))
    }

    fn set_inner_node(
        &mut self,
        location: NodeLocation<ACCOUNT_TREE_L>,
        new_node: Inner<1, PallasParameters, VestaParameters>,
    ) -> Result<(), Self::Error> {
        // set the inner node in the storage.
        AccountInnerNodes::<T>::insert(location, new_node);
        Ok(())
    }
}

pub type AssetCurveTreeType<T> = CurveTreeWithBackend<
    ASSET_TREE_L,
    1,
    PallasParameters,
    VestaParameters,
    AssetCurveTreeStorage<T>,
    Error<T>,
>;

pub struct AssetCurveTree<T: Config>(AssetCurveTreeType<T>);

impl<T: Config> Deref for AssetCurveTree<T> {
    type Target = AssetCurveTreeType<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: Config> DerefMut for AssetCurveTree<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T: Config> AssetCurveTree<T> {
    pub fn new(height: NodeLevel, gens_length: usize) -> Result<Self, Error<T>> {
        Ok(Self(CurveTreeWithBackend::new_no_init(
            height,
            gens_length,
        )?))
    }
}

impl<T: Config> ValidateCurveTreeRoot<ASSET_TREE_L> for &AssetCurveTree<T> {
    fn validate_root(&self, root: &CurveTreeRoot<ASSET_TREE_L>) -> bool {
        AssetCurveTreeRoots::<T>::contains_key(root)
    }

    fn params(&self) -> &CurveTreeParameters {
        self.parameters()
    }
}

pub type AccountCurveTreeType<T> = CurveTreeWithBackend<
    ACCOUNT_TREE_L,
    1,
    PallasParameters,
    VestaParameters,
    AccountCurveTreeStorage<T>,
    Error<T>,
>;

pub struct AccountCurveTree<T: Config>(AccountCurveTreeType<T>);

impl<T: Config> Deref for AccountCurveTree<T> {
    type Target = AccountCurveTreeType<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: Config> DerefMut for AccountCurveTree<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T: Config> AccountCurveTree<T> {
    pub fn new(height: NodeLevel, gens_length: usize) -> Result<Self, Error<T>> {
        Ok(Self(CurveTreeWithBackend::new_no_init(
            height,
            gens_length,
        )?))
    }
}

impl<T: Config> ValidateCurveTreeRoot<ACCOUNT_TREE_L> for &AccountCurveTree<T> {
    fn validate_root(&self, root: &CurveTreeRoot<ACCOUNT_TREE_L>) -> bool {
        AccountCurveTreeRoots::<T>::contains_key(root)
    }

    fn params(&self) -> &CurveTreeParameters {
        self.parameters()
    }
}

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::pallet_prelude::*;

    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    /// Configuration trait.
    #[pallet::config]
    pub trait Config: frame_system::Config + pallet_identity::Config + core::fmt::Debug {
        /// Pallet's events.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        /// Randomness source.
        type Randomness: Randomness<Self::Hash, Self::BlockNumber>;

        /// Dart asset pallet weights.
        type WeightInfo: WeightInfo;

        /// Maximum total supply.
        type MaxTotalSupply: Get<Balance>;

        /// Maximum asset data length.
        type MaxAssetDataLength: Get<u32>;

        /// Maximum number of settlement legs.
        type MaxSettlementLegs: Get<u32>;
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A new DART account has been registered.
        AccountRegistered {
            /// Caller's identity.
            caller_did: IdentityId,
            /// Dart account (public key)
            account: AccountPublicKey,
            /// Dart account (encryuption key)
            encryption_key: EncryptionPublicKey,
        },
        /// A new DART asset has been created.
        AssetCreated {
            /// Caller's identity.
            caller_did: IdentityId,
            /// Asset ID.
            asset_id: DartAssetId,
            /// Auditor or mediator.
            auditor_or_mediator: AuditorOrMediator,
            /// Asset data.
            data: BoundedVec<u8, T::MaxAssetDataLength>,
        },
        /// A DART asset has been updated.
        AssetUpdated {
            /// Caller's identity.
            caller_did: IdentityId,
            /// Asset ID.
            asset_id: DartAssetId,
            /// Auditor or mediator.
            auditor_or_mediator: AuditorOrMediator,
        },
        /// Account asset registered.
        AccountAssetRegistered {
            /// Caller's identity.
            caller_did: IdentityId,
            /// Dart account (public key)
            account: AccountPublicKey,
            /// Dart asset ID.
            asset_id: DartAssetId,
        },
        /// Minted DART asset.
        AssetMinted {
            /// Caller's identity.
            caller_did: IdentityId,
            /// Dart asset ID.
            asset_id: DartAssetId,
            /// Amount minted.
            amount: Balance,
            /// Total supply after minting.
            total_supply: Balance,
            /// Dart account (public key)
            account: AccountPublicKey,
        },
        /// Settlement created.
        SettlementCreated {
            /// Settlement ID.
            settlement_id: SettlementId,
            /// Legs in the settlement.
            legs: BoundedVec<LegEncrypted, T::MaxSettlementLegs>,
        },
        /// Sender has affirmed a leg.
        SenderAffirmed {
            /// Settlement Leg reference.
            leg_ref: LegRef,
        },
        /// Receiver has affirmed a leg.
        ReceiverAffirmed {
            /// Settlement Leg reference.
            leg_ref: LegRef,
        },
        /// Mediator has affirmed a leg.
        MediatorAffirmed {
            /// Settlement Leg reference.
            leg_ref: LegRef,
        },
        /// Sender updated counter.
        SenderCounterUpdated {
            /// Settlement Leg reference.
            leg_ref: LegRef,
        },
        /// Sender has reverted a leg.
        SenderReverted {
            /// Settlement Leg reference.
            leg_ref: LegRef,
        },
        /// Receiver has claimed assets.
        ReceiverClaimed {
            /// Settlement Leg reference.
            leg_ref: LegRef,
        },
        /// Settlement status updated.
        SettlementStatusUpdated {
            /// Settlement ID.
            settlement_id: SettlementId,
            /// New status of the settlement.
            status: SettlementStatus,
        },
        /// Account curve tree leaf inserted.
        ///
        /// This curve tree is append-only, so we only store the new leaf.
        AccountStateLeafInserted {
            /// The new leaf index.
            leaf_index: LeafIndex,
            /// The new account state leaf.
            account_leaf: AccountLeaf,
        },
        /// An asset state leaf has been updated.
        ///
        /// This curve tree is mutable, so we can update existing leaves.
        AssetStateLeafUpdated {
            /// The new leaf index.
            leaf_index: LeafIndex,
            /// The new asset leaf.
            asset_leaf: AssetLeaf,
        },
        /// Asset curve tree root updated.
        AssetCurveTreeRootUpdated {
            /// The new root.
            root: CurveTreeRoot<ASSET_TREE_L>,
        },
        /// Account curve tree root updated.
        AccountCurveTreeRootUpdated {
            /// The new root.
            root: CurveTreeRoot<ACCOUNT_TREE_L>,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        /// Dart account hasn't been registered yet.
        AccountMissing,
        /// Dart account already exists.
        AccountAlreadyCreated,
        /// Dart account has already registered that asset.
        AccountAssetAlreadyRegistered,
        /// CurveTree error.
        CurveTreeError,
        /// Leaf not found in the curve tree.
        LeafNotFound,
        /// Invalid proof provided.
        InvalidProof,
        /// Dart asset hasn't been registered yet.
        AssetMissing,
        /// The caller is not the owner of the DART account.
        NotAccountOwner,
        /// The caller is not the owner of the DART asset.
        NotAssetOwner,
        /// The asset total supply cannot exceed the maximum total supply.
        MaxTotalSupplyExceeded,
        /// The nullifier for the account state commitment has already been used.
        NullifierAlreadyUsed,
        /// Encryption key for the DART account is missing.
        EncryptionKeyMissing,
        /// Settlement is missing legs.
        SettlementMissingLegs,
        /// Settlement has too many legs.
        SettlementTooManyLegs,
        /// Cannot go from pending to finalized.
        CannotGoFromPendingToFinalized,
        /// Cannot go from finalized to pending.
        CannotGoFromFinalizedToPending,
        /// Cannot go from finalized to rejected.
        CannotGoFromFinalizedToRejected,
        /// Cannot go from rejected to finalized.
        CannotGoFromRejectedToFinalized,
        /// Cannot reject a finalized settlement.
        CannotRejectFinalizedSettlement,
        /// Leg hasn't been affirmed by the sender.
        SenderHasNotAffirmed,
        /// Leg hasn't been affirmed by the receiver.
        ReceiverHasNotAffirmed,
        /// Already affirmed.
        AlreadyAffirmed,
        /// Leg not affirmed.
        LegNotAffirmed,
        /// Leg not rejected.
        LegNotRejected,
        /// No mediator for this leg.
        NoMediatorForThisLeg,
        /// Settlement not found.
        SettlementNotFound,
        /// Leg not found in the settlement.
        LegNotFound,
        /// Settlement not pending.
        SettlementNotPending,
        /// Settlement not executed.
        SettlementNotExecuted,
        /// Settlement not rejected.
        SettlementNotRejected,
    }

    impl<T: Config> From<DartError> for Error<T> {
        fn from(_error: DartError) -> Self {
            Self::CurveTreeError
        }
    }

    /// Next Asset ID to be used for DART assets.
    #[pallet::storage]
    pub(crate) type NextAssetId<T: Config> = StorageValue<_, DartAssetId, ValueQuery>;

    /// Mapping of Dart Asset ID to its details.
    #[pallet::storage]
    pub(super) type DartAssetDetails<T: Config> =
        StorageMap<_, Twox64Concat, DartAssetId, DartAssetDetail<T>, OptionQuery>;

    /// Dart account to identity mapping.
    #[pallet::storage]
    pub(super) type AccountDid<T: Config> =
        StorageMap<_, Twox64Concat, AccountPublicKey, IdentityId, OptionQuery>;

    /// Mapping of Dart account public keys to their encryption keys.
    #[pallet::storage]
    pub(super) type AccountEncryptionKey<T: Config> =
        StorageMap<_, Twox64Concat, AccountPublicKey, EncryptionPublicKey, OptionQuery>;

    /// Mapping of Dart encryption keys to their public keys.
    #[pallet::storage]
    pub(super) type EncryptionKeyAccount<T: Config> =
        StorageMap<_, Twox64Concat, EncryptionPublicKey, AccountPublicKey, OptionQuery>;

    /// Dart account asset registrations.
    ///
    /// The chain must prevent the same account from registering the same asset multiple times.
    ///
    /// This is a double map where the first key is the account public key and the second key is the asset ID.
    #[pallet::storage]
    pub(super) type AccountAssetRegistrations<T: Config> = StorageNMap<
        _,
        (
            NMapKey<Twox64Concat, AccountPublicKey>,
            NMapKey<Twox64Concat, DartAssetId>,
        ),
        (),
        ValueQuery,
    >;

    /// Leaf storage for DART assets curve tree.
    ///
    /// A counted map is used since we need to support updating the leaves in the tree.
    #[pallet::storage]
    pub(super) type AssetLeaves<T: Config> =
        CountedStorageMap<_, Twox64Concat, LeafIndex, AssetLeaf, OptionQuery>;

    /// Inner node storage for DART assets curve tree.
    #[pallet::storage]
    pub(super) type AssetInnerNodes<T: Config> =
        StorageMap<_, Twox64Concat, AssetNodeLocation, AssetInnerNode, OptionQuery>;

    /// CurveTree Roots for DART assets curve tree.
    ///
    /// At the end of each block we will store the root of the assets curve tree.
    /// The map key is the root and the value is the block number when the root was last updated.
    #[pallet::storage]
    pub(super) type AssetCurveTreeRoots<T: Config> =
        StorageMap<_, Twox64Concat, CurveTreeRoot<ASSET_TREE_L>, T::BlockNumber, OptionQuery>;

    /// Update flag for the asset curve tree.
    ///
    /// This is used to detect when the asset curve tree has been updated.
    #[pallet::storage]
    pub(crate) type UpdatedAssetCurveTree<T: Config> = StorageValue<_, bool, ValueQuery>;

    /// Leaf storage for DART accounts curve tree.
    ///
    /// The leaves are immutable, so we use a simple storage map.
    #[pallet::storage]
    pub(super) type AccountLeaves<T: Config> =
        StorageMap<_, Twox64Concat, LeafIndex, AccountLeaf, OptionQuery>;

    /// Next leaf index for DART accounts curve tree.
    ///
    /// This is used to allocate new leaves in the tree.
    #[pallet::storage]
    pub(super) type NextAccountLeafIndex<T: Config> = StorageValue<_, LeafIndex, ValueQuery>;

    /// Inner node storage for DART accounts curve tree.
    #[pallet::storage]
    pub(super) type AccountInnerNodes<T: Config> =
        StorageMap<_, Twox64Concat, AccountNodeLocation, AccountInnerNode, OptionQuery>;

    /// CurveTree Roots for DART accounts curve tree.
    ///
    /// At the end of each block we will store the root of the accounts curve tree.
    /// The map key is the root and the value is the block number when the root was last updated.
    #[pallet::storage]
    pub(super) type AccountCurveTreeRoots<T: Config> =
        StorageMap<_, Twox64Concat, CurveTreeRoot<ACCOUNT_TREE_L>, T::BlockNumber, OptionQuery>;

    /// Nullifiers for DART account state commitments.
    ///
    /// This is used to ensure that the same account state commitment cannot be used twice.
    #[pallet::storage]
    pub(super) type AccountStateCommitmentNullifiers<T: Config> =
        StorageMap<_, Twox64Concat, AccountStateNullifier, (), ValueQuery>;

    /// Update flag for the account curve tree.
    ///
    /// This is used to detect when the account curve tree has been updated.
    #[pallet::storage]
    pub(crate) type UpdatedAccountCurveTree<T: Config> = StorageValue<_, bool, ValueQuery>;

    /// The next settlement ID to be used.
    #[pallet::storage]
    pub(crate) type NextSettlementId<T: Config> = StorageValue<_, SettlementId, ValueQuery>;

    /// The settlement status.
    #[pallet::storage]
    pub(crate) type SettlementState<T: Config> =
        StorageMap<_, Twox64Concat, SettlementId, SettlementStatus, OptionQuery>;

    /// The settlement legs.
    ///
    /// This is a double map where the first key is the settlement ID and the second key is the leg ID.
    /// The value is the DartSettlementLeg.
    #[pallet::storage]
    pub(crate) type SettlementLegs<T: Config> = StorageNMap<
        _,
        (
            NMapKey<Twox64Concat, SettlementId>,
            NMapKey<Twox64Concat, LegId>,
        ),
        DartSettlementLeg<T>,
        OptionQuery,
    >;

    /// RngNonce - Nonce used as `subject` to `Randomness`.
    #[pallet::storage]
    #[pallet::getter(fn rng_nonce)]
    pub(super) type RngNonce<T: Config> = StorageValue<_, u64, ValueQuery>;

    #[pallet::genesis_config]
    #[derive(Default)]
    pub struct GenesisConfig {}

    #[pallet::genesis_build]
    impl<T: Config> GenesisBuild<T> for GenesisConfig {
        fn build(&self) {
            // TODO: Pre-create X assets to reserve the first 0-X asset IDs.
        }
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_initialize(_n: BlockNumberFor<T>) -> Weight {
            UpdatedAssetCurveTree::<T>::put(false);
            UpdatedAccountCurveTree::<T>::put(false);
            // TODO: weight.
            Weight::zero()
        }

        fn on_finalize(_n: BlockNumberFor<T>) {
            // Check if the asset curve tree has been updated.
            if UpdatedAssetCurveTree::<T>::get() {
                // Get the asset curve tree.
                let tree = Self::get_asset_curve_tree()
                    .expect("Asset curve tree should be initialized; qed");

                // Get the root of the asset curve tree.
                let root = CurveTreeRoot::new(
                    &tree
                        .root_node()
                        .expect("Asset curve tree should have a root; qed"),
                )
                .expect("Asset curve tree root should be valid; qed");

                // Store the root in the storage.
                AssetCurveTreeRoots::<T>::insert(&root, frame_system::Pallet::<T>::block_number());

                // Emit an event for the asset curve tree root update.
                Self::deposit_event(Event::<T>::AssetCurveTreeRootUpdated { root });
            }

            // Check if the account curve tree has been updated.
            if UpdatedAccountCurveTree::<T>::get() {
                // Get the account curve tree.
                let tree = Self::get_account_curve_tree()
                    .expect("Account curve tree should be initialized; qed");

                // Get the root of the account curve tree.
                let root = CurveTreeRoot::new(
                    &tree
                        .root_node()
                        .expect("Account curve tree should have a root; qed"),
                )
                .expect("Account curve tree root should be valid; qed");

                // Store the root in the storage.
                AccountCurveTreeRoots::<T>::insert(
                    &root,
                    frame_system::Pallet::<T>::block_number(),
                );

                // Emit an event for the account curve tree root update.
                Self::deposit_event(Event::<T>::AccountCurveTreeRootUpdated { root });
            }
        }
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Register a dart account.
        ///
        /// # Arguments
        /// * `account` the dart account to register.
        /// * `encryption_key` the encryption key for the dart account.
        ///
        /// # Errors
        /// * `BadOrigin` if `origin` isn't signed.
        /// * `AccountAlreadyCreated` if the dart account or encryption key is already registered.
        #[pallet::call_index(0)]
        #[pallet::weight(<T as Config>::WeightInfo::register_account())]
        pub fn register_account(
            origin: OriginFor<T>,
            account: AccountPublicKey,
            encryption_key: EncryptionPublicKey,
        ) -> DispatchResult {
            let caller_did = PalletIdentity::<T>::ensure_perms(origin)?;
            // Ensure the dart account doesn't exist.
            ensure!(
                !AccountDid::<T>::contains_key(&account),
                Error::<T>::AccountAlreadyCreated
            );
            // Ensure the encryption key doesn't exist.
            ensure!(
                !EncryptionKeyAccount::<T>::contains_key(&encryption_key),
                Error::<T>::AccountAlreadyCreated
            );
            // Link the dart account to the caller's identity.
            AccountDid::<T>::insert(&account, caller_did);
            // Link the encryption key to the dart account.
            AccountEncryptionKey::<T>::insert(&account, &encryption_key);
            // Link the dart account to the encryption key.
            EncryptionKeyAccount::<T>::insert(&encryption_key, &account);

            Self::deposit_event(Event::<T>::AccountRegistered {
                caller_did,
                account,
                encryption_key,
            });
            Ok(())
        }

        /// Create a new DART Asset.
        ///
        /// # Arguments
        /// * `auditor_or_mediator` - The auditor or mediator public key.
        ///
        /// # Errors
        /// * `BadOrigin` if `origin` isn't signed.
        /// * `AccountMissing` if the auditor or mediator is not registered.
        /// * `EncryptionKeyMissing` if the encryption key of the auditor or mediator is not registered.
        #[pallet::call_index(1)]
        #[pallet::weight(<T as Config>::WeightInfo::create_asset())]
        pub fn create_asset(
            origin: OriginFor<T>,
            auditor_or_mediator: AuditorOrMediator,
            data: BoundedVec<u8, T::MaxAssetDataLength>,
        ) -> DispatchResult {
            let issuer = PalletIdentity::<T>::ensure_perms(origin)?;

            Self::base_create_asset(issuer, auditor_or_mediator, data)?;
            Ok(())
        }

        /// Register a DART asset with a DART account.
        ///
        /// This is used to initialize the first account state commitment of the DART asset for the DART account.
        ///
        /// # Arguments
        /// * `origin` - The origin of the call.  They must be the owner of the DART account.
        /// * `proof` - The Account asset registration proof.
        ///
        /// # Errors
        /// * `BadOrigin` if `origin` isn't signed.
        /// * `AccountMissing` if the DART account is not registered.
        /// * `AssetMissing` if the DART asset is not registered.
        /// * `AccountAssetAlreadyRegistered` if the DART account has already registered the DART asset.
        /// * `NotAccountOwner` if the caller is not the owner of the DART account.
        /// * `InvalidProof` if the proof is invalid.
        #[pallet::call_index(2)]
        #[pallet::weight(<T as Config>::WeightInfo::register_account_asset())]
        pub fn register_account_asset(
            origin: OriginFor<T>,
            proof: polymesh_dart::AccountAssetRegistrationProof,
        ) -> DispatchResult {
            // Ensure the caller has the required permissions to register the account asset.
            let caller_did = Self::ensure_dart_account_permissions(origin, &proof.account)?;

            // Ensure the DART asset exists.
            Self::ensure_dart_asset_exists(proof.asset_id)?;

            // Ensure the DART account hasn't already registered the DART asset.
            ensure!(
                !AccountAssetRegistrations::<T>::contains_key((&proof.account, &proof.asset_id)),
                Error::<T>::AccountAssetAlreadyRegistered
            );

            // Verify the proof.
            proof
                .verify(&caller_did.0[..])
                .map_err(|_| Error::<T>::InvalidProof)?;

            // Get the account curve tree.
            let mut account_curve_tree = Self::get_account_curve_tree()?;

            // Insert the new account state commitment from the proof into the account curve tree.
            Self::insert_account_leaf(
                &mut &mut account_curve_tree,
                proof.account_state_commitment,
            )?;

            // Emit an event for the account asset registration.
            Self::deposit_event(Event::<T>::AccountAssetRegistered {
                caller_did,
                asset_id: proof.asset_id,
                account: proof.account,
            });

            Ok(())
        }

        /// Mint a DART asset.
        ///
        /// # Arguments
        /// * `origin` - The origin of the call. They must be the owner of the DART asset and DART account.
        /// * `proof` - The minting proof.
        ///
        /// # Errors
        /// * `BadOrigin` if `origin` isn't signed.
        /// * `AccountMissing` if the DART account is not registered.
        /// * `AssetMissing` if the DART asset is not registered.
        /// * `NotAccountOwner` if the caller is not the owner of the DART account.
        /// * `InvalidProof` if the proof is invalid.
        /// * `NotAssetOwner` if the caller is not the owner of the DART asset.
        /// * `MaxTotalSupplyExceeded` if the total supply of the DART asset exceeds the maximum total supply.
        /// * `NullifierAlreadyUsed` if the nullifier for the account state commitment has already been used.
        #[pallet::call_index(3)]
        #[pallet::weight(<T as Config>::WeightInfo::mint_asset())]
        pub fn mint_asset(
            origin: OriginFor<T>,
            proof: polymesh_dart::AssetMintingProof,
        ) -> DispatchResult {
            // Ensure the caller has the required permissions to mint the asset.
            let caller_did = Self::ensure_dart_account_permissions(origin, &proof.pk)?;

            // Ensure the caller is the owner of the DART asset.
            let mut asset_details = Self::ensure_dart_asset_owner(caller_did, proof.asset_id)?;

            // Update the total supply of the DART asset and ensure it does not exceed the maximum total supply.
            let amount = proof.amount as Balance;
            asset_details.total_supply = asset_details
                .total_supply
                .checked_add(amount)
                .ok_or(Error::<T>::MaxTotalSupplyExceeded)?;
            ensure!(
                asset_details.total_supply <= T::MaxTotalSupply::get(),
                Error::<T>::MaxTotalSupplyExceeded
            );

            // Ensure the nullifier is unique.
            let nullifier = proof.nullifier();
            Self::ensure_account_state_nullifier_unique(&nullifier)?;

            // Get account curve tree.
            let mut account_curve_tree = Self::get_account_curve_tree()?;

            // Verify the proof.
            let mut rng = Self::get_rng();
            proof
                .verify(&account_curve_tree, &mut rng)
                .map_err(|_| Error::<T>::InvalidProof)?;

            // Store the updated asset details.
            DartAssetDetails::<T>::insert(proof.asset_id, &asset_details);

            // Insert the update account state commitment into the account curve tree.
            let account_commitment = proof.account_state_commitment();
            Self::insert_account_leaf(&mut account_curve_tree, account_commitment)?;

            // Burn the nullifier to ensure it cannot be used again.
            AccountStateCommitmentNullifiers::<T>::insert(nullifier, ());

            // Emit an event for the asset minting.
            Self::deposit_event(Event::<T>::AssetMinted {
                caller_did,
                asset_id: proof.asset_id,
                amount,
                total_supply: asset_details.total_supply,
                account: proof.pk,
            });

            Ok(())
        }

        /// Create a new settlement.
        ///
        /// # Arguments
        /// * `origin` - The origin of the call.
        /// * `proof` - The settlement proof.
        ///
        /// # Errors
        /// * `BadOrigin` if `origin` isn't signed.
        /// * `InvalidProof` if the proof is invalid.
        /// * `SettlementMissingLegs` if the settlement has no legs.
        /// * `SettlementTooManyLegs` if the settlement has more legs than the maximum allowed.
        #[pallet::call_index(4)]
        #[pallet::weight(<T as Config>::WeightInfo::create_settlement(proof.legs.len() as u32))]
        pub fn create_settlement(
            origin: OriginFor<T>,
            proof: polymesh_dart::SettlementProof,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            let leg_count = proof.legs.len();
            // Ensure the settlement has at least one leg.
            ensure!(leg_count > 0, Error::<T>::SettlementMissingLegs);

            // Ensure the settlement doesn't have more than the maximum number of legs.
            ensure!(
                leg_count <= T::MaxSettlementLegs::get() as usize,
                Error::<T>::SettlementTooManyLegs
            );

            // Get the asset curve tree.
            let asset_curve_tree = Self::get_asset_curve_tree()?;

            // Verify the settlement proof.
            let mut rng = Self::get_rng();
            proof
                .verify(&asset_curve_tree, &mut rng)
                .map_err(|_| Error::<T>::InvalidProof)?;

            // Allocate a new settlement ID.
            let settlement_id = NextSettlementId::<T>::get();
            NextSettlementId::<T>::put(settlement_id + 1);

            // Set the settlement state to pending.
            SettlementState::<T>::insert(settlement_id, SettlementStatus::Pending);

            // Store the settlement legs.
            let mut legs = Vec::with_capacity(leg_count);
            for (leg_id, leg) in proof.legs.into_iter().enumerate() {
                let leg_id = leg_id as LegId;
                let leg_enc = leg.leg_enc().map_err(Error::<T>::from)?;
                legs.push(leg_enc.clone());

                // Mediator affirmation status if the leg has a mediator.
                let mediator = leg
                    .has_mediator()
                    .map_err(Error::<T>::from)?
                    .then_some(AffirmationStatus::Pending);

                SettlementLegs::<T>::insert(
                    (settlement_id, leg_id),
                    DartSettlementLeg {
                        enc: leg_enc.clone(),
                        sender: AffirmationStatus::Pending,
                        receiver: AffirmationStatus::Pending,
                        mediator,
                        status: AffirmationStatus::Pending,
                        _marker: core::marker::PhantomData,
                    },
                );
            }

            // Emit an event for the settlement creation.
            Self::deposit_event(Event::<T>::SettlementCreated {
                settlement_id,
                legs: legs
                    .try_into()
                    .map_err(|_| Error::<T>::SettlementTooManyLegs)?,
            });

            Ok(())
        }

        /// Sender affirms a settlement leg.
        ///
        /// # Arguments
        /// * `origin` - The origin of the call.
        /// * `proof` - The sender affirmation proof.
        ///
        /// # Errors
        /// * `BadOrigin` if `origin` isn't signed.
        /// * `SettlementNotPending` if the settlement is not pending.
        /// * `SettlementNotFound` if the settlement is not found.
        /// * `LegNotFound` if the leg is not found in the settlement.
        /// * `AlreadyAffirmed` if the leg has already been affirmed by the sender.
        #[pallet::call_index(5)]
        #[pallet::weight(<T as Config>::WeightInfo::sender_affirmation())]
        pub fn sender_affirmation(
            origin: OriginFor<T>,
            proof: polymesh_dart::SenderAffirmationProof,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            // Ensure the nullifier is unique.
            let nullifier = proof.nullifier();
            Self::ensure_account_state_nullifier_unique(&nullifier)?;

            // Get account curve tree.
            let mut account_curve_tree = Self::get_account_curve_tree()?;

            // Create an update settlement status instance.
            let mut update_settlement = UpdateSettlementStatus::<T>::new(proof.leg_ref)?;

            // Verify the sender affirmation proof and update the settlement and leg status.
            let mut rng = Self::get_rng();
            update_settlement.sender_affirmation(&proof, &account_curve_tree, &mut rng)?;

            // Insert the update account state commitment into the account curve tree.
            let account_commitment = proof.account_state_commitment();
            Self::insert_account_leaf(&mut account_curve_tree, account_commitment)?;

            // Burn the nullifier to ensure it cannot be used again.
            AccountStateCommitmentNullifiers::<T>::insert(nullifier, ());

            // Emit an event for the sender affirmation.
            Self::deposit_event(Event::<T>::SenderAffirmed {
                leg_ref: proof.leg_ref,
            });

            Ok(())
        }

        /// Receiver affirms a settlement leg.
        ///
        /// # Arguments
        /// * `origin` - The origin of the call.
        /// * `proof` - The receiver affirmation proof.
        ///
        /// # Errors
        /// * `BadOrigin` if `origin` isn't signed.
        /// * `SettlementNotPending` if the settlement is not pending.
        /// * `SettlementNotFound` if the settlement is not found.
        /// * `LegNotFound` if the leg is not found in the settlement.
        /// * `AlreadyAffirmed` if the leg has already been affirmed by the receiver.
        #[pallet::call_index(6)]
        #[pallet::weight(<T as Config>::WeightInfo::receiver_affirmation())]
        pub fn receiver_affirmation(
            origin: OriginFor<T>,
            proof: polymesh_dart::ReceiverAffirmationProof,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            // Ensure the nullifier is unique.
            let nullifier = proof.nullifier();
            Self::ensure_account_state_nullifier_unique(&nullifier)?;

            // Get account curve tree.
            let mut account_curve_tree = Self::get_account_curve_tree()?;

            // Create an update settlement status instance.
            let mut update_settlement = UpdateSettlementStatus::<T>::new(proof.leg_ref)?;

            // Verify the receiver affirmation proof and update the settlement and leg status.
            let mut rng = Self::get_rng();
            update_settlement.receiver_affirmation(&proof, &account_curve_tree, &mut rng)?;

            // Insert the update account state commitment into the account curve tree.
            let account_commitment = proof.account_state_commitment();
            Self::insert_account_leaf(&mut account_curve_tree, account_commitment)?;

            // Burn the nullifier to ensure it cannot be used again.
            AccountStateCommitmentNullifiers::<T>::insert(nullifier, ());

            // Emit an event for the receiver affirmation.
            Self::deposit_event(Event::<T>::ReceiverAffirmed {
                leg_ref: proof.leg_ref,
            });

            Ok(())
        }

        /// Mediator affirms a settlement leg.
        ///
        /// # Arguments
        /// * `origin` - The origin of the call.
        /// * `proof` - The mediator affirmation proof.
        ///
        /// # Errors
        /// * `BadOrigin` if `origin` isn't signed.
        /// * `SettlementNotPending` if the settlement is not pending.
        /// * `SettlementNotFound` if the settlement is not found.
        /// * `LegNotFound` if the leg is not found in the settlement.
        /// * `AlreadyAffirmed` if the leg has already been affirmed by the mediator.
        /// * `NoMediatorForThisLeg` if the leg does not have a mediator.
        #[pallet::call_index(7)]
        #[pallet::weight(<T as Config>::WeightInfo::mediator_affirmation())]
        pub fn mediator_affirmation(
            origin: OriginFor<T>,
            proof: polymesh_dart::MediatorAffirmationProof,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            // Create an update settlement status instance.
            let mut update_settlement = UpdateSettlementStatus::<T>::new(proof.leg_ref)?;

            // Verify the mediator affirmation proof and update the settlement and leg status.
            update_settlement.mediator_affirmation(&proof)?;

            // Emit an event for the mediator affirmation.
            Self::deposit_event(Event::<T>::MediatorAffirmed {
                leg_ref: proof.leg_ref,
            });

            Ok(())
        }

        /// Sender updates their counter after a settlement has been executed.
        ///
        /// # Arguments
        /// * `origin` - The origin of the call.
        /// * `proof` - The sender update proof.
        ///
        /// # Errors
        /// * `BadOrigin` if `origin` isn't signed.
        /// * `SettlementNotExecuted` if the settlement has not been executed.
        /// * `SettlementNotFound` if the settlement is not found.
        /// * `LegNotFound` if the leg is not found in the settlement.
        /// * `SenderHasNotAffirmed` if the sender has not affirmed the leg.
        #[pallet::call_index(8)]
        #[pallet::weight(<T as Config>::WeightInfo::sender_update_counter())]
        pub fn sender_update_counter(
            origin: OriginFor<T>,
            proof: polymesh_dart::SenderCounterUpdateProof,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            // Ensure the nullifier is unique.
            let nullifier = proof.nullifier();
            Self::ensure_account_state_nullifier_unique(&nullifier)?;

            // Get account curve tree.
            let mut account_curve_tree = Self::get_account_curve_tree()?;

            // Create an update settlement status instance.
            let mut update_settlement = UpdateSettlementStatus::<T>::new(proof.leg_ref)?;

            // Verify the sender update proof and update the settlement and leg status.
            let mut rng = Self::get_rng();
            update_settlement.sender_counter_update(&proof, &account_curve_tree, &mut rng)?;

            // Insert the update account state commitment into the account curve tree.
            let account_commitment = proof.account_state_commitment();
            Self::insert_account_leaf(&mut account_curve_tree, account_commitment)?;

            // Burn the nullifier to ensure it cannot be used again.
            AccountStateCommitmentNullifiers::<T>::insert(nullifier, ());

            // Emit an event for the sender update counter.
            Self::deposit_event(Event::<T>::SenderCounterUpdated {
                leg_ref: proof.leg_ref,
            });

            Ok(())
        }

        /// Sender reverts their affirmation after a settlement has been rejected.
        ///
        /// # Arguments
        /// * `origin` - The origin of the call.
        /// * `proof` - The sender revert proof.
        ///
        /// # Errors
        /// * `BadOrigin` if `origin` isn't signed.
        /// * `SettlementNotRejected` if the settlement has not been rejected.
        /// * `SettlementNotFound` if the settlement is not found.
        /// * `LegNotFound` if the leg is not found in the settlement.
        /// * `SenderHasNotAffirmed` if the sender has not affirmed the leg.
        #[pallet::call_index(9)]
        #[pallet::weight(<T as Config>::WeightInfo::sender_revert())]
        pub fn sender_revert(
            origin: OriginFor<T>,
            proof: polymesh_dart::SenderReversalProof,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            // Ensure the nullifier is unique.
            let nullifier = proof.nullifier();
            Self::ensure_account_state_nullifier_unique(&nullifier)?;

            // Get account curve tree.
            let mut account_curve_tree = Self::get_account_curve_tree()?;

            // Create an update settlement status instance.
            let mut update_settlement = UpdateSettlementStatus::<T>::new(proof.leg_ref)?;

            // Verify the sender reversal proof and update the settlement and leg status.
            let mut rng = Self::get_rng();
            update_settlement.sender_reversal(&proof, &account_curve_tree, &mut rng)?;

            // Insert the update account state commitment into the account curve tree.
            let account_commitment = proof.account_state_commitment();
            Self::insert_account_leaf(&mut account_curve_tree, account_commitment)?;

            // Burn the nullifier to ensure it cannot be used again.
            AccountStateCommitmentNullifiers::<T>::insert(nullifier, ());

            // Emit an event for the sender revert.
            Self::deposit_event(Event::<T>::SenderReverted {
                leg_ref: proof.leg_ref,
            });

            Ok(())
        }

        /// Receiver claims their assets after a settlement has been executed.
        ///
        /// # Arguments
        /// * `origin` - The origin of the call.
        /// * `proof` - The receiver claim proof.
        ///
        /// # Errors
        /// * `BadOrigin` if `origin` isn't signed.
        /// * `SettlementNotExecuted` if the settlement has not been executed.
        /// * `SettlementNotFound` if the settlement is not found.
        /// * `LegNotFound` if the leg is not found in the settlement.
        /// * `ReceiverHasNotAffirmed` if the receiver has not affirmed the leg.
        #[pallet::call_index(10)]
        #[pallet::weight(<T as Config>::WeightInfo::receiver_claim())]
        pub fn receiver_claim(
            origin: OriginFor<T>,
            proof: polymesh_dart::ReceiverClaimProof,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            // Ensure the nullifier is unique.
            let nullifier = proof.nullifier();
            Self::ensure_account_state_nullifier_unique(&nullifier)?;

            // Get account curve tree.
            let mut account_curve_tree = Self::get_account_curve_tree()?;

            // Create an update settlement status instance.
            let mut update_settlement = UpdateSettlementStatus::<T>::new(proof.leg_ref)?;

            // Verify the receiver claim proof and update the settlement and leg status.
            let mut rng = Self::get_rng();
            update_settlement.receiver_claim(&proof, &account_curve_tree, &mut rng)?;

            // Insert the update account state commitment into the account curve tree.
            let account_commitment = proof.account_state_commitment();
            Self::insert_account_leaf(&mut account_curve_tree, account_commitment)?;

            // Burn the nullifier to ensure it cannot be used again.
            AccountStateCommitmentNullifiers::<T>::insert(nullifier, ());

            // Emit an event for the receiver claim.
            Self::deposit_event(Event::<T>::ReceiverClaimed {
                leg_ref: proof.leg_ref,
            });

            Ok(())
        }
    }
}

impl<T: Config> Pallet<T> {
    /// Create a new DART asset.
    pub fn base_create_asset(
        owner_did: IdentityId,
        auditor_or_mediator: AuditorOrMediator,
        data: BoundedVec<u8, T::MaxAssetDataLength>,
    ) -> Result<DartAssetId, DispatchError> {
        // Ensure the auditor or mediator is registered.
        Self::ensure_auditor_or_mediator_registered(&auditor_or_mediator)?;

        // Allocate a new asset ID.
        let asset_id = NextAssetId::<T>::get();
        // Increment the next asset ID for the next call.
        NextAssetId::<T>::put(asset_id + 1);

        // Create the asset details.
        let asset_detail = DartAssetDetail {
            total_supply: 0,
            asset_id,
            owner_did,
            data: data.clone(),
            auditor_or_mediator,
        };
        // Store the asset details.
        DartAssetDetails::<T>::insert(asset_id, asset_detail);

        // Insert the asset state into the asset curve tree.
        Self::update_asset_leaf(owner_did, asset_id, &auditor_or_mediator, true)?;

        // Emit the event for asset creation.
        Self::deposit_event(Event::<T>::AssetCreated {
            caller_did: owner_did,
            asset_id,
            auditor_or_mediator,
            data,
        });

        Ok(asset_id)
    }

    /// Get the asset curve tree interface.
    pub fn get_asset_curve_tree() -> Result<AssetCurveTree<T>, Error<T>> {
        Ok(AssetCurveTree::<T>::new(
            ASSET_TREE_HEIGHT,
            ASSET_TREE_GENS,
        )?)
    }

    /// Get the account curve tree interface.
    pub fn get_account_curve_tree() -> Result<AccountCurveTree<T>, Error<T>> {
        Ok(AccountCurveTree::<T>::new(
            ACCOUNT_TREE_HEIGHT,
            ASSET_TREE_GENS,
        )?)
    }

    /// Update the asset leaf in the asset curve tree.
    fn update_asset_leaf(
        caller_did: IdentityId,
        asset_id: DartAssetId,
        auditor_or_mediator: &AuditorOrMediator,
        is_new: bool,
    ) -> DispatchResult {
        // Ensure the auditor or mediator is registered.
        Self::ensure_auditor_or_mediator_registered(auditor_or_mediator)?;

        // Create the Asset State.
        let (is_mediator, pk) = match auditor_or_mediator {
            AuditorOrMediator::Auditor(pk) => (false, pk.clone()),
            AuditorOrMediator::Mediator(pk) => {
                // HACK: Shouldn't we be using the mediator's encryption key here?
                (true, pk.acct.into())
                //(true, pk.enc.clone())
            }
        };
        let asset_state = AssetState::new(asset_id, is_mediator, pk);
        let asset_leaf = asset_state
            .commitment()
            .and_then(|c| c.as_leaf_value())
            .map_err(Error::<T>::from)?;

        // Update the asset curve tree with the new asset.
        let mut asset_curve_tree = Self::get_asset_curve_tree()?;
        let leaf_index = asset_id.into();
        if is_new {
            asset_curve_tree.insert_leaf(asset_leaf)?;
        } else {
            asset_curve_tree.update_leaf(leaf_index, asset_leaf)?;
        }

        // Set the updated flag for the asset curve tree.
        UpdatedAssetCurveTree::<T>::put(true);

        // Emit an event for the asset state update.
        Self::deposit_event(Event::<T>::AssetUpdated {
            caller_did,
            asset_id,
            auditor_or_mediator: auditor_or_mediator.clone(),
        });
        Self::deposit_event(Event::<T>::AssetStateLeafUpdated {
            leaf_index,
            asset_leaf,
        });

        Ok(())
    }

    /// Insert a new account state commitment into the account curve tree.
    fn insert_account_leaf(
        account_curve_tree: &mut AccountCurveTree<T>,
        account_commitment: AccountStateCommitment,
    ) -> Result<(), Error<T>> {
        // Create the account leaf.
        let account_leaf = account_commitment.as_leaf_value()?;

        // Insert the new account leaf.
        let leaf_index = account_curve_tree.insert_leaf(account_leaf)?;

        // Set the updated flag for the account curve tree.
        UpdatedAccountCurveTree::<T>::put(true);

        // Emit an event for the account curve tree update.
        Self::deposit_event(Event::<T>::AccountStateLeafInserted {
            leaf_index,
            account_leaf,
        });

        Ok(())
    }

    /// Ensure account state nullifier is unique.
    pub fn ensure_account_state_nullifier_unique(
        nullifier: &AccountStateNullifier,
    ) -> Result<(), Error<T>> {
        // Ensure the nullifier is not already used.
        ensure!(
            !AccountStateCommitmentNullifiers::<T>::contains_key(nullifier),
            Error::<T>::NullifierAlreadyUsed
        );
        Ok(())
    }

    /// Ensure DART account is registered.
    pub fn ensure_dart_account_registered(
        account: &AccountPublicKey,
    ) -> Result<IdentityId, Error<T>> {
        AccountDid::<T>::get(account).ok_or(Error::<T>::AccountMissing)
    }

    /// Ensure the caller's identity is the owner of the DART account.
    pub fn ensure_dart_account_owner(
        caller_did: IdentityId,
        account: &AccountPublicKey,
    ) -> Result<(), DispatchError> {
        let owner_did = Self::ensure_dart_account_registered(account)?;
        ensure!(owner_did == caller_did, Error::<T>::NotAccountOwner);
        Ok(())
    }

    /// Ensure the caller's identity is the owner of the DART asset.
    pub fn ensure_dart_asset_owner(
        caller_did: IdentityId,
        asset_id: DartAssetId,
    ) -> Result<DartAssetDetail<T>, DispatchError> {
        // Ensure the DART asset exists.
        let asset_detail = Self::ensure_dart_asset_exists(asset_id)?;
        // Ensure the caller's identity is the owner of the DART asset.
        ensure!(
            asset_detail.owner_did == caller_did,
            Error::<T>::NotAssetOwner
        );
        Ok(asset_detail)
    }

    /// Ensure the caller has the required permissions to access the DART account.
    pub fn ensure_dart_account_permissions(
        origin: OriginFor<T>,
        account: &AccountPublicKey,
    ) -> Result<IdentityId, DispatchError> {
        // Ensure the caller is allowed to make this call.
        let caller_did = PalletIdentity::<T>::ensure_perms(origin)?;
        // Ensure the DART account is registered to the caller's identity.
        Self::ensure_dart_account_owner(caller_did, account)?;
        // Return the caller's identity.
        Ok(caller_did)
    }

    /// Ensure that the DART asset exists.
    pub fn ensure_dart_asset_exists(asset_id: DartAssetId) -> Result<DartAssetDetail<T>, Error<T>> {
        DartAssetDetails::<T>::get(asset_id).ok_or(Error::<T>::AssetMissing)
    }

    /// Ensure DART account encryption key is registered.
    pub fn ensure_dart_account_encryption_key_registered(
        encryption_key: &EncryptionPublicKey,
    ) -> Result<AccountPublicKey, Error<T>> {
        EncryptionKeyAccount::<T>::get(encryption_key).ok_or(Error::<T>::EncryptionKeyMissing)
    }

    /// Ensure auditor or mediator is registered.
    pub fn ensure_auditor_or_mediator_registered(
        auditor_or_mediator: &AuditorOrMediator,
    ) -> Result<(), Error<T>> {
        match auditor_or_mediator {
            AuditorOrMediator::Auditor(account) => {
                Self::ensure_dart_account_encryption_key_registered(account)?;
            }
            AuditorOrMediator::Mediator(account) => {
                Self::ensure_dart_account_encryption_key_registered(&account.enc)?;
                Self::ensure_dart_account_registered(&account.acct)?;
            }
        }
        Ok(())
    }

    fn get_seed(update: bool) -> [u8; 32] {
        // Increase the nonce each time.
        let nonce = RngNonce::<T>::get();
        if update {
            RngNonce::<T>::put(nonce.wrapping_add(1));
        }
        // Use the `nonce` and chain randomness to generate a new seed.
        let (random_hash, _) = T::Randomness::random(&(b"ConfidentialAsset", nonce).encode());
        let s = random_hash.as_ref();
        let mut seed = [0u8; 32];
        let len = seed.len().min(s.len());
        seed[..len].copy_from_slice(&s[..len]);
        seed
    }

    fn get_rng() -> rand_chacha::ChaCha20Rng {
        use rand_core::SeedableRng;
        // Get the random number generator.
        rand_chacha::ChaCha20Rng::from_seed(Self::get_seed(true))
    }
}
