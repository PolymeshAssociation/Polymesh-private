use codec::{Decode, Encode};
use frame_support::{
    dispatch::{DispatchError, DispatchResult},
    ensure,
    traits::Get,
    BoundedBTreeMap,
};
use polymesh_dart_host_functions::VerifyMediatorRequest;
use scale_info::TypeInfo;
use sp_std::vec::Vec;

use polymesh_dart::{
    LegEncrypted, LegId, LegRef, MediatorAffirmationProof, MediatorId, ReceiverAffirmationProof,
    ReceiverClaimProof, SenderAffirmationProof, SenderCounterUpdateProof, SenderReversalProof,
    SettlementRef,
};

use super::*;

/// The affirmation status for each party in a DART settlement leg.
#[derive(Copy, Clone, Encode, Decode, Debug, TypeInfo, PartialEq, Eq)]
pub enum AffirmationStatus {
    /// The leg is pending affirmation.
    Pending,
    /// The leg has been affirmed by the sender, receiver, and mediator.
    Affirmed,
    /// The leg has been rejected by one party.
    Rejected,
    /// The leg has been finalized by all parties.
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
    pub mediators: BoundedBTreeMap<MediatorId, AffirmationStatus, T::MaxAssetMediators>,
    /// The leg status, which is derived from the sender, receiver, and mediator statuses.
    pub status: AffirmationStatus,
    _marker: core::marker::PhantomData<T>,
}

impl<T: Config> DartSettlementLeg<T> {
    /// Create a new `DartSettlementLeg` instance.
    pub fn new(enc: LegEncrypted, mediator_ids: Vec<MediatorId>) -> Result<Self, DispatchError> {
        let mut mediators = BoundedBTreeMap::new();
        for id in mediator_ids {
            mediators
                .try_insert(id, AffirmationStatus::Pending)
                .map_err(|_| Error::<T>::TooManyMediators)?;
        }
        Ok(Self {
            enc,
            sender: AffirmationStatus::Pending,
            receiver: AffirmationStatus::Pending,
            mediators,
            status: AffirmationStatus::Pending,
            _marker: core::marker::PhantomData,
        })
    }

    /// Try to update the status of the leg based on the current sender, receiver, and mediator statuses.
    fn check_for_updated_status(&mut self) -> Result<(), DispatchError> {
        // Merge the sender and receiver statuses.
        let mut affirmation = self.sender.merge::<T>(self.receiver)?;
        // If there is a mediator, merge the mediator status as well.
        for (_, mediator) in &self.mediators {
            affirmation = affirmation.merge::<T>(*mediator)?;
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

        // If the sender is still pending, then mark their status as finalized.
        if self.sender == AffirmationStatus::Pending {
            self.sender = AffirmationStatus::Finalized;
        }
        // If the receiver is still pending, then mark their status as finalized.
        if self.receiver == AffirmationStatus::Pending {
            self.receiver = AffirmationStatus::Finalized;
        }

        // Mark the mediators as finalized.  Since they cannot affirm or reject anymore.
        self.finalize_mediators();

        Ok(())
    }

    /// When the settlement is rejected or affirmed (all legs are affirmed), then we can finalize the mediators.
    pub fn finalize_mediators(&mut self) {
        // Mark the mediator as finalized, since they cannot affirm or reject anymore.
        for (_, mediator) in &mut self.mediators {
            *mediator = AffirmationStatus::Finalized;
        }
    }

    /// Verify a sender affirmation proof for this leg.
    pub fn sender_affirmation(
        &mut self,
        proof: SenderAffirmationProof<AccountTreeConfig>,
        root: AccountTreeRoot,
        seed: BatchSeed,
    ) -> DispatchResult {
        // The sender can only affirm if the sender affirmation status is `Pending`.
        ensure!(
            self.sender == AffirmationStatus::Pending,
            Error::<T>::AlreadyAffirmed
        );

        // verify the proof.
        let req = VerifyDartAssetRequest::SenderAffirmation {
            leg_enc: self.enc.clone(),
            root,
            proof,
        };
        req.verify(seed).map_err(|_| Error::<T>::InvalidProof)?;

        // Update the leg's status.
        self.sender = AffirmationStatus::Affirmed;

        // Update the leg status.  If the other parties have already affirmed, this will update the leg's status to `Affirmed`.
        self.check_for_updated_status()?;

        Ok(())
    }

    /// Verify a receiver affirmation proof for this leg.
    pub fn receiver_affirmation(
        &mut self,
        proof: ReceiverAffirmationProof<AccountTreeConfig>,
        root: AccountTreeRoot,
        seed: BatchSeed,
    ) -> DispatchResult {
        // The receiver can only affirm if the receiver affirmation status is `Pending`.
        ensure!(
            self.receiver == AffirmationStatus::Pending,
            Error::<T>::AlreadyAffirmed
        );

        // verify the proof.
        let req = VerifyDartAssetRequest::ReceiverAffirmation {
            leg_enc: self.enc.clone(),
            root,
            proof: proof.clone(),
        };
        req.verify(seed).map_err(|_| Error::<T>::InvalidProof)?;

        // Update the leg's status.
        self.receiver = AffirmationStatus::Affirmed;

        // Update the leg status.  If the other parties have already affirmed, this will update the leg's status to `Affirmed`.
        self.check_for_updated_status()?;

        Ok(())
    }

    /// Verify a mediator affirmation proof for this leg.
    pub fn mediator_affirmation(&mut self, proof: MediatorAffirmationProof) -> DispatchResult {
        // A mediator can only affirm if the leg has a mediator.
        ensure!(
            !self.mediators.is_empty(),
            Error::<T>::NoMediatorsForThisLeg,
        );
        // The mediator can only affirm if the mediator affirmation status is `Pending`.
        let mediator_id = proof.key_index;
        let mediator = self
            .mediators
            .get_mut(&mediator_id)
            .ok_or(Error::<T>::WrongMediatorId)?;
        ensure!(
            *mediator == AffirmationStatus::Pending,
            Error::<T>::AlreadyAffirmed
        );

        // verify the proof.
        let accept = proof.accept;
        let req = VerifyMediatorRequest {
            leg_enc: self.enc.clone(),
            proof,
        };
        req.verify().map_err(|_| Error::<T>::InvalidProof)?;

        // Update the leg's mediator status based on the proof.
        if accept {
            // The mediator is affirming the leg.
            *mediator = AffirmationStatus::Affirmed;
        } else {
            // The mediator is rejecting the leg.
            *mediator = AffirmationStatus::Rejected;
        }

        // Update the leg status.  If the other parties have already affirmed, this will update the leg's status to `Affirmed`.
        self.check_for_updated_status()?;

        Ok(())
    }

    /// Verify the sender's counter update proof for this leg.
    ///
    /// The sender is only allowed to submit this proof if the settlement has been executed.
    pub fn sender_counter_update(
        &mut self,
        proof: SenderCounterUpdateProof<AccountTreeConfig>,
        root: AccountTreeRoot,
        seed: BatchSeed,
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
        let req = VerifyDartAssetRequest::SenderCounterUpdate {
            leg_enc: self.enc.clone(),
            root,
            proof: proof.clone(),
        };
        req.verify(seed).map_err(|_| Error::<T>::InvalidProof)?;

        // Update the leg's status.
        self.sender = AffirmationStatus::Finalized;

        // Update the leg status.  If the other parties have finalized, this will update the leg's status to `Finalized`.
        self.check_for_updated_status()?;

        Ok(())
    }

    /// Verify the sender's Reversal proof for this leg.
    ///
    /// The sender is only allowed to submit this proof if the settlement has been rejected.
    pub fn sender_reversal(
        &mut self,
        proof: SenderReversalProof<AccountTreeConfig>,
        root: AccountTreeRoot,
        seed: BatchSeed,
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
        let req = VerifyDartAssetRequest::SenderReversal {
            leg_enc: self.enc.clone(),
            root,
            proof: proof.clone(),
        };
        req.verify(seed).map_err(|_| Error::<T>::InvalidProof)?;

        // Update the leg's status.
        self.sender = AffirmationStatus::Finalized;

        // Update the leg status.  If the other parties have finalized, this will update the leg's status to `Finalized`.
        self.check_for_updated_status()?;

        Ok(())
    }

    /// Verify the receiver's claim proof for this leg.
    ///
    /// The receiver is only allowed to submit this proof if the settlement has been executed.
    pub fn receiver_claim(
        &mut self,
        proof: ReceiverClaimProof<AccountTreeConfig>,
        root: AccountTreeRoot,
        seed: BatchSeed,
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
        let req = VerifyDartAssetRequest::ReceiverClaim {
            leg_enc: self.enc.clone(),
            root,
            proof: proof.clone(),
        };
        req.verify(seed).map_err(|_| Error::<T>::InvalidProof)?;

        // Update the leg's status.
        self.receiver = AffirmationStatus::Finalized;

        // Update the leg status.  If the other parties have finalized, this will update the leg's status to `Finalized`.
        self.check_for_updated_status()?;

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
    /// The settlement reference.
    pub settlement_ref: SettlementRef,
    /// The status of the settlement.
    pub status: SettlementStatus,
    _marker: core::marker::PhantomData<T>,
}

impl<T: Config> UpdateSettlementStatus<T> {
    /// Create a new `UpdateSettlementStatus` instance.
    pub fn new(leg_ref: LegRef) -> Result<Self, DispatchError> {
        // Get the settlement reference from the leg reference.
        let settlement_ref = leg_ref.settlement;
        // Get the status of the settlement.
        let status =
            SettlementState::<T>::get(settlement_ref).ok_or(Error::<T>::SettlementNotFound)?;

        Ok(Self {
            settlement_ref,
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
        Ok(SettlementLegs::<T>::get((self.settlement_ref, leg_id))
            .ok_or(Error::<T>::LegNotFound)?)
    }

    /// Update a specific leg in the settlement.
    fn update_leg(&mut self, leg_id: LegId, leg: DartSettlementLeg<T>) -> DispatchResult {
        SettlementLegs::<T>::insert((self.settlement_ref, leg_id), leg);
        Ok(())
    }

    /// Verify a sender affirmation proof for a specific leg in the settlement.
    pub fn sender_affirmation(
        &mut self,
        proof: SenderAffirmationProof<AccountTreeConfig>,
        root: AccountTreeRoot,
        seed: BatchSeed,
    ) -> DispatchResult {
        self.ensure_pending()?;

        let leg_id = proof.leg_ref.leg_id();
        let mut leg = self.get_leg(leg_id)?;

        leg.sender_affirmation(proof, root, seed)?;

        // Update the leg in the settlement.
        self.update_leg(leg_id, leg)?;

        // If the sender has affirmed, update the status of the settlement.
        self.check_for_updated_status()?;

        Ok(())
    }

    /// Verify a receiver affirmation proof for a specific leg in the settlement.
    pub fn receiver_affirmation(
        &mut self,
        proof: ReceiverAffirmationProof<AccountTreeConfig>,
        root: AccountTreeRoot,
        seed: BatchSeed,
    ) -> DispatchResult {
        self.ensure_pending()?;

        let leg_id = proof.leg_ref.leg_id();
        let mut leg = self.get_leg(leg_id)?;

        leg.receiver_affirmation(proof, root, seed)?;

        // Update the leg in the settlement.
        self.update_leg(leg_id, leg)?;

        // If the receiver has affirmed, update the status of the settlement.
        self.check_for_updated_status()?;
        Ok(())
    }

    /// Verify a mediator affirmation proof for a specific leg in the settlement.
    pub fn mediator_affirmation(&mut self, proof: MediatorAffirmationProof) -> DispatchResult {
        self.ensure_pending()?;

        let leg_id = proof.leg_ref.leg_id();
        let accept = proof.accept;
        let mut leg = self.get_leg(leg_id)?;

        leg.mediator_affirmation(proof)?;

        // Update the leg in the settlement.
        self.update_leg(leg_id, leg)?;

        if accept {
            // If the mediator has accepted, update the status of the settlement.
            self.check_for_updated_status()?;
        } else {
            // If the mediator has rejected, set the settlement status to rejected.
            self.reject_all_legs()?;
        }
        Ok(())
    }

    /// Verify the sender's counter update proof for a specific leg in the settlement.
    pub fn sender_counter_update(
        &mut self,
        proof: SenderCounterUpdateProof<AccountTreeConfig>,
        root: AccountTreeRoot,
        seed: BatchSeed,
    ) -> DispatchResult {
        // The sender can only update the counter if the settlement has been executed.
        ensure!(
            self.status == SettlementStatus::Executed,
            Error::<T>::SettlementNotExecuted
        );

        let leg_id = proof.leg_ref.leg_id();
        let mut leg = self.get_leg(leg_id)?;

        leg.sender_counter_update(proof, root, seed)?;

        // Update the leg in the settlement.
        self.update_leg(leg_id, leg)?;

        // If the sender has finalized the leg, update the status of the settlement.
        self.check_for_updated_status()?;
        Ok(())
    }

    /// Verify the sender's reversal proof for a specific leg in the settlement.
    pub fn sender_reversal(
        &mut self,
        proof: SenderReversalProof<AccountTreeConfig>,
        root: AccountTreeRoot,
        seed: BatchSeed,
    ) -> DispatchResult {
        // The sender can only reverse if the settlement has been rejected.
        ensure!(
            self.status == SettlementStatus::Rejected,
            Error::<T>::SettlementNotRejected
        );

        let leg_id = proof.leg_ref.leg_id();
        let mut leg = self.get_leg(leg_id)?;

        leg.sender_reversal(proof, root, seed)?;

        // Update the leg in the settlement.
        self.update_leg(leg_id, leg)?;

        // If the sender has finalized the leg, update the status of the settlement.
        self.check_for_updated_status()?;
        Ok(())
    }

    /// Verify the receiver's claim proof for a specific leg in the settlement.
    pub fn receiver_claim(
        &mut self,
        proof: ReceiverClaimProof<AccountTreeConfig>,
        root: AccountTreeRoot,
        seed: BatchSeed,
    ) -> DispatchResult {
        // The receiver can only claim if the settlement has been executed.
        ensure!(
            self.status == SettlementStatus::Executed,
            Error::<T>::SettlementNotExecuted
        );

        let leg_id = proof.leg_ref.leg_id();
        let mut leg = self.get_leg(leg_id)?;

        leg.receiver_claim(proof, root, seed)?;

        // Update the leg in the settlement.
        self.update_leg(leg_id, leg)?;

        // If the receiver has finalized the leg, update the status of the settlement.
        self.check_for_updated_status()?;
        Ok(())
    }

    fn check_for_updated_status(&mut self) -> DispatchResult {
        match self.status {
            SettlementStatus::Pending => {
                // If the settlement is pending, check if all legs are affirmed.
                for id in 0..T::MaxSettlementLegs::get() {
                    if let Ok(leg) = self.get_leg(id as LegId) {
                        if leg.status != AffirmationStatus::Affirmed {
                            return Ok(()); // Still pending
                        }
                    } else {
                        // No more legs to check
                        break;
                    }
                }
                // If all legs are affirmed, update the settlement status to executed.
                self.execute()
            }
            SettlementStatus::Executed | SettlementStatus::Rejected => {
                // If the settlement is in the executed or rejected state,
                // check if all legs are finalized.
                for id in 0..T::MaxSettlementLegs::get() {
                    if let Ok(leg) = self.get_leg(id as LegId) {
                        if leg.status != AffirmationStatus::Finalized {
                            return Ok(()); // Still not finalized
                        }
                    } else {
                        // No more legs to check
                        break;
                    }
                }
                // If all legs are finalized, update the settlement status to finalized.
                self.finalize()
            }
            SettlementStatus::Finalized => {
                // If the settlement is already finalized, do nothing.
                Ok(())
            }
        }
    }

    fn set_status(&self, status: SettlementStatus) {
        // Set the settlement status in the storage.
        SettlementState::<T>::insert(self.settlement_ref, status);

        // Emit an event for the settlement status update.
        Pallet::<T>::deposit_event(Event::<T>::SettlementStatusUpdated {
            settlement_ref: self.settlement_ref,
            status,
        });
    }

    fn reject_all_legs(&mut self) -> DispatchResult {
        // Reject all legs in the settlement.
        for id in 0..T::MaxSettlementLegs::get() {
            if let Ok(mut leg) = self.get_leg(id as LegId) {
                leg.reject()?;
                self.update_leg(id as LegId, leg)?;
            } else {
                // No more legs to reject
                break;
            }
        }
        self.set_status(SettlementStatus::Rejected);
        Ok(())
    }

    /// Execute the settlement, marking it as executed.
    fn execute(&mut self) -> DispatchResult {
        // Ensure the settlement is in a pending state before executing.
        ensure!(
            self.status == SettlementStatus::Pending,
            Error::<T>::SettlementNotPending
        );

        // Finalize the mediators in all legs.  Mediators cannot affirm or reject anymore.
        for id in 0..T::MaxSettlementLegs::get() {
            if let Ok(mut leg) = self.get_leg(id as LegId) {
                leg.finalize_mediators();
            } else {
                // No more legs to execute
                break;
            }
        }

        // Set the settlement status to executed.
        self.set_status(SettlementStatus::Executed);

        Ok(())
    }

    /// Finalize the settlement, marking it as finalized.
    fn finalize(&mut self) -> DispatchResult {
        // TODO: Prune all settlement state.

        // Set the settlement status to finalized.
        self.set_status(SettlementStatus::Finalized);

        Ok(())
    }
}
