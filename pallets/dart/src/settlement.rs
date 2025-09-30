use codec::{Decode, Encode};
use frame_support::{
    dispatch::{DispatchError, DispatchResult},
    ensure,
};
use scale_info::TypeInfo;

use polymesh_dart::{
    LegEncrypted, LegId, LegRef, MediatorAffirmationProof, MediatorId, ReceiverAffirmationProof,
    ReceiverClaimProof, SenderAffirmationProof, SenderCounterUpdateProof, SenderReversalProof,
    SettlementRef,
};

use super::*;

/// Leg affirmation party.
#[derive(Copy, Clone, Encode, Decode, Debug, TypeInfo, PartialEq, Eq)]
pub enum LegAffirmParty {
    Sender,
    Receiver,
    Mediator(MediatorId),
}

impl LegAffirmParty {
    pub fn is_mediator(&self) -> bool {
        matches!(self, LegAffirmParty::Mediator(_))
    }
}

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
    /// The leg id.
    pub leg_id: LegId,
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
            leg_id: leg_ref.leg_id(),
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

    /// Get the encrypted leg data.
    fn get_leg(&self) -> Result<LegEncrypted, DispatchError> {
        // Ensure the leg ID is valid.
        let leg_enc = SettlementLegs::<T>::get((self.settlement_ref, self.leg_id))
            .ok_or(Error::<T>::LegNotFound)?;
        Ok(leg_enc)
    }

    fn set_party_status(
        &self,
        party: LegAffirmParty,
        old_status: AffirmationStatus,
        new_status: AffirmationStatus,
    ) -> Result<u32, DispatchError> {
        // Try to set the party's affirmation status.
        LegAffirmationStatus::<T>::try_mutate(
            (self.settlement_ref, self.leg_id, party),
            |status| -> Result<(), DispatchError> {
                if let Some(status) = status.as_mut() {
                    // Ensure the party's current status matches the expected old status.
                    ensure!(*status == old_status, Error::<T>::AlreadyAffirmed);
                    // Update the party's affirmation status to the new status.
                    *status = new_status;
                    Ok(())
                } else if party.is_mediator() {
                    Err(Error::<T>::WrongMediatorId.into())
                } else {
                    Err(Error::<T>::LegNotFound.into())
                }
            },
        )?;

        let pending_final = match (party, new_status) {
            (LegAffirmParty::Sender | LegAffirmParty::Receiver, AffirmationStatus::Affirmed) => {
                // If the party is not a mediator and they accepted, increase the number of pending finalizations for the settlement.
                SettlementPendingFinalizations::<T>::mutate(self.settlement_ref, |count| {
                    *count += 1;
                    *count
                })
            }
            (LegAffirmParty::Sender | LegAffirmParty::Receiver, AffirmationStatus::Finalized) => {
                // If the party is not a mediator and they finalized, decrease the number of pending finalizations for the settlement.
                SettlementPendingFinalizations::<T>::mutate(self.settlement_ref, |count| {
                    *count -= 1;
                    *count
                })
            }
            // Not used for other cases.
            _ => 0,
        };

        Ok(pending_final)
    }

    fn party_affirms(&self, party: LegAffirmParty, accept: bool) -> Result<u32, DispatchError> {
        let new_status = if accept {
            AffirmationStatus::Affirmed
        } else {
            AffirmationStatus::Rejected
        };
        // Try to set the party's affirmation status.
        self.set_party_status(party, AffirmationStatus::Pending, new_status)?;

        // Try to decrease the number of pending affirmations for the settlement.
        let pending_count = SettlementPendingAffirmations::<T>::try_mutate(
            self.settlement_ref,
            |count| -> Result<u32, DispatchError> {
                *count = count
                    .checked_sub(1)
                    .ok_or(Error::<T>::NoPendingAffirmations)?;
                Ok(*count)
            },
        )?;

        Ok(pending_count)
    }

    fn party_finalizes(&self, party: LegAffirmParty) -> Result<u32, DispatchError> {
        // Try to set the party's affirmation status to finalized.
        self.set_party_status(
            party,
            AffirmationStatus::Affirmed,
            AffirmationStatus::Finalized,
        )
    }

    /// Verify a sender affirmation proof for a specific leg in the settlement.
    pub fn sender_affirmation(
        &self,
        proof: SenderAffirmationProof<AccountTreeConfig>,
        root: AccountTreeRoot,
    ) -> DispatchResult {
        self.ensure_pending()?;

        // The receiver is only allowed to submit this proof if the settlement has been executed and they have affirmed.
        let pending = self.party_affirms(LegAffirmParty::Sender, true)?;

        // verify the proof.
        let req = VerifyDartAssetRequest::SenderAffirmation {
            leg_enc: self.get_leg()?,
            root,
            proof: proof.clone(),
        };
        req.verify().map_err(|_| Error::<T>::InvalidProof)?;

        // If the sender has affirmed, update the status of the settlement.
        self.check_for_execution(pending)?;

        Ok(())
    }

    /// Verify a receiver affirmation proof for a specific leg in the settlement.
    pub fn receiver_affirmation(
        &self,
        proof: ReceiverAffirmationProof<AccountTreeConfig>,
        root: AccountTreeRoot,
    ) -> DispatchResult {
        self.ensure_pending()?;

        // Affirm as the receiver if they have not already affirmed.
        let pending = self.party_affirms(LegAffirmParty::Receiver, true)?;

        // verify the proof.
        let req = VerifyDartAssetRequest::ReceiverAffirmation {
            leg_enc: self.get_leg()?,
            root,
            proof: proof.clone(),
        };
        req.verify().map_err(|_| Error::<T>::InvalidProof)?;

        // If the receiver has affirmed, update the status of the settlement.
        self.check_for_execution(pending)?;
        Ok(())
    }

    /// Verify a mediator affirmation proof for a specific leg in the settlement.
    pub fn mediator_affirmation(&self, proof: MediatorAffirmationProof) -> DispatchResult {
        self.ensure_pending()?;

        let accept = proof.accept;
        let mediator_id = proof.key_index;
        // Affirm as the mediator if they have not already affirmed.
        let pending = self.party_affirms(LegAffirmParty::Mediator(mediator_id), accept)?;

        // verify the proof.
        let req = VerifyDartAssetRequest::MediatorAffirmation {
            leg_enc: self.get_leg()?,
            proof,
        };
        req.verify().map_err(|_| Error::<T>::InvalidProof)?;

        if accept {
            // If the mediator has accepted, update the status of the settlement.
            self.check_for_execution(pending)?;
        } else {
            // If the mediator has rejected, set the settlement status to rejected.
            self.set_status(SettlementStatus::Rejected);
        }
        Ok(())
    }

    /// Verify the sender's counter update proof for a specific leg in the settlement.
    pub fn sender_counter_update(
        &self,
        proof: SenderCounterUpdateProof<AccountTreeConfig>,
        root: AccountTreeRoot,
    ) -> DispatchResult {
        // The sender can only update the counter if the settlement has been executed.
        ensure!(
            self.status == SettlementStatus::Executed,
            Error::<T>::SettlementNotExecuted
        );

        // The sender is only allowed to submit this proof if the settlement has been executed and they have affirmed.
        let pending_final = self.party_finalizes(LegAffirmParty::Sender)?;

        // verify the proof.
        let req = VerifyDartAssetRequest::SenderCounterUpdate {
            leg_enc: self.get_leg()?,
            root,
            proof: proof.clone(),
        };
        req.verify().map_err(|_| Error::<T>::InvalidProof)?;

        // If the sender has finalized the leg, update the status of the settlement.
        self.check_for_finalization(pending_final)?;
        Ok(())
    }

    /// Verify the sender's reversal proof for a specific leg in the settlement.
    pub fn sender_reversal(
        &self,
        proof: SenderReversalProof<AccountTreeConfig>,
        root: AccountTreeRoot,
    ) -> DispatchResult {
        // The sender can only reverse if the settlement has been rejected.
        ensure!(
            self.status == SettlementStatus::Rejected,
            Error::<T>::SettlementNotRejected
        );

        // The sender is only allowed to submit this proof if the settlement has been rejected and they have affirmed.
        let pending_final = self.party_finalizes(LegAffirmParty::Sender)?;

        // verify the proof.
        let req = VerifyDartAssetRequest::SenderReversal {
            leg_enc: self.get_leg()?,
            root,
            proof: proof.clone(),
        };
        req.verify().map_err(|_| Error::<T>::InvalidProof)?;

        // If the sender has finalized the leg, update the status of the settlement.
        self.check_for_finalization(pending_final)?;
        Ok(())
    }

    /// Verify the receiver's claim proof for a specific leg in the settlement.
    pub fn receiver_claim(
        &self,
        proof: ReceiverClaimProof<AccountTreeConfig>,
        root: AccountTreeRoot,
    ) -> DispatchResult {
        // The receiver can only claim if the settlement has been executed.
        ensure!(
            self.status == SettlementStatus::Executed,
            Error::<T>::SettlementNotExecuted
        );

        // The receiver is only allowed to submit this proof if the settlement has been executed and they have affirmed.
        let pending_final = self.party_finalizes(LegAffirmParty::Receiver)?;

        // verify the proof.
        let req = VerifyDartAssetRequest::ReceiverClaim {
            leg_enc: self.get_leg()?,
            root,
            proof: proof.clone(),
        };
        req.verify().map_err(|_| Error::<T>::InvalidProof)?;

        // If the receiver has finalized the leg, update the status of the settlement.
        self.check_for_finalization(pending_final)?;
        Ok(())
    }

    fn check_for_execution(&self, pending_count: u32) -> DispatchResult {
        if self.status == SettlementStatus::Pending && pending_count == 0 {
            self.execute()?;
        }
        Ok(())
    }

    fn check_for_finalization(&self, pending_final: u32) -> DispatchResult {
        if self.status == SettlementStatus::Executed && pending_final == 0 {
            self.finalize()?;
        }
        Ok(())
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

    /// Execute the settlement, marking it as executed.
    fn execute(&self) -> DispatchResult {
        // Ensure the settlement is in a pending state before executing.
        ensure!(
            self.status == SettlementStatus::Pending,
            Error::<T>::SettlementNotPending
        );

        // Set the settlement status to executed.
        self.set_status(SettlementStatus::Executed);

        Ok(())
    }

    /// Finalize the settlement, marking it as finalized.
    fn finalize(&self) -> DispatchResult {
        // TODO: Prune all settlement state.

        // Set the settlement status to finalized.
        self.set_status(SettlementStatus::Finalized);

        Ok(())
    }
}
