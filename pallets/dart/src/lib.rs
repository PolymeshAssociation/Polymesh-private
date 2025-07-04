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
use sp_io::hashing::blake2_256;
use sp_std::convert::From;

use polymesh_dart::{
    curve_tree::{
        CurveTreeBackend, CurveTreeParameters, CurveTreeRoot, CurveTreeWithBackend, Inner,
        LeafValue, NodeLocation, ValidateCurveTreeRoot,
    },
    AccountPublicKey, AccountStateCommitment, AccountStateNullifier, AssetId as DartAssetId,
    AssetState, AuditorOrMediator, EncryptionPublicKey, Error as DartError, LeafIndex,
    LegEncrypted, LegId, MediatorAffirmationProof, NodeLevel, PallasParameters,
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

#[derive(Copy, Clone, Encode, Decode, Debug, TypeInfo, PartialEq, Eq)]
pub enum AffirmationStatus {
    Pending,
    Affirmed,
    Rejected,
    Finalized,
}

impl AffirmationStatus {
    pub fn apply<T: Config>(
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

#[derive(Clone, Encode, Decode, Debug, TypeInfo, PartialEq, Eq)]
pub struct DartSettlementLeg {
    pub enc: LegEncrypted,
    pub sender: AffirmationStatus,
    pub receiver: AffirmationStatus,
    pub mediator: Option<AffirmationStatus>,
    pub status: AffirmationStatus,
}

//*
impl DartSettlementLeg {
    /// Try to update the status of the leg based on the current sender, receiver, and mediator statuses.
    fn update_status<T: Config>(&mut self) -> Result<(), DispatchError> {
        let mut affirmation = self.sender.apply::<T>(self.receiver)?;
        if let Some(mediator) = self.mediator {
            affirmation = affirmation.apply::<T>(mediator)?;
        }
        self.status = affirmation;
        Ok(())
    }

    pub fn reject<T: Config>(&mut self) -> Result<(), DispatchError> {
        if self.status == AffirmationStatus::Finalized {
            Err(Error::<T>::CannotRejectFinalizedSettlement)?;
        }
        self.status = AffirmationStatus::Rejected;
        Ok(())
    }

    /// Verify a sender affirmation proof for this leg.
    pub fn sender_affirmation<T: Config, R: RngCore + CryptoRng>(
        &mut self,
        proof: &SenderAffirmationProof,
        tree_roots: impl ValidateCurveTreeRoot<ACCOUNT_TREE_L>,
        rng: &mut R,
    ) -> DispatchResult {
        if self.sender != AffirmationStatus::Pending {
            Err(Error::<T>::AlreadyAffirmed)?;
        }
        // verify the proof.
        proof
            .verify(&self.enc, tree_roots, rng)
            .map_err(|_| Error::<T>::InvalidProof)?;

        // Update the leg's status.
        self.sender = AffirmationStatus::Affirmed;
        self.update_status::<T>()?;

        Ok(())
    }

    /// Verify a receiver affirmation proof for this leg.
    pub fn receiver_affirmation<T: Config, R: RngCore + CryptoRng>(
        &mut self,
        proof: &ReceiverAffirmationProof,
        tree_roots: impl ValidateCurveTreeRoot<ACCOUNT_TREE_L>,
        rng: &mut R,
    ) -> DispatchResult {
        if self.receiver != AffirmationStatus::Pending {
            Err(Error::<T>::AlreadyAffirmed)?;
        }
        // verify the proof.
        proof
            .verify(&self.enc, tree_roots, rng)
            .map_err(|_| Error::<T>::InvalidProof)?;

        // Update the leg's status.
        self.receiver = AffirmationStatus::Affirmed;
        self.update_status::<T>()?;

        Ok(())
    }

    /// Verify a mediator affirmation proof for this leg.
    pub fn mediator_affirmation<T: Config>(
        &mut self,
        proof: &MediatorAffirmationProof,
    ) -> DispatchResult {
        if self.mediator.is_none() {
            Err(Error::<T>::NoMediatorForThisLeg)?;
        }
        if self.mediator != Some(AffirmationStatus::Pending) {
            Err(Error::<T>::AlreadyAffirmed)?;
        }
        // verify the proof.
        proof
            .verify(&self.enc)
            .map_err(|_| Error::<T>::InvalidProof)?;

        // Update the leg's mediator status based on the proof.
        if proof.accept {
            self.mediator = Some(AffirmationStatus::Affirmed);
        } else {
            self.mediator = Some(AffirmationStatus::Rejected);
        }
        self.update_status::<T>()?;
        Ok(())
    }

    /// Verify the sender's counter update proof for this leg.
    ///
    /// The sender is only allowed to submit this proof if the settlement has been executed.
    pub fn sender_counter_update<T: Config, R: RngCore + CryptoRng>(
        &mut self,
        proof: &SenderCounterUpdateProof,
        tree_roots: impl ValidateCurveTreeRoot<ACCOUNT_TREE_L>,
        rng: &mut R,
    ) -> DispatchResult {
        if self.sender != AffirmationStatus::Affirmed {
            Err(Error::<T>::SenderHasNotAffirmed)?;
        }
        if self.status != AffirmationStatus::Affirmed {
            Err(Error::<T>::LegNotAffirmed)?;
        }
        // verify the proof.
        proof
            .verify(&self.enc, tree_roots, rng)
            .map_err(|_| Error::<T>::InvalidProof)?;

        // Update the leg's status.
        self.sender = AffirmationStatus::Finalized;
        self.update_status::<T>()?;

        Ok(())
    }

    /// Verify the sender's Reversal proof for this leg.
    ///
    /// The sender is only allowed to submit this proof if the settlement has been rejected.
    pub fn sender_reversal<T: Config, R: RngCore + CryptoRng>(
        &mut self,
        proof: &SenderReversalProof,
        tree_roots: impl ValidateCurveTreeRoot<ACCOUNT_TREE_L>,
        rng: &mut R,
    ) -> DispatchResult {
        if self.sender != AffirmationStatus::Affirmed {
            Err(Error::<T>::SenderHasNotAffirmed)?;
        }
        if self.status != AffirmationStatus::Rejected {
            Err(Error::<T>::LegNotRejected)?;
        }
        // verify the proof.
        proof
            .verify(&self.enc, tree_roots, rng)
            .map_err(|_| Error::<T>::InvalidProof)?;

        // Update the leg's status.
        self.sender = AffirmationStatus::Finalized;
        self.update_status::<T>()?;

        Ok(())
    }

    /// Verify the receiver's claim proof for this leg.
    ///
    /// The receiver is only allowed to submit this proof if the settlement has been executed.
    pub fn receiver_claim<T: Config, R: RngCore + CryptoRng>(
        &mut self,
        proof: &ReceiverClaimProof,
        tree_roots: impl ValidateCurveTreeRoot<ACCOUNT_TREE_L>,
        rng: &mut R,
    ) -> DispatchResult {
        if self.receiver != AffirmationStatus::Affirmed {
            Err(Error::<T>::ReceiverHasNotAffirmed)?;
        }
        if self.status != AffirmationStatus::Affirmed {
            Err(Error::<T>::LegNotAffirmed)?;
        }
        // verify the proof.
        proof
            .verify(&self.enc, tree_roots, rng)
            .map_err(|_| Error::<T>::InvalidProof)?;

        // Update the leg's status.
        self.receiver = AffirmationStatus::Finalized;
        self.update_status::<T>()?;

        Ok(())
    }
}
// */
#[derive(Copy, Clone, Encode, Decode, Debug, TypeInfo, PartialEq, Eq)]
pub enum SettlementStatus {
    Pending,
    Executed,
    Rejected,
    Finalized,
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

pub type CurveTreeRootHash = [u8; 32];

pub fn hash_curve_tree_root<const L: usize>(root: &CurveTreeRoot<L>) -> CurveTreeRootHash {
    blake2_256(&(b"modlpy/dart_root_hash", root).encode())
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
        Ok(Self(CurveTreeWithBackend::new(height, gens_length)?))
    }
}

impl<T: Config> ValidateCurveTreeRoot<ASSET_TREE_L> for &AssetCurveTree<T> {
    fn validate_root(&self, root: &CurveTreeRoot<ASSET_TREE_L>) -> bool {
        let hash = hash_curve_tree_root::<ASSET_TREE_L>(root);
        AssetCurveTreeRoots::<T>::contains_key(hash)
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
        Ok(Self(CurveTreeWithBackend::new(height, gens_length)?))
    }
}

impl<T: Config> ValidateCurveTreeRoot<ACCOUNT_TREE_L> for &AccountCurveTree<T> {
    fn validate_root(&self, root: &CurveTreeRoot<ACCOUNT_TREE_L>) -> bool {
        let hash = hash_curve_tree_root::<ACCOUNT_TREE_L>(root);
        AccountCurveTreeRoots::<T>::contains_key(hash)
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
    }

    #[pallet::error]
    pub enum Error<T> {
        /// Dart account hasn't been registered yet.
        AccountMissing,
        /// Dart account already exists.
        AccountAlreadyCreated,
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

    /// Root hashes for DART assets curve tree.
    ///
    /// At the end of each block we will store the root hash of the assets curve tree.
    /// The map key is the root hash and the value is the block number when the root hash was last updated.
    #[pallet::storage]
    pub(super) type AssetCurveTreeRoots<T: Config> =
        StorageMap<_, Twox64Concat, CurveTreeRootHash, T::BlockNumber, OptionQuery>;

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

    /// Root hashes for DART accounts curve tree.
    ///
    /// At the end of each block we will store the root hash of the accounts curve tree.
    /// The map key is the root hash and the value is the block number when the root hash was last updated.
    #[pallet::storage]
    pub(super) type AccountCurveTreeRoots<T: Config> =
        StorageMap<_, Twox64Concat, CurveTreeRootHash, T::BlockNumber, OptionQuery>;

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
    pub(crate) type SettlementLegs<T: Config> = StorageDoubleMap<
        _,
        Twox64Concat,
        SettlementId,
        Twox64Concat,
        LegId,
        DartSettlementLeg,
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
        fn build(&self) {}
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
                let root = tree
                    .root_node()
                    .expect("Asset curve tree should have a root; qed")
                    .into();
                // Store the root hash in the storage.
                let root_hash = hash_curve_tree_root::<ASSET_TREE_L>(&root);
                AssetCurveTreeRoots::<T>::insert(
                    root_hash,
                    frame_system::Pallet::<T>::block_number(),
                );
            }

            // Check if the account curve tree has been updated.
            if UpdatedAccountCurveTree::<T>::get() {
                // Get the account curve tree.
                let tree = Self::get_account_curve_tree()
                    .expect("Account curve tree should be initialized; qed");
                // Get the root of the account curve tree.
                let root = tree
                    .root_node()
                    .expect("Account curve tree should have a root; qed")
                    .into();
                // Store the root hash in the storage.
                let root_hash = hash_curve_tree_root::<ACCOUNT_TREE_L>(&root);
                AccountCurveTreeRoots::<T>::insert(
                    root_hash,
                    frame_system::Pallet::<T>::block_number(),
                );
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
            DartAssetDetails::<T>::insert(proof.asset_id, asset_details);

            // Insert the update account state commitment into the account curve tree.
            let account_commitment = proof.account_state_commitment();
            Self::insert_account_leaf(&mut account_curve_tree, account_commitment)?;

            // Burn the nullifier to ensure it cannot be used again.
            AccountStateCommitmentNullifiers::<T>::insert(nullifier, ());

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
        #[pallet::call_index(4)]
        #[pallet::weight(<T as Config>::WeightInfo::create_settlement(proof.legs.len() as u32))]
        pub fn create_settlement(
            origin: OriginFor<T>,
            proof: polymesh_dart::SettlementProof,
        ) -> DispatchResult {
            // Ensure the caller has the required permissions to create the settlement.
            let _caller_did = PalletIdentity::<T>::ensure_perms(origin)?;

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
            for (leg_id, leg) in proof.legs.into_iter().enumerate() {
                let leg_id = leg_id as LegId;
                // Mediator affirmation status if the leg has a mediator.
                let mediator = leg
                    .has_mediator()
                    .map_err(Error::<T>::from)?
                    .then_some(AffirmationStatus::Pending);
                SettlementLegs::<T>::insert(
                    settlement_id,
                    leg_id,
                    DartSettlementLeg {
                        enc: leg.leg_enc().map_err(Error::<T>::from)?,
                        sender: AffirmationStatus::Pending,
                        receiver: AffirmationStatus::Pending,
                        mediator,
                        status: AffirmationStatus::Pending,
                    },
                );
            }

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
            data,
            auditor_or_mediator,
        };
        // Store the asset details.
        DartAssetDetails::<T>::insert(asset_id, asset_detail);

        // Insert the asset state into the asset curve tree.
        Self::update_asset_leaf(asset_id, &auditor_or_mediator, true)?;

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
        if is_new {
            asset_curve_tree.insert_leaf(asset_leaf)?;
        } else {
            asset_curve_tree.update_leaf(asset_id.into(), asset_leaf)?;
        }

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
        account_curve_tree.insert_leaf(account_leaf)?;

        // Set the updated flag for the account curve tree.
        UpdatedAccountCurveTree::<T>::put(true);

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
