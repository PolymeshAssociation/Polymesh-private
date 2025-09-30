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
use frame_support::{
    dispatch::{DispatchError, DispatchResult},
    ensure,
    traits::{Get, Randomness},
    weights::Weight,
    BoundedVec,
};
use frame_system::pallet_prelude::*;
use polymesh_primitives::{Balance, IdentityId};
use scale_info::TypeInfo;
use sp_runtime::BoundedBTreeSet;
use sp_std::collections::btree_set::BTreeSet;
use sp_std::convert::From;
use sp_std::vec::Vec;

use polymesh_dart::{
    curve_tree::WrappedCurveTreeParameters, AccountPublicKey, AccountStateCommitment,
    AccountStateNullifier, AccountStateUpdate, AssetId as DartAssetId, AssetState,
    BatchedSettlementCounts, DartLimits, EncryptionPublicKey, Error as DartError, LeafIndex,
    LegEncrypted, LegId, LegRef, PolymeshPrivateLimits, SettlementId, SettlementRef,
    ACCOUNT_TREE_HEIGHT, ASSET_TREE_HEIGHT, MAX_CURVE_TREE_GENS,
};

use polymesh_dart_host_functions::{native_dart_assets, BatchId, VerifyDartAssetRequest};

type PalletIdentity<T> = pallet_identity::Pallet<T>;

#[cfg(feature = "runtime-benchmarks")]
pub mod benchmarking;

#[cfg(feature = "testing")]
pub mod testing;

pub mod weights;

mod curve_tree;
pub use curve_tree::*;

mod settlement;
pub use settlement::*;

pub trait WeightInfo {
    fn update_account_curve_tree_root(l: u32) -> Weight;

    fn register_accounts(k: u32) -> Weight;

    fn create_asset() -> Weight;
    fn create_settlement(l: u32) -> Weight;
    fn mediator_affirmation() -> Weight;

    // Account state transition weights.
    fn register_account_assets(p: u32) -> Weight;
    fn mint_asset() -> Weight;
    fn sender_affirmation() -> Weight;
    fn receiver_affirmation() -> Weight;
    fn sender_update_counter() -> Weight;
    fn sender_revert() -> Weight;
    fn receiver_claim() -> Weight;

    fn batched_settlement(counts: BatchedSettlementCounts) -> Weight {
        Self::create_settlement(counts.leg_count)
            .saturating_add(
                Self::sender_affirmation_with_leaf().saturating_mul(counts.sender_count),
            )
            .saturating_add(
                Self::receiver_affirmation_with_leaf().saturating_mul(counts.receiver_count),
            )
    }

    fn on_init() -> Weight {
        Self::update_account_curve_tree_root(0)
    }

    fn insert_account_leaf(l: u32) -> Weight {
        Self::update_account_curve_tree_root(l)
            .saturating_sub(Self::update_account_curve_tree_root(0))
    }

    fn register_account_assets_with_leaf(p: u32) -> Weight {
        Self::register_account_assets(p).saturating_add(Self::insert_account_leaf(p))
    }

    fn mint_asset_with_leaf() -> Weight {
        Self::mint_asset().saturating_add(Self::insert_account_leaf(1))
    }

    fn sender_affirmation_with_leaf() -> Weight {
        Self::sender_affirmation().saturating_add(Self::insert_account_leaf(1))
    }

    fn receiver_affirmation_with_leaf() -> Weight {
        Self::receiver_affirmation().saturating_add(Self::insert_account_leaf(1))
    }

    fn sender_update_counter_with_leaf() -> Weight {
        Self::sender_update_counter().saturating_add(Self::insert_account_leaf(1))
    }

    fn sender_revert_with_leaf() -> Weight {
        Self::sender_revert().saturating_add(Self::insert_account_leaf(1))
    }

    fn receiver_claim_with_leaf() -> Weight {
        Self::receiver_claim().saturating_add(Self::insert_account_leaf(1))
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
    /// Mediator public keys.
    pub mediators: BoundedBTreeSet<EncryptionPublicKey, T::MaxAssetMediators>,
    /// Auditor public keys.
    pub auditors: BoundedBTreeSet<EncryptionPublicKey, T::MaxAssetAuditors>,
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
    pub trait Config: frame_system::Config + pallet_identity::Config + DartLimits {
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
            /// Mediators.
            mediators: BoundedBTreeSet<EncryptionPublicKey, T::MaxAssetMediators>,
            /// Auditors.
            auditors: BoundedBTreeSet<EncryptionPublicKey, T::MaxAssetAuditors>,
            /// Asset data.
            data: BoundedVec<u8, T::MaxAssetDataLength>,
        },
        /// A DART asset has been updated.
        AssetUpdated {
            /// Caller's identity.
            caller_did: IdentityId,
            /// Asset ID.
            asset_id: DartAssetId,
            /// Mediators.
            mediators: BoundedBTreeSet<EncryptionPublicKey, T::MaxAssetMediators>,
            /// Auditors.
            auditors: BoundedBTreeSet<EncryptionPublicKey, T::MaxAssetAuditors>,
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
            /// Settlement reference.
            settlement_ref: SettlementRef,
            /// Settlement memo.
            memo: BoundedVec<u8, <PolymeshPrivateLimits as DartLimits>::MaxSettlementMemoLength>,
            /// Asset CurveTree root_block.
            asset_root_block: BlockNumberFor<T>,
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
        /// Mediator has rejected a leg.
        MediatorRejected {
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
            /// Settlement reference.
            settlement_ref: SettlementRef,
            /// New status of the settlement.
            status: SettlementStatus,
        },
        /// Account curve tree leaf inserted.
        ///
        /// This curve tree is append-only, so we only store the new leaf.
        AccountStateLeafInserted {
            /// The new leaf index.
            leaf_index: LeafIndex,
            /// The new account state commitment.
            account_commitment: AccountStateCommitment,
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
            root: AssetTreeRoot,
        },
        /// Account curve tree root updated.
        AccountCurveTreeRootUpdated {
            /// The new root.
            root: AccountTreeRoot,
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
        /// CurveTree root not found.
        CurveTreeRootNotFound,
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
        /// Settlement memo is too long.
        SettlementMemoTooLong,
        /// Batched settlement has invalid leg references.
        BatchedSettlementInvalidLegRefs,
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
        /// No mediators for this leg.
        NoMediatorsForThisLeg,
        /// Too many mediators for this leg.
        TooManyMediators,
        /// Wrong mediator id for this leg.
        WrongMediatorId,
        /// No pending affirmations for this settlement.
        NoPendingAffirmations,
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
        /// CurveTree parameters not set.
        CurveTreeParametersNotSet,
    }

    impl<T: Config> From<DartError> for Error<T> {
        fn from(_error: DartError) -> Self {
            Self::CurveTreeError
        }
    }

    /// Cache wrapped asset curve tree parameters.
    #[pallet::storage]
    pub(crate) type CachedAssetCurveTreeParameters<T: Config> =
        StorageValue<_, WrappedCurveTreeParameters, OptionQuery>;

    /// Cache wrapped account curve tree parameters.
    #[pallet::storage]
    pub(crate) type CachedAccountCurveTreeParameters<T: Config> =
        StorageValue<_, WrappedCurveTreeParameters, OptionQuery>;

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
        bool,
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

    /// The current CurveTree Root for DART assets curve tree.
    #[pallet::storage]
    pub(super) type AssetCurveTreeCurrentRoot<T: Config> =
        StorageValue<_, AssetTreeRoot, OptionQuery>;

    /// CurveTree Roots for DART assets curve tree.
    ///
    /// At the end of each block we will store the root of the assets curve tree.
    /// The map key is the block number and the value is the root of the assets curve tree.
    #[pallet::storage]
    pub(super) type AssetCurveTreeRoots<T: Config> =
        StorageMap<_, Identity, T::BlockNumber, AssetTreeRoot, OptionQuery>;

    /// The block number of the last asset curve tree root update.
    ///
    /// This is used to track the last time the asset curve tree was updated.
    #[pallet::storage]
    pub(crate) type AssetCurveTreeLastUpdate<T: Config> =
        StorageValue<_, T::BlockNumber, ValueQuery>;

    /// Leaf storage for DART accounts curve tree.
    ///
    /// The leaves are immutable, so we use a simple storage map.
    #[pallet::storage]
    pub(super) type AccountLeaves<T: Config> =
        StorageMap<_, Twox64Concat, LeafIndex, AccountStateCommitment, OptionQuery>;

    /// Next leaf index for DART accounts curve tree.
    ///
    /// This is used to allocate new leaves in the tree.
    #[pallet::storage]
    pub(super) type NextAccountLeafIndex<T: Config> = StorageValue<_, LeafIndex, ValueQuery>;

    /// The last committed leaf index for DART accounts curve tree.
    ///
    /// This is used to do batched inserts into the tree.
    #[pallet::storage]
    pub(super) type LastCommittedAccountLeafIndex<T: Config> =
        StorageValue<_, LeafIndex, ValueQuery>;

    /// Inner node storage for DART accounts curve tree.
    #[pallet::storage]
    pub(super) type AccountInnerNodes<T: Config> =
        StorageMap<_, Twox64Concat, AccountNodeLocation, AccountInnerNode, OptionQuery>;

    /// The current CurveTree Root for DART accounts curve tree.
    #[pallet::storage]
    pub(super) type AccountCurveTreeCurrentRoot<T: Config> =
        StorageValue<_, AccountTreeRoot, OptionQuery>;

    /// CurveTree Roots for DART accounts curve tree.
    ///
    /// At the end of each block we will store the root of the accounts curve tree.
    /// The map key is the block number and the value is the root of the accounts curve tree.
    #[pallet::storage]
    pub(super) type AccountCurveTreeRoots<T: Config> =
        StorageMap<_, Identity, T::BlockNumber, AccountTreeRoot, OptionQuery>;

    /// The block number of the last account curve tree root update.
    ///
    /// This is used to track the last time the account curve tree was updated.
    #[pallet::storage]
    pub(crate) type AccountCurveTreeLastUpdate<T: Config> =
        StorageValue<_, T::BlockNumber, ValueQuery>;

    /// Nullifiers for DART account state commitments.
    ///
    /// This is used to ensure that the same account state commitment cannot be used twice.
    #[pallet::storage]
    pub(super) type AccountStateCommitmentNullifiers<T: Config> =
        StorageMap<_, Identity, AccountStateNullifier, (), OptionQuery>;

    /// The next settlement ID to be used.
    #[pallet::storage]
    pub(crate) type NextSettlementId<T: Config> = StorageValue<_, SettlementId, ValueQuery>;

    /// The settlement status.
    #[pallet::storage]
    pub(crate) type SettlementState<T: Config> =
        StorageMap<_, Twox64Concat, SettlementRef, SettlementStatus, OptionQuery>;

    /// The settlement memo.
    #[pallet::storage]
    pub(crate) type SettlementMemo<T: Config> = StorageMap<
        _,
        Twox64Concat,
        SettlementRef,
        BoundedVec<u8, <PolymeshPrivateLimits as DartLimits>::MaxSettlementMemoLength>,
        OptionQuery,
    >;

    /// The settlement legs.
    ///
    /// This is a double map where the first key is the settlement ID and the second key is the leg ID.
    /// The value is the DartSettlementLeg.
    #[pallet::storage]
    pub(crate) type SettlementLegs<T: Config> = StorageNMap<
        _,
        (
            NMapKey<Twox64Concat, SettlementRef>,
            NMapKey<Twox64Concat, LegId>,
        ),
        LegEncrypted,
        OptionQuery,
    >;

    /// The number of pending affirmations for a settlement.
    /// This is used to track when a settlement can be executed.
    #[pallet::storage]
    pub(crate) type SettlementPendingAffirmations<T: Config> =
        StorageMap<_, Twox64Concat, SettlementRef, u32, ValueQuery>;

    /// The number of pending finalizations for a settlement.
    /// This is used to track when a settlement can be finalized and all storage can be cleaned up.
    #[pallet::storage]
    pub(crate) type SettlementPendingFinalizations<T: Config> =
        StorageMap<_, Twox64Concat, SettlementRef, u32, ValueQuery>;

    /// The affirmation status of each party in a settlement leg.
    /// This is a triple map where the first key is the settlement ID, the second key is the leg ID, and the third key is the party (sender, receiver, mediator).
    #[pallet::storage]
    pub(crate) type LegAffirmationStatus<T: Config> = StorageNMap<
        _,
        (
            NMapKey<Twox64Concat, SettlementRef>,
            NMapKey<Twox64Concat, LegId>,
            NMapKey<Twox64Concat, LegAffirmParty>,
        ),
        AffirmationStatus,
        OptionQuery,
    >;

    /// The BatchId for the current block.
    #[pallet::storage]
    pub(crate) type CurrentBatchId<T: Config> = StorageValue<_, BatchId, OptionQuery>;

    #[pallet::genesis_config]
    #[derive(Default)]
    pub struct GenesisConfig {}

    #[pallet::genesis_build]
    impl<T: Config> GenesisBuild<T> for GenesisConfig {
        fn build(&self) {
            // Generate the asset curve tree parameters.
            let params = WrappedCurveTreeParameters::new::<AssetTreeConfig>(
                polymesh_dart::MAX_CURVE_TREE_GENS,
            )
            .expect("Asset curve tree parameters should be valid; qed");
            // Store the asset curve tree parameters in the storage.
            CachedAssetCurveTreeParameters::<T>::put(params);

            // Generate the account curve tree parameters.
            let params = WrappedCurveTreeParameters::new::<AccountTreeConfig>(
                polymesh_dart::MAX_CURVE_TREE_GENS,
            )
            .expect("Account curve tree parameters should be valid; qed");
            // Store the account curve tree parameters in the storage.
            CachedAccountCurveTreeParameters::<T>::put(params);

            // Initialize the Asset Curve Tree.
            {
                let mut tree = Pallet::<T>::get_asset_curve_tree()
                    .expect("Asset curve tree should be initialized; qed");
                tree.init_root()
                    .expect("Asset curve tree should be able to init root; qed");
            }
            // Initialize the Account Curve Tree.
            {
                let mut tree = Pallet::<T>::get_account_curve_tree()
                    .expect("Account curve tree should be initialized; qed");
                tree.init_root()
                    .expect("Account curve tree should be able to init root; qed");
            }
        }
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_initialize(_n: BlockNumberFor<T>) -> Weight {
            // Get a new batch ID for the block.
            let batch_id = native_dart_assets::create_batch(true);
            CurrentBatchId::<T>::put(batch_id);

            // TODO: add missing writes to weight.
            <T as Config>::WeightInfo::on_init()
        }

        fn on_finalize(_n: BlockNumberFor<T>) {
            Self::update_account_curve_tree_root();
            CurrentBatchId::<T>::kill();
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
        #[pallet::weight(<T as Config>::WeightInfo::register_accounts(proof.len() as u32))]
        pub fn register_accounts(
            origin: OriginFor<T>,
            proof: polymesh_dart::AccountRegistrationProof,
        ) -> DispatchResult {
            let caller_did = PalletIdentity::<T>::ensure_perms(origin)?;

            // Ensure the accounts haven't already been registered.
            for account in &proof.accounts {
                // Ensure the dart account doesn't exist.
                ensure!(
                    !AccountDid::<T>::contains_key(&account.acct),
                    Error::<T>::AccountAlreadyCreated
                );
                // Ensure the encryption key doesn't exist.
                ensure!(
                    !EncryptionKeyAccount::<T>::contains_key(&account.enc),
                    Error::<T>::AccountAlreadyCreated
                );
                // Link the dart account to the caller's identity.
                AccountDid::<T>::insert(&account.acct, caller_did);
                // Link the encryption key to the dart account.
                AccountEncryptionKey::<T>::insert(&account.acct, &account.enc);
                // Link the dart account to the encryption key.
                EncryptionKeyAccount::<T>::insert(&account.enc, &account.acct);

                Self::deposit_event(Event::<T>::AccountRegistered {
                    caller_did,
                    account: account.acct,
                    encryption_key: account.enc,
                });
            }

            // Verify the proof.
            let req = VerifyDartAssetRequest::AccountRegistration {
                did: caller_did,
                proof,
            };
            req.verify().map_err(|_| Error::<T>::InvalidProof)?;

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
            mediators: BoundedBTreeSet<EncryptionPublicKey, T::MaxAssetMediators>,
            auditors: BoundedBTreeSet<EncryptionPublicKey, T::MaxAssetAuditors>,
            data: BoundedVec<u8, T::MaxAssetDataLength>,
        ) -> DispatchResult {
            let issuer = PalletIdentity::<T>::ensure_perms(origin)?;

            Self::base_create_asset(issuer, mediators, auditors, data)?;
            Ok(())
        }

        /// Batch register multiple accounts and assets.
        ///
        /// This is used to initialize the first account state commitment of the DART asset for the DART account.
        ///
        /// # Arguments
        /// * `origin` - The origin of the call.  They must be the owner of the DART account.
        /// * `proof` - The Batched Account asset registration proof.
        ///
        /// # Errors
        /// * `BadOrigin` if `origin` isn't signed.
        /// * `AccountMissing` if the DART account is not registered.
        /// * `AssetMissing` if the DART asset is not registered.
        /// * `AccountAssetAlreadyRegistered` if the DART account has already registered the DART asset.
        /// * `NotAccountOwner` if the caller is not the owner of the DART account.
        /// * `InvalidProof` if the proof is invalid.
        #[pallet::call_index(2)]
        #[pallet::weight(<T as Config>::WeightInfo::register_account_assets_with_leaf(proof.len() as u32))]
        pub fn register_account_assets(
            origin: OriginFor<T>,
            proof: polymesh_dart::BatchedAccountAssetRegistrationProof<PolymeshPrivateLimits>,
        ) -> DispatchResult {
            // Ensure the caller is allowed to make this call.
            let caller_did = PalletIdentity::<T>::ensure_perms(origin)?;

            let mut seen_account = BTreeSet::new();
            let mut seen_asset = BTreeSet::new();
            let mut registrations = Vec::with_capacity(proof.proofs.len());
            for p in &proof.proofs {
                if !seen_account.contains(&p.account) {
                    seen_account.insert(p.account);
                    // Ensure the DART account is registered to the caller's identity.
                    Self::ensure_dart_account_owner(caller_did, &p.account)?;
                }
                if !seen_asset.contains(&p.asset_id) {
                    seen_asset.insert(p.asset_id);
                    // Ensure the DART asset exists.
                    Self::ensure_dart_asset_exists(p.asset_id)?;
                }

                // Ensure the DART account hasn't already registered the DART asset.
                ensure!(
                    !AccountAssetRegistrations::<T>::get((&p.account, &p.asset_id)),
                    Error::<T>::AccountAssetAlreadyRegistered
                );
                AccountAssetRegistrations::<T>::insert((&p.account, &p.asset_id), true);

                // Ensure the nullifier is unique.
                Self::ensure_account_state_nullifier_unique(&p.nullifier)?;

                registrations.push((
                    p.account,
                    p.asset_id,
                    p.nullifier,
                    p.account_state_commitment,
                ));
            }

            // Verify the proof.
            let req = VerifyDartAssetRequest::BatchedAccountAssetRegistration {
                did: caller_did,
                proof,
            };
            req.verify().map_err(|_| Error::<T>::InvalidProof)?;

            // Process each registration.
            for (account, asset_id, nullifier, account_state_commitment) in registrations {
                // Insert the new account state commitment from the proof into the account curve tree.
                Self::insert_account_leaf(account_state_commitment)?;

                // Burn the nullifier to ensure it cannot be used again.
                AccountStateCommitmentNullifiers::<T>::insert(nullifier, ());

                // Emit an event for the account asset registration.
                Self::deposit_event(Event::<T>::AccountAssetRegistered {
                    caller_did,
                    asset_id,
                    account,
                });
            }

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
        #[pallet::weight(<T as Config>::WeightInfo::mint_asset_with_leaf())]
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

            let asset_id = proof.asset_id;
            let account = proof.pk;
            // Handle the account state update proof and verify the nullifier.
            Self::handle_account_state_update_proof(proof, |proof, root| {
                // Verify the proof.
                let req = VerifyDartAssetRequest::MintAsset {
                    did: caller_did,
                    root,
                    proof,
                };
                req.verify().map_err(|_| Error::<T>::InvalidProof)?;
                Ok(())
            })?;

            // Store the updated asset details.
            DartAssetDetails::<T>::insert(asset_id, &asset_details);

            // Emit an event for the asset minting.
            Self::deposit_event(Event::<T>::AssetMinted {
                caller_did,
                asset_id,
                amount,
                total_supply: asset_details.total_supply,
                account,
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
            proof: polymesh_dart::SettlementProof<PolymeshPrivateLimits>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            // Allocate a new settlement ID.
            let settlement_id = NextSettlementId::<T>::get();
            NextSettlementId::<T>::put(settlement_id + 1);
            let settlement_ref = SettlementRef::from(settlement_id);

            Self::base_create_settlement(settlement_ref, proof)
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
        #[pallet::weight(<T as Config>::WeightInfo::sender_affirmation_with_leaf())]
        pub fn sender_affirmation(
            origin: OriginFor<T>,
            proof: polymesh_dart::SenderAffirmationProof,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            Self::base_sender_affirmation(proof)
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
        #[pallet::weight(<T as Config>::WeightInfo::receiver_affirmation_with_leaf())]
        pub fn receiver_affirmation(
            origin: OriginFor<T>,
            proof: polymesh_dart::ReceiverAffirmationProof,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            Self::base_receiver_affirmation(proof)
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

            let leg_ref = proof.leg_ref;
            let accept = proof.accept;
            // Create an update settlement status instance.
            let update_settlement = UpdateSettlementStatus::<T>::new(leg_ref)?;

            // Verify the mediator affirmation proof and update the settlement and leg status.
            update_settlement.mediator_affirmation(proof)?;

            // Emit an event for the mediator affirmation.
            if accept {
                Self::deposit_event(Event::<T>::MediatorAffirmed { leg_ref });
            } else {
                Self::deposit_event(Event::<T>::MediatorRejected { leg_ref });
            }

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
        #[pallet::weight(<T as Config>::WeightInfo::sender_update_counter_with_leaf())]
        pub fn sender_update_counter(
            origin: OriginFor<T>,
            proof: polymesh_dart::SenderCounterUpdateProof,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            let leg_ref = proof.leg_ref;
            // Handle the account state update proof and verify the nullifier.
            Self::handle_account_state_update_proof(proof, |proof, root| {
                // Create an update settlement status instance.
                let update_settlement = UpdateSettlementStatus::<T>::new(proof.leg_ref)?;

                // Verify the sender update proof and update the settlement and leg status.
                update_settlement.sender_counter_update(proof, root)
            })?;

            // Emit an event for the sender update counter.
            Self::deposit_event(Event::<T>::SenderCounterUpdated { leg_ref });

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
        #[pallet::weight(<T as Config>::WeightInfo::sender_revert_with_leaf())]
        pub fn sender_revert(
            origin: OriginFor<T>,
            proof: polymesh_dart::SenderReversalProof,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            let leg_ref = proof.leg_ref;
            // Handle the account state update proof and verify the nullifier.
            Self::handle_account_state_update_proof(proof, |proof, root| {
                // Create an update settlement status instance.
                let update_settlement = UpdateSettlementStatus::<T>::new(proof.leg_ref)?;

                // Verify the sender reversal proof and update the settlement and leg status.
                update_settlement.sender_reversal(proof, root)
            })?;

            // Emit an event for the sender revert.
            Self::deposit_event(Event::<T>::SenderReverted { leg_ref });

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
        #[pallet::weight(<T as Config>::WeightInfo::receiver_claim_with_leaf())]
        pub fn receiver_claim(
            origin: OriginFor<T>,
            proof: polymesh_dart::ReceiverClaimProof,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            let leg_ref = proof.leg_ref;
            // Handle the account state update proof and verify the nullifier.
            Self::handle_account_state_update_proof(proof, |proof, root| {
                // Create an update settlement status instance.
                let update_settlement = UpdateSettlementStatus::<T>::new(proof.leg_ref)?;

                // Verify the receiver claim proof and update the settlement and leg status.
                update_settlement.receiver_claim(proof, root)
            })?;

            // Emit an event for the receiver claim.
            Self::deposit_event(Event::<T>::ReceiverClaimed { leg_ref });

            Ok(())
        }

        /// Create a settlement with batched leg affirmations.
        ///
        /// # Arguments
        /// * `origin` - The origin of the call.
        /// * `proof` - The settlement proof with batched leg affirmations.
        ///
        /// # Errors
        /// * `BadOrigin` if `origin` isn't signed.
        /// * `InvalidProof` if the proof is invalid.
        /// * `SettlementMissingLegs` if the settlement has no legs.
        /// * `SettlementTooManyLegs` if the settlement has more legs than the maximum allowed.
        #[pallet::call_index(11)]
        #[pallet::weight(<T as Config>::WeightInfo::batched_settlement(proof.count_leg_affirmations()))]
        pub fn batched_settlement(
            origin: OriginFor<T>,
            proof: polymesh_dart::BatchedSettlementProof<PolymeshPrivateLimits>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            // Ensure that the all the leg affirmations have the same settlement reference.
            ensure!(
                proof.check_leg_references(),
                Error::<T>::BatchedSettlementInvalidLegRefs
            );

            // Get the hash based settlement reference.
            let settlement_ref = proof.settlement_ref();

            // Create the settlement with the provided proof.
            Self::base_create_settlement(settlement_ref, proof.hashed_settlement.settlement)?;

            // Handle the leg affirmations in the proof.
            for leg_affirmation in proof.leg_affirmations {
                if let Some(sender_proof) = leg_affirmation.sender {
                    Self::base_sender_affirmation(sender_proof)?;
                }
                if let Some(receiver_proof) = leg_affirmation.receiver {
                    Self::base_receiver_affirmation(receiver_proof)?;
                }
            }

            Ok(())
        }
    }
}

impl<T: Config> Pallet<T> {
    /// Create a new DART asset.
    pub fn base_create_asset(
        owner_did: IdentityId,
        mediators: BoundedBTreeSet<EncryptionPublicKey, T::MaxAssetMediators>,
        auditors: BoundedBTreeSet<EncryptionPublicKey, T::MaxAssetAuditors>,
        data: BoundedVec<u8, T::MaxAssetDataLength>,
    ) -> Result<DartAssetId, DispatchError> {
        // Ensure the auditor or mediator is registered.
        Self::ensure_mediators_registered(&mediators)?;
        Self::ensure_auditors_registered(&auditors)?;

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
            mediators: mediators.clone(),
            auditors: auditors.clone(),
        };
        // Store the asset details.
        DartAssetDetails::<T>::insert(asset_id, asset_detail);

        // Insert the asset state into the asset curve tree.
        Self::update_asset_leaf(owner_did, asset_id, &auditors, &mediators)?;

        // Emit the event for asset creation.
        Self::deposit_event(Event::<T>::AssetCreated {
            caller_did: owner_did,
            asset_id,
            mediators: mediators.clone(),
            auditors: auditors.clone(),
            data,
        });

        Ok(asset_id)
    }

    pub fn base_create_settlement(
        settlement_ref: SettlementRef,
        proof: polymesh_dart::SettlementProof<PolymeshPrivateLimits>,
    ) -> DispatchResult {
        let leg_count = proof.legs.len();
        // Ensure the settlement has at least one leg.
        ensure!(leg_count > 0, Error::<T>::SettlementMissingLegs);

        // Ensure the settlement doesn't have more than the maximum number of legs.
        ensure!(
            leg_count <= T::MaxSettlementLegs::get() as usize,
            Error::<T>::SettlementTooManyLegs
        );

        // Get details of the settlement.
        let memo = proof.memo.clone();
        let proof_legs = proof.legs.clone();
        let root_block: BlockNumberFor<T> = proof.root_block.into();

        // Verify the settlement proof.
        let root =
            AssetCurveTreeRoots::<T>::get(root_block).ok_or(Error::<T>::CurveTreeRootNotFound)?;
        let req = VerifyDartAssetRequest::CreateSettlement { root, proof };
        req.verify().map_err(|_| Error::<T>::InvalidProof)?;

        // Set the settlement state to pending.
        SettlementState::<T>::insert(settlement_ref, SettlementStatus::Pending);

        // Initialize all affirmation statuses to Pending.
        let mut pending_affirmations = 0;
        for (leg_idx, leg) in proof_legs.iter().enumerate() {
            let leg_idx = leg_idx as LegId;
            let mediators = leg.mediator_count().map_err(Error::<T>::from)? as u32;

            pending_affirmations += 2 + mediators; // Sender + Receiver + Mediators
            LegAffirmationStatus::<T>::insert(
                (settlement_ref, leg_idx, LegAffirmParty::Sender),
                AffirmationStatus::Pending,
            );
            LegAffirmationStatus::<T>::insert(
                (settlement_ref, leg_idx, LegAffirmParty::Receiver),
                AffirmationStatus::Pending,
            );
            for idx in 0..mediators {
                LegAffirmationStatus::<T>::insert(
                    (settlement_ref, leg_idx, LegAffirmParty::Mediator(idx as u8)),
                    AffirmationStatus::Pending,
                );
            }
        }
        // Store the number of pending affirmations for the settlement.
        SettlementPendingAffirmations::<T>::insert(settlement_ref, pending_affirmations);

        // Store the settlement memo.
        SettlementMemo::<T>::insert(settlement_ref, &memo);

        // Store the settlement legs.
        let mut legs = BoundedVec::new();
        for (leg_id, leg) in proof_legs.into_iter().enumerate() {
            let leg_id = leg_id as LegId;
            legs.force_push(leg.leg_enc.clone());

            SettlementLegs::<T>::insert((settlement_ref, leg_id), leg.leg_enc);
        }

        // Emit an event for the settlement creation.
        Self::deposit_event(Event::<T>::SettlementCreated {
            settlement_ref,
            asset_root_block: root_block,
            memo,
            legs,
        });

        Ok(())
    }

    pub fn base_sender_affirmation(proof: polymesh_dart::SenderAffirmationProof) -> DispatchResult {
        let leg_ref = proof.leg_ref;
        // Handle the account state update proof and verify the nullifier.
        Self::handle_account_state_update_proof(proof, |proof, root| {
            // Create an update settlement status instance.
            let update_settlement = UpdateSettlementStatus::<T>::new(proof.leg_ref)?;

            // Verify the sender affirmation proof and update the settlement and leg status.
            update_settlement.sender_affirmation(proof, root)
        })?;

        // Emit an event for the sender affirmation.
        Self::deposit_event(Event::<T>::SenderAffirmed { leg_ref });

        Ok(())
    }

    pub fn base_receiver_affirmation(
        proof: polymesh_dart::ReceiverAffirmationProof,
    ) -> DispatchResult {
        let leg_ref = proof.leg_ref;
        // Handle the account state update proof and verify the nullifier.
        Self::handle_account_state_update_proof(proof, |proof, root| {
            // Create an update settlement status instance.
            let update_settlement = UpdateSettlementStatus::<T>::new(proof.leg_ref)?;

            // Verify the receiver affirmation proof and update the settlement and leg status.
            update_settlement.receiver_affirmation(proof, root)
        })?;

        // Emit an event for the receiver affirmation.
        Self::deposit_event(Event::<T>::ReceiverAffirmed { leg_ref });

        Ok(())
    }

    /// Handle account state update proof verification and insertion.
    pub fn handle_account_state_update_proof<P: AccountStateUpdate>(
        proof: P,
        verify: impl FnOnce(P, AccountTreeRoot) -> DispatchResult,
    ) -> DispatchResult {
        let nullifier = proof.nullifier();
        let account_commitment = proof.account_state_commitment();
        // Ensure the nullifier is unique.
        Self::ensure_account_state_nullifier_unique(&nullifier)?;

        // Verify the account state update proof.
        let root_block: BlockNumberFor<T> = proof.root_block().into();
        let root =
            AccountCurveTreeRoots::<T>::get(root_block).ok_or(Error::<T>::CurveTreeRootNotFound)?;
        verify(proof, root)?;

        // Insert the update account state commitment into the account curve tree.
        Self::insert_account_leaf(account_commitment)?;

        // Burn the nullifier to ensure it cannot be used again.
        AccountStateCommitmentNullifiers::<T>::insert(nullifier, ());

        Ok(())
    }

    /// Get the asset curve tree interface.
    pub fn get_asset_curve_tree() -> Result<AssetCurveTree<T>, Error<T>> {
        Ok(AssetCurveTree::<T>::new(
            ASSET_TREE_HEIGHT,
            MAX_CURVE_TREE_GENS,
        )?)
    }

    /// Get the account curve tree interface.
    pub fn get_account_curve_tree() -> Result<AccountCurveTree<T>, Error<T>> {
        Ok(AccountCurveTree::<T>::new(
            ACCOUNT_TREE_HEIGHT,
            MAX_CURVE_TREE_GENS,
        )?)
    }

    /// Update the asset leaf in the asset curve tree.
    fn update_asset_leaf(
        caller_did: IdentityId,
        asset_id: DartAssetId,
        auditors: &BoundedBTreeSet<EncryptionPublicKey, T::MaxAssetAuditors>,
        mediators: &BoundedBTreeSet<EncryptionPublicKey, T::MaxAssetMediators>,
    ) -> DispatchResult {
        // Create the Asset State.
        let asset_state = AssetState::<T>::new_bounded(asset_id, mediators, auditors);
        let asset_leaf = asset_state.commitment().map_err(Error::<T>::from)?;

        // Update the asset curve tree with the new asset.
        let mut asset_curve_tree = Self::get_asset_curve_tree()?;
        let leaf_index = asset_id.into();
        asset_curve_tree.update_leaf(leaf_index, asset_leaf)?;

        // Emit an event for the asset state update.
        Self::deposit_event(Event::<T>::AssetUpdated {
            caller_did,
            asset_id,
            auditors: auditors.clone(),
            mediators: mediators.clone(),
        });
        Self::deposit_event(Event::<T>::AssetStateLeafUpdated {
            leaf_index,
            asset_leaf,
        });

        Ok(())
    }

    /// Insert a new account state commitment into the account curve tree.
    fn insert_account_leaf(account_commitment: AccountStateCommitment) -> Result<(), Error<T>> {
        // Insert the new account leaf.
        let leaf_index = Self::next_account_leaf_index();
        AccountLeaves::<T>::set(leaf_index, Some(account_commitment));

        // Emit an event for the account curve tree update.
        Self::deposit_event(Event::<T>::AccountStateLeafInserted {
            leaf_index,
            account_commitment,
        });

        Ok(())
    }

    /// Get the next account leaf index.
    pub fn next_account_leaf_index() -> LeafIndex {
        let leaf_index = NextAccountLeafIndex::<T>::get();
        // Increment the next leaf index for the next call.
        NextAccountLeafIndex::<T>::put(leaf_index + 1);
        leaf_index
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

    /// Ensure auditor encryption public keys are registered.
    pub fn ensure_auditors_registered(
        keys: &BoundedBTreeSet<EncryptionPublicKey, T::MaxAssetAuditors>,
    ) -> Result<(), Error<T>> {
        for key in keys {
            Self::ensure_dart_account_encryption_key_registered(key)?;
        }
        Ok(())
    }

    /// Ensure mediator encryption public keys are registered.
    pub fn ensure_mediators_registered(
        keys: &BoundedBTreeSet<EncryptionPublicKey, T::MaxAssetMediators>,
    ) -> Result<(), Error<T>> {
        for key in keys {
            Self::ensure_dart_account_encryption_key_registered(key)?;
        }
        Ok(())
    }

    pub fn update_account_curve_tree_root() {
        // Get the account curve tree.
        let mut tree =
            Self::get_account_curve_tree().expect("Account curve tree should be initialized; qed");

        // Commit the delayed updates to the account curve tree.
        tree.commit_leaves_to_tree()
            .expect("Account curve tree should be able to commit leaves; qed");
    }
}
