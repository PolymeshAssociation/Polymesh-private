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
use sp_std::convert::From;

use polymesh_dart::{
    curve_tree::{CurveTreeRoot, WrappedCurveTreeParameters},
    AccountPublicKey, AccountStateCommitment, AccountStateNullifier, AccountStateUpdate,
    AssetId as DartAssetId, AssetState, AuditorOrMediator, BatchedSettlementCounts, DartLimits,
    EncryptionPublicKey, Error as DartError, LeafIndex, LegEncrypted, LegId, LegRef, SettlementId,
    SettlementRef, ACCOUNT_TREE_HEIGHT, ACCOUNT_TREE_L, ASSET_TREE_HEIGHT, ASSET_TREE_L,
    MAX_CURVE_TREE_GENS,
};

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

    fn batched_settlement(counts: BatchedSettlementCounts) -> Weight {
        Self::create_settlement(counts.leg_count)
            .saturating_add(Self::sender_affirmation().saturating_mul(counts.sender_count))
            .saturating_add(Self::receiver_affirmation().saturating_mul(counts.receiver_count))
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
            /// Settlement reference.
            settlement_ref: SettlementRef,
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
        /// CurveTree parameters not set.
        CurveTreeParametersNotSet,
    }

    impl<T: Config> From<DartError> for Error<T> {
        fn from(_error: DartError) -> Self {
            Self::CurveTreeError
        }
    }

    /// Cache wrapped curve tree parameters.
    #[pallet::storage]
    pub(crate) type CachedCurveTreeParameters<T: Config> =
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
        StorageMap<_, Twox64Concat, SettlementRef, SettlementStatus, OptionQuery>;

    /// The settlement memo.
    #[pallet::storage]
    pub(crate) type SettlementMemo<T: Config> = StorageMap<
        _,
        Twox64Concat,
        SettlementRef,
        BoundedVec<u8, T::MaxSettlementMemoLength>,
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

            let params = WrappedCurveTreeParameters::new(polymesh_dart::MAX_CURVE_TREE_GENS)
                .expect("Curve tree parameters should be valid; qed");
            // Store the curve tree parameters in the storage.
            CachedCurveTreeParameters::<T>::put(params);
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
            Self::update_curve_tree_roots();
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

            // Handle the account state update proof and verify the nullifier.
            Self::handle_account_state_update_proof(&proof, |account_curve_tree, rng| {
                // Verify the proof.
                proof
                    .verify(account_curve_tree, rng)
                    .map_err(|_| Error::<T>::InvalidProof)?;
                Ok(())
            })?;

            // Store the updated asset details.
            DartAssetDetails::<T>::insert(proof.asset_id, &asset_details);

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
            proof: polymesh_dart::SettlementProof<T>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            // Allocate a new settlement ID.
            let settlement_id = NextSettlementId::<T>::get();
            NextSettlementId::<T>::put(settlement_id + 1);
            let settlement_ref = SettlementRef::from(settlement_id);

            Self::base_create_settlement(settlement_ref, &proof)
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

            Self::base_sender_affirmation(&proof)
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

            Self::base_receiver_affirmation(&proof)
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
            if proof.accept {
                Self::deposit_event(Event::<T>::MediatorAffirmed {
                    leg_ref: proof.leg_ref,
                });
            } else {
                Self::deposit_event(Event::<T>::MediatorRejected {
                    leg_ref: proof.leg_ref,
                });
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
        #[pallet::weight(<T as Config>::WeightInfo::sender_update_counter())]
        pub fn sender_update_counter(
            origin: OriginFor<T>,
            proof: polymesh_dart::SenderCounterUpdateProof,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            // Handle the account state update proof and verify the nullifier.
            Self::handle_account_state_update_proof(&proof, |account_curve_tree, rng| {
                // Create an update settlement status instance.
                let mut update_settlement = UpdateSettlementStatus::<T>::new(proof.leg_ref)?;

                // Verify the sender update proof and update the settlement and leg status.
                update_settlement.sender_counter_update(&proof, account_curve_tree, rng)
            })?;

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

            // Handle the account state update proof and verify the nullifier.
            Self::handle_account_state_update_proof(&proof, |account_curve_tree, rng| {
                // Create an update settlement status instance.
                let mut update_settlement = UpdateSettlementStatus::<T>::new(proof.leg_ref)?;

                // Verify the sender reversal proof and update the settlement and leg status.
                update_settlement.sender_reversal(&proof, account_curve_tree, rng)
            })?;

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

            // Handle the account state update proof and verify the nullifier.
            Self::handle_account_state_update_proof(&proof, |account_curve_tree, rng| {
                // Create an update settlement status instance.
                let mut update_settlement = UpdateSettlementStatus::<T>::new(proof.leg_ref)?;

                // Verify the receiver claim proof and update the settlement and leg status.
                update_settlement.receiver_claim(&proof, account_curve_tree, rng)
            })?;

            // Emit an event for the receiver claim.
            Self::deposit_event(Event::<T>::ReceiverClaimed {
                leg_ref: proof.leg_ref,
            });

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
            proof: polymesh_dart::BatchedSettlementProof<T>,
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
            Self::base_create_settlement(settlement_ref, proof.settlement_proof())?;

            // Handle the leg affirmations in the proof.
            for leg_affirmation in &proof.leg_affirmations {
                if let Some(sender_proof) = &leg_affirmation.sender {
                    Self::base_sender_affirmation(sender_proof)?;
                }
                if let Some(receiver_proof) = &leg_affirmation.receiver {
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

    pub fn base_create_settlement(
        settlement_ref: SettlementRef,
        proof: &polymesh_dart::SettlementProof<T>,
    ) -> DispatchResult {
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

        // Set the settlement state to pending.
        SettlementState::<T>::insert(settlement_ref, SettlementStatus::Pending);

        // Store the settlement memo.
        SettlementMemo::<T>::insert(settlement_ref, &proof.memo);

        // Store the settlement legs.
        let mut legs = BoundedVec::new();
        for (leg_id, leg) in proof.legs.iter().enumerate() {
            let leg_id = leg_id as LegId;
            let leg_enc = leg.leg_enc().map_err(Error::<T>::from)?;
            legs.force_push(leg_enc.clone());

            // Mediator affirmation status if the leg has a mediator.
            let has_mediator = leg.has_mediator().map_err(Error::<T>::from)?;

            SettlementLegs::<T>::insert(
                (settlement_ref, leg_id),
                DartSettlementLeg::new(leg_enc, has_mediator),
            );
        }

        // Emit an event for the settlement creation.
        Self::deposit_event(Event::<T>::SettlementCreated {
            settlement_ref,
            legs,
        });

        Ok(())
    }

    pub fn base_sender_affirmation(
        proof: &polymesh_dart::SenderAffirmationProof,
    ) -> DispatchResult {
        // Handle the account state update proof and verify the nullifier.
        Self::handle_account_state_update_proof(proof, |account_curve_tree, rng| {
            // Create an update settlement status instance.
            let mut update_settlement = UpdateSettlementStatus::<T>::new(proof.leg_ref)?;

            // Verify the sender affirmation proof and update the settlement and leg status.
            update_settlement.sender_affirmation(&proof, account_curve_tree, rng)
        })?;

        // Emit an event for the sender affirmation.
        Self::deposit_event(Event::<T>::SenderAffirmed {
            leg_ref: proof.leg_ref,
        });

        Ok(())
    }

    pub fn base_receiver_affirmation(
        proof: &polymesh_dart::ReceiverAffirmationProof,
    ) -> DispatchResult {
        // Handle the account state update proof and verify the nullifier.
        Self::handle_account_state_update_proof(proof, |account_curve_tree, rng| {
            // Create an update settlement status instance.
            let mut update_settlement = UpdateSettlementStatus::<T>::new(proof.leg_ref)?;

            // Verify the receiver affirmation proof and update the settlement and leg status.
            update_settlement.receiver_affirmation(&proof, account_curve_tree, rng)
        })?;

        // Emit an event for the receiver affirmation.
        Self::deposit_event(Event::<T>::ReceiverAffirmed {
            leg_ref: proof.leg_ref,
        });

        Ok(())
    }

    /// Handle account state update proof verification and insertion.
    pub fn handle_account_state_update_proof(
        proof: &impl AccountStateUpdate,
        verify: impl FnOnce(&AccountCurveTree<T>, &mut rand_chacha::ChaCha20Rng) -> DispatchResult,
    ) -> DispatchResult {
        // Ensure the nullifier is unique.
        let nullifier = proof.nullifier();
        Self::ensure_account_state_nullifier_unique(&nullifier)?;

        // Get account curve tree.
        let mut account_curve_tree = Self::get_account_curve_tree()?;

        // Verify the account state update proof.
        let mut rng = Self::get_rng();
        verify(&account_curve_tree, &mut rng)?;

        // Insert the update account state commitment into the account curve tree.
        let account_commitment = proof.account_state_commitment();
        Self::insert_account_leaf(&mut account_curve_tree, account_commitment)?;

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

    pub fn update_curve_tree_roots() {
        // Check if the asset curve tree has been updated.
        if UpdatedAssetCurveTree::<T>::get() {
            // Get the asset curve tree.
            let tree =
                Self::get_asset_curve_tree().expect("Asset curve tree should be initialized; qed");

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
            AccountCurveTreeRoots::<T>::insert(&root, frame_system::Pallet::<T>::block_number());

            // Emit an event for the account curve tree root update.
            Self::deposit_event(Event::<T>::AccountCurveTreeRootUpdated { root });
        }
    }
}
