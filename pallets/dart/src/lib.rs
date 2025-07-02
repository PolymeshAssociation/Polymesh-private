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
use scale_info::TypeInfo;
use frame_support::{
    dispatch::{DispatchResult, DispatchError},
    ensure,
    traits::{Get, Randomness},
    weights::Weight,
    BoundedVec,
};
use pallet_balances::Config as BalancesConfig;
use pallet_identity::Config as IdentityConfig;
use polymesh_primitives::{
    Balance, IdentityId,
};
use sp_io::hashing::blake2_256;
use sp_std::convert::From;

use polymesh_dart::{
    curve_tree::{
        CurveTreeBackend, CurveTreeRoot, CurveTreeWithBackend, Inner, LeafValue, NodeLocation
    }, AccountPublicKey, AssetId as DartAssetId, AssetState, AuditorOrMediator, EncryptionPublicKey, Error as DartError, LeafIndex, NodeLevel, PallasParameters, VestaParameters, ACCOUNT_TREE_HEIGHT, ACCOUNT_TREE_L, ASSET_TREE_GENS, ASSET_TREE_HEIGHT, ASSET_TREE_L
};

type PalletIdentity<T> = pallet_identity::Pallet<T>;

pub mod weights;

pub trait WeightInfo {
    fn register_account() -> Weight;
    fn create_asset() -> Weight;
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

pub fn hash_curve_tree_root<const L: usize>(root: CurveTreeRoot<L>) -> CurveTreeRootHash {
    blake2_256(&(b"modlpy/dart_root_hash", &root).encode())
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

impl<T: Config> CurveTreeBackend<ASSET_TREE_L, 1, PallasParameters, VestaParameters> for AssetCurveTreeStorage<T> {
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

    fn get_leaf(&self, leaf_index: LeafIndex) -> Result<Option<LeafValue<PallasParameters>>, Self::Error> {
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

    fn get_inner_node(&self, location: NodeLocation<ASSET_TREE_L>) -> Result<Option<Inner<1, PallasParameters, VestaParameters>>, Self::Error> {
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

impl<T: Config> CurveTreeBackend<ACCOUNT_TREE_L, 1, PallasParameters, VestaParameters> for AccountCurveTreeStorage<T> {
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

    fn get_leaf(&self, leaf_index: LeafIndex) -> Result<Option<LeafValue<PallasParameters>>, Self::Error> {
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

    fn get_inner_node(&self, location: NodeLocation<ACCOUNT_TREE_L>) -> Result<Option<Inner<1, PallasParameters, VestaParameters>>, Self::Error> {
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

pub type AssetCurveTree<T> = CurveTreeWithBackend<
    ASSET_TREE_L,
    1,
    PallasParameters,
    VestaParameters,
    AssetCurveTreeStorage<T>,
    Error<T>,
>;
pub type AccountCurveTree<T> = CurveTreeWithBackend<
    ACCOUNT_TREE_L,
    1,
    PallasParameters,
    VestaParameters,
    AccountCurveTreeStorage<T>,
    Error<T>,
>;

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::pallet_prelude::{OptionQuery, *};
    use frame_system::pallet_prelude::*;

    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    /// Configuration trait.
    #[pallet::config]
    pub trait Config:
        frame_system::Config
        + BalancesConfig
        + IdentityConfig
        + pallet_statistics::Config
        + core::fmt::Debug
    {
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
    }

    #[pallet::error]
    pub enum Error<T> {
        /// Dart account hasn't been registered yet.
        DartAccountMissing,
        /// Dart account already exists.
        DartAccountAlreadyCreated,
        /// CurveTree error.
        CurveTreeError,
        /// Leaf not found in the curve tree.
        LeafNotFound,
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
    pub(super) type NextAccountLeafIndex<T: Config> =
        StorageValue<_, LeafIndex, ValueQuery>;
    
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

    #[pallet::genesis_config]
    #[derive(Default)]
    pub struct GenesisConfig {}

    #[pallet::genesis_build]
    impl<T: Config> GenesisBuild<T> for GenesisConfig {
        fn build(&self) {
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
                Error::<T>::DartAccountAlreadyCreated
            );
            // Ensure the encryption key doesn't exist.
            ensure!(
                !EncryptionKeyAccount::<T>::contains_key(&encryption_key),
                Error::<T>::DartAccountAlreadyCreated
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
    }
}

impl<T: Config> Pallet<T> {
    /// Create a new DART asset.
    pub fn base_create_asset(owner_did: IdentityId, auditor_or_mediator: AuditorOrMediator, data: BoundedVec<u8, T::MaxAssetDataLength>) -> Result<DartAssetId, DispatchError> {
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
    pub fn get_asset_curve_tree() -> Result<AssetCurveTree<T>, DispatchError> {
        Ok(AssetCurveTree::<T>::new(ASSET_TREE_HEIGHT, ASSET_TREE_GENS)?)
    }

    /// Get the account curve tree interface.
    pub fn get_account_curve_tree() -> Result<AccountCurveTree<T>, DispatchError> {
        Ok(AccountCurveTree::<T>::new(ACCOUNT_TREE_HEIGHT, ASSET_TREE_GENS)?)
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
        let asset_leaf = asset_state.commitment()
            .and_then(|c| c.as_leaf_value())
            .map_err(Error::<T>::from)?;

        // Update the asset curve tree with the new asset.
        let mut asset_curve_tree = Self::get_asset_curve_tree()?;
        if is_new {
            asset_curve_tree
                .insert_leaf(asset_leaf)?;
        } else {
            asset_curve_tree
                .update_leaf(asset_id.into(), asset_leaf)?;
        }

        Ok(())
    }

    /// Ensure DART account is registered.
    pub fn ensure_dart_account_registered(
        account: &AccountPublicKey,
    ) -> Result<IdentityId, Error<T>> {
        AccountDid::<T>::get(account).ok_or(Error::<T>::DartAccountMissing)
    }

    /// Ensure DART account encryption key is registered.
    pub fn ensure_dart_account_encryption_key_registered(
        encryption_key: &EncryptionPublicKey,
    ) -> Result<AccountPublicKey, Error<T>> {
        EncryptionKeyAccount::<T>::get(encryption_key)
            .ok_or(Error::<T>::DartAccountMissing)
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
}
