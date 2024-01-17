// This file is part of the Polymesh distribution (https://github.com/PolymeshAssociation/Polymesh).
// Copyright (c) 2023 Polymesh

//! # Confidential Asset Pallet
//!
//! The Confidential Asset pallet provides privacy of account balances and transaction amounts.
//!
//! ## Overview
//!
//! These pallets call out to the [Confidential Assets library](https://github.com/PolymeshAssociation/confidential_assets)
//! which implements the ZK-proofs for confidential transfers.
//!
//!

#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode, MaxEncodedLen};
use confidential_assets::{
    transaction::ConfidentialTransferProof, AssetId, Balance as ConfidentialBalance, CipherText,
    CompressedElgamalPublicKey, ElgamalPublicKey,
};
use frame_support::{
    dispatch::{DispatchError, DispatchResult, DispatchResultWithPostInfo},
    ensure,
    traits::{Get, Randomness},
    weights::Weight,
    BoundedBTreeMap, BoundedBTreeSet, BoundedVec,
};
use pallet_base::try_next_post;
use polymesh_common_utilities::{
    balances::Config as BalancesConfig, identity::Config as IdentityConfig, GetExtra,
};
use polymesh_host_functions::VerifyConfidentialTransferRequest;
use polymesh_primitives::{
    impl_checked_inc, settlement::VenueId, Balance, IdentityId, Memo, Ticker,
};
use scale_info::TypeInfo;
use sp_io::hashing::blake2_128;
use sp_runtime::{traits::Zero, SaturatedConversion};
use sp_std::collections::btree_map::BTreeMap;
use sp_std::collections::btree_set::BTreeSet;
use sp_std::{convert::From, prelude::*};

type PalletIdentity<T> = pallet_identity::Module<T>;
type System<T> = frame_system::Pallet<T>;

#[cfg(feature = "runtime-benchmarks")]
pub mod benchmarking;

#[cfg(feature = "testing")]
pub mod testing;

pub mod weights;

pub trait WeightInfo {
    fn create_account() -> Weight;
    fn create_confidential_asset() -> Weight;
    fn mint_confidential_asset() -> Weight;
    fn set_asset_frozen() -> Weight;
    fn set_account_asset_frozen() -> Weight;
    fn apply_incoming_balance() -> Weight;
    fn create_venue() -> Weight;
    fn set_venue_filtering() -> Weight;
    fn allow_venues(l: u32) -> Weight;
    fn disallow_venues(l: u32) -> Weight;
    fn add_transaction(l: u32, m: u32) -> Weight;
    fn sender_affirm_transaction(a: u32) -> Weight;
    fn receiver_affirm_transaction() -> Weight;
    fn mediator_affirm_transaction() -> Weight;
    fn execute_transaction(l: u32) -> Weight;
    fn reject_transaction(l: u32) -> Weight;

    fn affirm_transactions<T: Config>(transactions: &[AffirmTransaction<T>]) -> Weight {
        if transactions.len() > 0 {
            let mut sum = Weight::zero();
            for tx in transactions {
                match &tx.leg.party {
                    AffirmParty::Sender(transfers) => {
                        for (_, proof) in &transfers.proofs {
                            sum += match proof.auditor_count() {
                                Ok(count) => Self::sender_affirm_transaction(count as u32),
                                _ => Weight::MAX,
                            };
                        }
                    }
                    AffirmParty::Receiver => {
                        sum += Self::receiver_affirm_transaction();
                    }
                    AffirmParty::Mediator => {
                        sum += Self::mediator_affirm_transaction();
                    }
                }
            }
            sum
        } else {
            // If no transaction to affirm, use the weight of a single mediator affirm.
            Self::mediator_affirm_transaction()
        }
    }
}

/// A global and unique confidential transaction ID.
#[derive(
    Encode,
    Decode,
    MaxEncodedLen,
    TypeInfo,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Default,
    Debug,
)]
pub struct TransactionId(#[codec(compact)] pub u64);
impl_checked_inc!(TransactionId);

/// Transaction leg ID.
///
/// The leg ID is it's index position (i.e. the first leg is 0).
#[derive(
    Encode,
    Decode,
    MaxEncodedLen,
    TypeInfo,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Default,
    Debug,
)]
pub struct TransactionLegId(#[codec(compact)] pub u32);

/// A confidential account that can hold confidential assets.
#[derive(Encode, Decode, MaxEncodedLen, TypeInfo, Copy, Clone, Debug, PartialEq, Eq)]
pub struct ConfidentialAccount(pub CompressedElgamalPublicKey);

impl From<ElgamalPublicKey> for ConfidentialAccount {
    fn from(data: ElgamalPublicKey) -> Self {
        Self(data.into())
    }
}

impl From<&ElgamalPublicKey> for ConfidentialAccount {
    fn from(data: &ElgamalPublicKey) -> Self {
        Self(data.into())
    }
}

/// An auditor account.
///
/// Auditor accounts can't hold confidential assets.
#[derive(
    Encode, Decode, MaxEncodedLen, TypeInfo, Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq,
)]
pub struct AuditorAccount(pub CompressedElgamalPublicKey);

impl From<ElgamalPublicKey> for AuditorAccount {
    fn from(data: ElgamalPublicKey) -> Self {
        Self(data.into())
    }
}

impl From<&ElgamalPublicKey> for AuditorAccount {
    fn from(data: &ElgamalPublicKey) -> Self {
        Self(data.into())
    }
}

/// A set of confidential asset transfers between the same sender & receiver.
#[derive(Clone, Debug, Encode, Decode, TypeInfo, PartialEq, Eq)]
#[scale_info(skip_type_params(T))]
pub struct ConfidentialTransfers<T: Config> {
    pub proofs: BoundedBTreeMap<AssetId, ConfidentialTransferProof, T::MaxAssetsPerLeg>,
}

impl<T: Config> ConfidentialTransfers<T> {
    pub fn new() -> Self {
        Self {
            proofs: Default::default(),
        }
    }

    pub fn insert(&mut self, asset_id: AssetId, proof: ConfidentialTransferProof) -> bool {
        self.proofs.try_insert(asset_id, proof).is_ok()
    }
}

/// Who is affirming the transaction leg.
#[derive(Encode, Decode, TypeInfo, Clone, Debug, PartialEq)]
#[scale_info(skip_type_params(T))]
pub enum AffirmParty<T: Config> {
    Sender(ConfidentialTransfers<T>),
    Receiver,
    Mediator,
}

/// A batch of transactions to affirm.
#[derive(Encode, Decode, TypeInfo, Clone, Debug, PartialEq)]
#[scale_info(skip_type_params(T))]
pub struct AffirmTransactions<T: Config>(BoundedVec<AffirmTransaction<T>, T::MaxNumberOfAffirms>);

impl<T: Config> core::ops::Deref for AffirmTransactions<T> {
    type Target = BoundedVec<AffirmTransaction<T>, T::MaxNumberOfAffirms>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: Config> AffirmTransactions<T> {
    pub fn new() -> Self {
        Self(Default::default())
    }

    pub fn push(&mut self, affirm: AffirmTransaction<T>) -> bool {
        self.0.try_push(affirm).is_ok()
    }
}

/// The transaction and leg to affirm.
#[derive(Encode, Decode, TypeInfo, Clone, Debug, PartialEq)]
#[scale_info(skip_type_params(T))]
pub struct AffirmTransaction<T: Config> {
    pub id: TransactionId,
    pub leg: AffirmLeg<T>,
}

#[derive(Encode, Decode, TypeInfo, Clone, Debug, PartialEq)]
#[scale_info(skip_type_params(T))]
pub struct AffirmLeg<T: Config> {
    leg_id: TransactionLegId,
    party: AffirmParty<T>,
}

impl<T: Config> AffirmLeg<T> {
    pub fn sender(leg_id: TransactionLegId, tx: ConfidentialTransfers<T>) -> Self {
        Self {
            leg_id,
            party: AffirmParty::Sender(tx),
        }
    }

    pub fn receiver(leg_id: TransactionLegId) -> Self {
        Self {
            leg_id,
            party: AffirmParty::Receiver,
        }
    }

    pub fn mediator(leg_id: TransactionLegId) -> Self {
        Self {
            leg_id,
            party: AffirmParty::Mediator,
        }
    }

    pub fn leg_party(&self) -> LegParty {
        match self.party {
            AffirmParty::Sender(_) => LegParty::Sender,
            AffirmParty::Receiver => LegParty::Receiver,
            AffirmParty::Mediator => LegParty::Mediator,
        }
    }
}

/// Which party of the transaction leg.
#[derive(Encode, Decode, MaxEncodedLen, TypeInfo, Clone, Copy, Debug, PartialEq)]
pub enum LegParty {
    Sender,
    Receiver,
    Mediator,
}

/// Confidential asset details.
#[derive(Encode, Decode, TypeInfo, Clone, Default, Debug, PartialEq, Eq)]
#[scale_info(skip_type_params(T))]
pub struct ConfidentialAssetDetails<T: Config> {
    /// Total supply of the asset.
    pub total_supply: Balance,
    /// Asset's owner DID.
    pub owner_did: IdentityId,
    /// Asset data.
    pub data: BoundedVec<u8, T::MaxAssetDataLength>,
    /// Asset ticker (optional)
    pub ticker: Option<Ticker>,
}

/// Confidential transaction leg asset pending state.
#[derive(Encode, Decode, TypeInfo, Clone, Debug, PartialEq, Eq)]
pub struct TransactionLegAssetState {
    pub sender_init_balance: CipherText,
    pub sender_amount: CipherText,
    pub receiver_amount: CipherText,
}

/// Confidential transaction leg pending state.
#[derive(Encode, Decode, TypeInfo, Clone, Debug, Default, PartialEq, Eq)]
pub struct TransactionLegState {
    /// Leg asset pending state.
    pub asset_state: BTreeMap<AssetId, TransactionLegAssetState>,
}

/// Confidential transaction leg details.
#[derive(Encode, Decode, TypeInfo, Clone, Debug, PartialEq, Eq)]
#[scale_info(skip_type_params(T))]
pub struct TransactionLegDetails<T: Config> {
    /// Asset auditors (both Asset & Venue auditors) for each leg asset.
    pub auditors: BoundedBTreeMap<
        AssetId,
        BoundedBTreeSet<AuditorAccount, T::MaxAuditorsPerLeg>,
        T::MaxAssetsPerLeg,
    >,
    /// Confidential account of the sender.
    pub sender: ConfidentialAccount,
    /// Confidential account of the receiver.
    pub receiver: ConfidentialAccount,
    /// Leg mediators (both Asset & Venue mediators).
    pub mediators: BoundedBTreeSet<IdentityId, T::MaxMediatorsPerLeg>,
}

/// Confidential transaction leg.
#[derive(Encode, Decode, TypeInfo, Clone, Debug, PartialEq, Eq)]
#[scale_info(skip_type_params(T))]
pub struct TransactionLeg<T: Config> {
    /// Leg assets.
    pub assets: BoundedBTreeSet<AssetId, T::MaxAssetsPerLeg>,
    /// Confidential account of the sender.
    pub sender: ConfidentialAccount,
    /// Confidential account of the receiver.
    pub receiver: ConfidentialAccount,
    /// Venue auditors.
    pub auditors: BoundedBTreeSet<AuditorAccount, T::MaxVenueAuditors>,
    /// Venue mediators.
    pub mediators: BoundedBTreeSet<IdentityId, T::MaxVenueMediators>,
}

impl<T: Config> TransactionLeg<T> {
    pub fn new(
        asset_id: AssetId,
        sender: ConfidentialAccount,
        receiver: ConfidentialAccount,
    ) -> Option<Self> {
        let mut assets = BoundedBTreeSet::new();
        assets.try_insert(asset_id).ok()?;
        Some(TransactionLeg {
            assets,
            sender,
            receiver,
            auditors: Default::default(),
            mediators: Default::default(),
        })
    }

    pub fn mediators(&self) -> impl Iterator<Item = &IdentityId> {
        self.mediators.iter()
    }

    pub fn mediators_len(&self) -> usize {
        self.mediators.len()
    }
}

/// Confidential auditors and/or mediators.
#[derive(Encode, Decode, MaxEncodedLen, TypeInfo, Clone, Default, Debug, PartialEq, Eq)]
#[scale_info(skip_type_params(T))]
pub struct ConfidentialAuditors<T: Config> {
    /// Auditor public keys.
    pub auditors: BoundedBTreeSet<AuditorAccount, T::MaxAssetAuditors>,
    /// Mediator identities.
    pub mediators: BoundedBTreeSet<IdentityId, T::MaxAssetMediators>,
}

impl<T: Config> ConfidentialAuditors<T> {
    pub fn new() -> Self {
        Self {
            auditors: Default::default(),
            mediators: Default::default(),
        }
    }
}

/// Transaction information.
#[derive(Encode, Decode, TypeInfo, Clone, Default, Debug, PartialEq, Eq)]
pub struct Transaction<BlockNumber> {
    /// Id of the venue this instruction belongs to
    pub venue_id: VenueId,
    /// BlockNumber that the transaction was created.
    pub created_at: BlockNumber,
    /// Memo attached to the transaction.
    pub memo: Option<Memo>,
}

/// Status of a transaction.
#[derive(Encode, Decode, MaxEncodedLen, TypeInfo, Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionStatus<BlockNumber> {
    /// Pending affirmation and execution.
    Pending,
    /// Executed at block.
    Executed(BlockNumber),
    /// Rejected at block.
    Rejected(BlockNumber),
}

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
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

        /// Confidential asset pallet weights.
        type WeightInfo: WeightInfo;

        /// Maximum total supply.
        type MaxTotalSupply: Get<Balance>;

        /// Maximum length of asset data.
        type MaxAssetDataLength: GetExtra<u32>;

        /// Maximum number of affirms in a batch.
        type MaxNumberOfAffirms: GetExtra<u32>;

        /// Maximum number of legs in a confidential transaction.
        type MaxNumberOfLegs: GetExtra<u32>;

        /// Maximum number of assets per leg.
        type MaxAssetsPerLeg: GetExtra<u32>;

        /// Maximum number of auditors per leg.
        type MaxAuditorsPerLeg: GetExtra<u32>;

        /// Maximum number of mediators per leg.
        type MaxMediatorsPerLeg: GetExtra<u32>;

        /// Maximum number of confidential venue auditors.
        type MaxVenueAuditors: GetExtra<u32>;

        /// Maximum number of confidential venue mediators.
        type MaxVenueMediators: GetExtra<u32>;

        /// Maximum number of confidential asset auditors.
        type MaxAssetAuditors: GetExtra<u32>;

        /// Maximum number of confidential asset mediators.
        type MaxAssetMediators: GetExtra<u32>;
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Event for creation of a Confidential account.
        ///
        /// caller DID, confidential account (public key)
        AccountCreated(IdentityId, ConfidentialAccount),
        /// Event for creation of a confidential asset.
        ///
        /// (caller DID, asset id, auditors and mediators)
        ConfidentialAssetCreated(IdentityId, AssetId, ConfidentialAuditors<T>),
        /// Issued confidential assets.
        ///
        /// (caller DID, asset id, amount issued, total_supply)
        Issued(IdentityId, AssetId, Balance, Balance),
        /// A new venue has been created.
        ///
        /// (caller DID, venue_id)
        VenueCreated(IdentityId, VenueId),
        /// Venue filtering changed for an asset.
        ///
        /// (caller DID, asset id, enabled)
        VenueFiltering(IdentityId, AssetId, bool),
        /// Venues added to allow list.
        ///
        /// (caller DID, asset id, Vec<VenueId>)
        VenuesAllowed(IdentityId, AssetId, Vec<VenueId>),
        /// Venues removed from the allow list.
        ///
        /// (caller DID, asset id, Vec<VenueId>)
        VenuesBlocked(IdentityId, AssetId, Vec<VenueId>),
        /// A new transaction has been created
        ///
        /// (caller DID, venue_id, transaction_id, legs, memo)
        TransactionCreated(
            IdentityId,
            VenueId,
            TransactionId,
            BoundedVec<TransactionLegDetails<T>, T::MaxNumberOfLegs>,
            Option<Memo>,
        ),
        /// Confidential transaction executed.
        ///
        /// (caller DID, transaction_id, memo)
        TransactionExecuted(IdentityId, TransactionId, Option<Memo>),
        /// Confidential transaction rejected.
        ///
        /// (caller DID, transaction_id, memo)
        TransactionRejected(IdentityId, TransactionId, Option<Memo>),
        /// Confidential transaction leg affirmed.
        ///
        /// (caller DID, TransactionId, TransactionLegId, AffirmParty, PendingAffirms)
        TransactionAffirmed(
            IdentityId,
            TransactionId,
            TransactionLegId,
            AffirmParty<T>,
            u32,
        ),
        /// Confidential account balance decreased.
        /// This happens when the sender affirms the transaction.
        ///
        /// (confidential account, asset id, encrypted amount, new encrypted balance)
        AccountWithdraw(ConfidentialAccount, AssetId, CipherText, CipherText),
        /// Confidential account balance increased.
        /// This happens when the receiver calls `apply_incoming_balance`.
        ///
        /// (confidential account, asset id, encrypted amount, new encrypted balance)
        AccountDeposit(ConfidentialAccount, AssetId, CipherText, CipherText),
        /// Confidential account has an incoming amount.
        /// This happens when a transaction executes.
        ///
        /// (confidential account, asset id, encrypted amount, new encrypted incoming balance)
        AccountDepositIncoming(ConfidentialAccount, AssetId, CipherText, CipherText),
        /// Confidential asset frozen.
        ///
        /// (identity, asset id)
        AssetFrozen(IdentityId, AssetId),
        /// Confidential asset unfrozen.
        ///
        /// (identity, asset id)
        AssetUnfrozen(IdentityId, AssetId),
        /// Confidential account asset frozen.
        ///
        /// (identity, confidential account, asset id)
        AccountAssetFrozen(IdentityId, ConfidentialAccount, AssetId),
        /// Confidential account asset unfrozen.
        ///
        /// (identity, confidential account, asset id)
        AccountAssetUnfrozen(IdentityId, ConfidentialAccount, AssetId),
    }

    #[pallet::error]
    pub enum Error<T> {
        /// Mediator account hasn't been created yet.
        AuditorAccountMissing,
        /// Confidential account hasn't been created yet.
        ConfidentialAccountMissing,
        /// Confidential account is frozen for the asset.
        AccountAssetFrozen,
        /// Confidential account for the asset is already frozen.
        AccountAssetAlreadyFrozen,
        /// Confidential account for the asset wasn't frozen.
        AccountAssetNotFrozen,
        /// Confidential asset is frozen.
        AssetFrozen,
        /// Confidential asset is already frozen.
        AlreadyFrozen,
        /// Confidential asset wasn't frozen.
        NotFrozen,
        /// A required auditor/mediator is missing.
        RequiredAssetAuditorMissing,
        /// The number of confidential asset auditors doesn't meet the minimum requirement.
        NotEnoughAssetAuditors,
        /// Asset or leg has too many auditors.
        TooManyAuditors,
        /// Asset or leg has too many mediators.
        TooManyMediators,
        /// Confidential mediator account already created.
        AuditorAccountAlreadyCreated,
        /// Confidential account already created.
        ConfidentialAccountAlreadyCreated,
        /// Confidential account's balance already initialized.
        ConfidentialAccountAlreadyInitialized,
        /// Confidential account isn't a valid CompressedEncryptionPubKey.
        InvalidConfidentialAccount,
        /// Mediator account isn't a valid CompressedEncryptionPubKey.
        InvalidAuditorAccount,
        /// The balance values does not fit a confidential balance.
        TotalSupplyAboveConfidentialBalanceLimit,
        /// The user is not authorized.
        Unauthorized,
        /// The asset id is not a registered confidential asset.
        UnknownConfidentialAsset,
        /// The confidential asset has already been created.
        ConfidentialAssetAlreadyCreated,
        /// A confidential asset's total supply can't go above `T::MaxTotalSupply`.
        TotalSupplyOverLimit,
        /// A confidential asset's total supply must be positive.
        TotalSupplyMustBePositive,
        /// The confidential transfer sender proof is invalid.
        InvalidSenderProof,
        /// Venue does not exist.
        InvalidVenue,
        /// Transaction has not been affirmed.
        TransactionNotAffirmed,
        /// Transaction has already been affirmed.
        TransactionAlreadyAffirmed,
        /// Venue does not have required permissions.
        UnauthorizedVenue,
        /// Transaction failed to execute.
        TransactionFailed,
        /// Legs count should matches with the total number of legs in the transaction.
        LegCountTooSmall,
        /// Transaction is unknown.
        UnknownTransaction,
        /// Transaction leg is unknown.
        UnknownTransactionLeg,
        /// Transaction has no legs.
        TransactionNoLegs,
    }

    /// Venue creator.
    ///
    /// venue_id -> Option<IdentityId>
    #[pallet::storage]
    #[pallet::getter(fn venue_creator)]
    pub type VenueCreator<T: Config> = StorageMap<_, Twox64Concat, VenueId, IdentityId>;

    /// Track venues created by an identity.
    /// Only needed for the UI.
    ///
    /// creator_did -> venue_id -> ()
    #[pallet::storage]
    #[pallet::getter(fn identity_venues)]
    pub type IdentityVenues<T: Config> =
        StorageDoubleMap<_, Twox64Concat, IdentityId, Twox64Concat, VenueId, (), ValueQuery>;

    /// Transaction created by a venue.
    /// Only needed for the UI.
    ///
    /// venue_id -> transaction_id -> ()
    #[pallet::storage]
    #[pallet::getter(fn venue_transactions)]
    pub type VenueTransactions<T: Config> =
        StorageDoubleMap<_, Twox64Concat, VenueId, Twox64Concat, TransactionId, (), ValueQuery>;

    /// Venue filtering is enabled for the asset.
    ///
    /// asset id -> filtering_enabled
    #[pallet::storage]
    #[pallet::getter(fn venue_filtering)]
    pub type VenueFiltering<T: Config> = StorageMap<_, Blake2_128Concat, AssetId, bool, ValueQuery>;

    /// Venues that are allowed to create transactions involving a particular asset id.
    ///
    /// asset id -> venue_id -> allowed
    #[pallet::storage]
    #[pallet::getter(fn venue_allow_list)]
    pub type VenueAllowList<T: Config> =
        StorageDoubleMap<_, Blake2_128Concat, AssetId, Twox64Concat, VenueId, bool, ValueQuery>;

    /// Number of venues in the system (It's one more than the actual number)
    #[pallet::storage]
    #[pallet::getter(fn venue_counter)]
    pub type VenueCounter<T: Config> = StorageValue<_, VenueId, ValueQuery>;

    /// Map a ticker to a confidential asset id.
    ///
    /// ticker -> asset id
    #[pallet::storage]
    #[pallet::getter(fn ticker_to_asset_id)]
    pub type TickerToAsset<T: Config> = StorageMap<_, Blake2_128Concat, Ticker, AssetId>;

    /// Details of the confidential asset.
    ///
    /// asset id -> Option<ConfidentialAssetDetails>
    #[pallet::storage]
    #[pallet::getter(fn confidential_asset_details)]
    pub type Details<T: Config> =
        StorageMap<_, Blake2_128Concat, AssetId, ConfidentialAssetDetails<T>>;

    /// Is the confidential asset frozen.
    ///
    /// asset id -> bool
    #[pallet::storage]
    #[pallet::getter(fn asset_frozen)]
    pub type AssetFrozen<T: Config> = StorageMap<_, Blake2_128Concat, AssetId, bool, ValueQuery>;

    /// Confidential asset's auditor/mediators.
    ///
    /// asset id -> Option<ConfidentialAuditors>
    #[pallet::storage]
    #[pallet::getter(fn asset_auditors)]
    pub type AssetAuditors<T: Config> =
        StorageMap<_, Blake2_128Concat, AssetId, ConfidentialAuditors<T>>;

    /// Records the did for a confidential account.
    ///
    /// account -> Option<IdentityId>.
    #[pallet::storage]
    #[pallet::getter(fn account_did)]
    pub type AccountDid<T: Config> =
        StorageMap<_, Blake2_128Concat, ConfidentialAccount, IdentityId>;

    /// Is the confidential account asset frozen.
    ///
    /// account -> asset id -> bool
    #[pallet::storage]
    #[pallet::getter(fn account_asset_frozen)]
    pub type AccountAssetFrozen<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        ConfidentialAccount,
        Blake2_128Concat,
        AssetId,
        bool,
        ValueQuery,
    >;

    /// Contains the encrypted balance of a confidential account.
    ///
    /// account -> asset id -> Option<CipherText>
    #[pallet::storage]
    #[pallet::getter(fn account_balance)]
    pub type AccountBalance<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        ConfidentialAccount,
        Blake2_128Concat,
        AssetId,
        CipherText,
    >;

    /// Accumulates the encrypted incoming balance for a confidential account.
    ///
    /// account -> asset id -> Option<CipherText>
    #[pallet::storage]
    #[pallet::getter(fn incoming_balance)]
    pub type IncomingBalance<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        ConfidentialAccount,
        Blake2_128Concat,
        AssetId,
        CipherText,
    >;

    /// Legs of a transaction.
    ///
    /// transaction_id -> leg_id -> Option<TransactionLegDetails>
    #[pallet::storage]
    #[pallet::getter(fn transaction_legs)]
    pub type TransactionLegs<T: Config> = StorageDoubleMap<
        _,
        Twox64Concat,
        TransactionId,
        Twox64Concat,
        TransactionLegId,
        TransactionLegDetails<T>,
    >;

    /// Pending state for each leg of a transaction.
    ///
    /// transaction_id -> leg_id -> Option<TransactionLegState>
    #[pallet::storage]
    #[pallet::getter(fn transaction_leg_states)]
    pub type TxLegStates<T: Config> = StorageDoubleMap<
        _,
        Twox64Concat,
        TransactionId,
        Twox64Concat,
        TransactionLegId,
        TransactionLegState,
    >;

    /// Number of affirmations pending before transaction is executed.
    ///
    /// transaction_id -> Option<affirms_pending>
    #[pallet::storage]
    #[pallet::getter(fn affirms_pending)]
    pub type PendingAffirms<T: Config> = StorageMap<_, Twox64Concat, TransactionId, u32>;

    /// All parties (identities) of a transaction.
    ///
    /// transaction_id -> identity -> bool
    #[pallet::storage]
    #[pallet::getter(fn transaction_parties)]
    pub type TransactionParties<T: Config> = StorageDoubleMap<
        _,
        Twox64Concat,
        TransactionId,
        Twox64Concat,
        IdentityId,
        bool,
        ValueQuery,
    >;

    /// Number of parties in a transaction.
    ///
    /// transaction_id -> Option<party_count>
    #[pallet::storage]
    #[pallet::getter(fn transaction_party_count)]
    pub type TransactionPartyCount<T: Config> = StorageMap<_, Twox64Concat, TransactionId, u32>;

    /// Track pending transaction affirmations.
    ///
    /// identity -> (transaction_id, leg_id, leg_party) -> Option<bool>
    #[pallet::storage]
    #[pallet::getter(fn user_affirmations)]
    pub type UserAffirmations<T: Config> = StorageDoubleMap<
        _,
        Twox64Concat,
        IdentityId,
        Twox64Concat,
        (TransactionId, TransactionLegId, LegParty),
        bool,
    >;

    /// Transaction statuses.
    ///
    /// transaction_id -> Option<TransactionStatus>
    #[pallet::storage]
    #[pallet::getter(fn transaction_status)]
    pub type TransactionStatuses<T: Config> =
        StorageMap<_, Twox64Concat, TransactionId, TransactionStatus<T::BlockNumber>>;

    /// Details about an instruction.
    ///
    /// transaction_id -> transaction_details
    #[pallet::storage]
    #[pallet::getter(fn transactions)]
    pub type Transactions<T: Config> =
        StorageMap<_, Twox64Concat, TransactionId, Transaction<T::BlockNumber>>;

    /// Number of transactions in the system (It's one more than the actual number)
    #[pallet::storage]
    #[pallet::getter(fn transaction_counter)]
    pub type TransactionCounter<T: Config> = StorageValue<_, TransactionId, ValueQuery>;

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
            VenueCounter::<T>::set(VenueId(1u64));
            TransactionCounter::<T>::set(TransactionId(1u64));
        }
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Register a confidential account.
        ///
        /// # Arguments
        /// * `account` the confidential account to register.
        ///
        /// # Errors
        /// * `BadOrigin` if `origin` isn't signed.
        #[pallet::call_index(0)]
        #[pallet::weight(<T as Config>::WeightInfo::create_account())]
        pub fn create_account(
            origin: OriginFor<T>,
            account: ConfidentialAccount,
        ) -> DispatchResult {
            let caller_did = PalletIdentity::<T>::ensure_perms(origin)?;
            Self::base_create_account(caller_did, account)
        }

        /// Initializes a new confidential security token.
        /// Makes the initiating account the owner of the security token
        /// & the balance of the owner is set to total zero. To set to total supply, `mint_confidential_asset` should
        /// be called after a successful call of this function.
        ///
        /// # Arguments
        /// * `origin` - contains the secondary key of the caller (i.e who signed the transaction to execute this function).
        ///
        /// # Errors
        /// - `TotalSupplyAboveLimit` if `total_supply` exceeds the limit.
        /// - `BadOrigin` if not signed.
        #[pallet::call_index(2)]
        #[pallet::weight(<T as Config>::WeightInfo::create_confidential_asset())]
        pub fn create_confidential_asset(
            origin: OriginFor<T>,
            ticker: Option<Ticker>,
            data: BoundedVec<u8, T::MaxAssetDataLength>,
            auditors: ConfidentialAuditors<T>,
        ) -> DispatchResult {
            let owner_did = PalletIdentity::<T>::ensure_perms(origin)?;
            Self::base_create_confidential_asset(owner_did, ticker, data, auditors)
        }

        /// Mint more assets into the asset issuer's `account`.
        ///
        /// # Arguments
        /// * `origin` - contains the secondary key of the caller (i.e who signed the transaction to execute this function).
        /// * `asset_id` - the asset_id symbol of the token.
        /// * `amount` - amount of tokens to mint.
        /// * `account` - the asset isser's confidential account to receive the minted assets.
        ///
        /// # Errors
        /// - `BadOrigin` if not signed.
        /// - `Unauthorized` if origin is not the owner of the asset.
        /// - `TotalSupplyMustBePositive` if `amount` is zero.
        /// - `TotalSupplyAboveConfidentialBalanceLimit` if `total_supply` exceeds the confidential balance limit.
        /// - `UnknownConfidentialAsset` The asset_id is not a confidential asset.
        #[pallet::call_index(3)]
        #[pallet::weight(<T as Config>::WeightInfo::mint_confidential_asset())]
        pub fn mint_confidential_asset(
            origin: OriginFor<T>,
            asset_id: AssetId,
            amount: Balance,
            account: ConfidentialAccount,
        ) -> DispatchResult {
            let owner_did = PalletIdentity::<T>::ensure_perms(origin)?;
            Self::base_mint_confidential_asset(owner_did, asset_id, amount, account)
        }

        /// Applies any incoming balance to the confidential account balance.
        ///
        /// # Arguments
        /// * `origin` - contains the secondary key of the caller (i.e who signed the transaction to execute this function).
        /// * `account` - the confidential account (Elgamal public key) of the `origin`.
        /// * `asset_id` - AssetId of confidential account.
        ///
        /// # Errors
        /// - `BadOrigin` if not signed.
        #[pallet::call_index(4)]
        #[pallet::weight(<T as Config>::WeightInfo::apply_incoming_balance())]
        pub fn apply_incoming_balance(
            origin: OriginFor<T>,
            account: ConfidentialAccount,
            asset_id: AssetId,
        ) -> DispatchResult {
            let caller_did = PalletIdentity::<T>::ensure_perms(origin)?;
            Self::base_apply_incoming_balance(caller_did, account, asset_id)
        }

        /// Registers a new venue.
        ///
        #[pallet::call_index(5)]
        #[pallet::weight(<T as Config>::WeightInfo::create_venue())]
        pub fn create_venue(origin: OriginFor<T>) -> DispatchResult {
            let did = PalletIdentity::<T>::ensure_perms(origin)?;
            Self::base_create_venue(did)
        }

        /// Enables or disabled venue filtering for a token.
        ///
        /// # Arguments
        /// * `asset_id` - AssetId of the token in question.
        /// * `enabled` - Boolean that decides if the filtering should be enabled.
        #[pallet::call_index(6)]
        #[pallet::weight(<T as Config>::WeightInfo::set_venue_filtering())]
        pub fn set_venue_filtering(
            origin: OriginFor<T>,
            asset_id: AssetId,
            enabled: bool,
        ) -> DispatchResult {
            let did = PalletIdentity::<T>::ensure_perms(origin)?;
            Self::base_set_venue_filtering(did, asset_id, enabled)
        }

        /// Allows additional venues to create instructions involving an asset.
        ///
        /// * `asset_id` - AssetId of the token in question.
        /// * `venues` - Array of venues that are allowed to create instructions for the token in question.
        #[pallet::call_index(7)]
        #[pallet::weight(<T as Config>::WeightInfo::allow_venues(venues.len() as u32))]
        pub fn allow_venues(
            origin: OriginFor<T>,
            asset_id: AssetId,
            venues: Vec<VenueId>,
        ) -> DispatchResult {
            let did = PalletIdentity::<T>::ensure_perms(origin)?;
            Self::base_update_venue_allow_list(did, asset_id, venues, true)
        }

        /// Revokes permission given to venues for creating instructions involving a particular asset.
        ///
        /// * `asset_id` - AssetId of the token in question.
        /// * `venues` - Array of venues that are no longer allowed to create instructions for the token in question.
        #[pallet::call_index(8)]
        #[pallet::weight(<T as Config>::WeightInfo::disallow_venues(venues.len() as u32))]
        pub fn disallow_venues(
            origin: OriginFor<T>,
            asset_id: AssetId,
            venues: Vec<VenueId>,
        ) -> DispatchResult {
            let did = PalletIdentity::<T>::ensure_perms(origin)?;
            Self::base_update_venue_allow_list(did, asset_id, venues, false)
        }

        /// Adds a new transaction.
        #[pallet::call_index(9)]
        #[pallet::weight({
            // Count the number of mediators.
            let m_count = legs.iter().fold(0, |acc, l| {
                acc + l.mediators_len()
            });
            <T as Config>::WeightInfo::add_transaction(legs.len() as u32, m_count as u32)
        })]
        pub fn add_transaction(
            origin: OriginFor<T>,
            venue_id: VenueId,
            legs: BoundedVec<TransactionLeg<T>, T::MaxNumberOfLegs>,
            memo: Option<Memo>,
        ) -> DispatchResultWithPostInfo {
            let did = PalletIdentity::<T>::ensure_perms(origin)?;
            Self::base_add_transaction(did, venue_id, legs, memo)?;
            Ok(().into())
        }

        /// Affirm transactions.
        #[pallet::call_index(10)]
        #[pallet::weight(<T as Config>::WeightInfo::affirm_transactions(transactions.as_slice()))]
        pub fn affirm_transactions(
            origin: OriginFor<T>,
            transactions: AffirmTransactions<T>,
        ) -> DispatchResultWithPostInfo {
            let did = PalletIdentity::<T>::ensure_perms(origin)?;
            Self::base_affirm_transactions(did, transactions)?;
            Ok(().into())
        }

        /// Execute transaction.
        #[pallet::call_index(11)]
        #[pallet::weight(<T as Config>::WeightInfo::execute_transaction(*leg_count))]
        pub fn execute_transaction(
            origin: OriginFor<T>,
            transaction_id: TransactionId,
            leg_count: u32,
        ) -> DispatchResultWithPostInfo {
            let did = PalletIdentity::<T>::ensure_perms(origin)?;
            Self::base_execute_transaction(did, transaction_id, leg_count as usize)?;
            Ok(().into())
        }

        /// Reject pending transaction.
        #[pallet::call_index(12)]
        #[pallet::weight(<T as Config>::WeightInfo::execute_transaction(*leg_count))]
        pub fn reject_transaction(
            origin: OriginFor<T>,
            transaction_id: TransactionId,
            leg_count: u32,
        ) -> DispatchResultWithPostInfo {
            let did = PalletIdentity::<T>::ensure_perms(origin)?;
            Self::base_reject_transaction(did, transaction_id, leg_count as usize)?;
            Ok(().into())
        }

        /// Freeze/unfreeze a confidential asset.
        ///
        /// # Arguments
        /// * `origin` - Must be the asset issuer.
        /// * `asset_id` - confidential asset to freeze/unfreeze.
        /// * `freeze` - freeze/unfreeze.
        ///
        /// # Errors
        /// - `BadOrigin` if not signed.
        #[pallet::call_index(13)]
        #[pallet::weight(<T as Config>::WeightInfo::set_asset_frozen())]
        pub fn set_asset_frozen(
            origin: OriginFor<T>,
            asset_id: AssetId,
            freeze: bool,
        ) -> DispatchResult {
            let did = PalletIdentity::<T>::ensure_perms(origin)?;
            Self::base_set_asset_frozen(did, asset_id, freeze)
        }

        /// The confidential asset issuer can freeze/unfreeze accounts.
        ///
        /// # Arguments
        /// * `origin` - Must be the asset issuer.
        /// * `account` - the confidential account to lock/unlock.
        /// * `asset_id` - AssetId of confidential account.
        /// * `freeze` - freeze/unfreeze.
        ///
        /// # Errors
        /// - `BadOrigin` if not signed.
        #[pallet::call_index(14)]
        #[pallet::weight(<T as Config>::WeightInfo::set_account_asset_frozen())]
        pub fn set_account_asset_frozen(
            origin: OriginFor<T>,
            account: ConfidentialAccount,
            asset_id: AssetId,
            freeze: bool,
        ) -> DispatchResult {
            let did = PalletIdentity::<T>::ensure_perms(origin)?;
            Self::base_set_account_asset_frozen(did, account, asset_id, freeze)
        }
    }
}

impl<T: Config> Pallet<T> {
    fn base_create_account(caller_did: IdentityId, account: ConfidentialAccount) -> DispatchResult {
        // Ensure the confidential account doesn't exist.
        ensure!(
            !AccountDid::<T>::contains_key(&account),
            Error::<T>::ConfidentialAccountAlreadyCreated
        );
        // Link the confidential account to the caller's identity.
        AccountDid::<T>::insert(&account, caller_did);

        Self::deposit_event(Event::<T>::AccountCreated(caller_did, account));
        Ok(())
    }

    pub fn next_asset_id(owner_did: IdentityId, update: bool) -> AssetId {
        let seed = Self::get_seed(update);
        blake2_128(&(b"modlpy/confidential_asset", owner_did, seed).encode())
    }

    fn base_create_confidential_asset(
        owner_did: IdentityId,
        ticker: Option<Ticker>,
        data: BoundedVec<u8, T::MaxAssetDataLength>,
        auditors: ConfidentialAuditors<T>,
    ) -> DispatchResult {
        let asset_id = Self::next_asset_id(owner_did, true);
        // Ensure the asset hasn't been created yet.
        ensure!(
            !Details::<T>::contains_key(asset_id),
            Error::<T>::ConfidentialAssetAlreadyCreated
        );
        // Ensure that there is at least one auditor.
        ensure!(
            auditors.auditors.len() >= 1,
            Error::<T>::NotEnoughAssetAuditors
        );

        if let Some(ticker) = ticker {
            // Ensure unique tickers.
            // TODO: new error variant.
            ensure!(
                !TickerToAsset::<T>::contains_key(ticker),
                Error::<T>::ConfidentialAssetAlreadyCreated
            );
            TickerToAsset::<T>::insert(ticker, asset_id);
        }

        // Ensure the mediators exist.
        for _mediator_did in &auditors.mediators {
            // TODO: validate mediator identity.
        }

        // Store asset auditors.
        AssetAuditors::<T>::insert(asset_id, &auditors);

        let details = ConfidentialAssetDetails {
            total_supply: Zero::zero(),
            owner_did,
            ticker,
            data,
        };
        Details::<T>::insert(asset_id, details);

        Self::deposit_event(Event::<T>::ConfidentialAssetCreated(
            owner_did, asset_id, auditors,
        ));
        Ok(())
    }

    fn base_mint_confidential_asset(
        owner_did: IdentityId,
        asset_id: AssetId,
        amount: Balance,
        account: ConfidentialAccount,
    ) -> DispatchResult {
        // Ensure `owner_did` owns `account`.
        let account_did = Self::account_did(&account);
        ensure!(Some(owner_did) == account_did, Error::<T>::Unauthorized);

        // Ensure the caller is the asset owner and get the asset details.
        let mut details = Self::ensure_asset_owner(asset_id, owner_did)?;

        // The mint amount must be positive.
        ensure!(
            amount != Zero::zero(),
            Error::<T>::TotalSupplyMustBePositive
        );

        // Ensure the total supply doesn't go above `T::MaxTotalSupply`.
        details.total_supply = details.total_supply.saturating_add(amount);
        ensure!(
            details.total_supply < T::MaxTotalSupply::get(),
            Error::<T>::TotalSupplyOverLimit
        );

        // At the moment, `confidential_assets` lib imposes that balances can be at most 64 bits.
        let max_balance = ConfidentialBalance::MAX.saturated_into::<Balance>();
        ensure!(
            details.total_supply <= max_balance,
            Error::<T>::TotalSupplyAboveConfidentialBalanceLimit
        );

        // Ensure the confidential account's balance has been initialized.
        ensure!(
            AccountDid::<T>::contains_key(&account),
            Error::<T>::ConfidentialAccountMissing
        );

        let enc_issued_amount = CipherText::value(amount.into());
        // Deposit the minted assets into the issuer's confidential account.
        Self::account_deposit_amount(&account, asset_id, enc_issued_amount)?;

        // Emit Issue event with new `total_supply`.
        Self::deposit_event(Event::<T>::Issued(
            owner_did,
            asset_id,
            amount,
            details.total_supply,
        ));

        // Update `total_supply`.
        Details::<T>::insert(asset_id, details);
        Ok(())
    }

    fn base_set_asset_frozen(did: IdentityId, asset_id: AssetId, freeze: bool) -> DispatchResult {
        // Ensure the caller is the asset owner.
        Self::ensure_asset_owner(asset_id, did)?;

        match (Self::asset_frozen(&asset_id), freeze) {
            (true, true) => {
                Err(Error::<T>::AlreadyFrozen)?;
            }
            (false, false) => Err(Error::<T>::NotFrozen)?,
            (false, true) => {
                AssetFrozen::<T>::insert(&asset_id, true);
                Self::deposit_event(Event::<T>::AssetFrozen(did, asset_id))
            }
            (true, false) => {
                AssetFrozen::<T>::insert(&asset_id, false);
                Self::deposit_event(Event::<T>::AssetUnfrozen(did, asset_id))
            }
        }

        Ok(())
    }

    fn base_set_account_asset_frozen(
        did: IdentityId,
        account: ConfidentialAccount,
        asset_id: AssetId,
        freeze: bool,
    ) -> DispatchResult {
        // Ensure the caller is the asset owner.
        Self::ensure_asset_owner(asset_id, did)?;

        match (Self::account_asset_frozen(&account, &asset_id), freeze) {
            (true, true) => {
                Err(Error::<T>::AccountAssetAlreadyFrozen)?;
            }
            (false, false) => Err(Error::<T>::AccountAssetNotFrozen)?,
            (false, true) => {
                AccountAssetFrozen::<T>::insert(&account, &asset_id, true);
                Self::deposit_event(Event::<T>::AccountAssetFrozen(did, account, asset_id))
            }
            (true, false) => {
                AccountAssetFrozen::<T>::insert(&account, &asset_id, false);
                Self::deposit_event(Event::<T>::AccountAssetUnfrozen(did, account, asset_id))
            }
        }

        Ok(())
    }

    fn base_apply_incoming_balance(
        caller_did: IdentityId,
        account: ConfidentialAccount,
        asset_id: AssetId,
    ) -> DispatchResult {
        let account_did = Self::get_account_did(&account)?;
        // Ensure the caller is the owner of the confidential account.
        ensure!(account_did == caller_did, Error::<T>::Unauthorized);

        // Take the incoming balance.
        match IncomingBalance::<T>::take(&account, asset_id) {
            Some(incoming_balance) => {
                // If there is an incoming balance, deposit it into the confidential account balance.
                Self::account_deposit_amount(&account, asset_id, incoming_balance)?;
            }
            None => (),
        }

        Ok(())
    }

    // Ensure the caller is the asset owner.
    fn ensure_asset_owner(
        asset_id: AssetId,
        did: IdentityId,
    ) -> Result<ConfidentialAssetDetails<T>, DispatchError> {
        let details = Self::confidential_asset_details(asset_id)
            .ok_or(Error::<T>::UnknownConfidentialAsset)?;

        // Ensure that the caller is the asset owner.
        ensure!(details.owner_did == did, Error::<T>::Unauthorized);
        Ok(details)
    }

    // Ensure the caller is the venue creator.
    fn ensure_venue_creator(id: VenueId, did: IdentityId) -> Result<(), DispatchError> {
        // Get the venue creator.
        let creator_did = Self::venue_creator(id).ok_or(Error::<T>::InvalidVenue)?;
        ensure!(creator_did == did, Error::<T>::Unauthorized);
        Ok(())
    }

    // Ensure the asset allows the venue.
    fn ensure_venue_allowed(asset_id: AssetId, venue_id: &VenueId) -> DispatchResult {
        if Self::venue_filtering(asset_id) {
            ensure!(
                Self::venue_allow_list(asset_id, venue_id),
                Error::<T>::UnauthorizedVenue
            );
        }
        Ok(())
    }

    // Ensure that the asset issuers allows `venue_id`.
    // Also collect mediators and auditors for the leg details.
    fn build_leg_details(
        leg: TransactionLeg<T>,
        venue_id: &VenueId,
        asset_auditors: &mut BTreeMap<AssetId, ConfidentialAuditors<T>>,
    ) -> Result<TransactionLegDetails<T>, DispatchError> {
        use sp_std::collections::btree_map::Entry;

        // leg auditors/mediators.
        let mut leg_auditors = BTreeMap::new();
        let mut leg_mediators = leg.mediators.into_inner();
        let venue_auditors = leg.auditors.into_inner();

        for asset_id in leg.assets {
            let asset = match asset_auditors.entry(asset_id) {
                Entry::Vacant(entry) => {
                    // Ensure that the asset issuer allows this `venue_id`.
                    Self::ensure_venue_allowed(asset_id, venue_id)?;
                    // Ensure that the asset isn't frozen.
                    ensure!(!Self::asset_frozen(asset_id), Error::<T>::AssetFrozen);
                    // Load and cache the required auditors for the asset.
                    entry
                        .insert(
                            Self::asset_auditors(asset_id)
                                .ok_or(Error::<T>::UnknownConfidentialAsset)?,
                        )
                        .clone()
                }
                Entry::Occupied(entry) => entry.get().clone(),
            };
            // Ensure that the sender's asset isn't frozen.
            ensure!(
                !Self::account_asset_frozen(leg.sender, asset_id),
                Error::<T>::AccountAssetFrozen
            );
            // Add the asset mediators to the mediators for this leg.
            leg_mediators.extend(&asset.mediators);
            let auditors = venue_auditors
                .iter()
                .chain(asset.auditors.iter())
                .copied()
                .collect::<BTreeSet<_>>()
                .try_into()
                .map_err(|_| Error::<T>::TooManyAuditors)?;
            leg_auditors.insert(asset_id, auditors);
        }

        Ok(TransactionLegDetails {
            auditors: leg_auditors
                .try_into()
                .map_err(|_| Error::<T>::TooManyAuditors)?,
            sender: leg.sender,
            receiver: leg.receiver,
            mediators: leg_mediators
                .try_into()
                .map_err(|_| Error::<T>::TooManyMediators)?,
        })
    }

    fn base_create_venue(did: IdentityId) -> DispatchResult {
        // Advance venue counter.
        // NB: Venue counter starts with 1.
        let venue_id = VenueCounter::<T>::try_mutate(try_next_post::<T, _>)?;

        // Other commits to storage + emit event.
        VenueCreator::<T>::insert(venue_id, did);
        IdentityVenues::<T>::insert(did, venue_id, ());
        Self::deposit_event(Event::<T>::VenueCreated(did, venue_id));
        Ok(())
    }

    fn base_set_venue_filtering(
        did: IdentityId,
        asset_id: AssetId,
        enabled: bool,
    ) -> DispatchResult {
        if enabled {
            VenueFiltering::<T>::insert(asset_id, enabled);
        } else {
            VenueFiltering::<T>::remove(asset_id);
        }
        Self::deposit_event(Event::<T>::VenueFiltering(did, asset_id, enabled));
        Ok(())
    }

    fn base_update_venue_allow_list(
        did: IdentityId,
        asset_id: AssetId,
        venues: Vec<VenueId>,
        allow: bool,
    ) -> DispatchResult {
        // Ensure the caller is the asset owner.
        Self::ensure_asset_owner(asset_id, did)?;
        if allow {
            for venue in &venues {
                VenueAllowList::<T>::insert(&asset_id, venue, true);
            }
            Self::deposit_event(Event::<T>::VenuesAllowed(did, asset_id, venues));
        } else {
            for venue in &venues {
                VenueAllowList::<T>::remove(&asset_id, venue);
            }
            Self::deposit_event(Event::<T>::VenuesBlocked(did, asset_id, venues));
        }
        Ok(())
    }

    pub fn base_add_transaction(
        did: IdentityId,
        venue_id: VenueId,
        legs: BoundedVec<TransactionLeg<T>, T::MaxNumberOfLegs>,
        memo: Option<Memo>,
    ) -> Result<TransactionId, DispatchError> {
        // Ensure transaction does not have too many legs.
        ensure!(legs.len() > 0, Error::<T>::TransactionNoLegs);

        // Ensure venue exists and the caller is its creator.
        Self::ensure_venue_creator(venue_id, did)?;

        // Advance and get next `transaction_id`.
        let transaction_id = TransactionCounter::<T>::try_mutate(try_next_post::<T, _>)?;
        VenueTransactions::<T>::insert(venue_id, transaction_id, ());

        let mut parties = BTreeSet::new();
        // Add the caller to the parties.
        // Used to allow the caller to execute/reject the transaction.
        parties.insert(did);

        let mut pending_affirms = 0u32;
        let mut asset_auditors = BTreeMap::new();
        let mut leg_details = Vec::new();
        for (i, leg) in legs.into_iter().enumerate() {
            // Check venue filtering and get asset auditors/mediators.
            let leg = Self::build_leg_details(leg, &venue_id, &mut asset_auditors)?;

            let leg_id = TransactionLegId(i as _);
            let sender_did = Self::get_account_did(&leg.sender)?;
            let receiver_did = Self::get_account_did(&leg.receiver)?;
            parties.insert(sender_did);
            UserAffirmations::<T>::insert(
                sender_did,
                (transaction_id, leg_id, LegParty::Sender),
                false,
            );
            parties.insert(receiver_did);
            UserAffirmations::<T>::insert(
                receiver_did,
                (transaction_id, leg_id, LegParty::Receiver),
                false,
            );
            pending_affirms += 2;
            // Add pending affirmations from all Venue & Asset mediators.
            for mediator_did in &leg.mediators {
                parties.insert(*mediator_did);
                pending_affirms += 1;
                UserAffirmations::<T>::insert(
                    mediator_did,
                    (transaction_id, leg_id, LegParty::Mediator),
                    false,
                );
            }
            TransactionLegs::<T>::insert(transaction_id, leg_id, &leg);
            leg_details.push(leg);
        }

        // Track pending affirms.
        PendingAffirms::<T>::insert(transaction_id, pending_affirms);

        // Add parties to transaction.
        TransactionPartyCount::<T>::insert(transaction_id, parties.len() as u32);
        for did in parties {
            TransactionParties::<T>::insert(transaction_id, did, true);
        }

        // Record transaction details and status.
        <Transactions<T>>::insert(
            transaction_id,
            Transaction {
                venue_id,
                created_at: System::<T>::block_number(),
                memo: memo.clone(),
            },
        );
        <TransactionStatuses<T>>::insert(transaction_id, TransactionStatus::Pending);

        Self::deposit_event(Event::<T>::TransactionCreated(
            did,
            venue_id,
            transaction_id,
            // Should never be truncated.
            BoundedVec::truncate_from(leg_details),
            memo,
        ));

        Ok(transaction_id)
    }

    fn base_affirm_transactions(
        caller_did: IdentityId,
        transactions: AffirmTransactions<T>,
    ) -> DispatchResultWithPostInfo {
        // TODO: Return actual weight.
        for tx in transactions.0 {
            Self::base_affirm_transaction(caller_did, tx.id, tx.leg)?;
        }
        Ok(().into())
    }

    fn base_affirm_transaction(
        caller_did: IdentityId,
        transaction_id: TransactionId,
        affirm: AffirmLeg<T>,
    ) -> DispatchResult {
        let leg_id = affirm.leg_id;
        let leg = TransactionLegs::<T>::get(transaction_id, leg_id)
            .ok_or(Error::<T>::UnknownTransactionLeg)?;

        // Ensure the caller hasn't already affirmed this leg.
        let party = affirm.leg_party();
        let caller_affirm = UserAffirmations::<T>::get(caller_did, (transaction_id, leg_id, party));
        ensure!(
            caller_affirm == Some(false),
            Error::<T>::TransactionAlreadyAffirmed
        );

        match &affirm.party {
            AffirmParty::Sender(transfers) => {
                let mut leg_state = TransactionLegState::default();
                let sender = leg.sender;
                let receiver = leg.receiver;

                let sender_did = Self::account_did(&sender);
                ensure!(Some(caller_did) == sender_did, Error::<T>::Unauthorized);

                // Ensure the same number of assets.
                ensure!(
                    transfers.proofs.len() == leg.auditors.len(),
                    Error::<T>::InvalidSenderProof
                );

                for (asset_id, auditors) in leg.auditors {
                    let proof = transfers
                        .proofs
                        .get(&asset_id)
                        .ok_or(Error::<T>::InvalidSenderProof)?;
                    // Get the sender's current balance.
                    let sender_init_balance = Self::account_balance(&sender, asset_id)
                        .ok_or(Error::<T>::ConfidentialAccountMissing)?;

                    let req = VerifyConfidentialTransferRequest {
                        sender: sender.0,
                        sender_balance: sender_init_balance,
                        receiver: receiver.0,
                        auditors: auditors.iter().map(|account| account.0).collect(),
                        proof: proof.encode(),
                        seed: Self::get_seed(true),
                    };

                    // Verify the sender's proof.
                    let resp = req.verify().map_err(|_| Error::<T>::InvalidSenderProof)?;

                    // Withdraw the transaction amount when the sender affirms.
                    let sender_amount = resp.sender_amount;
                    Self::account_withdraw_amount(&sender, asset_id, sender_amount)?;

                    // Store the pending state for this transaction leg.
                    let receiver_amount = resp.receiver_amount;
                    leg_state.asset_state.insert(
                        asset_id,
                        TransactionLegAssetState {
                            sender_init_balance,
                            sender_amount,
                            receiver_amount,
                        },
                    );
                }
                TxLegStates::<T>::insert(transaction_id, leg_id, leg_state);
            }
            AffirmParty::Receiver => {
                let receiver_did = Self::account_did(&leg.receiver);
                ensure!(Some(caller_did) == receiver_did, Error::<T>::Unauthorized);
                // TODO: Create new error, "Sender hasn't affirmed leg".
                ensure!(
                    TxLegStates::<T>::contains_key(transaction_id, leg_id),
                    Error::<T>::TransactionNotAffirmed
                );
            }
            AffirmParty::Mediator => {
                // TODO: check mediator's did.
                //let mediator_did = Self::mediator_account_did(mediator);
                //ensure!(Some(caller_did) == mediator_did, Error::<T>::Unauthorized);
                // TODO: Create new error, "Sender hasn't affirmed leg".
                ensure!(
                    TxLegStates::<T>::contains_key(transaction_id, leg_id),
                    Error::<T>::TransactionNotAffirmed
                );
            }
        }

        // Update affirmations.
        UserAffirmations::<T>::insert(caller_did, (transaction_id, leg_id, party), true);
        let pending = PendingAffirms::<T>::try_mutate(
            transaction_id,
            |pending| -> Result<_, DispatchError> {
                if let Some(ref mut pending) = pending {
                    *pending = pending.saturating_sub(1);
                    Ok(*pending)
                } else {
                    Err(Error::<T>::UnknownTransaction.into())
                }
            },
        )?;

        // Emit affirmation event.
        Self::deposit_event(Event::<T>::TransactionAffirmed(
            caller_did,
            transaction_id,
            leg_id,
            affirm.party,
            pending,
        ));

        Ok(())
    }

    fn base_execute_transaction(
        caller_did: IdentityId,
        transaction_id: TransactionId,
        leg_count: usize,
    ) -> DispatchResult {
        // Get and remove transaction details.
        let details =
            <Transactions<T>>::take(transaction_id).ok_or(Error::<T>::UnknownTransaction)?;

        // Ensure the caller is the venue creator.
        Self::ensure_venue_creator(details.venue_id, caller_did)?;

        // Take transaction legs.
        let legs = TransactionLegs::<T>::drain_prefix(transaction_id).collect::<Vec<_>>();
        ensure!(legs.len() <= leg_count, Error::<T>::LegCountTooSmall);

        // Take pending affirms count and ensure that the transaction has been affirmed.
        let pending_affirms = PendingAffirms::<T>::take(transaction_id);
        ensure!(
            pending_affirms == Some(0),
            Error::<T>::TransactionNotAffirmed
        );

        // Execute transaction legs.
        for (leg_id, leg) in legs {
            Self::execute_leg(transaction_id, leg_id, leg)?;
        }

        // Cleanup transaction.
        Self::cleanup_transaction(caller_did, transaction_id, details, true)?;

        Ok(())
    }

    /// Transfer the confidential asset into the receiver's incoming account balance.
    fn execute_leg(
        transaction_id: TransactionId,
        leg_id: TransactionLegId,
        leg: TransactionLegDetails<T>,
    ) -> DispatchResult {
        // Check affirmations and remove them.
        let sender_did = Self::get_account_did(&leg.sender)?;
        let sender_affirm =
            UserAffirmations::<T>::take(sender_did, (transaction_id, leg_id, LegParty::Sender));
        ensure!(
            sender_affirm == Some(true),
            Error::<T>::TransactionNotAffirmed
        );
        let receiver_did = Self::get_account_did(&leg.receiver)?;
        let receiver_affirm =
            UserAffirmations::<T>::take(receiver_did, (transaction_id, leg_id, LegParty::Receiver));
        ensure!(
            receiver_affirm == Some(true),
            Error::<T>::TransactionNotAffirmed
        );
        // Check mediator affirmations.
        for mediator_did in leg.mediators {
            let mediator_affirm = UserAffirmations::<T>::take(
                mediator_did,
                (transaction_id, leg_id, LegParty::Mediator),
            );
            ensure!(
                mediator_affirm == Some(true),
                Error::<T>::TransactionNotAffirmed
            );
        }

        // Take the transaction leg's pending state.
        let leg_state = TxLegStates::<T>::take(transaction_id, leg_id)
            .ok_or(Error::<T>::TransactionNotAffirmed)?;
        for (asset_id, state) in leg_state.asset_state {
            // Ensure that the asset isn't frozen.
            ensure!(!Self::asset_frozen(asset_id), Error::<T>::AssetFrozen);
            // Ensure that the sender's asset isn't frozen.
            ensure!(
                !Self::account_asset_frozen(leg.sender, asset_id),
                Error::<T>::AccountAssetFrozen
            );
            // Deposit the transaction amount into the receiver's account.
            Self::account_deposit_amount_incoming(&leg.receiver, asset_id, state.receiver_amount);
        }
        Ok(())
    }

    fn base_reject_transaction(
        caller_did: IdentityId,
        transaction_id: TransactionId,
        leg_count: usize,
    ) -> DispatchResult {
        // Check if the caller is a party of the transaction.
        ensure!(
            TransactionParties::<T>::get(transaction_id, caller_did),
            Error::<T>::Unauthorized
        );

        // Take transaction legs.
        let legs = TransactionLegs::<T>::drain_prefix(transaction_id).collect::<Vec<_>>();
        ensure!(legs.len() <= leg_count, Error::<T>::LegCountTooSmall);

        // Remove the pending affirmation count.
        PendingAffirms::<T>::remove(transaction_id);

        // Remove transaction details.
        let details =
            <Transactions<T>>::take(transaction_id).ok_or(Error::<T>::UnknownTransactionLeg)?;

        // Revert transaction legs.  This is needed for legs where the sender
        // has affirmed it with the sender proof.
        for (leg_id, leg) in legs {
            Self::revert_leg(transaction_id, leg_id, leg)?;
        }

        // Cleanup transaction.
        Self::cleanup_transaction(caller_did, transaction_id, details, false)?;

        Ok(())
    }

    /// Revert the leg by transfer the `amount` back to the sender.
    fn revert_leg(
        transaction_id: TransactionId,
        leg_id: TransactionLegId,
        leg: TransactionLegDetails<T>,
    ) -> DispatchResult {
        // Remove user affirmations.
        let sender_did = Self::get_account_did(&leg.sender)?;
        UserAffirmations::<T>::remove(sender_did, (transaction_id, leg_id, LegParty::Sender));
        let receiver_did = Self::get_account_did(&leg.receiver)?;
        UserAffirmations::<T>::remove(receiver_did, (transaction_id, leg_id, LegParty::Receiver));
        // Remove mediator affirmations.
        for mediator_did in leg.mediators {
            UserAffirmations::<T>::remove(
                mediator_did,
                (transaction_id, leg_id, LegParty::Mediator),
            );
        }

        // If the sender affirmed, then return the assets to them.
        if let Some(leg_state) = TxLegStates::<T>::take(transaction_id, leg_id) {
            for (asset_id, state) in leg_state.asset_state {
                // Deposit the transaction amount back into the sender's incoming account.
                Self::account_deposit_amount_incoming(&leg.sender, asset_id, state.sender_amount);
            }
        }

        Ok(())
    }

    /// Cleanup transaction storage after it has been execute/rejected.
    fn cleanup_transaction(
        caller_did: IdentityId,
        transaction_id: TransactionId,
        details: Transaction<T::BlockNumber>,
        is_execute: bool,
    ) -> DispatchResult {
        // Remove transaction parties.
        let party_count = TransactionPartyCount::<T>::take(transaction_id).unwrap_or(u32::MAX);
        // We track how many parties are added to `TransactionParties`, so
        // this `clear_prefix` should remove all parties in a single call.
        let _ = TransactionParties::<T>::clear_prefix(transaction_id, party_count, None);

        let block = System::<T>::block_number();
        let memo = details.memo;
        let (status, event) = if is_execute {
            (
                TransactionStatus::Executed(block),
                Event::<T>::TransactionExecuted(caller_did, transaction_id, memo),
            )
        } else {
            (
                TransactionStatus::Rejected(block),
                Event::<T>::TransactionRejected(caller_did, transaction_id, memo),
            )
        };

        // Update status.
        TransactionStatuses::<T>::insert(transaction_id, status);

        // emit event.
        Self::deposit_event(event);
        Ok(())
    }

    pub fn get_account_did(account: &ConfidentialAccount) -> Result<IdentityId, DispatchError> {
        Self::account_did(account).ok_or_else(|| Error::<T>::ConfidentialAccountMissing.into())
    }

    /// Subtract the `amount` from the confidential account balance.
    fn account_withdraw_amount(
        account: &ConfidentialAccount,
        asset_id: AssetId,
        amount: CipherText,
    ) -> DispatchResult {
        let balance = AccountBalance::<T>::try_mutate(
            account,
            asset_id,
            |balance| -> Result<CipherText, DispatchError> {
                if let Some(ref mut balance) = balance {
                    *balance -= amount;
                    Ok(*balance)
                } else {
                    Err(Error::<T>::ConfidentialAccountMissing.into())
                }
            },
        )?;
        Self::deposit_event(Event::<T>::AccountWithdraw(
            *account, asset_id, amount, balance,
        ));
        Ok(())
    }

    /// Add the `amount` to the confidential account's balance.
    fn account_deposit_amount(
        account: &ConfidentialAccount,
        asset_id: AssetId,
        amount: CipherText,
    ) -> DispatchResult {
        let balance = AccountBalance::<T>::mutate(account, asset_id, |balance| match balance {
            Some(balance) => {
                *balance += amount;
                *balance
            }
            None => {
                *balance = Some(amount);
                amount
            }
        });
        Self::deposit_event(Event::<T>::AccountDeposit(
            *account, asset_id, amount, balance,
        ));
        Ok(())
    }

    /// Add the `amount` to the confidential account's `IncomingBalance` accumulator.
    fn account_deposit_amount_incoming(
        account: &ConfidentialAccount,
        asset_id: AssetId,
        amount: CipherText,
    ) {
        let incoming_balance =
            IncomingBalance::<T>::mutate(account, asset_id, |incoming_balance| {
                match incoming_balance {
                    Some(previous_balance) => {
                        *previous_balance += amount;
                        *previous_balance
                    }
                    None => {
                        *incoming_balance = Some(amount);
                        amount
                    }
                }
            });
        Self::deposit_event(Event::<T>::AccountDepositIncoming(
            *account,
            asset_id,
            amount,
            incoming_balance,
        ));
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
}
