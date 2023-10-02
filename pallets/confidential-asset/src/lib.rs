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
    transaction::{AuditorId, ConfidentialTransferProof},
    Balance as ConfidentialBalance, CipherText, CompressedElgamalPublicKey, ElgamalPublicKey,
};
use frame_support::{
    dispatch::{DispatchError, DispatchResult},
    ensure,
    traits::{Get, Randomness},
    weights::Weight,
    BoundedBTreeMap, BoundedVec,
};
use pallet_base::try_next_post;
use polymesh_common_utilities::{
    balances::Config as BalancesConfig, identity::Config as IdentityConfig, GetExtra,
};
use polymesh_primitives::{
    asset::{AssetName, AssetType},
    impl_checked_inc,
    settlement::VenueId,
    Balance, IdentityId, Memo, Ticker,
};
use scale_info::TypeInfo;
use sp_runtime::{traits::Zero, SaturatedConversion};
use sp_std::collections::btree_map::BTreeMap;
use sp_std::collections::btree_set::BTreeSet;
use sp_std::{convert::From, prelude::*};

use rand_chacha::ChaCha20Rng as Rng;
use rand_core::SeedableRng;

type PalletIdentity<T> = pallet_identity::Module<T>;
type System<T> = frame_system::Pallet<T>;

#[cfg(feature = "runtime-benchmarks")]
pub mod benchmarking;

#[cfg(feature = "testing")]
pub mod testing;

pub mod weights;

pub trait WeightInfo {
    fn create_account() -> Weight;
    fn add_mediator_account() -> Weight;
    fn create_confidential_asset() -> Weight;
    fn mint_confidential_asset() -> Weight;
    fn apply_incoming_balance() -> Weight;
    fn create_venue() -> Weight;
    fn allow_venues(l: u32) -> Weight;
    fn disallow_venues(l: u32) -> Weight;
    fn add_transaction(l: u32) -> Weight;
    fn sender_affirm_transaction() -> Weight;
    fn receiver_affirm_transaction() -> Weight;
    fn mediator_affirm_transaction() -> Weight;
    fn sender_unaffirm_transaction() -> Weight;
    fn receiver_unaffirm_transaction() -> Weight;
    fn mediator_unaffirm_transaction() -> Weight;
    fn execute_transaction(l: u32) -> Weight;
    fn reject_transaction(l: u32) -> Weight;

    fn affirm_transaction(affirm: &AffirmLeg) -> Weight {
        match affirm.party {
            AffirmParty::Sender(_) => Self::sender_affirm_transaction(),
            AffirmParty::Receiver => Self::receiver_affirm_transaction(),
            AffirmParty::Mediator(_) => Self::mediator_affirm_transaction(),
        }
    }

    fn unaffirm_transaction(unaffirm: &UnaffirmLeg) -> Weight {
        match unaffirm.party {
            LegParty::Sender => Self::sender_unaffirm_transaction(),
            LegParty::Receiver => Self::receiver_unaffirm_transaction(),
            LegParty::Mediator(_) => Self::mediator_unaffirm_transaction(),
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
pub struct ConfidentialAccount(CompressedElgamalPublicKey);

impl ConfidentialAccount {
    pub fn into_inner(&self) -> Option<ElgamalPublicKey> {
        self.0.into_public_key()
    }

    pub fn is_valid(&self) -> bool {
        self.0.into_public_key().is_some()
    }
}

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

/// A mediator account.
///
/// Mediator accounts can't hold confidential assets.
#[derive(
    Encode, Decode, MaxEncodedLen, TypeInfo, Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq,
)]
pub struct MediatorAccount(CompressedElgamalPublicKey);

impl MediatorAccount {
    pub fn into_inner(&self) -> Option<ElgamalPublicKey> {
        self.0.into_public_key()
    }

    pub fn is_valid(&self) -> bool {
        self.0.into_public_key().is_some()
    }
}

impl From<ElgamalPublicKey> for MediatorAccount {
    fn from(data: ElgamalPublicKey) -> Self {
        Self(data.into())
    }
}

impl From<&ElgamalPublicKey> for MediatorAccount {
    fn from(data: &ElgamalPublicKey) -> Self {
        Self(data.into())
    }
}

/// Confidential transaction leg.
#[derive(Encode, Decode, TypeInfo, Clone, Debug, PartialEq, Eq)]
#[scale_info(skip_type_params(S))]
pub struct TransactionLeg<S: Get<u32>> {
    /// Asset ticker.
    pub ticker: Ticker,
    /// Confidential account of the sender.
    pub sender: ConfidentialAccount,
    /// Confidential account of the receiver.
    pub receiver: ConfidentialAccount,
    /// Auditors.
    pub auditors: ConfidentialAuditors<S>,
}

impl<S: Get<u32>> TransactionLeg<S> {
    /// Check if the sender/receiver/auditor accounts are valid.
    pub fn verify_accounts(&self) -> bool {
        self.sender.is_valid() && self.receiver.is_valid() && self.auditors.is_valid()
    }

    pub fn sender_account(&self) -> Option<ElgamalPublicKey> {
        self.sender.into_inner()
    }

    pub fn receiver_account(&self) -> Option<ElgamalPublicKey> {
        self.receiver.into_inner()
    }

    pub fn mediators(&self) -> impl Iterator<Item = &MediatorAccount> {
        self.auditors.mediators()
    }
}

/// Confidential transfer sender proof.
#[derive(Encode, Decode, TypeInfo, Clone, Debug, Eq, PartialEq)]
pub struct SenderProof(Vec<u8>);

impl SenderProof {
    pub fn into_tx(&self) -> Option<ConfidentialTransferProof> {
        ConfidentialTransferProof::decode(&mut self.0.as_slice()).ok()
    }
}

/// Who is affirming the transaction leg.
#[derive(Encode, Decode, TypeInfo, Clone, Debug, PartialEq)]
pub enum AffirmParty {
    Sender(Box<SenderProof>),
    Receiver,
    Mediator(MediatorAccount),
}

#[derive(Encode, Decode, TypeInfo, Clone, Debug, PartialEq)]
pub struct AffirmLeg {
    leg_id: TransactionLegId,
    party: AffirmParty,
}

impl AffirmLeg {
    pub fn sender(leg_id: TransactionLegId, tx: ConfidentialTransferProof) -> Self {
        Self {
            leg_id,
            party: AffirmParty::Sender(Box::new(SenderProof(tx.encode()))),
        }
    }

    pub fn receiver(leg_id: TransactionLegId) -> Self {
        Self {
            leg_id,
            party: AffirmParty::Receiver,
        }
    }

    pub fn mediator(leg_id: TransactionLegId, account: MediatorAccount) -> Self {
        Self {
            leg_id,
            party: AffirmParty::Mediator(account),
        }
    }

    pub fn leg_party(&self) -> LegParty {
        match self.party {
            AffirmParty::Sender(_) => LegParty::Sender,
            AffirmParty::Receiver => LegParty::Receiver,
            AffirmParty::Mediator(account) => LegParty::Mediator(account),
        }
    }
}

/// Which party of the transaction leg.
#[derive(Encode, Decode, MaxEncodedLen, TypeInfo, Clone, Copy, Debug, PartialEq)]
pub enum LegParty {
    Sender,
    Receiver,
    Mediator(MediatorAccount),
}

#[derive(Encode, Decode, TypeInfo, Clone, Debug, PartialEq)]
pub struct UnaffirmLeg {
    leg_id: TransactionLegId,
    party: LegParty,
}

impl UnaffirmLeg {
    pub fn sender(leg_id: TransactionLegId) -> Self {
        Self {
            leg_id,
            party: LegParty::Sender,
        }
    }

    pub fn receiver(leg_id: TransactionLegId) -> Self {
        Self {
            leg_id,
            party: LegParty::Receiver,
        }
    }

    pub fn mediator(leg_id: TransactionLegId, account: MediatorAccount) -> Self {
        Self {
            leg_id,
            party: LegParty::Mediator(account),
        }
    }
}

/// Confidential asset details.
#[derive(Encode, Decode, TypeInfo, Clone, Default, Debug, PartialEq, Eq)]
pub struct ConfidentialAssetDetails {
    /// Confidential asset name.
    pub name: AssetName,
    /// Total supply of the asset.
    pub total_supply: Balance,
    /// Asset's owner DID.
    pub owner_did: IdentityId,
    /// Type of the asset.
    pub asset_type: AssetType,
}

/// Confidential transaction role auditor/mediator.
#[derive(Encode, Decode, MaxEncodedLen, TypeInfo, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfidentialTransactionRole {
    /// An auditor that only needs to audit confidential transactions.
    Auditor,
    /// A mediator needs to affirm confidential transactions between identities.
    Mediator,
}

/// Confidential auditors and/or mediators.
#[derive(Encode, Decode, MaxEncodedLen, TypeInfo, Clone, Default, Debug, PartialEq, Eq)]
#[scale_info(skip_type_params(S))]
pub struct ConfidentialAuditors<S: Get<u32>> {
    /// Auditors/Mediators and their role in confidential transactions.
    auditors: BoundedBTreeMap<MediatorAccount, ConfidentialTransactionRole, S>,
}

impl<S: Get<u32>> ConfidentialAuditors<S> {
    /// Check if the auditor accounts are valid.
    pub fn is_valid(&self) -> bool {
        self.auditors.keys().all(|m| m.is_valid())
    }

    /// Auditors are order by there compressed Elgamal public key (`MediatorAccount`).
    /// Assign an `AuditorId` to each auditor for the Confidential transfer proof.
    pub fn build_auditor_map(&self) -> Option<BTreeMap<AuditorId, ElgamalPublicKey>> {
        self.auditors
            .keys()
            .enumerate()
            .map(|(idx, account)| account.into_inner().map(|key| (AuditorId(idx as u32), key)))
            .collect()
    }

    /// Add an auditor/mediator.
    pub fn add_auditor(
        &mut self,
        account: &MediatorAccount,
        role: ConfidentialTransactionRole,
    ) -> Result<Option<ConfidentialTransactionRole>, (MediatorAccount, ConfidentialTransactionRole)>
    {
        self.auditors.try_insert(*account, role)
    }

    /// Get an auditors role.
    pub fn get_auditor_role(
        &self,
        account: &MediatorAccount,
    ) -> Option<ConfidentialTransactionRole> {
        self.auditors.get(account).copied()
    }

    /// Get only the mediators.
    pub fn mediators(&self) -> impl Iterator<Item = &MediatorAccount> {
        self.auditors
            .iter()
            .filter_map(|(account, role)| match role {
                ConfidentialTransactionRole::Mediator => Some(account),
                _ => None,
            })
    }

    /// Get an iterator over all auditors.
    pub fn auditors(
        &self,
    ) -> impl Iterator<Item = (&MediatorAccount, &ConfidentialTransactionRole)> {
        self.auditors.iter()
    }

    /// Returns the number of all auditors (including mediators).
    pub fn len(&self) -> usize {
        self.auditors.len()
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
        frame_system::Config + BalancesConfig + IdentityConfig + pallet_statistics::Config
    {
        /// Pallet's events.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        /// Randomness source.
        type Randomness: Randomness<Self::Hash, Self::BlockNumber>;

        /// Confidential asset pallet weights.
        type WeightInfo: WeightInfo;

        /// Maximum total supply.
        type MaxTotalSupply: Get<Balance>;

        /// Maximum number of legs in a confidential transaction.
        type MaxNumberOfLegs: GetExtra<u32>;

        /// Maximum number of auditors (to limit SenderProof verification time).
        type MaxNumberOfAuditors: GetExtra<u32>;

        /// Maximum number of confidential asset auditors (should be lower then `MaxNumberOfAuditors`).
        type MaxNumberOfAssetAuditors: GetExtra<u32>;
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Event for creation of a Mediator account.
        /// caller DID, Mediator confidential account (public key)
        MediatorAccountCreated(IdentityId, MediatorAccount),
        /// Event for creation of a Confidential account.
        /// caller DID, confidential account (public key), ticker, encrypted balance
        AccountCreated(IdentityId, ConfidentialAccount, Ticker, CipherText),
        /// Event for creation of a confidential asset.
        /// (caller DID, ticker, total supply, asset type)
        ConfidentialAssetCreated(IdentityId, Ticker, Balance, AssetType),
        /// Issued confidential assets.
        /// (caller DID, ticker, amount issued, total_supply)
        Issued(IdentityId, Ticker, Balance, Balance),
        /// A new venue has been created.
        /// (caller DID, venue_id)
        VenueCreated(IdentityId, VenueId),
        /// Venues added to allow list.
        /// (caller DID, ticker, Vec<VenueId>)
        VenuesAllowed(IdentityId, Ticker, Vec<VenueId>),
        /// Venues removed from the allow list.
        /// (caller DID, ticker, Vec<VenueId>)
        VenuesBlocked(IdentityId, Ticker, Vec<VenueId>),
        /// A new transaction has been created
        /// (caller DID, venue_id, transaction_id, legs, memo)
        TransactionCreated(
            IdentityId,
            VenueId,
            TransactionId,
            BoundedVec<TransactionLeg<T::MaxNumberOfAuditors>, T::MaxNumberOfLegs>,
            Option<Memo>,
        ),
        /// Confidential transaction executed.
        /// (caller DID, transaction_id, memo)
        TransactionExecuted(IdentityId, TransactionId, Option<Memo>),
        /// Confidential transaction rejected.
        /// (caller DID, transaction_id, memo)
        TransactionRejected(IdentityId, TransactionId, Option<Memo>),
        /// Confidential transaction leg affirmed.
        /// (caller DID, TransactionId, TransactionLegId, SenderProof)
        TransactionAffirmed(
            IdentityId,
            TransactionId,
            TransactionLegId,
            Option<SenderProof>,
        ),
        /// Confidential account balance decreased.
        /// This happens when the sender affirms the transaction.
        /// (confidential account, ticker, new encrypted balance)
        AccountWithdraw(ConfidentialAccount, Ticker, CipherText),
        /// Confidential account balance increased.
        /// This happens when the sender unaffirms a transaction or
        /// when the receiver calls `apply_incoming_balance`.
        /// (confidential account, ticker, new encrypted balance)
        AccountDeposit(ConfidentialAccount, Ticker, CipherText),
        /// Confidential account has an incoming amount.
        /// This happens when a transaction executes.
        /// (confidential account, ticker, encrypted amount)
        AccountDepositIncoming(ConfidentialAccount, Ticker, CipherText),
    }

    #[pallet::error]
    pub enum Error<T> {
        /// Mediator account hasn't been created yet.
        MediatorAccountMissing,
        /// Confidential account hasn't been created yet.
        ConfidentialAccountMissing,
        /// A required auditor/mediator is missing.
        RequiredAssetAuditorMissing,
        /// A required auditor/mediator has the wrong role.
        RequiredAssetAuditorWrongRole,
        /// The number of confidential asset auditors doesn't meet the minimum requirement.
        NotEnoughAssetAuditors,
        /// Confidential account already created.
        ConfidentialAccountAlreadyCreated,
        /// Confidential account's balance already initialized.
        ConfidentialAccountAlreadyInitialized,
        /// Confidential account isn't a valid CompressedEncryptionPubKey.
        InvalidConfidentialAccount,
        /// Mediator account isn't a valid CompressedEncryptionPubKey.
        InvalidMediatorAccount,
        /// The balance values does not fit a confidential balance.
        TotalSupplyAboveConfidentialBalanceLimit,
        /// The user is not authorized.
        Unauthorized,
        /// The ticker is not a registered confidential asset.
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
        /// Maximum legs that can be in a single instruction.
        TransactionHasTooManyLegs,
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

    /// Venues that are allowed to create transactions involving a particular ticker.
    ///
    /// ticker -> venue_id -> allowed
    #[pallet::storage]
    #[pallet::getter(fn venue_allow_list)]
    pub type VenueAllowList<T: Config> =
        StorageDoubleMap<_, Blake2_128Concat, Ticker, Twox64Concat, VenueId, bool, ValueQuery>;

    /// Number of venues in the system (It's one more than the actual number)
    #[pallet::storage]
    #[pallet::getter(fn venue_counter)]
    pub type VenueCounter<T: Config> = StorageValue<_, VenueId, ValueQuery>;

    /// Details of the confidential asset.
    ///
    /// ticker -> Option<ConfidentialAssetDetails>
    #[pallet::storage]
    #[pallet::getter(fn confidential_asset_details)]
    pub type Details<T: Config> = StorageMap<_, Blake2_128Concat, Ticker, ConfidentialAssetDetails>;

    /// Confidential asset's auditor/mediators.
    ///
    /// ticker -> Option<ConfidentialAuditors>
    #[pallet::storage]
    #[pallet::getter(fn asset_auditors)]
    pub type AssetAuditors<T: Config> =
        StorageMap<_, Blake2_128Concat, Ticker, ConfidentialAuditors<T::MaxNumberOfAssetAuditors>>;

    /// Records the did for a mediator account.
    ///
    /// mediator_account -> Option<IdentityId>.
    #[pallet::storage]
    #[pallet::getter(fn mediator_account_did)]
    pub type MediatorAccountDid<T: Config> =
        StorageMap<_, Blake2_128Concat, MediatorAccount, IdentityId>;

    /// Records the did for a confidential account.
    ///
    /// account -> Option<IdentityId>.
    #[pallet::storage]
    #[pallet::getter(fn account_did)]
    pub type AccountDid<T: Config> =
        StorageMap<_, Blake2_128Concat, ConfidentialAccount, IdentityId>;

    /// Contains the encrypted balance of a confidential account.
    ///
    /// account -> ticker -> Option<CipherText>
    #[pallet::storage]
    #[pallet::getter(fn account_balance)]
    pub type AccountBalance<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        ConfidentialAccount,
        Blake2_128Concat,
        Ticker,
        CipherText,
    >;

    /// Accumulates the encrypted incoming balance for a confidential account.
    ///
    /// account -> ticker -> Option<CipherText>
    #[pallet::storage]
    #[pallet::getter(fn incoming_balance)]
    pub type IncomingBalance<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        ConfidentialAccount,
        Blake2_128Concat,
        Ticker,
        CipherText,
    >;

    /// Legs of a transaction.
    ///
    /// transaction_id -> leg_id -> Option<Leg>
    #[pallet::storage]
    #[pallet::getter(fn transaction_legs)]
    pub type TransactionLegs<T: Config> = StorageDoubleMap<
        _,
        Twox64Concat,
        TransactionId,
        Twox64Concat,
        TransactionLegId,
        TransactionLeg<T::MaxNumberOfAuditors>,
    >;

    /// Stores the sender's initial balance when they affirmed the transaction leg.
    ///
    /// This is needed to verify the sender's proof.  It is only stored
    /// for clients to use during off-chain proof verification.
    ///
    /// (transaction_id, leg_id) -> Option<CipherText>
    #[pallet::storage]
    #[pallet::getter(fn tx_leg_sender_balance)]
    pub type TxLegSenderBalance<T: Config> =
        StorageMap<_, Blake2_128Concat, (TransactionId, TransactionLegId), CipherText>;

    /// Stores the transfer amount encrypted using the sender's public key.
    ///
    /// This is needed to revert the transaction leg.
    ///
    /// (transaction_id, leg_id) -> Option<CipherText>
    #[pallet::storage]
    #[pallet::getter(fn tx_leg_sender_amount)]
    pub type TxLegSenderAmount<T: Config> =
        StorageMap<_, Blake2_128Concat, (TransactionId, TransactionLegId), CipherText>;

    /// Stores the transfer amount encrypted using the receiver's public key.
    ///
    /// This is needed to execute the transaction.
    ///
    /// (transaction_id, leg_id) -> Option<CipherText>
    #[pallet::storage]
    #[pallet::getter(fn tx_leg_receiver_amount)]
    pub type TxLegReceiverAmount<T: Config> =
        StorageMap<_, Blake2_128Concat, (TransactionId, TransactionLegId), CipherText>;

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
        /// Initializes a confidential account for an asset.
        ///
        /// # Arguments
        /// * `ticker` the asset.
        /// * `account` the confidential account to initialize for `ticker`.
        ///
        /// # Errors
        /// * `BadOrigin` if `origin` isn't signed.
        #[pallet::call_index(0)]
        #[pallet::weight(<T as Config>::WeightInfo::create_account())]
        pub fn create_account(
            origin: OriginFor<T>,
            ticker: Ticker,
            account: ConfidentialAccount,
        ) -> DispatchResult {
            let caller_did = PalletIdentity::<T>::ensure_perms(origin)?;
            Self::base_create_account(caller_did, ticker, account)
        }

        /// Stores mediator's public key.
        ///
        /// # Arguments
        /// * `mediator` the public key of the mediator.
        ///
        /// # Errors
        /// * `BadOrigin` if `origin` isn't signed.
        #[pallet::call_index(1)]
        #[pallet::weight(<T as Config>::WeightInfo::add_mediator_account())]
        pub fn add_mediator_account(
            origin: OriginFor<T>,
            mediator: MediatorAccount,
        ) -> DispatchResult {
            let caller_did = PalletIdentity::<T>::ensure_perms(origin)?;
            Self::base_add_mediator_account(caller_did, mediator)
        }

        /// Initializes a new confidential security token.
        /// Makes the initiating account the owner of the security token
        /// & the balance of the owner is set to total zero. To set to total supply, `mint_confidential_asset` should
        /// be called after a successful call of this function.
        ///
        /// # Arguments
        /// * `origin` - contains the secondary key of the caller (i.e who signed the transaction to execute this function).
        /// * `name` - the name of the token.
        /// * `ticker` - the ticker symbol of the token.
        /// * `asset_type` - the asset type.
        ///
        /// # Errors
        /// - `TickerAlreadyRegistered` if the ticker was already registered, e.g., by `origin`.
        /// - `TickerRegistrationExpired` if the ticker's registration has expired.
        /// - `TotalSupplyAboveLimit` if `total_supply` exceeds the limit.
        /// - `BadOrigin` if not signed.
        #[pallet::call_index(2)]
        #[pallet::weight(<T as Config>::WeightInfo::create_confidential_asset())]
        pub fn create_confidential_asset(
            origin: OriginFor<T>,
            name: AssetName,
            ticker: Ticker,
            asset_type: AssetType,
            auditors: ConfidentialAuditors<T::MaxNumberOfAssetAuditors>,
        ) -> DispatchResult {
            let owner_did = PalletIdentity::<T>::ensure_perms(origin)?;
            Self::base_create_confidential_asset(owner_did, name, ticker, asset_type, auditors)
        }

        /// Mint more assets into the asset issuer's `account`.
        ///
        /// # Arguments
        /// * `origin` - contains the secondary key of the caller (i.e who signed the transaction to execute this function).
        /// * `ticker` - the ticker symbol of the token.
        /// * `amount` - amount of tokens to mint.
        /// * `account` - the asset isser's confidential account to receive the minted assets.
        ///
        /// # Errors
        /// - `BadOrigin` if not signed.
        /// - `Unauthorized` if origin is not the owner of the asset.
        /// - `TotalSupplyMustBePositive` if `amount` is zero.
        /// - `TotalSupplyAboveConfidentialBalanceLimit` if `total_supply` exceeds the confidential balance limit.
        /// - `UnknownConfidentialAsset` The ticker is not a confidential asset.
        #[pallet::call_index(3)]
        #[pallet::weight(<T as Config>::WeightInfo::mint_confidential_asset())]
        pub fn mint_confidential_asset(
            origin: OriginFor<T>,
            ticker: Ticker,
            amount: Balance,
            account: ConfidentialAccount,
        ) -> DispatchResult {
            let owner_did = PalletIdentity::<T>::ensure_perms(origin)?;
            Self::base_mint_confidential_asset(owner_did, ticker, amount, account)
        }

        /// Applies any incoming balance to the confidential account balance.
        ///
        /// # Arguments
        /// * `origin` - contains the secondary key of the caller (i.e who signed the transaction to execute this function).
        /// * `account` - the confidential account (Elgamal public key) of the `origin`.
        /// * `ticker` - Ticker of confidential account.
        ///
        /// # Errors
        /// - `BadOrigin` if not signed.
        #[pallet::call_index(4)]
        #[pallet::weight(<T as Config>::WeightInfo::apply_incoming_balance())]
        pub fn apply_incoming_balance(
            origin: OriginFor<T>,
            account: ConfidentialAccount,
            ticker: Ticker,
        ) -> DispatchResult {
            let caller_did = PalletIdentity::<T>::ensure_perms(origin)?;
            Self::base_apply_incoming_balance(caller_did, account, ticker)
        }

        /// Registers a new venue.
        ///
        #[pallet::call_index(5)]
        #[pallet::weight(<T as Config>::WeightInfo::create_venue())]
        pub fn create_venue(origin: OriginFor<T>) -> DispatchResult {
            let did = PalletIdentity::<T>::ensure_perms(origin)?;
            Self::base_create_venue(did)
        }

        /// Allows additional venues to create instructions involving an asset.
        ///
        /// * `ticker` - Ticker of the token in question.
        /// * `venues` - Array of venues that are allowed to create instructions for the token in question.
        #[pallet::call_index(6)]
        #[pallet::weight(<T as Config>::WeightInfo::allow_venues(venues.len() as u32))]
        pub fn allow_venues(
            origin: OriginFor<T>,
            ticker: Ticker,
            venues: Vec<VenueId>,
        ) -> DispatchResult {
            let did = PalletIdentity::<T>::ensure_perms(origin)?;
            Self::base_update_venue_allow_list(did, ticker, venues, true)
        }

        /// Revokes permission given to venues for creating instructions involving a particular asset.
        ///
        /// * `ticker` - Ticker of the token in question.
        /// * `venues` - Array of venues that are no longer allowed to create instructions for the token in question.
        #[pallet::call_index(7)]
        #[pallet::weight(<T as Config>::WeightInfo::disallow_venues(venues.len() as u32))]
        pub fn disallow_venues(
            origin: OriginFor<T>,
            ticker: Ticker,
            venues: Vec<VenueId>,
        ) -> DispatchResult {
            let did = PalletIdentity::<T>::ensure_perms(origin)?;
            Self::base_update_venue_allow_list(did, ticker, venues, false)
        }

        /// Adds a new transaction.
        ///
        /// TODO: Update weight to include auditor count.
        #[pallet::call_index(8)]
        #[pallet::weight(<T as Config>::WeightInfo::add_transaction(legs.len() as u32))]
        pub fn add_transaction(
            origin: OriginFor<T>,
            venue_id: VenueId,
            legs: BoundedVec<TransactionLeg<T::MaxNumberOfAuditors>, T::MaxNumberOfLegs>,
            memo: Option<Memo>,
        ) -> DispatchResultWithPostInfo {
            let did = PalletIdentity::<T>::ensure_perms(origin)?;
            Self::base_add_transaction(did, venue_id, legs, memo)?;
            Ok(().into())
        }

        /// Affirm a transaction.
        #[pallet::call_index(9)]
        #[pallet::weight(<T as Config>::WeightInfo::affirm_transaction(&affirm))]
        pub fn affirm_transaction(
            origin: OriginFor<T>,
            transaction_id: TransactionId,
            affirm: AffirmLeg,
        ) -> DispatchResultWithPostInfo {
            let did = PalletIdentity::<T>::ensure_perms(origin)?;
            Self::base_affirm_transaction(did, transaction_id, affirm)?;
            Ok(().into())
        }

        /// Unaffirm a transaction.
        #[pallet::call_index(10)]
        #[pallet::weight(<T as Config>::WeightInfo::unaffirm_transaction(&unaffirm))]
        pub fn unaffirm_transaction(
            origin: OriginFor<T>,
            transaction_id: TransactionId,
            unaffirm: UnaffirmLeg,
        ) -> DispatchResultWithPostInfo {
            let did = PalletIdentity::<T>::ensure_perms(origin)?;
            Self::base_unaffirm_transaction(did, transaction_id, unaffirm)?;
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
    }
}

impl<T: Config> Pallet<T> {
    fn base_create_account(
        caller_did: IdentityId,
        ticker: Ticker,
        account: ConfidentialAccount,
    ) -> DispatchResult {
        // Ensure the confidential account's balance hasn't been initialized.
        ensure!(
            !AccountBalance::<T>::contains_key(&account, ticker),
            Error::<T>::ConfidentialAccountAlreadyInitialized
        );
        // Ensure the confidential account doesn't exist, or is already linked to the caller's identity.
        AccountDid::<T>::try_mutate(&account, |account_did| -> DispatchResult {
            match account_did {
                Some(account_did) => {
                    // Ensure the caller's identity is the same.
                    ensure!(
                        *account_did == caller_did,
                        Error::<T>::ConfidentialAccountAlreadyCreated
                    );
                }
                None => {
                    // Link the confidential account to the caller's identity.
                    *account_did = Some(caller_did);
                }
            }
            Ok(())
        })?;

        // Initialize the confidential account balance to zero.
        let enc_balance = CipherText::zero();
        AccountBalance::<T>::insert(&account, ticker, enc_balance);

        Self::deposit_event(Event::<T>::AccountCreated(
            caller_did,
            account,
            ticker,
            enc_balance,
        ));
        Ok(())
    }

    fn base_add_mediator_account(
        caller_did: IdentityId,
        account: MediatorAccount,
    ) -> DispatchResult {
        ensure!(account.is_valid(), Error::<T>::InvalidConfidentialAccount);

        MediatorAccountDid::<T>::insert(&account, &caller_did);

        Self::deposit_event(Event::<T>::MediatorAccountCreated(caller_did, account));
        Ok(())
    }

    fn base_create_confidential_asset(
        owner_did: IdentityId,
        name: AssetName,
        ticker: Ticker,
        asset_type: AssetType,
        auditors: ConfidentialAuditors<T::MaxNumberOfAssetAuditors>,
    ) -> DispatchResult {
        // Ensure the asset hasn't been created yet.
        ensure!(
            !Details::<T>::contains_key(ticker),
            Error::<T>::ConfidentialAssetAlreadyCreated
        );
        // Ensure the auditor accounts are valid.
        ensure!(auditors.is_valid(), Error::<T>::InvalidMediatorAccount);
        // Ensure that there is at least one auditor.
        ensure!(auditors.len() >= 1, Error::<T>::NotEnoughAssetAuditors);
        AssetAuditors::<T>::insert(ticker, auditors);

        let details = ConfidentialAssetDetails {
            name,
            total_supply: Zero::zero(),
            owner_did,
            asset_type,
        };
        Details::<T>::insert(ticker, details);

        Self::deposit_event(Event::<T>::ConfidentialAssetCreated(
            owner_did,
            ticker,
            Zero::zero(),
            asset_type,
        ));
        Ok(())
    }

    fn base_mint_confidential_asset(
        owner_did: IdentityId,
        ticker: Ticker,
        amount: Balance,
        account: ConfidentialAccount,
    ) -> DispatchResult {
        // Ensure `owner_did` owns `account`.
        let account_did = Self::account_did(&account);
        ensure!(Some(owner_did) == account_did, Error::<T>::Unauthorized);

        // Ensure the caller is the asset owner and get the asset details.
        let mut details = Self::ensure_asset_owner(ticker, owner_did)?;

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

        ensure!(
            Details::<T>::contains_key(ticker),
            Error::<T>::UnknownConfidentialAsset
        );

        // Ensure the confidential account's balance has been initialized.
        ensure!(
            AccountBalance::<T>::contains_key(&account, ticker),
            Error::<T>::ConfidentialAccountMissing
        );

        let enc_issued_amount = CipherText::value(amount.into());
        // Deposit the minted assets into the issuer's confidential account.
        Self::account_deposit_amount(&account, ticker, enc_issued_amount)?;

        // Emit Issue event with new `total_supply`.
        Self::deposit_event(Event::<T>::Issued(
            owner_did,
            ticker,
            amount,
            details.total_supply,
        ));

        // Update `total_supply`.
        Details::<T>::insert(ticker, details);
        Ok(())
    }

    fn base_apply_incoming_balance(
        caller_did: IdentityId,
        account: ConfidentialAccount,
        ticker: Ticker,
    ) -> DispatchResult {
        let account_did = Self::get_account_did(&account)?;
        // Ensure the caller is the owner of the confidential account.
        ensure!(account_did == caller_did, Error::<T>::Unauthorized);

        // Take the incoming balance.
        match IncomingBalance::<T>::take(&account, ticker) {
            Some(incoming_balance) => {
                // If there is an incoming balance, deposit it into the confidential account balance.
                Self::account_deposit_amount(&account, ticker, incoming_balance)?;
            }
            None => (),
        }

        Ok(())
    }

    // Ensure the caller is the asset owner.
    fn ensure_asset_owner(
        ticker: Ticker,
        did: IdentityId,
    ) -> Result<ConfidentialAssetDetails, DispatchError> {
        let details =
            Self::confidential_asset_details(ticker).ok_or(Error::<T>::UnknownConfidentialAsset)?;

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

    // Ensure that the required asset auditors/mediators are included and
    // that the asset issuer allows `venue_id`.
    fn ensure_valid_leg(
        leg: &TransactionLeg<T::MaxNumberOfAuditors>,
        venue_id: &VenueId,
        asset_auditors: &mut BTreeMap<Ticker, ConfidentialAuditors<T::MaxNumberOfAssetAuditors>>,
    ) -> DispatchResult {
        use sp_std::collections::btree_map::Entry;

        // Ensure all accounts in the leg are valid.
        ensure!(
            leg.verify_accounts(),
            Error::<T>::InvalidConfidentialAccount
        );

        let required_auditors = match asset_auditors.entry(leg.ticker) {
            Entry::Vacant(entry) => {
                // Ensure that the asset issuer allows this `venue_id`.
                ensure!(
                    Self::venue_allow_list(leg.ticker, venue_id),
                    Error::<T>::UnauthorizedVenue
                );
                // Load and cache the required auditors for the asset.
                entry.insert(
                    Self::asset_auditors(leg.ticker).ok_or(Error::<T>::UnknownConfidentialAsset)?,
                )
            }
            Entry::Occupied(entry) => entry.into_mut(),
        };

        // Ensure all required auditors are included in the leg.
        for (account, required_role) in required_auditors.auditors() {
            let role = leg
                .auditors
                .get_auditor_role(account)
                .ok_or(Error::<T>::RequiredAssetAuditorMissing)?;
            ensure!(
                *required_role == role,
                Error::<T>::RequiredAssetAuditorWrongRole
            );
        }
        Ok(())
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

    fn base_update_venue_allow_list(
        did: IdentityId,
        ticker: Ticker,
        venues: Vec<VenueId>,
        allow: bool,
    ) -> DispatchResult {
        // Ensure the caller is the asset owner.
        Self::ensure_asset_owner(ticker, did)?;
        if allow {
            for venue in &venues {
                VenueAllowList::<T>::insert(&ticker, venue, true);
            }
            Self::deposit_event(Event::<T>::VenuesAllowed(did, ticker, venues));
        } else {
            for venue in &venues {
                VenueAllowList::<T>::remove(&ticker, venue);
            }
            Self::deposit_event(Event::<T>::VenuesBlocked(did, ticker, venues));
        }
        Ok(())
    }

    pub fn base_add_transaction(
        did: IdentityId,
        venue_id: VenueId,
        legs: BoundedVec<TransactionLeg<T::MaxNumberOfAuditors>, T::MaxNumberOfLegs>,
        memo: Option<Memo>,
    ) -> Result<TransactionId, DispatchError> {
        // Ensure transaction does not have too many legs.
        ensure!(
            legs.len() <= T::MaxNumberOfLegs::get() as usize,
            Error::<T>::TransactionHasTooManyLegs
        );

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
        for (i, leg) in legs.iter().enumerate() {
            // Ensure the required asset auditors are included and
            // check venue filtering.
            Self::ensure_valid_leg(&leg, &venue_id, &mut asset_auditors)?;

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
            // Get the mediators from the auditors list.
            for mediator in leg.mediators() {
                let mediator_did = Self::get_mediator_did(mediator)?;
                parties.insert(mediator_did);
                pending_affirms += 1;
                UserAffirmations::<T>::insert(
                    mediator_did,
                    (transaction_id, leg_id, LegParty::Mediator(*mediator)),
                    false,
                );
            }
            TransactionLegs::<T>::insert(transaction_id, leg_id, &leg);
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
            legs,
            memo,
        ));

        Ok(transaction_id)
    }

    fn base_affirm_transaction(
        caller_did: IdentityId,
        transaction_id: TransactionId,
        affirm: AffirmLeg,
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

        match affirm.party {
            AffirmParty::Sender(proof) => {
                let init_tx = proof.into_tx().ok_or(Error::<T>::InvalidSenderProof)?;
                let sender_did = Self::account_did(&leg.sender);
                ensure!(Some(caller_did) == sender_did, Error::<T>::Unauthorized);

                // Get sender/receiver accounts from the leg.
                let sender_account = leg
                    .sender_account()
                    .ok_or(Error::<T>::InvalidConfidentialAccount)?;
                let receiver_account = leg
                    .receiver_account()
                    .ok_or(Error::<T>::InvalidConfidentialAccount)?;
                let auditors = leg
                    .auditors
                    .build_auditor_map()
                    .ok_or(Error::<T>::InvalidConfidentialAccount)?;

                // Get the sender's current balance.
                let from_current_balance = Self::account_balance(&leg.sender, leg.ticker)
                    .ok_or(Error::<T>::ConfidentialAccountMissing)?;

                // Verify the sender's proof.
                let mut rng = Self::get_rng();
                init_tx
                    .verify(
                        &sender_account,
                        &from_current_balance,
                        &receiver_account,
                        &auditors,
                        &mut rng,
                    )
                    .map_err(|_| Error::<T>::InvalidSenderProof)?;

                // Withdraw the transaction amount when the sender affirms.
                let sender_amount = init_tx.sender_amount();
                Self::account_withdraw_amount(&leg.sender, leg.ticker, sender_amount)?;

                // Store the pending state for this transaction leg.
                let receiver_amount = init_tx.receiver_amount();
                TxLegSenderBalance::<T>::insert(&(transaction_id, leg_id), from_current_balance);
                TxLegSenderAmount::<T>::insert(&(transaction_id, leg_id), sender_amount);
                TxLegReceiverAmount::<T>::insert(&(transaction_id, leg_id), receiver_amount);

                Self::deposit_event(Event::<T>::TransactionAffirmed(
                    caller_did,
                    transaction_id,
                    leg_id,
                    Some(*proof),
                ));
            }
            AffirmParty::Receiver => {
                let receiver_did = Self::account_did(&leg.receiver);
                ensure!(Some(caller_did) == receiver_did, Error::<T>::Unauthorized);
            }
            AffirmParty::Mediator(mediator) => {
                let mediator_did = Self::mediator_account_did(mediator);
                ensure!(Some(caller_did) == mediator_did, Error::<T>::Unauthorized);
            }
        }
        // Update affirmations.
        UserAffirmations::<T>::insert(caller_did, (transaction_id, leg_id, party), true);
        PendingAffirms::<T>::try_mutate(transaction_id, |pending| -> DispatchResult {
            if let Some(ref mut pending) = pending {
                *pending = pending.saturating_sub(1);
                Ok(())
            } else {
                Err(Error::<T>::UnknownTransaction.into())
            }
        })?;

        Ok(())
    }

    fn base_unaffirm_transaction(
        caller_did: IdentityId,
        transaction_id: TransactionId,
        unaffirm: UnaffirmLeg,
    ) -> DispatchResult {
        let leg_id = unaffirm.leg_id;

        // Ensure the caller has affirmed this leg.
        let caller_affirm =
            UserAffirmations::<T>::get(caller_did, (transaction_id, leg_id, unaffirm.party));
        ensure!(
            caller_affirm == Some(true),
            Error::<T>::TransactionNotAffirmed
        );

        let leg = TransactionLegs::<T>::get(transaction_id, leg_id)
            .ok_or(Error::<T>::UnknownTransactionLeg)?;
        let pending_affirms = match unaffirm.party {
            LegParty::Sender => {
                let sender_did = Self::account_did(&leg.sender);
                ensure!(Some(caller_did) == sender_did, Error::<T>::Unauthorized);

                let mut pending_affirms = 1;
                // If the receiver has affirmed the leg, then we need to invalid their affirmation.
                let receiver_did = Self::get_account_did(&leg.receiver)?;
                UserAffirmations::<T>::mutate(
                    receiver_did,
                    (transaction_id, leg_id, LegParty::Receiver),
                    |affirmed| {
                        if *affirmed == Some(true) {
                            pending_affirms += 1;
                        }
                        *affirmed = Some(false)
                    },
                );
                // If mediators have affirmed the leg, then we need to invalid their affirmation.
                for mediator in leg.mediators() {
                    let mediator_did = Self::get_mediator_did(mediator)?;
                    UserAffirmations::<T>::mutate(
                        mediator_did,
                        (transaction_id, leg_id, LegParty::Mediator(*mediator)),
                        |affirmed| {
                            if *affirmed == Some(true) {
                                pending_affirms += 1;
                            }
                            *affirmed = Some(false)
                        },
                    );
                }

                // Take the transaction leg's pending state.
                TxLegSenderBalance::<T>::remove((transaction_id, leg_id));
                let sender_amount = TxLegSenderAmount::<T>::take((transaction_id, leg_id))
                    .ok_or(Error::<T>::TransactionNotAffirmed)?;
                TxLegReceiverAmount::<T>::remove((transaction_id, leg_id));

                // Deposit the transaction amount back into the sender's account.
                Self::account_deposit_amount(&leg.sender, leg.ticker, sender_amount)?;

                pending_affirms
            }
            LegParty::Receiver => {
                let receiver_did = Self::account_did(&leg.receiver);
                ensure!(Some(caller_did) == receiver_did, Error::<T>::Unauthorized);

                1
            }
            LegParty::Mediator(mediator) => {
                let mediator_did = Self::mediator_account_did(mediator);
                ensure!(Some(caller_did) == mediator_did, Error::<T>::Unauthorized);

                1
            }
        };
        // Update affirmations.
        UserAffirmations::<T>::insert(caller_did, (transaction_id, leg_id, unaffirm.party), false);
        PendingAffirms::<T>::try_mutate(transaction_id, |pending| -> DispatchResult {
            if let Some(ref mut pending) = pending {
                *pending = pending.saturating_add(pending_affirms);
                Ok(())
            } else {
                Err(Error::<T>::UnknownTransaction.into())
            }
        })?;

        Ok(())
    }

    fn base_execute_transaction(
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

        // Take pending affirms count and ensure that the transaction has been affirmed.
        let pending_affirms = PendingAffirms::<T>::take(transaction_id);
        ensure!(
            pending_affirms == Some(0),
            Error::<T>::TransactionNotAffirmed
        );

        // Remove transaction details.
        let details =
            <Transactions<T>>::take(transaction_id).ok_or(Error::<T>::UnknownTransactionLeg)?;

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
        leg: TransactionLeg<T::MaxNumberOfAuditors>,
    ) -> DispatchResult {
        let ticker = leg.ticker;

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
        for mediator in leg.mediators() {
            let mediator_did = Self::get_mediator_did(mediator)?;
            let mediator_affirm = UserAffirmations::<T>::take(
                mediator_did,
                (transaction_id, leg_id, LegParty::Mediator(*mediator)),
            );
            ensure!(
                mediator_affirm == Some(true),
                Error::<T>::TransactionNotAffirmed
            );
        }

        // Take the transaction leg's pending state.
        TxLegSenderBalance::<T>::remove((transaction_id, leg_id));
        TxLegSenderAmount::<T>::remove((transaction_id, leg_id));
        let receiver_amount = TxLegReceiverAmount::<T>::take((transaction_id, leg_id))
            .ok_or(Error::<T>::TransactionNotAffirmed)?;

        // Deposit the transaction amount into the receiver's account.
        Self::account_deposit_amount_incoming(&leg.receiver, ticker, receiver_amount);
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
        leg: TransactionLeg<T::MaxNumberOfAuditors>,
    ) -> DispatchResult {
        // Remove user affirmations.
        let sender_did = Self::get_account_did(&leg.sender)?;
        let sender_affirm =
            UserAffirmations::<T>::take(sender_did, (transaction_id, leg_id, LegParty::Sender));
        let receiver_did = Self::get_account_did(&leg.receiver)?;
        UserAffirmations::<T>::remove(receiver_did, (transaction_id, leg_id, LegParty::Receiver));
        for mediator in leg.mediators() {
            let mediator_did = Self::get_mediator_did(mediator)?;
            UserAffirmations::<T>::remove(
                mediator_did,
                (transaction_id, leg_id, LegParty::Mediator(*mediator)),
            );
        }

        if sender_affirm == Some(true) {
            // Take the transaction leg's pending state.
            match TxLegSenderAmount::<T>::take((transaction_id, leg_id)) {
                Some(sender_amount) => {
                    // Deposit the transaction amount back into the sender's incoming account.
                    Self::account_deposit_amount_incoming(&leg.sender, leg.ticker, sender_amount);
                }
                None => (),
            }
            TxLegSenderBalance::<T>::remove((transaction_id, leg_id));
            TxLegReceiverAmount::<T>::remove((transaction_id, leg_id));
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

    pub fn get_mediator_did(mediator: &MediatorAccount) -> Result<IdentityId, DispatchError> {
        Self::mediator_account_did(mediator)
            .ok_or_else(|| Error::<T>::MediatorAccountMissing.into())
    }

    /// Subtract the `amount` from the confidential account balance.
    fn account_withdraw_amount(
        account: &ConfidentialAccount,
        ticker: Ticker,
        amount: CipherText,
    ) -> DispatchResult {
        let balance = AccountBalance::<T>::try_mutate(
            account,
            ticker,
            |balance| -> Result<CipherText, DispatchError> {
                if let Some(ref mut balance) = balance {
                    *balance -= amount;
                    Ok(*balance)
                } else {
                    Err(Error::<T>::ConfidentialAccountMissing.into())
                }
            },
        )?;
        Self::deposit_event(Event::<T>::AccountWithdraw(*account, ticker, balance));
        Ok(())
    }

    /// Add the `amount` to the confidential account's balance.
    fn account_deposit_amount(
        account: &ConfidentialAccount,
        ticker: Ticker,
        amount: CipherText,
    ) -> DispatchResult {
        let balance = AccountBalance::<T>::try_mutate(
            account,
            ticker,
            |balance| -> Result<CipherText, DispatchError> {
                if let Some(ref mut balance) = balance {
                    *balance += amount;
                    Ok(*balance)
                } else {
                    Err(Error::<T>::ConfidentialAccountMissing.into())
                }
            },
        )?;
        Self::deposit_event(Event::<T>::AccountDeposit(*account, ticker, balance));
        Ok(())
    }

    /// Add the `amount` to the confidential account's `IncomingBalance` accumulator.
    fn account_deposit_amount_incoming(
        account: &ConfidentialAccount,
        ticker: Ticker,
        amount: CipherText,
    ) {
        IncomingBalance::<T>::mutate(account, ticker, |incoming_balance| match incoming_balance {
            Some(previous_balance) => {
                *previous_balance += amount;
            }
            None => {
                *incoming_balance = Some(amount);
            }
        });
        Self::deposit_event(Event::<T>::AccountDepositIncoming(*account, ticker, amount));
    }

    fn get_rng() -> Rng {
        // Increase the nonce each time.
        let nonce = RngNonce::<T>::get();
        RngNonce::<T>::put(nonce.wrapping_add(1));
        // Use the `nonce` and chain randomness to generate a new seed.
        let (random_hash, _) = T::Randomness::random(&(b"ConfidentialAsset", nonce).encode());
        let s = random_hash.as_ref();
        let mut seed = [0u8; 32];
        let len = seed.len().min(s.len());
        seed[..len].copy_from_slice(&s[..len]);
        Rng::from_seed(seed)
    }
}
