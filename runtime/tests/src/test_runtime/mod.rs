pub mod constants;
pub mod ext_builder;

#[cfg(feature = "std")]
use sp_version::NativeVersion;

use codec::Encode;
use frame_support::dispatch::Weight;
use frame_support::parameter_types;
use frame_support::traits::{Currency, Imbalance, KeyOwnerProofSystem, OnUnbalanced};
use frame_support::weights::RuntimeDbWeight;
use frame_system::EnsureRoot;
use sp_core::crypto::Pair as PairTrait;
use sp_core::sr25519::Pair;
use sp_keyring::AccountKeyring;
use sp_runtime::create_runtime_str;
use sp_runtime::traits::{
    BlakeTwo256, Block as BlockT, Extrinsic, NumberFor, StaticLookup, Verify,
};
use sp_runtime::transaction_validity::{InvalidTransaction, TransactionPriority};
use sp_runtime::Perbill;
use sp_version::RuntimeVersion;
use std::cell::RefCell;
use std::convert::From;

use pallet_asset::checkpoint as pallet_checkpoint;
use pallet_balances as balances;
use pallet_committee as committee;
use pallet_corporate_actions::ballot as pallet_corporate_ballot;
use pallet_corporate_actions::distribution as pallet_capital_distribution;
use pallet_group as group;
use pallet_identity::{self as identity, Context};
use pallet_pips as pips;
use pallet_protocol_fee as protocol_fee;
use pallet_session::historical as pallet_session_historical;
use pallet_transaction_payment::RuntimeDispatchInfo;
use pallet_utility;
use polymesh_common_utilities::protocol_fee::ProtocolOp;
use polymesh_primitives::constants::currency::DOLLARS;
use polymesh_primitives::traits::group::GroupTrait;
use polymesh_primitives::traits::CddAndFeeDetails;
use polymesh_primitives::ConstSize;
use polymesh_primitives::{AccountId, BlockNumber, Claim, Moment};
use polymesh_runtime_common::runtime::{BENCHMARK_MAX_INCREASE, VMO};
use polymesh_runtime_common::{merge_active_and_inactive, AvailableBlockRatio, MaximumBlockWeight};

use crate::test_runtime::constants::{EPOCH_DURATION_IN_BLOCKS, MILLISECS_PER_BLOCK};
use crate::test_runtime::ext_builder::{EXTRINSIC_BASE_WEIGHT, TRANSACTION_BYTE_FEE};

type Runtime = TestRuntime;
type CddHandler = TestRuntime;
type Committee = committee::Pallet<TestRuntime, committee::Instance1>;
type CddServiceProvider = group::Pallet<TestRuntime, group::Instance2>;

type Balance = u128;
type RuntimeBaseCallFilter = TestBaseCallFilter;

// 1 in 4 blocks (on average, not counting collisions) will be primary babe blocks.
const PRIMARY_PROBABILITY: (u64, u64) = (1, 4);
const VERSION: RuntimeVersion = RuntimeVersion {
    spec_name: create_runtime_str!("test-runtime"),
    impl_name: create_runtime_str!("test-runtime"),
    authoring_version: 1,
    spec_version: 1,
    impl_version: 1,
    apis: RUNTIME_API_VERSIONS,
    transaction_version: 7,
    state_version: 1,
};

parameter_types! {
    pub const EpochDuration: u64 = EPOCH_DURATION_IN_BLOCKS as u64;
    pub const Version: RuntimeVersion = VERSION;
    pub const ExpectedBlockTime: Moment = MILLISECS_PER_BLOCK;
    pub const IndexDeposit: Balance = DOLLARS;
    pub const MaxNumberOfFungibleAssets: u32 = 100;
    pub const MaxNumberOfNFTsPerLeg: u32 = 10;
    pub const MaxNumberOfNFTs: u32 = 100;
    pub const ImOnlineUnsignedPriority: TransactionPriority = TransactionPriority::max_value();
    pub const MaxSetIdSessionEntries: u32 = 0;
    pub const ReportLongevity: u64 = 1_000;
    pub const MinAuthorities: u32 = 2;
    pub const MaxAuthorities: u32 = 10_000;
    pub const MaxKeys: u32 = 10_000;
    pub const MaxPeerInHeartbeats: u32 = 10_000;
    pub const MaxPeerDataEncodingSize: u32 = 1_000;
    pub const MaxNumberOfCollectionKeys: u8 = u8::MAX;
    pub const MaxNumberOfFungibleMoves: u32 = 10;
    pub const MaxNumberOfNFTsMoves: u32 = 100;
    pub const MaxNumberOfOffChainAssets: u32 = 10;
    pub const MaxNumberOfPortfolios: u32 = (10 + 100) * 2;
    pub const MaxNumberOfVenueSigners: u32 = 50;
    pub const MaxInstructionMediators: u32 = 4;
    pub const MaximumLockPeriod: Moment = 1_440_000; // 24 hours
    pub const MaxAssetMediators: u32 = 4;
    pub const MaxMultiSigSigners: u32 = 50;

    // PIPs
    pub const MaxRefundsAndVotesPruned: u32 = 128;

    // Confidential asset.
    pub const MaxTotalSupply: Balance = 10_000_000_000_000;
}

pub type ConfidentialAssetMaxNumberOfAffirms = ConstSize<10>;
pub type ConfidentialAssetMaxNumberOfLegs = ConstSize<10>;
pub type ConfidentialAssetMaxAssetsPerLeg = ConstSize<4>;
pub type ConfidentialAssetMaxAuditorsPerLeg = ConstSize<{ 4 + 4 }>;
pub type ConfidentialAssetMaxMediatorsPerLeg = ConstSize<{ 4 * 8 }>;
pub type ConfidentialAssetMaxVenueAuditors = ConstSize<4>;
pub type ConfidentialAssetMaxVenueMediators = ConstSize<4>;
pub type ConfidentialAssetMaxAssetAuditors = ConstSize<4>;
pub type ConfidentialAssetMaxAssetMediators = ConstSize<4>;
pub type ConfidentialAssetMaxAssetDataLength = ConstSize<8192>;

#[cfg(feature = "runtime-benchmarks")]
pub type ConfidentialAssetMaxAssetsPerMoveFunds = ConstSize<2000>;
#[cfg(feature = "runtime-benchmarks")]
pub type ConfidentialAssetMaxMoveFunds = ConstSize<2000>;

#[cfg(not(feature = "runtime-benchmarks"))]
pub type ConfidentialAssetMaxAssetsPerMoveFunds = ConstSize<100>;
#[cfg(not(feature = "runtime-benchmarks"))]
pub type ConfidentialAssetMaxMoveFunds = ConstSize<2000>;

pub type ConfidentialAssetBatchHostThreads = ConstSize<8>;

frame_support::construct_runtime!(
    pub enum TestRuntime where
    Block = Block,
    NodeBlock = polymesh_primitives::Block,
    UncheckedExtrinsic = UncheckedExtrinsic,
{
        System: frame_system::{Pallet, Call, Config, Storage, Event<T>} = 0,
        Babe: pallet_babe::{Pallet, Call, Storage, Config, ValidateUnsigned} = 1,
        Timestamp: pallet_timestamp::{Pallet, Call, Storage, Inherent} = 2,
        Indices: pallet_indices::{Pallet, Call, Storage, Config<T>, Event<T>} = 3,
        Balances: pallet_balances::{Pallet, Call, Storage, Config<T>, Event<T>} = 5,
        TransactionPayment: pallet_transaction_payment::{Pallet, Call, Event<T>, Storage} = 6,
        Identity: pallet_identity::{Pallet, Call, Storage, Event<T>, Config<T>} = 7,
        CddServiceProviders: pallet_group::<Instance2>::{Pallet, Call, Storage, Event<T>, Config<T>} = 8,
        PolymeshCommittee: pallet_committee::<Instance1>::{Pallet, Call, Storage, Origin<T>, Event<T>, Config<T>} = 9,
        CommitteeMembership: pallet_group::<Instance1>::{Pallet, Call, Storage, Event<T>, Config<T>} = 10,
        TechnicalCommittee: pallet_committee::<Instance3>::{Pallet, Call, Storage, Origin<T>, Event<T>, Config<T>} = 11,
        TechnicalCommitteeMembership: pallet_group::<Instance3>::{Pallet, Call, Storage, Event<T>, Config<T>} = 12,
        UpgradeCommittee: pallet_committee::<Instance4>::{Pallet, Call, Storage, Origin<T>, Event<T>, Config<T>} = 13,
        UpgradeCommitteeMembership: pallet_group::<Instance4>::{Pallet, Call, Storage, Event<T>, Config<T>} = 14,
        MultiSig: pallet_multisig::{Pallet, Call, Config, Storage, Event<T>} = 15,

        // PoA
        ValidatorSet: validator_set = 17,

        Offences: pallet_offences::{Pallet, Storage, Event} = 18,
        Session: pallet_session::{Pallet, Call, Storage, Event, Config<T>} = 19,
        AuthorityDiscovery: pallet_authority_discovery::{Pallet, Config} = 20,
        Grandpa: pallet_grandpa::{Pallet, Call, Storage, Config, Event} = 21,
        Historical: pallet_session_historical::{Pallet} = 22,
        ImOnline: pallet_im_online::{Pallet, Call, Storage, Event<T>, ValidateUnsigned, Config<T>} = 23,
        RandomnessCollectiveFlip: pallet_insecure_randomness_collective_flip::{Pallet, Storage} = 24,
        Sudo: pallet_sudo::{Pallet, Call, Config<T>, Storage, Event<T>} = 25,
        Asset: pallet_asset::{Pallet, Call, Storage, Config, Event<T>} = 26,
        CapitalDistribution: pallet_capital_distribution::{Pallet, Call, Storage, Event<T>} = 27,
        Checkpoint: pallet_checkpoint::{Pallet, Call, Storage, Event<T>, Config} = 28,
        ComplianceManager: pallet_compliance_manager::{Pallet, Call, Storage, Event<T>} = 29,
        CorporateAction: pallet_corporate_actions::{Pallet, Call, Storage, Event<T>, Config} = 30,
        CorporateBallot: pallet_corporate_ballot::{Pallet, Call, Storage, Event<T>} = 31,
        Permissions: pallet_permissions::{Pallet, Storage} = 32,
        Pips: pallet_pips::{Pallet, Call, Storage, Event<T>, Config<T>} = 33,
        Portfolio: pallet_portfolio::{Pallet, Call, Storage, Event<T>} = 34,
        ProtocolFee: pallet_protocol_fee::{Pallet, Call, Storage, Event<T>, Config} = 35,
        Scheduler: pallet_scheduler::{Pallet, Call, Storage, Event<T>} = 36,
        Settlement: pallet_settlement::{Pallet, Call, Storage, Event<T>, Config} = 37,
        Statistics: pallet_statistics::{Pallet, Call, Storage, Event<T>} = 38,
        Sto: pallet_sto::{Pallet, Call, Storage, Event<T>} = 39,
        Treasury: pallet_treasury::{Pallet, Call, Event<T>} = 40,
        Utility: pallet_utility::{Pallet, Call, Storage, Event<T>} = 41,
        Base: pallet_base::{Pallet, Call, Event} = 42,
        ExternalAgents: pallet_external_agents::{Pallet, Call, Storage, Event<T>} = 43,
        Relayer: pallet_relayer::{Pallet, Call, Storage, Event<T>} = 44,
        Contracts: pallet_contracts::{Pallet, Call, Storage, Event<T>} = 46,
        PolymeshContracts: polymesh_contracts::{Pallet, Call, Storage, Event<T>, Config<T>} = 47,
        Preimage: pallet_preimage::{Pallet, Call, Storage, Event<T>} = 48,
        Nft: pallet_nft::{Pallet, Call, Storage, Event<T>} = 51,
        ConfidentialAsset: pallet_confidential_asset::{Pallet, Call, Storage, Event<T>} = 60,
    }
);

polymesh_runtime_common::runtime_apis! {}

pub type EventTest = RuntimeEvent;

parameter_types! {
    pub MaximumExtrinsicWeight: Weight = AvailableBlockRatio::get()
        .saturating_sub(Perbill::from_percent(10)) * MaximumBlockWeight::get();
    pub const BlockExecutionWeight: Weight = Weight::from_ref_time(10);
    pub TransactionByteFee: Balance = TRANSACTION_BYTE_FEE.with(|v| *v.borrow());
    pub ExtrinsicBaseWeight: Weight = EXTRINSIC_BASE_WEIGHT.with(|v| *v.borrow());
    pub const DbWeight: RuntimeDbWeight = RuntimeDbWeight {
        read: 10,
        write: 100,
    };
}

parameter_types! {
    pub const SS58Prefix: u8 = 12;
    pub const ExistentialDeposit: u64 = 0;
    pub const MaxLocks: u32 = 50;
    pub const MaxLen: u32 = 256;
    pub const AssetNameMaxLength: u32 = 128;
    pub const FundingRoundNameMaxLength: u32 = 128;
    pub const AssetMetadataNameMaxLength: u32 = 256;
    pub const AssetMetadataValueMaxLength: u32 = 8 * 1024;
    pub const AssetMetadataTypeDefMaxLength: u32 = 8 * 1024;
    pub const BlockRangeForTimelock: BlockNumber = 1000;
    pub const MaxTargetIds: u32 = 10;
    pub const MaxDidWhts: u32 = 10;
    pub const MinimumPeriod: u64 = 3;

    pub const MaxStatsPerAsset: u32 = 10 + BENCHMARK_MAX_INCREASE;
    pub const MaxTransferConditionsPerAsset: u32 = 4 + BENCHMARK_MAX_INCREASE;

    pub const MaxConditionComplexity: u32 = 50;
    pub const MaxDefaultTrustedClaimIssuers: usize = 10;
    pub const MaxTrustedIssuerPerCondition: usize = 10;
    pub const MaxSenderConditionsPerCompliance: usize = 30;
    pub const MaxReceiverConditionsPerCompliance: usize = 30;
    pub const MaxCompliancePerRequirement: usize = 10;

    pub MaximumSchedulerWeight: Weight = Perbill::from_percent(80) * MaximumBlockWeight::get();
    pub const MaxScheduledPerBlock: u32 = 50;

    pub const InitialPOLYX: Balance = 41;
    pub const MaxGivenAuths: u32 = 1024;
    pub const SignedClaimHandicap: u64 = 2;
    pub const StorageSizeOffset: u32 = 8;
    pub const MaxDepth: u32 = 100;
    pub const MaxValueSize: u32 = 16_384;

    pub Schedule: pallet_contracts::Schedule<Runtime> = Default::default();
    pub DeletionWeightLimit: Weight = Weight::from_ref_time(500_000_000_000);
    pub DeletionQueueDepth: u32 = 1024;
    pub MaxInLen: u32 = 8 * 1024;
    pub MaxOutLen: u32 = 8 * 1024;
}

thread_local! {
    pub static FORCE_SESSION_END: RefCell<bool> = RefCell::new(false);
    pub static SESSION_LENGTH: RefCell<BlockNumber> = RefCell::new(2);
}

pub type NegativeImbalance<T> =
    <balances::Pallet<T> as Currency<<T as frame_system::Config>::AccountId>>::NegativeImbalance;

impl CddAndFeeDetails<AccountId, RuntimeCall> for TestRuntime {
    fn get_valid_payer(
        _: &RuntimeCall,
        caller: &AccountId,
    ) -> Result<Option<AccountId>, InvalidTransaction> {
        let caller: AccountId = caller.clone();
        Ok(Some(caller))
    }
    fn clear_context() {
        Context::set_current_payer::<Identity>(None);
    }
    fn set_payer_context(payer: Option<AccountId>) {
        Context::set_current_payer::<Identity>(payer);
    }
    fn get_payer_from_context() -> Option<AccountId> {
        Context::current_payer::<Identity>()
    }
}

impl pallet_confidential_asset::Config for TestRuntime {
    type RuntimeEvent = RuntimeEvent;
    type Randomness = pallet_babe::RandomnessFromOneEpochAgo<Runtime>;
    type WeightInfo = pallet_confidential_asset::weights::SubstrateWeight;
    type MaxTotalSupply = MaxTotalSupply;
    type MaxAssetDataLength = ConfidentialAssetMaxAssetDataLength;
    type MaxNumberOfAffirms = ConfidentialAssetMaxNumberOfAffirms;
    type MaxNumberOfLegs = ConfidentialAssetMaxNumberOfLegs;
    type MaxAssetsPerLeg = ConfidentialAssetMaxAssetsPerLeg;
    type MaxAuditorsPerLeg = ConfidentialAssetMaxAuditorsPerLeg;
    type MaxMediatorsPerLeg = ConfidentialAssetMaxMediatorsPerLeg;
    type MaxVenueAuditors = ConfidentialAssetMaxVenueAuditors;
    type MaxVenueMediators = ConfidentialAssetMaxVenueMediators;
    type MaxAssetAuditors = ConfidentialAssetMaxAssetAuditors;
    type MaxAssetMediators = ConfidentialAssetMaxAssetMediators;
    type MaxAssetsPerMoveFunds = ConfidentialAssetMaxAssetsPerMoveFunds;
    type MaxMoveFunds = ConfidentialAssetMaxMoveFunds;
    type BatchHostThreads = ConfidentialAssetBatchHostThreads;
}

impl group::Config<group::Instance1> for TestRuntime {
    type RuntimeEvent = RuntimeEvent;
    type LimitOrigin = EnsureRoot<AccountId>;
    type AddOrigin = EnsureRoot<AccountId>;
    type RemoveOrigin = EnsureRoot<AccountId>;
    type SwapOrigin = EnsureRoot<AccountId>;
    type ResetOrigin = EnsureRoot<AccountId>;
    type MembershipInitialized = committee::Pallet<TestRuntime, committee::Instance1>;
    type MembershipChanged = committee::Pallet<TestRuntime, committee::Instance1>;
    type WeightInfo = polymesh_weights::pallet_group::SubstrateWeight;
}

impl group::Config<group::Instance2> for TestRuntime {
    type RuntimeEvent = RuntimeEvent;
    type LimitOrigin = EnsureRoot<AccountId>;
    type AddOrigin = EnsureRoot<AccountId>;
    type RemoveOrigin = EnsureRoot<AccountId>;
    type SwapOrigin = EnsureRoot<AccountId>;
    type ResetOrigin = EnsureRoot<AccountId>;
    type MembershipInitialized = identity::Pallet<TestRuntime>;
    type MembershipChanged = identity::Pallet<TestRuntime>;
    type WeightInfo = polymesh_weights::pallet_group::SubstrateWeight;
}

impl group::Config<group::Instance3> for TestRuntime {
    type RuntimeEvent = RuntimeEvent;
    type LimitOrigin = EnsureRoot<AccountId>;
    type AddOrigin = EnsureRoot<AccountId>;
    type RemoveOrigin = EnsureRoot<AccountId>;
    type SwapOrigin = EnsureRoot<AccountId>;
    type ResetOrigin = EnsureRoot<AccountId>;
    type MembershipInitialized = TechnicalCommittee;
    type MembershipChanged = TechnicalCommittee;
    type WeightInfo = polymesh_weights::pallet_group::SubstrateWeight;
}

impl group::Config<group::Instance4> for TestRuntime {
    type RuntimeEvent = RuntimeEvent;
    type LimitOrigin = EnsureRoot<AccountId>;
    type AddOrigin = EnsureRoot<AccountId>;
    type RemoveOrigin = EnsureRoot<AccountId>;
    type SwapOrigin = EnsureRoot<AccountId>;
    type ResetOrigin = EnsureRoot<AccountId>;
    type MembershipInitialized = UpgradeCommittee;
    type MembershipChanged = UpgradeCommittee;
    type WeightInfo = polymesh_weights::pallet_group::SubstrateWeight;
}

impl committee::Config<committee::Instance1> for TestRuntime {
    type RuntimeOrigin = RuntimeOrigin;
    type Proposal = RuntimeCall;
    type CommitteeOrigin = VMO<committee::Instance1>;
    type VoteThresholdOrigin = Self::CommitteeOrigin;
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = polymesh_weights::pallet_committee::SubstrateWeight;
}

impl committee::Config<committee::Instance3> for TestRuntime {
    type RuntimeOrigin = RuntimeOrigin;
    type Proposal = RuntimeCall;
    type CommitteeOrigin = EnsureRoot<AccountId>;
    type VoteThresholdOrigin = Self::CommitteeOrigin;
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = polymesh_weights::pallet_committee::SubstrateWeight;
}

impl committee::Config<committee::Instance4> for TestRuntime {
    type RuntimeOrigin = RuntimeOrigin;
    type Proposal = RuntimeCall;
    type CommitteeOrigin = EnsureRoot<AccountId>;
    type VoteThresholdOrigin = Self::CommitteeOrigin;
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = polymesh_weights::pallet_committee::SubstrateWeight;
}

impl pallet_identity::Config for TestRuntime {
    type RuntimeEvent = RuntimeEvent;
    type Proposal = RuntimeCall;
    type CddServiceProviders = CddServiceProvider;
    type Balances = balances::Pallet<TestRuntime>;
    type CddHandler = TestRuntime;
    type Public = <MultiSignature as Verify>::Signer;
    type OffChainSignature = MultiSignature;
    type ProtocolFee = protocol_fee::Pallet<TestRuntime>;
    type GCVotingMajorityOrigin = VMO<committee::Instance1>;
    type WeightInfo = polymesh_weights::pallet_identity::SubstrateWeight;
    type IdentityFn = identity::Pallet<TestRuntime>;
    type SchedulerOrigin = OriginCaller;
    type InitialPOLYX = InitialPOLYX;
    type MaxGivenAuths = MaxGivenAuths;
}

impl pips::Config for TestRuntime {
    type Currency = balances::Pallet<Self>;
    type VotingMajorityOrigin = VMO<committee::Instance1>;
    type GovernanceCommittee = Committee;
    type TechnicalCommitteeVMO = VMO<committee::Instance3>;
    type UpgradeCommitteeVMO = VMO<committee::Instance4>;
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = polymesh_weights::pallet_pips::SubstrateWeight;
    type Scheduler = Scheduler;
    type SchedulerCall = RuntimeCall;
    type MaxRefundsAndVotesPruned = MaxRefundsAndVotesPruned;
}

impl pallet_sudo::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type RuntimeCall = RuntimeCall;
}

pub struct TestBaseCallFilter;

impl frame_support::traits::Contains<RuntimeCall> for TestBaseCallFilter {
    fn contains(c: &RuntimeCall) -> bool {
        match *c {
            RuntimeCall::System(frame_system::Call::set_storage { .. }) => false,
            _ => true,
        }
    }
}

pub struct DealWithFees;

impl OnUnbalanced<NegativeImbalance<TestRuntime>> for DealWithFees {
    fn on_nonzero_unbalanced(amount: NegativeImbalance<TestRuntime>) {
        let target = account_from(5000);
        let positive_imbalance = Balances::deposit_creating(&target, amount.peek());
        let _ = amount.offset(positive_imbalance).same().map_err(|_| 4); // random value mapped for error
    }
}

pub fn account_from(id: u64) -> AccountId {
    let mut enc_id_vec = id.encode();
    enc_id_vec.resize_with(32, Default::default);

    let mut enc_id = [0u8; 32];
    enc_id.copy_from_slice(enc_id_vec.as_slice());

    let pk = *Pair::from_seed(&enc_id).public().as_array_ref();
    pk.into()
}

#[derive(Copy, Clone)]
pub struct User {
    /// The `ring` of the `User` used to derive account related data,
    /// e.g., origins, keys, and balances.
    pub ring: AccountKeyring,
    /// The DID of the `User`.
    /// The `ring` need not be the primary key of this DID.
    pub did: IdentityId,
}

impl User {
    /// Creates a `User` provided a `did` and a `ring`.
    ///
    /// The function is useful when `ring` refers to a secondary key.
    /// At the time of calling, nothing is asserted about `did`'s registration.
    pub const fn new_with(did: IdentityId, ring: AccountKeyring) -> Self {
        User { ring, did }
    }

    /// Creates and registers a `User` for the given `ring` which will act as the primary key.
    pub fn new(ring: AccountKeyring) -> Self {
        Self::new_with(register_keyring_account(ring).unwrap(), ring)
    }

    /// Returns `self`'s `AccountId`. This is based on the `ring`.
    pub fn acc(&self) -> AccountId {
        self.ring.to_account_id()
    }

    /// Returns an `Origin` that can be used to execute extrinsics.
    pub fn origin(&self) -> RuntimeOrigin {
        RuntimeOrigin::signed(self.acc())
    }
}

pub fn register_keyring_account(acc: AccountKeyring) -> Result<IdentityId, &'static str> {
    register_keyring_account_with_balance(acc, 10_000_000)
}

pub fn register_keyring_account_with_balance(
    acc: AccountKeyring,
    balance: Balance,
) -> Result<IdentityId, &'static str> {
    let acc_id = acc.to_account_id();
    make_account_with_balance(acc_id, balance).map(|(_, id)| id)
}

/// It creates an Account and registers its DID.
pub fn make_account_with_balance(
    id: AccountId,
    balance: Balance,
) -> Result<
    (
        <TestRuntime as frame_system::Config>::RuntimeOrigin,
        IdentityId,
    ),
    &'static str,
> {
    let signed_id = RuntimeOrigin::signed(id.clone());
    Balances::make_free_balance_be(&id, balance);

    // If we have CDD providers, first of them executes the registration.
    let cdd_providers = CddServiceProvider::get_members();
    let did = match cdd_providers.into_iter().nth(0) {
        Some(cdd_provider) => {
            let cdd_acc = get_primary_key(cdd_provider);
            let _ = Identity::cdd_register_did(
                RuntimeOrigin::signed(cdd_acc.clone()),
                id.clone(),
                vec![],
            )
            .map_err(|_| "CDD register DID failed")?;

            // Add CDD Claim
            let did = Identity::get_identity(&id).unwrap();
            let cdd_claim = Claim::CustomerDueDiligence(Default::default());
            Identity::add_claim(RuntimeOrigin::signed(cdd_acc), did, cdd_claim, None)
                .map_err(|_| "CDD provider cannot add the CDD claim")?;
            did
        }
        _ => {
            let _ = Identity::testing_cdd_register_did(id.clone(), vec![])
                .map_err(|_| "Register DID failed")?;
            Identity::get_identity(&id).unwrap()
        }
    };

    Ok((signed_id, did))
}

pub fn get_primary_key(target: IdentityId) -> AccountId {
    Identity::get_primary_key(target).expect("Primary key")
}

polymesh_runtime_common::misc_pallet_impls!();
