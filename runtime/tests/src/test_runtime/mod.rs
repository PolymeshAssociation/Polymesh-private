pub mod constants;
pub mod ext_builder;

#[cfg(feature = "std")]
use sp_version::NativeVersion;

use codec::Encode;
use frame_support::dispatch::{DispatchInfo, DispatchResult, Weight};
use frame_support::parameter_types;
use frame_support::traits::{Currency, Imbalance, KeyOwnerProofSystem, OnUnbalanced};
use frame_support::weights::RuntimeDbWeight;
use frame_system::EnsureRoot;
use sp_core::crypto::Pair as PairTrait;
use sp_core::sr25519::Pair;
use sp_keyring::AccountKeyring;
use sp_runtime::create_runtime_str;
use sp_runtime::curve::PiecewiseLinear;
use sp_runtime::traits::{
    BlakeTwo256, Block as BlockT, Extrinsic, NumberFor, StaticLookup, Verify,
};
use sp_runtime::transaction_validity::{
    InvalidTransaction, TransactionPriority, TransactionValidity, ValidTransaction,
};
use sp_runtime::{Perbill, Permill};
use sp_version::RuntimeVersion;
use std::cell::RefCell;
use std::convert::From;

use pallet_asset::checkpoint as pallet_checkpoint;
use pallet_balances as balances;
use pallet_committee as committee;
use pallet_corporate_actions::ballot as corporate_ballots;
use pallet_corporate_actions::distribution as capital_distributions;
use pallet_group as group;
use pallet_identity as identity;
use pallet_multisig as multisig;
use pallet_pips as pips;
use pallet_portfolio as portfolio;
use pallet_protocol_fee as protocol_fee;
use pallet_session::historical as pallet_session_historical;
use pallet_transaction_payment::RuntimeDispatchInfo;
use pallet_utility;
use polymesh_common_utilities::constants::currency::{DOLLARS, POLY};
use polymesh_common_utilities::protocol_fee::ProtocolOp;
use polymesh_common_utilities::traits::group::GroupTrait;
use polymesh_common_utilities::traits::transaction_payment::{CddAndFeeDetails, ChargeTxFee};
use polymesh_common_utilities::{ConstSize, Context, TestUtilsFn};
use polymesh_primitives::{AccountId, BlockNumber, Claim, Moment};
use polymesh_runtime_common::runtime::{BENCHMARK_MAX_INCREASE, VMO};
use polymesh_runtime_common::{merge_active_and_inactive, AvailableBlockRatio, MaximumBlockWeight};

use crate::test_runtime::constants::{EPOCH_DURATION_IN_BLOCKS, MILLISECS_PER_BLOCK};
use crate::test_runtime::ext_builder::{EXTRINSIC_BASE_WEIGHT, TRANSACTION_BYTE_FEE};

type Runtime = TestRuntime;
type CddHandler = TestRuntime;
type Committee = committee::Module<TestRuntime, committee::Instance1>;
type CddServiceProvider = group::Module<TestRuntime, group::Instance2>;

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

pallet_staking_reward_curve::build! {
    const REWARD_CURVE: PiecewiseLinear<'_> = curve!(
        min_inflation: 0_025_000,
        max_inflation: 0_140_000,
        ideal_stake: 0_700_000,
        falloff: 0_050_000,
        max_piece_count: 40,
        test_precision: 0_005_000,
    );
}

parameter_types! {
    pub const EpochDuration: u64 = EPOCH_DURATION_IN_BLOCKS as u64;
    pub const Version: RuntimeVersion = VERSION;
    pub const ExpectedBlockTime: Moment = MILLISECS_PER_BLOCK;
    pub const SessionsPerEra: sp_staking::SessionIndex = 3;
    pub const BondingDuration: pallet_staking::EraIndex = 7;
    pub const SlashDeferDuration: pallet_staking::EraIndex = 4;
    pub const ElectionLookahead: BlockNumber = EPOCH_DURATION_IN_BLOCKS / 4;
    pub const MaxIterations: u32 = 10;
    pub MinSolutionScoreBump: Perbill = Perbill::from_rational(5u32, 10_000);
    pub const MaxNominatorRewardedPerValidator: u32 = 2048;
    pub const OffendingValidatorsThreshold: Perbill = Perbill::from_percent(17);
    pub const IndexDeposit: Balance = DOLLARS;
    pub const RewardCurve: &'static PiecewiseLinear<'static> = &REWARD_CURVE;
    pub const StakingUnsignedPriority: TransactionPriority = TransactionPriority::max_value() / 2;
    pub const MaxValidatorPerIdentity: Permill = Permill::from_percent(33);
    pub const MaxVariableInflationTotalIssuance: Balance = 1_000_000_000 * POLY;
    pub const FixedYearlyReward: Balance = 140_000_000 * POLY;
    pub const MinimumBond: Balance = 1 * POLY;
    pub const MaxNumberOfFungibleAssets: u32 = 100;
    pub const MaxNumberOfNFTsPerLeg: u32 = 10;
    pub const MaxNumberOfNFTs: u32 = 100;
    pub const ImOnlineUnsignedPriority: TransactionPriority = TransactionPriority::max_value();
    pub const MaxSetIdSessionEntries: u32 = BondingDuration::get() * SessionsPerEra::get();
    pub const MaxAuthorities: u32 = 100_000;
    pub const MaxKeys: u32 = 10_000;
    pub const MaxPeerInHeartbeats: u32 = 10_000;
    pub const MaxPeerDataEncodingSize: u32 = 1_000;
    pub const ReportLongevity: u64 =
        BondingDuration::get() as u64 * SessionsPerEra::get() as u64 * EpochDuration::get();
    pub const MaxNumberOfCollectionKeys: u8 = u8::MAX;
    pub const MaxNumberOfFungibleMoves: u32 = 10;
    pub const MaxNumberOfNFTsMoves: u32 = 100;
    pub const MaxNumberOfOffChainAssets: u32 = 10;
    pub const MaxNumberOfVenueSigners: u32 = 50;
    pub const MaxInstructionMediators: u32 = 4;
    pub const MaxAssetMediators: u32 = 4;

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

/// NB It is needed by benchmarks, in order to use `UserBuilder`.
impl TestUtilsFn<AccountId> for Runtime {
    fn register_did(
        target: AccountId,
        secondary_keys: Vec<polymesh_primitives::secondary_key::SecondaryKey<AccountId>>,
    ) -> DispatchResult {
        <TestUtils as TestUtilsFn<AccountId>>::register_did(target, secondary_keys)
    }
}

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
        TransactionPayment: pallet_transaction_payment::{Pallet, Event<T>, Storage} = 6,
        Identity: pallet_identity::{Pallet, Call, Storage, Event<T>, Config<T>} = 7,
        CddServiceProviders: pallet_group::<Instance2>::{Pallet, Call, Storage, Event<T>, Config<T>} = 8,
        PolymeshCommittee: pallet_committee::<Instance1>::{Pallet, Call, Storage, Origin<T>, Event<T>, Config<T>} = 9,
        CommitteeMembership: pallet_group::<Instance1>::{Pallet, Call, Storage, Event<T>, Config<T>} = 10,
        TechnicalCommittee: pallet_committee::<Instance3>::{Pallet, Call, Storage, Origin<T>, Event<T>, Config<T>} = 11,
        TechnicalCommitteeMembership: pallet_group::<Instance3>::{Pallet, Call, Storage, Event<T>, Config<T>} = 12,
        UpgradeCommittee: pallet_committee::<Instance4>::{Pallet, Call, Storage, Origin<T>, Event<T>, Config<T>} = 13,
        UpgradeCommitteeMembership: pallet_group::<Instance4>::{Pallet, Call, Storage, Event<T>, Config<T>} = 14,
        MultiSig: pallet_multisig::{Pallet, Call, Config, Storage, Event<T>} = 15,
        Bridge: pallet_bridge::{Pallet, Call, Storage, Config<T>, Event<T>} = 16,
        Staking: pallet_staking::{Pallet, Call, Config<T>, Storage, Event<T>, ValidateUnsigned} = 17,
        Offences: pallet_offences::{Pallet, Storage, Event} = 18,
        Session: pallet_session::{Pallet, Call, Storage, Event, Config<T>} = 19,
        AuthorityDiscovery: pallet_authority_discovery::{Pallet, Config} = 20,
        Grandpa: pallet_grandpa::{Pallet, Call, Storage, Config, Event} = 21,
        Historical: pallet_session_historical::{Pallet} = 22,
        ImOnline: pallet_im_online::{Pallet, Call, Storage, Event<T>, ValidateUnsigned, Config<T>} = 23,
        RandomnessCollectiveFlip: pallet_insecure_randomness_collective_flip::{Pallet, Storage} = 24,
        Sudo: pallet_sudo::{Pallet, Call, Config<T>, Storage, Event<T>} = 25,
        Asset: pallet_asset::{Pallet, Call, Storage, Config<T>, Event<T>} = 26,
        CapitalDistribution: capital_distributions::{Pallet, Call, Storage, Event} = 27,
        Checkpoint: pallet_checkpoint::{Pallet, Call, Storage, Event, Config} = 28,
        ComplianceManager: pallet_compliance_manager::{Pallet, Call, Storage, Event} = 29,
        CorporateAction: pallet_corporate_actions::{Pallet, Call, Storage, Event, Config} = 30,
        CorporateBallot: corporate_ballots::{Pallet, Call, Storage, Event} = 31,
        Permissions: pallet_permissions::{Pallet, Storage} = 32,
        Pips: pallet_pips::{Pallet, Call, Storage, Event<T>, Config<T>} = 33,
        Portfolio: pallet_portfolio::{Pallet, Call, Storage, Event} = 34,
        ProtocolFee: pallet_protocol_fee::{Pallet, Call, Storage, Event<T>, Config} = 35,
        Scheduler: pallet_scheduler::{Pallet, Call, Storage, Event<T>} = 36,
        Settlement: pallet_settlement::{Pallet, Call, Storage, Event<T>, Config} = 37,
        Statistics: pallet_statistics::{Pallet, Call, Storage, Event} = 38,
        Sto: pallet_sto::{Pallet, Call, Storage, Event<T>} = 39,
        Treasury: pallet_treasury::{Pallet, Call, Event<T>} = 40,
        Utility: pallet_utility::{Pallet, Call, Storage, Event<T>} = 41,
        Base: pallet_base::{Pallet, Call, Event} = 42,
        ExternalAgents: pallet_external_agents::{Pallet, Call, Storage, Event} = 43,
        Relayer: pallet_relayer::{Pallet, Call, Storage, Event<T>} = 44,
        Contracts: pallet_contracts::{Pallet, Call, Storage, Event<T>} = 46,
        PolymeshContracts: polymesh_contracts::{Pallet, Call, Storage, Event<T>, Config} = 47,
        Preimage: pallet_preimage::{Pallet, Call, Storage, Event<T>} = 48,
        TestUtils: pallet_test_utils::{Pallet, Call, Storage, Event<T> } = 50,
        Nft: pallet_nft::{Pallet, Call, Storage, Event} = 51,
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
    <balances::Module<T> as Currency<<T as frame_system::Config>::AccountId>>::NegativeImbalance;

impl ChargeTxFee for TestRuntime {
    fn charge_fee(_len: u32, _info: DispatchInfo) -> TransactionValidity {
        Ok(ValidTransaction::default())
    }
}

impl CddAndFeeDetails<AccountId, RuntimeCall> for TestRuntime {
    fn get_valid_payer(
        _: &RuntimeCall,
        caller: &AccountId,
    ) -> Result<Option<AccountId>, InvalidTransaction> {
        let caller: AccountId = caller.clone();
        Ok(Some(caller))
    }
    fn clear_context() {
        Context::set_current_identity::<Identity>(None);
        Context::set_current_payer::<Identity>(None);
    }
    fn set_payer_context(payer: Option<AccountId>) {
        Context::set_current_payer::<Identity>(payer);
    }
    fn get_payer_from_context() -> Option<AccountId> {
        Context::current_payer::<Identity>()
    }
    fn set_current_identity(did: &IdentityId) {
        Context::set_current_identity::<Identity>(Some(*did));
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
}

impl group::Config<group::Instance1> for TestRuntime {
    type RuntimeEvent = RuntimeEvent;
    type LimitOrigin = EnsureRoot<AccountId>;
    type AddOrigin = EnsureRoot<AccountId>;
    type RemoveOrigin = EnsureRoot<AccountId>;
    type SwapOrigin = EnsureRoot<AccountId>;
    type ResetOrigin = EnsureRoot<AccountId>;
    type MembershipInitialized = committee::Module<TestRuntime, committee::Instance1>;
    type MembershipChanged = committee::Module<TestRuntime, committee::Instance1>;
    type WeightInfo = polymesh_weights::pallet_group::SubstrateWeight;
}

impl group::Config<group::Instance2> for TestRuntime {
    type RuntimeEvent = RuntimeEvent;
    type LimitOrigin = EnsureRoot<AccountId>;
    type AddOrigin = EnsureRoot<AccountId>;
    type RemoveOrigin = EnsureRoot<AccountId>;
    type SwapOrigin = EnsureRoot<AccountId>;
    type ResetOrigin = EnsureRoot<AccountId>;
    type MembershipInitialized = identity::Module<TestRuntime>;
    type MembershipChanged = identity::Module<TestRuntime>;
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

impl polymesh_common_utilities::traits::identity::Config for TestRuntime {
    type RuntimeEvent = RuntimeEvent;
    type Proposal = RuntimeCall;
    type MultiSig = multisig::Module<TestRuntime>;
    type Portfolio = portfolio::Module<TestRuntime>;
    type CddServiceProviders = CddServiceProvider;
    type Balances = balances::Module<TestRuntime>;
    type ChargeTxFeeTarget = TestRuntime;
    type CddHandler = TestRuntime;
    type Public = <MultiSignature as Verify>::Signer;
    type OffChainSignature = MultiSignature;
    type ProtocolFee = protocol_fee::Module<TestRuntime>;
    type GCVotingMajorityOrigin = VMO<committee::Instance1>;
    type WeightInfo = polymesh_weights::pallet_identity::SubstrateWeight;
    type IdentityFn = identity::Module<TestRuntime>;
    type SchedulerOrigin = OriginCaller;
    type InitialPOLYX = InitialPOLYX;
    type MultiSigBalanceLimit = polymesh_runtime_common::MultiSigBalanceLimit;
}

impl pips::Config for TestRuntime {
    type Currency = balances::Module<Self>;
    type VotingMajorityOrigin = VMO<committee::Instance1>;
    type GovernanceCommittee = Committee;
    type TechnicalCommitteeVMO = VMO<committee::Instance3>;
    type UpgradeCommitteeVMO = VMO<committee::Instance4>;
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = polymesh_weights::pallet_pips::SubstrateWeight;
    type Scheduler = Scheduler;
    type SchedulerCall = RuntimeCall;
}

impl pallet_test_utils::Config for TestRuntime {
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = polymesh_weights::pallet_test_utils::SubstrateWeight;
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
            let _ = TestUtils::register_did(signed_id.clone(), vec![])
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
