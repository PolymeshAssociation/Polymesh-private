#![allow(clippy::not_unsafe_ptr_arg_deref)]

use crate::constants::time::*;
use codec::Encode;
use frame_support::{
    construct_runtime, parameter_types, traits::KeyOwnerProofSystem, weights::Weight,
};
use pallet_asset::checkpoint as pallet_checkpoint;
use pallet_corporate_actions::ballot as pallet_corporate_ballot;
use pallet_corporate_actions::distribution as pallet_capital_distribution;
use pallet_session::historical as pallet_session_historical;
pub use pallet_transaction_payment::{Multiplier, RuntimeDispatchInfo, TargetedFeeAdjustment};
use polymesh_common_utilities::protocol_fee::ProtocolOp;
use polymesh_primitives::{constants::currency::*, constants::ENSURED_MAX_LEN, ConstSize};
use polymesh_primitives::{Balance, BlockNumber, Moment};
use polymesh_runtime_common::{
    impls::Author,
    merge_active_and_inactive,
    runtime::{GovernanceCommittee, BENCHMARK_MAX_INCREASE, VMO},
    AvailableBlockRatio, MaximumBlockWeight,
};
use sp_runtime::transaction_validity::TransactionPriority;
use sp_runtime::{
    create_runtime_str,
    traits::{BlakeTwo256, Block as BlockT, Extrinsic, NumberFor, StaticLookup, Verify},
    Perbill,
};
use sp_std::prelude::*;
#[cfg(feature = "std")]
use sp_version::NativeVersion;
use sp_version::RuntimeVersion;

pub use frame_support::StorageValue;
pub use frame_system::Call as SystemCall;
pub use pallet_balances::Call as BalancesCall;
pub use pallet_timestamp::Call as TimestampCall;
#[cfg(any(feature = "std", test))]
pub use sp_runtime::BuildStorage;

// Make the WASM binary available.
#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));

/// Runtime version.
pub const VERSION: RuntimeVersion = RuntimeVersion {
    spec_name: create_runtime_str!("polymesh_private_prod"),
    impl_name: create_runtime_str!("polymesh_private_prod"),
    authoring_version: 1,
    // `spec_version: aaa_bbb_ccd` should match node version v`aaa.bbb.cc`
    // N.B. `d` is unpinned from the binary version
    spec_version: 2_001_000,
    impl_version: 0,
    apis: RUNTIME_API_VERSIONS,
    transaction_version: 1,
    state_version: 1,
};

parameter_types! {
    /// Assume 10% of weight for average on_initialize calls.
    pub MaximumExtrinsicWeight: Weight = AvailableBlockRatio::get()
        .saturating_sub(Perbill::from_percent(10)) * MaximumBlockWeight::get();
    pub const Version: RuntimeVersion = VERSION;

    // Frame:
    pub const EpochDuration: u64 = EPOCH_DURATION_IN_BLOCKS as u64;
    pub const ExpectedBlockTime: Moment = MILLISECS_PER_BLOCK;
    pub const SS58Prefix: u8 = 12;

    // Base:
    pub const MaxLen: u32 = ENSURED_MAX_LEN;

    // Indices:
    pub const IndexDeposit: Balance = DOLLARS;

    // Balances:
    pub const ExistentialDeposit: Balance = 0u128;
    pub const MaxLocks: u32 = 50;

    // Timestamp:
    pub const MinimumPeriod: Moment = SLOT_DURATION / 2;

    // Settlement:
    pub const MaxNumberOfOffChainAssets: u32 = 10;
    pub const MaxNumberOfFungibleAssets: u32 = 10;
    pub const MaxNumberOfNFTsPerLeg: u32 = 10;
    pub const MaxNumberOfNFTs: u32 = 100;
    pub const MaxNumberOfPortfolios: u32 = (10 + 100) * 2;
    pub const MaxNumberOfVenueSigners: u32 = 50;
    pub const MaxInstructionMediators: u32 = 4;
    pub const MaximumLockPeriod: Moment = 1_440_000; // 24 hours

    // I'm online:
    pub const ImOnlineUnsignedPriority: TransactionPriority = TransactionPriority::max_value();

    pub const MaxSetIdSessionEntries: u32 = 0;
    pub const ReportLongevity: u64 = 1_000;
    pub const MinAuthorities: u32 = 2;
    pub const MaxAuthorities: u32 = 10_000;
    pub const MaxKeys: u32 = 10_000;
    pub const MaxPeerInHeartbeats: u32 = 10_000;
    pub const MaxPeerDataEncodingSize: u32 = 1_000;

    // Assets:
    pub const AssetNameMaxLength: u32 = 128;
    pub const FundingRoundNameMaxLength: u32 = 128;
    pub const AssetMetadataNameMaxLength: u32 = 256;
    pub const AssetMetadataValueMaxLength: u32 = 8 * 1024;
    pub const AssetMetadataTypeDefMaxLength: u32 = 8 * 1024;
    pub const MaxAssetMediators: u32 = 4;

    // Compliance manager:
    pub const MaxConditionComplexity: u32 = 50;

    // Corporate Actions:
    pub const MaxTargetIds: u32 = 1000;
    pub const MaxDidWhts: u32 = 1000;

    // Statistics:
    pub const MaxStatsPerAsset: u32 = 10 + BENCHMARK_MAX_INCREASE;
    pub const MaxTransferConditionsPerAsset: u32 = 4 + BENCHMARK_MAX_INCREASE;

    // Scheduler:
    pub MaximumSchedulerWeight: Weight = Perbill::from_percent(80) * MaximumBlockWeight::get();
    pub const MaxScheduledPerBlock: u32 = 50;

    // Identity:
    pub const InitialPOLYX: Balance = 0;
    pub const MaxGivenAuths: u32 = 1024;

    // Contracts:
    pub Schedule: pallet_contracts::Schedule<Runtime> = Default::default();
    pub DeletionWeightLimit: Weight = Weight::from_ref_time(500_000_000_000);
    pub DeletionQueueDepth: u32 = 1024;
    pub MaxInLen: u32 = 8 * 1024;
    pub MaxOutLen: u32 = 8 * 1024;

    // NFT:
    pub const MaxNumberOfCollectionKeys: u8 = u8::MAX;

    // Portfolio:
    pub const MaxNumberOfFungibleMoves: u32 = 10;
    pub const MaxNumberOfNFTsMoves: u32 = 100;

    // Confidential asset.
    pub const MaxTotalSupply: Balance = 10_000_000_000_000;

    // Multisig
    pub const MaxMultiSigSigners: u32 = 50;

    // PIPs
    pub const MaxRefundsAndVotesPruned: u32 = 128;
}

type ConfidentialAssetMaxNumberOfAffirms = ConstSize<10>;
type ConfidentialAssetMaxNumberOfLegs = ConstSize<10>;
type ConfidentialAssetMaxAssetsPerLeg = ConstSize<4>;
type ConfidentialAssetMaxAuditorsPerLeg = ConstSize<{ 4 + 4 }>;
type ConfidentialAssetMaxMediatorsPerLeg = ConstSize<{ 4 * 8 }>;
type ConfidentialAssetMaxVenueAuditors = ConstSize<4>;
type ConfidentialAssetMaxVenueMediators = ConstSize<4>;
type ConfidentialAssetMaxAssetAuditors = ConstSize<4>;
type ConfidentialAssetMaxAssetMediators = ConstSize<4>;
type ConfidentialAssetMaxAssetDataLength = ConstSize<8192>;

type ConfidentialAssetMaxAssetsPerMoveFunds = ConstSize<100>;
type ConfidentialAssetMaxMoveFunds = ConstSize<2000>;

type ConfidentialAssetBatchHostThreads = ConstSize<8>;

/// 100% goes to the block author.
pub type DealWithFees = Author<Runtime>;

polymesh_runtime_common::misc_pallet_impls!();

type CddHandler = polymesh_runtime_common::fee_details::CddHandler<Runtime>;

impl pallet_identity::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type Proposal = RuntimeCall;
    type CddServiceProviders = CddServiceProviders;
    type Balances = pallet_balances::Pallet<Runtime>;
    type CddHandler = CddHandler;
    type Public = <MultiSignature as Verify>::Signer;
    type OffChainSignature = MultiSignature;
    type ProtocolFee = pallet_protocol_fee::Pallet<Runtime>;
    type GCVotingMajorityOrigin = VMO<GovernanceCommittee>;
    type WeightInfo = polymesh_weights::pallet_identity::SubstrateWeight;
    type IdentityFn = pallet_identity::Pallet<Runtime>;
    type SchedulerOrigin = OriginCaller;
    type InitialPOLYX = InitialPOLYX;
    type MaxGivenAuths = MaxGivenAuths;
}

impl pallet_committee::Config<GovernanceCommittee> for Runtime {
    type RuntimeOrigin = RuntimeOrigin;
    type Proposal = RuntimeCall;
    type CommitteeOrigin = VMO<GovernanceCommittee>;
    type VoteThresholdOrigin = Self::CommitteeOrigin;
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = polymesh_weights::pallet_committee::SubstrateWeight;
}

/// PolymeshCommittee as an instance of group
impl pallet_group::Config<pallet_group::Instance1> for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type LimitOrigin = polymesh_primitives::EnsureRoot;
    type AddOrigin = Self::LimitOrigin;
    type RemoveOrigin = Self::LimitOrigin;
    type SwapOrigin = Self::LimitOrigin;
    type ResetOrigin = Self::LimitOrigin;
    type MembershipInitialized = PolymeshCommittee;
    type MembershipChanged = PolymeshCommittee;
    type WeightInfo = polymesh_weights::pallet_group::SubstrateWeight;
}

impl pallet_confidential_asset::Config for Runtime {
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

macro_rules! committee_config {
    ($committee:ident, $instance:ident) => {
        impl pallet_committee::Config<pallet_committee::$instance> for Runtime {
            type RuntimeOrigin = RuntimeOrigin;
            type Proposal = RuntimeCall;
            // Can act upon itself.
            type CommitteeOrigin = VMO<pallet_committee::$instance>;
            type VoteThresholdOrigin = Self::CommitteeOrigin;
            type RuntimeEvent = RuntimeEvent;
            type WeightInfo = polymesh_weights::pallet_committee::SubstrateWeight;
        }
        impl pallet_group::Config<pallet_group::$instance> for Runtime {
            type RuntimeEvent = RuntimeEvent;
            // Committee cannot alter its own active membership limit.
            type LimitOrigin = polymesh_primitives::EnsureRoot;
            // Can manage its own addition, deletion, and swapping of membership...
            type AddOrigin = VMO<pallet_committee::$instance>;
            type RemoveOrigin = Self::AddOrigin;
            type SwapOrigin = Self::AddOrigin;
            // ...but it cannot reset its own membership; GC needs to do that.
            type ResetOrigin = VMO<GovernanceCommittee>;
            type MembershipInitialized = $committee;
            type MembershipChanged = $committee;
            type WeightInfo = polymesh_weights::pallet_group::SubstrateWeight;
        }
    };
}

committee_config!(TechnicalCommittee, Instance3);
committee_config!(UpgradeCommittee, Instance4);

impl pallet_pips::Config for Runtime {
    type Currency = Balances;
    type VotingMajorityOrigin = VMO<GovernanceCommittee>;
    type GovernanceCommittee = PolymeshCommittee;
    type TechnicalCommitteeVMO = VMO<pallet_committee::Instance3>;
    type UpgradeCommitteeVMO = VMO<pallet_committee::Instance4>;
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = polymesh_weights::pallet_pips::SubstrateWeight;
    type Scheduler = Scheduler;
    type SchedulerCall = RuntimeCall;
    type MaxRefundsAndVotesPruned = MaxRefundsAndVotesPruned;
}

/// CddProviders instance of group
impl pallet_group::Config<pallet_group::Instance2> for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type LimitOrigin = polymesh_primitives::EnsureRoot;
    type AddOrigin = polymesh_primitives::EnsureRoot;
    type RemoveOrigin = polymesh_primitives::EnsureRoot;
    type SwapOrigin = polymesh_primitives::EnsureRoot;
    type ResetOrigin = polymesh_primitives::EnsureRoot;
    type MembershipInitialized = Identity;
    type MembershipChanged = Identity;
    type WeightInfo = polymesh_weights::pallet_group::SubstrateWeight;
}

construct_runtime!(
    pub enum Runtime where
        Block = Block,
        NodeBlock = polymesh_primitives::Block,
        UncheckedExtrinsic = UncheckedExtrinsic
    {
        System: frame_system::{Pallet, Call, Config, Storage, Event<T>} = 0,
        Babe: pallet_babe::{Pallet, Call, Storage, Config, ValidateUnsigned} = 1,
        Timestamp: pallet_timestamp::{Pallet, Call, Storage, Inherent} = 2,
        Indices: pallet_indices::{Pallet, Call, Storage, Config<T>, Event<T>} = 3,
        Authorship: pallet_authorship = 4,

        // Balance: Genesis config dependencies: System.
        Balances: pallet_balances::{Pallet, Call, Storage, Config<T>, Event<T>} = 5,

        // TransactionPayment: Genesis config dependencies: Balance.
        TransactionPayment: pallet_transaction_payment::{Pallet, Call, Config, Event<T>, Storage} = 6,

        // Identity: Genesis config deps: Timestamp.
        Identity: pallet_identity::{Pallet, Call, Storage, Event<T>, Config<T>} = 7,

        // Polymesh Committees

        // CddServiceProviders (group only): Genesis config deps: Identity
        CddServiceProviders: pallet_group::<Instance2>::{Pallet, Call, Storage, Event<T>, Config<T>} = 8,

        // Governance Council (committee)
        PolymeshCommittee: pallet_committee::<Instance1>::{Pallet, Call, Storage, Origin<T>, Event<T>, Config<T>} = 9,
        // CommitteeMembership: Genesis config deps: PolymeshCommittee, Identity.
        CommitteeMembership: pallet_group::<Instance1>::{Pallet, Call, Storage, Event<T>, Config<T>} = 10,

        // Technical Committee
        TechnicalCommittee: pallet_committee::<Instance3>::{Pallet, Call, Storage, Origin<T>, Event<T>, Config<T>} = 11,
        // TechnicalCommitteeMembership: Genesis config deps: TechnicalCommittee, Identity
        TechnicalCommitteeMembership: pallet_group::<Instance3>::{Pallet, Call, Storage, Event<T>, Config<T>} = 12,

        // Upgrade Committee
        UpgradeCommittee: pallet_committee::<Instance4>::{Pallet, Call, Storage, Origin<T>, Event<T>, Config<T>} = 13,
        // UpgradeCommitteeMembership: Genesis config deps: UpgradeCommittee, Identity
        UpgradeCommitteeMembership: pallet_group::<Instance4>::{Pallet, Call, Storage, Event<T>, Config<T>} = 14,

        MultiSig: pallet_multisig::{Pallet, Call, Config, Storage, Event<T>} = 15,

        // PoA
        ValidatorSet: validator_set = 16,

        Offences: pallet_offences::{Pallet, Storage, Event} = 18,

        // Session: Genesis config deps: System.
        Session: pallet_session::{Pallet, Call, Storage, Event, Config<T>} = 19,
        AuthorityDiscovery: pallet_authority_discovery::{Pallet, Config} = 20,
        Grandpa: pallet_grandpa::{Pallet, Call, Storage, Config, Event} = 21,
        Historical: pallet_session_historical::{Pallet} = 22,
        ImOnline: pallet_im_online::{Pallet, Call, Storage, Event<T>, ValidateUnsigned, Config<T>} = 23,
        RandomnessCollectiveFlip: pallet_insecure_randomness_collective_flip::{Pallet, Storage} = 24,

        // Sudo. Usable initially.
        // Sudo: pallet_sudo::{Pallet, Call, Config<T>, Storage, Event<T>} = 25,

        // Asset: Genesis config deps: Timestamp,
        Asset: pallet_asset::{Pallet, Call, Storage, Config, Event<T>} = 26,
        CapitalDistribution: pallet_capital_distribution::{Pallet, Call, Storage, Event<T>} = 27,
        Checkpoint: pallet_checkpoint::{Pallet, Call, Storage, Event<T>, Config} = 28,
        ComplianceManager: pallet_compliance_manager::{Pallet, Call, Storage, Event<T>} = 29,
        CorporateAction: pallet_corporate_actions::{Pallet, Call, Storage, Event<T>, Config} = 30,
        CorporateBallot: pallet_corporate_ballot::{Pallet, Call, Storage, Event<T>} = 31,
        Permissions: pallet_permissions::{Pallet} = 32,
        Pips: pallet_pips::{Pallet, Call, Storage, Event<T>, Config<T>} = 33,
        Portfolio: pallet_portfolio::{Pallet, Call, Storage, Event<T>, Config} = 34,
        ProtocolFee: pallet_protocol_fee::{Pallet, Call, Storage, Event<T>, Config} = 35,
        Scheduler: pallet_scheduler::{Pallet, Call, Storage, Event<T>} = 36,
        Settlement: pallet_settlement::{Pallet, Call, Storage, Event<T>, Config} = 37,
        Statistics: pallet_statistics::{Pallet, Call, Storage, Event<T>, Config} = 38,
        Sto: pallet_sto::{Pallet, Call, Storage, Event<T>} = 39,
        Treasury: pallet_treasury::{Pallet, Call, Event<T>} = 40,
        Utility: pallet_utility::{Pallet, Call, Storage, Event<T>} = 41,
        Base: pallet_base::{Pallet, Call, Event} = 42,
        ExternalAgents: pallet_external_agents::{Pallet, Call, Storage, Event<T>} = 43,
        Relayer: pallet_relayer::{Pallet, Call, Storage, Event<T>} = 44,
        // Removed pallet_rewards = 45

        // Contracts
        Contracts: pallet_contracts::{Pallet, Call, Storage, Event<T>} = 46,
        PolymeshContracts: polymesh_contracts::{Pallet, Call, Storage, Event<T>, Config<T>} = 47,

        // Preimage register.  Used by `pallet_scheduler`.
        Preimage: pallet_preimage::{Pallet, Call, Storage, Event<T>} = 48,

        Nft: pallet_nft::{Pallet, Call, Storage, Event<T>} = 49,

        // Confidential Asset pallets.
        ConfidentialAsset: pallet_confidential_asset::{Pallet, Call, Storage, Event<T>, Config} = 60,
    }
);

polymesh_runtime_common::runtime_apis! {}
