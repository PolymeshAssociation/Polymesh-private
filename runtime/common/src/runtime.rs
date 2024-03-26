/// Voting majority origin for `Instance`.
pub type VMO<Instance> =
    pallet_committee::EnsureThresholdMet<polymesh_primitives::AccountId, Instance>;

pub type GovernanceCommittee = pallet_committee::Instance1;

// Allow benchmarks to run with larger inputs.
// This is needed for extrinsics that have a `Vec<_>` parameter
// and need to make sure that the cost function is correct for
// large inputs.
#[cfg(feature = "runtime-benchmarks")]
pub const BENCHMARK_MAX_INCREASE: u32 = 1000;
#[cfg(not(feature = "runtime-benchmarks"))]
pub const BENCHMARK_MAX_INCREASE: u32 = 0;

/// Provides miscellaneous and common pallet-`Config` implementations for a `Runtime`.
#[macro_export]
macro_rules! misc_pallet_impls {
    () => {
        /// Native version.
        #[cfg(any(feature = "std", test))]
        pub fn native_version() -> NativeVersion {
            NativeVersion {
                runtime_version: VERSION,
                can_author_with: Default::default(),
            }
        }

        use sp_runtime::{
            generic, impl_opaque_keys,
            traits::{SaturatedConversion as _, Saturating as _},
            ApplyExtrinsicResult, MultiSignature,
        };

        #[cfg(not(feature = "testing"))]
        type RuntimeBaseCallFilter = frame_support::traits::Everything;

        impl frame_system::Config for Runtime {
            /// The basic call filter to use in dispatchable.
            type BaseCallFilter = RuntimeBaseCallFilter;
            /// Block & extrinsics weights: base values and limits.
            type BlockWeights = polymesh_runtime_common::RuntimeBlockWeights;
            /// The maximum length of a block (in bytes).
            type BlockLength = polymesh_runtime_common::RuntimeBlockLength;
            /// The designated SS85 prefix of this chain.
            ///
            /// This replaces the "ss58Format" property declared in the chain spec. Reason is
            /// that the runtime should know about the prefix in order to make use of it as
            /// an identifier of the chain.
            type SS58Prefix = SS58Prefix;
            /// The identifier used to distinguish between accounts.
            type AccountId = polymesh_primitives::AccountId;
            /// The aggregated dispatch type that is available for extrinsics.
            type RuntimeCall = RuntimeCall;
            /// The lookup mechanism to get account ID from whatever is passed in dispatchers.
            type Lookup = Indices;
            /// The index type for storing how many extrinsics an account has signed.
            type Index = polymesh_primitives::Index;
            /// The index type for blocks.
            type BlockNumber = polymesh_primitives::BlockNumber;
            /// The type for hashing blocks and tries.
            type Hash = polymesh_primitives::Hash;
            /// The hashing algorithm used.
            type Hashing = sp_runtime::traits::BlakeTwo256;
            /// The header type.
            type Header =
                sp_runtime::generic::Header<polymesh_primitives::BlockNumber, BlakeTwo256>;
            /// The ubiquitous event type.
            type RuntimeEvent = RuntimeEvent;
            /// The ubiquitous origin type.
            type RuntimeOrigin = RuntimeOrigin;
            /// Maximum number of block number to block hash mappings to keep (oldest pruned first).
            type BlockHashCount = polymesh_runtime_common::BlockHashCount;
            /// The weight of database operations that the runtime can invoke.
            type DbWeight = polymesh_runtime_common::RocksDbWeight;
            /// Version of the runtime.
            type Version = Version;
            /// Converts a module to the index of the module in `construct_runtime!`.
            ///
            /// This type is being generated by `construct_runtime!`.
            type PalletInfo = PalletInfo;
            /// What to do if a new account is created.
            type OnNewAccount = ();
            /// What to do if an account is fully reaped from the system.
            type OnKilledAccount = ();
            /// The data to be stored in an account.
            type AccountData = polymesh_common_utilities::traits::balances::AccountData;
            type SystemWeightInfo = polymesh_weights::frame_system::SubstrateWeight;
            type OnSetCode = ();
            type MaxConsumers = frame_support::traits::ConstU32<16>;
        }

        impl pallet_base::Config for Runtime {
            type RuntimeEvent = RuntimeEvent;
            type MaxLen = MaxLen;
        }

        impl pallet_aura::Config for Runtime {
            type AuthorityId = sp_consensus_aura::sr25519::AuthorityId;
            type DisabledValidators = ();
            type MaxAuthorities = MaxAuthorities;
        }

        impl<'a> core::convert::TryFrom<&'a RuntimeCall>
            for polymesh_runtime_common::fee_details::Call<'a, Runtime>
        {
            type Error = ();
            fn try_from(call: &'a RuntimeCall) -> Result<Self, ()> {
                use polymesh_runtime_common::fee_details::Call::*;
                Ok(match call {
                    RuntimeCall::Identity(x) => Identity(x),
                    RuntimeCall::MultiSig(x) => MultiSig(x),
                    RuntimeCall::Relayer(x) => Relayer(x),
                    _ => return Err(()),
                })
            }
        }

        impl RuntimeCall {
            fn get_actual_weight(&self) -> Option<Weight> {
                match self {
                    RuntimeCall::Settlement(x) => Settlement::get_actual_weight(x),
                    _ => None,
                }
            }
        }

        impl pallet_transaction_payment::Config for Runtime {
            type RuntimeEvent = RuntimeEvent;
            type Currency = Balances;
            type OnChargeTransaction = pallet_transaction_payment::CurrencyAdapter<Balances, ()>;
            type TransactionByteFee = polymesh_runtime_common::TransactionByteFee;
            type WeightToFee = polymesh_runtime_common::WeightToFee;
            type FeeMultiplierUpdate = ();
            type CddHandler = CddHandler;
            type Subsidiser = Relayer;
            type GovernanceCommittee = PolymeshCommittee;
            type CddProviders = CddServiceProviders;
            type Identity = Identity;
        }

        impl polymesh_common_utilities::traits::CommonConfig for Runtime {
            type BlockRewardsReserve = pallet_balances::Pallet<Runtime>;
        }

        impl pallet_balances::Config for Runtime {
            type MaxLocks = MaxLocks;
            type DustRemoval = ();
            type RuntimeEvent = RuntimeEvent;
            type ExistentialDeposit = ExistentialDeposit;
            type AccountStore = frame_system::Pallet<Runtime>;
            type CddChecker = polymesh_runtime_common::cdd_check::CddChecker<Runtime>;
            type WeightInfo = polymesh_weights::pallet_balances::SubstrateWeight;
        }

        impl pallet_protocol_fee::Config for Runtime {
            type RuntimeEvent = RuntimeEvent;
            type Currency = Balances;
            type OnProtocolFeePayment = ();
            type WeightInfo = polymesh_weights::pallet_protocol_fee::SubstrateWeight;
            type Subsidiser = Relayer;
        }

        impl pallet_timestamp::Config for Runtime {
            type Moment = polymesh_primitives::Moment;
            type OnTimestampSet = Aura;
            type MinimumPeriod = MinimumPeriod;
            type WeightInfo = polymesh_weights::pallet_timestamp::SubstrateWeight;
        }

        impl_opaque_keys! {
            pub struct SessionKeys {
                pub aura: Aura,
                pub grandpa: Grandpa,
            }
        }

        impl pallet_multisig::Config for Runtime {
            type RuntimeEvent = RuntimeEvent;
            type Scheduler = Scheduler;
            type SchedulerCall = RuntimeCall;
            type WeightInfo = polymesh_weights::pallet_multisig::SubstrateWeight;
        }

        impl pallet_portfolio::Config for Runtime {
            type RuntimeEvent = RuntimeEvent;
            type Asset = Asset;
            type WeightInfo = polymesh_weights::pallet_portfolio::SubstrateWeight;
            type MaxNumberOfFungibleMoves = MaxNumberOfFungibleMoves;
            type MaxNumberOfNFTsMoves = MaxNumberOfNFTsMoves;
            type NFT = pallet_nft::Module<Runtime>;
        }

        impl pallet_external_agents::Config for Runtime {
            type RuntimeEvent = RuntimeEvent;
            type WeightInfo = polymesh_weights::pallet_external_agents::SubstrateWeight;
        }

        impl pallet_relayer::Config for Runtime {
            type RuntimeEvent = RuntimeEvent;
            type WeightInfo = polymesh_weights::pallet_relayer::SubstrateWeight;
        }

        impl pallet_asset::Config for Runtime {
            type RuntimeEvent = RuntimeEvent;
            type Currency = Balances;
            type ComplianceManager = pallet_compliance_manager::Module<Runtime>;
            type UnixTime = pallet_timestamp::Pallet<Runtime>;
            type AssetNameMaxLength = AssetNameMaxLength;
            type FundingRoundNameMaxLength = FundingRoundNameMaxLength;
            type AssetMetadataNameMaxLength = AssetMetadataNameMaxLength;
            type AssetMetadataValueMaxLength = AssetMetadataValueMaxLength;
            type AssetMetadataTypeDefMaxLength = AssetMetadataTypeDefMaxLength;
            type AssetFn = Asset;
            type WeightInfo = polymesh_weights::pallet_asset::SubstrateWeight;
            type CPWeightInfo = polymesh_weights::pallet_checkpoint::SubstrateWeight;
            type NFTFn = pallet_nft::Module<Runtime>;
            type MaxAssetMediators = MaxAssetMediators;
        }

        impl polymesh_contracts::Config for Runtime {
            type RuntimeEvent = RuntimeEvent;
            type MaxInLen = MaxInLen;
            type MaxOutLen = MaxOutLen;
            type WeightInfo = polymesh_weights::polymesh_contracts::SubstrateWeight;
        }

        impl pallet_contracts::Config for Runtime {
            type Time = Timestamp;
            type Randomness = RandomnessCollectiveFlip;
            type Currency = Balances;
            type RuntimeEvent = RuntimeEvent;
            type RuntimeCall = RuntimeCall;
            // The `CallFilter` ends up being used in `ext.call_runtime()`,
            // via the `seal_call_runtime` feature,
            // which won't swap the current identity,
            // so we need `Nothing` to basically disable that feature.
            type CallFilter = frame_support::traits::Nothing;
            type DepositPerItem = polymesh_runtime_common::DepositPerItem;
            type DepositPerByte = polymesh_runtime_common::DepositPerByte;
            type CallStack = [pallet_contracts::Frame<Self>; 5];
            type WeightPrice = pallet_transaction_payment::Pallet<Self>;
            type WeightInfo = polymesh_weights::pallet_contracts::SubstrateWeight;
            type ChainExtension = polymesh_contracts::PolymeshExtension;
            type Schedule = Schedule;
            type DeletionQueueDepth = DeletionQueueDepth;
            type DeletionWeightLimit = DeletionWeightLimit;
            type AddressGenerator = pallet_contracts::DefaultAddressGenerator;
            #[cfg(not(feature = "runtime-benchmarks"))]
            type PolymeshHooks = polymesh_contracts::ContractPolymeshHooks;
            #[cfg(feature = "runtime-benchmarks")]
            type PolymeshHooks = polymesh_contracts::benchmarking::BenchmarkContractPolymeshHooks;
            type MaxCodeLen = frame_support::traits::ConstU32<{ 123 * 1024 }>;
            type MaxStorageKeyLen = frame_support::traits::ConstU32<128>;
            type UnsafeUnstableInterface = frame_support::traits::ConstBool<false>;
            type MaxDebugBufferLen = frame_support::traits::ConstU32<{ 2 * 1024 * 1024 }>;
        }

        impl pallet_compliance_manager::Config for Runtime {
            type RuntimeEvent = RuntimeEvent;
            type Asset = Asset;
            type WeightInfo = polymesh_weights::pallet_compliance_manager::SubstrateWeight;
            type MaxConditionComplexity = MaxConditionComplexity;
        }

        impl pallet_corporate_actions::Config for Runtime {
            type RuntimeEvent = RuntimeEvent;
            type MaxTargetIds = MaxTargetIds;
            type MaxDidWhts = MaxDidWhts;
            type WeightInfo = polymesh_weights::pallet_corporate_actions::SubstrateWeight;
            type BallotWeightInfo = polymesh_weights::pallet_corporate_ballot::SubstrateWeight;
            type DistWeightInfo = polymesh_weights::pallet_capital_distribution::SubstrateWeight;
        }

        impl pallet_statistics::Config for Runtime {
            type RuntimeEvent = RuntimeEvent;
            type Asset = Asset;
            type MaxStatsPerAsset = MaxStatsPerAsset;
            type MaxTransferConditionsPerAsset = MaxTransferConditionsPerAsset;
            type WeightInfo = polymesh_weights::pallet_statistics::SubstrateWeight;
        }

        impl pallet_utility::Config for Runtime {
            type RuntimeEvent = RuntimeEvent;
            type RuntimeCall = RuntimeCall;
            type PalletsOrigin = OriginCaller;
            type WeightInfo = polymesh_weights::pallet_utility::SubstrateWeight;
        }

        impl pallet_scheduler::Config for Runtime {
            type RuntimeEvent = RuntimeEvent;
            type RuntimeOrigin = RuntimeOrigin;
            type PalletsOrigin = OriginCaller;
            type RuntimeCall = RuntimeCall;
            type MaximumWeight = MaximumSchedulerWeight;
            type ScheduleOrigin = polymesh_primitives::EnsureRoot;
            type MaxScheduledPerBlock = MaxScheduledPerBlock;
            type WeightInfo = polymesh_weights::pallet_scheduler::SubstrateWeight;
            type OriginPrivilegeCmp = frame_support::traits::EqualPrivilegeOnly;
            type Preimages = Preimage;
        }

        parameter_types! {
            pub const PreimageMaxSize: u32 = 4096 * 1024;
            pub const PreimageBaseDeposit: Balance = polymesh_runtime_common::deposit(2, 64);
            pub const PreimageByteDeposit: Balance = polymesh_runtime_common::deposit(0, 1);
        }

        impl pallet_preimage::Config for Runtime {
            type WeightInfo = polymesh_weights::pallet_preimage::SubstrateWeight;
            type RuntimeEvent = RuntimeEvent;
            type Currency = Balances;
            type ManagerOrigin = polymesh_primitives::EnsureRoot;
            type BaseDeposit = PreimageBaseDeposit;
            type ByteDeposit = PreimageByteDeposit;
        }

        type GrandpaKey = (sp_core::crypto::KeyTypeId, pallet_grandpa::AuthorityId);

        impl pallet_grandpa::Config for Runtime {
            type RuntimeEvent = RuntimeEvent;

            type KeyOwnerProofSystem = ();

            type KeyOwnerProof =
                <Self::KeyOwnerProofSystem as KeyOwnerProofSystem<GrandpaKey>>::Proof;

            type KeyOwnerIdentification =
                <Self::KeyOwnerProofSystem as KeyOwnerProofSystem<GrandpaKey>>::IdentificationTuple;

            type HandleEquivocation = ();

            type WeightInfo = ();
            type MaxAuthorities = MaxAuthorities;
            type MaxSetIdSessionEntries = MaxSetIdSessionEntries;
        }

        impl pallet_insecure_randomness_collective_flip::Config for Runtime {}

        impl pallet_treasury::Config for Runtime {
            type RuntimeEvent = RuntimeEvent;
            type Currency = Balances;
            type WeightInfo = polymesh_weights::pallet_treasury::SubstrateWeight;
        }

        impl pallet_settlement::Config for Runtime {
            type RuntimeEvent = RuntimeEvent;
            type Proposal = RuntimeCall;
            type Scheduler = Scheduler;
            type WeightInfo = polymesh_weights::pallet_settlement::SubstrateWeight;
            type MaxNumberOfFungibleAssets = MaxNumberOfFungibleAssets;
            type MaxNumberOfNFTsPerLeg = MaxNumberOfNFTsPerLeg;
            type MaxNumberOfNFTs = MaxNumberOfNFTs;
            type MaxNumberOfOffChainAssets = MaxNumberOfOffChainAssets;
            type MaxNumberOfVenueSigners = MaxNumberOfVenueSigners;
            type MaxInstructionMediators = MaxInstructionMediators;
        }

        impl pallet_sto::Config for Runtime {
            type RuntimeEvent = RuntimeEvent;
            type WeightInfo = polymesh_weights::pallet_sto::SubstrateWeight;
        }

        impl polymesh_common_utilities::traits::permissions::Config for Runtime {
            type Checker = Identity;
        }

        impl<LocalCall> frame_system::offchain::CreateSignedTransaction<LocalCall> for Runtime
        where
            RuntimeCall: From<LocalCall>,
        {
            fn create_transaction<
                C: frame_system::offchain::AppCrypto<Self::Public, Self::Signature>,
            >(
                call: RuntimeCall,
                public: <polymesh_primitives::Signature as Verify>::Signer,
                account: polymesh_primitives::AccountId,
                nonce: polymesh_primitives::Index,
            ) -> Option<(
                RuntimeCall,
                <UncheckedExtrinsic as Extrinsic>::SignaturePayload,
            )> {
                // take the biggest period possible.
                let period = polymesh_runtime_common::BlockHashCount::get()
                    .checked_next_power_of_two()
                    .map(|c| c / 2)
                    .unwrap_or(2) as u64;
                let current_block = System::block_number()
                    .saturated_into::<u64>()
                    // The `System::block_number` is initialized with `n+1`,
                    // so the actual block number is `n`.
                    .saturating_sub(1);
                let tip = 0;
                let extra: SignedExtra = (
                    frame_system::CheckSpecVersion::new(),
                    frame_system::CheckTxVersion::new(),
                    frame_system::CheckGenesis::new(),
                    frame_system::CheckEra::from(generic::Era::mortal(period, current_block)),
                    frame_system::CheckNonce::from(nonce),
                    polymesh_extensions::CheckWeight::new(),
                    pallet_transaction_payment::ChargeTransactionPayment::from(tip),
                    pallet_permissions::StoreCallMetadata::new(),
                );
                let raw_payload = SignedPayload::new(call, extra)
                    .map_err(|e| {
                        log::warn!("Unable to create signed payload: {:?}", e);
                    })
                    .ok()?;
                let signature = raw_payload.using_encoded(|payload| C::sign(payload, public))?;
                let address = Indices::unlookup(account);
                let (call, extra, _) = raw_payload.deconstruct();
                Some((call, (address, signature, extra)))
            }
        }

        impl frame_system::offchain::SigningTypes for Runtime {
            type Public = <polymesh_primitives::Signature as Verify>::Signer;
            type Signature = polymesh_primitives::Signature;
        }

        impl<C> frame_system::offchain::SendTransactionTypes<C> for Runtime
        where
            RuntimeCall: From<C>,
        {
            type Extrinsic = UncheckedExtrinsic;
            type OverarchingCall = RuntimeCall;
        }

        impl pallet_nft::Config for Runtime {
            type RuntimeEvent = RuntimeEvent;
            type WeightInfo = polymesh_weights::pallet_nft::SubstrateWeight;
            type Compliance = pallet_compliance_manager::Module<Runtime>;
            type MaxNumberOfCollectionKeys = MaxNumberOfCollectionKeys;
            type MaxNumberOfNFTsCount = MaxNumberOfNFTsPerLeg;
        }
    };
}

/// Defines API implementations, e.g., for RPCs, and type aliases, for a `Runtime`.
#[macro_export]
macro_rules! runtime_apis {
    ($($extra:item)*) => {
        use frame_support::dispatch::{GetStorageVersion, DispatchError};
        use sp_inherents::{CheckInherentsResult, InherentData};
        use frame_support::dispatch::result::Result as FrameResult;
        use node_rpc_runtime_api::asset as rpc_api_asset;

        use pallet_identity::types::{AssetDidResult, CddStatus, RpcDidRecords, DidStatus, KeyIdentityData};
        use pallet_pips::{Vote, VoteCount};
        use pallet_protocol_fee_rpc_runtime_api::CappedFee;
        use polymesh_primitives::asset::GranularCanTransferResult;
        use polymesh_primitives::settlement::{InstructionId, ExecuteInstructionInfo, AffirmationCount};
        use polymesh_primitives::{
            asset::CheckpointId, compliance_manager::AssetComplianceResult, IdentityId, Index, NFTs,
            PortfolioId, Signatory, Ticker, WeightMeter, IdentityClaim
        };

        /// The address format for describing accounts.
        pub type Address = <Indices as StaticLookup>::Source;
        /// Block header type as expected by this runtime.
        pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
        /// Block type as expected by this runtime.
        pub type Block = generic::Block<Header, UncheckedExtrinsic>;
        /// A Block signed with a Justification
        pub type SignedBlock = generic::SignedBlock<Block>;
        /// BlockId type as expected by this runtime.
        pub type BlockId = generic::BlockId<Block>;
        /// The SignedExtension to the basic transaction logic.
        pub type SignedExtra = (
            frame_system::CheckSpecVersion<Runtime>,
            frame_system::CheckTxVersion<Runtime>,
            frame_system::CheckGenesis<Runtime>,
            frame_system::CheckEra<Runtime>,
            frame_system::CheckNonce<Runtime>,
            polymesh_extensions::CheckWeight<Runtime>,
            pallet_transaction_payment::ChargeTransactionPayment<Runtime>,
            pallet_permissions::StoreCallMetadata<Runtime>,
        );
        /// Unchecked extrinsic type as expected by this runtime.
        pub type UncheckedExtrinsic = generic::UncheckedExtrinsic<Address, RuntimeCall, polymesh_primitives::Signature, SignedExtra>;
        /// The payload being signed in transactions.
        pub type SignedPayload = generic::SignedPayload<RuntimeCall, SignedExtra>;
        /// Extrinsic type that has already been checked.
        pub type CheckedExtrinsic = generic::CheckedExtrinsic<polymesh_primitives::AccountId, RuntimeCall, SignedExtra>;
        /// Executive: handles dispatch to the various modules.
        pub type Executive = pallet_executive::Executive<
            Runtime,
            Block,
            frame_system::ChainContext<Runtime>,
            Runtime,
            AllPalletsWithSystem,
            (
              pallet_scheduler::migration::v4::CleanupAgendas<Runtime>,
              pallet_contracts::Migration<Runtime>,
            )
        >;

        sp_api::impl_runtime_apis! {
            impl sp_api::Core<Block> for Runtime {
                fn version() -> RuntimeVersion {
                    VERSION
                }

                fn execute_block(block: Block) {
                    Executive::execute_block(block)
                }

                fn initialize_block(header: &<Block as BlockT>::Header) {
                    Executive::initialize_block(header)
                }
            }

            impl sp_api::Metadata<Block> for Runtime {
                fn metadata() -> sp_core::OpaqueMetadata {
                    sp_core::OpaqueMetadata::new(Runtime::metadata().into())
                }
            }

            impl sp_block_builder::BlockBuilder<Block> for Runtime {
                fn apply_extrinsic(extrinsic: <Block as BlockT>::Extrinsic) -> ApplyExtrinsicResult {
                    Executive::apply_extrinsic(extrinsic)
                }

                fn finalize_block() -> <Block as BlockT>::Header {
                    Executive::finalize_block()
                }

                fn inherent_extrinsics(data: InherentData) -> Vec<<Block as BlockT>::Extrinsic> {
                    data.create_extrinsics()
                }

                fn check_inherents(block: Block, data: InherentData) -> CheckInherentsResult {
                    data.check_extrinsics(&block)
                }
            }

            impl sp_transaction_pool::runtime_api::TaggedTransactionQueue<Block> for Runtime {
                fn validate_transaction(
                    source: sp_runtime::transaction_validity::TransactionSource,
                    tx: <Block as BlockT>::Extrinsic,
                    block_hash: <Block as BlockT>::Hash,
                ) -> sp_runtime::transaction_validity::TransactionValidity {
                    Executive::validate_transaction(source, tx, block_hash)
                }
            }

            impl sp_offchain::OffchainWorkerApi<Block> for Runtime {
                fn offchain_worker(header: &<Block as BlockT>::Header) {
                    Executive::offchain_worker(header)
                }
            }

            impl sp_consensus_grandpa::GrandpaApi<Block> for Runtime {
                fn grandpa_authorities() -> sp_consensus_grandpa::AuthorityList {
                    Grandpa::grandpa_authorities()
                }

                fn submit_report_equivocation_unsigned_extrinsic(
                    _equivocation_proof: sp_consensus_grandpa::EquivocationProof<
                        <Block as BlockT>::Hash,
                        NumberFor<Block>,
                    >,
                    _key_owner_proof: sp_consensus_grandpa::OpaqueKeyOwnershipProof,
                ) -> Option<()> {
                    // TODO: Do we need this for Aura?
                    None
                }

                fn generate_key_ownership_proof(
                    _set_id: sp_consensus_grandpa::SetId,
                    _authority_id: pallet_grandpa::AuthorityId,
                ) -> Option<sp_consensus_grandpa::OpaqueKeyOwnershipProof> {
                    // TODO: Do we need this for Aura?
                    None
                }

                fn current_set_id() -> sp_consensus_grandpa::SetId {
                    Grandpa::current_set_id()
                }
            }

            impl sp_consensus_aura::AuraApi<Block, AuraId> for Runtime {
                fn slot_duration() -> sp_consensus_aura::SlotDuration {
                    sp_consensus_aura::SlotDuration::from_millis(Aura::slot_duration())
                }

                fn authorities() -> Vec<AuraId> {
                    Aura::authorities().into_inner()
                }
            }

            impl frame_system_rpc_runtime_api::AccountNonceApi<Block, polymesh_primitives::AccountId, Index> for Runtime {
                fn account_nonce(account: polymesh_primitives::AccountId) -> Index {
                    System::account_nonce(account)
                }
            }

            impl pallet_contracts::ContractsApi<
                Block,
                polymesh_primitives::AccountId,
                Balance,
                BlockNumber,
                polymesh_primitives::Hash,
            > for Runtime {
                fn call(
                    origin: polymesh_primitives::AccountId,
                    dest: polymesh_primitives::AccountId,
                    value: Balance,
                    gas_limit: Option<Weight>,
                    storage_deposit_limit: Option<Balance>,
                    input_data: Vec<u8>,
                ) -> pallet_contracts_primitives::ContractExecResult<Balance> {
                    let gas_limit = gas_limit.unwrap_or(polymesh_runtime_common::RuntimeBlockWeights::get().max_block);
                    Contracts::bare_call(origin, dest, value, gas_limit, storage_deposit_limit, input_data, true, pallet_contracts::Determinism::Deterministic)
                }

                fn instantiate(
                    origin: polymesh_primitives::AccountId,
                    value: Balance,
                    gas_limit: Option<Weight>,
                    storage_deposit_limit: Option<Balance>,
                    code: pallet_contracts_primitives::Code<polymesh_primitives::Hash>,
                    data: Vec<u8>,
                    salt: Vec<u8>,
                ) -> pallet_contracts_primitives::ContractInstantiateResult<polymesh_primitives::AccountId, Balance> {
                    let gas_limit = gas_limit.unwrap_or(polymesh_runtime_common::RuntimeBlockWeights::get().max_block);
                    Contracts::bare_instantiate(origin, value, gas_limit, storage_deposit_limit, code, data, salt, true)
                }

                fn upload_code(
                    origin: polymesh_primitives::AccountId,
                    code: Vec<u8>,
                    storage_deposit_limit: Option<Balance>,
                    determinism: pallet_contracts::Determinism,
                ) -> pallet_contracts_primitives::CodeUploadResult<polymesh_primitives::Hash, Balance> {
                    Contracts::bare_upload_code(origin, code, storage_deposit_limit, determinism)
                }

                fn get_storage(
                    address: polymesh_primitives::AccountId,
                    key: Vec<u8>,
                ) -> pallet_contracts_primitives::GetStorageResult {
                    Contracts::get_storage(address, key)
                }
            }

            impl node_rpc_runtime_api::transaction_payment::TransactionPaymentApi<
                Block,
            > for Runtime {
                fn query_info(uxt: <Block as BlockT>::Extrinsic, len: u32) -> RuntimeDispatchInfo<Balance> {
                    let actual = uxt.function.get_actual_weight();
                    TransactionPayment::query_info(uxt, len, actual)
                }

                fn query_fee_details(uxt: <Block as BlockT>::Extrinsic, len: u32) -> pallet_transaction_payment::FeeDetails<Balance> {
                    let actual = uxt.function.get_actual_weight();
                    TransactionPayment::query_fee_details(uxt, len, actual)
                }
            }

            impl node_rpc_runtime_api::transaction_payment::TransactionPaymentCallApi<Block, RuntimeCall>
                for Runtime
            {
                fn query_call_info(call: RuntimeCall, len: u32) -> RuntimeDispatchInfo<Balance> {
                    let actual = call.get_actual_weight();
                    TransactionPayment::query_call_info(call, len, actual)
                }
                fn query_call_fee_details(call: RuntimeCall, len: u32) -> pallet_transaction_payment::FeeDetails<Balance> {
                    let actual = call.get_actual_weight();
                    TransactionPayment::query_call_fee_details(call, len, actual)
                }
            }

            impl sp_session::SessionKeys<Block> for Runtime {
                fn generate_session_keys(seed: Option<Vec<u8>>) -> Vec<u8> {
                    SessionKeys::generate(seed)
                }

                fn decode_session_keys(
                    encoded: Vec<u8>,
                ) -> Option<Vec<(Vec<u8>, sp_core::crypto::KeyTypeId)>> {
                    SessionKeys::decode_into_raw_public_keys(&encoded)
                }
            }

            impl node_rpc_runtime_api::pips::PipsApi<Block, polymesh_primitives::AccountId>
            for Runtime
            {
                /// Vote count for the PIP identified by `id`.
                fn get_votes(id: pallet_pips::PipId) -> VoteCount {
                    Pips::get_votes(id)
                }

                /// PIPs voted on by `address`.
                fn proposed_by(address: polymesh_primitives::AccountId) -> Vec<pallet_pips::PipId> {
                    Pips::proposed_by(pallet_pips::Proposer::Community(address))
                }

                /// PIPs `address` voted on.
                fn voted_on(address: polymesh_primitives::AccountId) -> Vec<pallet_pips::PipId> {
                    Pips::voted_on(address)
                }
            }

            impl pallet_protocol_fee_rpc_runtime_api::ProtocolFeeApi<
                Block,
            > for Runtime {
                fn compute_fee(op: ProtocolOp) -> CappedFee {
                    ProtocolFee::compute_fee(&[op]).into()
                }
            }

            impl
                node_rpc_runtime_api::identity::IdentityApi<
                    Block,
                    IdentityId,
                    Ticker,
                    polymesh_primitives::AccountId,
                    Moment
                > for Runtime
            {
                /// RPC call to know whether the given did has valid cdd claim or not
                fn is_identity_has_valid_cdd(did: IdentityId, leeway: Option<u64>) -> CddStatus {
                    Identity::fetch_cdd(did, leeway.unwrap_or_default())
                        .ok_or_else(|| "Either cdd claim is expired or not yet provided to give identity".into())
                }

                /// RPC call to query the given ticker did
                fn get_asset_did(ticker: Ticker) -> AssetDidResult {
                    Identity::get_token_did(&ticker)
                        .map_err(|_| "Error in computing the given ticker error".into())
                }

                /// Retrieve primary key and secondary keys for a given IdentityId
                fn get_did_records(did: IdentityId) -> RpcDidRecords<polymesh_primitives::AccountId> {
                    Identity::get_did_records(did)
                }

                /// Retrieve the status of the DIDs
                fn get_did_status(dids: Vec<IdentityId>) -> Vec<DidStatus> {
                    Identity::get_did_status(dids)
                }

                fn get_key_identity_data(acc: polymesh_primitives::AccountId) -> Option<KeyIdentityData<IdentityId>> {
                    Identity::get_key_identity_data(acc)
                }

                /// Retrieve list of a authorization for a given signatory
                fn get_filtered_authorizations(
                    signatory: Signatory<polymesh_primitives::AccountId>,
                    allow_expired: bool,
                    auth_type: Option<polymesh_primitives::AuthorizationType>
                ) -> Vec<polymesh_primitives::Authorization<polymesh_primitives::AccountId, Moment>> {
                    Identity::get_filtered_authorizations(signatory, allow_expired, auth_type)
                }

                /// Returns all valid [`IdentityClaim`] of type `CustomerDueDiligence` for the given `target_identity`.
                fn valid_cdd_claims(target_identity: IdentityId, cdd_checker_leeway: Option<u64>) -> Vec<IdentityClaim> {
                    Identity::valid_cdd_claims(target_identity, cdd_checker_leeway)
                }
            }

            impl rpc_api_asset::AssetApi<Block, polymesh_primitives::AccountId> for Runtime {
                #[inline]
                fn can_transfer_granular(
                    from_custodian: Option<IdentityId>,
                    from_portfolio: PortfolioId,
                    to_custodian: Option<IdentityId>,
                    to_portfolio: PortfolioId,
                    ticker: &Ticker,
                    value: Balance
                ) -> FrameResult<GranularCanTransferResult, DispatchError>
                {
                    let mut weight_meter = WeightMeter::max_limit_no_minimum();
                    Asset::unsafe_can_transfer_granular(
                        from_custodian,
                        from_portfolio,
                        to_custodian,
                        to_portfolio,
                        ticker,
                        value,
                        &mut weight_meter
                    )
                }
            }

            impl pallet_group_rpc_runtime_api::GroupApi<Block> for Runtime {
                fn get_cdd_valid_members() -> Vec<pallet_group_rpc_runtime_api::Member> {
                    merge_active_and_inactive::<Block>(
                        CddServiceProviders::active_members(),
                        CddServiceProviders::inactive_members())
                }

                fn get_gc_valid_members() -> Vec<pallet_group_rpc_runtime_api::Member> {
                    merge_active_and_inactive::<Block>(
                        CommitteeMembership::active_members(),
                        CommitteeMembership::inactive_members())
                }
            }

            impl node_rpc_runtime_api::nft::NFTApi<Block> for Runtime {
                #[inline]
                fn validate_nft_transfer(
                    sender_portfolio: &PortfolioId,
                    receiver_portfolio: &PortfolioId,
                    nfts: &NFTs
                ) -> frame_support::dispatch::DispatchResult {
                    let mut weight_meter = WeightMeter::max_limit_no_minimum();
                    Nft::validate_nft_transfer(sender_portfolio, receiver_portfolio, nfts, &mut weight_meter)
                }
            }

            impl node_rpc_runtime_api::settlement::SettlementApi<Block> for Runtime {
                #[inline]
                fn get_execute_instruction_info(
                    instruction_id: &InstructionId
                ) -> ExecuteInstructionInfo {
                    Settlement::execute_instruction_info(instruction_id)
                }

                #[inline]
                fn get_affirmation_count(
                    instruction_id: InstructionId,
                    portfolios: Vec<PortfolioId>,
                ) -> AffirmationCount {
                    Settlement::affirmation_count(instruction_id, portfolios)
                }
            }

            $($extra)*
        }
    }
}
