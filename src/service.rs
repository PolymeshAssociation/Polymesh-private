//! Service and ServiceFactory implementation. Specialized wrapper over substrate service.

use futures::stream::StreamExt;
pub use polymesh_primitives::{
    crypto::native_schnorrkel, AccountId, Block, IdentityId, Index as Nonce, Moment, Ticker,
};
pub use polymesh_private_runtime_develop;
pub use polymesh_private_runtime_production;
use prometheus_endpoint::Registry;
use sc_client_api::BlockBackend;
use sc_consensus_aura::{ImportQueueParams, SlotProportion, StartAuraParams};
use sc_consensus_grandpa::SharedVoterState;
use sc_executor::NativeElseWasmExecutor;
pub use sc_executor::NativeExecutionDispatch;
use sc_network::NetworkService;
use sc_service::{
    config::Configuration, error::Error as ServiceError, RpcHandlers, TaskManager, WarpSyncParams,
};
pub use sc_service::{config::PrometheusConfig, ChainSpec, Error};
use sc_telemetry::{Telemetry, TelemetryWorker};
pub use sp_api::ConstructRuntimeApi;
use sp_consensus_aura::sr25519::{AuthorityId as AuraId, AuthorityPair as AuraPair};
pub use sp_runtime::traits::BlakeTwo256;
use sp_runtime::traits::Block as BlockT;
use std::{sync::Arc, time::Duration};

/// Known networks based on name.
pub enum Network {
    Production,
    Other,
}

pub trait IsNetwork {
    fn network(&self) -> Network;
}

impl IsNetwork for dyn ChainSpec {
    fn network(&self) -> Network {
        let name = self.name();
        if name.starts_with("Polymesh Private Production") {
            Network::Production
        } else {
            Network::Other
        }
    }
}

macro_rules! native_executor_instance {
    ($exec:ident, $module:ident, $ehf:ty) => {
        pub struct $exec;
        impl NativeExecutionDispatch for $exec {
            type ExtendHostFunctions = $ehf;

            fn dispatch(method: &str, data: &[u8]) -> Option<Vec<u8>> {
                $module::api::dispatch(method, data)
            }

            fn native_version() -> sc_executor::NativeVersion {
                $module::native_version()
            }
        }
    };
}

type EHF = (
    frame_benchmarking::benchmarking::HostFunctions,
    polymesh_host_functions::native_confidential_assets::HostFunctions,
);

native_executor_instance!(
    DevelopExecutor,
    polymesh_private_runtime_develop,
    (EHF, native_schnorrkel::HostFunctions)
);
native_executor_instance!(ProductionExecutor, polymesh_private_runtime_production, EHF);

/// A set of APIs that polkadot-like runtimes must implement.
pub trait RuntimeApiCollection:
    sp_transaction_pool::runtime_api::TaggedTransactionQueue<Block>
    + sp_api::ApiExt<Block>
    + sp_consensus_aura::AuraApi<Block, AuraId>
    + sc_consensus_grandpa::GrandpaApi<Block>
    + sp_block_builder::BlockBuilder<Block>
    + frame_system_rpc_runtime_api::AccountNonceApi<Block, AccountId, Nonce>
    + node_rpc_runtime_api::transaction_payment::TransactionPaymentApi<Block>
    + sp_api::Metadata<Block>
    + sp_offchain::OffchainWorkerApi<Block>
    + sp_session::SessionKeys<Block>
    + node_rpc_runtime_api::pips::PipsApi<Block, AccountId>
    + node_rpc_runtime_api::identity::IdentityApi<Block, IdentityId, Ticker, AccountId, Moment>
    + pallet_protocol_fee_rpc_runtime_api::ProtocolFeeApi<Block>
    + node_rpc_runtime_api::asset::AssetApi<Block, AccountId>
    + pallet_group_rpc_runtime_api::GroupApi<Block>
    + node_rpc_runtime_api::nft::NFTApi<Block>
    + node_rpc_runtime_api::settlement::SettlementApi<Block>
where
    <Self as sp_api::ApiExt<Block>>::StateBackend: sp_api::StateBackend<BlakeTwo256>,
{
}

impl<Api> RuntimeApiCollection for Api
where
    Api: sp_transaction_pool::runtime_api::TaggedTransactionQueue<Block>
        + sp_api::ApiExt<Block>
        + sp_consensus_aura::AuraApi<Block, AuraId>
        + sc_consensus_grandpa::GrandpaApi<Block>
        + sp_block_builder::BlockBuilder<Block>
        + frame_system_rpc_runtime_api::AccountNonceApi<Block, AccountId, Nonce>
        + node_rpc_runtime_api::transaction_payment::TransactionPaymentApi<Block>
        + sp_api::Metadata<Block>
        + sp_offchain::OffchainWorkerApi<Block>
        + sp_session::SessionKeys<Block>
        + node_rpc_runtime_api::pips::PipsApi<Block, AccountId>
        + node_rpc_runtime_api::identity::IdentityApi<Block, IdentityId, Ticker, AccountId, Moment>
        + pallet_protocol_fee_rpc_runtime_api::ProtocolFeeApi<Block>
        + node_rpc_runtime_api::asset::AssetApi<Block, AccountId>
        + pallet_group_rpc_runtime_api::GroupApi<Block>
        + node_rpc_runtime_api::nft::NFTApi<Block>
        + node_rpc_runtime_api::settlement::SettlementApi<Block>,
    <Self as sp_api::ApiExt<Block>>::StateBackend: sp_api::StateBackend<BlakeTwo256>,
{
}

// Using prometheus, use a registry with a prefix of `polymesh`.
fn set_prometheus_registry(config: &mut Configuration) -> Result<(), ServiceError> {
    if let Some(PrometheusConfig { registry, .. }) = config.prometheus_config.as_mut() {
        *registry = Registry::new_custom(Some("polymesh".into()), None)?;
    }

    Ok(())
}

type FullLinkHalf<R, D> = sc_consensus_grandpa::LinkHalf<Block, FullClient<R, D>, FullSelectChain>;
pub type FullClient<R, D> = sc_service::TFullClient<Block, R, NativeElseWasmExecutor<D>>;
type FullBackend = sc_service::TFullBackend<Block>;
type FullSelectChain = sc_consensus::LongestChain<FullBackend, Block>;
type FullGrandpaBlockImport<R, D> =
    sc_consensus_grandpa::GrandpaBlockImport<FullBackend, Block, FullClient<R, D>, FullSelectChain>;
type FullAuraImportQueue<R, D> = sc_consensus::DefaultImportQueue<Block, FullClient<R, D>>;
type FullStateBackend = sc_client_api::StateBackendFor<FullBackend, Block>;
type FullPool<R, D> = sc_transaction_pool::FullPool<Block, FullClient<R, D>>;
pub type FullServiceComponents<R, D, F> = sc_service::PartialComponents<
    FullClient<R, D>,
    FullBackend,
    FullSelectChain,
    FullAuraImportQueue<R, D>,
    FullPool<R, D>,
    (
        F,
        (FullGrandpaBlockImport<R, D>, FullLinkHalf<R, D>),
        Option<Telemetry>,
    ),
>;

pub fn new_partial<R, D>(
    config: &mut Configuration,
) -> Result<
    FullServiceComponents<
        R,
        D,
        impl Fn(
            sc_rpc::DenyUnsafe,
            sc_rpc::SubscriptionTaskExecutor,
        ) -> Result<jsonrpsee::RpcModule<()>, Error>,
    >,
    Error,
>
where
    R: ConstructRuntimeApi<Block, FullClient<R, D>> + Send + Sync + 'static,
    R::RuntimeApi: RuntimeApiCollection<StateBackend = FullStateBackend>,
    D: NativeExecutionDispatch + 'static,
{
    set_prometheus_registry(config)?;
    // TODO: handle `keystore_remote`.

    let telemetry = config
        .telemetry_endpoints
        .clone()
        .filter(|x| !x.is_empty())
        .map(|endpoints| -> Result<_, sc_telemetry::Error> {
            let worker = TelemetryWorker::new(16)?;
            let telemetry = worker.handle().new_telemetry(endpoints);
            Ok((worker, telemetry))
        })
        .transpose()?;

    let executor = NativeElseWasmExecutor::<D>::new(
        config.wasm_method,
        config.default_heap_pages,
        config.max_runtime_instances,
        config.runtime_cache_size,
    );

    let (client, backend, keystore_container, task_manager) =
        sc_service::new_full_parts::<Block, R, NativeElseWasmExecutor<D>>(
            config,
            telemetry.as_ref().map(|(_, telemetry)| telemetry.handle()),
            executor,
        )?;
    let client = Arc::new(client);

    let telemetry = telemetry.map(|(worker, telemetry)| {
        task_manager
            .spawn_handle()
            .spawn("telemetry", None, worker.run());
        telemetry
    });

    let select_chain = sc_consensus::LongestChain::new(backend.clone());

    let transaction_pool = sc_transaction_pool::BasicPool::new_full(
        config.transaction_pool.clone(),
        config.role.is_authority().into(),
        config.prometheus_registry(),
        task_manager.spawn_essential_handle(),
        client.clone(),
    );

    let (grandpa_block_import, grandpa_link) = sc_consensus_grandpa::block_import(
        client.clone(),
        &(client.clone() as Arc<_>),
        select_chain.clone(),
        telemetry.as_ref().map(|x| x.handle()),
    )?;

    let slot_duration = sc_consensus_aura::slot_duration(&*client)?;

    let import_queue = sc_consensus_aura::import_queue::<AuraPair, _, _, _, _, _>(
        ImportQueueParams {
            block_import: grandpa_block_import.clone(),
            justification_import: Some(Box::new(grandpa_block_import.clone())),
            client: client.clone(),
            create_inherent_data_providers: move |_, ()| async move {
                let timestamp = sp_timestamp::InherentDataProvider::from_system_time();

                let slot =
                sp_consensus_aura::inherents::InherentDataProvider::from_timestamp_and_slot_duration(
                    *timestamp,
                    slot_duration,
                );

                Ok((slot, timestamp))
            },
            spawner: &task_manager.spawn_essential_handle(),
            registry: config.prometheus_registry(),
            check_for_equivocation: Default::default(),
            telemetry: telemetry.as_ref().map(|x| x.handle()),
            compatibility_mode: Default::default(),
        },
    )?;

    let import_setup = (grandpa_block_import, grandpa_link);

    let (rpc_extensions_builder, rpc_setup) = {
        let (_, grandpa_link) = &import_setup;

        let justification_stream = grandpa_link.justification_stream();
        let shared_authority_set = grandpa_link.shared_authority_set().clone();
        let shared_voter_state = SharedVoterState::empty();

        let finality_proof_provider = sc_consensus_grandpa::FinalityProofProvider::new_for_service(
            backend.clone(),
            Some(shared_authority_set.clone()),
        );

        let client = client.clone();
        let pool = transaction_pool.clone();
        let select_chain = select_chain.clone();
        let chain_spec = config.chain_spec.cloned_box();

        let rpc_backend = backend.clone();
        let rpc_extensions_builder = move |deny_unsafe, subscription_executor| {
            let deps = crate::rpc::FullDeps {
                client: client.clone(),
                pool: pool.clone(),
                select_chain: select_chain.clone(),
                chain_spec: chain_spec.cloned_box(),
                deny_unsafe,
                grandpa: crate::rpc::GrandpaDeps {
                    shared_voter_state,
                    shared_authority_set: shared_authority_set.clone(),
                    justification_stream: justification_stream.clone(),
                    subscription_executor,
                    finality_provider: finality_proof_provider.clone(),
                },
            };

            crate::rpc::create_full(deps, rpc_backend.clone()).map_err(Into::into)
        };

        rpc_extensions_builder
    };

    Ok(sc_service::PartialComponents {
        client,
        backend,
        task_manager,
        import_queue,
        keystore_container,
        select_chain,
        transaction_pool,
        other: (rpc_extensions_builder, import_setup, telemetry),
    })
}

pub struct NewFullBase<R, D>
where
    R: ConstructRuntimeApi<Block, FullClient<R, D>> + Send + Sync + 'static,
    R::RuntimeApi: RuntimeApiCollection<StateBackend = FullStateBackend>,
    D: NativeExecutionDispatch + 'static,
{
    /// The task manager of the node.
    pub task_manager: TaskManager,
    /// The client instance of the node.
    pub client: Arc<FullClient<R, D>>,
    /// The networking service of the node.
    pub network: Arc<NetworkService<Block, <Block as BlockT>::Hash>>,
    /// The transaction pool of the node.
    pub transaction_pool: Arc<FullPool<R, D>>,
    /// The rpc handlers of the node.
    pub rpc_handlers: RpcHandlers,
}

/// Creates a full service from the configuration.
pub fn new_full_base<R, D, F>(
    mut config: Configuration,
    with_startup_data: F,
) -> Result<NewFullBase<R, D>, ServiceError>
where
    F: FnOnce(&FullGrandpaBlockImport<R, D>),
    R: ConstructRuntimeApi<Block, FullClient<R, D>> + Send + Sync + 'static,
    R::RuntimeApi: RuntimeApiCollection<StateBackend = FullStateBackend>,
    D: NativeExecutionDispatch + 'static,
{
    let sc_service::PartialComponents {
        client,
        backend,
        mut task_manager,
        import_queue,
        keystore_container,
        select_chain,
        transaction_pool,
        other: (rpc_builder, (block_import, grandpa_link), mut telemetry),
    } = new_partial(&mut config)?;

    // TODO: Handle remote keystore.

    let grandpa_protocol_name = sc_consensus_grandpa::protocol_standard_name(
        &client
            .block_hash(0)
            .ok()
            .flatten()
            .expect("Genesis block exists; qed"),
        &config.chain_spec,
    );

    config
        .network
        .extra_sets
        .push(sc_consensus_grandpa::grandpa_peers_set_config(
            grandpa_protocol_name.clone(),
        ));
    let warp_sync = Arc::new(sc_consensus_grandpa::warp_proof::NetworkProvider::new(
        backend.clone(),
        grandpa_link.shared_authority_set().clone(),
        Vec::default(),
    ));

    #[cfg(feature = "cli")]
    config.network.request_response_protocols.push(
        sc_consensus_grandpa_warp_sync::request_response_config_for_chain(
            &config,
            task_manager.spawn_handle(),
            backend.clone(),
        ),
    );

    let (network, system_rpc_tx, tx_handler_controller, network_starter) =
        sc_service::build_network(sc_service::BuildNetworkParams {
            config: &config,
            client: client.clone(),
            transaction_pool: transaction_pool.clone(),
            spawn_handle: task_manager.spawn_handle(),
            import_queue,
            block_announce_validator_builder: None,
            warp_sync_params: Some(WarpSyncParams::WithProvider(warp_sync)),
        })?;

    if config.offchain_worker.enabled {
        sc_service::build_offchain_workers(
            &config,
            task_manager.spawn_handle(),
            client.clone(),
            network.clone(),
        );
    }

    let role = config.role.clone();
    let force_authoring = config.force_authoring;
    let backoff_authoring_blocks: Option<()> = None;
    let name = config.network.node_name.clone();
    let enable_grandpa = !config.disable_grandpa;
    let prometheus_registry = config.prometheus_registry().cloned();

    let rpc_handlers = sc_service::spawn_tasks(sc_service::SpawnTasksParams {
        network: network.clone(),
        client: client.clone(),
        keystore: keystore_container.sync_keystore(),
        task_manager: &mut task_manager,
        transaction_pool: transaction_pool.clone(),
        rpc_builder: Box::new(rpc_builder),
        backend,
        system_rpc_tx,
        tx_handler_controller,
        config,
        telemetry: telemetry.as_mut(),
    })?;

    (with_startup_data)(&block_import);

    if role.is_authority() {
        let proposer_factory = sc_basic_authorship::ProposerFactory::new(
            task_manager.spawn_handle(),
            client.clone(),
            transaction_pool.clone(),
            prometheus_registry.as_ref(),
            telemetry.as_ref().map(|x| x.handle()),
        );

        let slot_duration = sc_consensus_aura::slot_duration(&*client)?;

        let aura_config = StartAuraParams {
            slot_duration,
            client,
            select_chain,
            block_import,
            proposer_factory,
            create_inherent_data_providers: move |_, ()| async move {
                let timestamp = sp_timestamp::InherentDataProvider::from_system_time();

                let slot =
                    sp_consensus_aura::inherents::InherentDataProvider::from_timestamp_and_slot_duration(
                        *timestamp,
                        slot_duration,
                    );

                Ok((slot, timestamp))
            },
            force_authoring,
            backoff_authoring_blocks,
            keystore: keystore_container.sync_keystore(),
            sync_oracle: network.clone(),
            justification_sync_link: network.clone(),
            block_proposal_slot_portion: SlotProportion::new(2f32 / 3f32),
            max_block_proposal_slot_portion: None,
            telemetry: telemetry.as_ref().map(|x| x.handle()),
            compatibility_mode: Default::default(),
        };

        let aura = sc_consensus_aura::start_aura(aura_config)?;
        task_manager
            .spawn_essential_handle()
            .spawn_blocking("aura", Some("block-authoring"), aura);
    }

    if enable_grandpa {
        // if the node isn't actively participating in consensus then it doesn't
        // need a keystore, regardless of which protocol we use below.
        let keystore = if role.is_authority() {
            Some(keystore_container.sync_keystore())
        } else {
            None
        };

        let config = sc_consensus_grandpa::Config {
            // FIXME #1578 make this available through chainspec
            gossip_duration: Duration::from_millis(333),
            justification_period: 512,
            name: Some(name),
            observer_enabled: false,
            keystore,
            local_role: role,
            telemetry: telemetry.as_ref().map(|x| x.handle()),
            protocol_name: grandpa_protocol_name,
        };

        // start the full GRANDPA voter
        // NOTE: non-authorities could run the GRANDPA observer protocol, but at
        // this point the full voter should provide better guarantees of block
        // and vote data availability than the observer. The observer has not
        // been tested extensively yet and having most nodes in a network run it
        // could lead to finality stalls.
        let grandpa_config = sc_consensus_grandpa::GrandpaParams {
            config,
            link: grandpa_link,
            network,
            voting_rule: sc_consensus_grandpa::VotingRulesBuilder::default().build(),
            prometheus_registry,
            shared_voter_state: SharedVoterState::empty(),
            telemetry: telemetry.as_ref().map(|x| x.handle()),
        };

        // the GRANDPA voter task is considered infallible, i.e.
        // if it fails we take down the service with it.
        task_manager.spawn_essential_handle().spawn_blocking(
            "grandpa-voter",
            None,
            sc_consensus_grandpa::run_grandpa_voter(grandpa_config)?,
        );
    }

    network_starter.start_network();
    Ok(NewFullBase {
        task_manager,
        client,
        network,
        transaction_pool,
        rpc_handlers,
    })
}

type TaskResult = Result<TaskManager, ServiceError>;

/// Create a new Develop node service for a full node.
pub fn develop_new_full(config: Configuration) -> TaskResult {
    new_full_base::<polymesh_private_runtime_develop::RuntimeApi, DevelopExecutor, _>(
        config,
        |_| (),
    )
    .map(|data| data.task_manager)
}

/// Create a new Production service for a full node.
pub fn production_new_full(config: Configuration) -> TaskResult {
    new_full_base::<polymesh_private_runtime_production::RuntimeApi, ProductionExecutor, _>(
        config,
        |_| (),
    )
    .map(|data| data.task_manager)
}

pub type NewChainOps<R, D> = (
    Arc<FullClient<R, D>>,
    Arc<FullBackend>,
    FullAuraImportQueue<R, D>,
    TaskManager,
);

/// Builds a new object suitable for chain operations.
pub fn chain_ops<R, D>(config: &mut Configuration) -> Result<NewChainOps<R, D>, ServiceError>
where
    R: ConstructRuntimeApi<Block, FullClient<R, D>> + Send + Sync + 'static,
    R::RuntimeApi: RuntimeApiCollection<StateBackend = FullStateBackend>,
    D: NativeExecutionDispatch + 'static,
{
    config.keystore = sc_service::config::KeystoreConfig::InMemory;
    let FullServiceComponents {
        client,
        backend,
        import_queue,
        task_manager,
        ..
    } = new_partial::<R, D>(config)?;
    Ok((client, backend, import_queue, task_manager))
}

pub fn develop_chain_ops(
    config: &mut Configuration,
) -> Result<NewChainOps<polymesh_private_runtime_develop::RuntimeApi, DevelopExecutor>, ServiceError>
{
    chain_ops::<_, _>(config)
}

pub fn production_chain_ops(
    config: &mut Configuration,
) -> Result<
    NewChainOps<polymesh_private_runtime_production::RuntimeApi, ProductionExecutor>,
    ServiceError,
> {
    chain_ops::<_, _>(config)
}
