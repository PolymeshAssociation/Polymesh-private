//! A collection of node-specific RPC methods.
//!
//! Substrate provides the `sc-rpc` crate, which defines the core RPC layer
//! used by Substrate nodes. This file extends those RPC definitions with
//! capabilities that are specific to this project's runtime configuration.

#![warn(missing_docs)]

use std::sync::Arc;

use jsonrpsee::RpcModule;
use polymesh_primitives::{AccountId, Block, BlockNumber, Hash, IdentityId, Index, Moment, Ticker};
use sc_client_api::AuxStore;
use sc_consensus_grandpa::{
    FinalityProofProvider, GrandpaJustificationStream, SharedAuthoritySet, SharedVoterState,
};
use sc_rpc::SubscriptionTaskExecutor;
pub use sc_rpc_api::DenyUnsafe;
use sc_transaction_pool_api::TransactionPool;
use sp_api::ProvideRuntimeApi;
use sp_block_builder::BlockBuilder;
use sp_blockchain::{Error as BlockChainError, HeaderBackend, HeaderMetadata};
use sp_consensus::SelectChain;

/// Extra dependencies for GRANDPA
pub struct GrandpaDeps<B> {
    /// Voting round info.
    pub shared_voter_state: SharedVoterState,
    /// Authority set info.
    pub shared_authority_set: SharedAuthoritySet<Hash, BlockNumber>,
    /// Receives notifications about justification events from Grandpa.
    pub justification_stream: GrandpaJustificationStream<Block>,
    /// Executor to drive the subscription manager in the Grandpa RPC handler.
    pub subscription_executor: SubscriptionTaskExecutor,
    /// Finality proof provider.
    pub finality_provider: Arc<FinalityProofProvider<B, Block>>,
}

/// Full client dependencies.
pub struct FullDeps<C, P, SC, B> {
    /// The client instance to use.
    pub client: Arc<C>,
    /// Transaction pool instance.
    pub pool: Arc<P>,
    /// The SelectChain Strategy
    pub select_chain: SC,
    /// A copy of the chain spec.
    pub chain_spec: Box<dyn sc_chain_spec::ChainSpec>,
    /// Whether to deny unsafe calls
    pub deny_unsafe: DenyUnsafe,
    /// GRANDPA specific dependencies.
    pub grandpa: GrandpaDeps<B>,
}

/// Instantiate all Full RPC extensions.
pub fn create_full<C, P, SC, B>(
    deps: FullDeps<C, P, SC, B>,
    backend: Arc<B>,
) -> Result<RpcModule<()>, Box<dyn std::error::Error + Send + Sync>>
where
    C: ProvideRuntimeApi<Block>
        + sc_client_api::BlockBackend<Block>
        + HeaderBackend<Block>
        + AuxStore
        + HeaderMetadata<Block, Error = BlockChainError>
        + Sync
        + Send
        + 'static,
    C::Api: substrate_frame_rpc_system::AccountNonceApi<Block, AccountId, Index>,
    C::Api: node_rpc::transaction_payment::TransactionPaymentRuntimeApi<Block>,
    C::Api: node_rpc::pips::PipsRuntimeApi<Block, AccountId>,
    C::Api: node_rpc::identity::IdentityRuntimeApi<Block, IdentityId, Ticker, AccountId, Moment>,
    C::Api: pallet_protocol_fee_rpc::ProtocolFeeRuntimeApi<Block>,
    C::Api: node_rpc::asset::AssetRuntimeApi<Block, AccountId>,
    C::Api: pallet_group_rpc::GroupRuntimeApi<Block>,
    C::Api: BlockBuilder<Block>,
    C::Api: node_rpc::nft::NFTRuntimeApi<Block>,
    C::Api: node_rpc::settlement::SettlementRuntimeApi<Block>,
    P: TransactionPool + 'static,
    SC: SelectChain<Block> + 'static,
    B: sc_client_api::Backend<Block> + Send + Sync + 'static,
    B::State: sc_client_api::backend::StateBackend<sp_runtime::traits::HashFor<Block>>,
{
    use node_rpc::{
        asset::{Asset, AssetApiServer},
        identity::{Identity, IdentityApiServer},
        nft::{NFTApiServer, NFT},
        pips::{Pips, PipsApiServer},
        settlement::{Settlement, SettlementApiServer},
        transaction_payment::{TransactionPayment, TransactionPaymentApiServer},
    };
    use pallet_group_rpc::{Group, GroupApiServer};
    use pallet_protocol_fee_rpc::{ProtocolFee, ProtocolFeeApiServer};
    use sc_consensus_grandpa_rpc::{Grandpa, GrandpaApiServer};
    use sc_rpc::dev::{Dev, DevApiServer};
    use sc_rpc_spec_v2::chain_spec::{ChainSpec, ChainSpecApiServer};
    use substrate_frame_rpc_system::{System, SystemApiServer};
    use substrate_state_trie_migration_rpc::{StateMigration, StateMigrationApiServer};

    let mut io = RpcModule::new(());
    let FullDeps {
        client,
        pool,
        select_chain,
        chain_spec,
        deny_unsafe,
        grandpa,
    } = deps;

    let GrandpaDeps {
        shared_voter_state,
        shared_authority_set,
        justification_stream,
        subscription_executor,
        finality_provider,
    } = grandpa;

    let chain_name = chain_spec.name().to_string();
    let genesis_hash = client
        .block_hash(0)
        .ok()
        .flatten()
        .expect("Genesis block exists; qed");
    let properties = chain_spec.properties();
    io.merge(ChainSpec::new(chain_name, genesis_hash, properties).into_rpc())?;

    io.merge(System::new(client.clone(), pool, deny_unsafe).into_rpc())?;
    io.merge(TransactionPayment::new(client.clone()).into_rpc())?;
    io.merge(
        Grandpa::new(
            subscription_executor,
            shared_authority_set,
            shared_voter_state,
            justification_stream,
            finality_provider,
        )
        .into_rpc(),
    )?;

    io.merge(StateMigration::new(client.clone(), backend, deny_unsafe).into_rpc())?;
    io.merge(Dev::new(client.clone(), deny_unsafe).into_rpc())?;

    io.merge(Pips::new(client.clone()).into_rpc())?;
    io.merge(Identity::new(client.clone()).into_rpc())?;
    io.merge(ProtocolFee::new(client.clone()).into_rpc())?;
    io.merge(Asset::new(client.clone()).into_rpc())?;
    io.merge(Group::from(client.clone()).into_rpc())?;
    io.merge(NFT::new(client.clone()).into_rpc())?;
    io.merge(Settlement::new(client).into_rpc())?;

    Ok(io)
}
