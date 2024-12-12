use sc_chain_spec::ChainType;
use sc_network_common::config::MultiaddrWithPeerId;
use sc_telemetry::TelemetryEndpoints;
use sp_runtime::{Deserialize, Serialize};

use polymesh_primitives::AccountId;

#[derive(Debug, clap::Parser)]
pub struct Cli {
    /// Possible subcommand with parameters.
    #[clap(subcommand)]
    pub subcommand: Option<Subcommand>,
    #[allow(missing_docs)]
    #[clap(flatten)]
    pub run: PolymeshRunCmd,
}

#[allow(missing_docs)]
#[derive(Debug, clap::Parser)]
pub struct PolymeshRunCmd {
    #[allow(missing_docs)]
    #[clap(flatten)]
    pub base: sc_cli::RunCmd,
    /// Enable validator mode.
    ///
    /// It is an alias of the `--validator` flag. User has the choice to use either `--validator` or `--operator` flag both works same.
    #[clap(long)]
    pub operator: bool,
}

/// Possible subcommands of the main binary.
#[derive(Debug, clap::Subcommand)]
pub enum Subcommand {
    /// Build a chain specification.
    BuildSpec(sc_cli::BuildSpecCmd),

    /// Validate blocks.
    CheckBlock(sc_cli::CheckBlockCmd),

    /// Export blocks.
    ExportBlocks(sc_cli::ExportBlocksCmd),

    /// Export the state of a given block into a chain spec.
    ExportState(sc_cli::ExportStateCmd),

    /// Import blocks.
    ImportBlocks(sc_cli::ImportBlocksCmd),

    /// Remove the whole chain.
    PurgeChain(sc_cli::PurgeChainCmd),

    /// Revert the chain to a previous state.
    Revert(sc_cli::RevertCmd),

    /// The custom benchmark subcommmand benchmarking runtime pallets.
    #[clap(name = "benchmark", about = "Benchmark runtime pallets.")]
    #[clap(subcommand)]
    Benchmark(frame_benchmarking_cli::BenchmarkCmd),
}

/// List of chain configuration that can be customized at initialization.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CustomChainConfig {
    /// The name of the chain
    pub chain_name: String,
    /// The chain identifier
    pub chain_id: String,
    /// Sets the chain type (see [`ChainType`]).
    pub chain_type: ChainType,
    /// The address of the boot nodes (see [`MultiaddrWithPeerId`]).
    pub boot_nodes: Option<Vec<MultiaddrWithPeerId>>,
    /// List of telemetry servers we want to talk to. Contains the URL of the server, and the maximum verbosity level.
    pub telemetry_endpoints: Option<TelemetryEndpoints>,
    /// The protocol identifier
    pub protocol_id: Option<String>,
    /// Sets the account SS58 pre-fix. If `None` will default to 12.
    pub account_ss58_prefix: Option<u8>,
    /// Defines the token symbol. If `None` will default to POLYX.
    pub token_symbol: Option<String>,
    /// A list of identities that are created at initialization.
    pub initial_identities: Option<Vec<InitialIdentity>>,
    /// The amount that will be added to the funded accounts.
    pub initial_funds: Option<u128>,
    /// The polymesh commmittee coordinator account.
    pub polymesh_release_coordinator: Option<AccountId>,
    /// The technical commmittee coordinator account.
    pub technical_release_coordinator: Option<AccountId>,
    /// The upgrade commmittee coordinator account.
    pub upgrade_release_coordinator: Option<AccountId>,
    /// Set to `true` if there are no sudo accounts.
    pub disable_sudo: Option<bool>,
    /// The sudo account. If `None`, "Eve" will be the sudo account.
    pub sudo_account: Option<AccountId>,
    /// Set to `true` if no fees should be charged.
    pub disable_fees: Option<bool>,
}

/// Data needed for creating identities at initialization.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InitialIdentity {
    /// The public key of the account.
    pub account_id: AccountId,
    /// Set to `true` if the identity should be a chain validator.
    pub is_validator: bool,
    /// Set to `true` if the identity should be a CDD provider.
    pub is_cdd_provider: bool,
    /// Set to `true` if the account should be funded at initialization.
    pub is_funded: bool,
    /// Set to `true` if the account's identity should be part of the polymesh committee.
    pub polymesh_committee_member: bool,
    /// Set to `true` if the account's identity should be part of the technical committee.
    pub technical_committee_member: bool,
    /// Set to `true` if the account's identity should be part of the upgrade committee.
    pub upgrade_committee_member: bool,
}
