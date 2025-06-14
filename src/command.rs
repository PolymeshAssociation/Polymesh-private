// This file is part of Substrate.

// Copyright (C) 2017-2021 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::chain_spec;
use crate::cli::{Cli, CustomChainConfig, Subcommand};
use crate::service::{
    self, develop_chain_ops, new_partial, production_chain_ops, DevelopExecutor, FullClient,
    FullServiceComponents, IsNetwork, Network, NewChainOps, ProductionExecutor,
};
use frame_benchmarking_cli::*;
use sc_cli::{ChainSpec, Result, RuntimeVersion, SubstrateCli};
use sc_service::{Configuration, TaskManager};

use core::future::Future;
use log::info;
use polymesh_primitives::Block;
use std::sync::Arc;

impl SubstrateCli for Cli {
    fn impl_name() -> String {
        "Polymesh Node".into()
    }

    fn impl_version() -> String {
        env!("CARGO_PKG_VERSION").into()
    }

    fn description() -> String {
        env!("CARGO_PKG_DESCRIPTION").into()
    }

    fn author() -> String {
        env!("CARGO_PKG_AUTHORS").into()
    }

    fn support_url() -> String {
        "https://github.com/PolymeshAssociation/Polymesh/issues/new".into()
    }

    fn copyright_start_year() -> i32 {
        2017
    }

    fn executable_name() -> String {
        "polymesh".into()
    }

    fn load_spec(&self, id: &str) -> std::result::Result<Box<dyn sc_service::ChainSpec>, String> {
        if let Some(file_path) = id.strip_prefix("config_path:") {
            let custom_chain_config = read_chain_config(file_path)?;

            return Ok(Box::new(chain_spec::custom::chain_spec(
                custom_chain_config,
            )));
        }

        Ok(match id {
            "dev" => Box::new(chain_spec::develop::develop_config()),
            "local" => Box::new(chain_spec::develop::local_config()),
            "production-dev" => Box::new(chain_spec::production::develop_config()),
            "production-local" => Box::new(chain_spec::production::local_config()),
            "production-bootstrap" => Box::new(chain_spec::production::bootstrap_config()),
            "PRODUCTION" | "production" => {
                return Err(
                    "Chain spec file required to connect to a Polymesh Private Production network"
                        .into(),
                );
            }
            path => {
                if let Some(path) = path.strip_prefix("dev:") {
                    Box::new(chain_spec::develop::ChainSpec::from_json_file(
                        std::path::PathBuf::from(path),
                    )?)
                } else if let Some(path) = path.strip_prefix("prod:") {
                    Box::new(chain_spec::production::ChainSpec::from_json_file(
                        std::path::PathBuf::from(path),
                    )?)
                } else {
                    Box::new(chain_spec::production::ChainSpec::from_json_file(
                        std::path::PathBuf::from(path),
                    )?)
                }
            }
        })
    }

    fn native_runtime_version(chain_spec: &Box<dyn ChainSpec>) -> &'static RuntimeVersion {
        match chain_spec.network() {
            Network::Production => &polymesh_private_runtime_production::runtime::VERSION,
            Network::Other => &polymesh_private_runtime_develop::runtime::VERSION,
        }
    }
}

/// Parses Polymesh specific CLI arguments and run the service.
pub fn run() -> Result<()> {
    let mut cli = Cli::from_args();

    if cli.run.operator {
        cli.run.base.validator = true;
    }

    match &cli.subcommand {
        None => {
            let runner = cli.create_runner(&cli.run.base)?;
            let network = runner.config().chain_spec.network();

            //let authority_discovery_enabled = cli.run.authority_discovery_enabled;
            info!(
                "Reserved nodes: {:?}",
                cli.run.base.network_params.reserved_nodes
            );

            runner.run_node_until_exit(|config| async move {
                match network {
                    Network::Production => service::production_new_full(config),
                    Network::Other => service::develop_new_full(config),
                }
                .map_err(sc_cli::Error::Service)
            })
        }
        Some(Subcommand::BuildSpec(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner.sync_run(|config| cmd.run(config.chain_spec, config.network))
        }
        Some(Subcommand::CheckBlock(cmd)) => async_run(
            &cli,
            cmd,
            |(c, _, iq, tm), _| Ok((cmd.run(c, iq), tm)),
            |(c, _, iq, tm), _| Ok((cmd.run(c, iq), tm)),
        ),
        Some(Subcommand::ExportBlocks(cmd)) => async_run(
            &cli,
            cmd,
            |(c, .., tm), config| Ok((cmd.run(c, config.database), tm)),
            |(c, .., tm), config| Ok((cmd.run(c, config.database), tm)),
        ),
        Some(Subcommand::ExportState(cmd)) => async_run(
            &cli,
            cmd,
            |(c, .., tm), config| Ok((cmd.run(c, config.chain_spec), tm)),
            |(c, .., tm), config| Ok((cmd.run(c, config.chain_spec), tm)),
        ),
        Some(Subcommand::ImportBlocks(cmd)) => async_run(
            &cli,
            cmd,
            |(c, _, iq, tm), _| Ok((cmd.run(c, iq), tm)),
            |(c, _, iq, tm), _| Ok((cmd.run(c, iq), tm)),
        ),
        Some(Subcommand::PurgeChain(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner.sync_run(|config| cmd.run(config.database))
        }
        Some(Subcommand::Revert(cmd)) => async_run(
            &cli,
            cmd,
            |(c, b, _, tm), _| {
                let aux_revert = Box::new(|client: Arc<FullClient<_, _>>, backend, blocks| {
                    sc_consensus_babe::revert(client.clone(), backend, blocks)?;
                    sc_consensus_grandpa::revert(client, blocks)?;
                    Ok(())
                });
                Ok((cmd.run(c, b, Some(aux_revert)), tm))
            },
            |(c, b, _, tm), _| {
                let aux_revert = Box::new(|client: Arc<FullClient<_, _>>, backend, blocks| {
                    sc_consensus_babe::revert(client.clone(), backend, blocks)?;
                    sc_consensus_grandpa::revert(client, blocks)?;
                    Ok(())
                });
                Ok((cmd.run(c, b, Some(aux_revert)), tm))
            },
        ),
        Some(Subcommand::Benchmark(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            let network = runner.config().chain_spec.network();

            runner.sync_run(|mut config| {
                match (cmd, network) {
                    (BenchmarkCmd::Pallet(cmd), Network::Other) => {
                        if !cfg!(feature = "runtime-benchmarks") {
                            return Err("Benchmarking wasn't enabled when building the node. \
			                      You can enable it with `--features runtime-benchmarks`."
                                .into());
                        }

                        cmd.run::<Block, service::DevelopExecutor>(config)
                    }
                    (BenchmarkCmd::Block(cmd), Network::Other) => {
                        let FullServiceComponents { client, .. } =
                            new_partial::<
                                polymesh_private_runtime_develop::RuntimeApi,
                                DevelopExecutor,
                            >(&mut config)?;
                        cmd.run(client)
                    }
                    #[cfg(not(feature = "runtime-benchmarks"))]
                    (BenchmarkCmd::Storage(_), Network::Other) => Err(
                        "Storage benchmarking can be enabled with `--features runtime-benchmarks`."
                            .into(),
                    ),
                    #[cfg(feature = "runtime-benchmarks")]
                    (BenchmarkCmd::Storage(cmd), Network::Other) => {
                        let FullServiceComponents {
                            client, backend, ..
                        } = new_partial::<
                            polymesh_private_runtime_develop::RuntimeApi,
                            DevelopExecutor,
                        >(&mut config)?;
                        let db = backend.expose_db();
                        let storage = backend.expose_storage();

                        cmd.run(config, client, db, storage)
                    }
                    (BenchmarkCmd::Overhead(_cmd), Network::Other) => {
                        unimplemented!();
                        /*
                                    let FullServiceComponents { client, .. } = new_partial::<polymesh_private_runtime_develop::RuntimeApi, DevelopExecutor>(&mut config)?;
                                    let ext_builder = BenchmarkExtrinsicBuilder::new(client.clone());

                        cmd.run(config, client, inherent_benchmark_data()?, Arc::new(ext_builder))
                        */
                    }
                    (BenchmarkCmd::Machine(cmd), Network::Other) => {
                        cmd.run(&config, SUBSTRATE_REFERENCE_HARDWARE.clone())
                    }
                    (_, _) => Err("Benchmarking is only supported with the `develop` runtime.")?,
                }
            })
        }
    }
}

fn async_run<G, H>(
    cli: &impl sc_cli::SubstrateCli,
    cmd: &impl sc_cli::CliConfiguration,
    develop: impl FnOnce(
        NewChainOps<polymesh_private_runtime_develop::RuntimeApi, DevelopExecutor>,
        Configuration,
    ) -> sc_cli::Result<(G, TaskManager)>,
    production: impl FnOnce(
        NewChainOps<polymesh_private_runtime_production::RuntimeApi, ProductionExecutor>,
        Configuration,
    ) -> sc_cli::Result<(H, TaskManager)>,
) -> sc_service::Result<(), sc_cli::Error>
where
    G: Future<Output = sc_cli::Result<()>>,
    H: Future<Output = sc_cli::Result<()>>,
{
    let runner = cli.create_runner(cmd)?;
    match runner.config().chain_spec.network() {
        Network::Other => {
            runner.async_run(|mut config| develop(develop_chain_ops(&mut config)?, config))
        }
        Network::Production => {
            runner.async_run(|mut config| production(production_chain_ops(&mut config)?, config))
        }
    }
}

/// Returns [`CustomChainConfig`] if `config_path` contains the path to its valid JSON file.
fn read_chain_config(config_path: &str) -> std::result::Result<CustomChainConfig, String> {
    let file = std::fs::File::open(config_path).map_err(|_| "Failed to open file".to_owned())?;
    let reader = std::io::BufReader::new(file);

    serde_json::from_reader(reader)
        .map_err(|_| "Unable to deserialize CustomChainConfig from file".into())
}
