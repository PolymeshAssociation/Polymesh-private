// This file is part of Substrate.

// Copyright (C) 2021 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Autogenerated weights for pallet_sto
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 4.0.0-dev
//! DATE: 2024-06-06, STEPS: `100`, REPEAT: 5, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! EXECUTION: Some(Native), WASM-EXECUTION: Compiled, CHAIN: None, DB CACHE: 512
//! HOSTNAME: `trinity`, CPU: `AMD Ryzen 9 7950X 16-Core Processor`

// Executed Command:
// ./target/release/polymesh-private
// benchmark
// pallet
// -s
// 100
// -r
// 5
// -p=pallet_sto
// -e=*
// --heap-pages
// 4096
// --db-cache
// 512
// --execution
// native
// --output
// ./pallets/weights/src/
// --template
// ./.maintain/frame-weight-template.hbs

#![allow(unused_parens)]
#![allow(unused_imports)]

use polymesh_runtime_common::{RocksDbWeight as DbWeight, Weight};

/// Weights for pallet_sto using the Substrate node and recommended hardware.
pub struct SubstrateWeight;
impl pallet_sto::WeightInfo for SubstrateWeight {
    // Storage: Identity KeyRecords (r:1 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: ExternalAgents GroupOfAgent (r:1 w:0)
    // Proof Skipped: ExternalAgents GroupOfAgent (max_values: None, max_size: None, mode: Measured)
    // Storage: Permissions CurrentPalletName (r:1 w:0)
    // Proof Skipped: Permissions CurrentPalletName (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Permissions CurrentDispatchableName (r:1 w:0)
    // Proof Skipped: Permissions CurrentDispatchableName (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Settlement VenueInfo (r:1 w:0)
    // Proof Skipped: Settlement VenueInfo (max_values: None, max_size: None, mode: Measured)
    // Storage: Portfolio PortfolioCustodian (r:2 w:0)
    // Proof Skipped: Portfolio PortfolioCustodian (max_values: None, max_size: None, mode: Measured)
    // Storage: Timestamp Now (r:1 w:0)
    // Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
    // Storage: Sto FundraiserCount (r:1 w:1)
    // Proof Skipped: Sto FundraiserCount (max_values: None, max_size: None, mode: Measured)
    // Storage: Asset Tokens (r:1 w:0)
    // Proof Skipped: Asset Tokens (max_values: None, max_size: None, mode: Measured)
    // Storage: Portfolio PortfolioAssetBalances (r:1 w:0)
    // Proof Skipped: Portfolio PortfolioAssetBalances (max_values: None, max_size: None, mode: Measured)
    // Storage: Portfolio PortfolioLockedAssets (r:1 w:1)
    // Proof Skipped: Portfolio PortfolioLockedAssets (max_values: None, max_size: None, mode: Measured)
    // Storage: Sto FundraiserNames (r:0 w:1)
    // Proof Skipped: Sto FundraiserNames (max_values: None, max_size: None, mode: Measured)
    // Storage: Sto Fundraisers (r:0 w:1)
    // Proof Skipped: Sto Fundraisers (max_values: None, max_size: None, mode: Measured)
    /// The range of component `i` is `[1, 10]`.
    fn create_fundraiser(i: u32) -> Weight {
        // Minimum execution time: 35_967 nanoseconds.
        Weight::from_ref_time(36_895_572)
            // Standard Error: 14_303
            .saturating_add(Weight::from_ref_time(101_916).saturating_mul(i.into()))
            .saturating_add(DbWeight::get().reads(12))
            .saturating_add(DbWeight::get().writes(4))
    }
    // Storage: Identity KeyRecords (r:1 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: Portfolio PortfolioCustodian (r:4 w:0)
    // Proof Skipped: Portfolio PortfolioCustodian (max_values: None, max_size: None, mode: Measured)
    // Storage: Sto Fundraisers (r:1 w:1)
    // Proof Skipped: Sto Fundraisers (max_values: None, max_size: None, mode: Measured)
    // Storage: Timestamp Now (r:1 w:0)
    // Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
    // Storage: Portfolio PortfolioLockedAssets (r:2 w:2)
    // Proof Skipped: Portfolio PortfolioLockedAssets (max_values: None, max_size: None, mode: Measured)
    // Storage: Settlement VenueInfo (r:1 w:0)
    // Proof Skipped: Settlement VenueInfo (max_values: None, max_size: None, mode: Measured)
    // Storage: Asset Tokens (r:2 w:0)
    // Proof Skipped: Asset Tokens (max_values: None, max_size: None, mode: Measured)
    // Storage: Settlement VenueFiltering (r:2 w:0)
    // Proof Skipped: Settlement VenueFiltering (max_values: None, max_size: None, mode: Measured)
    // Storage: Asset TickersExemptFromAffirmation (r:2 w:0)
    // Proof Skipped: Asset TickersExemptFromAffirmation (max_values: None, max_size: None, mode: Measured)
    // Storage: Asset PreApprovedTicker (r:2 w:0)
    // Proof Skipped: Asset PreApprovedTicker (max_values: None, max_size: None, mode: Measured)
    // Storage: Portfolio PreApprovedPortfolios (r:2 w:0)
    // Proof Skipped: Portfolio PreApprovedPortfolios (max_values: None, max_size: None, mode: Measured)
    // Storage: Asset MandatoryMediators (r:2 w:0)
    // Proof Skipped: Asset MandatoryMediators (max_values: None, max_size: None, mode: Measured)
    // Storage: Settlement InstructionCounter (r:1 w:1)
    // Proof Skipped: Settlement InstructionCounter (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Settlement InstructionLegs (r:3 w:2)
    // Proof Skipped: Settlement InstructionLegs (max_values: None, max_size: None, mode: Measured)
    // Storage: Portfolio PortfolioAssetBalances (r:4 w:4)
    // Proof Skipped: Portfolio PortfolioAssetBalances (max_values: None, max_size: None, mode: Measured)
    // Storage: Settlement InstructionMediatorsAffirmations (r:1 w:0)
    // Proof Skipped: Settlement InstructionMediatorsAffirmations (max_values: None, max_size: None, mode: Measured)
    // Storage: Settlement InstructionMemos (r:1 w:0)
    // Proof Skipped: Settlement InstructionMemos (max_values: None, max_size: None, mode: Measured)
    // Storage: Asset BalanceOf (r:4 w:4)
    // Proof Skipped: Asset BalanceOf (max_values: None, max_size: None, mode: Measured)
    // Storage: Portfolio Portfolios (r:4 w:0)
    // Proof Skipped: Portfolio Portfolios (max_values: None, max_size: None, mode: Measured)
    // Storage: Asset Frozen (r:2 w:0)
    // Proof Skipped: Asset Frozen (max_values: None, max_size: None, mode: Measured)
    // Storage: Instance2Group ActiveMembers (r:1 w:0)
    // Proof Skipped: Instance2Group ActiveMembers (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Identity Claims (r:46 w:0)
    // Proof Skipped: Identity Claims (max_values: None, max_size: None, mode: Measured)
    // Storage: Statistics AssetTransferCompliances (r:2 w:0)
    // Proof Skipped: Statistics AssetTransferCompliances (max_values: None, max_size: None, mode: Measured)
    // Storage: Statistics AssetStats (r:28 w:20)
    // Proof Skipped: Statistics AssetStats (max_values: None, max_size: None, mode: Measured)
    // Storage: ComplianceManager AssetCompliances (r:2 w:0)
    // Proof Skipped: ComplianceManager AssetCompliances (max_values: None, max_size: None, mode: Measured)
    // Storage: Checkpoint CachedNextCheckpoints (r:2 w:0)
    // Proof Skipped: Checkpoint CachedNextCheckpoints (max_values: None, max_size: None, mode: Measured)
    // Storage: Checkpoint CheckpointIdSequence (r:2 w:0)
    // Proof Skipped: Checkpoint CheckpointIdSequence (max_values: None, max_size: None, mode: Measured)
    // Storage: Portfolio PortfolioAssetCount (r:2 w:2)
    // Proof Skipped: Portfolio PortfolioAssetCount (max_values: None, max_size: None, mode: Measured)
    // Storage: Statistics ActiveAssetStats (r:2 w:0)
    // Proof Skipped: Statistics ActiveAssetStats (max_values: None, max_size: None, mode: Measured)
    // Storage: Settlement UserAffirmations (r:0 w:4)
    // Proof Skipped: Settlement UserAffirmations (max_values: None, max_size: None, mode: Measured)
    // Storage: Settlement InstructionAffirmsPending (r:0 w:1)
    // Proof Skipped: Settlement InstructionAffirmsPending (max_values: None, max_size: None, mode: Measured)
    // Storage: Settlement InstructionStatuses (r:0 w:1)
    // Proof Skipped: Settlement InstructionStatuses (max_values: None, max_size: None, mode: Measured)
    // Storage: Settlement InstructionDetails (r:0 w:1)
    // Proof Skipped: Settlement InstructionDetails (max_values: None, max_size: None, mode: Measured)
    // Storage: Settlement VenueInstructions (r:0 w:1)
    // Proof Skipped: Settlement VenueInstructions (max_values: None, max_size: None, mode: Measured)
    // Storage: Settlement AffirmsReceived (r:0 w:4)
    // Proof Skipped: Settlement AffirmsReceived (max_values: None, max_size: None, mode: Measured)
    // Storage: Settlement InstructionLegStatus (r:0 w:2)
    // Proof Skipped: Settlement InstructionLegStatus (max_values: None, max_size: None, mode: Measured)
    fn invest() -> Weight {
        // Minimum execution time: 340_457 nanoseconds.
        Weight::from_ref_time(346_759_000)
            .saturating_add(DbWeight::get().reads(129))
            .saturating_add(DbWeight::get().writes(50))
    }
    // Storage: Identity KeyRecords (r:1 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: ExternalAgents GroupOfAgent (r:1 w:0)
    // Proof Skipped: ExternalAgents GroupOfAgent (max_values: None, max_size: None, mode: Measured)
    // Storage: Permissions CurrentPalletName (r:1 w:0)
    // Proof Skipped: Permissions CurrentPalletName (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Permissions CurrentDispatchableName (r:1 w:0)
    // Proof Skipped: Permissions CurrentDispatchableName (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Sto Fundraisers (r:1 w:1)
    // Proof Skipped: Sto Fundraisers (max_values: None, max_size: None, mode: Measured)
    fn freeze_fundraiser() -> Weight {
        // Minimum execution time: 18_564 nanoseconds.
        Weight::from_ref_time(18_966_000)
            .saturating_add(DbWeight::get().reads(5))
            .saturating_add(DbWeight::get().writes(1))
    }
    // Storage: Identity KeyRecords (r:1 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: ExternalAgents GroupOfAgent (r:1 w:0)
    // Proof Skipped: ExternalAgents GroupOfAgent (max_values: None, max_size: None, mode: Measured)
    // Storage: Permissions CurrentPalletName (r:1 w:0)
    // Proof Skipped: Permissions CurrentPalletName (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Permissions CurrentDispatchableName (r:1 w:0)
    // Proof Skipped: Permissions CurrentDispatchableName (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Sto Fundraisers (r:1 w:1)
    // Proof Skipped: Sto Fundraisers (max_values: None, max_size: None, mode: Measured)
    fn unfreeze_fundraiser() -> Weight {
        // Minimum execution time: 18_284 nanoseconds.
        Weight::from_ref_time(18_435_000)
            .saturating_add(DbWeight::get().reads(5))
            .saturating_add(DbWeight::get().writes(1))
    }
    // Storage: Identity KeyRecords (r:1 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: ExternalAgents GroupOfAgent (r:1 w:0)
    // Proof Skipped: ExternalAgents GroupOfAgent (max_values: None, max_size: None, mode: Measured)
    // Storage: Permissions CurrentPalletName (r:1 w:0)
    // Proof Skipped: Permissions CurrentPalletName (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Permissions CurrentDispatchableName (r:1 w:0)
    // Proof Skipped: Permissions CurrentDispatchableName (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Sto Fundraisers (r:1 w:1)
    // Proof Skipped: Sto Fundraisers (max_values: None, max_size: None, mode: Measured)
    // Storage: Timestamp Now (r:1 w:0)
    // Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
    fn modify_fundraiser_window() -> Weight {
        // Minimum execution time: 21_470 nanoseconds.
        Weight::from_ref_time(21_580_000)
            .saturating_add(DbWeight::get().reads(6))
            .saturating_add(DbWeight::get().writes(1))
    }
    // Storage: Sto Fundraisers (r:1 w:1)
    // Proof Skipped: Sto Fundraisers (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity KeyRecords (r:1 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: Portfolio PortfolioLockedAssets (r:1 w:1)
    // Proof Skipped: Portfolio PortfolioLockedAssets (max_values: None, max_size: None, mode: Measured)
    // Storage: Timestamp Now (r:1 w:0)
    // Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
    fn stop() -> Weight {
        // Minimum execution time: 19_146 nanoseconds.
        Weight::from_ref_time(19_567_000)
            .saturating_add(DbWeight::get().reads(4))
            .saturating_add(DbWeight::get().writes(2))
    }
}
