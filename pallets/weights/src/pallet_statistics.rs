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

//! Autogenerated weights for pallet_statistics
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 4.0.0-dev
//! DATE: 2023-11-24, STEPS: `100`, REPEAT: 5, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! EXECUTION: Some(Wasm), WASM-EXECUTION: Compiled, CHAIN: None, DB CACHE: 512
//! HOSTNAME: `Ubuntu-2204-jammy-amd64-base`, CPU: `AMD Ryzen 9 7950X3D 16-Core Processor`

// Executed Command:
// ./target/release/polymesh-private
// benchmark
// pallet
// -s
// 100
// -r
// 5
// -p=pallet_statistics
// -e=*
// --heap-pages
// 4096
// --db-cache
// 512
// --execution
// wasm
// --wasm-execution
// compiled
// --output
// ./pallets/weights/src/
// --template
// ./.maintain/frame-weight-template.hbs

#![allow(unused_parens)]
#![allow(unused_imports)]

use polymesh_runtime_common::{RocksDbWeight as DbWeight, Weight};

/// Weights for pallet_statistics using the Substrate node and recommended hardware.
pub struct SubstrateWeight;
impl pallet_statistics::WeightInfo for SubstrateWeight {
    // Storage: Identity KeyRecords (r:1 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: ExternalAgents GroupOfAgent (r:1 w:0)
    // Proof Skipped: ExternalAgents GroupOfAgent (max_values: None, max_size: None, mode: Measured)
    // Storage: Permissions CurrentPalletName (r:1 w:0)
    // Proof Skipped: Permissions CurrentPalletName (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Permissions CurrentDispatchableName (r:1 w:0)
    // Proof Skipped: Permissions CurrentDispatchableName (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Statistics AssetTransferCompliances (r:1 w:0)
    // Proof Skipped: Statistics AssetTransferCompliances (max_values: None, max_size: None, mode: Measured)
    // Storage: Statistics ActiveAssetStats (r:1 w:1)
    // Proof Skipped: Statistics ActiveAssetStats (max_values: None, max_size: None, mode: Measured)
    /// The range of component `i` is `[1, 9]`.
    fn set_active_asset_stats(i: u32) -> Weight {
        // Minimum execution time: 30_076 nanoseconds.
        Weight::from_ref_time(31_570_682)
            // Standard Error: 17_018
            .saturating_add(Weight::from_ref_time(64_502).saturating_mul(i.into()))
            .saturating_add(DbWeight::get().reads(6))
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
    // Storage: Statistics ActiveAssetStats (r:1 w:0)
    // Proof Skipped: Statistics ActiveAssetStats (max_values: None, max_size: None, mode: Measured)
    // Storage: Statistics AssetStats (r:0 w:250)
    // Proof Skipped: Statistics AssetStats (max_values: None, max_size: None, mode: Measured)
    /// The range of component `i` is `[1, 250]`.
    fn batch_update_asset_stats(i: u32) -> Weight {
        // Minimum execution time: 31_940 nanoseconds.
        Weight::from_ref_time(27_190_525)
            // Standard Error: 6_482
            .saturating_add(Weight::from_ref_time(2_248_621).saturating_mul(i.into()))
            .saturating_add(DbWeight::get().reads(5))
            .saturating_add(DbWeight::get().writes((1_u64).saturating_mul(i.into())))
    }
    // Storage: Identity KeyRecords (r:1 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: ExternalAgents GroupOfAgent (r:1 w:0)
    // Proof Skipped: ExternalAgents GroupOfAgent (max_values: None, max_size: None, mode: Measured)
    // Storage: Permissions CurrentPalletName (r:1 w:0)
    // Proof Skipped: Permissions CurrentPalletName (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Permissions CurrentDispatchableName (r:1 w:0)
    // Proof Skipped: Permissions CurrentDispatchableName (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Statistics ActiveAssetStats (r:1 w:0)
    // Proof Skipped: Statistics ActiveAssetStats (max_values: None, max_size: None, mode: Measured)
    // Storage: Statistics AssetTransferCompliances (r:1 w:1)
    // Proof Skipped: Statistics AssetTransferCompliances (max_values: None, max_size: None, mode: Measured)
    /// The range of component `i` is `[1, 3]`.
    fn set_asset_transfer_compliance(i: u32) -> Weight {
        // Minimum execution time: 30_417 nanoseconds.
        Weight::from_ref_time(29_663_016)
            // Standard Error: 45_274
            .saturating_add(Weight::from_ref_time(2_185_298).saturating_mul(i.into()))
            .saturating_add(DbWeight::get().reads(6))
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
    // Storage: Statistics TransferConditionExemptEntities (r:0 w:1000)
    // Proof Skipped: Statistics TransferConditionExemptEntities (max_values: None, max_size: None, mode: Measured)
    /// The range of component `i` is `[0, 1000]`.
    fn set_entities_exempt(i: u32) -> Weight {
        // Minimum execution time: 21_791 nanoseconds.
        Weight::from_ref_time(6_817_024)
            // Standard Error: 7_149
            .saturating_add(Weight::from_ref_time(2_238_159).saturating_mul(i.into()))
            .saturating_add(DbWeight::get().reads(4))
            .saturating_add(DbWeight::get().writes((1_u64).saturating_mul(i.into())))
    }
    // Storage: Statistics AssetStats (r:1 w:0)
    // Proof Skipped: Statistics AssetStats (max_values: None, max_size: None, mode: Measured)
    /// The range of component `a` is `[0, 1]`.
    fn max_investor_count_restriction(a: u32) -> Weight {
        // Minimum execution time: 300 nanoseconds.
        Weight::from_ref_time(410_771)
            // Standard Error: 12_530
            .saturating_add(Weight::from_ref_time(4_965_895).saturating_mul(a.into()))
            .saturating_add(DbWeight::get().reads((1_u64).saturating_mul(a.into())))
    }
    fn max_investor_ownership_restriction() -> Weight {
        // Minimum execution time: 421 nanoseconds.
        Weight::from_ref_time(480_000)
    }
    // Storage: Timestamp Now (r:1 w:0)
    // Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
    // Storage: Identity Claims (r:2 w:0)
    // Proof Skipped: Identity Claims (max_values: None, max_size: None, mode: Measured)
    /// The range of component `c` is `[0, 1]`.
    fn claim_count_restriction_no_stats(c: u32) -> Weight {
        // Minimum execution time: 271 nanoseconds.
        Weight::from_ref_time(391_397)
            // Standard Error: 21_348
            .saturating_add(Weight::from_ref_time(11_284_269).saturating_mul(c.into()))
            .saturating_add(DbWeight::get().reads((3_u64).saturating_mul(c.into())))
    }
    // Storage: Timestamp Now (r:1 w:0)
    // Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
    // Storage: Identity Claims (r:2 w:0)
    // Proof Skipped: Identity Claims (max_values: None, max_size: None, mode: Measured)
    // Storage: Statistics AssetStats (r:1 w:0)
    // Proof Skipped: Statistics AssetStats (max_values: None, max_size: None, mode: Measured)
    fn claim_count_restriction_with_stats() -> Weight {
        // Minimum execution time: 15_449 nanoseconds.
        Weight::from_ref_time(15_749_000).saturating_add(DbWeight::get().reads(4))
    }
    // Storage: Timestamp Now (r:1 w:0)
    // Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
    // Storage: Identity Claims (r:2 w:0)
    // Proof Skipped: Identity Claims (max_values: None, max_size: None, mode: Measured)
    // Storage: Statistics AssetStats (r:1 w:0)
    // Proof Skipped: Statistics AssetStats (max_values: None, max_size: None, mode: Measured)
    /// The range of component `a` is `[0, 1]`.
    fn claim_ownership_restriction(a: u32) -> Weight {
        // Minimum execution time: 10_740 nanoseconds.
        Weight::from_ref_time(11_449_413)
            // Standard Error: 106_034
            .saturating_add(Weight::from_ref_time(5_792_586).saturating_mul(a.into()))
            .saturating_add(DbWeight::get().reads(3))
            .saturating_add(DbWeight::get().reads((1_u64).saturating_mul(a.into())))
    }
    // Storage: Timestamp Now (r:1 w:0)
    // Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
    // Storage: Identity Claims (r:2 w:0)
    // Proof Skipped: Identity Claims (max_values: None, max_size: None, mode: Measured)
    // Storage: Statistics AssetStats (r:2 w:2)
    // Proof Skipped: Statistics AssetStats (max_values: None, max_size: None, mode: Measured)
    /// The range of component `a` is `[0, 2]`.
    fn update_asset_count_stats(a: u32) -> Weight {
        // Minimum execution time: 10_781 nanoseconds.
        Weight::from_ref_time(11_431_699)
            // Standard Error: 30_021
            .saturating_add(Weight::from_ref_time(4_789_516).saturating_mul(a.into()))
            .saturating_add(DbWeight::get().reads(3))
            .saturating_add(DbWeight::get().reads((1_u64).saturating_mul(a.into())))
            .saturating_add(DbWeight::get().writes((1_u64).saturating_mul(a.into())))
    }
    // Storage: Timestamp Now (r:1 w:0)
    // Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
    // Storage: Identity Claims (r:2 w:0)
    // Proof Skipped: Identity Claims (max_values: None, max_size: None, mode: Measured)
    // Storage: Statistics AssetStats (r:2 w:2)
    // Proof Skipped: Statistics AssetStats (max_values: None, max_size: None, mode: Measured)
    /// The range of component `a` is `[0, 2]`.
    fn update_asset_balance_stats(a: u32) -> Weight {
        // Minimum execution time: 10_680 nanoseconds.
        Weight::from_ref_time(11_566_985)
            // Standard Error: 48_137
            .saturating_add(Weight::from_ref_time(5_327_036).saturating_mul(a.into()))
            .saturating_add(DbWeight::get().reads(3))
            .saturating_add(DbWeight::get().reads((1_u64).saturating_mul(a.into())))
            .saturating_add(DbWeight::get().writes((1_u64).saturating_mul(a.into())))
    }
    /// The range of component `i` is `[0, 4]`.
    fn verify_requirements(i: u32) -> Weight {
        // Minimum execution time: 261 nanoseconds.
        Weight::from_ref_time(378_601)
            // Standard Error: 2_916
            .saturating_add(Weight::from_ref_time(58_326).saturating_mul(i.into()))
    }
    // Storage: Statistics ActiveAssetStats (r:1 w:0)
    // Proof Skipped: Statistics ActiveAssetStats (max_values: None, max_size: None, mode: Measured)
    /// The range of component `a` is `[1, 10]`.
    fn active_asset_statistics_load(a: u32) -> Weight {
        // Minimum execution time: 5_651 nanoseconds.
        Weight::from_ref_time(5_968_040)
            // Standard Error: 2_672
            .saturating_add(Weight::from_ref_time(25_135).saturating_mul(a.into()))
            .saturating_add(DbWeight::get().reads(1))
    }
    // Storage: Statistics TransferConditionExemptEntities (r:1 w:0)
    // Proof Skipped: Statistics TransferConditionExemptEntities (max_values: None, max_size: None, mode: Measured)
    fn is_exempt() -> Weight {
        // Minimum execution time: 6_312 nanoseconds.
        Weight::from_ref_time(6_682_000).saturating_add(DbWeight::get().reads(1))
    }
}
