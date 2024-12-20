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

//! Autogenerated weights for pallet_utility
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 4.0.0-dev
//! DATE: 2024-11-16, STEPS: `100`, REPEAT: 5, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! EXECUTION: Some(Wasm), WASM-EXECUTION: Compiled, CHAIN: None, DB CACHE: 512
//! HOSTNAME: `Ubuntu-2204-jammy-amd64-base`, CPU: `AMD Ryzen 9 7950X3D 16-Core Processor`

// Executed Command:
// ./polymesh-private
// benchmark
// pallet
// -s
// 100
// -r
// 5
// -p=*
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
// ./Polymesh-private/pallets/weights/src/
// --template
// ./Polymesh-private/.maintain/frame-weight-template.hbs

#![allow(unused_parens)]
#![allow(unused_imports)]

use polymesh_runtime_common::{RocksDbWeight as DbWeight, Weight};

/// Weights for pallet_utility using the Substrate node and recommended hardware.
pub struct SubstrateWeight;
impl pallet_utility::WeightInfo for SubstrateWeight {
    // Storage: Permissions CurrentPalletName (r:1 w:1)
    // Proof Skipped: Permissions CurrentPalletName (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Permissions CurrentDispatchableName (r:1 w:1)
    // Proof Skipped: Permissions CurrentDispatchableName (max_values: Some(1), max_size: None, mode: Measured)
    /// The range of component `c` is `[0, 1000]`.
    fn batch(c: u32) -> Weight {
        // Minimum execution time: 5_520 nanoseconds.
        Weight::from_ref_time(5_670_000)
            // Standard Error: 19_627
            .saturating_add(Weight::from_ref_time(9_566_695).saturating_mul(c.into()))
            .saturating_add(DbWeight::get().reads(2))
            .saturating_add(DbWeight::get().writes(2))
    }
    // Storage: Permissions CurrentPalletName (r:1 w:1)
    // Proof Skipped: Permissions CurrentPalletName (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Permissions CurrentDispatchableName (r:1 w:1)
    // Proof Skipped: Permissions CurrentDispatchableName (max_values: Some(1), max_size: None, mode: Measured)
    /// The range of component `c` is `[0, 1000]`.
    fn batch_all(c: u32) -> Weight {
        // Minimum execution time: 5_571 nanoseconds.
        Weight::from_ref_time(65_158_265)
            // Standard Error: 51_945
            .saturating_add(Weight::from_ref_time(9_848_869).saturating_mul(c.into()))
            .saturating_add(DbWeight::get().reads(2))
            .saturating_add(DbWeight::get().writes(2))
    }
    // Storage: Identity CurrentPayer (r:1 w:1)
    // Proof Skipped: Identity CurrentPayer (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Permissions CurrentPalletName (r:1 w:1)
    // Proof Skipped: Permissions CurrentPalletName (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Permissions CurrentDispatchableName (r:1 w:1)
    // Proof Skipped: Permissions CurrentDispatchableName (max_values: Some(1), max_size: None, mode: Measured)
    fn dispatch_as() -> Weight {
        // Minimum execution time: 17_613 nanoseconds.
        Weight::from_ref_time(18_735_000)
            .saturating_add(DbWeight::get().reads(3))
            .saturating_add(DbWeight::get().writes(3))
    }
    // Storage: Permissions CurrentPalletName (r:1 w:1)
    // Proof Skipped: Permissions CurrentPalletName (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Permissions CurrentDispatchableName (r:1 w:1)
    // Proof Skipped: Permissions CurrentDispatchableName (max_values: Some(1), max_size: None, mode: Measured)
    /// The range of component `c` is `[0, 1000]`.
    fn force_batch(c: u32) -> Weight {
        // Minimum execution time: 5_540 nanoseconds.
        Weight::from_ref_time(5_610_000)
            // Standard Error: 29_980
            .saturating_add(Weight::from_ref_time(9_833_192).saturating_mul(c.into()))
            .saturating_add(DbWeight::get().reads(2))
            .saturating_add(DbWeight::get().writes(2))
    }
    // Storage: Identity KeyRecords (r:2 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: Utility Nonces (r:1 w:1)
    // Proof: Utility Nonces (max_values: None, max_size: Some(48), added: 2523, mode: MaxEncodedLen)
    // Storage: Timestamp Now (r:1 w:0)
    // Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
    // Storage: Instance2Group ActiveMembers (r:1 w:0)
    // Proof Skipped: Instance2Group ActiveMembers (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Identity Claims (r:2 w:0)
    // Proof Skipped: Identity Claims (max_values: None, max_size: None, mode: Measured)
    // Storage: Permissions CurrentPalletName (r:1 w:1)
    // Proof Skipped: Permissions CurrentPalletName (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Permissions CurrentDispatchableName (r:1 w:1)
    // Proof Skipped: Permissions CurrentDispatchableName (max_values: Some(1), max_size: None, mode: Measured)
    fn relay_tx() -> Weight {
        // Minimum execution time: 90_320 nanoseconds.
        Weight::from_ref_time(91_993_000)
            .saturating_add(DbWeight::get().reads(9))
            .saturating_add(DbWeight::get().writes(3))
    }
    fn ensure_root() -> Weight {
        // Minimum execution time: 1_363 nanoseconds.
        Weight::from_ref_time(1_623_000)
    }
    // Storage: Identity CurrentPayer (r:1 w:1)
    // Proof Skipped: Identity CurrentPayer (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Permissions CurrentPalletName (r:1 w:1)
    // Proof Skipped: Permissions CurrentPalletName (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Permissions CurrentDispatchableName (r:1 w:1)
    // Proof Skipped: Permissions CurrentDispatchableName (max_values: Some(1), max_size: None, mode: Measured)
    fn as_derivative() -> Weight {
        // Minimum execution time: 16_441 nanoseconds.
        Weight::from_ref_time(17_313_000)
            .saturating_add(DbWeight::get().reads(3))
            .saturating_add(DbWeight::get().writes(3))
    }
}
