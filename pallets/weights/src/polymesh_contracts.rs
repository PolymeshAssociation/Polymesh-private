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

//! Autogenerated weights for polymesh_contracts
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 4.0.0-dev
//! DATE: 2023-11-25, STEPS: `100`, REPEAT: 5, LOW RANGE: `[]`, HIGH RANGE: `[]`
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
// -p=polymesh_contracts
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

/// Weights for polymesh_contracts using the Substrate node and recommended hardware.
pub struct SubstrateWeight;
impl polymesh_contracts::WeightInfo for SubstrateWeight {
    // Storage: Identity KeyRecords (r:2 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: System Account (r:1 w:0)
    // Proof: System Account (max_values: None, max_size: Some(128), added: 2603, mode: MaxEncodedLen)
    // Storage: Contracts ContractInfoOf (r:1 w:1)
    // Proof: Contracts ContractInfoOf (max_values: None, max_size: Some(290), added: 2765, mode: MaxEncodedLen)
    // Storage: Contracts CodeStorage (r:1 w:0)
    // Proof: Contracts CodeStorage (max_values: None, max_size: Some(126001), added: 128476, mode: MaxEncodedLen)
    // Storage: Timestamp Now (r:1 w:0)
    // Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
    // Storage: Identity IsDidFrozen (r:1 w:0)
    // Proof Skipped: Identity IsDidFrozen (max_values: None, max_size: None, mode: Measured)
    // Storage: Instance2Group ActiveMembers (r:1 w:0)
    // Proof Skipped: Instance2Group ActiveMembers (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Identity Claims (r:2 w:0)
    // Proof Skipped: Identity Claims (max_values: None, max_size: None, mode: Measured)
    // Storage: unknown `0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f` (r:1 w:0)
    // Proof Skipped: unknown `0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f` (r:1 w:0)
    // Storage: System EventTopics (r:2 w:2)
    // Proof Skipped: System EventTopics (max_values: None, max_size: None, mode: Measured)
    // Storage: unknown `0x00` (r:1 w:0)
    // Proof Skipped: unknown `0x00` (r:1 w:0)
    /// The range of component `k` is `[1, 8192]`.
    /// The range of component `v` is `[1, 8192]`.
    fn chain_extension_read_storage(k: u32, v: u32) -> Weight {
        // Minimum execution time: 313_377 nanoseconds.
        Weight::from_ref_time(318_611_357)
            // Standard Error: 1_256
            .saturating_add(Weight::from_ref_time(3_003).saturating_mul(k.into()))
            // Standard Error: 1_256
            .saturating_add(Weight::from_ref_time(3_083).saturating_mul(v.into()))
            .saturating_add(DbWeight::get().reads(13))
            .saturating_add(DbWeight::get().writes(3))
    }
    // Storage: Identity KeyRecords (r:2 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: System Account (r:1 w:0)
    // Proof: System Account (max_values: None, max_size: Some(128), added: 2603, mode: MaxEncodedLen)
    // Storage: Contracts ContractInfoOf (r:1 w:1)
    // Proof: Contracts ContractInfoOf (max_values: None, max_size: Some(290), added: 2765, mode: MaxEncodedLen)
    // Storage: Contracts CodeStorage (r:1 w:0)
    // Proof: Contracts CodeStorage (max_values: None, max_size: Some(126001), added: 128476, mode: MaxEncodedLen)
    // Storage: Timestamp Now (r:1 w:0)
    // Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
    // Storage: Identity IsDidFrozen (r:1 w:0)
    // Proof Skipped: Identity IsDidFrozen (max_values: None, max_size: None, mode: Measured)
    // Storage: Instance2Group ActiveMembers (r:1 w:0)
    // Proof Skipped: Instance2Group ActiveMembers (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Identity Claims (r:2 w:0)
    // Proof Skipped: Identity Claims (max_values: None, max_size: None, mode: Measured)
    // Storage: System EventTopics (r:2 w:2)
    // Proof Skipped: System EventTopics (max_values: None, max_size: None, mode: Measured)
    /// The range of component `r` is `[0, 20]`.
    fn chain_extension_get_version(r: u32) -> Weight {
        // Minimum execution time: 281_739 nanoseconds.
        Weight::from_ref_time(294_848_264)
            // Standard Error: 307_480
            .saturating_add(Weight::from_ref_time(51_175_380).saturating_mul(r.into()))
            .saturating_add(DbWeight::get().reads(12))
            .saturating_add(DbWeight::get().writes(3))
    }
    // Storage: Identity KeyRecords (r:2002 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: System Account (r:1 w:0)
    // Proof: System Account (max_values: None, max_size: Some(128), added: 2603, mode: MaxEncodedLen)
    // Storage: Contracts ContractInfoOf (r:1 w:1)
    // Proof: Contracts ContractInfoOf (max_values: None, max_size: Some(290), added: 2765, mode: MaxEncodedLen)
    // Storage: Contracts CodeStorage (r:1 w:0)
    // Proof: Contracts CodeStorage (max_values: None, max_size: Some(126001), added: 128476, mode: MaxEncodedLen)
    // Storage: Timestamp Now (r:1 w:0)
    // Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
    // Storage: Identity IsDidFrozen (r:2001 w:0)
    // Proof Skipped: Identity IsDidFrozen (max_values: None, max_size: None, mode: Measured)
    // Storage: Instance2Group ActiveMembers (r:1 w:0)
    // Proof Skipped: Instance2Group ActiveMembers (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Identity Claims (r:2 w:0)
    // Proof Skipped: Identity Claims (max_values: None, max_size: None, mode: Measured)
    // Storage: System EventTopics (r:2 w:2)
    // Proof Skipped: System EventTopics (max_values: None, max_size: None, mode: Measured)
    /// The range of component `r` is `[1, 20]`.
    fn chain_extension_get_key_did(r: u32) -> Weight {
        // Minimum execution time: 117_172_986 nanoseconds.
        Weight::from_ref_time(117_826_301_000)
            // Standard Error: 326_749_286
            .saturating_add(Weight::from_ref_time(109_851_306_954).saturating_mul(r.into()))
            .saturating_add(DbWeight::get().reads(12))
            .saturating_add(DbWeight::get().reads((200_u64).saturating_mul(r.into())))
            .saturating_add(DbWeight::get().writes(3))
    }
    // Storage: Identity KeyRecords (r:2 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: System Account (r:1 w:0)
    // Proof: System Account (max_values: None, max_size: Some(128), added: 2603, mode: MaxEncodedLen)
    // Storage: Contracts ContractInfoOf (r:1 w:1)
    // Proof: Contracts ContractInfoOf (max_values: None, max_size: Some(290), added: 2765, mode: MaxEncodedLen)
    // Storage: Contracts CodeStorage (r:1 w:0)
    // Proof: Contracts CodeStorage (max_values: None, max_size: Some(126001), added: 128476, mode: MaxEncodedLen)
    // Storage: Timestamp Now (r:1 w:0)
    // Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
    // Storage: Identity IsDidFrozen (r:1 w:0)
    // Proof Skipped: Identity IsDidFrozen (max_values: None, max_size: None, mode: Measured)
    // Storage: Instance2Group ActiveMembers (r:1 w:0)
    // Proof Skipped: Instance2Group ActiveMembers (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Identity Claims (r:2 w:0)
    // Proof Skipped: Identity Claims (max_values: None, max_size: None, mode: Measured)
    // Storage: System EventTopics (r:2 w:2)
    // Proof Skipped: System EventTopics (max_values: None, max_size: None, mode: Measured)
    /// The range of component `r` is `[0, 20]`.
    fn chain_extension_hash_twox_64(r: u32) -> Weight {
        // Minimum execution time: 317_515 nanoseconds.
        Weight::from_ref_time(360_630_839)
            // Standard Error: 296_423
            .saturating_add(Weight::from_ref_time(54_821_175).saturating_mul(r.into()))
            .saturating_add(DbWeight::get().reads(12))
            .saturating_add(DbWeight::get().writes(3))
    }
    // Storage: Identity KeyRecords (r:2 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: System Account (r:1 w:0)
    // Proof: System Account (max_values: None, max_size: Some(128), added: 2603, mode: MaxEncodedLen)
    // Storage: Contracts ContractInfoOf (r:1 w:1)
    // Proof: Contracts ContractInfoOf (max_values: None, max_size: Some(290), added: 2765, mode: MaxEncodedLen)
    // Storage: Contracts CodeStorage (r:1 w:0)
    // Proof: Contracts CodeStorage (max_values: None, max_size: Some(126001), added: 128476, mode: MaxEncodedLen)
    // Storage: Timestamp Now (r:1 w:0)
    // Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
    // Storage: Identity IsDidFrozen (r:1 w:0)
    // Proof Skipped: Identity IsDidFrozen (max_values: None, max_size: None, mode: Measured)
    // Storage: Instance2Group ActiveMembers (r:1 w:0)
    // Proof Skipped: Instance2Group ActiveMembers (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Identity Claims (r:2 w:0)
    // Proof Skipped: Identity Claims (max_values: None, max_size: None, mode: Measured)
    // Storage: System EventTopics (r:2 w:2)
    // Proof Skipped: System EventTopics (max_values: None, max_size: None, mode: Measured)
    /// The range of component `n` is `[0, 64]`.
    fn chain_extension_hash_twox_64_per_kb(n: u32) -> Weight {
        // Minimum execution time: 357_881 nanoseconds.
        Weight::from_ref_time(408_642_401)
            // Standard Error: 432_656
            .saturating_add(Weight::from_ref_time(18_701_006).saturating_mul(n.into()))
            .saturating_add(DbWeight::get().reads(12))
            .saturating_add(DbWeight::get().writes(3))
    }
    // Storage: Identity KeyRecords (r:2 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: System Account (r:1 w:0)
    // Proof: System Account (max_values: None, max_size: Some(128), added: 2603, mode: MaxEncodedLen)
    // Storage: Contracts ContractInfoOf (r:1 w:1)
    // Proof: Contracts ContractInfoOf (max_values: None, max_size: Some(290), added: 2765, mode: MaxEncodedLen)
    // Storage: Contracts CodeStorage (r:1 w:0)
    // Proof: Contracts CodeStorage (max_values: None, max_size: Some(126001), added: 128476, mode: MaxEncodedLen)
    // Storage: Timestamp Now (r:1 w:0)
    // Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
    // Storage: Identity IsDidFrozen (r:1 w:0)
    // Proof Skipped: Identity IsDidFrozen (max_values: None, max_size: None, mode: Measured)
    // Storage: Instance2Group ActiveMembers (r:1 w:0)
    // Proof Skipped: Instance2Group ActiveMembers (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Identity Claims (r:2 w:0)
    // Proof Skipped: Identity Claims (max_values: None, max_size: None, mode: Measured)
    // Storage: System EventTopics (r:2 w:2)
    // Proof Skipped: System EventTopics (max_values: None, max_size: None, mode: Measured)
    /// The range of component `r` is `[0, 20]`.
    fn chain_extension_hash_twox_128(r: u32) -> Weight {
        // Minimum execution time: 286_848 nanoseconds.
        Weight::from_ref_time(300_886_488)
            // Standard Error: 117_523
            .saturating_add(Weight::from_ref_time(59_548_316).saturating_mul(r.into()))
            .saturating_add(DbWeight::get().reads(12))
            .saturating_add(DbWeight::get().writes(3))
    }
    // Storage: Identity KeyRecords (r:2 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: System Account (r:1 w:0)
    // Proof: System Account (max_values: None, max_size: Some(128), added: 2603, mode: MaxEncodedLen)
    // Storage: Contracts ContractInfoOf (r:1 w:1)
    // Proof: Contracts ContractInfoOf (max_values: None, max_size: Some(290), added: 2765, mode: MaxEncodedLen)
    // Storage: Contracts CodeStorage (r:1 w:0)
    // Proof: Contracts CodeStorage (max_values: None, max_size: Some(126001), added: 128476, mode: MaxEncodedLen)
    // Storage: Timestamp Now (r:1 w:0)
    // Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
    // Storage: Identity IsDidFrozen (r:1 w:0)
    // Proof Skipped: Identity IsDidFrozen (max_values: None, max_size: None, mode: Measured)
    // Storage: Instance2Group ActiveMembers (r:1 w:0)
    // Proof Skipped: Instance2Group ActiveMembers (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Identity Claims (r:2 w:0)
    // Proof Skipped: Identity Claims (max_values: None, max_size: None, mode: Measured)
    // Storage: System EventTopics (r:2 w:2)
    // Proof Skipped: System EventTopics (max_values: None, max_size: None, mode: Measured)
    /// The range of component `n` is `[0, 64]`.
    fn chain_extension_hash_twox_128_per_kb(n: u32) -> Weight {
        // Minimum execution time: 343_233 nanoseconds.
        Weight::from_ref_time(405_929_785)
            // Standard Error: 313_415
            .saturating_add(Weight::from_ref_time(20_072_306).saturating_mul(n.into()))
            .saturating_add(DbWeight::get().reads(12))
            .saturating_add(DbWeight::get().writes(3))
    }
    // Storage: Identity KeyRecords (r:2 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: System Account (r:1 w:0)
    // Proof: System Account (max_values: None, max_size: Some(128), added: 2603, mode: MaxEncodedLen)
    // Storage: Contracts ContractInfoOf (r:1 w:1)
    // Proof: Contracts ContractInfoOf (max_values: None, max_size: Some(290), added: 2765, mode: MaxEncodedLen)
    // Storage: Contracts CodeStorage (r:1 w:0)
    // Proof: Contracts CodeStorage (max_values: None, max_size: Some(126001), added: 128476, mode: MaxEncodedLen)
    // Storage: Timestamp Now (r:1 w:0)
    // Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
    // Storage: Identity IsDidFrozen (r:1 w:0)
    // Proof Skipped: Identity IsDidFrozen (max_values: None, max_size: None, mode: Measured)
    // Storage: Instance2Group ActiveMembers (r:1 w:0)
    // Proof Skipped: Instance2Group ActiveMembers (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Identity Claims (r:2 w:0)
    // Proof Skipped: Identity Claims (max_values: None, max_size: None, mode: Measured)
    // Storage: System EventTopics (r:2 w:2)
    // Proof Skipped: System EventTopics (max_values: None, max_size: None, mode: Measured)
    /// The range of component `r` is `[0, 20]`.
    fn chain_extension_hash_twox_256(r: u32) -> Weight {
        // Minimum execution time: 279_645 nanoseconds.
        Weight::from_ref_time(293_355_519)
            // Standard Error: 136_879
            .saturating_add(Weight::from_ref_time(64_599_071).saturating_mul(r.into()))
            .saturating_add(DbWeight::get().reads(12))
            .saturating_add(DbWeight::get().writes(3))
    }
    // Storage: Identity KeyRecords (r:2 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: System Account (r:1 w:0)
    // Proof: System Account (max_values: None, max_size: Some(128), added: 2603, mode: MaxEncodedLen)
    // Storage: Contracts ContractInfoOf (r:1 w:1)
    // Proof: Contracts ContractInfoOf (max_values: None, max_size: Some(290), added: 2765, mode: MaxEncodedLen)
    // Storage: Contracts CodeStorage (r:1 w:0)
    // Proof: Contracts CodeStorage (max_values: None, max_size: Some(126001), added: 128476, mode: MaxEncodedLen)
    // Storage: Timestamp Now (r:1 w:0)
    // Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
    // Storage: Identity IsDidFrozen (r:1 w:0)
    // Proof Skipped: Identity IsDidFrozen (max_values: None, max_size: None, mode: Measured)
    // Storage: Instance2Group ActiveMembers (r:1 w:0)
    // Proof Skipped: Instance2Group ActiveMembers (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Identity Claims (r:2 w:0)
    // Proof Skipped: Identity Claims (max_values: None, max_size: None, mode: Measured)
    // Storage: System EventTopics (r:2 w:2)
    // Proof Skipped: System EventTopics (max_values: None, max_size: None, mode: Measured)
    /// The range of component `n` is `[0, 64]`.
    fn chain_extension_hash_twox_256_per_kb(n: u32) -> Weight {
        // Minimum execution time: 352_501 nanoseconds.
        Weight::from_ref_time(341_418_262)
            // Standard Error: 319_227
            .saturating_add(Weight::from_ref_time(30_401_914).saturating_mul(n.into()))
            .saturating_add(DbWeight::get().reads(12))
            .saturating_add(DbWeight::get().writes(3))
    }
    // Storage: Identity KeyRecords (r:2 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: System Account (r:1 w:0)
    // Proof: System Account (max_values: None, max_size: Some(128), added: 2603, mode: MaxEncodedLen)
    // Storage: Contracts ContractInfoOf (r:1 w:1)
    // Proof: Contracts ContractInfoOf (max_values: None, max_size: Some(290), added: 2765, mode: MaxEncodedLen)
    // Storage: Contracts CodeStorage (r:1 w:0)
    // Proof: Contracts CodeStorage (max_values: None, max_size: Some(126001), added: 128476, mode: MaxEncodedLen)
    // Storage: Timestamp Now (r:1 w:0)
    // Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
    // Storage: Identity IsDidFrozen (r:1 w:0)
    // Proof Skipped: Identity IsDidFrozen (max_values: None, max_size: None, mode: Measured)
    // Storage: Instance2Group ActiveMembers (r:1 w:0)
    // Proof Skipped: Instance2Group ActiveMembers (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Identity Claims (r:2 w:0)
    // Proof Skipped: Identity Claims (max_values: None, max_size: None, mode: Measured)
    // Storage: PolymeshContracts CallRuntimeWhitelist (r:1 w:0)
    // Proof Skipped: PolymeshContracts CallRuntimeWhitelist (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity CurrentPayer (r:1 w:1)
    // Proof Skipped: Identity CurrentPayer (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Identity CurrentDid (r:1 w:1)
    // Proof Skipped: Identity CurrentDid (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Permissions CurrentPalletName (r:1 w:1)
    // Proof Skipped: Permissions CurrentPalletName (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Permissions CurrentDispatchableName (r:1 w:1)
    // Proof Skipped: Permissions CurrentDispatchableName (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: System EventTopics (r:2 w:2)
    // Proof Skipped: System EventTopics (max_values: None, max_size: None, mode: Measured)
    /// The range of component `n` is `[1, 8188]`.
    fn chain_extension_call_runtime(n: u32) -> Weight {
        // Minimum execution time: 319_038 nanoseconds.
        Weight::from_ref_time(362_100_277)
            // Standard Error: 115
            .saturating_add(Weight::from_ref_time(2_332).saturating_mul(n.into()))
            .saturating_add(DbWeight::get().reads(17))
            .saturating_add(DbWeight::get().writes(7))
    }
    // Storage: Identity KeyRecords (r:2 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: System Account (r:1 w:0)
    // Proof: System Account (max_values: None, max_size: Some(128), added: 2603, mode: MaxEncodedLen)
    // Storage: Contracts ContractInfoOf (r:1 w:1)
    // Proof: Contracts ContractInfoOf (max_values: None, max_size: Some(290), added: 2765, mode: MaxEncodedLen)
    // Storage: Contracts CodeStorage (r:1 w:0)
    // Proof: Contracts CodeStorage (max_values: None, max_size: Some(126001), added: 128476, mode: MaxEncodedLen)
    // Storage: Timestamp Now (r:1 w:0)
    // Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
    // Storage: Identity IsDidFrozen (r:1 w:0)
    // Proof Skipped: Identity IsDidFrozen (max_values: None, max_size: None, mode: Measured)
    // Storage: Instance2Group ActiveMembers (r:1 w:0)
    // Proof Skipped: Instance2Group ActiveMembers (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Identity Claims (r:2 w:0)
    // Proof Skipped: Identity Claims (max_values: None, max_size: None, mode: Measured)
    // Storage: System EventTopics (r:2 w:2)
    // Proof Skipped: System EventTopics (max_values: None, max_size: None, mode: Measured)
    fn dummy_contract() -> Weight {
        // Minimum execution time: 183_053 nanoseconds.
        Weight::from_ref_time(185_888_000)
            .saturating_add(DbWeight::get().reads(12))
            .saturating_add(DbWeight::get().writes(3))
    }
    /// The range of component `n` is `[1, 8188]`.
    fn basic_runtime_call(n: u32) -> Weight {
        // Minimum execution time: 1_593 nanoseconds.
        Weight::from_ref_time(1_908_010)
            // Standard Error: 12
            .saturating_add(Weight::from_ref_time(18).saturating_mul(n.into()))
    }
    // Storage: Identity KeyRecords (r:3 w:1)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: Contracts CodeStorage (r:1 w:0)
    // Proof: Contracts CodeStorage (max_values: None, max_size: Some(126001), added: 128476, mode: MaxEncodedLen)
    // Storage: System Account (r:3 w:3)
    // Proof: System Account (max_values: None, max_size: Some(128), added: 2603, mode: MaxEncodedLen)
    // Storage: Contracts Nonce (r:1 w:1)
    // Proof: Contracts Nonce (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
    // Storage: Contracts ContractInfoOf (r:1 w:1)
    // Proof: Contracts ContractInfoOf (max_values: None, max_size: Some(290), added: 2765, mode: MaxEncodedLen)
    // Storage: Timestamp Now (r:1 w:0)
    // Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
    // Storage: Identity IsDidFrozen (r:1 w:0)
    // Proof Skipped: Identity IsDidFrozen (max_values: None, max_size: None, mode: Measured)
    // Storage: Instance2Group ActiveMembers (r:1 w:0)
    // Proof Skipped: Instance2Group ActiveMembers (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Identity Claims (r:2 w:0)
    // Proof Skipped: Identity Claims (max_values: None, max_size: None, mode: Measured)
    // Storage: Contracts OwnerInfoOf (r:1 w:1)
    // Proof: Contracts OwnerInfoOf (max_values: None, max_size: Some(88), added: 2563, mode: MaxEncodedLen)
    // Storage: System EventTopics (r:2 w:2)
    // Proof Skipped: System EventTopics (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity DidKeys (r:0 w:1)
    // Proof Skipped: Identity DidKeys (max_values: None, max_size: None, mode: Measured)
    /// The range of component `s` is `[0, 1048576]`.
    fn instantiate_with_hash_perms(s: u32) -> Weight {
        // Minimum execution time: 289_092 nanoseconds.
        Weight::from_ref_time(341_595_607)
            // Standard Error: 21
            .saturating_add(Weight::from_ref_time(1_955).saturating_mul(s.into()))
            .saturating_add(DbWeight::get().reads(17))
            .saturating_add(DbWeight::get().writes(10))
    }
    // Storage: Identity KeyRecords (r:3 w:1)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: Contracts OwnerInfoOf (r:1 w:1)
    // Proof: Contracts OwnerInfoOf (max_values: None, max_size: Some(88), added: 2563, mode: MaxEncodedLen)
    // Storage: System Account (r:3 w:3)
    // Proof: System Account (max_values: None, max_size: Some(128), added: 2603, mode: MaxEncodedLen)
    // Storage: Contracts Nonce (r:1 w:1)
    // Proof: Contracts Nonce (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
    // Storage: Contracts ContractInfoOf (r:1 w:1)
    // Proof: Contracts ContractInfoOf (max_values: None, max_size: Some(290), added: 2765, mode: MaxEncodedLen)
    // Storage: Timestamp Now (r:1 w:0)
    // Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
    // Storage: Identity IsDidFrozen (r:1 w:0)
    // Proof Skipped: Identity IsDidFrozen (max_values: None, max_size: None, mode: Measured)
    // Storage: Instance2Group ActiveMembers (r:1 w:0)
    // Proof Skipped: Instance2Group ActiveMembers (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Identity Claims (r:2 w:0)
    // Proof Skipped: Identity Claims (max_values: None, max_size: None, mode: Measured)
    // Storage: System EventTopics (r:3 w:3)
    // Proof Skipped: System EventTopics (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity DidKeys (r:0 w:1)
    // Proof Skipped: Identity DidKeys (max_values: None, max_size: None, mode: Measured)
    // Storage: Contracts CodeStorage (r:0 w:1)
    // Proof: Contracts CodeStorage (max_values: None, max_size: Some(126001), added: 128476, mode: MaxEncodedLen)
    // Storage: Contracts PristineCode (r:0 w:1)
    // Proof: Contracts PristineCode (max_values: None, max_size: Some(125988), added: 128463, mode: MaxEncodedLen)
    /// The range of component `c` is `[0, 61717]`.
    /// The range of component `s` is `[0, 1048576]`.
    fn instantiate_with_code_perms(c: u32, s: u32) -> Weight {
        // Minimum execution time: 2_652_751 nanoseconds.
        Weight::from_ref_time(767_222_298)
            // Standard Error: 794
            .saturating_add(Weight::from_ref_time(77_701).saturating_mul(c.into()))
            // Standard Error: 46
            .saturating_add(Weight::from_ref_time(1_775).saturating_mul(s.into()))
            .saturating_add(DbWeight::get().reads(17))
            .saturating_add(DbWeight::get().writes(13))
    }
    // Storage: PolymeshContracts CallRuntimeWhitelist (r:0 w:2000)
    // Proof Skipped: PolymeshContracts CallRuntimeWhitelist (max_values: None, max_size: None, mode: Measured)
    /// The range of component `u` is `[0, 2000]`.
    fn update_call_runtime_whitelist(u: u32) -> Weight {
        // Minimum execution time: 3_136 nanoseconds.
        Weight::from_ref_time(3_216_000)
            // Standard Error: 6_746
            .saturating_add(Weight::from_ref_time(1_404_850).saturating_mul(u.into()))
            .saturating_add(DbWeight::get().writes((1_u64).saturating_mul(u.into())))
    }
    // Storage: Identity KeyRecords (r:3 w:1)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity ParentDid (r:1 w:1)
    // Proof Skipped: Identity ParentDid (max_values: None, max_size: None, mode: Measured)
    // Storage: ProtocolFee Coefficient (r:1 w:0)
    // Proof Skipped: ProtocolFee Coefficient (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: ProtocolFee BaseFees (r:1 w:0)
    // Proof Skipped: ProtocolFee BaseFees (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity MultiPurposeNonce (r:1 w:1)
    // Proof Skipped: Identity MultiPurposeNonce (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: System ParentHash (r:1 w:0)
    // Proof: System ParentHash (max_values: Some(1), max_size: Some(32), added: 527, mode: MaxEncodedLen)
    // Storage: Identity DidRecords (r:1 w:1)
    // Proof Skipped: Identity DidRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: Contracts OwnerInfoOf (r:1 w:1)
    // Proof: Contracts OwnerInfoOf (max_values: None, max_size: Some(88), added: 2563, mode: MaxEncodedLen)
    // Storage: System Account (r:3 w:3)
    // Proof: System Account (max_values: None, max_size: Some(128), added: 2603, mode: MaxEncodedLen)
    // Storage: Contracts Nonce (r:1 w:1)
    // Proof: Contracts Nonce (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
    // Storage: Contracts ContractInfoOf (r:1 w:1)
    // Proof: Contracts ContractInfoOf (max_values: None, max_size: Some(290), added: 2765, mode: MaxEncodedLen)
    // Storage: Timestamp Now (r:1 w:0)
    // Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
    // Storage: Instance2Group ActiveMembers (r:1 w:0)
    // Proof Skipped: Instance2Group ActiveMembers (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Identity Claims (r:3 w:0)
    // Proof Skipped: Identity Claims (max_values: None, max_size: None, mode: Measured)
    // Storage: System EventTopics (r:3 w:3)
    // Proof Skipped: System EventTopics (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity DidKeys (r:0 w:1)
    // Proof Skipped: Identity DidKeys (max_values: None, max_size: None, mode: Measured)
    // Storage: Contracts CodeStorage (r:0 w:1)
    // Proof: Contracts CodeStorage (max_values: None, max_size: Some(126001), added: 128476, mode: MaxEncodedLen)
    // Storage: Contracts PristineCode (r:0 w:1)
    // Proof: Contracts PristineCode (max_values: None, max_size: Some(125988), added: 128463, mode: MaxEncodedLen)
    /// The range of component `c` is `[0, 61717]`.
    /// The range of component `s` is `[0, 1048576]`.
    fn instantiate_with_code_as_primary_key(c: u32, s: u32) -> Weight {
        // Minimum execution time: 2_967_523 nanoseconds.
        Weight::from_ref_time(513_702_747)
            // Standard Error: 659
            .saturating_add(Weight::from_ref_time(72_659).saturating_mul(c.into()))
            // Standard Error: 38
            .saturating_add(Weight::from_ref_time(2_371).saturating_mul(s.into()))
            .saturating_add(DbWeight::get().reads(23))
            .saturating_add(DbWeight::get().writes(16))
    }
    // Storage: Identity KeyRecords (r:3 w:1)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity ParentDid (r:1 w:1)
    // Proof Skipped: Identity ParentDid (max_values: None, max_size: None, mode: Measured)
    // Storage: ProtocolFee Coefficient (r:1 w:0)
    // Proof Skipped: ProtocolFee Coefficient (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: ProtocolFee BaseFees (r:1 w:0)
    // Proof Skipped: ProtocolFee BaseFees (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity MultiPurposeNonce (r:1 w:1)
    // Proof Skipped: Identity MultiPurposeNonce (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: System ParentHash (r:1 w:0)
    // Proof: System ParentHash (max_values: Some(1), max_size: Some(32), added: 527, mode: MaxEncodedLen)
    // Storage: Identity DidRecords (r:1 w:1)
    // Proof Skipped: Identity DidRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: Contracts CodeStorage (r:1 w:0)
    // Proof: Contracts CodeStorage (max_values: None, max_size: Some(126001), added: 128476, mode: MaxEncodedLen)
    // Storage: System Account (r:3 w:3)
    // Proof: System Account (max_values: None, max_size: Some(128), added: 2603, mode: MaxEncodedLen)
    // Storage: Contracts Nonce (r:1 w:1)
    // Proof: Contracts Nonce (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
    // Storage: Contracts ContractInfoOf (r:1 w:1)
    // Proof: Contracts ContractInfoOf (max_values: None, max_size: Some(290), added: 2765, mode: MaxEncodedLen)
    // Storage: Timestamp Now (r:1 w:0)
    // Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
    // Storage: Instance2Group ActiveMembers (r:1 w:0)
    // Proof Skipped: Instance2Group ActiveMembers (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Identity Claims (r:3 w:0)
    // Proof Skipped: Identity Claims (max_values: None, max_size: None, mode: Measured)
    // Storage: Contracts OwnerInfoOf (r:1 w:1)
    // Proof: Contracts OwnerInfoOf (max_values: None, max_size: Some(88), added: 2563, mode: MaxEncodedLen)
    // Storage: System EventTopics (r:2 w:2)
    // Proof Skipped: System EventTopics (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity DidKeys (r:0 w:1)
    // Proof Skipped: Identity DidKeys (max_values: None, max_size: None, mode: Measured)
    /// The range of component `s` is `[0, 1048576]`.
    fn instantiate_with_hash_as_primary_key(s: u32) -> Weight {
        // Minimum execution time: 313_117 nanoseconds.
        Weight::from_ref_time(352_178_032)
            // Standard Error: 17
            .saturating_add(Weight::from_ref_time(1_957).saturating_mul(s.into()))
            .saturating_add(DbWeight::get().reads(23))
            .saturating_add(DbWeight::get().writes(13))
    }
    // Storage: PolymeshContracts ApiNextUpgrade (r:0 w:1)
    // Proof Skipped: PolymeshContracts ApiNextUpgrade (max_values: None, max_size: None, mode: Measured)
    fn upgrade_api() -> Weight {
        // Minimum execution time: 9_778 nanoseconds.
        Weight::from_ref_time(9_918_000).saturating_add(DbWeight::get().writes(1))
    }
    // Storage: Identity KeyRecords (r:2 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: System Account (r:1 w:0)
    // Proof: System Account (max_values: None, max_size: Some(128), added: 2603, mode: MaxEncodedLen)
    // Storage: Contracts ContractInfoOf (r:1 w:1)
    // Proof: Contracts ContractInfoOf (max_values: None, max_size: Some(290), added: 2765, mode: MaxEncodedLen)
    // Storage: Contracts CodeStorage (r:1 w:0)
    // Proof: Contracts CodeStorage (max_values: None, max_size: Some(126001), added: 128476, mode: MaxEncodedLen)
    // Storage: Timestamp Now (r:1 w:0)
    // Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
    // Storage: Identity IsDidFrozen (r:1 w:0)
    // Proof Skipped: Identity IsDidFrozen (max_values: None, max_size: None, mode: Measured)
    // Storage: Instance2Group ActiveMembers (r:1 w:0)
    // Proof Skipped: Instance2Group ActiveMembers (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Identity Claims (r:2 w:0)
    // Proof Skipped: Identity Claims (max_values: None, max_size: None, mode: Measured)
    // Storage: PolymeshContracts CurrentApiHash (r:1 w:1)
    // Proof Skipped: PolymeshContracts CurrentApiHash (max_values: None, max_size: None, mode: Measured)
    // Storage: PolymeshContracts ApiNextUpgrade (r:1 w:1)
    // Proof Skipped: PolymeshContracts ApiNextUpgrade (max_values: None, max_size: None, mode: Measured)
    // Storage: System EventTopics (r:2 w:2)
    // Proof Skipped: System EventTopics (max_values: None, max_size: None, mode: Measured)
    /// The range of component `r` is `[0, 20]`.
    fn chain_extension_get_latest_api_upgrade(r: u32) -> Weight {
        // Minimum execution time: 282_670 nanoseconds.
        Weight::from_ref_time(320_358_146)
            // Standard Error: 657_365
            .saturating_add(Weight::from_ref_time(286_204_378).saturating_mul(r.into()))
            .saturating_add(DbWeight::get().reads(14))
            .saturating_add(DbWeight::get().writes(5))
    }
}
