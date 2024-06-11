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
// -p=polymesh_contracts
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
        // Minimum execution time: 105_627 nanoseconds.
        Weight::from_ref_time(105_498_622)
            // Standard Error: 28
            .saturating_add(Weight::from_ref_time(2_704).saturating_mul(k.into()))
            // Standard Error: 28
            .saturating_add(Weight::from_ref_time(208).saturating_mul(v.into()))
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
        // Minimum execution time: 96_932 nanoseconds.
        Weight::from_ref_time(104_284_433)
            // Standard Error: 21_766
            .saturating_add(Weight::from_ref_time(14_882_712).saturating_mul(r.into()))
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
        // Minimum execution time: 45_340_662 nanoseconds.
        Weight::from_ref_time(45_472_778_000)
            // Standard Error: 225_453_662
            .saturating_add(Weight::from_ref_time(49_464_054_235).saturating_mul(r.into()))
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
        // Minimum execution time: 101_049 nanoseconds.
        Weight::from_ref_time(107_077_930)
            // Standard Error: 25_247
            .saturating_add(Weight::from_ref_time(18_205_095).saturating_mul(r.into()))
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
        // Minimum execution time: 124_824 nanoseconds.
        Weight::from_ref_time(123_691_014)
            // Standard Error: 20_423
            .saturating_add(Weight::from_ref_time(6_063_156).saturating_mul(n.into()))
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
        // Minimum execution time: 99_947 nanoseconds.
        Weight::from_ref_time(108_030_319)
            // Standard Error: 25_256
            .saturating_add(Weight::from_ref_time(19_007_854).saturating_mul(r.into()))
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
        // Minimum execution time: 124_203 nanoseconds.
        Weight::from_ref_time(125_362_035)
            // Standard Error: 19_335
            .saturating_add(Weight::from_ref_time(9_763_124).saturating_mul(n.into()))
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
        // Minimum execution time: 100_198 nanoseconds.
        Weight::from_ref_time(107_656_414)
            // Standard Error: 26_906
            .saturating_add(Weight::from_ref_time(21_393_757).saturating_mul(r.into()))
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
        // Minimum execution time: 126_518 nanoseconds.
        Weight::from_ref_time(129_320_366)
            // Standard Error: 17_347
            .saturating_add(Weight::from_ref_time(17_158_067).saturating_mul(n.into()))
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
        // Minimum execution time: 117_640 nanoseconds.
        Weight::from_ref_time(121_086_563)
            // Standard Error: 29
            .saturating_add(Weight::from_ref_time(118).saturating_mul(n.into()))
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
        // Minimum execution time: 77_375 nanoseconds.
        Weight::from_ref_time(77_695_000)
            .saturating_add(DbWeight::get().reads(12))
            .saturating_add(DbWeight::get().writes(3))
    }
    /// The range of component `n` is `[1, 8188]`.
    fn basic_runtime_call(n: u32) -> Weight {
        // Minimum execution time: 481 nanoseconds.
        Weight::from_ref_time(614_715)
            // Standard Error: 1
            .saturating_add(Weight::from_ref_time(4).saturating_mul(n.into()))
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
        // Minimum execution time: 118_061 nanoseconds.
        Weight::from_ref_time(126_633_817)
            // Standard Error: 1
            .saturating_add(Weight::from_ref_time(1_591).saturating_mul(s.into()))
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
        // Minimum execution time: 1_817_686 nanoseconds.
        Weight::from_ref_time(169_396_187)
            // Standard Error: 62
            .saturating_add(Weight::from_ref_time(55_376).saturating_mul(c.into()))
            // Standard Error: 3
            .saturating_add(Weight::from_ref_time(1_584).saturating_mul(s.into()))
            .saturating_add(DbWeight::get().reads(17))
            .saturating_add(DbWeight::get().writes(13))
    }
    // Storage: PolymeshContracts CallRuntimeWhitelist (r:0 w:2000)
    // Proof Skipped: PolymeshContracts CallRuntimeWhitelist (max_values: None, max_size: None, mode: Measured)
    /// The range of component `u` is `[0, 2000]`.
    fn update_call_runtime_whitelist(u: u32) -> Weight {
        // Minimum execution time: 942 nanoseconds.
        Weight::from_ref_time(1_002_000)
            // Standard Error: 2_211
            .saturating_add(Weight::from_ref_time(673_370).saturating_mul(u.into()))
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
    // Storage: Identity ChildDid (r:0 w:1)
    // Proof Skipped: Identity ChildDid (max_values: None, max_size: None, mode: Measured)
    // Storage: Contracts CodeStorage (r:0 w:1)
    // Proof: Contracts CodeStorage (max_values: None, max_size: Some(126001), added: 128476, mode: MaxEncodedLen)
    // Storage: Contracts PristineCode (r:0 w:1)
    // Proof: Contracts PristineCode (max_values: None, max_size: Some(125988), added: 128463, mode: MaxEncodedLen)
    /// The range of component `c` is `[0, 61717]`.
    /// The range of component `s` is `[0, 1048576]`.
    fn instantiate_with_code_as_primary_key(c: u32, s: u32) -> Weight {
        // Minimum execution time: 1_843_605 nanoseconds.
        Weight::from_ref_time(171_487_039)
            // Standard Error: 35
            .saturating_add(Weight::from_ref_time(54_817).saturating_mul(c.into()))
            // Standard Error: 2
            .saturating_add(Weight::from_ref_time(1_593).saturating_mul(s.into()))
            .saturating_add(DbWeight::get().reads(23))
            .saturating_add(DbWeight::get().writes(17))
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
    // Storage: Identity ChildDid (r:0 w:1)
    // Proof Skipped: Identity ChildDid (max_values: None, max_size: None, mode: Measured)
    /// The range of component `s` is `[0, 1048576]`.
    fn instantiate_with_hash_as_primary_key(s: u32) -> Weight {
        // Minimum execution time: 131_045 nanoseconds.
        Weight::from_ref_time(133_375_738)
            // Standard Error: 6
            .saturating_add(Weight::from_ref_time(1_610).saturating_mul(s.into()))
            .saturating_add(DbWeight::get().reads(23))
            .saturating_add(DbWeight::get().writes(14))
    }
    // Storage: PolymeshContracts ApiNextUpgrade (r:0 w:1)
    // Proof Skipped: PolymeshContracts ApiNextUpgrade (max_values: None, max_size: None, mode: Measured)
    fn upgrade_api() -> Weight {
        // Minimum execution time: 3_116 nanoseconds.
        Weight::from_ref_time(3_206_000).saturating_add(DbWeight::get().writes(1))
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
        // Minimum execution time: 98_625 nanoseconds.
        Weight::from_ref_time(111_788_127)
            // Standard Error: 38_959
            .saturating_add(Weight::from_ref_time(53_366_478).saturating_mul(r.into()))
            .saturating_add(DbWeight::get().reads(14))
            .saturating_add(DbWeight::get().writes(5))
    }
}
