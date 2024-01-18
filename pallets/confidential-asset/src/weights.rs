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

//! Autogenerated weights for pallet_confidential_asset
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 4.0.0-dev
//! DATE: 2023-11-26, STEPS: `100`, REPEAT: 5, LOW RANGE: `[]`, HIGH RANGE: `[]`
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
// -p=pallet_confidential_asset
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
// ./pallets/confidential-asset/src/weights.rs
// --template
// ./.maintain/frame-weight-template.hbs

#![allow(unused_parens)]
#![allow(unused_imports)]

use polymesh_runtime_common::{RocksDbWeight as DbWeight, Weight};

/// Weights for pallet_confidential_asset using the Substrate node and recommended hardware.
pub struct SubstrateWeight;
impl crate::WeightInfo for SubstrateWeight {
    // Storage: Identity KeyRecords (r:1 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset Details (r:1 w:0)
    // Proof Skipped: ConfidentialAsset Details (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset AccountBalance (r:1 w:1)
    // Proof Skipped: ConfidentialAsset AccountBalance (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset AccountDid (r:1 w:1)
    // Proof Skipped: ConfidentialAsset AccountDid (max_values: None, max_size: None, mode: Measured)
    fn create_account() -> Weight {
        // Minimum execution time: 93_385 nanoseconds.
        Weight::from_ref_time(93_856_000)
            .saturating_add(DbWeight::get().reads(4))
            .saturating_add(DbWeight::get().writes(2))
    }
    // Storage: Identity KeyRecords (r:1 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset Details (r:1 w:1)
    // Proof Skipped: ConfidentialAsset Details (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset MediatorAccountDid (r:1 w:0)
    // Proof Skipped: ConfidentialAsset MediatorAccountDid (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset AssetAuditors (r:0 w:1)
    // Proof Skipped: ConfidentialAsset AssetAuditors (max_values: None, max_size: None, mode: Measured)
    fn create_confidential_asset() -> Weight {
        // Minimum execution time: 91_011 nanoseconds.
        Weight::from_ref_time(91_171_000)
            .saturating_add(DbWeight::get().reads(3))
            .saturating_add(DbWeight::get().writes(2))
    }
    // Storage: Identity KeyRecords (r:1 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset AccountDid (r:1 w:0)
    // Proof Skipped: ConfidentialAsset AccountDid (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset Details (r:1 w:1)
    // Proof Skipped: ConfidentialAsset Details (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset AccountBalance (r:1 w:1)
    // Proof Skipped: ConfidentialAsset AccountBalance (max_values: None, max_size: None, mode: Measured)
    fn mint_confidential_asset() -> Weight {
        // Minimum execution time: 346_169 nanoseconds.
        Weight::from_ref_time(347_050_000)
            .saturating_add(DbWeight::get().reads(4))
            .saturating_add(DbWeight::get().writes(2))
    }
    // Storage: Identity KeyRecords (r:1 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset Details (r:1 w:0)
    // Proof Skipped: ConfidentialAsset Details (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset AssetFrozen (r:1 w:1)
    // Proof Skipped: ConfidentialAsset AssetFrozen (max_values: None, max_size: None, mode: Measured)
    fn set_asset_frozen() -> Weight {
        // Minimum execution time: 88_925 nanoseconds.
        Weight::from_ref_time(88_925_000)
            .saturating_add(DbWeight::get().reads(3))
            .saturating_add(DbWeight::get().writes(1))
    }
    // Storage: Identity KeyRecords (r:1 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset Details (r:1 w:0)
    // Proof Skipped: ConfidentialAsset Details (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset AccountAssetFrozen (r:1 w:1)
    // Proof Skipped: ConfidentialAsset AccountAssetFrozen (max_values: None, max_size: None, mode: Measured)
    fn set_account_asset_frozen() -> Weight {
        // Minimum execution time: 128_656 nanoseconds.
        Weight::from_ref_time(128_656_000)
            .saturating_add(DbWeight::get().reads(3))
            .saturating_add(DbWeight::get().writes(1))
    }
    // Storage: Identity KeyRecords (r:1 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset AccountDid (r:1 w:0)
    // Proof Skipped: ConfidentialAsset AccountDid (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset IncomingBalance (r:1 w:1)
    // Proof Skipped: ConfidentialAsset IncomingBalance (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset AccountBalance (r:1 w:1)
    // Proof Skipped: ConfidentialAsset AccountBalance (max_values: None, max_size: None, mode: Measured)
    fn apply_incoming_balance() -> Weight {
        // Minimum execution time: 155_161 nanoseconds.
        Weight::from_ref_time(155_982_000)
            .saturating_add(DbWeight::get().reads(4))
            .saturating_add(DbWeight::get().writes(2))
    }
    // Storage: Identity KeyRecords (r:1 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset AccountDid (r:1 w:0)
    // Proof Skipped: ConfidentialAsset AccountDid (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset IncomingBalance (r:201 w:200)
    // Proof Skipped: ConfidentialAsset IncomingBalance (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset AccountBalance (r:200 w:200)
    // Proof Skipped: ConfidentialAsset AccountBalance (max_values: None, max_size: None, mode: Measured)
    /// The range of component `b` is `[0, 200]`.
    fn apply_incoming_balances(b: u32, ) -> Weight {
        // Minimum execution time: 91_290 nanoseconds.
        Weight::from_ref_time(287_828_944)
            // Standard Error: 1_557_055
            .saturating_add(Weight::from_ref_time(442_401_399).saturating_mul(b.into()))
            .saturating_add(DbWeight::get().reads(3))
            .saturating_add(DbWeight::get().reads((2_u64).saturating_mul(b.into())))
            .saturating_add(DbWeight::get().writes((2_u64).saturating_mul(b.into())))
    }
    // Storage: Identity KeyRecords (r:1 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset VenueCounter (r:1 w:1)
    // Proof Skipped: ConfidentialAsset VenueCounter (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: ConfidentialAsset VenueCreator (r:0 w:1)
    // Proof Skipped: ConfidentialAsset VenueCreator (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset IdentityVenues (r:0 w:1)
    // Proof Skipped: ConfidentialAsset IdentityVenues (max_values: None, max_size: None, mode: Measured)
    fn create_venue() -> Weight {
        // Minimum execution time: 19_136 nanoseconds.
        Weight::from_ref_time(19_347_000)
            .saturating_add(DbWeight::get().reads(2))
            .saturating_add(DbWeight::get().writes(3))
    }
    // Storage: Identity KeyRecords (r:1 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset VenueFiltering (r:0 w:1)
    // Proof Skipped: ConfidentialAsset VenueFiltering (max_values: None, max_size: None, mode: Measured)
    fn set_venue_filtering() -> Weight {
        // Minimum execution time: 15_840 nanoseconds.
        Weight::from_ref_time(16_280_000)
            .saturating_add(DbWeight::get().reads(1))
            .saturating_add(DbWeight::get().writes(1))
    }
    // Storage: Identity KeyRecords (r:1 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset Details (r:1 w:0)
    // Proof Skipped: ConfidentialAsset Details (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset VenueAllowList (r:0 w:99)
    // Proof Skipped: ConfidentialAsset VenueAllowList (max_values: None, max_size: None, mode: Measured)
    /// The range of component `v` is `[0, 100]`.
    fn allow_venues(v: u32) -> Weight {
        // Minimum execution time: 20_949 nanoseconds.
        Weight::from_ref_time(21_098_925)
            // Standard Error: 3_638
            .saturating_add(Weight::from_ref_time(1_665_893).saturating_mul(v.into()))
            .saturating_add(DbWeight::get().reads(2))
            .saturating_add(DbWeight::get().writes((1_u64).saturating_mul(v.into())))
    }
    // Storage: Identity KeyRecords (r:1 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset Details (r:1 w:0)
    // Proof Skipped: ConfidentialAsset Details (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset VenueAllowList (r:0 w:99)
    // Proof Skipped: ConfidentialAsset VenueAllowList (max_values: None, max_size: None, mode: Measured)
    /// The range of component `v` is `[0, 100]`.
    fn disallow_venues(v: u32) -> Weight {
        // Minimum execution time: 19_807 nanoseconds.
        Weight::from_ref_time(18_832_564)
            // Standard Error: 7_330
            .saturating_add(Weight::from_ref_time(1_650_184).saturating_mul(v.into()))
            .saturating_add(DbWeight::get().reads(2))
            .saturating_add(DbWeight::get().writes((1_u64).saturating_mul(v.into())))
    }
    // Storage: Identity KeyRecords (r:1 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset VenueCreator (r:1 w:0)
    // Proof Skipped: ConfidentialAsset VenueCreator (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset TransactionCounter (r:1 w:1)
    // Proof Skipped: ConfidentialAsset TransactionCounter (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: ConfidentialAsset VenueFiltering (r:100 w:0)
    // Proof Skipped: ConfidentialAsset VenueFiltering (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset AssetAuditors (r:100 w:0)
    // Proof Skipped: ConfidentialAsset AssetAuditors (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset AccountDid (r:200 w:0)
    // Proof Skipped: ConfidentialAsset AccountDid (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset MediatorAccountDid (r:799 w:0)
    // Proof Skipped: ConfidentialAsset MediatorAccountDid (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset PendingAffirms (r:0 w:1)
    // Proof Skipped: ConfidentialAsset PendingAffirms (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset TransactionStatuses (r:0 w:1)
    // Proof Skipped: ConfidentialAsset TransactionStatuses (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset UserAffirmations (r:0 w:999)
    // Proof Skipped: ConfidentialAsset UserAffirmations (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset TransactionLegs (r:0 w:100)
    // Proof Skipped: ConfidentialAsset TransactionLegs (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset VenueTransactions (r:0 w:1)
    // Proof Skipped: ConfidentialAsset VenueTransactions (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset Transactions (r:0 w:1)
    // Proof Skipped: ConfidentialAsset Transactions (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset TransactionPartyCount (r:0 w:1)
    // Proof Skipped: ConfidentialAsset TransactionPartyCount (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset TransactionParties (r:0 w:1000)
    // Proof Skipped: ConfidentialAsset TransactionParties (max_values: None, max_size: None, mode: Measured)
    /// The range of component `l` is `[1, 100]`.
    /// The range of component `m` is `[0, 800]`.
    fn add_transaction(l: u32, m: u32) -> Weight {
        // Minimum execution time: 259_035 nanoseconds.
        Weight::from_ref_time(259_907_000)
            // Standard Error: 1_020_312
            .saturating_add(Weight::from_ref_time(189_485_496).saturating_mul(l.into()))
            // Standard Error: 127_729
            .saturating_add(Weight::from_ref_time(3_601_481).saturating_mul(m.into()))
            .saturating_add(DbWeight::get().reads(15))
            .saturating_add(DbWeight::get().reads((7_u64).saturating_mul(l.into())))
            .saturating_add(DbWeight::get().writes(28))
            .saturating_add(DbWeight::get().writes((11_u64).saturating_mul(l.into())))
            .saturating_add(DbWeight::get().writes((1_u64).saturating_mul(m.into())))
    }
    // Storage: Identity KeyRecords (r:1 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset TransactionLegs (r:1 w:0)
    // Proof Skipped: ConfidentialAsset TransactionLegs (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset UserAffirmations (r:1 w:1)
    // Proof Skipped: ConfidentialAsset UserAffirmations (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset AccountDid (r:1 w:0)
    // Proof Skipped: ConfidentialAsset AccountDid (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset AccountBalance (r:1 w:1)
    // Proof Skipped: ConfidentialAsset AccountBalance (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset RngNonce (r:1 w:1)
    // Proof Skipped: ConfidentialAsset RngNonce (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Babe NextRandomness (r:1 w:0)
    // Proof: Babe NextRandomness (max_values: Some(1), max_size: Some(32), added: 527, mode: MaxEncodedLen)
    // Storage: Babe EpochStart (r:1 w:0)
    // Proof: Babe EpochStart (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
    // Storage: ConfidentialAsset PendingAffirms (r:1 w:1)
    // Proof Skipped: ConfidentialAsset PendingAffirms (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset TxLegSenderAmount (r:0 w:1)
    // Proof Skipped: ConfidentialAsset TxLegSenderAmount (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset TxLegReceiverAmount (r:0 w:1)
    // Proof Skipped: ConfidentialAsset TxLegReceiverAmount (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset TxLegSenderBalance (r:0 w:1)
    // Proof Skipped: ConfidentialAsset TxLegSenderBalance (max_values: None, max_size: None, mode: Measured)
    /// The range of component `a` is `[0, 8]`.
    fn sender_affirm_transaction(a: u32) -> Weight {
        // Minimum execution time: 2_662_260 nanoseconds.
        Weight::from_ref_time(2_671_818_178)
            // Standard Error: 649_848
            .saturating_add(Weight::from_ref_time(45_227_255).saturating_mul(a.into()))
            .saturating_add(DbWeight::get().reads(9))
            .saturating_add(DbWeight::get().writes(7))
    }
    // Storage: Identity KeyRecords (r:1 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset TransactionLegs (r:1 w:0)
    // Proof Skipped: ConfidentialAsset TransactionLegs (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset UserAffirmations (r:1 w:1)
    // Proof Skipped: ConfidentialAsset UserAffirmations (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset AccountDid (r:1 w:0)
    // Proof Skipped: ConfidentialAsset AccountDid (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset PendingAffirms (r:1 w:1)
    // Proof Skipped: ConfidentialAsset PendingAffirms (max_values: None, max_size: None, mode: Measured)
    fn receiver_affirm_transaction() -> Weight {
        // Minimum execution time: 38_522 nanoseconds.
        Weight::from_ref_time(39_444_000)
            .saturating_add(DbWeight::get().reads(5))
            .saturating_add(DbWeight::get().writes(2))
    }
    // Storage: Identity KeyRecords (r:1 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset TransactionLegs (r:1 w:0)
    // Proof Skipped: ConfidentialAsset TransactionLegs (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset UserAffirmations (r:1 w:1)
    // Proof Skipped: ConfidentialAsset UserAffirmations (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset MediatorAccountDid (r:1 w:0)
    // Proof Skipped: ConfidentialAsset MediatorAccountDid (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset PendingAffirms (r:1 w:1)
    // Proof Skipped: ConfidentialAsset PendingAffirms (max_values: None, max_size: None, mode: Measured)
    fn mediator_affirm_transaction() -> Weight {
        // Minimum execution time: 39_484 nanoseconds.
        Weight::from_ref_time(39_665_000)
            .saturating_add(DbWeight::get().reads(5))
            .saturating_add(DbWeight::get().writes(2))
    }
    // Storage: Identity KeyRecords (r:1 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset TransactionParties (r:1001 w:1001)
    // Proof Skipped: ConfidentialAsset TransactionParties (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset TransactionLegs (r:101 w:100)
    // Proof Skipped: ConfidentialAsset TransactionLegs (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset PendingAffirms (r:1 w:1)
    // Proof Skipped: ConfidentialAsset PendingAffirms (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset Transactions (r:1 w:1)
    // Proof Skipped: ConfidentialAsset Transactions (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset AccountDid (r:200 w:0)
    // Proof Skipped: ConfidentialAsset AccountDid (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset UserAffirmations (r:1000 w:1000)
    // Proof Skipped: ConfidentialAsset UserAffirmations (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset MediatorAccountDid (r:800 w:0)
    // Proof Skipped: ConfidentialAsset MediatorAccountDid (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset TxLegReceiverAmount (r:100 w:100)
    // Proof Skipped: ConfidentialAsset TxLegReceiverAmount (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset IncomingBalance (r:100 w:100)
    // Proof Skipped: ConfidentialAsset IncomingBalance (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset TransactionPartyCount (r:1 w:1)
    // Proof Skipped: ConfidentialAsset TransactionPartyCount (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset TransactionStatuses (r:0 w:1)
    // Proof Skipped: ConfidentialAsset TransactionStatuses (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset TxLegSenderAmount (r:0 w:100)
    // Proof Skipped: ConfidentialAsset TxLegSenderAmount (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset TxLegSenderBalance (r:0 w:100)
    // Proof Skipped: ConfidentialAsset TxLegSenderBalance (max_values: None, max_size: None, mode: Measured)
    /// The range of component `l` is `[1, 100]`.
    fn execute_transaction(l: u32) -> Weight {
        // Minimum execution time: 237_866 nanoseconds.
        Weight::from_ref_time(238_166_000)
            // Standard Error: 282_936
            .saturating_add(Weight::from_ref_time(200_746_406).saturating_mul(l.into()))
            .saturating_add(DbWeight::get().reads(6))
            .saturating_add(DbWeight::get().reads((33_u64).saturating_mul(l.into())))
            .saturating_add(DbWeight::get().writes(5))
            .saturating_add(DbWeight::get().writes((25_u64).saturating_mul(l.into())))
    }
    // Storage: Identity KeyRecords (r:1 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset TransactionParties (r:1001 w:1001)
    // Proof Skipped: ConfidentialAsset TransactionParties (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset TransactionLegs (r:101 w:100)
    // Proof Skipped: ConfidentialAsset TransactionLegs (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset Transactions (r:1 w:1)
    // Proof Skipped: ConfidentialAsset Transactions (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset AccountDid (r:200 w:0)
    // Proof Skipped: ConfidentialAsset AccountDid (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset UserAffirmations (r:100 w:1000)
    // Proof Skipped: ConfidentialAsset UserAffirmations (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset MediatorAccountDid (r:800 w:0)
    // Proof Skipped: ConfidentialAsset MediatorAccountDid (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset TxLegSenderAmount (r:100 w:100)
    // Proof Skipped: ConfidentialAsset TxLegSenderAmount (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset IncomingBalance (r:100 w:100)
    // Proof Skipped: ConfidentialAsset IncomingBalance (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset TransactionPartyCount (r:1 w:1)
    // Proof Skipped: ConfidentialAsset TransactionPartyCount (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset PendingAffirms (r:0 w:1)
    // Proof Skipped: ConfidentialAsset PendingAffirms (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset TransactionStatuses (r:0 w:1)
    // Proof Skipped: ConfidentialAsset TransactionStatuses (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset TxLegReceiverAmount (r:0 w:100)
    // Proof Skipped: ConfidentialAsset TxLegReceiverAmount (max_values: None, max_size: None, mode: Measured)
    // Storage: ConfidentialAsset TxLegSenderBalance (r:0 w:100)
    // Proof Skipped: ConfidentialAsset TxLegSenderBalance (max_values: None, max_size: None, mode: Measured)
    /// The range of component `l` is `[1, 100]`.
    fn reject_transaction(l: u32) -> Weight {
        // Minimum execution time: 217_328 nanoseconds.
        Weight::from_ref_time(150_456_392)
            // Standard Error: 1_067_121
            .saturating_add(Weight::from_ref_time(184_118_359).saturating_mul(l.into()))
            .saturating_add(DbWeight::get().reads(5))
            .saturating_add(DbWeight::get().reads((24_u64).saturating_mul(l.into())))
            .saturating_add(DbWeight::get().writes(5))
            .saturating_add(DbWeight::get().writes((25_u64).saturating_mul(l.into())))
    }
}
