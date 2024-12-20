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

//! Autogenerated weights for pallet_corporate_actions
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

/// Weights for pallet_corporate_actions using the Substrate node and recommended hardware.
pub struct SubstrateWeight;
impl pallet_corporate_actions::WeightInfo for SubstrateWeight {
    // Storage: CorporateAction MaxDetailsLength (r:0 w:1)
    // Proof Skipped: CorporateAction MaxDetailsLength (max_values: Some(1), max_size: None, mode: Measured)
    fn set_max_details_length() -> Weight {
        // Minimum execution time: 8_345 nanoseconds.
        Weight::from_ref_time(8_436_000).saturating_add(DbWeight::get().writes(1))
    }
    // Storage: Identity KeyRecords (r:1 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: ExternalAgents GroupOfAgent (r:1 w:0)
    // Proof Skipped: ExternalAgents GroupOfAgent (max_values: None, max_size: None, mode: Measured)
    // Storage: Permissions CurrentPalletName (r:1 w:0)
    // Proof Skipped: Permissions CurrentPalletName (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Permissions CurrentDispatchableName (r:1 w:0)
    // Proof Skipped: Permissions CurrentDispatchableName (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: CorporateAction DefaultTargetIdentities (r:1 w:1)
    // Proof Skipped: CorporateAction DefaultTargetIdentities (max_values: None, max_size: None, mode: Measured)
    /// The range of component `t` is `[0, 500]`.
    fn set_default_targets(t: u32) -> Weight {
        // Minimum execution time: 25_568 nanoseconds.
        Weight::from_ref_time(25_839_173)
            // Standard Error: 907
            .saturating_add(Weight::from_ref_time(170_841).saturating_mul(t.into()))
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
    // Storage: CorporateAction DefaultWithholdingTax (r:1 w:1)
    // Proof Skipped: CorporateAction DefaultWithholdingTax (max_values: None, max_size: None, mode: Measured)
    fn set_default_withholding_tax() -> Weight {
        // Minimum execution time: 23_924 nanoseconds.
        Weight::from_ref_time(24_516_000)
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
    // Storage: CorporateAction DidWithholdingTax (r:1 w:1)
    // Proof Skipped: CorporateAction DidWithholdingTax (max_values: None, max_size: None, mode: Measured)
    /// The range of component `w` is `[0, 999]`.
    fn set_did_withholding_tax(w: u32) -> Weight {
        // Minimum execution time: 26_149 nanoseconds.
        Weight::from_ref_time(28_764_446)
            // Standard Error: 508
            .saturating_add(Weight::from_ref_time(33_564).saturating_mul(w.into()))
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
    // Storage: CorporateAction MaxDetailsLength (r:1 w:0)
    // Proof Skipped: CorporateAction MaxDetailsLength (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: CorporateAction CAIdSequence (r:1 w:1)
    // Proof Skipped: CorporateAction CAIdSequence (max_values: None, max_size: None, mode: Measured)
    // Storage: Timestamp Now (r:1 w:0)
    // Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
    // Storage: Checkpoint SchedulesMaxComplexity (r:1 w:0)
    // Proof Skipped: Checkpoint SchedulesMaxComplexity (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Checkpoint CachedNextCheckpoints (r:1 w:1)
    // Proof Skipped: Checkpoint CachedNextCheckpoints (max_values: None, max_size: None, mode: Measured)
    // Storage: Checkpoint ScheduleIdSequence (r:1 w:1)
    // Proof Skipped: Checkpoint ScheduleIdSequence (max_values: None, max_size: None, mode: Measured)
    // Storage: ProtocolFee Coefficient (r:1 w:0)
    // Proof Skipped: ProtocolFee Coefficient (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: ProtocolFee BaseFees (r:1 w:0)
    // Proof Skipped: ProtocolFee BaseFees (max_values: None, max_size: None, mode: Measured)
    // Storage: CorporateAction DefaultTargetIdentities (r:1 w:0)
    // Proof Skipped: CorporateAction DefaultTargetIdentities (max_values: None, max_size: None, mode: Measured)
    // Storage: CorporateAction DefaultWithholdingTax (r:1 w:0)
    // Proof Skipped: CorporateAction DefaultWithholdingTax (max_values: None, max_size: None, mode: Measured)
    // Storage: CorporateAction DidWithholdingTax (r:1 w:0)
    // Proof Skipped: CorporateAction DidWithholdingTax (max_values: None, max_size: None, mode: Measured)
    // Storage: Checkpoint ScheduledCheckpoints (r:0 w:1)
    // Proof Skipped: Checkpoint ScheduledCheckpoints (max_values: None, max_size: None, mode: Measured)
    // Storage: Checkpoint ScheduleRefCount (r:0 w:1)
    // Proof Skipped: Checkpoint ScheduleRefCount (max_values: None, max_size: None, mode: Measured)
    // Storage: CorporateAction CorporateActions (r:0 w:1)
    // Proof Skipped: CorporateAction CorporateActions (max_values: None, max_size: None, mode: Measured)
    // Storage: CorporateAction Details (r:0 w:1)
    // Proof Skipped: CorporateAction Details (max_values: None, max_size: None, mode: Measured)
    /// The range of component `w` is `[0, 1000]`.
    /// The range of component `t` is `[0, 500]`.
    fn initiate_corporate_action_use_defaults(w: u32, t: u32) -> Weight {
        // Minimum execution time: 85_561 nanoseconds.
        Weight::from_ref_time(57_719_093)
            // Standard Error: 1_184
            .saturating_add(Weight::from_ref_time(49_760).saturating_mul(w.into()))
            // Standard Error: 2_368
            .saturating_add(Weight::from_ref_time(52_226).saturating_mul(t.into()))
            .saturating_add(DbWeight::get().reads(15))
            .saturating_add(DbWeight::get().writes(7))
    }
    // Storage: Identity KeyRecords (r:1 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: ExternalAgents GroupOfAgent (r:1 w:0)
    // Proof Skipped: ExternalAgents GroupOfAgent (max_values: None, max_size: None, mode: Measured)
    // Storage: Permissions CurrentPalletName (r:1 w:0)
    // Proof Skipped: Permissions CurrentPalletName (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Permissions CurrentDispatchableName (r:1 w:0)
    // Proof Skipped: Permissions CurrentDispatchableName (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: CorporateAction MaxDetailsLength (r:1 w:0)
    // Proof Skipped: CorporateAction MaxDetailsLength (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: CorporateAction CAIdSequence (r:1 w:1)
    // Proof Skipped: CorporateAction CAIdSequence (max_values: None, max_size: None, mode: Measured)
    // Storage: Timestamp Now (r:1 w:0)
    // Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
    // Storage: Checkpoint SchedulesMaxComplexity (r:1 w:0)
    // Proof Skipped: Checkpoint SchedulesMaxComplexity (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Checkpoint CachedNextCheckpoints (r:1 w:1)
    // Proof Skipped: Checkpoint CachedNextCheckpoints (max_values: None, max_size: None, mode: Measured)
    // Storage: Checkpoint ScheduleIdSequence (r:1 w:1)
    // Proof Skipped: Checkpoint ScheduleIdSequence (max_values: None, max_size: None, mode: Measured)
    // Storage: ProtocolFee Coefficient (r:1 w:0)
    // Proof Skipped: ProtocolFee Coefficient (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: ProtocolFee BaseFees (r:1 w:0)
    // Proof Skipped: ProtocolFee BaseFees (max_values: None, max_size: None, mode: Measured)
    // Storage: Checkpoint ScheduledCheckpoints (r:0 w:1)
    // Proof Skipped: Checkpoint ScheduledCheckpoints (max_values: None, max_size: None, mode: Measured)
    // Storage: Checkpoint ScheduleRefCount (r:0 w:1)
    // Proof Skipped: Checkpoint ScheduleRefCount (max_values: None, max_size: None, mode: Measured)
    // Storage: CorporateAction CorporateActions (r:0 w:1)
    // Proof Skipped: CorporateAction CorporateActions (max_values: None, max_size: None, mode: Measured)
    // Storage: CorporateAction Details (r:0 w:1)
    // Proof Skipped: CorporateAction Details (max_values: None, max_size: None, mode: Measured)
    /// The range of component `w` is `[0, 1000]`.
    /// The range of component `t` is `[0, 500]`.
    fn initiate_corporate_action_provided(w: u32, t: u32) -> Weight {
        // Minimum execution time: 150_613 nanoseconds.
        Weight::from_ref_time(55_533_825)
            // Standard Error: 980
            .saturating_add(Weight::from_ref_time(112_323).saturating_mul(w.into()))
            // Standard Error: 1_960
            .saturating_add(Weight::from_ref_time(175_037).saturating_mul(t.into()))
            .saturating_add(DbWeight::get().reads(12))
            .saturating_add(DbWeight::get().writes(7))
    }
    // Storage: Identity KeyRecords (r:1 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: ExternalAgents GroupOfAgent (r:1 w:0)
    // Proof Skipped: ExternalAgents GroupOfAgent (max_values: None, max_size: None, mode: Measured)
    // Storage: Permissions CurrentPalletName (r:1 w:0)
    // Proof Skipped: Permissions CurrentPalletName (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Permissions CurrentDispatchableName (r:1 w:0)
    // Proof Skipped: Permissions CurrentDispatchableName (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: CorporateAction CorporateActions (r:1 w:0)
    // Proof Skipped: CorporateAction CorporateActions (max_values: None, max_size: None, mode: Measured)
    // Storage: Asset AssetDocuments (r:1000 w:0)
    // Proof Skipped: Asset AssetDocuments (max_values: None, max_size: None, mode: Measured)
    // Storage: CorporateAction CADocLink (r:1 w:1)
    // Proof Skipped: CorporateAction CADocLink (max_values: None, max_size: None, mode: Measured)
    /// The range of component `d` is `[0, 1000]`.
    fn link_ca_doc(d: u32) -> Weight {
        // Minimum execution time: 27_972 nanoseconds.
        Weight::from_ref_time(28_253_000)
            // Standard Error: 5_568
            .saturating_add(Weight::from_ref_time(2_793_512).saturating_mul(d.into()))
            .saturating_add(DbWeight::get().reads(6))
            .saturating_add(DbWeight::get().reads((1_u64).saturating_mul(d.into())))
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
    // Storage: CorporateAction CorporateActions (r:1 w:1)
    // Proof Skipped: CorporateAction CorporateActions (max_values: None, max_size: None, mode: Measured)
    // Storage: CorporateBallot TimeRanges (r:1 w:1)
    // Proof Skipped: CorporateBallot TimeRanges (max_values: None, max_size: None, mode: Measured)
    // Storage: Timestamp Now (r:1 w:0)
    // Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
    // Storage: Checkpoint ScheduleRefCount (r:1 w:1)
    // Proof Skipped: Checkpoint ScheduleRefCount (max_values: None, max_size: None, mode: Measured)
    // Storage: CorporateAction Details (r:0 w:1)
    // Proof Skipped: CorporateAction Details (max_values: None, max_size: None, mode: Measured)
    // Storage: CorporateAction CADocLink (r:0 w:1)
    // Proof Skipped: CorporateAction CADocLink (max_values: None, max_size: None, mode: Measured)
    // Storage: CorporateBallot MotionNumChoices (r:0 w:1)
    // Proof Skipped: CorporateBallot MotionNumChoices (max_values: None, max_size: None, mode: Measured)
    // Storage: CorporateBallot Metas (r:0 w:1)
    // Proof Skipped: CorporateBallot Metas (max_values: None, max_size: None, mode: Measured)
    // Storage: CorporateBallot RCV (r:0 w:1)
    // Proof Skipped: CorporateBallot RCV (max_values: None, max_size: None, mode: Measured)
    fn remove_ca_with_ballot() -> Weight {
        // Minimum execution time: 51_527 nanoseconds.
        Weight::from_ref_time(52_258_000)
            .saturating_add(DbWeight::get().reads(8))
            .saturating_add(DbWeight::get().writes(8))
    }
    // Storage: Identity KeyRecords (r:1 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: ExternalAgents GroupOfAgent (r:1 w:0)
    // Proof Skipped: ExternalAgents GroupOfAgent (max_values: None, max_size: None, mode: Measured)
    // Storage: Permissions CurrentPalletName (r:1 w:0)
    // Proof Skipped: Permissions CurrentPalletName (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Permissions CurrentDispatchableName (r:1 w:0)
    // Proof Skipped: Permissions CurrentDispatchableName (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: CorporateAction CorporateActions (r:1 w:1)
    // Proof Skipped: CorporateAction CorporateActions (max_values: None, max_size: None, mode: Measured)
    // Storage: CapitalDistribution Distributions (r:1 w:1)
    // Proof Skipped: CapitalDistribution Distributions (max_values: None, max_size: None, mode: Measured)
    // Storage: Timestamp Now (r:1 w:0)
    // Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
    // Storage: Portfolio PortfolioLockedAssets (r:1 w:1)
    // Proof Skipped: Portfolio PortfolioLockedAssets (max_values: None, max_size: None, mode: Measured)
    // Storage: Checkpoint ScheduleRefCount (r:1 w:1)
    // Proof Skipped: Checkpoint ScheduleRefCount (max_values: None, max_size: None, mode: Measured)
    // Storage: CorporateAction Details (r:0 w:1)
    // Proof Skipped: CorporateAction Details (max_values: None, max_size: None, mode: Measured)
    // Storage: CorporateAction CADocLink (r:0 w:1)
    // Proof Skipped: CorporateAction CADocLink (max_values: None, max_size: None, mode: Measured)
    fn remove_ca_with_dist() -> Weight {
        // Minimum execution time: 56_076 nanoseconds.
        Weight::from_ref_time(56_787_000)
            .saturating_add(DbWeight::get().reads(9))
            .saturating_add(DbWeight::get().writes(6))
    }
    // Storage: Identity KeyRecords (r:1 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: ExternalAgents GroupOfAgent (r:1 w:0)
    // Proof Skipped: ExternalAgents GroupOfAgent (max_values: None, max_size: None, mode: Measured)
    // Storage: Permissions CurrentPalletName (r:1 w:0)
    // Proof Skipped: Permissions CurrentPalletName (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Permissions CurrentDispatchableName (r:1 w:0)
    // Proof Skipped: Permissions CurrentDispatchableName (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: CorporateAction CorporateActions (r:1 w:1)
    // Proof Skipped: CorporateAction CorporateActions (max_values: None, max_size: None, mode: Measured)
    // Storage: Checkpoint ScheduleRefCount (r:1 w:2)
    // Proof Skipped: Checkpoint ScheduleRefCount (max_values: None, max_size: None, mode: Measured)
    // Storage: Checkpoint SchedulesMaxComplexity (r:1 w:0)
    // Proof Skipped: Checkpoint SchedulesMaxComplexity (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Checkpoint CachedNextCheckpoints (r:1 w:1)
    // Proof Skipped: Checkpoint CachedNextCheckpoints (max_values: None, max_size: None, mode: Measured)
    // Storage: Timestamp Now (r:1 w:0)
    // Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
    // Storage: Checkpoint ScheduleIdSequence (r:1 w:1)
    // Proof Skipped: Checkpoint ScheduleIdSequence (max_values: None, max_size: None, mode: Measured)
    // Storage: ProtocolFee Coefficient (r:1 w:0)
    // Proof Skipped: ProtocolFee Coefficient (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: ProtocolFee BaseFees (r:1 w:0)
    // Proof Skipped: ProtocolFee BaseFees (max_values: None, max_size: None, mode: Measured)
    // Storage: CorporateBallot TimeRanges (r:1 w:0)
    // Proof Skipped: CorporateBallot TimeRanges (max_values: None, max_size: None, mode: Measured)
    // Storage: Checkpoint ScheduledCheckpoints (r:0 w:1)
    // Proof Skipped: Checkpoint ScheduledCheckpoints (max_values: None, max_size: None, mode: Measured)
    fn change_record_date_with_ballot() -> Weight {
        // Minimum execution time: 67_677 nanoseconds.
        Weight::from_ref_time(68_037_000)
            .saturating_add(DbWeight::get().reads(13))
            .saturating_add(DbWeight::get().writes(6))
    }
    // Storage: Identity KeyRecords (r:1 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: ExternalAgents GroupOfAgent (r:1 w:0)
    // Proof Skipped: ExternalAgents GroupOfAgent (max_values: None, max_size: None, mode: Measured)
    // Storage: Permissions CurrentPalletName (r:1 w:0)
    // Proof Skipped: Permissions CurrentPalletName (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Permissions CurrentDispatchableName (r:1 w:0)
    // Proof Skipped: Permissions CurrentDispatchableName (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: CorporateAction CorporateActions (r:1 w:1)
    // Proof Skipped: CorporateAction CorporateActions (max_values: None, max_size: None, mode: Measured)
    // Storage: Checkpoint ScheduleRefCount (r:1 w:2)
    // Proof Skipped: Checkpoint ScheduleRefCount (max_values: None, max_size: None, mode: Measured)
    // Storage: Checkpoint SchedulesMaxComplexity (r:1 w:0)
    // Proof Skipped: Checkpoint SchedulesMaxComplexity (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Checkpoint CachedNextCheckpoints (r:1 w:1)
    // Proof Skipped: Checkpoint CachedNextCheckpoints (max_values: None, max_size: None, mode: Measured)
    // Storage: Timestamp Now (r:1 w:0)
    // Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
    // Storage: Checkpoint ScheduleIdSequence (r:1 w:1)
    // Proof Skipped: Checkpoint ScheduleIdSequence (max_values: None, max_size: None, mode: Measured)
    // Storage: ProtocolFee Coefficient (r:1 w:0)
    // Proof Skipped: ProtocolFee Coefficient (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: ProtocolFee BaseFees (r:1 w:0)
    // Proof Skipped: ProtocolFee BaseFees (max_values: None, max_size: None, mode: Measured)
    // Storage: CapitalDistribution Distributions (r:1 w:0)
    // Proof Skipped: CapitalDistribution Distributions (max_values: None, max_size: None, mode: Measured)
    // Storage: Checkpoint ScheduledCheckpoints (r:0 w:1)
    // Proof Skipped: Checkpoint ScheduledCheckpoints (max_values: None, max_size: None, mode: Measured)
    fn change_record_date_with_dist() -> Weight {
        // Minimum execution time: 69_020 nanoseconds.
        Weight::from_ref_time(69_150_000)
            .saturating_add(DbWeight::get().reads(13))
            .saturating_add(DbWeight::get().writes(6))
    }
}
