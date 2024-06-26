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

//! Autogenerated weights for pallet_identity
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
// -p=pallet_identity
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

/// Weights for pallet_identity using the Substrate node and recommended hardware.
pub struct SubstrateWeight;
impl pallet_identity::WeightInfo for SubstrateWeight {
    // Storage: Identity KeyRecords (r:2 w:1)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity ParentDid (r:1 w:1)
    // Proof Skipped: Identity ParentDid (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity AccountKeyRefCount (r:1 w:0)
    // Proof Skipped: Identity AccountKeyRefCount (max_values: None, max_size: None, mode: Measured)
    // Storage: MultiSig MultiSigToIdentity (r:1 w:0)
    // Proof Skipped: MultiSig MultiSigToIdentity (max_values: None, max_size: None, mode: Measured)
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
    // Storage: Identity DidKeys (r:0 w:2)
    // Proof Skipped: Identity DidKeys (max_values: None, max_size: None, mode: Measured)
    fn create_child_identity() -> Weight {
        // Minimum execution time: 59_671 nanoseconds.
        Weight::from_ref_time(60_693_000)
            .saturating_add(DbWeight::get().reads(10))
            .saturating_add(DbWeight::get().writes(6))
    }
    // Storage: Identity KeyRecords (r:100 w:99)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity ParentDid (r:1 w:99)
    // Proof Skipped: Identity ParentDid (max_values: None, max_size: None, mode: Measured)
    // Storage: Timestamp Now (r:1 w:0)
    // Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
    // Storage: Identity OffChainAuthorizationNonce (r:1 w:1)
    // Proof Skipped: Identity OffChainAuthorizationNonce (max_values: None, max_size: None, mode: Measured)
    // Storage: ProtocolFee Coefficient (r:1 w:0)
    // Proof Skipped: ProtocolFee Coefficient (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: ProtocolFee BaseFees (r:1 w:0)
    // Proof Skipped: ProtocolFee BaseFees (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity MultiPurposeNonce (r:1 w:1)
    // Proof Skipped: Identity MultiPurposeNonce (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: System ParentHash (r:1 w:0)
    // Proof: System ParentHash (max_values: Some(1), max_size: Some(32), added: 527, mode: MaxEncodedLen)
    // Storage: Identity DidRecords (r:99 w:99)
    // Proof Skipped: Identity DidRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity DidKeys (r:0 w:99)
    // Proof Skipped: Identity DidKeys (max_values: None, max_size: None, mode: Measured)
    /// The range of component `i` is `[0, 100]`.
    fn create_child_identities(i: u32) -> Weight {
        // Minimum execution time: 22_292 nanoseconds.
        Weight::from_ref_time(51_937_688)
            // Standard Error: 202_881
            .saturating_add(Weight::from_ref_time(55_550_034).saturating_mul(i.into()))
            .saturating_add(DbWeight::get().reads(8))
            .saturating_add(DbWeight::get().reads((2_u64).saturating_mul(i.into())))
            .saturating_add(DbWeight::get().writes(2))
            .saturating_add(DbWeight::get().writes((4_u64).saturating_mul(i.into())))
    }
    // Storage: Identity KeyRecords (r:1 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity ParentDid (r:1 w:1)
    // Proof Skipped: Identity ParentDid (max_values: None, max_size: None, mode: Measured)
    fn unlink_child_identity() -> Weight {
        // Minimum execution time: 17_773 nanoseconds.
        Weight::from_ref_time(18_164_000)
            .saturating_add(DbWeight::get().reads(2))
            .saturating_add(DbWeight::get().writes(1))
    }
    // Storage: Identity KeyRecords (r:201 w:1)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: Instance2Group ActiveMembers (r:1 w:0)
    // Proof Skipped: Instance2Group ActiveMembers (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Identity MultiPurposeNonce (r:1 w:1)
    // Proof Skipped: Identity MultiPurposeNonce (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: System ParentHash (r:1 w:0)
    // Proof: System ParentHash (max_values: Some(1), max_size: Some(32), added: 527, mode: MaxEncodedLen)
    // Storage: Identity DidRecords (r:1 w:1)
    // Proof Skipped: Identity DidRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: ProtocolFee Coefficient (r:1 w:0)
    // Proof Skipped: ProtocolFee Coefficient (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: ProtocolFee BaseFees (r:1 w:0)
    // Proof Skipped: ProtocolFee BaseFees (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity AuthorizationsGiven (r:0 w:199)
    // Proof Skipped: Identity AuthorizationsGiven (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity DidKeys (r:0 w:1)
    // Proof Skipped: Identity DidKeys (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity Authorizations (r:0 w:199)
    // Proof Skipped: Identity Authorizations (max_values: None, max_size: None, mode: Measured)
    /// The range of component `i` is `[0, 200]`.
    fn cdd_register_did(i: u32) -> Weight {
        // Minimum execution time: 36_558 nanoseconds.
        Weight::from_ref_time(94_144_720)
            // Standard Error: 153_904
            .saturating_add(Weight::from_ref_time(9_636_661).saturating_mul(i.into()))
            .saturating_add(DbWeight::get().reads(8))
            .saturating_add(DbWeight::get().reads((1_u64).saturating_mul(i.into())))
            .saturating_add(DbWeight::get().writes(4))
            .saturating_add(DbWeight::get().writes((2_u64).saturating_mul(i.into())))
    }
    // Storage: Timestamp Now (r:1 w:0)
    // Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
    // Storage: Instance2Group ActiveMembers (r:1 w:1)
    // Proof Skipped: Instance2Group ActiveMembers (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Instance2Group InactiveMembers (r:1 w:1)
    // Proof Skipped: Instance2Group InactiveMembers (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Identity Claims (r:1 w:1)
    // Proof Skipped: Identity Claims (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity CurrentDid (r:1 w:0)
    // Proof Skipped: Identity CurrentDid (max_values: Some(1), max_size: None, mode: Measured)
    fn invalidate_cdd_claims() -> Weight {
        // Minimum execution time: 72_937 nanoseconds.
        Weight::from_ref_time(77_475_000)
            .saturating_add(DbWeight::get().reads(5))
            .saturating_add(DbWeight::get().writes(3))
    }
    // Storage: Identity KeyRecords (r:200 w:199)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity AccountKeyRefCount (r:199 w:0)
    // Proof Skipped: Identity AccountKeyRefCount (max_values: None, max_size: None, mode: Measured)
    // Storage: MultiSig MultiSigToIdentity (r:199 w:0)
    // Proof Skipped: MultiSig MultiSigToIdentity (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity DidKeys (r:0 w:199)
    // Proof Skipped: Identity DidKeys (max_values: None, max_size: None, mode: Measured)
    /// The range of component `i` is `[0, 200]`.
    fn remove_secondary_keys(i: u32) -> Weight {
        // Minimum execution time: 13_436 nanoseconds.
        Weight::from_ref_time(34_835_490)
            // Standard Error: 77_983
            .saturating_add(Weight::from_ref_time(9_611_971).saturating_mul(i.into()))
            .saturating_add(DbWeight::get().reads(1))
            .saturating_add(DbWeight::get().reads((3_u64).saturating_mul(i.into())))
            .saturating_add(DbWeight::get().writes((2_u64).saturating_mul(i.into())))
    }
    // Storage: Identity Authorizations (r:2 w:2)
    // Proof Skipped: Identity Authorizations (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity DidRecords (r:1 w:1)
    // Proof Skipped: Identity DidRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity KeyRecords (r:2 w:2)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity AccountKeyRefCount (r:1 w:0)
    // Proof Skipped: Identity AccountKeyRefCount (max_values: None, max_size: None, mode: Measured)
    // Storage: MultiSig MultiSigToIdentity (r:1 w:0)
    // Proof Skipped: MultiSig MultiSigToIdentity (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity CddAuthForPrimaryKeyRotation (r:1 w:0)
    // Proof Skipped: Identity CddAuthForPrimaryKeyRotation (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Instance2Group ActiveMembers (r:1 w:0)
    // Proof Skipped: Instance2Group ActiveMembers (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Identity AuthorizationsGiven (r:0 w:2)
    // Proof Skipped: Identity AuthorizationsGiven (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity DidKeys (r:0 w:2)
    // Proof Skipped: Identity DidKeys (max_values: None, max_size: None, mode: Measured)
    fn accept_primary_key() -> Weight {
        // Minimum execution time: 65_422 nanoseconds.
        Weight::from_ref_time(66_094_000)
            .saturating_add(DbWeight::get().reads(9))
            .saturating_add(DbWeight::get().writes(9))
    }
    // Storage: Identity Authorizations (r:2 w:2)
    // Proof Skipped: Identity Authorizations (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity DidRecords (r:1 w:1)
    // Proof Skipped: Identity DidRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity KeyRecords (r:1 w:2)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity CddAuthForPrimaryKeyRotation (r:1 w:0)
    // Proof Skipped: Identity CddAuthForPrimaryKeyRotation (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Instance2Group ActiveMembers (r:1 w:0)
    // Proof Skipped: Instance2Group ActiveMembers (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Identity AuthorizationsGiven (r:0 w:2)
    // Proof Skipped: Identity AuthorizationsGiven (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity DidKeys (r:0 w:1)
    // Proof Skipped: Identity DidKeys (max_values: None, max_size: None, mode: Measured)
    fn rotate_primary_key_to_secondary() -> Weight {
        // Minimum execution time: 56_075 nanoseconds.
        Weight::from_ref_time(56_676_000)
            .saturating_add(DbWeight::get().reads(6))
            .saturating_add(DbWeight::get().writes(8))
    }
    // Storage: Identity CddAuthForPrimaryKeyRotation (r:0 w:1)
    // Proof Skipped: Identity CddAuthForPrimaryKeyRotation (max_values: Some(1), max_size: None, mode: Measured)
    fn change_cdd_requirement_for_mk_rotation() -> Weight {
        // Minimum execution time: 7_524 nanoseconds.
        Weight::from_ref_time(7_685_000).saturating_add(DbWeight::get().writes(1))
    }
    // Storage: Identity Authorizations (r:1 w:1)
    // Proof Skipped: Identity Authorizations (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity DidRecords (r:1 w:0)
    // Proof Skipped: Identity DidRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity KeyRecords (r:1 w:1)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: Timestamp Now (r:1 w:0)
    // Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
    // Storage: Instance2Group ActiveMembers (r:1 w:0)
    // Proof Skipped: Instance2Group ActiveMembers (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Identity Claims (r:2 w:0)
    // Proof Skipped: Identity Claims (max_values: None, max_size: None, mode: Measured)
    // Storage: ProtocolFee Coefficient (r:1 w:0)
    // Proof Skipped: ProtocolFee Coefficient (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: ProtocolFee BaseFees (r:1 w:0)
    // Proof Skipped: ProtocolFee BaseFees (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity AuthorizationsGiven (r:0 w:1)
    // Proof Skipped: Identity AuthorizationsGiven (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity DidKeys (r:0 w:1)
    // Proof Skipped: Identity DidKeys (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity CurrentDid (r:0 w:1)
    // Proof Skipped: Identity CurrentDid (max_values: Some(1), max_size: None, mode: Measured)
    fn join_identity_as_key() -> Weight {
        // Minimum execution time: 53_130 nanoseconds.
        Weight::from_ref_time(54_121_000)
            .saturating_add(DbWeight::get().reads(9))
            .saturating_add(DbWeight::get().writes(5))
    }
    // Storage: Identity CurrentDid (r:1 w:0)
    // Proof Skipped: Identity CurrentDid (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Identity KeyRecords (r:1 w:1)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity AccountKeyRefCount (r:1 w:0)
    // Proof Skipped: Identity AccountKeyRefCount (max_values: None, max_size: None, mode: Measured)
    // Storage: MultiSig MultiSigToIdentity (r:1 w:0)
    // Proof Skipped: MultiSig MultiSigToIdentity (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity DidKeys (r:0 w:1)
    // Proof Skipped: Identity DidKeys (max_values: None, max_size: None, mode: Measured)
    fn leave_identity_as_key() -> Weight {
        // Minimum execution time: 28_333 nanoseconds.
        Weight::from_ref_time(28_423_000)
            .saturating_add(DbWeight::get().reads(4))
            .saturating_add(DbWeight::get().writes(2))
    }
    // Storage: Identity KeyRecords (r:1 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity DidRecords (r:1 w:0)
    // Proof Skipped: Identity DidRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: ProtocolFee Coefficient (r:1 w:0)
    // Proof Skipped: ProtocolFee Coefficient (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: ProtocolFee BaseFees (r:1 w:0)
    // Proof Skipped: ProtocolFee BaseFees (max_values: None, max_size: None, mode: Measured)
    // Storage: Timestamp Now (r:1 w:0)
    // Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
    // Storage: Identity Claims (r:1 w:1)
    // Proof Skipped: Identity Claims (max_values: None, max_size: None, mode: Measured)
    fn add_claim() -> Weight {
        // Minimum execution time: 30_737 nanoseconds.
        Weight::from_ref_time(31_399_000)
            .saturating_add(DbWeight::get().reads(6))
            .saturating_add(DbWeight::get().writes(1))
    }
    // Storage: Identity KeyRecords (r:1 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity Claims (r:1 w:1)
    // Proof Skipped: Identity Claims (max_values: None, max_size: None, mode: Measured)
    fn revoke_claim() -> Weight {
        // Minimum execution time: 18_865 nanoseconds.
        Weight::from_ref_time(19_867_000)
            .saturating_add(DbWeight::get().reads(2))
            .saturating_add(DbWeight::get().writes(1))
    }
    // Storage: Identity KeyRecords (r:1 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity Claims (r:1 w:1)
    // Proof Skipped: Identity Claims (max_values: None, max_size: None, mode: Measured)
    fn revoke_claim_by_index() -> Weight {
        // Minimum execution time: 18_544 nanoseconds.
        Weight::from_ref_time(19_226_000)
            .saturating_add(DbWeight::get().reads(2))
            .saturating_add(DbWeight::get().writes(1))
    }
    // Storage: Identity KeyRecords (r:2 w:1)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    fn set_secondary_key_permissions() -> Weight {
        // Minimum execution time: 19_727 nanoseconds.
        Weight::from_ref_time(20_378_000)
            .saturating_add(DbWeight::get().reads(2))
            .saturating_add(DbWeight::get().writes(1))
    }
    /// The range of component `a` is `[0, 2000]`.
    /// The range of component `p` is `[0, 2000]`.
    /// The range of component `l` is `[0, 80]`.
    /// The range of component `e` is `[0, 80]`.
    fn permissions_cost(a: u32, p: u32, l: u32, e: u32) -> Weight {
        // Minimum execution time: 229_059 nanoseconds.
        Weight::from_ref_time(229_780_000)
            // Manually set for `a`
            .saturating_add(Weight::from_ref_time(100_000).saturating_mul(a.into()))
            // Manually set for `p`
            .saturating_add(Weight::from_ref_time(100_000).saturating_mul(p.into()))
            // Standard Error: 216_248
            .saturating_add(Weight::from_ref_time(11_850_277).saturating_mul(l.into()))
            // Standard Error: 216_248
            .saturating_add(Weight::from_ref_time(9_950_582).saturating_mul(e.into()))
    }
    // Storage: Identity KeyRecords (r:1 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity IsDidFrozen (r:0 w:1)
    // Proof Skipped: Identity IsDidFrozen (max_values: None, max_size: None, mode: Measured)
    fn freeze_secondary_keys() -> Weight {
        // Minimum execution time: 14_868 nanoseconds.
        Weight::from_ref_time(15_459_000)
            .saturating_add(DbWeight::get().reads(1))
            .saturating_add(DbWeight::get().writes(1))
    }
    // Storage: Identity KeyRecords (r:1 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity IsDidFrozen (r:0 w:1)
    // Proof Skipped: Identity IsDidFrozen (max_values: None, max_size: None, mode: Measured)
    fn unfreeze_secondary_keys() -> Weight {
        // Minimum execution time: 14_086 nanoseconds.
        Weight::from_ref_time(14_537_000)
            .saturating_add(DbWeight::get().reads(1))
            .saturating_add(DbWeight::get().writes(1))
    }
    // Storage: Identity KeyRecords (r:1 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity MultiPurposeNonce (r:1 w:1)
    // Proof Skipped: Identity MultiPurposeNonce (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Identity AuthorizationsGiven (r:0 w:1)
    // Proof Skipped: Identity AuthorizationsGiven (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity Authorizations (r:0 w:1)
    // Proof Skipped: Identity Authorizations (max_values: None, max_size: None, mode: Measured)
    fn add_authorization() -> Weight {
        // Minimum execution time: 19_216 nanoseconds.
        Weight::from_ref_time(19_908_000)
            .saturating_add(DbWeight::get().reads(2))
            .saturating_add(DbWeight::get().writes(3))
    }
    // Storage: Identity KeyRecords (r:1 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity Authorizations (r:1 w:1)
    // Proof Skipped: Identity Authorizations (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity AuthorizationsGiven (r:0 w:1)
    // Proof Skipped: Identity AuthorizationsGiven (max_values: None, max_size: None, mode: Measured)
    fn remove_authorization() -> Weight {
        // Minimum execution time: 21_921 nanoseconds.
        Weight::from_ref_time(22_573_000)
            .saturating_add(DbWeight::get().reads(2))
            .saturating_add(DbWeight::get().writes(2))
    }
    // Storage: Identity KeyRecords (r:200 w:199)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: Timestamp Now (r:1 w:0)
    // Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
    // Storage: Identity OffChainAuthorizationNonce (r:1 w:1)
    // Proof Skipped: Identity OffChainAuthorizationNonce (max_values: None, max_size: None, mode: Measured)
    // Storage: ProtocolFee Coefficient (r:1 w:0)
    // Proof Skipped: ProtocolFee Coefficient (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: ProtocolFee BaseFees (r:1 w:0)
    // Proof Skipped: ProtocolFee BaseFees (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity DidKeys (r:0 w:199)
    // Proof Skipped: Identity DidKeys (max_values: None, max_size: None, mode: Measured)
    /// The range of component `i` is `[0, 200]`.
    fn add_secondary_keys_with_authorization(i: u32) -> Weight {
        // Minimum execution time: 24_846 nanoseconds.
        Weight::from_ref_time(24_867_000)
            // Standard Error: 117_973
            .saturating_add(Weight::from_ref_time(43_661_938).saturating_mul(i.into()))
            .saturating_add(DbWeight::get().reads(5))
            .saturating_add(DbWeight::get().reads((1_u64).saturating_mul(i.into())))
            .saturating_add(DbWeight::get().writes(1))
            .saturating_add(DbWeight::get().writes((2_u64).saturating_mul(i.into())))
    }
    // Storage: Identity KeyRecords (r:1 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity CustomClaimsInverse (r:1 w:1)
    // Proof Skipped: Identity CustomClaimsInverse (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity CustomClaimIdSequence (r:1 w:1)
    // Proof Skipped: Identity CustomClaimIdSequence (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Identity CustomClaims (r:0 w:1)
    // Proof Skipped: Identity CustomClaims (max_values: None, max_size: None, mode: Measured)
    /// The range of component `n` is `[1, 2048]`.
    fn register_custom_claim_type(n: u32) -> Weight {
        // Minimum execution time: 22_212 nanoseconds.
        Weight::from_ref_time(23_100_288)
            // Standard Error: 520
            .saturating_add(Weight::from_ref_time(5_203).saturating_mul(n.into()))
            .saturating_add(DbWeight::get().reads(3))
            .saturating_add(DbWeight::get().writes(3))
    }
}
