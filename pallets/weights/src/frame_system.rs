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

//! Autogenerated weights for frame_system
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
// -p=frame_system
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

/// Weights for frame_system using the Substrate node and recommended hardware.
pub struct SubstrateWeight;
impl frame_system::WeightInfo for SubstrateWeight {
    /// The range of component `b` is `[0, 7864320]`.
    fn remark(b: u32) -> Weight {
        // Minimum execution time: 2_044 nanoseconds.
        Weight::from_ref_time(13_901_155)
            // Standard Error: 0
            .saturating_add(Weight::from_ref_time(184).saturating_mul(b.into()))
    }
    /// The range of component `b` is `[0, 7864320]`.
    fn remark_with_event(b: u32) -> Weight {
        // Minimum execution time: 6_362 nanoseconds.
        Weight::from_ref_time(6_482_000)
            // Standard Error: 1
            .saturating_add(Weight::from_ref_time(1_011).saturating_mul(b.into()))
    }
    // Storage: System Digest (r:1 w:1)
    // Proof Skipped: System Digest (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: unknown `0x3a686561707061676573` (r:0 w:1)
    // Proof Skipped: unknown `0x3a686561707061676573` (r:0 w:1)
    fn set_heap_pages() -> Weight {
        // Minimum execution time: 3_767 nanoseconds.
        Weight::from_ref_time(3_887_000)
            .saturating_add(DbWeight::get().reads(1))
            .saturating_add(DbWeight::get().writes(2))
    }
    // Storage: Skipped Metadata (r:0 w:0)
    // Proof Skipped: Skipped Metadata (max_values: None, max_size: None, mode: Measured)
    /// The range of component `i` is `[0, 1000]`.
    fn set_storage(i: u32) -> Weight {
        // Minimum execution time: 2_004 nanoseconds.
        Weight::from_ref_time(2_134_000)
            // Standard Error: 911
            .saturating_add(Weight::from_ref_time(753_691).saturating_mul(i.into()))
            .saturating_add(DbWeight::get().writes((1_u64).saturating_mul(i.into())))
    }
    // Storage: Skipped Metadata (r:0 w:0)
    // Proof Skipped: Skipped Metadata (max_values: None, max_size: None, mode: Measured)
    /// The range of component `i` is `[0, 1000]`.
    fn kill_storage(i: u32) -> Weight {
        // Minimum execution time: 1_984 nanoseconds.
        Weight::from_ref_time(2_114_000)
            // Standard Error: 823
            .saturating_add(Weight::from_ref_time(523_241).saturating_mul(i.into()))
            .saturating_add(DbWeight::get().writes((1_u64).saturating_mul(i.into())))
    }
    // Storage: Skipped Metadata (r:0 w:0)
    // Proof Skipped: Skipped Metadata (max_values: None, max_size: None, mode: Measured)
    /// The range of component `p` is `[0, 1000]`.
    fn kill_prefix(p: u32) -> Weight {
        // Minimum execution time: 3_867 nanoseconds.
        Weight::from_ref_time(3_948_000)
            // Standard Error: 1_146
            .saturating_add(Weight::from_ref_time(966_715).saturating_mul(p.into()))
            .saturating_add(DbWeight::get().reads((1_u64).saturating_mul(p.into())))
            .saturating_add(DbWeight::get().writes((1_u64).saturating_mul(p.into())))
    }
}
