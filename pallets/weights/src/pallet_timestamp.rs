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

//! Autogenerated weights for pallet_timestamp
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

/// Weights for pallet_timestamp using the Substrate node and recommended hardware.
pub struct SubstrateWeight;
impl pallet_timestamp::WeightInfo for SubstrateWeight {
    // Storage: Timestamp Now (r:1 w:1)
    // Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
    // Storage: Babe CurrentSlot (r:1 w:0)
    // Proof: Babe CurrentSlot (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
    fn set() -> Weight {
        // Minimum execution time: 10_740 nanoseconds.
        Weight::from_ref_time(11_902_000)
            .saturating_add(DbWeight::get().reads(2))
            .saturating_add(DbWeight::get().writes(1))
    }
    fn on_finalize() -> Weight {
        // Minimum execution time: 4_870 nanoseconds.
        Weight::from_ref_time(5_050_000)
    }
}
