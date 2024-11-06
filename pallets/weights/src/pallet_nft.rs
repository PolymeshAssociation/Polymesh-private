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

//! Autogenerated weights for pallet_nft
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 4.0.0-dev
//! DATE: 2024-11-05, STEPS: `100`, REPEAT: 5, LOW RANGE: `[]`, HIGH RANGE: `[]`
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

/// Weights for pallet_nft using the Substrate node and recommended hardware.
pub struct SubstrateWeight;
impl pallet_nft::WeightInfo for SubstrateWeight {
    // Storage: Identity KeyRecords (r:1 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: System BlockHash (r:1 w:0)
    // Proof: System BlockHash (max_values: None, max_size: Some(44), added: 2519, mode: MaxEncodedLen)
    // Storage: Asset AssetNonce (r:1 w:1)
    // Proof Skipped: Asset AssetNonce (max_values: None, max_size: None, mode: Measured)
    // Storage: NFT CollectionAsset (r:1 w:1)
    // Proof Skipped: NFT CollectionAsset (max_values: None, max_size: None, mode: Measured)
    // Storage: Asset AssetMetadataGlobalKeyToName (r:255 w:0)
    // Proof Skipped: Asset AssetMetadataGlobalKeyToName (max_values: None, max_size: None, mode: Measured)
    // Storage: Asset Assets (r:1 w:1)
    // Proof Skipped: Asset Assets (max_values: None, max_size: None, mode: Measured)
    // Storage: Portfolio PortfolioCustodian (r:1 w:0)
    // Proof Skipped: Portfolio PortfolioCustodian (max_values: None, max_size: None, mode: Measured)
    // Storage: ProtocolFee Coefficient (r:1 w:0)
    // Proof Skipped: ProtocolFee Coefficient (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: ProtocolFee BaseFees (r:1 w:0)
    // Proof Skipped: ProtocolFee BaseFees (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity CurrentPayer (r:1 w:0)
    // Proof Skipped: Identity CurrentPayer (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: ExternalAgents NumFullAgents (r:1 w:1)
    // Proof Skipped: ExternalAgents NumFullAgents (max_values: None, max_size: None, mode: Measured)
    // Storage: NFT CurrentCollectionId (r:1 w:1)
    // Proof Skipped: NFT CurrentCollectionId (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: NFT Collection (r:0 w:1)
    // Proof Skipped: NFT Collection (max_values: None, max_size: None, mode: Measured)
    // Storage: NFT CollectionKeys (r:0 w:1)
    // Proof Skipped: NFT CollectionKeys (max_values: None, max_size: None, mode: Measured)
    // Storage: Asset AssetNames (r:0 w:1)
    // Proof Skipped: Asset AssetNames (max_values: None, max_size: None, mode: Measured)
    // Storage: Asset SecurityTokensOwnedByUser (r:0 w:1)
    // Proof Skipped: Asset SecurityTokensOwnedByUser (max_values: None, max_size: None, mode: Measured)
    // Storage: Asset AssetIdentifiers (r:0 w:1)
    // Proof Skipped: Asset AssetIdentifiers (max_values: None, max_size: None, mode: Measured)
    // Storage: ExternalAgents AgentOf (r:0 w:1)
    // Proof Skipped: ExternalAgents AgentOf (max_values: None, max_size: None, mode: Measured)
    // Storage: ExternalAgents GroupOfAgent (r:0 w:1)
    // Proof Skipped: ExternalAgents GroupOfAgent (max_values: None, max_size: None, mode: Measured)
    /// The range of component `n` is `[1, 255]`.
    fn create_nft_collection(n: u32) -> Weight {
        // Minimum execution time: 73_758 nanoseconds.
        Weight::from_ref_time(77_674_397)
            // Standard Error: 21_046
            .saturating_add(Weight::from_ref_time(1_875_083).saturating_mul(n.into()))
            .saturating_add(DbWeight::get().reads(11))
            .saturating_add(DbWeight::get().reads((1_u64).saturating_mul(n.into())))
            .saturating_add(DbWeight::get().writes(12))
    }
    // Storage: NFT CollectionAsset (r:1 w:0)
    // Proof Skipped: NFT CollectionAsset (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity KeyRecords (r:1 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: ExternalAgents GroupOfAgent (r:1 w:0)
    // Proof Skipped: ExternalAgents GroupOfAgent (max_values: None, max_size: None, mode: Measured)
    // Storage: Permissions CurrentPalletName (r:1 w:0)
    // Proof Skipped: Permissions CurrentPalletName (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Permissions CurrentDispatchableName (r:1 w:0)
    // Proof Skipped: Permissions CurrentDispatchableName (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: NFT CollectionKeys (r:1 w:0)
    // Proof Skipped: NFT CollectionKeys (max_values: None, max_size: None, mode: Measured)
    // Storage: NFT NFTsInCollection (r:1 w:1)
    // Proof Skipped: NFT NFTsInCollection (max_values: None, max_size: None, mode: Measured)
    // Storage: NFT NumberOfNFTs (r:1 w:1)
    // Proof Skipped: NFT NumberOfNFTs (max_values: None, max_size: None, mode: Measured)
    // Storage: NFT CurrentNFTId (r:1 w:1)
    // Proof Skipped: NFT CurrentNFTId (max_values: None, max_size: None, mode: Measured)
    // Storage: Portfolio PortfolioNFT (r:0 w:1)
    // Proof Skipped: Portfolio PortfolioNFT (max_values: None, max_size: None, mode: Measured)
    // Storage: NFT MetadataValue (r:0 w:255)
    // Proof Skipped: NFT MetadataValue (max_values: None, max_size: None, mode: Measured)
    // Storage: NFT NFTOwner (r:0 w:1)
    // Proof Skipped: NFT NFTOwner (max_values: None, max_size: None, mode: Measured)
    /// The range of component `n` is `[1, 255]`.
    fn issue_nft(n: u32) -> Weight {
        // Minimum execution time: 43_862 nanoseconds.
        Weight::from_ref_time(50_117_962)
            // Standard Error: 21_712
            .saturating_add(Weight::from_ref_time(2_288_617).saturating_mul(n.into()))
            .saturating_add(DbWeight::get().reads(9))
            .saturating_add(DbWeight::get().writes(5))
            .saturating_add(DbWeight::get().writes((1_u64).saturating_mul(n.into())))
    }
    // Storage: NFT CollectionAsset (r:1 w:0)
    // Proof Skipped: NFT CollectionAsset (max_values: None, max_size: None, mode: Measured)
    // Storage: Identity KeyRecords (r:1 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: ExternalAgents GroupOfAgent (r:1 w:0)
    // Proof Skipped: ExternalAgents GroupOfAgent (max_values: None, max_size: None, mode: Measured)
    // Storage: Permissions CurrentPalletName (r:1 w:0)
    // Proof Skipped: Permissions CurrentPalletName (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Permissions CurrentDispatchableName (r:1 w:0)
    // Proof Skipped: Permissions CurrentDispatchableName (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Portfolio PortfolioCustodian (r:1 w:0)
    // Proof Skipped: Portfolio PortfolioCustodian (max_values: None, max_size: None, mode: Measured)
    // Storage: Portfolio PortfolioNFT (r:1 w:1)
    // Proof Skipped: Portfolio PortfolioNFT (max_values: None, max_size: None, mode: Measured)
    // Storage: Portfolio PortfolioLockedNFT (r:1 w:0)
    // Proof Skipped: Portfolio PortfolioLockedNFT (max_values: None, max_size: None, mode: Measured)
    // Storage: NFT NFTsInCollection (r:1 w:1)
    // Proof Skipped: NFT NFTsInCollection (max_values: None, max_size: None, mode: Measured)
    // Storage: NFT NumberOfNFTs (r:1 w:1)
    // Proof Skipped: NFT NumberOfNFTs (max_values: None, max_size: None, mode: Measured)
    // Storage: NFT MetadataValue (r:256 w:255)
    // Proof Skipped: NFT MetadataValue (max_values: None, max_size: None, mode: Measured)
    // Storage: NFT NFTOwner (r:1 w:1)
    // Proof Skipped: NFT NFTOwner (max_values: None, max_size: None, mode: Measured)
    /// The range of component `n` is `[1, 255]`.
    fn redeem_nft(n: u32) -> Weight {
        // Minimum execution time: 55_104 nanoseconds.
        Weight::from_ref_time(53_110_584)
            // Standard Error: 12_109
            .saturating_add(Weight::from_ref_time(3_374_734).saturating_mul(n.into()))
            .saturating_add(DbWeight::get().reads(12))
            .saturating_add(DbWeight::get().reads((1_u64).saturating_mul(n.into())))
            .saturating_add(DbWeight::get().writes(4))
            .saturating_add(DbWeight::get().writes((1_u64).saturating_mul(n.into())))
    }
    // Storage: NFT CollectionAsset (r:1 w:0)
    // Proof Skipped: NFT CollectionAsset (max_values: None, max_size: None, mode: Measured)
    // Storage: NFT NumberOfNFTs (r:2 w:2)
    // Proof Skipped: NFT NumberOfNFTs (max_values: None, max_size: None, mode: Measured)
    // Storage: Portfolio PortfolioNFT (r:10 w:20)
    // Proof Skipped: Portfolio PortfolioNFT (max_values: None, max_size: None, mode: Measured)
    // Storage: Portfolio PortfolioLockedNFT (r:10 w:0)
    // Proof Skipped: Portfolio PortfolioLockedNFT (max_values: None, max_size: None, mode: Measured)
    // Storage: Asset Frozen (r:1 w:0)
    // Proof Skipped: Asset Frozen (max_values: None, max_size: None, mode: Measured)
    // Storage: Timestamp Now (r:1 w:0)
    // Proof: Timestamp Now (max_values: Some(1), max_size: Some(8), added: 503, mode: MaxEncodedLen)
    // Storage: Instance2Group ActiveMembers (r:1 w:0)
    // Proof Skipped: Instance2Group ActiveMembers (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Identity Claims (r:4 w:0)
    // Proof Skipped: Identity Claims (max_values: None, max_size: None, mode: Measured)
    // Storage: ComplianceManager AssetCompliances (r:1 w:0)
    // Proof Skipped: ComplianceManager AssetCompliances (max_values: None, max_size: None, mode: Measured)
    // Storage: NFT NFTOwner (r:0 w:10)
    // Proof Skipped: NFT NFTOwner (max_values: None, max_size: None, mode: Measured)
    /// The range of component `n` is `[1, 10]`.
    fn base_nft_transfer(n: u32) -> Weight {
        // Minimum execution time: 92_344 nanoseconds.
        Weight::from_ref_time(84_955_011)
            // Standard Error: 36_990
            .saturating_add(Weight::from_ref_time(9_631_700).saturating_mul(n.into()))
            .saturating_add(DbWeight::get().reads(11))
            .saturating_add(DbWeight::get().reads((2_u64).saturating_mul(n.into())))
            .saturating_add(DbWeight::get().writes(2))
            .saturating_add(DbWeight::get().writes((3_u64).saturating_mul(n.into())))
    }
    // Storage: Identity KeyRecords (r:1 w:0)
    // Proof Skipped: Identity KeyRecords (max_values: None, max_size: None, mode: Measured)
    // Storage: ExternalAgents GroupOfAgent (r:1 w:0)
    // Proof Skipped: ExternalAgents GroupOfAgent (max_values: None, max_size: None, mode: Measured)
    // Storage: Permissions CurrentPalletName (r:1 w:0)
    // Proof Skipped: Permissions CurrentPalletName (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Permissions CurrentDispatchableName (r:1 w:0)
    // Proof Skipped: Permissions CurrentDispatchableName (max_values: Some(1), max_size: None, mode: Measured)
    // Storage: Portfolio Portfolios (r:1 w:0)
    // Proof Skipped: Portfolio Portfolios (max_values: None, max_size: None, mode: Measured)
    // Storage: Portfolio PortfolioCustodian (r:1 w:0)
    // Proof Skipped: Portfolio PortfolioCustodian (max_values: None, max_size: None, mode: Measured)
    // Storage: NFT CollectionAsset (r:1 w:0)
    // Proof Skipped: NFT CollectionAsset (max_values: None, max_size: None, mode: Measured)
    // Storage: NFT NumberOfNFTs (r:2 w:2)
    // Proof Skipped: NFT NumberOfNFTs (max_values: None, max_size: None, mode: Measured)
    // Storage: Portfolio PortfolioNFT (r:10 w:20)
    // Proof Skipped: Portfolio PortfolioNFT (max_values: None, max_size: None, mode: Measured)
    // Storage: Portfolio PortfolioLockedNFT (r:10 w:0)
    // Proof Skipped: Portfolio PortfolioLockedNFT (max_values: None, max_size: None, mode: Measured)
    // Storage: NFT NFTOwner (r:0 w:10)
    // Proof Skipped: NFT NFTOwner (max_values: None, max_size: None, mode: Measured)
    /// The range of component `n` is `[1, 10]`.
    fn controller_transfer(n: u32) -> Weight {
        // Minimum execution time: 52_729 nanoseconds.
        Weight::from_ref_time(45_744_388)
            // Standard Error: 34_346
            .saturating_add(Weight::from_ref_time(9_703_248).saturating_mul(n.into()))
            .saturating_add(DbWeight::get().reads(9))
            .saturating_add(DbWeight::get().reads((2_u64).saturating_mul(n.into())))
            .saturating_add(DbWeight::get().writes(2))
            .saturating_add(DbWeight::get().writes((3_u64).saturating_mul(n.into())))
    }
}
