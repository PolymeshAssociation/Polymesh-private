// This file is part of the Polymesh distribution (https://github.com/PolymeshAssociation/Polymesh).
// Copyright (c) 2023 Polymesh

use frame_benchmarking::benchmarks;
use sp_std::vec::Vec;

use rand_chacha::ChaCha20Rng as Rng;
use rand_core::SeedableRng;

use polymesh_dart::{curve_tree::MultiLeafPathAndRoot, LegBuilder, SettlementBuilder};
use polymesh_dart_host_functions::{GenerateDartProofRequest, GenerateDartProofResponse};

use crate::testing::*;
use crate::*;

pub const MAX_LEGS: u32 = 10;

benchmarks! {
    where_clause { where T: Config }

    /*
    get_cached_curve_tree_parameters {
        // This benchmark is used to test the retrieval of cached curve tree parameters.
        // It does not require any specific setup.
    }: {
        let _ = Pallet::<T>::get_cached_curve_tree_parameters()
            .expect("Failed to get cached curve tree parameters");
    }
    // */

    insert_account_leaves {
        // Number of leaves to insert.
        let l in 1 .. 1000;

        let mut rng = Rng::from_seed([42u8; 32]);
        // Create an asset issuer and create an asset.
        let asset_issuer = DartUser::<T>::new("AssetIssuer");

        let keys = asset_issuer.keys();

        // Generate new account state commitments.
        let mut account_commitments = Vec::with_capacity(l as usize);
        for asset_id in 0..l {
            // Generate an initial account state for each asset.
            let account_state = keys.acct.account_state(&mut rng, asset_id, 0, &[42]).expect("Failed to create account state");
            let account_state_commitment = account_state.commitment(&keys.acct).expect("Failed to get account state commitment");
            account_commitments.push(account_state_commitment);
        }
    }: {
        // Insert the account state commitments into the account curve tree.
        for account_commitment in account_commitments {
            Pallet::<T>::insert_account_leaf(account_commitment)
                .expect("Failed to insert account leaf");
        }
    }

    commit_insert_account_leaves {
        // Number of leaves to insert.
        let l in 1 .. 1000;

        let mut rng = Rng::from_seed([42u8; 32]);
        // Create an asset issuer and create an asset.
        let asset_issuer = DartUser::<T>::new("AssetIssuer");

        let keys = asset_issuer.keys();

        // Generate new account state commitments.
        let mut account_commitments = Vec::with_capacity(l as usize);
        for asset_id in 0..l {
            // Generate an initial account state for each asset.
            let account_state = keys.acct.account_state(&mut rng, asset_id, 0, &[42]).expect("Failed to create account state");
            let account_state_commitment = account_state.commitment(&keys.acct).expect("Failed to get account state commitment");
            account_commitments.push(account_state_commitment);
        }

        // Insert the account state commitments into the account curve tree.
        for account_commitment in account_commitments {
            Pallet::<T>::insert_account_leaf(account_commitment)
                .expect("Failed to insert account leaf");
        }
    }: {
        // Get account curve tree.
        let mut account_curve_tree = Pallet::<T>::get_account_curve_tree()
            .expect("Failed to get account curve tree");

        // We need to commit the leaves to the tree to update the internal state.
        account_curve_tree.commit_leaves_to_tree()
            .expect("Account curve tree should be able to commit leaves; qed");
    }

    update_root {
        let mut rng = Rng::from_seed([42u8; 32]);
        // Create an asset issuer and create an asset.
        let asset_issuer = DartUser::<T>::new("AssetIssuer");
        let keys = asset_issuer.keys();

        // Generate new account state commitment.
        let account_state = keys.acct.account_state(&mut rng, 42, 0, &[42]).expect("Failed to create account state");
        let account_state_commitment = account_state.commitment(&keys.acct).expect("Failed to get account state commitment");
        // Insert the account state commitment into the account curve tree.
        Pallet::<T>::insert_account_leaf(account_state_commitment)
            .expect("Failed to insert account leaf");

        // Get account curve tree.
        let mut account_curve_tree = Pallet::<T>::get_account_curve_tree()
            .expect("Failed to get account curve tree");

        // We need to commit the leaves to the tree to update the internal state.
        account_curve_tree.commit_leaves_to_tree()
            .expect("Account curve tree should be able to commit leaves; qed");
     }: {
        // Get account curve tree.
        let mut account_curve_tree = Pallet::<T>::get_account_curve_tree()
            .expect("Failed to get account curve tree");

        // Store the new account curve tree root.
        account_curve_tree.store_root()
            .expect("Account curve tree should be able to store root; qed");
    }

    insert_account_leaves_and_update_root {
        // Number of leaves to insert.
        let l in 1 .. 1000;

        let mut rng = Rng::from_seed([42u8; 32]);
        // Create an asset issuer and create an asset.
        let asset_issuer = DartUser::<T>::new("AssetIssuer");

        let keys = asset_issuer.keys();

        // Generate new account state commitments.
        let mut account_commitments = Vec::with_capacity(l as usize);
        for asset_id in 0..l {
            // Generate an initial account state for each asset.
            let account_state = keys.acct.account_state(&mut rng, asset_id, 0, &[42]).expect("Failed to create account state");
            let account_state_commitment = account_state.commitment(&keys.acct).expect("Failed to get account state commitment");
            account_commitments.push(account_state_commitment);
        }
    }: {
        // Insert the account state commitments into the account curve tree.
        for account_commitment in account_commitments {
            Pallet::<T>::insert_account_leaf(account_commitment)
                .expect("Failed to insert account leaf");
        }

        // Get account curve tree.
        let mut account_curve_tree = Pallet::<T>::get_account_curve_tree()
            .expect("Failed to get account curve tree");

        // We need to commit the leaves to the tree to update the internal state.
        account_curve_tree.commit_leaves_to_tree()
            .expect("Account curve tree should be able to commit leaves; qed");

        // Store the new account curve tree root.
        account_curve_tree.store_root()
            .expect("Account curve tree should be able to store root; qed");
    }

    register_account {
        // Create user.
        let user = DartUser::<T>::new("User");
        let keys = user.public_keys();

    }: _(user.raw_origin(), keys.acct, keys.enc)

    create_asset {
        // Offchain prover state.
        let off_chain = OffchainProverState::<T>::new();

        // Create an asset issuer and create an asset.
        let asset_issuer = DartUser::<T>::new("AssetIssuer");

        // Register the asset issuer's account.
        asset_issuer.register_account();

        // Create the maximum number of auditors.
        let mut auditors = Vec::with_capacity(T::MaxAssetAuditors::get() as usize);
        let mut auditor_keys = BoundedBTreeSet::new();
        for i in 0..T::MaxAssetAuditors::get() {
            let auditor = DartUser::<T>::auditor_user("Auditor", 0, i);
            auditor.register_account();
            auditor_keys
                .try_insert(auditor.public_keys().enc)
                .expect("Failed to push auditor keys");
            auditors.push(auditor);
        }
        // Create the maximum number of mediators.
        let mut mediators = Vec::with_capacity(T::MaxAssetMediators::get() as usize);
        let mut mediator_keys = BoundedBTreeSet::new();
        for i in 0..T::MaxAssetMediators::get() {
            let mediator = DartUser::<T>::auditor_user("Mediator", 0, i);
            mediator.register_account();
            mediator_keys
                .try_insert(mediator.public_keys().enc)
                .expect("Failed to push mediator keys");
            mediators.push(mediator);
        }

        // Asset Data.
        let data = b"Test Asset"
            .to_vec()
            .try_into()
            .expect("Failed to convert asset data to AssetData");
    }: _(asset_issuer.raw_origin(), mediator_keys, auditor_keys, data)

    register_account_asset {
        // Offchain prover state.
        let mut off_chain = OffchainProverState::<T>::new();

        // Create asset issuer and an asset.
        let asset = DartTestAsset::<T>::new(&mut off_chain, "Test Asset", 0, 0, 1, None);

        // Asset issuer registers the asset.
        let (proof, _) = asset.issuer.register_account_asset_proof(asset.id);

    }: _(asset.issuer.raw_origin(), proof)

    mint_asset {
        // Offchain prover state.
        let mut off_chain = OffchainProverState::<T>::new();

        // Create asset issuer and an asset.
        let asset = DartTestAsset::<T>::new(&mut off_chain, "Test Asset", 0, 0, 1, None);

        // Asset issuer registers the asset.
        asset.issuer.register_account_asset(asset.id);

        // Update the curve tree roots.
        off_chain.apply_new_leaves();

        // Mint asset proof.
        let amount = 1000;
        let (proof, _) = asset.issuer.mint_asset_proof(&off_chain, asset.id, amount);

    }: _(asset.issuer.raw_origin(), proof)

    create_settlement {
        // Number of legs in transaction.
        let l in 1 .. MAX_LEGS;

        // Offchain prover state.
        let mut off_chain = OffchainProverState::<T>::new();

        // Venue user.
        let venue = DartUser::<T>::new("Venue");

        // Create a settlement to transfer some assets from the issuer to the investor.
        let mut settlement = SettlementBuilder::<PolymeshPrivateLimits>::new(b"Test");

        for asset_idx in 0..l {
            // Create asset issuer and an asset.
            let mut asset = DartTestAsset::<T>::new(&mut off_chain, "Test Asset", asset_idx, 0, 1, Some(1000));
            let asset_state = asset.asset_state();

            // Create investor.
            let user = asset.create_investor();

            settlement = settlement.leg(LegBuilder {
                sender: asset.issuer.public_keys(),
                receiver: user.public_keys(),
                asset: asset_state,
                amount: 500,
            })
        }

        let mut paths = Vec::new();
        for leg in &settlement.legs {
            paths.push(off_chain
                .asset_tree
                .get_path_and_root_by_index(leg.asset.asset_id as LeafIndex)
                .expect("Failed to get path to leaf"));
        }

        // Generate the settlement proof.
        let req = GenerateDartProofRequest::CreateSettlement {
            paths: MultiLeafPathAndRoot {
                paths,
            },
            settlement,
        };
        let seed = Pallet::<T>::get_seed(true);
        let proof = if let Ok(GenerateDartProofResponse::CreateSettlement { proof }) = req.generate(seed) {
            proof
        } else {
            panic!("Failed to generate create settlement proof");
        };
    }: _(venue.raw_origin(), proof)

    sender_affirmation {
        // Offchain prover state.
        let mut off_chain = OffchainProverState::<T>::new();

        // Create asset issuer and an asset.
        let mut asset = DartTestAsset::<T>::new(&mut off_chain, "Test Asset", 0, 0, 1, Some(1000));

        // Create settlement and one investor.
        let (settlement, _) =
            DartSettlementState::create_investors_and_fund(&mut asset, 1, 500, &mut off_chain);

        // Get the first leg of the settlement.
        let leg = settlement.legs[0].clone();

        // Update the curve tree roots.
        off_chain.apply_new_leaves();

        // Generate the sender's affirmation proof.
        let (proof, _) = leg.sender.sender_affirmation_proof(&off_chain, leg.leg_ref, leg.asset_id, leg.amount);
    }: _(leg.sender.raw_origin(), proof)

    receiver_affirmation {
        // Offchain prover state.
        let mut off_chain = OffchainProverState::<T>::new();

        // Create asset issuer and an asset.
        let mut asset = DartTestAsset::<T>::new(&mut off_chain, "Test Asset", 0, 0, 1, Some(1000));

        // Create settlement and one investor.
        let (settlement, _) =
            DartSettlementState::create_investors_and_fund(&mut asset, 1, 500, &mut off_chain);

        // Get the first leg of the settlement.
        let leg = settlement.legs[0].clone();

        // Update the curve tree roots.
        off_chain.apply_new_leaves();

        // Generate the receiver's affirmation proof.
        let (proof, _) = leg.receiver.receiver_affirmation_proof(&off_chain, leg.leg_ref, leg.asset_id, leg.amount);
    }: _(leg.receiver.raw_origin(), proof)

    mediator_affirmation {
        // Offchain prover state.
        let mut off_chain = OffchainProverState::<T>::new();

        // Create asset issuer and an asset.
        let mut asset = DartTestAsset::<T>::new(&mut off_chain, "Test Asset", 0, 0, 1, Some(1000));

        // Create settlement and one investor.
        let (settlement, _) =
            DartSettlementState::create_investors_and_fund(&mut asset, 1, 500, &mut off_chain);

        // Get the first leg of the settlement.
        let leg = &settlement.legs[0];
        let mediator = leg.mediators[0].clone();

        // Generate the mediator's affirmation proof.
        let proof = mediator.mediator_affirmation_proof(&off_chain, leg.leg_ref, true, Some((leg.asset_id, leg.amount)));
    }: _(mediator.raw_origin(), proof)

    receiver_claim {
        // Offchain prover state.
        let mut off_chain = OffchainProverState::<T>::new();

        // Create asset issuer and an asset.
        let mut asset = DartTestAsset::<T>::new(&mut off_chain, "Test Asset", 0, 0, 1, Some(1000));

        // Create settlement and one investor.
        let (settlement, _) =
            DartSettlementState::create_investors_and_fund(&mut asset, 1, 500, &mut off_chain);

        // Update the curve tree roots.
        off_chain.apply_new_leaves();

        // Affirm all the legs in the settlement.
        settlement.affirm_legs(&mut off_chain);

        // Get the first leg of the settlement.
        let leg = settlement.legs[0].clone();

        // Generate the receiver's claim proof.
        let (proof, _) = leg.receiver.receiver_claim_proof(&off_chain, leg.leg_ref, leg.asset_id, leg.amount);
    }: _(leg.receiver.raw_origin(), proof)

    sender_update_counter {
        // Offchain prover state.
        let mut off_chain = OffchainProverState::<T>::new();

        // Create asset issuer and an asset.
        let mut asset = DartTestAsset::<T>::new(&mut off_chain, "Test Asset", 0, 0, 1, Some(1000));

        // Create settlement and one investor.
        let (settlement, _) =
            DartSettlementState::create_investors_and_fund(&mut asset, 1, 500, &mut off_chain);

        // Update the curve tree roots.
        off_chain.apply_new_leaves();

        // Affirm all the legs in the settlement.
        settlement.affirm_legs(&mut off_chain);

        // Get the first leg of the settlement.
        let leg = settlement.legs[0].clone();

        // Update the curve tree roots.
        off_chain.apply_new_leaves();

        // Generate the sender's update counter proof.
        let (proof, _) = leg.sender.sender_counter_update_proof(&off_chain, leg.leg_ref, leg.asset_id);
    }: _(leg.sender.raw_origin(), proof)

    sender_revert {
        // Offchain prover state.
        let mut off_chain = OffchainProverState::<T>::new();

        // Create asset issuer and an asset.
        let mut asset = DartTestAsset::<T>::new(&mut off_chain, "Test Asset", 0, 0, 1, Some(1000));

        // Create settlement and one investor.
        let (settlement, _) =
            DartSettlementState::create_investors_and_fund(&mut asset, 1, 500, &mut off_chain);

        // Get the first leg of the settlement.
        let leg = settlement.legs[0].clone();

        // Update the curve tree roots.
        off_chain.apply_new_leaves();

        // Sender affirms the leg.
        leg.sender_affirmation(&mut off_chain);

        // Update the curve tree roots.
        off_chain.apply_new_leaves();

        // Mediator rejects the leg.  The settlement will go into a rejected state.
        leg.mediator_affirmation(&off_chain, false);

        // Generate the sender's revert proof.
        let (proof, _) = leg.sender.sender_revert_proof(&off_chain, leg.leg_ref, leg.asset_id, leg.amount);
    }: _(leg.sender.raw_origin(), proof)
}
