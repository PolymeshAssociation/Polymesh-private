// This file is part of the Polymesh distribution (https://github.com/PolymeshAssociation/Polymesh).
// Copyright (c) 2023 Polymesh

use frame_benchmarking::benchmarks;

use rand_chacha::ChaCha20Rng as StdRng;
use rand_core::SeedableRng;

use polymesh_dart::{AuditorOrMediator, LegBuilder, SettlementBuilder};

use crate::testing::*;
use crate::*;

pub const MAX_LEGS: u32 = 10;

benchmarks! {
    where_clause { where T: Config }

    get_cached_curve_tree_parameters {
        // This benchmark is used to test the retrieval of cached curve tree parameters.
        // It does not require any specific setup.
    }: {
        let _ = Pallet::<T>::get_cached_curve_tree_parameters()
            .expect("Failed to get cached curve tree parameters");
    }

    register_account {
        let mut rng = StdRng::from_seed([42u8; 32]);

        // Create user.
        let user = DartUser::<T>::new("User", &mut rng);
        let keys = user.public_keys();

    }: _(user.raw_origin(), keys.acct, keys.enc)

    create_asset {
        let mut rng = StdRng::from_seed([42u8; 32]);

        // Offchain prover state.
        let off_chain = OffchainProverState::<T>::new();

        // Create an asset issuer and create an asset.
        let asset_issuer = DartUser::<T>::new("AssetIssuer", &mut rng);

        // Register the asset issuer's account.
        asset_issuer.register_account();

        // Create mediator user and keys.
        let mediator = DartUser::<T>::auditor_user("Mediator", 0, 0, &mut rng);
        let auditor_or_mediator = AuditorOrMediator::Mediator(mediator.public_keys());

        // Register the mediator's keys.
        mediator.register_account();

        // Asset Data.
        let data = b"Test Asset"
            .to_vec()
            .try_into()
            .expect("Failed to convert asset data to AssetData");
    }: _(asset_issuer.raw_origin(), auditor_or_mediator, data)

    register_account_asset {
        let mut rng = StdRng::from_seed([42u8; 32]);

        // Offchain prover state.
        let mut off_chain = OffchainProverState::<T>::new();

        // Create asset issuer and an asset.
        let asset = DartTestAsset::<T>::new(&mut rng, &mut off_chain, "Test Asset", 0, 0, 1, None);

        // Asset issuer registers the asset.
        let (proof, _) = asset.issuer.register_account_asset_proof(&mut rng, asset.id);

    }: _(asset.issuer.raw_origin(), proof)

    mint_asset {
        let mut rng = StdRng::from_seed([42u8; 32]);

        // Offchain prover state.
        let mut off_chain = OffchainProverState::<T>::new();

        // Create asset issuer and an asset.
        let asset = DartTestAsset::<T>::new(&mut rng, &mut off_chain, "Test Asset", 0, 0, 1, None);

        // Asset issuer registers the asset.
        asset.issuer.register_account_asset(&mut rng, asset.id);

        // Update the curve tree roots.
        off_chain.apply_new_leaves();

        // Mint asset proof.
        let amount = 1000;
        let (proof, _) = asset.issuer.mint_asset_proof(&mut rng, &off_chain, asset.id, amount);

    }: _(asset.issuer.raw_origin(), proof)

    create_settlement {
        // Number of legs in transaction.
        let l in 1 .. MAX_LEGS;

        let mut rng = StdRng::from_seed([42u8; 32]);

        // Offchain prover state.
        let mut off_chain = OffchainProverState::<T>::new();

        // Venue user.
        let venue = DartUser::<T>::new("Venue", &mut rng);

        // Create a settlement to transfer some assets from the issuer to the investor.
        let mut settlement = SettlementBuilder::<T>::new(b"Test");

        for asset_idx in 0..l {
            // Create asset issuer and an asset.
            let mut asset = DartTestAsset::<T>::new(&mut rng, &mut off_chain, "Test Asset", asset_idx, 0, 1, Some(1000));

            // Create investor.
            let user = asset.create_investor(&mut rng);

            settlement = settlement.leg(LegBuilder {
                sender: asset.issuer.public_keys(),
                receiver: user.public_keys(),
                asset_id: asset.id,
                amount: 500,
                mediator: asset.auditor_or_mediator,
            })
        }

        // Generate the settlement proof.
        let proof = settlement.encryt_and_prove(&mut rng, &off_chain.asset_tree)
            .expect("Failed to create settlement");
    }: _(venue.raw_origin(), proof)

    sender_affirmation {
        let mut rng = StdRng::from_seed([42u8; 32]);

        // Offchain prover state.
        let mut off_chain = OffchainProverState::<T>::new();

        // Create asset issuer and an asset.
        let mut asset = DartTestAsset::<T>::new(&mut rng, &mut off_chain, "Test Asset", 0, 0, 1, Some(1000));

        // Create settlement and one investor.
        let (settlement, _) =
            DartSettlementState::create_investors_and_fund(&mut rng, &mut asset, 1, 500, &mut off_chain);

        let leg = settlement.legs[0].clone();

        // Generate the sender's affirmation proof.
        let (proof, _) = leg.sender.sender_affirmation_proof(&mut rng, &off_chain, leg.leg_ref, leg.asset_id, leg.amount);
    }: _(leg.sender.raw_origin(), proof)

    receiver_affirmation {
        let mut rng = StdRng::from_seed([42u8; 32]);

        // Offchain prover state.
        let mut off_chain = OffchainProverState::<T>::new();

        // Create asset issuer and an asset.
        let mut asset = DartTestAsset::<T>::new(&mut rng, &mut off_chain, "Test Asset", 0, 0, 1, Some(1000));

        // Create settlement and one investor.
        let (settlement, _) =
            DartSettlementState::create_investors_and_fund(&mut rng, &mut asset, 1, 500, &mut off_chain);

        let leg = settlement.legs[0].clone();

        // Generate the receiver's affirmation proof.
        let (proof, _) = leg.receiver.receiver_affirmation_proof(&mut rng, &off_chain, leg.leg_ref, leg.asset_id, leg.amount);
    }: _(leg.receiver.raw_origin(), proof)

    mediator_affirmation {
        let mut rng = StdRng::from_seed([42u8; 32]);

        // Offchain prover state.
        let mut off_chain = OffchainProverState::<T>::new();

        // Create asset issuer and an asset.
        let mut asset = DartTestAsset::<T>::new(&mut rng, &mut off_chain, "Test Asset", 0, 0, 1, Some(1000));

        // Create settlement and one investor.
        let (settlement, _) =
            DartSettlementState::create_investors_and_fund(&mut rng, &mut asset, 1, 500, &mut off_chain);

        let leg = &settlement.legs[0];
        let mediator = leg.mediator.as_ref().expect("Mediator should be present in the leg").clone();

        // Generate the mediator's affirmation proof.
        let proof = mediator.mediator_affirmation_proof(&mut rng, &off_chain, leg.leg_ref, true, Some((leg.asset_id, leg.amount)));
    }: _(mediator.raw_origin(), proof)

    receiver_claim {
        let mut rng = StdRng::from_seed([42u8; 32]);

        // Offchain prover state.
        let mut off_chain = OffchainProverState::<T>::new();

        // Create asset issuer and an asset.
        let mut asset = DartTestAsset::<T>::new(&mut rng, &mut off_chain, "Test Asset", 0, 0, 1, Some(1000));

        // Create settlement and one investor.
        let (settlement, _) =
            DartSettlementState::create_investors_and_fund(&mut rng, &mut asset, 1, 500, &mut off_chain);

        let leg = settlement.legs[0].clone();

        // Generate the receiver's claim proof.
        let (proof, _) = leg.receiver.receiver_claim_proof(&mut rng, &off_chain, leg.leg_ref);
    }: _(leg.receiver.raw_origin(), proof)
}
