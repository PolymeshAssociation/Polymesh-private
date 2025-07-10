// This file is part of the Polymesh distribution (https://github.com/PolymeshAssociation/Polymesh).
// Copyright (c) 2023 Polymesh

use frame_benchmarking::benchmarks;
use frame_support::assert_ok;

use rand_chacha::ChaCha20Rng as StdRng;
use rand_core::SeedableRng;

use pallet_identity::benchmarking::user;

use polymesh_dart::{
    curve_tree::ProverCurveTree, AccountKeys, AuditorOrMediator, LegBuilder, PallasParameters,
    SettlementBuilder, VestaParameters, ACCOUNT_TREE_GENS, ASSET_TREE_GENS,
};

use crate::*;

pub type AccountProverCurveTree<T> = ProverCurveTree<
    ACCOUNT_TREE_L,
    PallasParameters,
    VestaParameters,
    AccountCurveTreeStorage<T>,
    Error<T>,
>;

fn get_prover_account_curve_tree<T: Config>() -> AccountProverCurveTree<T> {
    AccountProverCurveTree::new(ACCOUNT_TREE_HEIGHT, ACCOUNT_TREE_GENS)
        .expect("Failed to create prover curve tree")
}

pub type AssetProverCurveTree<T> = ProverCurveTree<
    ASSET_TREE_L,
    PallasParameters,
    VestaParameters,
    AssetCurveTreeStorage<T>,
    Error<T>,
>;

fn get_prover_asset_curve_tree<T: Config>() -> AssetProverCurveTree<T> {
    AssetProverCurveTree::new(ASSET_TREE_HEIGHT, ASSET_TREE_GENS)
        .expect("Failed to create prover curve tree")
}

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

        let user = user::<T>("register_account", 0);
        let keys = AccountKeys::rand(&mut rng).expect("Failed to generate random keys");
    }: _(user.origin(), keys.acct.public, keys.enc.public)

    create_asset {
        let mut rng = StdRng::from_seed([42u8; 32]);

        let asset_issuer = user::<T>("create_asset", 0);

        // Generate random keys for the asset mediator.
        let mediator_keys = AccountKeys::rand(&mut rng).expect("Failed to generate random keys");
        let auditor_or_mediator = AuditorOrMediator::Mediator(mediator_keys.public_keys());

        // Register the mediator's keys.
        assert_ok!(Pallet::<T>::register_account(
            asset_issuer.origin().into(),
            mediator_keys.acct.public,
            mediator_keys.enc.public
        ));

        // Asset Data.
        let data = b"Test Asset".to_vec().try_into().expect("Failed to convert asset data to AssetData");
    }: _(asset_issuer.origin(), auditor_or_mediator, data)

    register_account_asset {
        let mut rng = StdRng::from_seed([42u8; 32]);

        // Create an asset issuer and create an asset.
        let asset_issuer = user::<T>("AssetIssuer", 0);

        // Generate random keys for the asset mediator.
        let mediator_keys = AccountKeys::rand(&mut rng).expect("Failed to generate random keys");
        let auditor_or_mediator = AuditorOrMediator::Mediator(mediator_keys.public_keys());

        // Register the mediator's keys.
        assert_ok!(Pallet::<T>::register_account(
            asset_issuer.origin().into(),
            mediator_keys.acct.public,
            mediator_keys.enc.public
        ));

        // Asset Data.
        let data = b"Test Asset".to_vec().try_into().expect("Failed to convert asset data to AssetData");

        // Create the asset.
        let asset_id = Pallet::<T>::base_create_asset(
            asset_issuer.did(),
            auditor_or_mediator,
            data
        ).expect("Failed to create asset");

        let user = user::<T>("register_account_asset", 0);
        let user_did = user.did();
        let keys = AccountKeys::rand(&mut rng).expect("Failed to generate random keys");

        // Register the account.
        assert_ok!(Pallet::<T>::register_account(
            user.origin().into(),
            keys.acct.public,
            keys.enc.public
        ));

        // Account asset registration proof.
        let (proof, _) = polymesh_dart::AccountAssetRegistrationProof::new(&mut rng, &keys, asset_id, &user_did.0[..])
            .expect("Failed to generate account asset registration proof");
    }: _(user.origin(), proof)

    mint_asset {
        let mut rng = StdRng::from_seed([42u8; 32]);

        // Create an asset issuer and create an asset.
        let asset_issuer = user::<T>("AssetIssuer", 0);
        let issuer_did = asset_issuer.did();

        // Generate random keys for the asset mediator.
        let mediator_keys = AccountKeys::rand(&mut rng).expect("Failed to generate random keys");
        let auditor_or_mediator = AuditorOrMediator::Mediator(mediator_keys.public_keys());

        // Register the mediator's keys.
        assert_ok!(Pallet::<T>::register_account(
            asset_issuer.origin().into(),
            mediator_keys.acct.public,
            mediator_keys.enc.public
        ));

        // Asset Data.
        let data = b"Test Asset".to_vec().try_into().expect("Failed to convert asset data to AssetData");

        // Create the asset.
        let asset_id = Pallet::<T>::base_create_asset(
            asset_issuer.did(),
            auditor_or_mediator,
            data
        ).expect("Failed to create asset");

        let keys = AccountKeys::rand(&mut rng).expect("Failed to generate random keys");

        // Register the account.
        assert_ok!(Pallet::<T>::register_account(
            asset_issuer.origin().into(),
            keys.acct.public,
            keys.enc.public
        ));

        // Account asset registration proof.
        let (proof, mut account_state) = polymesh_dart::AccountAssetRegistrationProof::new(&mut rng, &keys, asset_id, &issuer_did.0[..])
            .expect("Failed to generate account asset registration proof");

        // Register the account asset.
        assert_ok!(Pallet::<T>::register_account_asset(
            asset_issuer.origin().into(),
            proof
        ));

        // Commit pending changes to the account state.
        account_state.commit_pending_state()
            .expect("Failed to commit pending state");

        // Update the curve tree roots.
        Pallet::<T>::update_curve_tree_roots();

        // Get the account tree.
        let mut account_tree = get_prover_account_curve_tree::<T>();
        account_tree.apply_new_leaves();

        // Mint asset proof.
        let amount = 1000u128;
        let mint_proof = polymesh_dart::AssetMintingProof::new(&mut rng, &mut account_state, &account_tree, amount as _)
            .expect("Failed to generate mint asset proof");

    }: _(asset_issuer.origin(), mint_proof)

    create_settlement {
        let mut rng = StdRng::from_seed([42u8; 32]);

        // Create an asset issuer and create an asset.
        let asset_issuer = user::<T>("AssetIssuer", 0);
        let issuer_did = asset_issuer.did();

        // Generate random keys for the asset mediator.
        let mediator_keys = AccountKeys::rand(&mut rng).expect("Failed to generate random keys");
        let auditor_or_mediator = AuditorOrMediator::Mediator(mediator_keys.public_keys());

        // Register the mediator's keys.
        assert_ok!(Pallet::<T>::register_account(
            asset_issuer.origin().into(),
            mediator_keys.acct.public,
            mediator_keys.enc.public
        ));

        // Asset Data.
        let data = b"Test Asset".to_vec().try_into().expect("Failed to convert asset data to AssetData");

        // Create the asset.
        let asset_id = Pallet::<T>::base_create_asset(
            asset_issuer.did(),
            auditor_or_mediator,
            data
        ).expect("Failed to create asset");

        // Get the asset tree.
        let mut asset_tree = get_prover_asset_curve_tree::<T>();
        asset_tree.apply_new_leaves();

        let issuer_keys = AccountKeys::rand(&mut rng).expect("Failed to generate random keys");

        // Register the account.
        assert_ok!(Pallet::<T>::register_account(
            asset_issuer.origin().into(),
            issuer_keys.acct.public,
            issuer_keys.enc.public
        ));

        // Account asset registration proof.
        let (proof, mut issuer_account_state) = polymesh_dart::AccountAssetRegistrationProof::new(&mut rng, &issuer_keys, asset_id, &issuer_did.0[..])
            .expect("Failed to generate account asset registration proof");

        // Register the account asset.
        assert_ok!(Pallet::<T>::register_account_asset(
            asset_issuer.origin().into(),
            proof
        ));

        // Commit pending changes to the account state.
        issuer_account_state.commit_pending_state()
            .expect("Failed to commit pending state");

        let user = user::<T>("register_account_asset", 0);
        let user_did = user.did();
        let user_keys = AccountKeys::rand(&mut rng).expect("Failed to generate random keys");

        // Register the account.
        assert_ok!(Pallet::<T>::register_account(
            user.origin().into(),
            user_keys.acct.public,
            user_keys.enc.public
        ));

        // Account asset registration proof.
        let (proof, user_account_state) = polymesh_dart::AccountAssetRegistrationProof::new(&mut rng, &user_keys, asset_id, &user_did.0[..])
            .expect("Failed to generate account asset registration proof");

        // Register the account asset.
        assert_ok!(Pallet::<T>::register_account_asset(
            user.origin().into(),
            proof
        ));

        // Update the curve tree roots.
        Pallet::<T>::update_curve_tree_roots();

        // Get the account tree.
        let mut account_tree = get_prover_account_curve_tree::<T>();
        account_tree.apply_new_leaves();

        // Mint asset proof.
        let amount = 1000u128;
        let mint_proof = polymesh_dart::AssetMintingProof::new(&mut rng, &mut issuer_account_state, &account_tree, amount as _)
            .expect("Failed to generate mint asset proof");

        // Submit minting proof.
        assert_ok!(Pallet::<T>::mint_asset(
            asset_issuer.origin().into(),
            mint_proof
        ));

        // Update the curve tree roots.
        Pallet::<T>::update_curve_tree_roots();
        account_tree.apply_new_leaves();

        // Create a settlement to transfer some assets from the issuer to the investor.
        let settlement = SettlementBuilder::new(b"Test")
            .leg(LegBuilder {
                sender: issuer_keys.public_keys(),
                receiver: user_keys.public_keys(),
                asset_id,
                amount: 500,
                mediator: auditor_or_mediator,
            })
            .encryt_and_prove(&mut rng, &asset_tree)
            .expect("Failed to create settlement");

    }: _(asset_issuer.origin(), settlement)
}
