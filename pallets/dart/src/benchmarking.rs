// This file is part of the Polymesh distribution (https://github.com/PolymeshAssociation/Polymesh).
// Copyright (c) 2023 Polymesh

use frame_benchmarking::benchmarks;
use frame_support::assert_ok;

use rand_chacha::ChaCha20Rng as StdRng;
use rand_core::SeedableRng;

use pallet_identity::benchmarking::user;

use polymesh_dart::AccountKeys;

use crate::*;

benchmarks! {
    where_clause { where T: Config }

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
}
