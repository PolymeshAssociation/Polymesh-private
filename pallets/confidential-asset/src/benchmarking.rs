// This file is part of the Polymesh distribution (https://github.com/PolymeshAssociation/Polymesh).
// Copyright (c) 2023 Polymesh

use frame_benchmarking::benchmarks;
use frame_support::assert_ok;

use rand_chacha::ChaCha20Rng as StdRng;
use rand_core::SeedableRng;

use confidential_assets::Balance as ConfidentialBalance;

use polymesh_common_utilities::{
    benchs::{user, AccountIdOf},
    traits::TestUtilsFn,
};

use crate::testing::*;
use crate::*;

pub const MAX_LEGS: u32 = 100;
pub const MAX_MEDIATORS: u32 = MAX_LEGS * 8;

benchmarks! {
    where_clause { where T: Config, T: TestUtilsFn<AccountIdOf<T>> }

    create_account {
        let mut rng = StdRng::from_seed([10u8; 32]);
        let user = ConfidentialUser::<T>::new("user", &mut rng);
    }: _(user.raw_origin(), user.account())

    create_confidential_asset {
        let mut rng = StdRng::from_seed([10u8; 32]);
        let ticker = Ticker::from_slice_truncated(b"A".as_ref());
        let issuer = user::<T>("issuer", SEED);
        let auditors = AuditorState::<T>::new(0, &mut rng).get_asset_auditors();
    }: _(issuer.origin(), Some(ticker), Default::default(), auditors)

    mint_confidential_asset {
        let mut rng = StdRng::from_seed([10u8; 32]);
        let (asset_id, issuer, _) = create_confidential_token::<T>("A", &mut rng);
        issuer.create_account();

        let total_supply = 4_000_000_000 as ConfidentialBalance;
    }: _(issuer.raw_origin(), asset_id, total_supply.into(), issuer.account())

    set_asset_frozen {
        let mut rng = StdRng::from_seed([10u8; 32]);
        let (asset_id, issuer, _) = create_confidential_token::<T>("A", &mut rng);
    }: _(issuer.raw_origin(), asset_id, true)

    set_account_asset_frozen {
        let mut rng = StdRng::from_seed([10u8; 32]);
        let (asset_id, issuer, _) = create_confidential_token::<T>("A", &mut rng);
        let user = ConfidentialUser::<T>::new("user", &mut rng);
    }: _(issuer.raw_origin(), user.account(), asset_id, true)

    apply_incoming_balance {
        let mut rng = StdRng::from_seed([10u8; 32]);

        // Setup for transaction.
        let mut tx = TransactionState::<T>::new(&mut rng);
        tx.add_transaction();
        tx.affirm_legs(&mut rng);
        tx.execute();
        let leg = tx.leg(0);
    }: _(leg.investor.raw_origin(), leg.investor.account(), leg.asset_id)

    apply_incoming_balances {
        // Number of balances to update.
        let b in 0 .. 200;

        let mut rng = StdRng::from_seed([10u8; 32]);
        let user = ConfidentialUser::<T>::new("user", &mut rng);
        user.create_account();

        // Generate a lot of incoming balances.
        let key = user.pub_key();
        let (_, balance) = key.encrypt_value(1000u64.into(), &mut rng);
        let (_, incoming) = key.encrypt_value(100u64.into(), &mut rng);
        for idx in 0..300 {
          let asset_id = gen_asset_id(idx as _);
          user.set_balance(asset_id, balance);
          user.set_incoming_balance(asset_id, incoming);
        }
    }: _(user.raw_origin(), user.account(), b as u16)

    create_venue {
        let issuer = user::<T>("issuer", SEED);
    }: _(issuer.origin())

    set_venue_filtering {
        let mut rng = StdRng::from_seed([10u8; 32]);
        let (asset_id, issuer, _) = create_confidential_token::<T>("A", &mut rng);
    }: _(issuer.raw_origin(), asset_id, true)

    allow_venues {
        // Count of venues.
        let v in 0 .. 100;

        let mut rng = StdRng::from_seed([10u8; 32]);
        let (asset_id, issuer, _) = create_confidential_token::<T>("A", &mut rng);
        let mut venues = Vec::new();
        for i in 0 .. v {
            venues.push(VenueId(i.into()));
        }
        let s_venues = venues.clone();
    }: _(issuer.raw_origin(), asset_id, s_venues)
    verify {
        for v in venues.iter() {
            assert!(Pallet::<T>::venue_allow_list(asset_id, v), "Fail: allow_venue dispatch");
        }
    }

    disallow_venues {
        // Count of venues.
        let v in 0 .. 100;

        let mut rng = StdRng::from_seed([10u8; 32]);
        let (asset_id, issuer, _) = create_confidential_token::<T>("A", &mut rng);
        let mut venues = Vec::new();
        for i in 0 .. v {
            venues.push(VenueId(i.into()));
        }
        assert_ok!(Pallet::<T>::allow_venues(
            issuer.origin(),
            asset_id,
            venues.clone(),
        ));
        let s_venues = venues.clone();
    }: _(issuer.raw_origin(), asset_id, s_venues)
    verify {
        for v in venues.iter() {
            assert!(!Pallet::<T>::venue_allow_list(asset_id, v), "Fail: allow_venue dispatch");
        }
    }

    add_transaction {
        // Number of legs in transaction.
        let l in 1 .. MAX_LEGS;
        // Total number of mediators across all legs.
        let m in 0 .. MAX_MEDIATORS;

        // Always use the maximum number of auditors per leg.
        let a_count = l * (T::MaxVenueAuditors::get() + T::MaxAssetAuditors::get());

        let mut rng = StdRng::from_seed([10u8; 32]);

        // Setup for transaction.
        let tx = TransactionState::<T>::new_legs_full(l, a_count, m, &mut rng);

        let legs = tx.get_legs();
    }: _(tx.custodian.raw_origin(), tx.venue_id, legs, Some(Memo([7u8; 32])))

    sender_affirm_transaction {
        // Number of auditors in the sender proof.
        let a in 0 .. (T::MaxVenueAuditors::get() + T::MaxAssetAuditors::get());

        let mut rng = StdRng::from_seed([10u8; 32]);

        // Setup for transaction.
        let mut tx = TransactionState::<T>::new_legs_full(1, a, a, &mut rng);
        tx.add_transaction();

        let affirms = tx.affirms(&[tx.sender_proof(0, &mut rng)]);
        let leg = tx.leg(0);
    }: affirm_transactions(leg.issuer.raw_origin(), affirms)

    receiver_affirm_transaction {
        let mut rng = StdRng::from_seed([10u8; 32]);

        // Setup for transaction.
        let mut tx = TransactionState::<T>::new(&mut rng);
        tx.add_transaction();
        tx.sender_affirm(0, &mut rng);

        let affirms = tx.affirms(&[AffirmLeg::receiver(TransactionLegId(0))]);
        let leg = tx.leg(0);
    }: affirm_transactions(leg.investor.raw_origin(), affirms)

    mediator_affirm_transaction {
        let mut rng = StdRng::from_seed([10u8; 32]);

        // Setup for transaction.
        let mut tx = TransactionState::<T>::new(&mut rng);
        tx.add_transaction();
        tx.sender_affirm(0, &mut rng);
        tx.receiver_affirm(0);

        let leg = tx.leg(0);
        let mediator = leg.mediator(0);
        let affirms = tx.affirms(&[AffirmLeg::mediator(TransactionLegId(0))]);
    }: affirm_transactions(mediator.raw_origin(), affirms)

    execute_transaction {
        let l in 1..T::MaxNumberOfLegs::get();

        let mut rng = StdRng::from_seed([10u8; 32]);

        // Setup for transaction.
        let mut tx = TransactionState::<T>::new_legs(l, &mut rng);
        tx.add_transaction();
        tx.affirm_legs(&mut rng);
    }: _(tx.custodian.raw_origin(), tx.id, l)

    reject_transaction {
        let l in 1..T::MaxNumberOfLegs::get();

        let mut rng = StdRng::from_seed([10u8; 32]);

        // Setup for transaction.
        let mut tx = TransactionState::<T>::new_legs(l, &mut rng);
        tx.add_transaction();
        tx.affirm_legs(&mut rng);
        let leg = tx.leg(0);
        let mediator = leg.mediator(0);
    }: _(mediator.raw_origin(), tx.id, l)
}
