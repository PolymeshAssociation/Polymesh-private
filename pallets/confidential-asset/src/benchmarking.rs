// This file is part of the Polymesh distribution (https://github.com/PolymeshAssociation/Polymesh).
// Copyright (c) 2023 Polymesh

use frame_benchmarking::benchmarks;
use frame_support::assert_ok;

use rand_chacha::ChaCha20Rng as StdRng;

use confidential_assets::Balance as ConfidentialBalance;

use polymesh_common_utilities::{
    benchs::{user, AccountIdOf},
    traits::TestUtilsFn,
};
use polymesh_primitives::{
    asset::{AssetName, AssetType},
    Ticker,
};

use crate::testing::*;
use crate::*;

pub const MAX_LEGS: u32 = 100;
pub const MAX_MEDIATORS: u32 = MAX_LEGS * 8;

benchmarks! {
    where_clause { where T: Config, T: TestUtilsFn<AccountIdOf<T>> }

    create_account {
        let mut rng = StdRng::from_seed([10u8; 32]);
        let ticker = Ticker::from_slice_truncated(b"A".as_ref());
        let user = ConfidentialUser::<T>::new("user", &mut rng);
    }: _(user.raw_origin(), ticker, user.account())

    add_mediator_account {
        let mut rng = StdRng::from_seed([10u8; 32]);
        let mediator = ConfidentialUser::<T>::new("mediator", &mut rng);
        let account = mediator.mediator_account();
    }: _(mediator.raw_origin(), account)

    create_confidential_asset {
        let mut rng = StdRng::from_seed([10u8; 32]);
        let ticker = Ticker::from_slice_truncated(b"A".as_ref());
        let issuer = user::<T>("issuer", SEED);
        let auditors = AuditorState::<T>::new(0, &mut rng).get_asset_auditors();
    }: _(issuer.origin(), AssetName(b"Name".to_vec()), ticker, AssetType::default(), auditors)

    mint_confidential_asset {
        let mut rng = StdRng::from_seed([10u8; 32]);
        let (ticker, issuer, _) = create_confidential_token::<T>("A", 0, &mut rng);
        issuer.init_account(ticker);

        let total_supply = 4_000_000_000 as ConfidentialBalance;
    }: _(issuer.raw_origin(), ticker, total_supply.into(), issuer.account())

    apply_incoming_balance {
        let mut rng = StdRng::from_seed([10u8; 32]);

        // Setup for transaction.
        let mut tx = TransactionState::<T>::new(&mut rng);
        tx.add_transaction();
        tx.affirm_legs(&mut rng);
        tx.execute();
        let leg = tx.leg(0);
    }: _(leg.issuer.raw_origin(), leg.issuer.account(), leg.ticker)

    create_venue {
        let issuer = user::<T>("issuer", SEED);
    }: _(issuer.origin())

    set_venue_filtering {
        let mut rng = StdRng::from_seed([10u8; 32]);
        let (ticker, issuer, _) = create_confidential_token::<T>("A", 0, &mut rng);
    }: _(issuer.raw_origin(), ticker, true)

    allow_venues {
        // Count of venues.
        let v in 0 .. 100;

        let mut rng = StdRng::from_seed([10u8; 32]);
        let (ticker, issuer, _) = create_confidential_token::<T>("A", 0, &mut rng);
        let mut venues = Vec::new();
        for i in 0 .. v {
            venues.push(VenueId(i.into()));
        }
        let s_venues = venues.clone();
    }: _(issuer.raw_origin(), ticker, s_venues)
    verify {
        for v in venues.iter() {
            assert!(Pallet::<T>::venue_allow_list(ticker, v), "Fail: allow_venue dispatch");
        }
    }

    disallow_venues {
        // Count of venues.
        let v in 0 .. 100;

        let mut rng = StdRng::from_seed([10u8; 32]);
        let (ticker, issuer, _) = create_confidential_token::<T>("A", 0, &mut rng);
        let mut venues = Vec::new();
        for i in 0 .. v {
            venues.push(VenueId(i.into()));
        }
        assert_ok!(Pallet::<T>::allow_venues(
            issuer.origin(),
            ticker,
            venues.clone(),
        ));
        let s_venues = venues.clone();
    }: _(issuer.raw_origin(), ticker, s_venues)
    verify {
        for v in venues.iter() {
            assert!(!Pallet::<T>::venue_allow_list(ticker, v), "Fail: allow_venue dispatch");
        }
    }

    add_transaction {
        // Number of legs in transaction.
        let l in 1 .. MAX_LEGS;
        // Total number of mediators across all legs.
        let m in 0 .. MAX_MEDIATORS;

        // Always use the maximum number of auditors per leg.
        let a_count = l * T::MaxNumberOfAuditors::get();

        let mut rng = StdRng::from_seed([10u8; 32]);

        // Setup for transaction.
        let tx = TransactionState::<T>::new_legs_full(l, a_count, m, &mut rng);

        let legs = tx.get_legs();
    }: _(tx.custodian.raw_origin(), tx.venue_id, legs, Some(Memo([7u8; 32])))

    sender_affirm_transaction {
        // Number of auditors in the sender proof.
        let a in 0 .. T::MaxNumberOfAuditors::get();

        let mut rng = StdRng::from_seed([10u8; 32]);

        // Setup for transaction.
        let mut tx = TransactionState::<T>::new_legs_full(1, a, a, &mut rng);
        tx.add_transaction();

        let affirm = tx.sender_proof(0, &mut rng);
        let leg = tx.leg(0);
    }: affirm_transaction(leg.issuer.raw_origin(), tx.id, affirm)

    receiver_affirm_transaction {
        let mut rng = StdRng::from_seed([10u8; 32]);

        // Setup for transaction.
        let mut tx = TransactionState::<T>::new(&mut rng);
        tx.add_transaction();
        tx.sender_affirm(0, &mut rng);

        let affirm = AffirmLeg::receiver(TransactionLegId(0));
        let leg = tx.leg(0);
    }: affirm_transaction(leg.investor.raw_origin(), tx.id, affirm)

    mediator_affirm_transaction {
        let mut rng = StdRng::from_seed([10u8; 32]);

        // Setup for transaction.
        let mut tx = TransactionState::<T>::new(&mut rng);
        tx.add_transaction();
        tx.sender_affirm(0, &mut rng);
        tx.receiver_affirm(0);

        let leg = tx.leg(0);
        let mediator = leg.mediator(0);
        let affirm = AffirmLeg::mediator(TransactionLegId(0), mediator.mediator_account());
    }: affirm_transaction(mediator.raw_origin(), tx.id, affirm)

    sender_unaffirm_transaction {
        let mut rng = StdRng::from_seed([10u8; 32]);

        // Setup for transaction.
        let mut tx = TransactionState::<T>::new(&mut rng);
        tx.add_transaction();
        tx.affirm_legs(&mut rng);

        let unaffirm = UnaffirmLeg::sender(TransactionLegId(0));
        let leg = tx.leg(0);
    }: unaffirm_transaction(leg.issuer.raw_origin(), tx.id, unaffirm)

    receiver_unaffirm_transaction {
        let mut rng = StdRng::from_seed([10u8; 32]);

        // Setup for transaction.
        let mut tx = TransactionState::<T>::new(&mut rng);
        tx.add_transaction();
        tx.affirm_legs(&mut rng);

        let unaffirm = UnaffirmLeg::receiver(TransactionLegId(0));
        let leg = tx.leg(0);
    }: unaffirm_transaction(leg.investor.raw_origin(), tx.id, unaffirm)

    mediator_unaffirm_transaction {
        let mut rng = StdRng::from_seed([10u8; 32]);

        // Setup for transaction.
        let mut tx = TransactionState::<T>::new(&mut rng);
        tx.add_transaction();
        tx.affirm_legs(&mut rng);

        let leg = tx.leg(0);
        let mediator = leg.mediator(0);
        let affirm = AffirmLeg::mediator(TransactionLegId(0), mediator.mediator_account());
        let unaffirm = UnaffirmLeg::mediator(TransactionLegId(0), mediator.mediator_account());
    }: unaffirm_transaction(mediator.raw_origin(), tx.id, unaffirm)

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
