// This file is part of the Polymesh distribution (https://github.com/PolymeshAssociation/Polymesh).
// Copyright (c) 2023 Polymesh

use frame_benchmarking::benchmarks;
use frame_support::assert_ok;

use rand_chacha::ChaCha20Rng as StdRng;
use rand_core::{RngCore, SeedableRng};

use polymesh_host_functions::{BatchVerify, GenerateTransferProofRequest};

use confidential_assets::{elgamal::CommitmentWitness, Balance as ConfidentialBalance, Scalar};

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

    create_asset {
        let mut rng = StdRng::from_seed([10u8; 32]);
        let issuer = user::<T>("issuer", SEED);
        let auditors = AuditorState::<T>::new(0, &mut rng).get_asset_auditors();
    }: _(issuer.origin(), Default::default(), auditors)

    mint {
        let mut rng = StdRng::from_seed([10u8; 32]);
        let (asset_id, issuer, _) = create_confidential_token::<T>("A", &mut rng);
        issuer.create_account();

        let total_supply = 4_000_000_000 as ConfidentialBalance;
    }: _(issuer.raw_origin(), asset_id, total_supply.into(), issuer.account())

    burn {
        let mut rng = StdRng::from_seed([10u8; 32]);
        let (asset_id, issuer, _) = create_confidential_token::<T>("A", &mut rng);
        issuer.create_account();

        // Mint asset supply.
        let total_supply = 4_000_000_000 as ConfidentialBalance;
        assert_ok!(Pallet::<T>::mint(
            issuer.origin(), asset_id, total_supply.into(), issuer.account()
        ));

        // Generate the burn proof
        let amount = 1_000 as ConfidentialBalance;
        let proof = issuer.burn_proof(asset_id, total_supply, amount, &mut rng);
    }: _(issuer.raw_origin(), asset_id, amount.into(), issuer.account(), proof)

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
        let user = ConfidentialUser::<T>::new("user", &mut rng);
        user.create_account();

        // Generate a lot of incoming balances.
        let key = user.pub_key();
        let (_, balance) = key.encrypt_value(1000u64.into(), &mut rng);
        let (_, incoming) = key.encrypt_value(100u64.into(), &mut rng);
        let asset_id = gen_asset_id(42);
        user.set_balance(asset_id, balance);
        user.set_incoming_balance(asset_id, incoming);
    }: _(user.raw_origin(), user.account(), asset_id)

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

    sender_affirm_transaction_batch {
        // Number of sender proofs.
        let l in 1 .. T::MaxNumberOfAffirms::get();

        let mut rng = StdRng::from_seed([10u8; 32]);

        // Setup for transaction.
        let mut tx = TransactionState::<T>::new_legs(1, &mut rng);
        let amount = 4_000;
        // Take the first leg and generate proofs.
        let mut leg = tx.legs.pop().unwrap();
        // Set the per-leg amount.
        leg.amount = amount;
        let issuer = leg.issuer.clone();
        let asset_id = leg.asset_id;
        let investor_pub_account = leg.investor.pub_key();
        let mut issuer_enc_balance = issuer.enc_balance(asset_id);
        let mut issuer_balance = leg.issuer_balance;
        let auditor_keys = leg.auditors.build_auditor_set();

        let mut seed = [0; 32];
        rng.fill_bytes(&mut seed);
        let mut witness_rng = StdRng::from_seed(seed);
        let witness = CommitmentWitness::new(amount.into(), Scalar::random(&mut witness_rng));
        let sender_amount = issuer.sec.public.encrypt(&witness);
        let batch = BatchVerify::create();
        // Make sure to start with an empty list of legs.
        tx.legs = Vec::with_capacity(l as usize);
        for id in 0..l {
          let leg_id = TransactionLegId(id);
          leg.leg_id = leg_id;
          tx.legs.push(leg.clone());
          let req = GenerateTransferProofRequest::new(
              issuer.sec.clone(),
              issuer_enc_balance,
              issuer_balance,
              investor_pub_account,
              auditor_keys.clone(),
              amount,
              seed,
          );
          batch.generate_transfer_proof(req).expect("Batched generate transfer proof");
          issuer_balance -= amount;
          issuer_enc_balance -= sender_amount;
        }
        let proofs = batch.get_proofs().expect("batch get proofs");
        let mut affirms = Vec::new();
        for id in 0..l {
          let leg_id = TransactionLegId(id);
          let proof = proofs[id as usize].transfer_proof().expect("Transfer proof");
          let mut transfers = ConfidentialTransfers::new();
          transfers.insert(asset_id, proof);
          affirms.push(AffirmLeg::sender(leg_id, transfers));
        }
        tx.add_transaction();

        let affirms = tx.affirms(affirms.as_slice());
    }: affirm_transactions(issuer.raw_origin(), affirms)

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

    move_assets_no_assets {
        // Number of move batches (each batch has the same from/to account)
        let m in 0 .. (T::MaxMoveFunds::get());

        let m = m as usize;
        let mut rng = StdRng::from_seed([10u8; 32]);
        // Generate confidential assets and move funds.
        let (signer, moves) = create_move_funds::<T>(m, 0, &mut rng);
    }: move_assets(signer.raw_origin(), moves)

    move_assets_one_batch {
        // Number of assets to move in each batch.
        let a in 0 .. (T::MaxAssetsPerMoveFunds::get());

        let a = a as usize;
        let mut rng = StdRng::from_seed([10u8; 32]);
        // Generate confidential assets and move funds.
        let (signer, moves) = create_move_funds::<T>(1, a, &mut rng);
    }: move_assets(signer.raw_origin(), moves)
}
