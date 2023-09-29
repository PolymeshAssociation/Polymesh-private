use frame_support::assert_ok;
use frame_support::traits::OnInitialize;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng as StdRng;
use sp_runtime::traits::Zero;
use test_client::AccountKeyring;

use confidential_assets::transaction::ConfidentialTransferProof;

use pallet_confidential_asset::{
    testing::*, AffirmLeg, ConfidentialAssetDetails, Event, TransactionLeg, TransactionLegId,
};
use polymesh_primitives::asset::{AssetName, AssetType};
use polymesh_primitives::Ticker;

use crate::test_runtime::ext_builder::ExtBuilder;
use crate::test_runtime::{EventTest, TestRuntime, User};

type System = frame_system::Pallet<TestRuntime>;
type ConfidentialAsset = pallet_confidential_asset::Pallet<TestRuntime>;

macro_rules! assert_affirm_confidential_transaction {
    ($signer:expr, $transaction_id:expr, $data:expr) => {
        assert_ok!(ConfidentialAsset::affirm_transaction(
            $signer,
            $transaction_id,
            $data,
        ));
    };
}

pub fn next_block() {
    let block_number = frame_system::Pallet::<TestRuntime>::block_number() + 1;
    frame_system::Pallet::<TestRuntime>::set_block_number(block_number);
    pallet_scheduler::Pallet::<TestRuntime>::on_initialize(block_number);
}

pub fn create_auditors(idx: u32, rng: &mut StdRng) -> AuditorState<TestRuntime> {
    AuditorState::<TestRuntime>::new(idx, rng)
}

#[test]
fn issuers_can_create_and_rename_confidential_tokens() {
    ExtBuilder::default().build().execute_with(|| {
        // ------------ Setup
        let mut rng = StdRng::from_seed([10u8; 32]);

        let owner = User::new(AccountKeyring::Dave);
        // Expected token entry
        let token_name = vec![b'A'];
        let token = ConfidentialAssetDetails {
            name: AssetName(token_name.clone()),
            owner_did: owner.did,
            total_supply: 1_000_000,
            asset_type: AssetType::default(),
        };
        let ticker = Ticker::from_slice_truncated(token_name.as_slice());

        let auditors = create_auditors(0, &mut rng);

        // Issuance is successful.
        assert_ok!(ConfidentialAsset::create_confidential_asset(
            owner.origin(),
            token.name.clone(),
            ticker,
            token.asset_type.clone(),
            auditors.get_asset_auditors(),
        ));

        // A correct entry is added.
        let token_with_zero_supply = ConfidentialAssetDetails {
            name: AssetName(token_name.clone()),
            owner_did: token.owner_did,
            total_supply: Zero::zero(),
            asset_type: token.asset_type.clone(),
        };
        assert_eq!(
            ConfidentialAsset::confidential_asset_details(ticker).expect("Asset details"),
            token_with_zero_supply
        );

        /*
        // Unauthorized identities cannot rename the token.
        let eve = User::new(AccountKeyring::Eve);
        assert_err!(
            Asset::rename_asset(eve.origin(), ticker, vec![0xde, 0xad, 0xbe, 0xef].into()),
            EAError::UnauthorizedAgent
        );
        // The token should remain unchanged in storage.
        assert_eq!(ConfidentialAsset::confidential_asset_details(ticker).expect("Asset details"), token_with_zero_supply);
        // Rename the token and check storage has been updated.
        let renamed_token_name = vec![0x42];
        let renamed_token = ConfidentialAssetDetails {
            name: AssetName(token_name.clone()),
            owner_did: token.owner_did,
            total_supply: token_with_zero_supply.total_supply,
            asset_type: token.asset_type.clone(),
        };
        assert_ok!(Asset::rename_asset(
            owner.origin(),
            ticker,
            token.name.clone(),
        ));
        assert_eq!(ConfidentialAsset::confidential_asset_details(ticker).expect("Asset details"), renamed_token);
        */

        // Add another STO.
        // Expected token entry.
        let token_name = vec![b'B'];
        let token = ConfidentialAssetDetails {
            name: AssetName(token_name.clone()),
            owner_did: owner.did,
            total_supply: 1_000_000,
            asset_type: AssetType::default(),
        };
        let ticker2 = Ticker::from_slice_truncated(token_name.as_slice());

        // Second Issuance is successful.
        assert_ok!(ConfidentialAsset::create_confidential_asset(
            owner.origin(),
            token.name.clone(),
            ticker2,
            token.asset_type.clone(),
            auditors.get_asset_auditors(),
        ));

        let token_with_zero_supply = ConfidentialAssetDetails {
            name: AssetName(token_name.clone()),
            owner_did: token.owner_did,
            total_supply: Zero::zero(),
            asset_type: token.asset_type.clone(),
        };

        // A correct entry is added.
        assert_eq!(
            ConfidentialAsset::confidential_asset_details(ticker2).expect("Asset details"),
            token_with_zero_supply
        );
    });
}

#[test]
fn issuers_can_create_and_mint_tokens() {
    ExtBuilder::default().build().execute_with(|| {
        // ------------ Setup
        let mut rng = StdRng::from_seed([10u8; 32]);

        // Alice is the owner of the token in this test.
        let owner = ConfidentialUser::<TestRuntime>::new("alice", &mut rng);

        let auditors = create_auditors(0, &mut rng);

        // Create a few confidential assets.
        for idx in 0..3 {
            create_confidential_token::<TestRuntime>("A", idx, &mut rng);
        }

        let total_supply: u128 = 10_000_000;
        // Expected token entry
        let token_name = vec![b'D'];
        let token = ConfidentialAssetDetails {
            name: AssetName(token_name.clone()),
            owner_did: owner.did(),
            total_supply,
            asset_type: AssetType::default(),
        };
        let ticker = Ticker::from_slice_truncated(token_name.as_slice());

        assert_ok!(ConfidentialAsset::create_confidential_asset(
            owner.origin(),
            token.name.clone(),
            ticker,
            token.asset_type.clone(),
            auditors.get_asset_auditors(),
        ));

        // In the initial call, the total_supply must be zero.
        assert_eq!(
            ConfidentialAsset::confidential_asset_details(ticker)
                .expect("Asset details")
                .total_supply,
            Zero::zero()
        );

        // ---------------- Setup: prepare for minting the asset

        // The issuer's account must be initialized before minting.
        owner.init_account(ticker);

        ConfidentialAsset::mint_confidential_asset(
            owner.origin(),
            ticker,
            total_supply,
            owner.account(),
        )
        .unwrap();

        // ------------------------- Ensuring that the asset details are set correctly

        // A correct entry is added.
        assert_eq!(
            ConfidentialAsset::confidential_asset_details(ticker),
            Some(token)
        );

        // -------------------------- Ensure that the account balance is set properly.
        owner.ensure_balance(ticker, total_supply as _);
    })
}

#[test]
fn account_create() {
    ExtBuilder::default().build().execute_with(|| {
        let ticker = Ticker::from_slice_truncated(b"A".as_ref());

        // ------------- START: Computations that will happen in Alice's Wallet ----------
        let mut rng = StdRng::from_seed([10u8; 32]);
        let alice = ConfidentialUser::<TestRuntime>::new("alice", &mut rng);
        // ------------- END: Computations that will happen in the Wallet ----------

        // Wallet initialize the account for `ticker`.
        alice.init_account(ticker);

        // Ensure that the account has an initial balance of zero.
        alice.ensure_balance(ticker, 0);
    });
}

// ----------------------------------------- Confidential transfer tests -----------------------------------

#[test]
fn basic_confidential_settlement() {
    let cdd = AccountKeyring::Eve.to_account_id();
    ExtBuilder::default()
        .cdd_providers(vec![cdd.clone()])
        .build()
        .execute_with(|| {
            next_block();
            // The rest of rngs are built from it. Its initial value can be set using proptest.
            let mut rng = StdRng::from_seed([10u8; 32]);

            // Setting:
            //   - Alice is the token issuer.
            //   - Alice is also the sender of the token.
            //   - Bob is the receiver of the token.
            //   - Charlie is the venue manager.
            //   - And one or more mediators.

            let charlie = User::new(AccountKeyring::Charlie);

            // ------------ Setup confidential asset.

            // Create an account for Alice and mint 10,000,000 tokens to ACME.
            let total_supply = 1_1000_000 as u64;
            let (ticker, alice, alice_init_balance, auditors) =
                create_account_and_mint_token::<TestRuntime>(
                    "alice",
                    total_supply as u128,
                    0,
                    &mut rng,
                );

            // Create investor account for Bob.
            let bob = ConfidentialUser::<TestRuntime>::new("bob", &mut rng);
            bob.init_account(ticker);
            let bob_encrypted_init_balance = bob.enc_balance(ticker);

            // Mediator creates a venue
            let venue_id = ConfidentialAsset::venue_counter();
            assert_ok!(ConfidentialAsset::create_venue(charlie.origin()));

            // Add the venue to the allow list for the asset.
            assert_ok!(ConfidentialAsset::allow_venues(
                alice.origin(),
                ticker,
                vec![venue_id]
            ));

            // Mediator creates an transaction
            let transaction_id = ConfidentialAsset::transaction_counter();
            let leg_id = TransactionLegId(0);

            assert_ok!(ConfidentialAsset::add_transaction(
                charlie.origin(),
                venue_id,
                vec![TransactionLeg {
                    ticker,
                    sender: alice.account(),
                    receiver: bob.account(),
                    auditors: auditors.auditors.clone(),
                }],
                None
            ));

            // -------------------------- Perform the transfer
            let amount = 100;

            // Ensure that Alice has minted enough tokens.
            alice.ensure_balance(ticker, alice_init_balance);

            // ----- Sender authorizes.
            // Sender computes the proofs in the wallet.
            println!("-------------> Alice is going to authorize.");
            let alice_enc_balance = alice.enc_balance(ticker);
            let auditor_keys = auditors.build_auditor_map();
            let sender_proof = ConfidentialTransferProof::new(
                &alice.sec,
                &alice_enc_balance,
                alice_init_balance,
                &bob.pub_key(),
                &auditor_keys,
                amount,
                &mut rng,
            )
            .unwrap();
            let alice_encrypted_transfer_amount = sender_proof.sender_amount();
            let bob_encrypted_transfer_amount = sender_proof.receiver_amount();
            let affirm = AffirmLeg::sender(leg_id, sender_proof);
            // Sender authorizes the transaction and passes in the proofs.
            assert_affirm_confidential_transaction!(alice.origin(), transaction_id, affirm);

            // ------ Receiver authorizes.
            // Receiver reads the sender's proof from the event.
            println!("-------------> Bob is going to authorize.");
            let sender_proof = {
                match System::events().pop().unwrap().event {
                    EventTest::ConfidentialAsset(Event::TransactionAffirmed(_, _, _, proof)) => {
                        proof
                            .expect("Expected Proof")
                            .into_tx()
                            .expect("Valid sender proof")
                    }
                    _ => panic!("Exepected TransactionAffirmed event"),
                }
            };

            // Receiver computes the proofs in the wallet.
            sender_proof
                .receiver_verify(bob.sec.clone(), amount)
                .unwrap();
            let affirm = AffirmLeg::receiver(leg_id);

            // Receiver submits the proof to the chain.
            assert_affirm_confidential_transaction!(bob.origin(), transaction_id, affirm);

            // ------ Mediator authorizes.
            // Mediator reads the receiver's proofs from the chain (it contains the sender's proofs as well).
            println!("-------------> Charlie is going to authorize.");

            // Mediator verifies the proofs in the wallet.
            auditors.verify_proof(&sender_proof);
            for user in auditors.mediators() {
                let affirm = AffirmLeg::mediator(leg_id, user.mediator_account());

                assert_affirm_confidential_transaction!(user.origin(), transaction_id, affirm);
            }

            // Execute affirmed transaction.
            assert_ok!(ConfidentialAsset::execute_transaction(
                charlie.origin(),
                transaction_id,
                1,
            ));

            // Transaction should've settled.
            // Verify by decrypting the new balance of both Alice and Bob.
            let new_alice_balance = alice.enc_balance(ticker);
            let expected_alice_balance = alice_enc_balance - alice_encrypted_transfer_amount;
            assert_eq!(new_alice_balance, expected_alice_balance);

            alice.ensure_balance(ticker, total_supply - amount);

            // Bob update's their balance.
            assert_ok!(ConfidentialAsset::apply_incoming_balance(
                bob.origin(),
                bob.account(),
                ticker
            ));
            let new_bob_balance = bob.enc_balance(ticker);

            let expected_bob_balance = bob_encrypted_init_balance + bob_encrypted_transfer_amount;
            assert_eq!(new_bob_balance, expected_bob_balance);
            bob.ensure_balance(ticker, amount);
        });
}
