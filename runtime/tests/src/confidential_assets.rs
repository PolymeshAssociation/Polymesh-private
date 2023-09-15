use core::convert::TryInto;
use frame_support::assert_ok;
use frame_support::traits::OnInitialize;
use rand::{rngs::StdRng, SeedableRng};
use sp_runtime::traits::Zero;
use sp_std::collections::btree_map::BTreeMap;
use test_client::AccountKeyring;

use confidential_assets::{
    transaction::{AuditorId, ConfidentialTransferProof},
    Balance as ConfidentialBalance, CipherText, ElgamalKeys, ElgamalSecretKey, Scalar,
};

use pallet_confidential_asset::{
    AffirmLeg, ConfidentialAccount, ConfidentialAssetDetails, Event, MediatorAccount,
    TransactionLeg, TransactionLegId,
};
use polymesh_primitives::asset::{AssetName, AssetType};
use polymesh_primitives::Ticker;

use crate::test_runtime::ext_builder::ExtBuilder;
use crate::test_runtime::{EventTest, TestRuntime, User};

type System = frame_system::Pallet<TestRuntime>;
type ConfidentialAsset = pallet_confidential_asset::Module<TestRuntime>;

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

fn create_confidential_token(token_name: &[u8], ticker: Ticker, user: User) {
    assert_ok!(ConfidentialAsset::create_confidential_asset(
        user.origin(),
        AssetName(token_name.into()),
        ticker,
        AssetType::default(),
    ));
}

/// Creates a confidential account and returns its secret part (to be stored in the wallet) and
/// the account creation proofs (to be submitted to the chain).
pub fn gen_account(mut rng: &mut StdRng) -> ElgamalKeys {
    // These are the encryptions keys used by confidential asset transfers and are different from the signing keys
    // that Polymesh uses.
    let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
    ElgamalKeys {
        public: elg_secret.get_public_key(),
        secret: elg_secret,
    }
}

/// Creates a confidential account for the `owner` and submits the proofs to the chain and validates them.
/// It then return the secret part of the account, the account id, the public portion of the account and the initial
/// encrypted balance of zero.
pub fn init_account(
    mut rng: &mut StdRng,
    ticker: Ticker,
    owner: User,
) -> (ElgamalKeys, ConfidentialAccount, CipherText) {
    let enc_keys = gen_account(&mut rng);
    let account = enc_keys.public.into();

    assert_ok!(ConfidentialAsset::create_account(
        owner.origin(),
        ticker,
        account,
    ));

    let balance = ConfidentialAsset::account_balance(&account, ticker).expect("account balance");
    (enc_keys, account, balance)
}

/// Creates a confidential account for the `owner` and submits the proofs to the chain and validates them.
/// It then return the secret part of the account, the account id, the public portion of the account and the initial
/// encrypted balance of zero.
pub fn init_mediator(mut rng: &mut StdRng, owner: User) -> (ElgamalKeys, MediatorAccount) {
    let enc_keys = gen_account(&mut rng);
    let account = enc_keys.public.into();

    assert_ok!(ConfidentialAsset::add_mediator_account(
        owner.origin(),
        account,
    ));

    (enc_keys, account)
}

/// Performs confidential account creation, validation, and minting of the account with `total_supply` tokens.
/// It returns the next the secret portion of the account, the account id, the public portion of the account,
/// and the encrypted balance of `total_supply`.
pub fn create_account_and_mint_token(
    owner: User,
    total_supply: u128,
    token_name: Vec<u8>,
    mut rng: &mut StdRng,
) -> (ElgamalKeys, ConfidentialAccount, CipherText) {
    let token = ConfidentialAssetDetails {
        name: AssetName(token_name.clone()),
        total_supply,
        owner_did: owner.did,
        asset_type: AssetType::default(),
    };
    let ticker = Ticker::from_slice_truncated(token_name.as_slice());

    assert_ok!(ConfidentialAsset::create_confidential_asset(
        owner.origin(),
        token.name.clone(),
        ticker,
        token.asset_type.clone(),
    ));

    // In the initial call, the total_supply must be zero.
    assert_eq!(
        ConfidentialAsset::confidential_asset_details(ticker)
            .expect("Asset details")
            .total_supply,
        Zero::zero()
    );

    // ---------------- prepare for minting the asset

    let issuer_account = gen_account(&mut rng);
    let confidential_account = issuer_account.public.into();

    assert_ok!(ConfidentialAsset::create_account(
        owner.origin(),
        ticker,
        confidential_account,
    ));

    // ------------- Computations that will happen in owner's Wallet ----------
    let amount: ConfidentialBalance = token.total_supply.try_into().unwrap(); // confidential amounts are 64 bit integers.

    // Wallet submits the transaction to the chain for verification.
    assert_ok!(ConfidentialAsset::mint_confidential_asset(
        owner.origin(),
        ticker,
        amount.into(), // convert to u128
        confidential_account,
    ));

    // ------------------------- Ensuring that the asset details are set correctly

    // A correct entry is added.
    assert_eq!(
        ConfidentialAsset::confidential_asset_details(ticker)
            .expect("Asset details")
            .owner_did,
        token.owner_did
    );

    // -------------------------- Ensure the encrypted balance matches the minted amount.
    let balance =
        ConfidentialAsset::account_balance(&confidential_account, ticker).expect("account balance");
    let stored_balance = issuer_account.secret.decrypt(&balance).unwrap();

    assert_eq!(stored_balance, amount);

    (issuer_account, confidential_account, balance)
}

#[test]
fn issuers_can_create_and_rename_confidential_tokens() {
    ExtBuilder::default().build().execute_with(|| {
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

        // Issuance is successful.
        assert_ok!(ConfidentialAsset::create_confidential_asset(
            owner.origin(),
            token.name.clone(),
            ticker,
            token.asset_type.clone(),
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

        // Alice is the owner of the token in this test.
        let owner = User::new(AccountKeyring::Alice);
        let bob = User::new(AccountKeyring::Bob);

        let token_names = [[b'A'], [b'B'], [b'C']];
        for token_name in token_names.iter() {
            create_confidential_token(
                &token_name[..],
                Ticker::from_slice_truncated(&token_name[..]),
                bob, // Alice does not own any of these tokens.
            );
        }
        let total_supply: u128 = 10_000_000;
        // Expected token entry
        let token_name = vec![b'D'];
        let token = ConfidentialAssetDetails {
            name: AssetName(token_name.clone()),
            owner_did: owner.did,
            total_supply,
            asset_type: AssetType::default(),
        };
        let ticker = Ticker::from_slice_truncated(token_name.as_slice());

        assert_ok!(ConfidentialAsset::create_confidential_asset(
            owner.origin(),
            token.name.clone(),
            ticker,
            token.asset_type.clone(),
        ));

        // In the initial call, the total_supply must be zero.
        assert_eq!(
            ConfidentialAsset::confidential_asset_details(ticker)
                .expect("Asset details")
                .total_supply,
            Zero::zero()
        );

        // ---------------- Setup: prepare for minting the asset

        let mut rng = StdRng::from_seed([10u8; 32]);
        let issuer_account = gen_account(&mut rng);
        let confidential_account = issuer_account.public.into();

        ConfidentialAsset::create_account(owner.origin(), ticker, confidential_account).unwrap();

        // ------------- START: Computations that will happen in Alice's Wallet ----------
        let amount: ConfidentialBalance = token.total_supply.try_into().unwrap(); // confidential amounts are 64 bit integers.

        // ------------- END: Computations that will happen in the Wallet ----------

        // Wallet submits the transaction to the chain for verification.
        ConfidentialAsset::mint_confidential_asset(
            owner.origin(),
            ticker,
            amount.into(), // convert to u128
            confidential_account,
        )
        .unwrap();

        // ------------------------- Ensuring that the asset details are set correctly

        // A correct entry is added.
        assert_eq!(
            ConfidentialAsset::confidential_asset_details(ticker),
            Some(token)
        );

        // -------------------------- Ensure that the account balance is set properly.
        let balance = ConfidentialAsset::account_balance(&confidential_account, ticker)
            .expect("account balance");

        issuer_account
            .secret
            .verify(&balance, &amount.into())
            .expect("verify new balance");
    })
}

#[test]
fn account_create_tx() {
    ExtBuilder::default().build().execute_with(|| {
        let alice = User::new(AccountKeyring::Alice);
        // Simulating the case were issuers have registered some tickers and therefore the list of
        // valid asset ids contains some values.
        let ticker = Ticker::from_slice_truncated(b"A".as_ref());

        // ------------- START: Computations that will happen in Alice's Wallet ----------
        let mut rng = StdRng::from_seed([10u8; 32]);
        let account = gen_account(&mut rng);
        let confidential_account = account.public.into();
        // ------------- END: Computations that will happen in the Wallet ----------

        // Wallet submits the transaction to the chain for verification.
        ConfidentialAsset::create_account(alice.origin(), ticker, confidential_account).unwrap();

        // Ensure that the transaction was verified and that confidential account is created on the chain.
        let stored_balance = ConfidentialAsset::account_balance(&confidential_account, ticker)
            .expect("account balance");
        // Ensure that the account has an initial balance of zero.
        let stored_balance = account.secret.decrypt(&stored_balance).unwrap();
        assert_eq!(stored_balance, 0);
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
            //   - Charlie is the mediator.
            //   - Eve is the CDD provider.
            let alice = User::new(AccountKeyring::Alice);

            let bob = User::new(AccountKeyring::Bob);

            let charlie = User::new(AccountKeyring::Charlie);

            // ------------ Setup confidential accounts.
            let token_name = b"ACME";
            let ticker = Ticker::from_slice_truncated(&token_name[..]);

            // Create an account for Alice and mint 10,000,000 tokens to ACME.
            // let total_supply = 1_1000_000;
            let total_supply = 500;
            let (alice_keys, alice_account, alice_encrypted_init_balance) =
                create_account_and_mint_token(alice, total_supply, token_name.to_vec(), &mut rng);

            // Create accounts for Bob, and Charlie.
            let (bob_keys, bob_account, bob_encrypted_init_balance) =
                init_account(&mut rng, ticker, bob);

            let (charlie_keys, charlie_account) = init_mediator(&mut rng, charlie);

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
                    sender: alice_account,
                    receiver: bob_account,
                    mediator: charlie_account,
                }],
                None
            ));

            // -------------------------- Perform the transfer
            let amount = 100 as ConfidentialBalance; // This plain format is only used on functions that emulate the work of the wallet.

            println!("-------------> Checking if alice has enough funds.");
            // Ensure that Alice has minted enough tokens.
            let alice_init_balance = alice_keys
                .secret
                .decrypt(&alice_encrypted_init_balance)
                .unwrap();
            assert!(alice_init_balance > amount);

            // ----- Sender authorizes.
            // Sender computes the proofs in the wallet.
            println!("-------------> Alice is going to authorize.");
            let auditor_keys = BTreeMap::from([(AuditorId(0), charlie_keys.public)]);
            let sender_tx = ConfidentialTransferProof::new(
                &alice_keys,
                &alice_encrypted_init_balance,
                alice_init_balance,
                &bob_keys.public,
                &auditor_keys,
                amount,
                &mut rng,
            )
            .unwrap();
            let alice_encrypted_transfer_amount = sender_tx.sender_amount();
            let bob_encrypted_transfer_amount = sender_tx.receiver_amount();
            let initialized_tx = AffirmLeg::sender(leg_id, sender_tx);
            // Sender authorizes the transaction and passes in the proofs.
            assert_affirm_confidential_transaction!(alice.origin(), transaction_id, initialized_tx);

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
                .receiver_verify(bob_keys.clone(), amount)
                .unwrap();
            let finalized_tx = AffirmLeg::receiver(leg_id);

            // Receiver submits the proof to the chain.
            assert_affirm_confidential_transaction!(bob.origin(), transaction_id, finalized_tx);

            // ------ Mediator authorizes.
            // Mediator reads the receiver's proofs from the chain (it contains the sender's proofs as well).
            println!("-------------> Charlie is going to authorize.");

            // Mediator verifies the proofs in the wallet.
            sender_proof
                .auditor_verify(AuditorId(0), &charlie_keys)
                .unwrap();
            let justified_tx = AffirmLeg::mediator(leg_id);

            println!("-------------> This should trigger the execution");
            assert_affirm_confidential_transaction!(charlie.origin(), transaction_id, justified_tx);

            // Execute affirmed transaction.
            assert_ok!(ConfidentialAsset::execute_transaction(
                charlie.origin(),
                transaction_id,
                1,
            ));

            // Transaction should've settled.
            // Verify by decrypting the new balance of both Alice and Bob.
            let new_alice_balance = ConfidentialAsset::account_balance(&alice_account, ticker)
                .expect("account balance");
            let expected_alice_balance =
                alice_encrypted_init_balance - alice_encrypted_transfer_amount;
            assert_eq!(new_alice_balance, expected_alice_balance);

            let new_alice_balance = alice_keys.secret.decrypt(&new_alice_balance).unwrap();
            assert_eq!(new_alice_balance as u128, total_supply - amount as u128);

            // Bob update's their balance.
            assert_ok!(ConfidentialAsset::apply_incoming_balance(
                bob.origin(),
                bob_account,
                ticker
            ));
            let new_bob_balance =
                ConfidentialAsset::account_balance(&bob_account, ticker).expect("account balance");

            let expected_bob_balance = bob_encrypted_init_balance + bob_encrypted_transfer_amount;
            assert_eq!(new_bob_balance, expected_bob_balance);
            let new_bob_balance = bob_keys.secret.decrypt(&new_bob_balance).unwrap();
            assert_eq!(new_bob_balance, amount);
        });
}
