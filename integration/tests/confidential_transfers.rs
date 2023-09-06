use anyhow::Result;
use std::collections::BTreeMap;
use sp_core::{Encode, Decode};

use polymesh_api::types::{
    pallet_confidential_asset::{
        AffirmLeg, AffirmParty,
        MercatAccount,
        SenderProof,
        TransactionId, TransactionLeg, TransactionLegId,
    },
    polymesh_primitives::{
        asset::{AssetName, AssetType},
        settlement::VenueId,
    },
};
use polymesh_api::TransactionResults;

use confidential_assets::{
    elgamal::CipherText,
    transaction::{AuditorId, ConfidentialTransferProof},
    ElgamalKeys, ElgamalSecretKey, Scalar,
};

use integration::*;

fn create_account() -> (ElgamalKeys, MercatAccount) {
    let mut rng = rand::thread_rng();
    let secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
    let public = secret.get_public_key();
    // Convert ElgamalPublicKey to on-chain MercatAccount type.
    let enc_pub = public.encode();
    let account = MercatAccount::decode(&mut enc_pub.as_slice()).expect("MercatAccount");
    let keys = ElgamalKeys {
        public,
        secret,
    };
    (keys, account)
}

/// Search transaction events for ConfidentialAsset VenueId.
pub async fn get_venue_id(res: &mut TransactionResults) -> Result<Option<VenueId>> {
  Ok(res.events().await?.and_then(|events| {
    for rec in &events.0 {
      match &rec.event {
        RuntimeEvent::ConfidentialAsset(ConfidentialAssetEvent::VenueCreated(_, id)) => {
          return Some(*id);
        }
        _ => (),
      }
    }
    None
  }))
}

/// Search transaction events for ConfidentialAsset TransactionId.
pub async fn get_transaction_id(res: &mut TransactionResults) -> Result<Option<TransactionId>> {
  Ok(res.events().await?.and_then(|events| {
    for rec in &events.0 {
      match &rec.event {
        RuntimeEvent::ConfidentialAsset(ConfidentialAssetEvent::TransactionCreated(_, _, id, ..)) => {
          return Some(*id);
        }
        _ => (),
      }
    }
    None
  }))
}

/// Search transaction events for ConfidentialAsset TransactionAffirmed.
pub async fn get_transaction_affirmed(res: &mut TransactionResults) -> Result<Option<(TransactionId, TransactionLegId, Option<SenderProof>)>> {
  Ok(res.events().await?.and_then(|events| {
    for rec in &events.0 {
      match &rec.event {
        RuntimeEvent::ConfidentialAsset(ConfidentialAssetEvent::TransactionAffirmed(_, tx_id, leg_id, sender_proof)) => {
          return Some((*tx_id, *leg_id, sender_proof.clone()));
        }
        _ => (),
      }
    }
    None
  }))
}

#[tokio::test]
async fn confidential_transfer() -> Result<()> {
    let mut rng = rand::thread_rng();

    let mut tester = PolymeshTester::new().await?;
    let mut users = tester.users(&[
        "Issuer1",
        "Investor1",
        "Mediator1",
    ]).await?;
    let ticker = tester.gen_ticker();
    let mut mediator = users.pop().unwrap();
    let (mediator_keys, mediator_account) = create_account();
    let mut investor = users.pop().unwrap();
    let (investor_keys, investor_account) = create_account();
    let mut issuer = users.pop().unwrap();
    let (issuer_keys, issuer_account) = create_account();

    // Mediator registers their mercat account.
    tester
        .api
        .call()
        .confidential_asset()
        .add_mediator_mercat_account(mediator_account)?
        .submit_and_watch(&mut mediator)
        .await?;

    // Initialize the issuer's account.
    tester
        .api
        .call()
        .confidential_asset()
        .validate_mercat_account(ticker, issuer_account)?
        .submit_and_watch(&mut issuer)
        .await?;
    // Initialize the investor's account.
    tester
        .api
        .call()
        .confidential_asset()
        .validate_mercat_account(ticker, investor_account)?
        .submit_and_watch(&mut investor)
        .await?;

    // Mediator creates a venue.
    let mut res_venue = tester
        .api
        .call()
        .confidential_asset()
        .create_venue()?
        .submit_and_watch(&mut mediator)
        .await?;

    // Asset issuer create the confidential asset.
    let mut res_asset = tester
        .api
        .call()
        .confidential_asset()
        .create_confidential_asset(AssetName(b"Test".to_vec()), ticker, AssetType::EquityCommon)?
        .submit_and_watch(&mut issuer)
        .await?;
    let total_supply = 1_000_000_000u64;
    tester
        .api
        .call()
        .confidential_asset()
        .mint_confidential_asset(ticker, total_supply.into(), issuer_account)?
        .submit_and_watch(&mut issuer)
        .await?;

    // Wait for the `create_venue` tx and get the venue id.
    let venue_id = get_venue_id(&mut res_venue).await?
        .expect("Venue created");
    println!("venue_id = {:?}", venue_id);

    // The asset issuer needs to allow the mediator's venue.
    let mut res_allow_venue = tester
        .api
        .call()
        .confidential_asset()
        .allow_venues(ticker, vec![venue_id])?
        .submit_and_watch(&mut issuer)
        .await?;

    // Wait for asset to be created.
    res_asset.ok().await?;
    // Wait for venue to be allowed.
    res_allow_venue.ok().await?;

    // Setup confidential transfer.
    let auditors = BTreeMap::from([
        (AuditorId(0), mediator_keys.public),
    ]);
    let legs = vec![
        TransactionLeg {
            ticker,
            sender: issuer_account,
            receiver: investor_account,
            mediator: mediator.did.expect("Mediator DID"),
        }
    ];
    let mut res_add_tx = tester
        .api
        .call()
        .confidential_asset()
        .add_transaction(venue_id, legs, None)?
        .submit_and_watch(&mut mediator)
        .await?;
    // Wait for confidential transaction to be created..
    res_add_tx.ok().await?;
    let transaction_id = get_transaction_id(&mut res_add_tx).await?
        .expect("Transaction created");

    // Get the issuer's encrypted balance from chain storage.
    let sender_enc_balance = tester
        .api
        .query()
        .confidential_asset()
        .mercat_account_balance(issuer_account, ticker)
        .await?
        .and_then(|enc| {
            CipherText::decode(&mut &enc.0[..]).ok()
        })
        .expect("Issuer balance");

    // Generate sender proof.
    let tx_amount = 10_000_000;
    let tx_proof = ConfidentialTransferProof::new(
        &issuer_keys,
        &sender_enc_balance,
        total_supply.into(),
        &investor_keys.public,
        &auditors,
        tx_amount,
        &mut rng,
    ).expect("Sender proof");
    let sender_proof = SenderProof(tx_proof.encode());
    // Sender affirms the transaction with the sender proof.
    let sender_affirm = AffirmLeg {
        leg_id: TransactionLegId(0),
        party: AffirmParty::Sender(Box::new(sender_proof)),
    };
    let mut res_sender_affirm = tester
        .api
        .call()
        .confidential_asset()
        .affirm_transaction(transaction_id, sender_affirm)?
        .submit_and_watch(&mut issuer)
        .await?;

    // Receiver waits for `TransactionAffirmed` event from the sender's affirm tx.
    let (tx_id, leg_id, _sender_proof) = get_transaction_affirmed(&mut res_sender_affirm)
        .await?.expect("Sender affirm event.");
    // TODO: Receiver should verify transaction amount from `sender_proof`.
    let receiver_affirm = AffirmLeg {
        leg_id,
        party: AffirmParty::Receiver,
    };
    // Receiver affirms.
    tester
        .api
        .call()
        .confidential_asset()
        .affirm_transaction(tx_id, receiver_affirm)?
        .submit_and_watch(&mut investor)
        .await?;

    // TODO: Mediator should verify transaction amount from `sender_proof`.
    let mediator_affirm = AffirmLeg {
        leg_id,
        party: AffirmParty::Mediator,
    };
    // Mediator affirms.
    tester
        .api
        .call()
        .confidential_asset()
        .affirm_transaction(tx_id, mediator_affirm)?
        .submit_and_watch(&mut mediator)
        .await?;
    // Mediator executes transaction.
    let mut res_exec_tx = tester
        .api
        .call()
        .confidential_asset()
        .execute_transaction(tx_id, 1)?
        .submit_and_watch(&mut mediator)
        .await?;
    // Wait for confidential transaction to be executed.
    res_exec_tx.ok().await?;

    Ok(())
}
