use anyhow::Result;
use std::collections::{BTreeMap, BTreeSet};

use integration::*;

#[tokio::test]
async fn confidential_transfer() -> Result<()> {
    let mut rng = rand::thread_rng();

    let tester = ConfidentialAssetTester::init(&["Issuer1", "Investor1"], &["Mediator1"]).await?;
    let api = tester.api();
    let mut mediator = tester.auditor("Mediator1");
    let mut investor = tester.investor("Investor1");
    let mut issuer = tester.investor("Issuer1");

    let auditors = ConfidentialAuditors {
        auditors: BTreeSet::from([mediator.account()]),
        mediators: BTreeSet::from([mediator.user.did.expect("mediator did")]),
    };
    let auditors_ids = BTreeSet::from([mediator.pub_key()]);

    // Asset issuer create the confidential asset.
    let mut res_asset = api
        .call()
        .confidential_asset()
        .create_asset(vec![], auditors.clone())?
        .submit_and_watch(&mut issuer.user)
        .await?;

    // Initialize the issuer's account.
    issuer.create_account().await?;
    // Initialize the investor's account.
    investor.create_account().await?;

    // Wait for asset to be created.
    let asset_id = get_asset_id(&mut res_asset)
        .await?
        .expect("Confidential asset created");

    let total_supply = 1_000_000_000u64;
    let mut res_mint = api
        .call()
        .confidential_asset()
        .mint(asset_id, total_supply.into(), issuer.account())?
        .submit_and_watch(&mut issuer.user)
        .await?;

    // Mediator creates a venue.
    let venue_id = mediator.create_or_get_venue().await?;
    println!("venue_id = {:?}", venue_id);

    // Setup confidential transfer.
    let legs = vec![TransactionLeg {
        assets: BTreeSet::from([asset_id]),
        sender: issuer.account(),
        receiver: investor.account(),
        auditors: Default::default(),
        mediators: Default::default(),
    }];
    let mut res_add_tx = api
        .call()
        .confidential_asset()
        .add_transaction(venue_id, legs, None)?
        .submit_and_watch(&mut mediator.user)
        .await?;
    // Wait for confidential transaction to be created..
    res_add_tx.ok().await?;
    let transaction_id = get_transaction_id(&mut res_add_tx)
        .await?
        .expect("Transaction created");

    // Wait for mint.
    res_mint.ok().await?;
    // Get the issuer's encrypted balance from chain storage.
    let sender_enc_balance = issuer.account_balance(asset_id).await?;
    // Verify the issuer's balance.
    issuer.ensure_balance(&sender_enc_balance, total_supply)?;

    // Generate sender proof.
    let tx_amount = 10_000_000;
    let tx_proof = ConfidentialTransferProof::new(
        &issuer.keys,
        &sender_enc_balance,
        total_supply.into(),
        &investor.pub_key(),
        &auditors_ids,
        tx_amount,
        &mut rng,
    )
    .expect("Sender proof");
    let transfers = ConfidentialTransfers {
        proofs: BTreeMap::from([(asset_id, SenderProof(tx_proof.as_bytes()))]),
    };
    // Sender affirms the transaction with the sender proof.
    let affirms = AffirmTransactions(vec![AffirmTransaction {
        id: transaction_id,
        leg: AffirmLeg {
            leg_id: TransactionLegId(0),
            party: AffirmParty::Sender(transfers),
        },
    }]);
    let mut res_sender_affirm = api
        .call()
        .confidential_asset()
        .affirm_transactions(affirms)?
        .submit_and_watch(&mut issuer.user)
        .await?;

    // Receiver waits for `TransactionAffirmed` event from the sender's affirm tx.
    let (tx_id, leg_id, _sender_proof) = get_transaction_affirmed(&mut res_sender_affirm)
        .await?
        .expect("Sender affirm event.");
    // TODO: Receiver should verify transaction amount from `sender_proof`.
    let affirms = AffirmTransactions(vec![AffirmTransaction {
        id: tx_id,
        leg: AffirmLeg {
            leg_id,
            party: AffirmParty::Receiver,
        },
    }]);
    // Receiver affirms.
    api.call()
        .confidential_asset()
        .affirm_transactions(affirms)?
        .submit_and_watch(&mut investor.user)
        .await?;

    // TODO: Mediator should verify transaction amount from `sender_proof`.
    let affirms = AffirmTransactions(vec![AffirmTransaction {
        id: tx_id,
        leg: AffirmLeg {
            leg_id,
            party: AffirmParty::Mediator,
        },
    }]);
    // Mediator affirms.
    api.call()
        .confidential_asset()
        .affirm_transactions(affirms)?
        .submit_and_watch(&mut mediator.user)
        .await?;
    // Mediator executes transaction.
    let mut res_exec_tx = api
        .call()
        .confidential_asset()
        .execute_transaction(tx_id, 1)?
        .submit_and_watch(&mut mediator.user)
        .await?;
    // Wait for confidential transaction to be executed.
    res_exec_tx.ok().await?;

    // Verify the issuer's balance.
    let enc_balance = issuer.account_balance(asset_id).await?;
    issuer.ensure_balance(&enc_balance, total_supply - tx_amount)?;

    // Receiver applies their incoming balance.
    let mut res_tx = api
        .call()
        .confidential_asset()
        .apply_incoming_balance(investor.account(), asset_id)?
        .submit_and_watch(&mut investor.user)
        .await?;
    // Wait for confidential transaction to be executed.
    res_tx.ok().await?;

    // Verify the investor's balance.
    let enc_balance = investor.account_balance(asset_id).await?;
    investor.ensure_balance(&enc_balance, tx_amount)?;
    Ok(())
}
