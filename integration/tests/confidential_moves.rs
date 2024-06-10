use anyhow::Result;
use std::collections::{BTreeMap, BTreeSet};

use integration::*;

#[tokio::test]
async fn confidential_moves() -> Result<()> {
    let mut rng = rand::thread_rng();

    let tester = ConfidentialAssetTester::init(&["Issuer1"], &["Mediator1"]).await?;
    let api = tester.api();
    let mediator = tester.auditor("Mediator1");
    let mut issuer = tester.investor("Issuer1");
    // generate sub accounts (Portfolios).
    let mut subaccounts = (0..10).map(|_| issuer.sub_account()).collect::<Vec<_>>();

    let auditors = ConfidentialAuditors {
        auditors: BTreeSet::from([mediator.account()]),
        mediators: BTreeSet::from([mediator.did()?]),
    };
    let auditors_keys = BTreeSet::from([mediator.pub_key()]);

    // Asset issuer create the confidential asset.
    let mut res_asset = api
        .call()
        .confidential_asset()
        .create_asset(vec![], auditors.clone())?
        .submit_and_watch(&mut issuer.user)
        .await?;

    // Initialize the issuer's account.
    issuer.create_account().await?;
    // Initialize the sub accounts.
    for subaccount in &mut subaccounts {
        subaccount.create_account().await?;
    }

    // Wait for asset to be created.
    let asset_id = get_asset_id(&mut res_asset)
        .await?
        .expect("Confidential asset created");

    let move_amount = 10_000_000u64;
    let total_supply = subaccounts.len() as u64 * move_amount;
    let mut res_mint = api
        .call()
        .confidential_asset()
        .mint(asset_id, total_supply.into(), issuer.account())?
        .submit_and_watch(&mut issuer.user)
        .await?;

    // Wait for mint.
    res_mint.ok().await?;
    // Get the issuer's encrypted balance from chain storage.
    let mut sender_enc_balance = issuer.account_balance(asset_id).await?;
    issuer.ensure_balance(&sender_enc_balance, total_supply)?;
    let mut sender_balance = total_supply;

    // Move funds from the main `issuer` confidential account, to sub accounts (Portfolios).
    let mut move_funds = Vec::new();
    for subaccount in &subaccounts {
        // Generate sender proof.
        let tx_proof = ConfidentialTransferProof::new(
            &issuer.keys,
            &sender_enc_balance,
            sender_balance,
            &subaccount.pub_key(),
            &auditors_keys,
            move_amount,
            &mut rng,
        )
        .expect("Sender proof");
        // Update the "sender balance" for the next proof.
        sender_balance -= move_amount;
        sender_enc_balance -= tx_proof.sender_amount();

        let receiver_amount = tx_proof.receiver_amount();
        subaccount
            .keys
            .verify(&receiver_amount, &Scalar::from(move_amount))?;

        move_funds.push(ConfidentialMoveFunds {
            from: issuer.account(),
            to: subaccount.account(),
            proofs: BTreeMap::from([(asset_id, SenderProof(tx_proof.as_bytes()))]),
        });
    }
    let mut res = api
        .call()
        .confidential_asset()
        .move_assets(move_funds)?
        .submit_and_watch(&mut issuer.user)
        .await?;

    // Wait for confidential transaction to be executed.
    res.ok().await?;

    // Move funds back to main `issuer` account.
    let mut move_funds = Vec::new();
    for subaccount in &subaccounts {
        // Get the subaccount's encrypted balance from chain storage.
        let enc_balance = subaccount.account_balance(asset_id).await?;
        subaccount.ensure_balance(&enc_balance, move_amount)?;

        // Generate sender proof.
        let tx_proof = ConfidentialTransferProof::new(
            &subaccount.keys,
            &enc_balance,
            move_amount,
            &issuer.pub_key(),
            &auditors_keys,
            move_amount,
            &mut rng,
        )
        .expect("Sender proof");

        move_funds.push(ConfidentialMoveFunds {
            from: subaccount.account(),
            to: issuer.account(),
            proofs: BTreeMap::from([(asset_id, SenderProof(tx_proof.as_bytes()))]),
        });
    }
    let mut res = api
        .call()
        .confidential_asset()
        .move_assets(move_funds)?
        .submit_and_watch(&mut issuer.user)
        .await?;

    // Wait for confidential transaction to be executed.
    res.ok().await?;

    // Verify the asset issuer's main balance.
    let issuer_enc_balance = issuer.account_balance(asset_id).await?;
    issuer.ensure_balance(&issuer_enc_balance, total_supply)?;

    Ok(())
}
