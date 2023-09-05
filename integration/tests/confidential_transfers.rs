use anyhow::Result;
use sp_core::{Encode, Decode};

use polymesh_api::types::{
    pallet_confidential_asset::{
        //AffirmLeg, AffirmParty,
        MercatAccount,
        //SenderProof,
        //TransactionId, TransactionLeg, TransactionLegId,
    },
    polymesh_primitives::{
        asset::{AssetName, AssetType},
        settlement::VenueId,
        ticker::Ticker,
    },
};
use polymesh_api::TransactionResults;

use confidential_assets::{
    //elgamal::CipherText,
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

/// Search transaction events for VenueId.
pub async fn get_venue_id(res: &mut TransactionResults) -> Result<Option<VenueId>> {
  Ok(res.events().await?.and_then(|events| {
    for rec in &events.0 {
      match &rec.event {
        RuntimeEvent::ConfidentialAsset(ConfidentialAssetEvent::VenueCreated(_, venue_id)) => {
          return Some(venue_id.clone());
        }
        _ => (),
      }
    }
    None
  }))
}

#[tokio::test]
async fn confidential_transfer() -> Result<()> {
    let mut tester = PolymeshTester::new().await?;
    let mut users = tester.users(&[
        "Issuer1",
        "Investor1",
        "Mediator1",
    ]).await?;
    let ticker = Ticker(*b"ASSET1      ");
    let mut mediator = users.pop().unwrap();
    let (_mediator_keys, mediator_account) = create_account();
    let mut investor = users.pop().unwrap();
    let (_investor_keys, investor_account) = create_account();
    let mut issuer = users.pop().unwrap();
    let (_issuer_keys, issuer_account) = create_account();

    // Mediator registers their mercat account.
    tester
        .api
        .call()
        .confidential_asset()
        .add_mediator_mercat_account(mediator_account.clone())?
        .submit_and_watch(&mut mediator)
        .await?;

    // Initialize the issuer's account.
    tester
        .api
        .call()
        .confidential_asset()
        .validate_mercat_account(ticker, issuer_account.clone())?
        .submit_and_watch(&mut issuer)
        .await?;
    // Initialize the investor's account.
    tester
        .api
        .call()
        .confidential_asset()
        .validate_mercat_account(ticker, investor_account.clone())?
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
    tester
        .api
        .call()
        .confidential_asset()
        .mint_confidential_asset(ticker, 1_000_000_000, issuer_account)?
        .submit_and_watch(&mut issuer)
        .await?;

    // Wait for the `create_venue` tx and get the venue id.
    let venue_id = get_venue_id(&mut res_venue).await?
        .expect("Venue created");
    println!("venue_id = {:?}", venue_id);

    // The asset issuer needs to allow the mediator's venue.
    tester
        .api
        .call()
        .confidential_asset()
        .allow_venues(ticker, vec![venue_id])?
        .submit_and_watch(&mut issuer)
        .await?;

    // Wait for asset to be created.
    res_asset.ok().await?;

    Ok(())
}
