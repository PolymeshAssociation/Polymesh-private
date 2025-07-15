use anyhow::Result;
use polymesh_dart::AuditorOrMediator;

use integration::dart_asset_helper::*;

#[tokio::test]
async fn dart_transfer() -> Result<()> {
    let tester = DartAssetTester::init(&["Issuer1", "Investor1"], &["Auditor1"]).await?;
    let api = tester.api();
    let auditor = tester.auditor("Auditor1");
    let investor = tester.investor("Investor1");
    let issuer = tester.investor("Issuer1");

    let account_tree = AccountCurveTree::new(&api).await?;

    // The auditor needs to register their account.
    auditor.register_account().await?;
    let asset_auditor = AuditorOrMediator::auditor(&auditor.public_keys().enc);

    // The investor and issuer register their accounts.
    investor.register_account().await?;
    issuer.register_account().await?;

    // The issuer creates an asset
    let asset_id = issuer.create_asset("TestAset", asset_auditor).await?;

    // The issuer needs to register the asset with their account.
    issuer.register_account_asset(asset_id).await?;

    // The issuer can mint some assets.
    let mint_amount = 1000;
    issuer
        .mint_asset(&account_tree, asset_id, mint_amount)
        .await?;

    Ok(())
}
