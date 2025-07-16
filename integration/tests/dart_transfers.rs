use anyhow::Result;

use integration::dart_asset_helper::*;

#[tokio::test]
async fn simple_dart_funding() -> Result<()> {
    let mut tester = DartAssetTester::init(&["Issuer1", "Investor1", "Auditor1"]).await?;
    let investor = tester.user("Investor1");
    let issuer = tester.user("Issuer1");
    let auditor = tester.user("Auditor1");

    // Create asset issuer and an asset.
    let asset = tester
        .create_asset(&issuer, "Test Asset", &[&auditor], &[], Some(1000))
        .await?;

    // Create and fund some investors.
    let _investors = asset
        .register_and_fund_investors(&mut tester, &[&investor], 100)
        .await?;
    Ok(())
}

/// Atomic swap of two assets between two investors.
///
#[tokio::test]
async fn atomic_swap_test() -> Result<()> {
    let mut tester = DartAssetTester::init(&[
        "Asset1_Issuer",
        "Asset2_Issuer",
        "Venue",
        "Investor1",
        "Investor2",
        "Asset1_Auditor",
        "Asset2_Mediator",
    ])
    .await?;
    let asset1_issuer = tester.user("Asset1_Issuer");
    let asset2_issuer = tester.user("Asset2_Issuer");
    let venue = tester.user("Venue");
    let investor1 = tester.user("Investor1");
    let investor2 = tester.user("Investor2");
    let asset1_auditor = tester.user("Asset1_Auditor");
    let asset2_mediator = tester.user("Asset2_Mediator");

    // Create two assets with different issuers.
    let asset1 = tester
        .create_asset(
            &asset1_issuer,
            "Asset1",
            &[&asset1_auditor],
            &[],
            Some(50_000),
        )
        .await?;
    let asset2 = tester
        .create_asset(
            &asset2_issuer,
            "Asset2",
            &[&asset2_mediator],
            &[],
            Some(100_000),
        )
        .await?;

    // Register the investors for all assets.
    asset1.register_investors(&[&investor1, &investor2]).await?;
    asset2.register_investors(&[&investor1, &investor2]).await?;

    // Fund investors by sending them some assets from the issuers.
    asset1
        .register_and_fund_investors(&mut tester, &[&investor1], 500)
        .await?;
    asset2
        .register_and_fund_investors(&mut tester, &[&investor2], 20_000)
        .await?;

    // Create atomic swap settlement.
    let swap = DartSettlementState::new(
        &mut tester,
        &venue,
        &[
            DartLeg {
                sender: investor1.clone(),
                receiver: investor2.clone(),
                asset_id: asset1.id(),
                amount: 250,
            },
            DartLeg {
                sender: investor2.clone(),
                receiver: investor1.clone(),
                asset_id: asset2.id(),
                amount: 3_000,
            },
        ],
        Some(b"Test atomic swap"),
    )
    .await?;

    // All parties affirm all legs.
    swap.affirm_legs(&mut tester).await?;

    // The investors can now claim their assets.
    swap.claim_assets(&mut tester).await?;

    Ok(())
}
