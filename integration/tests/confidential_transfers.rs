use anyhow::Result;
use sp_core::{Decode, Encode};
use std::collections::{BTreeMap, BTreeSet};

use polymesh_api::types::{
    confidential_assets::transaction::ConfidentialTransferProof as SenderProof,
    pallet_confidential_asset::{
        AffirmLeg, AffirmParty, AffirmTransaction, AffirmTransactions, AuditorAccount,
        ConfidentialAccount, ConfidentialAuditors, ConfidentialTransfers, TransactionId,
        TransactionLeg, TransactionLegId,
    },
    polymesh_primitives::settlement::VenueId,
};
use polymesh_api::TransactionResults;

use confidential_assets::{
    elgamal::CipherText, transaction::ConfidentialTransferProof, AssetId, ElgamalKeys,
    ElgamalPublicKey, ElgamalSecretKey, Scalar,
};

use integration::*;

fn create_keys() -> ElgamalKeys {
    let mut rng = rand::thread_rng();
    let secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
    let public = secret.get_public_key();
    ElgamalKeys { public, secret }
}

#[derive(Clone)]
pub struct AuditorUser {
    api: Api,
    pub user: User,
    keys: ElgamalKeys,
    account: AuditorAccount,
    venue_id: Option<VenueId>,
}

impl AuditorUser {
    pub fn new(api: &Api, user: User) -> Self {
        let keys = create_keys();
        // Convert ElgamalPublicKey to on-chain AuditorAccount type.
        let enc_pub = keys.public.encode();
        let account = AuditorAccount::decode(&mut enc_pub.as_slice()).expect("AuditorAccount");
        Self {
            api: api.clone(),
            user,
            keys,
            account,
            venue_id: None,
        }
    }

    pub fn account(&self) -> AuditorAccount {
        self.account.clone()
    }

    pub fn pub_key(&self) -> ElgamalPublicKey {
        self.keys.public
    }

    pub async fn create_or_get_venue(&mut self) -> Result<VenueId> {
        if let Some(venue_id) = self.venue_id {
            return Ok(venue_id);
        }
        // Mediator creates a venue.
        let mut res_venue = self
            .api
            .call()
            .confidential_asset()
            .create_venue()?
            .submit_and_watch(&mut self.user)
            .await?;
        let venue_id = get_venue_id(&mut res_venue).await?.expect("Venue created");
        self.venue_id = Some(venue_id);
        Ok(venue_id)
    }
}

#[derive(Clone)]
pub struct ConfidentialUser {
    api: Api,
    pub user: User,
    keys: ElgamalKeys,
    account: ConfidentialAccount,
}

impl ConfidentialUser {
    pub fn new(api: &Api, user: User) -> Self {
        let keys = create_keys();
        // Convert ElgamalPublicKey to on-chain ConfidentialAccount type.
        let enc_pub = keys.public.encode();
        let account =
            ConfidentialAccount::decode(&mut enc_pub.as_slice()).expect("ConfidentialAccount");
        Self {
            api: api.clone(),
            user,
            keys,
            account,
        }
    }

    pub fn account(&self) -> ConfidentialAccount {
        self.account
    }

    pub fn pub_key(&self) -> ElgamalPublicKey {
        self.keys.public
    }

    /// Initialize the confidential account.
    pub async fn create_account(&mut self) -> Result<TransactionResults> {
        Ok(self
            .api
            .call()
            .confidential_asset()
            .create_account(self.account)?
            .submit_and_watch(&mut self.user)
            .await?)
    }
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

/// Search transaction events for ConfidentialAsset AssetId.
pub async fn get_asset_id(res: &mut TransactionResults) -> Result<Option<AssetId>> {
    Ok(res.events().await?.and_then(|events| {
        for rec in &events.0 {
            match &rec.event {
                RuntimeEvent::ConfidentialAsset(
                    ConfidentialAssetEvent::ConfidentialAssetCreated(_, asset, _),
                ) => {
                    return Some(*asset);
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
                RuntimeEvent::ConfidentialAsset(ConfidentialAssetEvent::TransactionCreated(
                    _,
                    _,
                    id,
                    ..,
                )) => {
                    return Some(*id);
                }
                _ => (),
            }
        }
        None
    }))
}

/// Search transaction events for ConfidentialAsset TransactionAffirmed.
pub async fn get_transaction_affirmed(
    res: &mut TransactionResults,
) -> Result<
    Option<(
        TransactionId,
        TransactionLegId,
        Option<ConfidentialTransfers>,
    )>,
> {
    Ok(res.events().await?.and_then(|events| {
        for rec in &events.0 {
            match &rec.event {
                RuntimeEvent::ConfidentialAsset(ConfidentialAssetEvent::TransactionAffirmed(
                    _,
                    tx_id,
                    leg_id,
                    AffirmParty::Sender(transfers),
                    _,
                )) => {
                    return Some((*tx_id, *leg_id, Some(transfers.clone())));
                }
                RuntimeEvent::ConfidentialAsset(ConfidentialAssetEvent::TransactionAffirmed(
                    _,
                    tx_id,
                    leg_id,
                    _,
                    _,
                )) => {
                    return Some((*tx_id, *leg_id, None));
                }
                _ => (),
            }
        }
        None
    }))
}

pub struct ConfidentialAssetTester {
    pub tester: PolymeshTester,
    pub investors: BTreeMap<String, ConfidentialUser>,
    pub auditors: BTreeMap<String, AuditorUser>,
}

impl ConfidentialAssetTester {
    pub async fn init(investors: &[&str], auditors: &[&str]) -> Result<Self> {
        let mut tester = PolymeshTester::new().await?;

        // Merge names to create all users in a batch.
        let names: Vec<&str> = investors
            .iter()
            .chain(auditors.iter())
            .map(|s| *s)
            .collect();
        let mut investor_users = tester.users(names.as_slice()).await?;
        // Split users into investors and auditors.
        let auditor_users = investor_users.split_off(investors.len());

        Ok(Self {
            investors: investors
                .into_iter()
                .zip(investor_users.into_iter())
                .map(|(n, u)| (n.to_string(), ConfidentialUser::new(&tester.api, u)))
                .collect(),
            auditors: auditors
                .into_iter()
                .zip(auditor_users.into_iter())
                .map(|(n, u)| (n.to_string(), AuditorUser::new(&tester.api, u)))
                .collect(),
            tester,
        })
    }

    pub fn investor(&self, name: &str) -> ConfidentialUser {
        self.investors.get(name).expect("Investor").clone()
    }

    pub fn auditor(&self, name: &str) -> AuditorUser {
        self.auditors.get(name).expect("Auditor").clone()
    }

    pub fn api(&self) -> Api {
        self.tester.api.clone()
    }
}

#[tokio::test]
async fn confidential_transfer() -> Result<()> {
    let mut rng = rand::thread_rng();

    let tester = ConfidentialAssetTester::init(&["Issuer1", "Investor1"], &["Mediator1"]).await?;
    let api = tester.api();
    let mut mediator = tester.auditor("Mediator1");
    let mut investor = tester.investor("Issuer1");
    let mut issuer = tester.investor("Investor1");

    let auditors = ConfidentialAuditors {
        auditors: BTreeSet::from([mediator.account()]),
        mediators: BTreeSet::from([mediator.user.did.expect("mediator did")]),
    };
    let auditors_ids = BTreeSet::from([mediator.pub_key()]);

    // Asset issuer create the confidential asset.
    let mut res_asset = api
        .call()
        .confidential_asset()
        .create_confidential_asset(None, vec![], auditors.clone())?
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
    api.call()
        .confidential_asset()
        .mint_confidential_asset(asset_id, total_supply.into(), issuer.account())?
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

    // Get the issuer's encrypted balance from chain storage.
    let sender_enc_balance = api
        .query()
        .confidential_asset()
        .account_balance(issuer.account(), asset_id)
        .await?
        .and_then(|enc| CipherText::decode(&mut &enc.0[..]).ok())
        .expect("Issuer balance");

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
        proofs: BTreeMap::from([(asset_id, SenderProof(tx_proof.encode()))]),
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

    // Receiver applies their incoming balance.
    let mut res_tx = api
        .call()
        .confidential_asset()
        .apply_incoming_balance(investor.account(), asset_id)?
        .submit_and_watch(&mut investor.user)
        .await?;
    // Wait for confidential transaction to be executed.
    res_tx.ok().await?;
    Ok(())
}
