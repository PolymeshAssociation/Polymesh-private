use anyhow::{anyhow, Result};
use sp_core::{Decode, Encode};
use std::collections::BTreeMap;

pub use polymesh_api_tester::{
    ConfidentialAssetEvent, IdentityId, PolymeshTester, RuntimeEvent, User,
};

pub use polymesh_api::types::{
    confidential_assets::transaction::ConfidentialTransferProof as SenderProof,
    pallet_confidential_asset::{
        AffirmLeg, AffirmParty, AffirmTransaction, AffirmTransactions, AuditorAccount,
        ConfidentialAccount, ConfidentialAuditors, ConfidentialMoveFunds, ConfidentialTransfers,
        TransactionId, TransactionLeg, TransactionLegId,
    },
    polymesh_primitives::settlement::VenueId,
};
pub use polymesh_api::{Api, TransactionResults};

pub use confidential_assets::{
    elgamal::CipherText, transaction::ConfidentialTransferProof, AssetId, Balance, ElgamalKeys,
    ElgamalPublicKey, ElgamalSecretKey, Scalar,
};

pub fn create_keys() -> ElgamalKeys {
    let mut rng = rand::thread_rng();
    let secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
    let public = secret.get_public_key();
    ElgamalKeys { public, secret }
}

#[derive(Clone)]
pub struct AuditorUser {
    api: Api,
    pub user: User,
    pub keys: ElgamalKeys,
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

    pub fn did(&self) -> Result<IdentityId> {
        self.user
            .did
            .ok_or_else(|| anyhow!("User is missing an identity"))
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
    pub keys: ElgamalKeys,
    account: ConfidentialAccount,
}

impl ConfidentialUser {
    pub fn new(api: &Api, user: User) -> Self {
        let keys = create_keys();
        Self::new_account(api, user, keys)
    }

    fn new_account(api: &Api, user: User, keys: ElgamalKeys) -> Self {
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

    pub fn sub_account(&self) -> Self {
        let keys = create_keys();
        Self::new_account(&self.api, self.user.clone(), keys)
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

    /// Get the account encrypted balance.
    pub async fn account_balance(&self, asset_id: AssetId) -> Result<CipherText> {
        let enc_balance = self
            .api
            .query()
            .confidential_asset()
            .account_balance(self.account(), asset_id)
            .await?
            .and_then(|enc| CipherText::decode(&mut &enc.0[..]).ok())
            .ok_or_else(|| anyhow!("Failed to get account balance."))?;
        Ok(enc_balance)
    }

    pub fn ensure_balance(&self, enc_balance: &CipherText, verify: Balance) -> Result<()> {
        self.decrypt_balance(enc_balance, Some(verify))?;
        Ok(())
    }

    pub fn decrypt_balance(
        &self,
        enc_balance: &CipherText,
        verify: Option<Balance>,
    ) -> Result<Balance> {
        let balance = if let Some(balance) = verify {
            self.keys.verify(enc_balance, &Scalar::from(balance))?;
            balance
        } else {
            self.keys.decrypt(enc_balance)?
        };
        Ok(balance)
    }
}

/// Search transaction events for ConfidentialAsset VenueId.
pub async fn get_venue_id(res: &mut TransactionResults) -> Result<Option<VenueId>> {
    Ok(res.events().await?.and_then(|events| {
        for rec in &events.0 {
            match &rec.event {
                RuntimeEvent::ConfidentialAsset(ConfidentialAssetEvent::VenueCreated {
                    venue_id,
                    ..
                }) => {
                    return Some(*venue_id);
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
                RuntimeEvent::ConfidentialAsset(ConfidentialAssetEvent::AssetCreated {
                    asset_id,
                    ..
                }) => {
                    return Some(*asset_id);
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
                RuntimeEvent::ConfidentialAsset(ConfidentialAssetEvent::TransactionCreated {
                    transaction_id,
                    ..
                }) => {
                    return Some(*transaction_id);
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
                RuntimeEvent::ConfidentialAsset(ConfidentialAssetEvent::TransactionAffirmed {
                    transaction_id,
                    leg_id,
                    party: AffirmParty::Sender(transfers),
                    ..
                }) => {
                    return Some((*transaction_id, *leg_id, Some(transfers.clone())));
                }
                RuntimeEvent::ConfidentialAsset(ConfidentialAssetEvent::TransactionAffirmed {
                    transaction_id,
                    leg_id,
                    ..
                }) => {
                    return Some((*transaction_id, *leg_id, None));
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
