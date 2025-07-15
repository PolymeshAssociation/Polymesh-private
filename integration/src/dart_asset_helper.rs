use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use anyhow::Result;
use codec::{Decode, Encode};

use polymesh_dart::{
    AccountAssetRegistrationProof, AccountPublicKeys, AssetMintingProof, AuditorOrMediator,
    LeafIndex,
};
pub use polymesh_dart::{AccountAssetState, AccountKeys, AssetId as DartAssetId};

pub use polymesh_api::types::polymesh_dart::bp::AccountPublicKeys as ChainAccountPublicKeys;
pub use polymesh_api::{Api, TransactionResults};
pub use polymesh_api_tester::{DartAssetEvent, IdentityId, PolymeshTester, RuntimeEvent, User};

pub mod curve_tree;
pub use curve_tree::*;

/// Search transaction events for DartAsset AssetId.
pub async fn get_asset_id(res: &mut TransactionResults) -> Result<Option<DartAssetId>> {
    Ok(res.events().await?.and_then(|events| {
        for rec in &events.0 {
            match &rec.event {
                RuntimeEvent::DartAsset(DartAssetEvent::AssetCreated { asset_id, .. }) => {
                    return Some(*asset_id);
                }
                _ => (),
            }
        }
        None
    }))
}

/// Search for the new account asset state in the transaction results.
pub async fn get_account_leaf_inserted(
    res: &mut TransactionResults,
) -> Result<Option<(LeafIndex, AccountLeaf)>> {
    Ok(res.events().await?.and_then(|events| {
        for rec in &events.0 {
            match &rec.event {
                RuntimeEvent::DartAsset(DartAssetEvent::AccountStateLeafInserted {
                    leaf_index,
                    account_leaf,
                }) => {
                    return Some((*leaf_index, to_scale(account_leaf)));
                }
                _ => (),
            }
        }
        None
    }))
}

pub fn to_scale<T1: Encode, T2: Decode>(value: &T1) -> T2 {
    let encoded = value.encode();
    Decode::decode(&mut encoded.as_slice()).expect("Failed to decode")
}

pub fn create_keys() -> AccountKeys {
    let mut rng = rand::thread_rng();
    AccountKeys::rand(&mut rng).expect("Failed to create random keys")
}

pub struct DartUserAccountAssetState {
    pub asset_state: AccountAssetState,
    pub leaf_index: Option<LeafIndex>,
}

impl DartUserAccountAssetState {
    pub fn new(asset_state: AccountAssetState) -> Self {
        Self {
            asset_state,
            leaf_index: None,
        }
    }

    pub fn commit_pending_state(&mut self) -> Result<()> {
        self.asset_state.commit_pending_state()?;
        Ok(())
    }

    pub async fn update_leaf_index(&mut self, res: &mut TransactionResults) -> Result<()> {
        if let Some((leaf_index, account_leaf)) = get_account_leaf_inserted(res).await? {
            // Get the expect new account commitment.
            let expected_leaf = if let Some(pending) = &self.asset_state.pending_state {
                pending.commitment()?.as_leaf_value()?
            } else {
                self.asset_state.current_state_commitment.as_leaf_value()?
            };

            // Check that the account leaf matches the expected state commitment.
            eprintln!(
                "Leaf index: {}, account leaf: {:?}, expected leaf: {:?}",
                leaf_index, account_leaf, expected_leaf,
            );
            if account_leaf != expected_leaf {
                return Err(anyhow::anyhow!(
                    "Account leaf does not match the expected state commitment"
                ));
            }
            self.leaf_index = Some(leaf_index);

            // We can commit the pending state now that we have the leaf index.
            self.asset_state.commit_pending_state()?;
        } else {
            return Err(anyhow::anyhow!(
                "Leaf index not found in transaction results"
            ));
        }
        Ok(())
    }

    pub async fn get_path_and_root(
        &self,
        account_tree: &AccountCurveTree,
    ) -> Result<AccountPathAndRoot> {
        let leaf_index = self
            .leaf_index
            .ok_or_else(|| anyhow::anyhow!("Leaf index not set"))?;
        AccountPathAndRoot::lookup(
            account_tree,
            leaf_index,
            self.asset_state.current_state_commitment.as_leaf_value()?,
        )
        .await
    }

    pub fn as_mut(&mut self) -> &mut AccountAssetState {
        &mut self.asset_state
    }
}

/// Dart User
pub struct DartUserInner {
    api: Api,
    pub user: User,
    pub keys: AccountKeys,
    pub assets: BTreeMap<DartAssetId, DartUserAccountAssetState>,
}

impl DartUserInner {
    pub fn new(user: User) -> Self {
        let api = user.api.clone();
        let keys = create_keys();
        Self {
            api,
            user,
            keys,
            assets: BTreeMap::new(),
        }
    }

    pub fn public_keys(&self) -> AccountPublicKeys {
        self.keys.public_keys()
    }

    pub fn did(&self) -> IdentityId {
        self.user.did.unwrap_or_default()
    }

    pub async fn register_account(&mut self) -> Result<()> {
        let keys = self.public_keys();
        self.api
            .call()
            .dart_asset()
            .register_account(to_scale(&keys.acct), to_scale(&keys.enc))?
            .submit_and_watch(&mut self.user)
            .await?;
        Ok(())
    }

    pub async fn register_account_asset(&mut self, asset_id: DartAssetId) -> Result<()> {
        // Generate the account asset registration proof.
        let mut rng = rand::thread_rng();
        let did = self.did();
        let (proof, asset_state) =
            AccountAssetRegistrationProof::new(&mut rng, &self.keys, asset_id, &did.0[..])?;
        let mut asset_state = DartUserAccountAssetState::new(asset_state);

        // Submit the registration proof.
        let mut res = self
            .api
            .call()
            .dart_asset()
            .register_account_asset(to_scale(&proof))?
            .submit_and_watch(&mut self.user)
            .await?;

        // Update the asset state with the new leaf index.
        asset_state.update_leaf_index(&mut res).await?;

        // Store the asset state in the user's assets.
        self.assets.insert(asset_id, asset_state);
        Ok(())
    }

    pub async fn create_asset(
        &mut self,
        description: &str,
        auditor: AuditorOrMediator,
    ) -> Result<DartAssetId> {
        let mut res = self
            .api
            .call()
            .dart_asset()
            .create_asset(to_scale(&auditor), description.as_bytes().to_vec())?
            .submit_and_watch(&mut self.user)
            .await?;

        let asset_id = get_asset_id(&mut res)
            .await?
            .expect("Asset creation failed");

        Ok(asset_id)
    }

    pub async fn mint_asset(
        &mut self,
        account_tree: &AccountCurveTree,
        asset_id: DartAssetId,
        amount: u64,
    ) -> Result<()> {
        // Get our current account asset state.
        let asset_state = self
            .assets
            .get_mut(&asset_id)
            .ok_or_else(|| anyhow::anyhow!("Asset not registered: {}", asset_id))?;

        // Lookup our current account asset state in the on-chain account tree.
        let account_lookup = asset_state.get_path_and_root(account_tree).await?;

        // Generate minting proof.
        let mut rng = rand::thread_rng();
        let proof = AssetMintingProof::new(&mut rng, asset_state.as_mut(), account_lookup, amount)?;

        // Submit the minting proof.
        let mut res = self
            .api
            .call()
            .dart_asset()
            .mint_asset(to_scale(&proof))?
            .submit_and_watch(&mut self.user)
            .await?;

        // Update the asset state with the new leaf index.
        asset_state.update_leaf_index(&mut res).await?;

        Ok(())
    }
}

#[derive(Clone)]
pub struct DartUser(Arc<RwLock<DartUserInner>>);

impl DartUser {
    pub fn new(user: User) -> Self {
        Self(Arc::new(RwLock::new(DartUserInner::new(user))))
    }

    pub fn public_keys(&self) -> AccountPublicKeys {
        self.0.read().unwrap().public_keys()
    }

    pub fn did(&self) -> IdentityId {
        self.0.read().unwrap().did()
    }

    pub async fn register_account(&self) -> Result<()> {
        self.0.write().unwrap().register_account().await
    }

    pub async fn register_account_asset(&self, asset_id: DartAssetId) -> Result<()> {
        self.0
            .write()
            .unwrap()
            .register_account_asset(asset_id)
            .await
    }

    pub async fn create_asset(
        &self,
        description: &str,
        auditor: AuditorOrMediator,
    ) -> Result<DartAssetId> {
        self.0
            .write()
            .unwrap()
            .create_asset(description, auditor)
            .await
    }

    pub async fn mint_asset(
        &self,
        account_tree: &AccountCurveTree,
        asset_id: DartAssetId,
        amount: u64,
    ) -> Result<()> {
        self.0
            .write()
            .unwrap()
            .mint_asset(account_tree, asset_id, amount)
            .await
    }
}

pub struct DartAssetTester {
    pub tester: PolymeshTester,
    pub investors: BTreeMap<String, DartUser>,
    pub auditors: BTreeMap<String, DartUser>,
}

impl DartAssetTester {
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
                .map(|(n, u)| (n.to_string(), DartUser::new(u)))
                .collect(),
            auditors: auditors
                .into_iter()
                .zip(auditor_users.into_iter())
                .map(|(n, u)| (n.to_string(), DartUser::new(u)))
                .collect(),
            tester,
        })
    }

    pub fn investor(&self, name: &str) -> DartUser {
        self.investors.get(name).expect("Investor").clone()
    }

    pub fn auditor(&self, name: &str) -> DartUser {
        self.auditors.get(name).expect("Auditor").clone()
    }

    pub fn api(&self) -> Api {
        self.tester.api.clone()
    }
}
