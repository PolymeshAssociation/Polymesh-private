use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use anyhow::Result;
use codec::{Decode, Encode};

use polymesh_dart::curve_tree::{AccountTreeConfig, LeafPathAndRoot};
use polymesh_dart::{
    curve_tree::get_account_curve_tree_parameters, AccountAssetRegistrationProof,
    AccountPublicKeys, AssetMintingProof, AssetState, Balance as DartBalance, EncryptionPublicKey,
    LeafIndex, LegBuilder, LegEncrypted, LegRef, LegRole, MediatorAffirmationProof,
    ReceiverAffirmationProof, ReceiverClaimProof, SenderAffirmationProof, SenderCounterUpdateProof,
    SenderReversalProof, SettlementBuilder, SettlementProof, SettlementRef, ACCOUNT_TREE_L,
    ACCOUNT_TREE_M,
};
pub use polymesh_dart::{AccountAssetState, AccountKeys, AssetId as DartAssetId};

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

/// Search for the created settlement in the transaction results.
pub async fn get_settlement_ref(res: &mut TransactionResults) -> Result<Option<SettlementRef>> {
    Ok(res.events().await?.and_then(|events| {
        for rec in &events.0 {
            match &rec.event {
                RuntimeEvent::DartAsset(DartAssetEvent::SettlementCreated {
                    settlement_ref,
                    ..
                }) => {
                    return Some(to_scale(settlement_ref));
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

    pub async fn get_path_and_root<'t>(
        &self,
        account_tree: &'t AccountCurveTree,
    ) -> Result<LeafPathAndRoot<'t, ACCOUNT_TREE_L, ACCOUNT_TREE_M, AccountTreeConfig>> {
        let leaf_index = self
            .leaf_index
            .ok_or_else(|| anyhow::anyhow!("Leaf index not set"))?;
        Ok(account_tree.get_path_and_root(leaf_index).await?)
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
    pub registered: bool,
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
            registered: false,
            assets: BTreeMap::new(),
        }
    }

    pub fn public_keys(&self) -> AccountPublicKeys {
        self.keys.public_keys()
    }

    pub fn did(&self) -> IdentityId {
        self.user.did.unwrap_or_default()
    }

    pub fn is_account_asset_registered(&self, asset_id: DartAssetId) -> bool {
        self.assets.contains_key(&asset_id)
    }

    pub async fn register_account(&mut self) -> Result<()> {
        if self.registered {
            return Ok(());
        }
        let keys = self.public_keys();
        self.api
            .call()
            .dart_asset()
            .register_account(to_scale(&keys.acct), to_scale(&keys.enc))?
            .submit_and_watch(&mut self.user)
            .await?;
        self.registered = true;
        Ok(())
    }

    pub async fn register_account_asset(&mut self, asset_id: DartAssetId) -> Result<()> {
        // Check if the account has already been registered for the asset.
        if self.is_account_asset_registered(asset_id) {
            return Ok(());
        }

        // Generate the account asset registration proof.
        let (proof, mut asset_state) = {
            let mut rng = rand::thread_rng();
            let did = self.did();
            let params = get_account_curve_tree_parameters();
            let (proof, asset_state) = AccountAssetRegistrationProof::new(
                &mut rng,
                &self.keys,
                asset_id,
                0,
                &did.0[..],
                params,
            )?;
            let asset_state = DartUserAccountAssetState::new(asset_state);
            (proof, asset_state)
        };

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
        auditors: Vec<EncryptionPublicKey>,
        mediators: Vec<EncryptionPublicKey>,
    ) -> Result<DartAssetId> {
        let mut res = self
            .api
            .call()
            .dart_asset()
            .create_asset(
                to_scale(&auditors),
                to_scale(&mediators),
                description.as_bytes().to_vec(),
            )?
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
        let proof = {
            let mut rng = rand::thread_rng();
            AssetMintingProof::new(&mut rng, asset_state.as_mut(), account_lookup, amount)?
        };

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

    pub async fn create_settlement(&mut self, proof: SettlementProof<()>) -> Result<SettlementRef> {
        // Submit the settlement proof.
        let mut res = self
            .api
            .call()
            .dart_asset()
            .create_settlement(to_scale(&proof))?
            .submit_and_watch(&mut self.user)
            .await?;

        // Get the settlement reference from the transaction results.
        let settlement_ref = get_settlement_ref(&mut res)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Settlement creation failed"))?;

        Ok(settlement_ref)
    }

    pub async fn sender_affirmation(
        &mut self,
        tester: &DartAssetTester,
        leg_ref: LegRef,
        asset_id: DartAssetId,
        amount: DartBalance,
    ) -> Result<()> {
        // Get the encrypted settlement leg from the chain.
        let leg_enc = tester
            .get_settlement_leg(leg_ref)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Settlement leg not found"))?;
        // Try to decrypt the leg as the sender
        let (leg, leg_enc_rand) =
            leg_enc.decrypt_with_randomness(LegRole::Sender, &self.keys.enc)?;

        // Check the leg asset and amount.
        if leg.asset_id() != asset_id || leg.amount() != amount {
            return Err(anyhow::anyhow!(
                "Leg asset or amount does not match: {:?} != {:?}, {} != {}",
                leg.asset_id(),
                asset_id,
                leg.amount(),
                amount
            ));
        }

        // Get our current account asset state.
        let asset_state = self
            .assets
            .get_mut(&asset_id)
            .ok_or_else(|| anyhow::anyhow!("Asset not registered: {}", asset_id))?;

        // Lookup our current account asset state in the on-chain account tree.
        let account_tree = tester.account_tree().await;
        let account_lookup = asset_state.get_path_and_root(&account_tree).await?;

        // Generate minting proof.
        let proof = {
            let mut rng = rand::thread_rng();
            SenderAffirmationProof::new(
                &mut rng,
                &leg_ref,
                amount,
                &leg_enc,
                &leg_enc_rand,
                asset_state.as_mut(),
                account_lookup,
            )?
        };

        // Submit the minting proof.
        let mut res = self
            .api
            .call()
            .dart_asset()
            .sender_affirmation(to_scale(&proof))?
            .submit_and_watch(&mut self.user)
            .await?;

        // Update the asset state with the new leaf index.
        asset_state.update_leaf_index(&mut res).await?;

        Ok(())
    }

    pub async fn receiver_affirmation(
        &mut self,
        tester: &DartAssetTester,
        leg_ref: LegRef,
        asset_id: DartAssetId,
        amount: DartBalance,
    ) -> Result<()> {
        // Get the encrypted settlement leg from the chain.
        let leg_enc = tester
            .get_settlement_leg(leg_ref)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Settlement leg not found"))?;
        // Try to decrypt the leg as the receiver
        let (leg, leg_enc_rand) =
            leg_enc.decrypt_with_randomness(LegRole::Receiver, &self.keys.enc)?;

        // Check the leg asset and amount.
        if leg.asset_id() != asset_id || leg.amount() != amount {
            return Err(anyhow::anyhow!(
                "Leg asset or amount does not match: {:?} != {:?}, {} != {}",
                leg.asset_id(),
                asset_id,
                leg.amount(),
                amount
            ));
        }

        // Get our current account asset state.
        let asset_state = self
            .assets
            .get_mut(&asset_id)
            .ok_or_else(|| anyhow::anyhow!("Asset not registered: {}", asset_id))?;

        // Lookup our current account asset state in the on-chain account tree.
        let account_tree = tester.account_tree().await;
        let account_lookup = asset_state.get_path_and_root(&account_tree).await?;

        // Generate minting proof.
        let proof = {
            let mut rng = rand::thread_rng();
            ReceiverAffirmationProof::new(
                &mut rng,
                &leg_ref,
                &leg_enc,
                &leg_enc_rand,
                asset_state.as_mut(),
                account_lookup,
            )?
        };

        // Submit the minting proof.
        let mut res = self
            .api
            .call()
            .dart_asset()
            .receiver_affirmation(to_scale(&proof))?
            .submit_and_watch(&mut self.user)
            .await?;

        // Update the asset state with the new leaf index.
        asset_state.update_leaf_index(&mut res).await?;

        Ok(())
    }

    pub async fn mediator_affirmation(
        &mut self,
        tester: &DartAssetTester,
        leg_ref: LegRef,
        accept: bool,
        asset_and_amount: Option<(DartAssetId, DartBalance)>,
    ) -> Result<()> {
        // Get the encrypted settlement leg from the chain.
        let leg_enc = tester
            .get_settlement_leg(leg_ref)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Settlement leg not found"))?;

        // Try to decrypt the leg as the mediator
        let leg = leg_enc
            .decrypt(LegRole::Mediator(0), &self.keys.enc)
            .unwrap();

        // Check the leg asset and amount if provided.
        if let Some((asset_id, amount)) = asset_and_amount {
            if leg.asset_id() != asset_id || leg.amount() != amount {
                return Err(anyhow::anyhow!(
                    "Leg asset or amount does not match: {:?} != {:?}, {} != {}",
                    leg.asset_id(),
                    asset_id,
                    leg.amount(),
                    amount
                ));
            }
        }

        // Generate minting proof.
        let proof = {
            let mut rng = rand::thread_rng();
            MediatorAffirmationProof::new(
                &mut rng,
                &leg_ref,
                leg.asset_id,
                &leg_enc,
                &self.keys.enc,
                0,
                accept,
            )?
        };

        // Submit the minting proof.
        self.api
            .call()
            .dart_asset()
            .mediator_affirmation(to_scale(&proof))?
            .submit_and_watch(&mut self.user)
            .await
            .expect("Failed to submit mediator affirmation");

        Ok(())
    }

    pub async fn receiver_claim(
        &mut self,
        tester: &DartAssetTester,
        leg_ref: LegRef,
    ) -> Result<()> {
        // Get the encrypted settlement leg from the chain.
        let leg_enc = tester
            .get_settlement_leg(leg_ref)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Settlement leg not found"))?;

        // Try to decrypt the leg as the receiver
        let (leg, leg_enc_rand) =
            leg_enc.decrypt_with_randomness(LegRole::Receiver, &self.keys.enc)?;
        let asset_id = leg.asset_id();
        let amount = leg.amount();

        // Get our current account asset state.
        let asset_state = self
            .assets
            .get_mut(&asset_id)
            .ok_or_else(|| anyhow::anyhow!("Asset not registered: {}", leg.asset_id()))?;

        // Lookup our current account asset state in the on-chain account tree.
        let account_tree = tester.account_tree().await;
        let account_lookup = asset_state.get_path_and_root(&account_tree).await?;

        // Generate receiver claim proof.
        let proof = {
            let mut rng = rand::thread_rng();
            ReceiverClaimProof::new(
                &mut rng,
                &leg_ref,
                amount,
                &leg_enc,
                &leg_enc_rand,
                asset_state.as_mut(),
                account_lookup,
            )?
        };

        // Submit the minting proof.
        let mut res = self
            .api
            .call()
            .dart_asset()
            .receiver_claim(to_scale(&proof))?
            .submit_and_watch(&mut self.user)
            .await?;

        // Update the asset state with the new leaf index.
        asset_state.update_leaf_index(&mut res).await?;

        Ok(())
    }

    pub async fn sender_counter_update(
        &mut self,
        tester: &DartAssetTester,
        leg_ref: LegRef,
    ) -> Result<()> {
        // Get the encrypted settlement leg from the chain.
        let leg_enc = tester
            .get_settlement_leg(leg_ref)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Settlement leg not found"))?;

        // Try to decrypt the leg as the sender
        let (leg, leg_enc_rand) =
            leg_enc.decrypt_with_randomness(LegRole::Sender, &self.keys.enc)?;

        // Get our current account asset state.
        let asset_state = self
            .assets
            .get_mut(&leg.asset_id())
            .ok_or_else(|| anyhow::anyhow!("Asset not registered: {}", leg.asset_id()))?;

        // Lookup our current account asset state in the on-chain account tree.
        let account_tree = tester.account_tree().await;
        let account_lookup = asset_state.get_path_and_root(&account_tree).await?;

        // Generate sender counter update proof.
        let proof = {
            let mut rng = rand::thread_rng();
            SenderCounterUpdateProof::new(
                &mut rng,
                &leg_ref,
                &leg_enc,
                &leg_enc_rand,
                asset_state.as_mut(),
                account_lookup,
            )?
        };

        // Submit the minting proof.
        let mut res = self
            .api
            .call()
            .dart_asset()
            .sender_update_counter(to_scale(&proof))?
            .submit_and_watch(&mut self.user)
            .await?;

        // Update the asset state with the new leaf index.
        asset_state.update_leaf_index(&mut res).await?;

        Ok(())
    }

    pub async fn sender_revert(&mut self, tester: &DartAssetTester, leg_ref: LegRef) -> Result<()> {
        // Get the encrypted settlement leg from the chain.
        let leg_enc = tester
            .get_settlement_leg(leg_ref)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Settlement leg not found"))?;

        // Try to decrypt the leg as the sender
        let (leg, leg_enc_rand) =
            leg_enc.decrypt_with_randomness(LegRole::Sender, &self.keys.enc)?;
        let asset_id = leg.asset_id();
        let amount = leg.amount();

        // Get our current account asset state.
        let asset_state = self
            .assets
            .get_mut(&asset_id)
            .ok_or_else(|| anyhow::anyhow!("Asset not registered: {}", leg.asset_id()))?;

        // Lookup our current account asset state in the on-chain account tree.
        let account_tree = tester.account_tree().await;
        let account_lookup = asset_state.get_path_and_root(&account_tree).await?;

        // Generate sender revert proof.
        let proof = {
            let mut rng = rand::thread_rng();
            SenderReversalProof::new(
                &mut rng,
                &leg_ref,
                amount,
                &leg_enc,
                &leg_enc_rand,
                asset_state.as_mut(),
                account_lookup,
            )?
        };

        // Submit the minting proof.
        let mut res = self
            .api
            .call()
            .dart_asset()
            .sender_revert(to_scale(&proof))?
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

    pub async fn public_keys(&self) -> AccountPublicKeys {
        self.0.read().await.public_keys()
    }

    pub async fn did(&self) -> IdentityId {
        self.0.read().await.did()
    }

    pub async fn register_account(&self) -> Result<()> {
        self.0.write().await.register_account().await
    }

    pub async fn register_account_asset(&self, asset_id: DartAssetId) -> Result<()> {
        self.0.write().await.register_account_asset(asset_id).await
    }

    pub async fn create_asset(
        &self,
        description: &str,
        auditors: Vec<EncryptionPublicKey>,
        mediators: Vec<EncryptionPublicKey>,
    ) -> Result<DartAssetId> {
        self.0
            .write()
            .await
            .create_asset(description, auditors, mediators)
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
            .await
            .mint_asset(account_tree, asset_id, amount)
            .await
    }

    pub async fn create_settlement(&self, proof: SettlementProof<()>) -> Result<SettlementRef> {
        self.0.write().await.create_settlement(proof).await
    }

    pub async fn sender_affirmation(
        &self,
        tester: &DartAssetTester,
        leg_ref: LegRef,
        asset_id: DartAssetId,
        amount: DartBalance,
    ) -> Result<()> {
        self.0
            .write()
            .await
            .sender_affirmation(tester, leg_ref, asset_id, amount)
            .await
    }

    pub async fn receiver_affirmation(
        &self,
        tester: &DartAssetTester,
        leg_ref: LegRef,
        asset_id: DartAssetId,
        amount: DartBalance,
    ) -> Result<()> {
        self.0
            .write()
            .await
            .receiver_affirmation(tester, leg_ref, asset_id, amount)
            .await
    }

    pub async fn mediator_affirmation(
        &self,
        tester: &DartAssetTester,
        leg_ref: LegRef,
        accept: bool,
        asset_and_amount: Option<(DartAssetId, DartBalance)>,
    ) -> Result<()> {
        self.0
            .write()
            .await
            .mediator_affirmation(tester, leg_ref, accept, asset_and_amount)
            .await
    }

    pub async fn receiver_claim(&self, tester: &DartAssetTester, leg_ref: LegRef) -> Result<()> {
        self.0.write().await.receiver_claim(tester, leg_ref).await
    }
}

pub struct DartAssetTesterInner {
    pub tester: PolymeshTester,
    pub users: BTreeMap<String, DartUser>,
    pub account_tree: AccountCurveTree,
    pub asset_tree: AssetCurveTree,
    pub asset_lookup: BTreeMap<String, DartAssetId>,
    pub assets: BTreeMap<DartAssetId, DartTestAsset>,
}

impl DartAssetTesterInner {
    pub async fn init(user_names: &[&str]) -> Result<Self> {
        let mut tester = PolymeshTester::new().await?;

        let account_tree = AccountCurveTree::new(&tester.api).await?;
        let asset_tree = AssetCurveTree::new(&tester.api).await?;

        // Merge names to create all users in a batch.
        let users = tester.users(user_names).await?;

        Ok(Self {
            users: user_names
                .into_iter()
                .zip(users.into_iter())
                .map(|(n, u)| (n.to_string(), DartUser::new(u)))
                .collect(),
            tester,
            account_tree,
            asset_tree,
            asset_lookup: BTreeMap::new(),
            assets: BTreeMap::new(),
        })
    }

    pub fn user(&self, name: &str) -> DartUser {
        self.users.get(name).expect("Missing Investor").clone()
    }

    pub fn api(&self) -> Api {
        self.tester.api.clone()
    }

    pub async fn get_settlement_leg(&self, leg_ref: LegRef) -> Result<Option<LegEncrypted>> {
        let leg = self
            .api()
            .query()
            .dart_asset()
            .settlement_legs(to_scale(&leg_ref.settlement), leg_ref.leg_id)
            .await?;

        Ok(leg.map(|l| to_scale(&l)))
    }

    pub fn get_named_asset(&self, name: &str) -> Option<DartTestAsset> {
        self.asset_lookup
            .get(name)
            .and_then(|id| self.assets.get(id))
            .cloned()
    }

    pub fn get_asset(&self, asset_id: DartAssetId) -> Option<DartTestAsset> {
        self.assets.get(&asset_id).cloned()
    }

    pub fn register_asset(&mut self, name: String, asset_id: DartAssetId, asset: DartTestAsset) {
        // Store the asset in the lookup map.
        self.asset_lookup.insert(name, asset_id);
        self.assets.insert(asset_id, asset);
    }
}

#[derive(Clone)]
pub struct DartAssetTester(Arc<RwLock<DartAssetTesterInner>>);

impl DartAssetTester {
    pub async fn init(user_names: &[&str]) -> Result<Self> {
        let inner = DartAssetTesterInner::init(user_names).await?;
        Ok(Self(Arc::new(RwLock::new(inner))))
    }

    pub fn spawn<F, Fut>(&self, f: F) -> tokio::task::JoinHandle<Fut::Output>
    where
        F: FnOnce(DartAssetTester) -> Fut,
        Fut: core::future::Future + Send + 'static,
        Fut::Output: Send + 'static,
    {
        let tester = self.clone();
        tokio::spawn(f(tester))
    }

    pub async fn user(&self, name: &str) -> DartUser {
        self.0.read().await.user(name)
    }

    pub async fn api(&self) -> Api {
        self.0.read().await.api()
    }

    pub async fn account_tree(&self) -> AccountCurveTree {
        self.0.read().await.account_tree.clone()
    }

    pub async fn asset_tree(&self) -> AssetCurveTree {
        self.0.read().await.asset_tree.clone()
    }

    pub async fn get_settlement_leg(&self, leg_ref: LegRef) -> Result<Option<LegEncrypted>> {
        self.0.read().await.get_settlement_leg(leg_ref).await
    }

    pub async fn get_named_asset(&self, name: &str) -> Option<DartTestAsset> {
        self.0.read().await.get_named_asset(name)
    }

    pub async fn get_asset(&self, asset_id: DartAssetId) -> Option<DartTestAsset> {
        self.0.read().await.get_asset(asset_id)
    }

    pub async fn register_asset(&self, asset: DartTestAsset) {
        let name = asset.name().await;
        let asset_id = asset.id;
        self.0.write().await.register_asset(name, asset_id, asset);
    }

    pub async fn create_asset(
        &self,
        asset_issuer: &DartUser,
        name: &'static str,
        auditors: &[&DartUser],
        mediators: &[&DartUser],
        mint_amount: Option<DartBalance>,
    ) -> Result<DartTestAsset> {
        // Check if the asset already exists.
        if let Some(asset) = self.0.read().await.get_named_asset(name) {
            // mint more if needed.
            if let Some(amount) = mint_amount {
                asset.mint_more(self, amount).await?;
            }
            return Ok(asset);
        }

        let account_tree = self.account_tree().await;
        // Create a new asset.
        let asset = DartTestAsset::new(
            &account_tree,
            asset_issuer,
            name,
            auditors,
            mediators,
            mint_amount,
        )
        .await?;

        // Register the asset in the tester.
        self.register_asset(asset.clone()).await;

        Ok(asset)
    }
}

pub struct DartTestAssetInner {
    pub id: DartAssetId,
    pub issuer: DartUser,
    pub name: String,
    issuer_balance: DartBalance,
    pub auditors: Vec<DartUser>,
    pub mediators: Vec<DartUser>,
    pub total_supply: DartBalance,
}

impl DartTestAssetInner {
    pub async fn new(
        account_tree: &AccountCurveTree,
        asset_issuer: &DartUser,
        name: &'static str,
        auditors: &[&DartUser],
        mediators: &[&DartUser],
        mint_amount: Option<DartBalance>,
    ) -> Result<Self> {
        assert!(
            (auditors.len() + mediators.len()) >= 1,
            "At least one auditor or mediator is required"
        );

        // Asset issuer register their account.
        asset_issuer.register_account().await?;

        // Create mediator user and keys.
        let mut auditor_keys = Vec::new();
        for &auditor in auditors {
            auditor.register_account().await?;
            auditor_keys.push(auditor.public_keys().await.enc);
        }
        let mut mediator_keys = Vec::new();
        for &mediator in mediators {
            mediator.register_account().await?;
            mediator_keys.push(mediator.public_keys().await.enc);
        }

        // Create the asset.
        let asset_id = asset_issuer
            .create_asset(name, auditor_keys, mediator_keys)
            .await?;

        let mint_amount = mint_amount.unwrap_or(0);
        if mint_amount > 0 {
            // Asset issuer registers the asset.
            asset_issuer.register_account_asset(asset_id).await?;

            // Mint asset proof.
            asset_issuer
                .mint_asset(account_tree, asset_id, mint_amount)
                .await?;
        }

        Ok(Self {
            id: asset_id,
            name: name.to_string(),
            issuer: asset_issuer.clone(),
            issuer_balance: mint_amount,
            auditors: auditors.into_iter().copied().cloned().collect(),
            mediators: mediators.into_iter().copied().cloned().collect(),
            total_supply: mint_amount,
        })
    }

    pub fn has_mediator(&self) -> bool {
        self.mediators.len() > 0
    }

    pub fn mediator(&self) -> Option<DartUser> {
        if self.has_mediator() {
            Some(self.mediators[0].clone())
        } else {
            None
        }
    }

    pub async fn asset_state(&self) -> AssetState {
        let mut auditors = Vec::new();
        for auditor in &self.auditors {
            auditors.push(auditor.public_keys().await.enc);
        }
        let mut mediators = Vec::new();
        for mediator in &self.mediators {
            mediators.push(mediator.public_keys().await.enc);
        }
        AssetState::new(self.id, &auditors, &mediators)
    }

    pub async fn mint_more(&mut self, tester: &DartAssetTester, amount: DartBalance) -> Result<()> {
        // Mint asset proof.
        self.issuer
            .mint_asset(&tester.account_tree().await, self.id, amount)
            .await?;

        // Update the total supply and issuer balance.
        self.total_supply += amount;
        self.issuer_balance += amount;

        Ok(())
    }

    pub async fn take_issuer_funds(
        &mut self,
        tester: &DartAssetTester,
        amount: DartBalance,
    ) -> Result<()> {
        if amount > self.issuer_balance {
            self.mint_more(tester, amount).await?;
        }

        self.issuer_balance -= amount;

        Ok(())
    }

    pub async fn register_investor(&mut self, user: &DartUser) -> Result<()> {
        // Register the account.
        user.register_account().await?;

        // Account asset registration proof.
        user.register_account_asset(self.id).await?;

        Ok(())
    }

    pub async fn register_investors(&mut self, investors: &[&DartUser]) -> Result<()> {
        let asset_id = self.id;
        // Register each investor.
        let mut tasks = Vec::with_capacity(investors.len());
        for &user in investors {
            let user = user.clone();
            tasks.push(tokio::spawn(async move {
                // Register the account.
                user.register_account().await?;

                // Account asset registration proof.
                user.register_account_asset(asset_id).await
            }));
        }
        // Wait for all registrations to complete.
        for task in tasks {
            task.await??; // Propagate any errors.
        }

        Ok(())
    }
}

#[derive(Clone)]
pub struct DartTestAsset {
    pub id: DartAssetId,
    inner: Arc<RwLock<DartTestAssetInner>>,
}

impl DartTestAsset {
    pub async fn new(
        account_tree: &AccountCurveTree,
        asset_issuer: &DartUser,
        name: &'static str,
        auditors: &[&DartUser],
        mediators: &[&DartUser],
        mint_amount: Option<DartBalance>,
    ) -> Result<Self> {
        let inner = DartTestAssetInner::new(
            account_tree,
            asset_issuer,
            name,
            auditors,
            mediators,
            mint_amount,
        )
        .await?;

        Ok(Self {
            id: inner.id,
            inner: Arc::new(RwLock::new(inner)),
        })
    }

    pub fn from_inner(inner: DartTestAssetInner) -> Self {
        Self {
            id: inner.id,
            inner: Arc::new(RwLock::new(inner)),
        }
    }

    pub async fn name(&self) -> String {
        let inner = self.inner.read().await;
        inner.name.clone()
    }

    pub async fn issuer(&self) -> DartUser {
        let inner = self.inner.read().await;
        inner.issuer.clone()
    }

    pub async fn mediator(&self) -> Option<DartUser> {
        let inner = self.inner.read().await;
        inner.mediator()
    }

    pub async fn asset_state(&self) -> AssetState {
        let inner = self.inner.read().await;
        inner.asset_state().await
    }

    pub async fn register_investor(&self, user: &DartUser) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.register_investor(user).await
    }

    pub async fn register_investors(&self, investors: &[&DartUser]) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.register_investors(investors).await
    }

    pub async fn mint_more(&self, tester: &DartAssetTester, amount: DartBalance) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.mint_more(tester, amount).await
    }

    pub async fn register_and_fund_investors(
        &self,
        tester: &DartAssetTester,
        investors: &[&DartUser],
        amount: DartBalance,
    ) -> Result<()> {
        // Get funds from the issuer.
        {
            let mut inner = self.inner.write().await;

            let total_amount = amount * investors.len() as DartBalance;
            inner.take_issuer_funds(tester, total_amount).await?;
        }

        let asset_id = self.id;
        let settlement =
            DartSettlementState::register_and_fund_investors(tester, investors, asset_id, amount)
                .await?;

        // Affirm all the legs in the settlement.
        settlement.affirm_legs(tester).await?;

        // All investors claim their assets.
        settlement.claim_assets(tester).await?;

        Ok(())
    }
}

#[derive(Clone)]
pub struct DartSettlementLegState {
    pub leg_ref: LegRef,
    pub sender: DartUser,
    pub receiver: DartUser,
    pub asset_id: DartAssetId,
    pub amount: DartBalance,
    pub mediator: Option<DartUser>,
}

impl DartSettlementLegState {
    pub async fn sender_affirmation(&self, tester: &DartAssetTester) -> Result<()> {
        self.sender
            .sender_affirmation(tester, self.leg_ref, self.asset_id, self.amount)
            .await?;
        Ok(())
    }

    pub async fn receiver_affirmation(&self, tester: &DartAssetTester) -> Result<()> {
        self.receiver
            .receiver_affirmation(tester, self.leg_ref, self.asset_id, self.amount)
            .await?;
        Ok(())
    }

    pub async fn mediator_affirmation(&self, tester: &DartAssetTester, accept: bool) -> Result<()> {
        if let Some(mediator) = &self.mediator {
            mediator
                .mediator_affirmation(
                    tester,
                    self.leg_ref,
                    accept,
                    Some((self.asset_id, self.amount)),
                )
                .await?;
        }
        Ok(())
    }

    pub async fn affirm_leg(&self, tester: &DartAssetTester) -> Result<()> {
        self.sender_affirmation(tester).await?;
        self.receiver_affirmation(tester).await?;
        self.mediator_affirmation(tester, true).await?;
        Ok(())
    }

    pub async fn receiver_claim(&self, tester: &DartAssetTester) -> Result<()> {
        self.receiver.receiver_claim(tester, self.leg_ref).await?;
        Ok(())
    }
}

pub struct DartLeg {
    pub sender: DartUser,
    pub receiver: DartUser,
    pub asset_id: DartAssetId,
    pub amount: DartBalance,
}

#[derive(Clone)]
pub struct DartSettlementState {
    pub settlement_ref: SettlementRef,
    pub legs: Vec<DartSettlementLegState>,
}

impl DartSettlementState {
    pub async fn new(
        tester: &DartAssetTester,
        venue: &DartUser,
        legs: &[DartLeg],
        memo: Option<&[u8]>,
    ) -> Result<Self> {
        let asset_tree = tester.asset_tree().await;
        let mut asset_paths = AssetLeafPaths::new(&asset_tree).await?;

        // Create the investors and setup settlement legs.
        let mut leg_states = Vec::with_capacity(legs.len());
        let mut settlement = SettlementBuilder::<()>::new(memo.unwrap_or(b"NewSettlement"));
        for (leg_idx, leg) in legs.into_iter().enumerate() {
            let asset_id = leg.asset_id;
            let amount = leg.amount;

            let leg_ref = LegRef {
                settlement: 0.into(),
                leg_id: leg_idx as _,
            };
            // Get the asset details.
            let asset = tester
                .get_asset(asset_id)
                .await
                .ok_or_else(|| anyhow::anyhow!("Asset not registered: {}", asset_id))?;
            let asset_state = asset.asset_state().await;

            // Track the asset's leaf path.
            asset_paths.track_asset(asset_id, &asset_tree).await?;

            settlement = settlement.leg(LegBuilder {
                sender: leg.sender.public_keys().await,
                receiver: leg.receiver.public_keys().await,
                asset: asset_state,
                amount,
            });
            leg_states.push(DartSettlementLegState {
                leg_ref,
                sender: leg.sender.clone(),
                receiver: leg.receiver.clone(),
                asset_id,
                amount,
                mediator: asset.mediator().await,
            });
        }

        // Create the settlement to transfer assets to all investors.
        let proof = {
            let mut rng = rand::thread_rng();
            settlement.encryt_and_prove(&mut rng, asset_paths)?
        };
        // Submit the settlement proof.
        let settlement_ref = venue.create_settlement(proof).await?;

        // Correct the settlement reference in the legs.
        for leg in &mut leg_states {
            leg.leg_ref.settlement = settlement_ref;
        }

        let settlement = Self {
            settlement_ref,
            legs: leg_states,
        };

        Ok(settlement)
    }

    pub async fn register_and_fund_investors(
        tester: &DartAssetTester,
        investors: &[&DartUser],
        asset_id: DartAssetId,
        amount: DartBalance,
    ) -> Result<Self> {
        let asset = tester
            .get_asset(asset_id)
            .await
            .ok_or_else(|| anyhow::anyhow!("Asset not registered: {}", asset_id))?;
        let issuer = asset.issuer().await;

        // Register all investors for the asset.
        asset.register_investors(investors).await?;

        let legs = investors
            .into_iter()
            .map(|&investor| DartLeg {
                sender: issuer.clone(),
                receiver: investor.clone(),
                asset_id,
                amount,
            })
            .collect::<Vec<_>>();

        Ok(Self::new(tester, &issuer, &legs, Some(b"FundInvestors")).await?)
    }

    pub async fn senders_affirm_legs(&self, tester: &DartAssetTester) -> Result<()> {
        // All senders affirm their legs.
        for leg in &self.legs {
            leg.sender_affirmation(tester).await?;
        }
        Ok(())
    }

    pub async fn receivers_affirm_legs(&self, tester: &DartAssetTester) -> Result<()> {
        // All receivers affirm their legs.
        for leg in &self.legs {
            leg.receiver_affirmation(tester).await?;
        }
        Ok(())
    }

    pub async fn mediators_affirm_legs(
        &self,
        tester: &DartAssetTester,
        accept: bool,
    ) -> Result<()> {
        // All mediators affirm their legs.
        for leg in &self.legs {
            leg.mediator_affirmation(tester, accept).await?;
        }
        Ok(())
    }

    pub async fn affirm_legs(&self, tester: &DartAssetTester) -> Result<()> {
        // Affirm all the legs in the settlement.
        let mut tasks = Vec::with_capacity(self.legs.len());
        for leg in &self.legs {
            // Sender affirm task.
            {
                let tester = tester.clone();
                let leg = leg.clone();
                tasks.push(tokio::spawn(async move {
                    leg.sender_affirmation(&tester).await
                }));
            }
            // Receiver affirm task.
            {
                let tester = tester.clone();
                let leg = leg.clone();
                tasks.push(tokio::spawn(async move {
                    leg.receiver_affirmation(&tester).await
                }));
            }
            // Mediator affirm task.
            if leg.mediator.is_some() {
                let tester = tester.clone();
                let leg = leg.clone();
                tasks.push(tokio::spawn(async move {
                    leg.mediator_affirmation(&tester, true).await
                }));
            }
        }
        // Wait for all tasks to complete.
        for task in tasks {
            task.await??;
        }
        Ok(())
    }

    pub async fn claim_assets(&self, tester: &DartAssetTester) -> Result<()> {
        // All investors claim their assets.
        let mut tasks = Vec::with_capacity(self.legs.len());
        for leg in &self.legs {
            // Investor claims the assets.
            {
                let tester = tester.clone();
                let leg = leg.clone();
                tasks.push(tokio::spawn(
                    async move { leg.receiver_claim(&tester).await },
                ));
            }
        }
        // Wait for all tasks to complete.
        for task in tasks {
            task.await??;
        }
        Ok(())
    }
}
