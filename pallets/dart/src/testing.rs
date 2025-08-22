use rand_chacha::ChaCha20Rng as StdRng;

use frame_support::assert_ok;
use sp_std::cell::RefCell;
use sp_std::collections::btree_map::BTreeMap;
use sp_std::rc::Rc;
use sp_std::vec::Vec;

use pallet_identity::benchmarking::{user, User};

use polymesh_dart::{
    curve_tree::ProverCurveTree, AccountAssetRegistrationProof, AccountAssetState, AccountKeys,
    AccountPublicKeys, AssetMintingProof, AssetState, Balance as DartBalance, LegBuilder, LegRole,
    MediatorAffirmationProof, ReceiverAffirmationProof, ReceiverClaimProof, SenderAffirmationProof,
    SenderCounterUpdateProof, SenderReversalProof, SettlementBuilder, ACCOUNT_TREE_GENS,
    ACCOUNT_TREE_L, ACCOUNT_TREE_M, ASSET_TREE_GENS, ASSET_TREE_L, ASSET_TREE_M,
};

use crate::*;

pub(crate) const SEED: u32 = 42;
pub(crate) const TICKER_SEED: u32 = 10_000_000;
pub(crate) const AUDITOR_SEED: u32 = 10_000;

pub type AccountProverCurveTree<T> = ProverCurveTree<
    ACCOUNT_TREE_L,
    ACCOUNT_TREE_M,
    AccountTreeConfig,
    AccountCurveTreeStorage<T>,
    Error<T>,
>;

pub fn get_prover_account_curve_tree<T: Config>() -> AccountProverCurveTree<T> {
    AccountProverCurveTree::new(ACCOUNT_TREE_HEIGHT, ACCOUNT_TREE_GENS)
        .expect("Failed to create prover curve tree")
}

pub type AssetProverCurveTree<T> = ProverCurveTree<
    ASSET_TREE_L,
    ASSET_TREE_M,
    AssetTreeConfig,
    AssetCurveTreeStorage<T>,
    Error<T>,
>;

pub fn get_prover_asset_curve_tree<T: Config>() -> AssetProverCurveTree<T> {
    AssetProverCurveTree::new(ASSET_TREE_HEIGHT, ASSET_TREE_GENS)
        .expect("Failed to create prover curve tree")
}

pub struct OffchainProverState<T: Config> {
    pub account_tree: AccountProverCurveTree<T>,
    pub asset_tree: AssetProverCurveTree<T>,
}

impl<T: Config> OffchainProverState<T> {
    pub fn new() -> Self {
        Self {
            account_tree: get_prover_account_curve_tree(),
            asset_tree: get_prover_asset_curve_tree(),
        }
    }

    pub fn apply_new_leaves(&mut self) {
        // Update the curve tree roots.
        Pallet::<T>::update_curve_tree_roots();

        self.account_tree.apply_new_leaves();
        self.asset_tree.apply_new_leaves();
    }

    pub fn get_settlement_leg(&self, leg_ref: LegRef) -> DartSettlementLeg<T> {
        SettlementLegs::<T>::get((leg_ref.settlement, leg_ref.leg_id))
            .expect("Failed to get settlement leg")
    }
}

pub struct DartUserInner<T: Config> {
    pub user: User<T>,
    pub keys: AccountKeys,
    pub assets: BTreeMap<DartAssetId, AccountAssetState>,
}

impl<T: Config> DartUserInner<T> {
    pub fn new(name: &'static str, rng: &mut StdRng) -> Self {
        Self::new_from_seed(name, SEED, rng)
    }

    pub fn asset_user(name: &'static str, asset: u32, user_idx: u32, rng: &mut StdRng) -> Self {
        Self::new_from_seed(name, (asset + 1) * TICKER_SEED + user_idx, rng)
    }

    pub fn auditor_user(
        name: &'static str,
        asset: u32,
        auditor_idx: u32,
        rng: &mut StdRng,
    ) -> Self {
        Self::new_from_seed(
            name,
            (asset + 1) * TICKER_SEED + (auditor_idx + 1) * AUDITOR_SEED,
            rng,
        )
    }

    fn gen_keys(rng: &mut StdRng) -> AccountKeys {
        AccountKeys::rand(rng).expect("Failed to generate random keys")
    }

    fn new_from_seed(name: &'static str, seed: u32, rng: &mut StdRng) -> Self {
        let user = user::<T>(name, seed);
        let keys = Self::gen_keys(rng);
        Self {
            user,
            keys,
            assets: BTreeMap::new(),
        }
    }

    pub fn new_account(&self, rng: &mut StdRng) -> Self {
        let user = Self {
            user: self.user.clone(),
            keys: Self::gen_keys(rng),
            assets: BTreeMap::new(),
        };
        user.register_account();
        user
    }

    pub fn public_keys(&self) -> AccountPublicKeys {
        self.keys.public_keys()
    }

    pub fn did(&self) -> IdentityId {
        self.user.did()
    }

    pub fn origin(&self) -> <T as frame_system::Config>::RuntimeOrigin {
        self.user.origin().into()
    }

    pub fn raw_origin(&self) -> frame_system::RawOrigin<T::AccountId> {
        self.user.origin()
    }

    pub fn register_account(&self) {
        assert_ok!(Pallet::<T>::register_account(
            self.origin(),
            self.keys.acct.public,
            self.keys.enc.public
        ));
    }

    pub fn register_account_asset_proof(
        &mut self,
        rng: &mut StdRng,
        asset_id: DartAssetId,
    ) -> (AccountAssetRegistrationProof, AccountAssetState) {
        assert!(
            !self.assets.contains_key(&asset_id),
            "Asset already registered"
        );
        let tree_params = Pallet::<T>::get_account_curve_tree_parameters();
        AccountAssetRegistrationProof::new(
            rng,
            &self.keys,
            asset_id,
            0,
            &self.did().0[..],
            tree_params,
        )
        .expect("Failed to generate account asset registration proof")
    }

    pub fn register_account_asset(&mut self, rng: &mut StdRng, asset_id: DartAssetId) {
        let (proof, mut account_state) = self.register_account_asset_proof(rng, asset_id);

        assert_ok!(Pallet::<T>::register_account_asset(self.origin(), proof));

        // Commit the pending state to the account state.
        account_state
            .commit_pending_state()
            .expect("Failed to commit pending state");

        self.assets.insert(asset_id, account_state);
    }

    pub fn mint_asset_proof(
        &mut self,
        rng: &mut StdRng,
        off_chain: &OffchainProverState<T>,
        asset_id: DartAssetId,
        amount: DartBalance,
    ) -> (AssetMintingProof<AccountTreeConfig>, &mut AccountAssetState) {
        let account_state = self
            .assets
            .get_mut(&asset_id)
            .expect("Asset not registered for user");

        let proof = AssetMintingProof::new(rng, account_state, &off_chain.account_tree, amount)
            .expect("Failed to generate mint asset proof");
        (proof, account_state)
    }

    pub fn mint_asset(
        &mut self,
        rng: &mut StdRng,
        off_chain: &OffchainProverState<T>,
        asset_id: DartAssetId,
        amount: DartBalance,
    ) {
        let origin = self.origin();
        let (mint_proof, account_state) = self.mint_asset_proof(rng, off_chain, asset_id, amount);

        assert_ok!(Pallet::<T>::mint_asset(origin, mint_proof));

        // Update pending state in the account state.
        account_state
            .commit_pending_state()
            .expect("Failed to commit pending state");
    }

    pub fn sender_affirmation_proof(
        &mut self,
        rng: &mut StdRng,
        off_chain: &OffchainProverState<T>,
        leg_ref: LegRef,
        asset_id: DartAssetId,
        amount: DartBalance,
    ) -> (
        SenderAffirmationProof<AccountTreeConfig>,
        &mut AccountAssetState,
    ) {
        let leg_enc = off_chain.get_settlement_leg(leg_ref).enc;

        // Decrypt leg.
        let (leg, leg_enc_rand) = leg_enc
            .decrypt_with_randomness(LegRole::Sender, &self.keys.enc)
            .expect("Failed to decrypt leg");

        assert!(
            asset_id == leg.asset_id(),
            "Asset ID mismatch in encrypted leg"
        );
        assert!(amount == leg.amount(), "Amount mismatch in encrypted leg");

        // Get the account state for the asset.
        let account_state = self
            .assets
            .get_mut(&asset_id)
            .expect("Asset not registered for user");

        // Generate the sender affirmation proof.
        let proof = SenderAffirmationProof::new(
            rng,
            &leg_ref,
            amount,
            &leg_enc,
            &leg_enc_rand,
            account_state,
            &off_chain.account_tree,
        )
        .expect("Failed to generate sender affirmation proof");

        (proof, account_state)
    }

    pub fn sender_affirmation(
        &mut self,
        rng: &mut StdRng,
        off_chain: &OffchainProverState<T>,
        leg_ref: LegRef,
        asset_id: DartAssetId,
        amount: DartBalance,
    ) {
        let origin = self.origin();
        let (proof, account_state) =
            self.sender_affirmation_proof(rng, off_chain, leg_ref, asset_id, amount);

        assert_ok!(Pallet::<T>::sender_affirmation(origin, proof));

        // Update pending state in the account state.
        account_state
            .commit_pending_state()
            .expect("Failed to commit pending state");
    }

    pub fn receiver_affirmation_proof(
        &mut self,
        rng: &mut StdRng,
        off_chain: &OffchainProverState<T>,
        leg_ref: LegRef,
        asset_id: DartAssetId,
        amount: DartBalance,
    ) -> (
        ReceiverAffirmationProof<AccountTreeConfig>,
        &mut AccountAssetState,
    ) {
        let leg_enc = off_chain.get_settlement_leg(leg_ref).enc;
        // Decrypt leg.
        let (leg, leg_enc_rand) = leg_enc
            .decrypt_with_randomness(LegRole::Receiver, &self.keys.enc)
            .expect("Failed to decrypt leg");

        assert!(
            asset_id == leg.asset_id(),
            "Asset ID mismatch in encrypted leg"
        );
        assert!(amount == leg.amount(), "Amount mismatch in encrypted leg");

        // Get the account state for the asset.
        let account_state = self
            .assets
            .get_mut(&asset_id)
            .expect("Asset not registered for user");

        // Generate the receiver affirmation proof.
        let proof = ReceiverAffirmationProof::new(
            rng,
            &leg_ref,
            &leg_enc,
            &leg_enc_rand,
            account_state,
            &off_chain.account_tree,
        )
        .expect("Failed to generate receiver affirmation proof");

        (proof, account_state)
    }

    pub fn receiver_affirmation(
        &mut self,
        rng: &mut StdRng,
        off_chain: &OffchainProverState<T>,
        leg_ref: LegRef,
        asset_id: DartAssetId,
        amount: DartBalance,
    ) {
        let origin = self.origin();
        let (proof, account_state) =
            self.receiver_affirmation_proof(rng, off_chain, leg_ref, asset_id, amount);

        assert_ok!(Pallet::<T>::receiver_affirmation(origin, proof));

        // Update pending state in the account state.
        account_state
            .commit_pending_state()
            .expect("Failed to commit pending state");
    }

    pub fn receiver_claim_proof(
        &mut self,
        rng: &mut StdRng,
        off_chain: &OffchainProverState<T>,
        leg_ref: LegRef,
    ) -> (
        ReceiverClaimProof<AccountTreeConfig>,
        &mut AccountAssetState,
    ) {
        let leg_enc = off_chain.get_settlement_leg(leg_ref).enc;
        let (leg, leg_enc_rand) = leg_enc
            .decrypt_with_randomness(LegRole::Receiver, &self.keys.enc)
            .expect("Failed to decrypt leg");
        let asset_id = leg.asset_id();
        let amount = leg.amount();

        // Get the account state for the asset.
        let account_state = self
            .assets
            .get_mut(&asset_id)
            .expect("Asset not registered for user");

        // Generate the receiver claim proof.
        let proof = ReceiverClaimProof::new(
            rng,
            &leg_ref,
            amount,
            &leg_enc,
            &leg_enc_rand,
            account_state,
            &off_chain.account_tree,
        )
        .expect("Failed to generate receiver claim proof");

        (proof, account_state)
    }

    pub fn receiver_claim(
        &mut self,
        rng: &mut StdRng,
        off_chain: &OffchainProverState<T>,
        leg_ref: LegRef,
    ) {
        let origin = self.origin();
        let (proof, account_state) = self.receiver_claim_proof(rng, off_chain, leg_ref);

        assert_ok!(Pallet::<T>::receiver_claim(origin, proof));

        // Update pending state in the account state.
        account_state
            .commit_pending_state()
            .expect("Failed to commit pending state");
    }

    pub fn sender_revert_proof(
        &mut self,
        rng: &mut StdRng,
        off_chain: &OffchainProverState<T>,
        leg_ref: LegRef,
    ) -> (
        SenderReversalProof<AccountTreeConfig>,
        &mut AccountAssetState,
    ) {
        let leg_enc = off_chain.get_settlement_leg(leg_ref).enc;
        let (leg, leg_enc_rand) = leg_enc
            .decrypt_with_randomness(LegRole::Sender, &self.keys.enc)
            .expect("Failed to decrypt leg");
        let asset_id = leg.asset_id();
        let amount = leg.amount();

        // Get the account state for the asset.
        let account_state = self
            .assets
            .get_mut(&asset_id)
            .expect("Asset not registered for user");

        // Generate the sender revert proof.
        let proof = SenderReversalProof::new(
            rng,
            &leg_ref,
            amount,
            &leg_enc,
            &leg_enc_rand,
            account_state,
            &off_chain.account_tree,
        )
        .expect("Failed to generate sender revert proof");

        (proof, account_state)
    }

    pub fn sender_revert(
        &mut self,
        rng: &mut StdRng,
        off_chain: &OffchainProverState<T>,
        leg_ref: LegRef,
    ) {
        let origin = self.origin();
        let (proof, account_state) = self.sender_revert_proof(rng, off_chain, leg_ref);

        assert_ok!(Pallet::<T>::sender_revert(origin, proof));

        // Update pending state in the account state.
        account_state
            .commit_pending_state()
            .expect("Failed to commit pending state");
    }

    pub fn sender_counter_update_proof(
        &mut self,
        rng: &mut StdRng,
        off_chain: &OffchainProverState<T>,
        leg_ref: LegRef,
    ) -> (
        SenderCounterUpdateProof<AccountTreeConfig>,
        &mut AccountAssetState,
    ) {
        let leg_enc = off_chain.get_settlement_leg(leg_ref).enc;
        let (leg, leg_enc_rand) = leg_enc
            .decrypt_with_randomness(LegRole::Sender, &self.keys.enc)
            .expect("Failed to decrypt leg");
        let asset_id = leg.asset_id();

        // Get the account state for the asset.
        let account_state = self
            .assets
            .get_mut(&asset_id)
            .expect("Asset not registered for user");

        // Generate the sender counter update proof.
        let proof = SenderCounterUpdateProof::new(
            rng,
            &leg_ref,
            &leg_enc,
            &leg_enc_rand,
            account_state,
            &off_chain.account_tree,
        )
        .expect("Failed to generate sender counter update proof");

        (proof, account_state)
    }

    pub fn sender_counter_update(
        &mut self,
        rng: &mut StdRng,
        off_chain: &OffchainProverState<T>,
        leg_ref: LegRef,
    ) {
        let origin = self.origin();
        let (proof, account_state) = self.sender_counter_update_proof(rng, off_chain, leg_ref);

        assert_ok!(Pallet::<T>::sender_update_counter(origin, proof));

        // Update pending state in the account state.
        account_state
            .commit_pending_state()
            .expect("Failed to commit pending state");
    }

    pub fn mediator_affirmation_proof(
        &self,
        rng: &mut StdRng,
        off_chain: &OffchainProverState<T>,
        leg_ref: LegRef,
        accept: bool,
        verify: Option<(DartAssetId, DartBalance)>,
    ) -> MediatorAffirmationProof {
        let leg_enc = off_chain.get_settlement_leg(leg_ref).enc;
        let leg = leg_enc
            .decrypt(LegRole::Mediator(0), &self.keys.enc)
            .expect("Failed to decrypt leg");

        if let Some((asset_id, amount)) = verify {
            assert!(
                asset_id == leg.asset_id,
                "Asset ID mismatch in encrypted leg"
            );
            assert!(amount == leg.amount(), "Amount mismatch in encrypted leg");
        }

        // Generate the mediator affirmation proof.
        MediatorAffirmationProof::new(
            rng,
            &leg_ref,
            leg.asset_id,
            &leg_enc,
            &self.keys.enc,
            0,
            accept,
        )
        .expect("Failed to generate mediator affirmation proof")
    }

    pub fn mediator_affirmation(
        &self,
        rng: &mut StdRng,
        off_chain: &OffchainProverState<T>,
        leg_ref: LegRef,
        accept: bool,
        verify: Option<(DartAssetId, DartBalance)>,
    ) {
        let origin = self.origin();
        let proof = self.mediator_affirmation_proof(rng, off_chain, leg_ref, accept, verify);

        assert_ok!(Pallet::<T>::mediator_affirmation(origin, proof));
    }
}

#[derive(Clone)]
pub struct DartUser<T: Config>(Rc<RefCell<DartUserInner<T>>>);

impl<T: Config> DartUser<T> {
    pub fn new(name: &'static str, rng: &mut StdRng) -> Self {
        Self(Rc::new(RefCell::new(DartUserInner::new(name, rng))))
    }

    pub fn asset_user(name: &'static str, asset: u32, user_idx: u32, rng: &mut StdRng) -> Self {
        Self(Rc::new(RefCell::new(DartUserInner::asset_user(
            name, asset, user_idx, rng,
        ))))
    }

    pub fn auditor_user(
        name: &'static str,
        asset: u32,
        auditor_idx: u32,
        rng: &mut StdRng,
    ) -> Self {
        Self(Rc::new(RefCell::new(DartUserInner::auditor_user(
            name,
            asset,
            auditor_idx,
            rng,
        ))))
    }

    pub fn public_keys(&self) -> AccountPublicKeys {
        let inner = self.0.borrow();
        inner.keys.public_keys()
    }

    pub fn did(&self) -> IdentityId {
        let inner = self.0.borrow();
        inner.user.did()
    }

    pub fn origin(&self) -> <T as frame_system::Config>::RuntimeOrigin {
        let inner = self.0.borrow();
        inner.user.origin().into()
    }

    pub fn raw_origin(&self) -> frame_system::RawOrigin<T::AccountId> {
        let inner = self.0.borrow();
        inner.user.origin()
    }

    pub fn register_account(&self) {
        let inner = self.0.borrow();
        assert_ok!(Pallet::<T>::register_account(
            inner.origin(),
            inner.keys.acct.public,
            inner.keys.enc.public
        ));
    }

    pub fn register_account_asset_proof(
        &self,
        rng: &mut StdRng,
        asset_id: DartAssetId,
    ) -> (AccountAssetRegistrationProof, AccountAssetState) {
        let mut inner = self.0.borrow_mut();
        inner.register_account_asset_proof(rng, asset_id)
    }

    pub fn register_account_asset(&self, rng: &mut StdRng, asset_id: DartAssetId) {
        let mut inner = self.0.borrow_mut();
        inner.register_account_asset(rng, asset_id);
    }

    pub fn mint_asset_proof(
        &self,
        rng: &mut StdRng,
        off_chain: &OffchainProverState<T>,
        asset_id: DartAssetId,
        amount: DartBalance,
    ) -> (AssetMintingProof<AccountTreeConfig>, AccountAssetState) {
        let mut inner = self.0.borrow_mut();
        let (proof, account_state) = inner.mint_asset_proof(rng, off_chain, asset_id, amount);

        (proof, account_state.clone())
    }

    pub fn mint_asset(
        &self,
        rng: &mut StdRng,
        off_chain: &OffchainProverState<T>,
        asset_id: DartAssetId,
        amount: DartBalance,
    ) {
        let mut inner = self.0.borrow_mut();
        inner.mint_asset(rng, off_chain, asset_id, amount);
    }

    pub fn sender_affirmation_proof(
        &self,
        rng: &mut StdRng,
        off_chain: &OffchainProverState<T>,
        leg_ref: LegRef,
        asset_id: DartAssetId,
        amount: DartBalance,
    ) -> (SenderAffirmationProof<AccountTreeConfig>, AccountAssetState) {
        let mut inner = self.0.borrow_mut();
        let (proof, account_state) =
            inner.sender_affirmation_proof(rng, off_chain, leg_ref, asset_id, amount);
        (proof, account_state.clone())
    }

    pub fn sender_affirmation(
        &self,
        rng: &mut StdRng,
        off_chain: &OffchainProverState<T>,
        leg_ref: LegRef,
        asset_id: DartAssetId,
        amount: DartBalance,
    ) {
        let mut inner = self.0.borrow_mut();
        inner.sender_affirmation(rng, off_chain, leg_ref, asset_id, amount);
    }

    pub fn receiver_affirmation_proof(
        &self,
        rng: &mut StdRng,
        off_chain: &OffchainProverState<T>,
        leg_ref: LegRef,
        asset_id: DartAssetId,
        amount: DartBalance,
    ) -> (
        ReceiverAffirmationProof<AccountTreeConfig>,
        AccountAssetState,
    ) {
        let mut inner = self.0.borrow_mut();
        let (proof, account_state) =
            inner.receiver_affirmation_proof(rng, off_chain, leg_ref, asset_id, amount);
        (proof, account_state.clone())
    }

    pub fn receiver_affirmation(
        &self,
        rng: &mut StdRng,
        off_chain: &OffchainProverState<T>,
        leg_ref: LegRef,
        asset_id: DartAssetId,
        amount: DartBalance,
    ) {
        let mut inner = self.0.borrow_mut();
        inner.receiver_affirmation(rng, off_chain, leg_ref, asset_id, amount);
    }

    pub fn receiver_claim_proof(
        &self,
        rng: &mut StdRng,
        off_chain: &OffchainProverState<T>,
        leg_ref: LegRef,
    ) -> (ReceiverClaimProof<AccountTreeConfig>, AccountAssetState) {
        let mut inner = self.0.borrow_mut();
        let (proof, account_state) = inner.receiver_claim_proof(rng, off_chain, leg_ref);

        (proof, account_state.clone())
    }

    pub fn receiver_claim(
        &self,
        rng: &mut StdRng,
        off_chain: &OffchainProverState<T>,
        leg_ref: LegRef,
    ) {
        let mut inner = self.0.borrow_mut();
        inner.receiver_claim(rng, off_chain, leg_ref);
    }

    pub fn sender_revert_proof(
        &self,
        rng: &mut StdRng,
        off_chain: &OffchainProverState<T>,
        leg_ref: LegRef,
    ) -> (SenderReversalProof<AccountTreeConfig>, AccountAssetState) {
        let mut inner = self.0.borrow_mut();
        let (proof, account_state) = inner.sender_revert_proof(rng, off_chain, leg_ref);

        (proof, account_state.clone())
    }

    pub fn sender_revert(
        &self,
        rng: &mut StdRng,
        off_chain: &OffchainProverState<T>,
        leg_ref: LegRef,
    ) {
        let mut inner = self.0.borrow_mut();
        inner.sender_revert(rng, off_chain, leg_ref);
    }

    pub fn sender_counter_update_proof(
        &self,
        rng: &mut StdRng,
        off_chain: &OffchainProverState<T>,
        leg_ref: LegRef,
    ) -> (
        SenderCounterUpdateProof<AccountTreeConfig>,
        AccountAssetState,
    ) {
        let mut inner = self.0.borrow_mut();
        let (proof, account_state) = inner.sender_counter_update_proof(rng, off_chain, leg_ref);

        (proof, account_state.clone())
    }

    pub fn sender_counter_update(
        &self,
        rng: &mut StdRng,
        off_chain: &OffchainProverState<T>,
        leg_ref: LegRef,
    ) {
        let mut inner = self.0.borrow_mut();
        inner.sender_counter_update(rng, off_chain, leg_ref);
    }

    pub fn mediator_affirmation_proof(
        &self,
        rng: &mut StdRng,
        off_chain: &OffchainProverState<T>,
        leg_ref: LegRef,
        accept: bool,
        verify: Option<(DartAssetId, DartBalance)>,
    ) -> MediatorAffirmationProof {
        let inner = self.0.borrow();
        inner.mediator_affirmation_proof(rng, off_chain, leg_ref, accept, verify)
    }

    pub fn mediator_affirmation(
        &self,
        rng: &mut StdRng,
        off_chain: &OffchainProverState<T>,
        leg_ref: LegRef,
        accept: bool,
        verify: Option<(DartAssetId, DartBalance)>,
    ) {
        let inner = self.0.borrow();
        inner.mediator_affirmation(rng, off_chain, leg_ref, accept, verify);
    }
}

pub struct DartTestAsset<T: Config> {
    pub id: DartAssetId,
    asset_idx: u32,
    idx: u32,
    pub issuer: DartUser<T>,
    issuer_balance: DartBalance,
    pub auditors: Vec<DartUser<T>>,
    pub mediators: Vec<DartUser<T>>,
    pub total_supply: DartBalance,
}

impl<T: Config> DartTestAsset<T> {
    pub fn new(
        rng: &mut StdRng,
        off_chain: &mut OffchainProverState<T>,
        name: &'static str,
        asset_idx: u32,
        auditor_count: u32,
        mediator_count: u32,
        mint_amount: Option<DartBalance>,
    ) -> Self {
        assert!(
            (auditor_count + mediator_count) >= 1,
            "At least one auditor or mediator is required"
        );

        // Create an asset issuer and create an asset.
        let asset_issuer = DartUser::<T>::asset_user(name, asset_idx, 0, rng);

        // Register the asset issuer's account.
        asset_issuer.register_account();

        // Create auditors and mediators.
        let mut auditors = Vec::new();
        let mut auditor_keys = BoundedVec::new();
        for i in 0..auditor_count {
            let auditor = DartUser::<T>::auditor_user("Auditor", asset_idx, i, rng);
            // Register the auditor's keys.
            auditor.register_account();
            auditor_keys
                .try_push(auditor.public_keys().enc)
                .expect("Failed to push auditor keys");
            auditors.push(auditor);
        }
        let mut mediators = Vec::new();
        let mut mediator_keys = BoundedVec::new();
        for i in 0..mediator_count {
            let mediator = DartUser::<T>::auditor_user("Mediator", asset_idx, i, rng);
            // Register the mediator's keys.
            mediator.register_account();
            mediator_keys
                .try_push(mediator.public_keys().enc)
                .expect("Failed to push mediator keys");
            mediators.push(mediator);
        }

        // Asset Data.
        let data = b"Test Asset"
            .to_vec()
            .try_into()
            .expect("Failed to convert asset data to AssetData");

        // Create the asset.
        let asset_id =
            Pallet::<T>::base_create_asset(asset_issuer.did(), auditor_keys, mediator_keys, data)
                .expect("Failed to create asset");

        // Need to update the asset curve tree.
        off_chain.apply_new_leaves();

        let mint_amount = mint_amount.unwrap_or(0);
        if mint_amount > 0 {
            // Asset issuer registers the asset.
            asset_issuer.register_account_asset(rng, asset_id);

            // Update the curve tree roots.
            off_chain.apply_new_leaves();

            // Mint asset proof.
            asset_issuer.mint_asset(rng, &off_chain, asset_id, mint_amount);

            // Update the curve tree roots.
            off_chain.apply_new_leaves();
        }

        Self {
            id: asset_id,
            asset_idx,
            idx: 0,
            issuer: asset_issuer,
            issuer_balance: mint_amount,
            mediators,
            auditors,
            total_supply: mint_amount,
        }
    }

    pub fn has_mediator(&self) -> bool {
        self.mediators.len() > 0
    }

    pub fn mediator(&self) -> Option<DartUser<T>> {
        self.mediators.get(0).cloned()
    }

    pub fn asset_state(&self) -> AssetState {
        let auditors = self
            .auditors
            .iter()
            .map(|a| a.public_keys().enc)
            .collect::<Vec<_>>();
        let mediators = self
            .mediators
            .iter()
            .map(|m| m.public_keys().enc)
            .collect::<Vec<_>>();
        AssetState::new(self.id, &auditors, &mediators)
    }

    pub fn mint_more(
        &mut self,
        rng: &mut StdRng,
        off_chain: &mut OffchainProverState<T>,
        amount: DartBalance,
    ) {
        // Mint asset proof.
        self.issuer.mint_asset(rng, off_chain, self.id, amount);

        // Update the curve tree roots.
        off_chain.apply_new_leaves();

        // Update the total supply and issuer balance.
        self.total_supply += amount;
        self.issuer_balance += amount;
    }

    pub fn create_investor(&mut self, rng: &mut StdRng) -> DartUser<T> {
        let idx = self.idx + 1;
        self.idx = idx;
        // Create a user to invest in the asset.
        let user = DartUser::<T>::asset_user("Investor", self.asset_idx, idx, rng);

        // Register the account.
        user.register_account();

        // Account asset registration proof.
        user.register_account_asset(rng, self.id);

        user
    }

    pub fn create_and_fund_investors(
        &mut self,
        rng: &mut StdRng,
        count: usize,
        amount: DartBalance,
        off_chain: &mut OffchainProverState<T>,
    ) -> Vec<DartUser<T>> {
        let total_amount = amount * count as DartBalance;
        if total_amount > self.issuer_balance {
            self.mint_more(rng, off_chain, total_amount);
        }

        let (settlement, investors) =
            DartSettlementState::create_investors_and_fund(rng, self, count, amount, off_chain);

        // Update the curve tree roots.
        off_chain.apply_new_leaves();

        // Affirm all the legs in the settlement.
        settlement.affirm_legs(rng, off_chain);

        // All investors claim their assets.
        settlement.claim_assets(rng, off_chain);

        investors
    }
}

#[derive(Clone)]
pub struct DartSettlementLegState<T: Config> {
    pub leg_ref: LegRef,
    pub sender: DartUser<T>,
    pub receiver: DartUser<T>,
    pub asset_id: DartAssetId,
    pub amount: DartBalance,
    pub mediators: Vec<DartUser<T>>,
}

impl<T: Config> DartSettlementLegState<T> {
    pub fn sender_affirmation(&self, rng: &mut StdRng, off_chain: &mut OffchainProverState<T>) {
        self.sender
            .sender_affirmation(rng, off_chain, self.leg_ref, self.asset_id, self.amount);
    }

    pub fn receiver_affirmation(&self, rng: &mut StdRng, off_chain: &mut OffchainProverState<T>) {
        self.receiver.receiver_affirmation(
            rng,
            off_chain,
            self.leg_ref,
            self.asset_id,
            self.amount,
        );
    }

    pub fn mediator_affirmation(
        &self,
        rng: &mut StdRng,
        off_chain: &OffchainProverState<T>,
        accept: bool,
    ) {
        for mediator in &self.mediators {
            mediator.mediator_affirmation(
                rng,
                off_chain,
                self.leg_ref,
                accept,
                Some((self.asset_id, self.amount)),
            );
        }
    }

    pub fn affirm_leg(&self, rng: &mut StdRng, off_chain: &mut OffchainProverState<T>) {
        self.sender_affirmation(rng, off_chain);
        off_chain.apply_new_leaves();
        self.receiver_affirmation(rng, off_chain);
        off_chain.apply_new_leaves();
        self.mediator_affirmation(rng, off_chain, true);
    }

    pub fn receiver_claim(&self, rng: &mut StdRng, off_chain: &mut OffchainProverState<T>) {
        self.receiver.receiver_claim(rng, off_chain, self.leg_ref);
    }
}

#[derive(Clone)]
pub struct DartSettlementState<T: Config> {
    pub settlement_id: SettlementRef,
    pub legs: Vec<DartSettlementLegState<T>>,
}

impl<T: Config> DartSettlementState<T> {
    pub fn create_investors_and_fund(
        rng: &mut StdRng,
        asset: &mut DartTestAsset<T>,
        count: usize,
        amount: DartBalance,
        off_chain: &mut OffchainProverState<T>,
    ) -> (Self, Vec<DartUser<T>>) {
        let asset_id = asset.id;
        let issuer = asset.issuer.clone();
        let asset_data = asset.asset_state();

        let settlement_id = NextSettlementId::<T>::get();
        // Create the investors.
        let mut investors = Vec::with_capacity(count);
        let mut legs = Vec::with_capacity(count);
        let mut settlement = SettlementBuilder::<T>::new(b"FundInvestors");
        for leg_idx in 0..count {
            let leg_ref = LegRef {
                settlement: settlement_id.into(),
                leg_id: leg_idx as _,
            };
            let user = asset.create_investor(rng);
            legs.push(DartSettlementLegState {
                leg_ref,
                sender: issuer.clone(),
                receiver: user.clone(),
                asset_id,
                amount,
                mediators: asset.mediators.clone(),
            });
            settlement = settlement.leg(LegBuilder {
                sender: issuer.public_keys(),
                receiver: user.public_keys(),
                asset: asset_data.clone(),
                amount,
            });
            investors.push(user);
        }

        // Create the settlement to transfer assets to all investors.
        let proof = settlement
            .encryt_and_prove(rng, &off_chain.asset_tree)
            .expect("Failed to create settlement");
        assert_ok!(Pallet::<T>::create_settlement(issuer.origin(), proof));

        let settlement = Self {
            settlement_id: settlement_id.into(),
            legs,
        };

        (settlement, investors)
    }

    pub fn senders_affirm_legs(&self, rng: &mut StdRng, off_chain: &mut OffchainProverState<T>) {
        // All senders affirm their legs.
        for leg in &self.legs {
            leg.sender_affirmation(rng, off_chain);
            off_chain.apply_new_leaves();
        }
    }

    pub fn receivers_affirm_legs(&self, rng: &mut StdRng, off_chain: &mut OffchainProverState<T>) {
        // All receivers affirm their legs.
        for leg in &self.legs {
            leg.receiver_affirmation(rng, off_chain);
            off_chain.apply_new_leaves();
        }
    }

    pub fn mediators_affirm_legs(
        &self,
        rng: &mut StdRng,
        off_chain: &mut OffchainProverState<T>,
        accept: bool,
    ) {
        // All mediators affirm their legs.
        for leg in &self.legs {
            leg.mediator_affirmation(rng, off_chain, accept);
            off_chain.apply_new_leaves();
        }
    }

    pub fn affirm_legs(&self, rng: &mut StdRng, off_chain: &mut OffchainProverState<T>) {
        // Affirm all the legs in the settlement.
        for leg in &self.legs {
            leg.affirm_leg(rng, off_chain);

            off_chain.apply_new_leaves();
        }
    }

    pub fn claim_assets(&self, rng: &mut StdRng, off_chain: &mut OffchainProverState<T>) {
        // All investors claim their assets.
        for leg in &self.legs {
            // Investor claims the assets.
            leg.receiver_claim(rng, off_chain);
        }
        off_chain.apply_new_leaves();
    }
}
