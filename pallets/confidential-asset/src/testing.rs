// This file is part of the Polymesh distribution (https://github.com/PolymeshAssociation/Polymesh).
// Copyright (c) 2023 Polymesh

use frame_support::assert_ok;
use frame_support::traits::TryCollect;
use sp_runtime::traits::Zero;

use rand_chacha::ChaCha20Rng as StdRng;
use rand_core::RngCore;

use confidential_assets::{
    transaction::ConfidentialTransferProof, AssetId, Balance as ConfidentialBalance, CipherText,
    ElgamalKeys, ElgamalPublicKey, ElgamalSecretKey, Scalar,
};

use polymesh_host_functions::{BatchVerify, GenerateTransferProofRequest};

use polymesh_common_utilities::{
    benchs::{user, AccountIdOf, User},
    traits::TestUtilsFn,
};

use crate::*;

pub trait ConfigT<T: frame_system::Config>: Config + TestUtilsFn<AccountIdOf<T>> {}

pub(crate) const SEED: u32 = 42;
pub(crate) const TICKER_SEED: u32 = 1_000_000;
pub(crate) const AUDITOR_SEED: u32 = 1_000;

pub(crate) fn gen_asset_id(u: u128) -> AssetId {
    u.to_be_bytes()
}

#[derive(Clone)]
pub struct AuditorState<T: Config + TestUtilsFn<AccountIdOf<T>>> {
    pub asset: ConfidentialAuditors<T>,
    pub auditors: BoundedBTreeSet<AuditorAccount, T::MaxVenueAuditors>,
    pub mediators: BoundedBTreeSet<IdentityId, T::MaxVenueMediators>,
    pub users: BTreeMap<AuditorAccount, ConfidentialUser<T>>,
}

impl<T: Config + TestUtilsFn<AccountIdOf<T>>> AuditorState<T> {
    /// Create maximum number of auditors with one mediator role for an asset.
    pub fn new(asset: u32, rng: &mut StdRng) -> Self {
        let count = T::MaxVenueAuditors::get() + T::MaxAssetAuditors::get();
        Self::new_full(asset, count, 1, rng)
    }

    /// Create `auditor_count` auditors with `mediator_count` mediator roles for an asset.
    pub fn new_full(
        asset_idx: u32,
        auditor_count: u32,
        mediator_count: u32,
        rng: &mut StdRng,
    ) -> Self {
        let mut auditors = BoundedBTreeSet::new();
        let mut mediators = BoundedBTreeSet::new();
        let mut users = BTreeMap::new();
        let auditor_count =
            auditor_count.clamp(1, T::MaxVenueAuditors::get() + T::MaxAssetAuditors::get());
        let mut mediator_count = mediator_count.min(auditor_count);
        let mut asset = ConfidentialAuditors::new();
        // Create auditors.
        for idx in 0..auditor_count {
            let user = ConfidentialUser::<T>::auditor_user("auditor", asset_idx, idx, rng);
            let did = user.did();
            let account = user.auditor_account();
            users.insert(account, user);
            // Make the first `mediator_count` auditors into mediators.
            let is_mediator = if mediator_count > 0 { true } else { false };
            // First add asset-level auditors/mediators.
            if asset.auditors.try_insert(account).is_ok() {
                if is_mediator && asset.mediators.try_insert(did).is_ok() {
                    mediator_count -= 1;
                }
            } else {
                // Then add venue-level auditors/mediators.
                if auditors.try_insert(account).is_ok() {
                    if is_mediator && mediators.try_insert(did).is_ok() {
                        mediator_count -= 1;
                    }
                }
            }
        }
        Self {
            asset,
            auditors,
            mediators,
            users,
        }
    }

    /// Return an `ConfidentialAuditors` limited to just the number of auditors allowed per asset.
    pub fn get_asset_auditors(&self) -> ConfidentialAuditors<T> {
        self.asset.clone()
    }

    pub fn build_auditor_set(&self) -> BTreeSet<ElgamalPublicKey> {
        self.auditors
            .iter()
            .chain(self.asset.auditors.iter())
            .map(|k| k.0.into_public_key().expect("valid key"))
            .collect()
    }

    pub fn mediators(&self) -> impl Iterator<Item = &ConfidentialUser<T>> {
        self.users.values()
    }

    pub fn verify_proof(
        &self,
        sender_proof: &ConfidentialTransferProof,
        amount: ConfidentialBalance,
    ) {
        let auditors = self.auditors.iter().enumerate();
        for (idx, account) in auditors {
            match self.users.get(account) {
                Some(mediator) => {
                    sender_proof
                        .auditor_verify(idx as u8, &mediator.sec, Some(amount))
                        .expect("Mediator verify proof");
                }
                None => {
                    panic!("Missing mediator");
                }
            }
        }
    }
}

pub fn next_asset_id<T: Config>(did: IdentityId) -> AssetId {
    Pallet::<T>::next_asset_id(did, false)
}

pub fn create_confidential_token<T: Config + TestUtilsFn<AccountIdOf<T>>>(
    prefix: &'static str,
    rng: &mut StdRng,
) -> (AssetId, ConfidentialUser<T>, AuditorState<T>) {
    let issuer = ConfidentialUser::<T>::new(prefix, rng);
    let auditors = AuditorState::new(0, rng);
    let asset_id = next_asset_id::<T>(issuer.did());
    assert_ok!(Pallet::<T>::create_asset(
        issuer.origin(),
        Default::default(),
        auditors.get_asset_auditors(),
    ));
    (asset_id, issuer, auditors)
}

#[derive(Clone, Debug)]
pub struct ConfidentialUser<T: Config + TestUtilsFn<AccountIdOf<T>>> {
    pub user: User<T>,
    pub sec: ElgamalKeys,
}

impl<T: Config + TestUtilsFn<AccountIdOf<T>>> ConfidentialUser<T> {
    /// Creates a confidential user.
    pub fn new(name: &'static str, rng: &mut StdRng) -> Self {
        Self::new_from_seed(name, SEED, rng)
    }

    /// Creates a confidential user with asset based seed.
    pub fn asset_user(name: &'static str, asset: u32, rng: &mut StdRng) -> Self {
        Self::new_from_seed(name, asset * TICKER_SEED, rng)
    }

    /// Creates a confidential user with asset/auditor based seed.
    pub fn auditor_user(name: &'static str, asset: u32, auditor: u32, rng: &mut StdRng) -> Self {
        Self::new_from_seed(name, asset * TICKER_SEED + auditor * AUDITOR_SEED, rng)
    }

    fn gen_keys(rng: &mut StdRng) -> ElgamalKeys {
        // These are the encryptions keys used by `confidential_assets` and are different from
        // the signing keys that Polymesh uses for singing transactions.
        let elg_secret = ElgamalSecretKey::new(Scalar::random(rng));

        ElgamalKeys {
            public: elg_secret.get_public_key(),
            secret: elg_secret,
        }
    }

    fn new_from_seed(name: &'static str, seed: u32, rng: &mut StdRng) -> Self {
        let user = user::<T>(name, seed);
        Self {
            user,
            sec: Self::gen_keys(rng),
        }
    }

    pub fn new_account(&self, rng: &mut StdRng) -> Self {
        let user = Self {
            user: self.user.clone(),
            sec: Self::gen_keys(rng),
        };
        user.create_account();
        user
    }

    pub fn pub_key(&self) -> ElgamalPublicKey {
        self.sec.public
    }

    pub fn auditor_account(&self) -> AuditorAccount {
        self.sec.public.into()
    }

    pub fn account(&self) -> ConfidentialAccount {
        self.sec.public.into()
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

    /// Register a new confidential account on-chain.
    pub fn create_account(&self) {
        assert_ok!(Pallet::<T>::create_account(self.origin(), self.account(),));
    }

    pub fn set_balance(&self, asset: AssetId, balance: CipherText) {
        AccountBalance::<T>::insert(self.account(), asset, balance)
    }

    pub fn set_incoming_balance(&self, asset: AssetId, balance: CipherText) {
        IncomingBalance::<T>::insert(self.account(), asset, balance)
    }

    pub fn enc_balance(&self, asset: AssetId) -> CipherText {
        Pallet::<T>::account_balance(self.account(), asset).unwrap_or_default()
    }

    pub fn ensure_balance(&self, asset: AssetId, balance: ConfidentialBalance) {
        let enc_balance = self.enc_balance(asset);
        self.sec
            .secret
            .verify(&enc_balance, &balance.into())
            .expect("verify confidential balance")
    }

    pub fn fund_account(
        &self,
        asset: AssetId,
        amount: ConfidentialBalance,
        rng: &mut StdRng,
    ) -> CipherText {
        let key = self.pub_key();
        let (_, balance) = key.encrypt_value(amount.into(), rng);
        self.set_balance(asset, balance);
        balance
    }

    pub fn burn_proof(
        &self,
        asset_id: AssetId,
        balance: ConfidentialBalance,
        amount: ConfidentialBalance,
        rng: &mut StdRng,
    ) -> ConfidentialBurnProof {
        let issuer_enc_balance = self.enc_balance(asset_id);
        let proof =
            ConfidentialBurnProof::new(&self.sec, &issuer_enc_balance, balance, amount, rng)
                .unwrap();
        proof
    }

    pub fn create_asset(
        &self,
        idx: u32,
        total_supply: ConfidentialBalance,
        auditors: u32,
        mediators: u32,
        rng: &mut StdRng,
    ) -> (AssetId, ConfidentialBalance, AuditorState<T>) {
        let auditors = AuditorState::new_full(idx, auditors, mediators, rng);
        let asset_id = next_asset_id::<T>(self.did());
        assert_ok!(Pallet::<T>::create_asset(
            self.origin(),
            Default::default(),
            auditors.get_asset_auditors(),
        ));

        // In the initial call, the total_supply must be zero.
        assert_eq!(
            Pallet::<T>::confidential_asset_details(asset_id)
                .expect("Asset details")
                .total_supply,
            Zero::zero()
        );

        // Wallet submits the transaction to the chain for verification.
        assert_ok!(Pallet::<T>::mint(
            self.origin(),
            asset_id,
            total_supply.into(), // convert to u128
            self.account(),
        ));

        // ------------------------- Ensuring that the asset details are set correctly

        // A correct entry is added.
        assert_eq!(
            Pallet::<T>::confidential_asset_details(asset_id)
                .expect("Asset details")
                .owner_did,
            self.did()
        );

        // -------------------------- Ensure the encrypted balance matches the minted amount.
        self.ensure_balance(asset_id, total_supply);

        (asset_id, total_supply, auditors)
    }
}

/// Create issuer's confidential account, create asset and mint.
pub fn create_account_and_mint_token<T: Config + TestUtilsFn<AccountIdOf<T>>>(
    name: &'static str,
    total_supply: ConfidentialBalance,
    idx: u32,
    auditors: u32,
    mediators: u32,
    rng: &mut StdRng,
) -> (
    AssetId,
    ConfidentialUser<T>,
    ConfidentialBalance,
    AuditorState<T>,
) {
    let owner = ConfidentialUser::asset_user(name, idx, rng);
    owner.create_account();

    let (asset_id, balance, auditors) =
        owner.create_asset(idx, total_supply, auditors, mediators, rng);
    (asset_id, owner, balance, auditors)
}

pub fn create_move_funds<T: Config + TestUtilsFn<AccountIdOf<T>>>(
    m: usize,
    a: usize,
    rng: &mut StdRng,
) -> (
    ConfidentialUser<T>,
    BoundedVec<ConfidentialMoveFunds<T>, T::MaxMoveFunds>,
) {
    // Generate confidential assets.
    let total_supply = 4_000_000_000 as ConfidentialBalance;
    let max_auditors = T::MaxAssetAuditors::get();
    let max_mediators = T::MaxAssetMediators::get();
    let mut assets = Vec::with_capacity(a);
    for idx in 0..(m * a) {
        let (asset, _, _, auditors) = create_account_and_mint_token::<T>(
            "issuer",
            total_supply,
            idx as u32,
            max_auditors,
            max_mediators,
            rng,
        );
        assets.push((asset, auditors));
    }

    // Generate all confidential accounts using the same on-chain user.
    let signer = ConfidentialUser::<T>::new("one", rng);
    let amount = 10;
    // Create the confidential move funds.
    let mut moves = BoundedVec::default();
    let mut batch = BatchVerify::create();
    for m_idx in 0..m {
        // Generate all confidential accounts using the same on-chain user.
        let from = signer.new_account(rng);
        let to = signer.new_account(rng);
        let funds = ConfidentialMoveFunds::new(from.account(), to.account());
        for a_idx in 0..a {
            let idx = (m_idx * a) + a_idx;
            let (asset, auditors) = &assets[idx];
            // fund both from/to accounts so they have balances for this asset.
            let init_balance = amount * 10;
            let from_enc_balance = from.fund_account(*asset, init_balance, rng);
            to.fund_account(*asset, 1, rng);

            let auditor_keys = auditors.build_auditor_set();
            let mut seed = [0; 32];
            rng.fill_bytes(&mut seed);
            let req = GenerateTransferProofRequest::new(
                from.sec.clone(),
                from_enc_balance,
                init_balance,
                to.pub_key(),
                auditor_keys,
                amount as u64,
                seed,
            );
            batch
                .generate_transfer_proof(req)
                .expect("Batched generate transfer proof");
        }
        moves.try_push(funds).expect("Shouldn't go over limit");
    }
    let proofs = batch.get_proofs().expect("batch get proofs");
    for m_idx in 0..m {
        let funds = &mut moves[m_idx];
        for a_idx in 0..a {
            let idx = (m_idx * a) + a_idx;
            let (asset, _) = assets[idx];
            let proof = proofs[idx].transfer_proof().expect("Transfer proof");
            assert!(funds.insert(asset, proof));
        }
    }
    (signer, moves)
}

#[derive(Clone)]
pub struct TransactionLegState<T: Config + TestUtilsFn<AccountIdOf<T>>> {
    pub asset_id: AssetId,
    pub amount: ConfidentialBalance,
    pub issuer_balance: ConfidentialBalance,
    pub issuer: ConfidentialUser<T>,
    pub investor: ConfidentialUser<T>,
    pub auditors: AuditorState<T>,
    pub leg_id: TransactionLegId,
    pub leg: TransactionLeg<T>,
}

impl<T: Config + TestUtilsFn<AccountIdOf<T>>> TransactionLegState<T> {
    /// Create 3 confidential accounts (issuer, investor, mediator), create asset, mint.
    pub fn new(
        venue_id: VenueId,
        leg_id: u32,
        auditors: u32,
        mediators: u32,
        rng: &mut StdRng,
    ) -> Self {
        let amount = 4_000_000_000 as ConfidentialBalance;
        let total_supply = amount + 100_000_000;
        // Setup confidential asset.
        let (asset_id, issuer, issuer_balance, auditors) = create_account_and_mint_token::<T>(
            "issuer",
            total_supply,
            leg_id,
            auditors,
            mediators,
            rng,
        );

        // Allow our venue.
        assert_ok!(Pallet::<T>::allow_venues(
            issuer.origin(),
            asset_id,
            vec![venue_id]
        ));

        // Setup investor.
        let investor = ConfidentialUser::<T>::asset_user("investor", leg_id, rng);
        investor.create_account();

        let mut assets = BTreeSet::new();
        assets.insert(asset_id);
        let leg = TransactionLeg {
            assets: assets.try_into().expect("Shouldn't fail"),
            sender: issuer.account(),
            receiver: investor.account(),
            auditors: auditors.auditors.clone(),
            mediators: auditors.mediators.clone(),
        };
        Self {
            asset_id,
            amount,
            issuer_balance,
            issuer,
            investor,
            auditors,
            leg_id: TransactionLegId(leg_id as _),
            leg,
        }
    }

    pub fn batch_sender_proof(&self, batch: &BatchVerify, rng: &mut StdRng) {
        let investor_pub_account = self.investor.pub_key();
        let issuer_enc_balance = self.issuer.enc_balance(self.asset_id);
        let auditor_keys = self.auditors.build_auditor_set();
        let mut seed = [0; 32];
        rng.fill_bytes(&mut seed);
        let req = GenerateTransferProofRequest::new(
            self.issuer.sec.clone(),
            issuer_enc_balance,
            self.issuer_balance,
            investor_pub_account,
            auditor_keys,
            self.amount,
            seed,
        );
        batch
            .generate_transfer_proof(req)
            .expect("Batched generate transfer proof");
    }

    pub fn sender_proof(&self, rng: &mut StdRng) -> AffirmLeg<T> {
        let investor_pub_account = self.investor.pub_key();
        let issuer_enc_balance = self.issuer.enc_balance(self.asset_id);
        let auditor_keys = self.auditors.build_auditor_set();
        let proof = ConfidentialTransferProof::new(
            &self.issuer.sec,
            &issuer_enc_balance,
            self.issuer_balance,
            &investor_pub_account,
            &auditor_keys,
            self.amount,
            rng,
        )
        .unwrap();
        let mut transfers = ConfidentialTransfers::new();
        transfers.insert(self.asset_id, proof);
        AffirmLeg::sender(self.leg_id, transfers)
    }

    pub fn affirm(&self, user: &ConfidentialUser<T>, id: TransactionId, leg: AffirmLeg<T>) {
        let mut affirms = AffirmTransactions::new();
        affirms.push(AffirmTransaction { id, leg });
        assert_ok!(Pallet::<T>::affirm_transactions(user.origin(), affirms));
    }

    pub fn batch_sender_affirm(&self, id: TransactionId, proof: ConfidentialTransferProof) {
        let mut transfers = ConfidentialTransfers::new();
        transfers.insert(self.asset_id, proof);
        let affirm = AffirmLeg::sender(self.leg_id, transfers);
        self.affirm(&self.issuer, id, affirm);
    }

    pub fn sender_affirm(&self, id: TransactionId, rng: &mut StdRng) {
        let affirm = self.sender_proof(rng);
        self.affirm(&self.issuer, id, affirm);
    }

    pub fn receiver_affirm(&self, id: TransactionId) {
        let affirm = AffirmLeg::receiver(self.leg_id);
        self.affirm(&self.investor, id, affirm);
    }

    pub fn mediator_affirm(&self, id: TransactionId) {
        for mediator in self.auditors.mediators() {
            let affirm = AffirmLeg::mediator(self.leg_id);
            self.affirm(mediator, id, affirm);
        }
    }

    pub fn affirm_leg(&self, id: TransactionId, rng: &mut StdRng) {
        self.sender_affirm(id, rng);
        self.receiver_affirm(id);
        self.mediator_affirm(id);
    }

    pub fn mediator(&self, idx: usize) -> ConfidentialUser<T> {
        self.auditors
            .mediators()
            .nth(idx)
            .expect("Mediator")
            .clone()
    }
}

#[derive(Clone)]
pub struct TransactionState<T: Config + TestUtilsFn<AccountIdOf<T>>> {
    pub custodian: ConfidentialUser<T>,
    pub venue_id: VenueId,
    pub legs: Vec<TransactionLegState<T>>,
    pub id: TransactionId,
}

impl<T: Config + TestUtilsFn<AccountIdOf<T>>> TransactionState<T> {
    /// Setup for a transaction with one leg.
    pub fn new(rng: &mut StdRng) -> Self {
        Self::new_legs(1, rng)
    }

    /// Setup for a transaction with `leg_count` legs each with maximum number of mediators.
    pub fn new_legs(leg_count: u32, rng: &mut StdRng) -> Self {
        let count = leg_count * (T::MaxVenueAuditors::get() + T::MaxAssetAuditors::get());
        Self::new_legs_full(leg_count, count, count, rng)
    }

    /// Setup for a transaction with `leg_count` legs and a total of `mediator_count` mediators
    /// across all legs.
    pub fn new_legs_full(
        leg_count: u32,
        mut auditors: u32,
        mut mediators: u32,
        rng: &mut StdRng,
    ) -> Self {
        assert!(leg_count > 0);
        let custodian = ConfidentialUser::<T>::new("custodian", rng);

        // Setup venue.
        let venue_id = Pallet::<T>::venue_counter();
        assert_ok!(Pallet::<T>::create_venue(custodian.origin()));

        let a_max = T::MaxVenueAuditors::get() + T::MaxAssetAuditors::get();
        let m_max = T::MaxVenueMediators::get() + T::MaxAssetMediators::get();
        let legs: Vec<_> = (0..leg_count)
            .into_iter()
            .map(|leg_id| {
                let a_count = auditors.min(a_max);
                auditors = auditors.saturating_sub(a_count);
                let m_count = mediators.min(m_max);
                mediators = mediators.saturating_sub(m_count);
                TransactionLegState::new(venue_id, leg_id, a_count, m_count, rng)
            })
            .collect();
        assert_eq!(legs.len(), leg_count as usize);

        Self {
            custodian,
            venue_id,
            legs,
            id: Pallet::<T>::transaction_counter(),
        }
    }

    pub fn get_legs(&self) -> BoundedVec<TransactionLeg<T>, T::MaxNumberOfLegs> {
        self.legs
            .iter()
            .map(|s| s.leg.clone())
            .try_collect()
            .expect("Shouldn't happen")
    }

    pub fn add_transaction(&mut self) {
        self.id = Pallet::<T>::transaction_counter();
        assert_ok!(Pallet::<T>::add_transaction(
            self.custodian.origin(),
            self.venue_id,
            self.get_legs(),
            Some(Memo([7u8; 32])),
        ));
    }

    pub fn leg(&self, leg_id: u32) -> TransactionLegState<T> {
        self.legs.get(leg_id as usize).expect("Leg").clone()
    }

    pub fn sender_proof(&self, leg_id: u32, rng: &mut StdRng) -> AffirmLeg<T> {
        self.leg(leg_id).sender_proof(rng)
    }

    pub fn sender_affirm(&self, leg_id: u32, rng: &mut StdRng) {
        self.leg(leg_id).sender_affirm(self.id, rng)
    }

    pub fn receiver_affirm(&self, leg_id: u32) {
        self.leg(leg_id).receiver_affirm(self.id)
    }

    pub fn mediator_affirm(&self, leg_id: u32) {
        self.leg(leg_id).mediator_affirm(self.id)
    }

    pub fn affirm_leg(&self, leg_id: u32, rng: &mut StdRng) {
        self.sender_affirm(leg_id, rng);
        self.receiver_affirm(leg_id);
        self.mediator_affirm(leg_id);
    }

    pub fn affirm_legs(&self, rng: &mut StdRng) {
        // Use batch to generate sender proofs.
        let mut batch = BatchVerify::create();
        for idx in 0..self.legs.len() {
            self.leg(idx as _).batch_sender_proof(&batch, rng);
        }
        let proofs = batch.get_proofs().expect("batch get proofs");
        for idx in 0..self.legs.len() {
            let proof = proofs[idx].transfer_proof().expect("Transfer proof");
            self.leg(idx as _).batch_sender_affirm(self.id, proof);
        }

        for idx in 0..self.legs.len() {
            let leg_id = idx as u32;
            self.receiver_affirm(leg_id);
            self.mediator_affirm(leg_id);
        }
    }

    pub fn affirms(&self, legs: &[AffirmLeg<T>]) -> AffirmTransactions<T> {
        let mut affirms = AffirmTransactions::new();
        for leg in legs {
            affirms.push(AffirmTransaction {
                id: self.id,
                leg: leg.clone(),
            });
        }
        affirms
    }

    pub fn execute(&self) {
        assert_ok!(Pallet::<T>::execute_transaction(
            self.custodian.origin(),
            self.id,
            self.legs.len() as u32,
        ));
    }
}
