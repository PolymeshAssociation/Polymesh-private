// This file is part of the Polymesh distribution (https://github.com/PolymeshAssociation/Polymesh).
// Copyright (c) 2023 Polymesh

use frame_support::assert_ok;
use frame_support::traits::TryCollect;
use sp_runtime::traits::Zero;

use rand_chacha::ChaCha20Rng as StdRng;

use confidential_assets::{
    transaction::ConfidentialTransferProof, AssetId, Balance as ConfidentialBalance, CipherText,
    ElgamalKeys, ElgamalPublicKey, ElgamalSecretKey, Scalar,
};

use polymesh_common_utilities::{
    benchs::{user, AccountIdOf, User},
    traits::TestUtilsFn,
};

use crate::*;

pub trait ConfigT<T: frame_system::Config>: Config + TestUtilsFn<AccountIdOf<T>> {}

pub(crate) const SEED: u32 = 42;
pub(crate) const TICKER_SEED: u32 = 1_000_000;
pub(crate) const AUDITOR_SEED: u32 = 1_000;

#[derive(Clone)]
pub struct AuditorState<T: Config + TestUtilsFn<AccountIdOf<T>>> {
    pub auditors: BTreeSet<AuditorAccount>,
    pub mediators: BTreeSet<IdentityId>,
    pub users: BTreeMap<AuditorAccount, ConfidentialUser<T>>,
}

impl<T: Config + TestUtilsFn<AccountIdOf<T>>> AuditorState<T> {
    /// Create maximum number of auditors with one mediator role for an asset.
    pub fn new(asset: u32, rng: &mut StdRng) -> Self {
        Self::new_full(asset, T::MaxNumberOfAuditors::get(), 1, rng)
    }

    /// Create `auditor_count` auditors with `mediator_count` mediator roles for an asset.
    pub fn new_full(asset: u32, auditor_count: u32, mediator_count: u32, rng: &mut StdRng) -> Self {
        let mut auditors = BTreeSet::new();
        let mut mediators = BTreeSet::new();
        let mut users = BTreeMap::new();
        let auditor_count = auditor_count.clamp(1, T::MaxNumberOfAuditors::get());
        let mut mediator_count = mediator_count.min(auditor_count);
        // Create auditors.
        for idx in 0..auditor_count {
            let user = ConfidentialUser::<T>::auditor_user("auditor", asset, idx, rng);
            let account = user.auditor_account();
            // Make the first `mediator_count` auditors into mediators.
            if mediator_count > 0 {
                mediator_count -= 1;
                mediators.insert(user.did());
            }
            users.insert(account, user);
            auditors.insert(account);
        }
        Self {
            auditors,
            mediators,
            users,
        }
    }

    /// Return an `ConfidentialAuditors` limited to just the number of auditors allowed per asset.
    pub fn get_asset_auditors(&self) -> ConfidentialAuditors<T> {
        let mut asset = ConfidentialAuditors {
            auditors: Default::default(),
            mediators: Default::default(),
        };
        for auditor in &self.auditors {
            asset
                .auditors
                .try_insert(*auditor)
                .ok()
                .and_then(|_| self.users.get(auditor))
                .and_then(|mediator| asset.mediators.try_insert(mediator.did()).ok());
        }
        asset
    }

    pub fn build_auditor_set(&self) -> BTreeSet<ElgamalPublicKey> {
        self.auditors
            .iter()
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
    assert_ok!(Pallet::<T>::create_confidential_asset(
        issuer.origin(),
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

    fn new_from_seed(name: &'static str, seed: u32, rng: &mut StdRng) -> Self {
        let user = user::<T>(name, seed);
        // These are the encryptions keys used by `confidential_assets` and are different from
        // the signing keys that Polymesh uses for singing transactions.
        let elg_secret = ElgamalSecretKey::new(Scalar::random(rng));

        Self {
            user,
            sec: ElgamalKeys {
                public: elg_secret.get_public_key(),
                secret: elg_secret,
            },
        }
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

    pub fn enc_balance(&self, asset: AssetId) -> CipherText {
        Pallet::<T>::account_balance(self.account(), asset).expect("confidential account balance")
    }

    pub fn ensure_balance(&self, asset: AssetId, balance: ConfidentialBalance) {
        let enc_balance = self.enc_balance(asset);
        self.sec
            .secret
            .verify(&enc_balance, &balance.into())
            .expect("verify confidential balance")
    }
}

/// Create issuer's confidential account, create asset and mint.
pub fn create_account_and_mint_token<T: Config + TestUtilsFn<AccountIdOf<T>>>(
    name: &'static str,
    total_supply: u128,
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
    let token = ConfidentialAssetDetails {
        total_supply,
        owner_did: owner.did(),
    };

    let auditors = AuditorState::new_full(idx, auditors, mediators, rng);
    let asset_id = next_asset_id::<T>(owner.did());
    assert_ok!(Pallet::<T>::create_confidential_asset(
        owner.origin(),
        auditors.get_asset_auditors(),
    ));

    // In the initial call, the total_supply must be zero.
    assert_eq!(
        Pallet::<T>::confidential_asset_details(asset_id)
            .expect("Asset details")
            .total_supply,
        Zero::zero()
    );

    // ---------------- prepare for minting the asset

    owner.create_account();

    // ------------- Computations that will happen in owner's Wallet ----------
    let amount: ConfidentialBalance = token.total_supply.try_into().unwrap(); // confidential amounts are 64 bit integers.

    // Wallet submits the transaction to the chain for verification.
    assert_ok!(Pallet::<T>::mint_confidential_asset(
        owner.origin(),
        asset_id,
        amount.into(), // convert to u128
        owner.account(),
    ));

    // ------------------------- Ensuring that the asset details are set correctly

    // A correct entry is added.
    assert_eq!(
        Pallet::<T>::confidential_asset_details(asset_id)
            .expect("Asset details")
            .owner_did,
        token.owner_did
    );

    // -------------------------- Ensure the encrypted balance matches the minted amount.
    owner.ensure_balance(asset_id, amount);

    (asset_id, owner, amount, auditors)
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
            total_supply as u128,
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
            // TODO: venue auditors/mediators.
            auditors: Default::default(),
            mediators: Default::default(),
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
        let count = leg_count * T::MaxNumberOfAuditors::get();
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

        let legs: Vec<_> = (0..leg_count)
            .into_iter()
            .map(|leg_id| {
                let a_count = auditors.min(T::MaxNumberOfAuditors::get());
                auditors = auditors.saturating_sub(a_count);
                let m_count = mediators.min(T::MaxNumberOfAuditors::get());
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
        for idx in 0..self.legs.len() {
            self.affirm_leg(idx as _, rng);
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
