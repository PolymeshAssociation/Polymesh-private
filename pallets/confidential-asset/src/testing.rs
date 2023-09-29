// This file is part of the Polymesh distribution (https://github.com/PolymeshAssociation/Polymesh).
// Copyright (c) 2023 Polymesh

use frame_support::assert_ok;
use scale_info::prelude::format;
use sp_runtime::traits::Zero;

use rand_chacha::ChaCha20Rng as StdRng;

use confidential_assets::{
    transaction::{AuditorId, ConfidentialTransferProof},
    Balance as ConfidentialBalance, CipherText, ElgamalKeys, ElgamalPublicKey, ElgamalSecretKey,
    Scalar,
};

use polymesh_common_utilities::{
    benchs::{user, AccountIdOf, User},
    traits::TestUtilsFn,
};
use polymesh_primitives::{
    asset::{AssetName, AssetType},
    Ticker,
};

use crate::*;

pub trait ConfigT<T: frame_system::Config>: Config + TestUtilsFn<AccountIdOf<T>> {}

pub(crate) const SEED: u32 = 42;
pub(crate) const TICKER_SEED: u32 = 1_000_000;
pub(crate) const AUDITOR_SEED: u32 = 1_000;

#[derive(Clone)]
pub struct AuditorState<T: Config + TestUtilsFn<AccountIdOf<T>>> {
    pub auditors: ConfidentialAuditors<T::MaxNumberOfAuditors>,
    pub users: BTreeMap<MediatorAccount, ConfidentialUser<T>>,
}

impl<T: Config + TestUtilsFn<AccountIdOf<T>>> AuditorState<T> {
    /// Create some auditors/mediators for a ticker.
    pub fn new(ticker: u32, rng: &mut StdRng) -> Self {
        Self::new_full(ticker, 1, rng)
    }

    /// Create some auditors/mediators for a ticker.
    pub fn new_full(ticker: u32, mediator_count: u32, rng: &mut StdRng) -> Self {
        let mut auditors = ConfidentialAuditors::default();
        let mut users = BTreeMap::new();
        let mut mediator_count = mediator_count.min(T::MaxNumberOfAuditors::get());
        // Create the maximum number of asset auditors.
        for idx in 0..T::MaxNumberOfAuditors::get() {
            let user = ConfidentialUser::<T>::auditor_user("auditor", ticker, idx, rng);
            let account = user.mediator_account();
            user.add_mediator();
            // Make the first `mediator_count` auditors into mediators.
            let role = if mediator_count > 0 {
                mediator_count -= 1;
                ConfidentialTransactionRole::Mediator
            } else {
                ConfidentialTransactionRole::Auditor
            };
            users.insert(account, user);
            auditors.add_auditor(&account, role).expect("Auditor added");
        }
        Self { auditors, users }
    }

    /// Return an `ConfidentialAuditors` limited to just the number of auditors allowed per asset.
    pub fn get_asset_auditors(&self) -> ConfidentialAuditors<T::MaxNumberOfAssetAuditors> {
        let mut auditors = ConfidentialAuditors::default();
        for (account, role) in self
            .auditors
            .auditors()
            .take(T::MaxNumberOfAssetAuditors::get() as usize)
        {
            auditors
                .add_auditor(account, *role)
                .expect("Shouldn't hit the limit");
        }
        auditors
    }

    pub fn build_auditor_map(&self) -> BTreeMap<AuditorId, ElgamalPublicKey> {
        self.auditors.build_auditor_map().expect("auditor map")
    }

    pub fn mediators(&self) -> impl Iterator<Item = &ConfidentialUser<T>> {
        self.auditors
            .mediators()
            .filter_map(|acc| self.users.get(acc))
    }

    pub fn verify_proof(&self, sender_proof: &ConfidentialTransferProof) {
        let auditors = self.auditors.auditors().enumerate();
        for (idx, (account, role)) in auditors {
            match (role, self.users.get(account)) {
                (ConfidentialTransactionRole::Mediator, Some(mediator)) => {
                    sender_proof
                        .auditor_verify(AuditorId(idx as u32), &mediator.sec)
                        .expect("Mediator verify proof");
                }
                (ConfidentialTransactionRole::Mediator, None) => {
                    panic!("Missing mediator");
                }
                _ => (),
            }
        }
    }
}

pub fn create_confidential_token<T: Config + TestUtilsFn<AccountIdOf<T>>>(
    prefix: &'static str,
    idx: u32,
    rng: &mut StdRng,
) -> (Ticker, ConfidentialUser<T>, AuditorState<T>) {
    let issuer = ConfidentialUser::<T>::new(prefix, rng);
    let name = format!("{prefix}{idx}");
    let ticker = Ticker::from_slice_truncated(name.as_bytes());
    let auditors = AuditorState::new(0, rng);
    assert_ok!(Pallet::<T>::create_confidential_asset(
        issuer.origin(),
        AssetName(b"Name".to_vec()),
        ticker,
        AssetType::default(),
        auditors.get_asset_auditors(),
    ));
    (ticker, issuer, auditors)
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

    /// Creates a confidential user with ticker based seed.
    pub fn ticker_user(name: &'static str, ticker: u32, rng: &mut StdRng) -> Self {
        Self::new_from_seed(name, ticker * TICKER_SEED, rng)
    }

    /// Creates a confidential user with ticker/auditor based seed.
    pub fn auditor_user(name: &'static str, ticker: u32, auditor: u32, rng: &mut StdRng) -> Self {
        Self::new_from_seed(name, ticker * TICKER_SEED + auditor * AUDITOR_SEED, rng)
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

    pub fn account(&self) -> ConfidentialAccount {
        self.sec.public.into()
    }

    pub fn mediator_account(&self) -> MediatorAccount {
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

    /// Initialize a new confidential account on-chain for `ticker`.
    pub fn init_account(&self, ticker: Ticker) {
        assert_ok!(Pallet::<T>::create_account(
            self.origin(),
            ticker,
            self.account(),
        ));
    }

    pub fn enc_balance(&self, ticker: Ticker) -> CipherText {
        Pallet::<T>::account_balance(self.account(), ticker).expect("confidential account balance")
    }

    pub fn ensure_balance(&self, ticker: Ticker, balance: ConfidentialBalance) {
        let enc_balance = self.enc_balance(ticker);
        self.sec
            .secret
            .verify(&enc_balance, &balance.into())
            .expect("verify confidential balance")
    }

    pub fn add_mediator(&self) {
        assert_ok!(Pallet::<T>::add_mediator_account(
            self.origin(),
            self.mediator_account(),
        ));
    }
}

/// Create issuer's confidential account, create asset and mint.
pub fn create_account_and_mint_token<T: Config + TestUtilsFn<AccountIdOf<T>>>(
    name: &'static str,
    total_supply: u128,
    idx: u32,
    rng: &mut StdRng,
) -> (
    Ticker,
    ConfidentialUser<T>,
    ConfidentialBalance,
    AuditorState<T>,
) {
    let token_name = format!("A{idx}");
    let owner = ConfidentialUser::ticker_user(name, idx, rng);
    let token = ConfidentialAssetDetails {
        name: AssetName(b"Name".to_vec()),
        total_supply,
        owner_did: owner.did(),
        asset_type: AssetType::default(),
    };
    let ticker = Ticker::from_slice_truncated(token_name.as_bytes());

    let auditors = AuditorState::new(idx, rng);
    assert_ok!(Pallet::<T>::create_confidential_asset(
        owner.origin(),
        AssetName(b"Name".to_vec()),
        ticker,
        AssetType::default(),
        auditors.get_asset_auditors(),
    ));

    // In the initial call, the total_supply must be zero.
    assert_eq!(
        Pallet::<T>::confidential_asset_details(ticker)
            .expect("Asset details")
            .total_supply,
        Zero::zero()
    );

    // ---------------- prepare for minting the asset

    owner.init_account(ticker);

    // ------------- Computations that will happen in owner's Wallet ----------
    let amount: ConfidentialBalance = token.total_supply.try_into().unwrap(); // confidential amounts are 64 bit integers.

    // Wallet submits the transaction to the chain for verification.
    assert_ok!(Pallet::<T>::mint_confidential_asset(
        owner.origin(),
        ticker,
        amount.into(), // convert to u128
        owner.account(),
    ));

    // ------------------------- Ensuring that the asset details are set correctly

    // A correct entry is added.
    assert_eq!(
        Pallet::<T>::confidential_asset_details(ticker)
            .expect("Asset details")
            .owner_did,
        token.owner_did
    );

    // -------------------------- Ensure the encrypted balance matches the minted amount.
    owner.ensure_balance(ticker, amount);

    (ticker, owner, amount, auditors)
}

#[derive(Clone)]
pub struct TransactionLegState<T: Config + TestUtilsFn<AccountIdOf<T>>> {
    pub ticker: Ticker,
    pub amount: ConfidentialBalance,
    pub issuer_balance: ConfidentialBalance,
    pub issuer: ConfidentialUser<T>,
    pub investor: ConfidentialUser<T>,
    pub auditors: AuditorState<T>,
    pub leg_id: TransactionLegId,
    pub leg: TransactionLeg<T::MaxNumberOfAuditors>,
}

impl<T: Config + TestUtilsFn<AccountIdOf<T>>> TransactionLegState<T> {
    /// Create 3 confidential accounts (issuer, investor, mediator), create asset, mint.
    pub fn new(venue_id: VenueId, leg_id: u32, rng: &mut StdRng) -> Self {
        let amount = 4_000_000_000 as ConfidentialBalance;
        let total_supply = amount + 100_000_000;
        // Setup confidential asset.
        let (ticker, issuer, issuer_balance, auditors) =
            create_account_and_mint_token::<T>("issuer", total_supply as u128, leg_id, rng);

        // Allow our venue.
        assert_ok!(Pallet::<T>::allow_venues(
            issuer.origin(),
            ticker,
            vec![venue_id]
        ));

        // Setup investor.
        let investor = ConfidentialUser::<T>::ticker_user("investor", leg_id, rng);
        investor.init_account(ticker);

        let leg = TransactionLeg {
            ticker,
            sender: issuer.account(),
            receiver: investor.account(),
            auditors: auditors.auditors.clone(),
        };
        Self {
            ticker,
            amount,
            issuer_balance,
            issuer,
            investor,
            auditors,
            leg_id: TransactionLegId(leg_id as _),
            leg,
        }
    }

    pub fn sender_proof(&self, rng: &mut StdRng) -> AffirmLeg {
        let investor_pub_account = self.investor.pub_key();
        let issuer_enc_balance = self.issuer.enc_balance(self.ticker);
        let auditor_keys = self.auditors.build_auditor_map();
        let sender_tx = ConfidentialTransferProof::new(
            &self.issuer.sec,
            &issuer_enc_balance,
            self.issuer_balance,
            &investor_pub_account,
            &auditor_keys,
            self.amount,
            rng,
        )
        .unwrap();
        AffirmLeg::sender(self.leg_id, sender_tx)
    }

    pub fn sender_affirm(&self, id: TransactionId, rng: &mut StdRng) {
        let affirm = self.sender_proof(rng);
        assert_ok!(Pallet::<T>::affirm_transaction(
            self.issuer.origin(),
            id,
            affirm
        ));
    }

    pub fn receiver_affirm(&self, id: TransactionId) {
        assert_ok!(Pallet::<T>::affirm_transaction(
            self.investor.origin(),
            id,
            AffirmLeg::receiver(self.leg_id),
        ));
    }

    pub fn mediator_affirm(&self, id: TransactionId) {
        for mediator in self.auditors.mediators() {
            assert_ok!(Pallet::<T>::affirm_transaction(
                mediator.origin(),
                id,
                AffirmLeg::mediator(self.leg_id, mediator.mediator_account()),
            ));
        }
    }

    pub fn sender_unaffirm(&self, id: TransactionId) {
        assert_ok!(Pallet::<T>::unaffirm_transaction(
            self.issuer.origin(),
            id,
            UnaffirmLeg::sender(self.leg_id),
        ));
    }

    pub fn receiver_unaffirm(&self, id: TransactionId) {
        assert_ok!(Pallet::<T>::unaffirm_transaction(
            self.investor.origin(),
            id,
            UnaffirmLeg::receiver(self.leg_id),
        ));
    }

    pub fn mediator_unaffirm(&self, id: TransactionId) {
        for mediator in self.auditors.mediators() {
            assert_ok!(Pallet::<T>::unaffirm_transaction(
                mediator.origin(),
                id,
                UnaffirmLeg::mediator(self.leg_id, mediator.mediator_account()),
            ));
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

    /// Setup for a transaction with `leg_count` legs.
    pub fn new_legs(leg_count: u32, rng: &mut StdRng) -> Self {
        let custodian = ConfidentialUser::<T>::new("custodian", rng);

        // Setup venue.
        let venue_id = Pallet::<T>::venue_counter();
        assert_ok!(Pallet::<T>::create_venue(custodian.origin()));

        let legs = (0..leg_count)
            .into_iter()
            .map(|leg_id| TransactionLegState::new(venue_id, leg_id, rng))
            .collect();

        Self {
            custodian,
            venue_id,
            legs,
            id: Pallet::<T>::transaction_counter(),
        }
    }

    pub fn get_legs(&self) -> Vec<TransactionLeg<T::MaxNumberOfAuditors>> {
        self.legs.iter().map(|s| s.leg.clone()).collect()
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

    pub fn sender_proof(&self, leg_id: u32, rng: &mut StdRng) -> AffirmLeg {
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

    pub fn sender_unaffirm(&self, leg_id: u32) {
        self.leg(leg_id).sender_unaffirm(self.id)
    }

    pub fn receiver_unaffirm(&self, leg_id: u32) {
        self.leg(leg_id).receiver_unaffirm(self.id)
    }

    pub fn mediator_unaffirm(&self, leg_id: u32) {
        self.leg(leg_id).mediator_unaffirm(self.id)
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

    pub fn execute(&self) {
        assert_ok!(Pallet::<T>::execute_transaction(
            self.custodian.origin(),
            self.id,
            self.legs.len() as u32,
        ));
    }
}
