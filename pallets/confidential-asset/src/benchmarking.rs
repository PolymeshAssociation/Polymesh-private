// This file is part of the Polymesh distribution (https://github.com/PolymeshAssociation/Polymesh).
// Copyright (c) 2020 Polymath

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 3.

// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

use frame_benchmarking::benchmarks;
use frame_support::assert_ok;
use scale_info::prelude::format;
use sp_runtime::traits::Zero;

use rand_chacha::ChaCha20Rng as StdRng;
use rand_core::SeedableRng;

use confidential_assets::{
    transaction::ConfidentialTransferProof,
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
    pub mediators: Vec<ConfidentialUser<T>>,
}

impl<T: Config + TestUtilsFn<AccountIdOf<T>>> AuditorState<T> {
    /// Create some auditors/mediators for a ticker.
    pub fn new(ticker: u32, rng: &mut StdRng) -> Self {
        Self::new_full(ticker, 1, rng)
    }

    /// Create some auditors/mediators for a ticker.
    pub fn new_full(ticker: u32, mediator_count: u32, rng: &mut StdRng) -> Self {
        let mut auditors = ConfidentialAuditors::default();
        let mut mediators = Vec::new();
        let mut mediator_count = mediator_count.min(T::MaxNumberOfAuditors::get());
        // Create the maximum number of asset auditors.
        for idx in 0..T::MaxNumberOfAuditors::get() {
            let user = ConfidentialUser::<T>::auditor_user("auditor", ticker, idx, rng);
            let account = user.mediator_account();
            user.add_mediator();
            // Make the first `mediator_count` auditors into mediators.
            let role = if mediator_count > 0 {
                mediators.push(user);
                mediator_count -= 1;
                ConfidentialTransactionRole::Mediator
            } else {
                ConfidentialTransactionRole::Auditor
            };
            auditors.add_auditor(&account, role)
                .expect("Auditor added");
        }
        Self {
            auditors,
            mediators,
        }
    }

    /// Return an `ConfidentialAuditors` limited to just the number of auditors allowed per asset.
    pub fn get_asset_auditors(&self) -> ConfidentialAuditors<T::MaxNumberOfAssetAuditors> {
        let mut auditors = ConfidentialAuditors::default();
        for (account, role) in self.auditors.auditors().take(T::MaxNumberOfAssetAuditors::get() as usize) {
          auditors.add_auditor(account, *role).expect("Shouldn't hit the limit");
        }
        auditors
    }
}

fn create_confidential_token<T: Config + TestUtilsFn<AccountIdOf<T>>>(
    user: &User<T>,
    ticker: Ticker,
    rng: &mut StdRng,
) -> AuditorState<T> {
    let auditors = AuditorState::new(0, rng);
    assert_ok!(Pallet::<T>::create_confidential_asset(
        user.origin().into(),
        AssetName(b"Name".to_vec()),
        ticker,
        AssetType::default(),
        auditors.get_asset_auditors(),
    ));
    auditors
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

    pub fn origin(&self) -> frame_system::RawOrigin<T::AccountId> {
        self.user.origin()
    }

    /// Initialize a new confidential account on-chain for `ticker`.
    pub fn init_account(&self, ticker: Ticker) {
        assert_ok!(Pallet::<T>::create_account(
            self.origin().into(),
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
            self.origin().into(),
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
) -> (Ticker, ConfidentialUser<T>, ConfidentialBalance, AuditorState<T>) {
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
        owner.origin().into(),
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
        owner.origin().into(),
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
            issuer.origin().into(),
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
        let auditor_keys = self.auditors.auditors.build_auditor_map().expect("auditor map");
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
            self.issuer.origin().into(),
            id,
            affirm
        ));
    }

    pub fn receiver_affirm(&self, id: TransactionId) {
        assert_ok!(Pallet::<T>::affirm_transaction(
            self.investor.origin().into(),
            id,
            AffirmLeg::receiver(self.leg_id),
        ));
    }

    pub fn mediator_affirm(&self, id: TransactionId) {
        for mediator in &self.auditors.mediators {
            assert_ok!(Pallet::<T>::affirm_transaction(
                mediator.origin().into(),
                id,
                AffirmLeg::mediator(self.leg_id, mediator.mediator_account()),
            ));
        }
    }

    pub fn sender_unaffirm(&self, id: TransactionId) {
        assert_ok!(Pallet::<T>::unaffirm_transaction(
            self.issuer.origin().into(),
            id,
            UnaffirmLeg::sender(self.leg_id),
        ));
    }

    pub fn receiver_unaffirm(&self, id: TransactionId) {
        assert_ok!(Pallet::<T>::unaffirm_transaction(
            self.investor.origin().into(),
            id,
            UnaffirmLeg::receiver(self.leg_id),
        ));
    }

    pub fn mediator_unaffirm(&self, id: TransactionId) {
        for mediator in &self.auditors.mediators {
            assert_ok!(Pallet::<T>::unaffirm_transaction(
                mediator.origin().into(),
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
        self.auditors.mediators.get(idx).expect("Mediator").clone()
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
        assert_ok!(Pallet::<T>::create_venue(custodian.origin().into(),));

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
            self.custodian.origin().into(),
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
            self.custodian.origin().into(),
            self.id,
            self.legs.len() as u32,
        ));
    }
}

benchmarks! {
    where_clause { where T: Config, T: TestUtilsFn<AccountIdOf<T>> }

    create_account {
        let mut rng = StdRng::from_seed([10u8; 32]);
        let ticker = Ticker::from_slice_truncated(b"A".as_ref());
        let user = ConfidentialUser::<T>::new("user", &mut rng);
    }: _(user.origin(), ticker, user.account())

    add_mediator_account {
        let mut rng = StdRng::from_seed([10u8; 32]);
        let mediator = ConfidentialUser::<T>::new("mediator", &mut rng);
        let account = mediator.mediator_account();
    }: _(mediator.origin(), account)

    create_confidential_asset {
        let mut rng = StdRng::from_seed([10u8; 32]);
        let ticker = Ticker::from_slice_truncated(b"A".as_ref());
        let issuer = user::<T>("issuer", SEED);
        let auditors = AuditorState::<T>::new(0, &mut rng).get_asset_auditors();
    }: _(issuer.origin(), AssetName(b"Name".to_vec()), ticker, AssetType::default(), auditors)

    mint_confidential_asset {
        let mut rng = StdRng::from_seed([10u8; 32]);
        let issuer = ConfidentialUser::<T>::new("issuer", &mut rng);
        let ticker = Ticker::from_slice_truncated(b"A".as_ref());
        create_confidential_token(
            &issuer.user,
            ticker,
            &mut rng,
        );
        issuer.init_account(ticker);

        let total_supply = 4_000_000_000 as ConfidentialBalance;
    }: _(issuer.origin(), ticker, total_supply.into(), issuer.account())

    apply_incoming_balance {
        let mut rng = StdRng::from_seed([10u8; 32]);

        // Setup for transaction.
        let mut tx = TransactionState::<T>::new(&mut rng);
        tx.add_transaction();
        tx.affirm_legs(&mut rng);
        tx.execute();
        let leg = tx.leg(0);
    }: _(leg.issuer.origin(), leg.issuer.account(), leg.ticker)

    create_venue {
        let issuer = user::<T>("issuer", SEED);
    }: _(issuer.origin())

    allow_venues {
        // Count of venues.
        let v in 0 .. 100;

        let mut rng = StdRng::from_seed([10u8; 32]);
        let issuer = ConfidentialUser::<T>::new("issuer", &mut rng);
        let ticker = Ticker::from_slice_truncated(b"A".as_ref());
        create_confidential_token(
            &issuer.user,
            ticker,
            &mut rng,
        );
        let mut venues = Vec::new();
        for i in 0 .. v {
            venues.push(VenueId(i.into()));
        }
        let s_venues = venues.clone();
    }: _(issuer.origin(), ticker, s_venues)
    verify {
        for v in venues.iter() {
            assert!(Pallet::<T>::venue_allow_list(ticker, v), "Fail: allow_venue dispatch");
        }
    }

    disallow_venues {
        // Count of venues.
        let v in 0 .. 100;

        let mut rng = StdRng::from_seed([10u8; 32]);
        let issuer = ConfidentialUser::<T>::new("issuer", &mut rng);
        let ticker = Ticker::from_slice_truncated(b"A".as_ref());
        create_confidential_token(
            &issuer.user,
            ticker,
            &mut rng,
        );
        let mut venues = Vec::new();
        for i in 0 .. v {
            venues.push(VenueId(i.into()));
        }
        assert_ok!(Pallet::<T>::allow_venues(
            issuer.origin().into(),
            ticker,
            venues.clone(),
        ));
        let s_venues = venues.clone();
    }: _(issuer.origin(), ticker, s_venues)
    verify {
        for v in venues.iter() {
            assert!(!Pallet::<T>::venue_allow_list(ticker, v), "Fail: allow_venue dispatch");
        }
    }

    add_transaction {
        // Number of legs in transaction.
        let l in 0 .. T::MaxNumberOfLegs::get();

        let mut rng = StdRng::from_seed([10u8; 32]);

        // Setup for transaction.
        let tx = TransactionState::<T>::new_legs(l, &mut rng);

        let legs = tx.get_legs();
    }: _(tx.custodian.origin(), tx.venue_id, legs, Some(Memo([7u8; 32])))

    sender_affirm_transaction {
        let mut rng = StdRng::from_seed([10u8; 32]);

        // Setup for transaction.
        let mut tx = TransactionState::<T>::new(&mut rng);
        tx.add_transaction();

        let affirm = tx.sender_proof(0, &mut rng);
        let leg = tx.leg(0);
    }: affirm_transaction(leg.issuer.origin(), tx.id, affirm)

    receiver_affirm_transaction {
        let mut rng = StdRng::from_seed([10u8; 32]);

        // Setup for transaction.
        let mut tx = TransactionState::<T>::new(&mut rng);
        tx.add_transaction();
        tx.sender_affirm(0, &mut rng);

        let affirm = AffirmLeg::receiver(TransactionLegId(0));
        let leg = tx.leg(0);
    }: affirm_transaction(leg.investor.origin(), tx.id, affirm)

    mediator_affirm_transaction {
        let mut rng = StdRng::from_seed([10u8; 32]);

        // Setup for transaction.
        let mut tx = TransactionState::<T>::new(&mut rng);
        tx.add_transaction();
        tx.sender_affirm(0, &mut rng);
        tx.receiver_affirm(0);

        let leg = tx.leg(0);
        let mediator = leg.mediator(0);
        let affirm = AffirmLeg::mediator(TransactionLegId(0), mediator.mediator_account());
    }: affirm_transaction(mediator.origin(), tx.id, affirm)

    sender_unaffirm_transaction {
        let mut rng = StdRng::from_seed([10u8; 32]);

        // Setup for transaction.
        let mut tx = TransactionState::<T>::new(&mut rng);
        tx.add_transaction();

        tx.sender_affirm(0, &mut rng);
        let unaffirm = UnaffirmLeg::sender(TransactionLegId(0));
        let leg = tx.leg(0);
    }: unaffirm_transaction(leg.issuer.origin(), tx.id, unaffirm)

    receiver_unaffirm_transaction {
        let mut rng = StdRng::from_seed([10u8; 32]);

        // Setup for transaction.
        let mut tx = TransactionState::<T>::new(&mut rng);
        tx.add_transaction();
        tx.sender_affirm(0, &mut rng);
        tx.receiver_affirm(0);

        let unaffirm = UnaffirmLeg::receiver(TransactionLegId(0));
        let leg = tx.leg(0);
    }: unaffirm_transaction(leg.investor.origin(), tx.id, unaffirm)

    mediator_unaffirm_transaction {
        let mut rng = StdRng::from_seed([10u8; 32]);

        // Setup for transaction.
        let mut tx = TransactionState::<T>::new(&mut rng);
        tx.add_transaction();
        tx.affirm_leg(0, &mut rng);

        let leg = tx.leg(0);
        let mediator = leg.mediator(0);
        let affirm = AffirmLeg::mediator(TransactionLegId(0), mediator.mediator_account());
        let unaffirm = UnaffirmLeg::mediator(TransactionLegId(0), mediator.mediator_account());
    }: unaffirm_transaction(mediator.origin(), tx.id, unaffirm)

    execute_transaction {
        let l in 0..T::MaxNumberOfLegs::get();

        let mut rng = StdRng::from_seed([10u8; 32]);

        // Setup for transaction.
        let mut tx = TransactionState::<T>::new_legs(l, &mut rng);
        tx.add_transaction();
        tx.affirm_legs(&mut rng);
    }: _(tx.custodian.origin(), tx.id, l)

    reject_transaction {
        let l in 1..T::MaxNumberOfLegs::get();

        let mut rng = StdRng::from_seed([10u8; 32]);

        // Setup for transaction.
        let mut tx = TransactionState::<T>::new_legs(l, &mut rng);
        tx.add_transaction();
        tx.affirm_legs(&mut rng);
        let leg = tx.leg(0);
        let mediator = leg.mediator(0);
    }: _(mediator.origin(), tx.id, l)
}
