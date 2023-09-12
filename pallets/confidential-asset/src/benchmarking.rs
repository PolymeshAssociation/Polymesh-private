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
use sp_runtime::traits::Zero;
use sp_std::collections::btree_map::BTreeMap;

use rand_chacha::ChaCha20Rng as StdRng;
use rand_core::SeedableRng;

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

fn create_confidential_token<T: Config + TestUtilsFn<AccountIdOf<T>>>(
    user: &User<T>,
    token_name: &[u8],
    ticker: Ticker,
) {
    assert_ok!(Module::<T>::create_confidential_asset(
        user.origin().into(),
        AssetName(token_name.into()),
        ticker,
        AssetType::default(),
    ));
}

#[derive(Clone, Debug)]
pub struct ConfidentialUser<T: Config + TestUtilsFn<AccountIdOf<T>>> {
    pub user: User<T>,
    pub sec: ElgamalKeys,
}

impl<T: Config + TestUtilsFn<AccountIdOf<T>>> ConfidentialUser<T> {
    /// Creates a confidential user.
    pub fn new(name: &'static str, rng: &mut StdRng) -> Self {
        let user = user::<T>(name, SEED);
        Self::new_from_user(user, rng)
    }

    /// Creates a confidential user.
    pub fn new_from_user(user: User<T>, rng: &mut StdRng) -> Self {
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

    pub fn did(&self) -> IdentityId {
        self.user.did()
    }

    pub fn origin(&self) -> frame_system::RawOrigin<T::AccountId> {
        self.user.origin()
    }

    /// Initialize a new confidential account on-chain for `ticker`.
    pub fn init_account(&self, ticker: Ticker) {
        assert_ok!(Module::<T>::create_account(
            self.origin().into(),
            ticker,
            self.account(),
        ));
    }

    pub fn enc_balance(&self, ticker: Ticker) -> CipherText {
        Module::<T>::account_balance(self.account(), ticker).expect("confidential account balance")
    }

    pub fn ensure_balance(&self, ticker: Ticker, balance: ConfidentialBalance) {
        let enc_balance = self.enc_balance(ticker);
        self.sec
            .secret
            .verify(&enc_balance, &balance.into())
            .expect("verify confidential balance")
    }

    pub fn add_mediator(&self) {
        assert_ok!(Module::<T>::add_mediator_account(
            self.origin().into(),
            self.account(),
        ));
    }
}

/// Create issuer's confidential account, create asset and mint.
pub fn create_account_and_mint_token<T: Config + TestUtilsFn<AccountIdOf<T>>>(
    name: &'static str,
    total_supply: u128,
    token_name: &[u8],
    rng: &mut StdRng,
) -> (Ticker, ConfidentialUser<T>, ConfidentialBalance) {
    let owner = ConfidentialUser::new(name, rng);
    let token = ConfidentialAssetDetails {
        name: AssetName(token_name.into()),
        total_supply,
        owner_did: owner.did(),
        asset_type: AssetType::default(),
    };
    let ticker = Ticker::from_slice_truncated(token_name);

    create_confidential_token(&owner.user, token_name, ticker);

    // In the initial call, the total_supply must be zero.
    assert_eq!(
        Module::<T>::confidential_asset_details(ticker)
            .expect("Asset details")
            .total_supply,
        Zero::zero()
    );

    // ---------------- prepare for minting the asset

    owner.init_account(ticker);

    // ------------- Computations that will happen in owner's Wallet ----------
    let amount: ConfidentialBalance = token.total_supply.try_into().unwrap(); // confidential amounts are 64 bit integers.

    // Wallet submits the transaction to the chain for verification.
    assert_ok!(Module::<T>::mint_confidential_asset(
        owner.origin().into(),
        ticker,
        amount.into(), // convert to u128
        owner.account(),
    ));

    // ------------------------- Ensuring that the asset details are set correctly

    // A correct entry is added.
    assert_eq!(
        Module::<T>::confidential_asset_details(ticker)
            .expect("Asset details")
            .owner_did,
        token.owner_did
    );

    // -------------------------- Ensure the encrypted balance matches the minted amount.
    owner.ensure_balance(ticker, amount);

    (ticker, owner, amount)
}

#[derive(Clone)]
pub struct TransactionState<T: Config + TestUtilsFn<AccountIdOf<T>>> {
    pub ticker: Ticker,
    pub amount: ConfidentialBalance,
    pub issuer_balance: ConfidentialBalance,
    pub issuer: ConfidentialUser<T>,
    pub investor: ConfidentialUser<T>,
    pub mediator: ConfidentialUser<T>,
    pub venue_id: VenueId,
    pub legs: Vec<TransactionLeg>,
    pub id: TransactionId,
}

impl<T: Config + TestUtilsFn<AccountIdOf<T>>> TransactionState<T> {
    /// Create 3 confidential accounts (issuer, investor, mediator), create asset, mint.
    pub fn new(rng: &mut StdRng) -> Self {
        Self::new_legs(1, rng)
    }

    /// Create 3 confidential accounts (issuer, investor, mediator), create asset, mint.
    pub fn new_legs(leg_count: u32, rng: &mut StdRng) -> Self {
        let amount = 4_000_000_000 as ConfidentialBalance;
        let total_supply = (amount * leg_count as ConfidentialBalance) + 100_000_000;
        // Setup confidential asset.
        let (ticker, issuer, issuer_balance) =
            create_account_and_mint_token::<T>("issuer", total_supply as u128, b"A", rng);

        // Setup mediator.
        let mediator = ConfidentialUser::<T>::new("mediator", rng);
        mediator.add_mediator();

        // Setup venue.
        let venue_id = Module::<T>::venue_counter();
        assert_ok!(Module::<T>::create_venue(issuer.origin().into(),));

        // Allow our venue.
        assert_ok!(Module::<T>::allow_venues(
            issuer.origin().into(),
            ticker,
            vec![venue_id]
        ));

        // Setup investor.
        let investor = ConfidentialUser::<T>::new("investor", rng);
        investor.init_account(ticker);

        let legs = (0..leg_count)
            .into_iter()
            .map(|_| TransactionLeg {
                ticker,
                sender: issuer.account(),
                receiver: investor.account(),
                mediator: mediator.did(),
            })
            .collect();
        Self {
            ticker,
            amount,
            issuer_balance,
            issuer,
            investor,
            mediator,
            venue_id,
            legs,
            id: Default::default(),
        }
    }

    pub fn add_transaction(&mut self) {
        self.id = Module::<T>::transaction_counter();
        assert_ok!(Module::<T>::add_transaction(
            self.issuer.origin().into(),
            self.venue_id,
            self.legs.clone(),
            Some(Memo([7u8; 32])),
        ));
    }

    pub fn sender_proof(&self, leg_id: u64, rng: &mut StdRng) -> AffirmLeg {
        let investor_pub_account = self.investor.pub_key();
        let issuer_balance = self.issuer_balance - (leg_id as ConfidentialBalance * self.amount);
        let issuer_enc_balance = self.issuer.enc_balance(self.ticker);
        let auditor_keys = BTreeMap::from([(AuditorId(0), self.mediator.pub_key())]);
        let sender_tx = ConfidentialTransferProof::new(
            &self.issuer.sec,
            &issuer_enc_balance,
            issuer_balance,
            &investor_pub_account,
            &auditor_keys,
            self.amount,
            rng,
        )
        .unwrap();
        AffirmLeg::sender(TransactionLegId(leg_id as _), sender_tx)
    }

    pub fn sender_affirm(&self, leg_id: u64, rng: &mut StdRng) {
        let affirm = self.sender_proof(leg_id, rng);
        assert_ok!(Module::<T>::affirm_transaction(
            self.issuer.origin().into(),
            self.id,
            affirm
        ));
    }

    pub fn receiver_affirm(&self, leg_id: u64) {
        assert_ok!(Module::<T>::affirm_transaction(
            self.investor.origin().into(),
            self.id,
            AffirmLeg::receiver(TransactionLegId(leg_id as _)),
        ));
    }

    pub fn mediator_affirm(&self, leg_id: u64) {
        assert_ok!(Module::<T>::affirm_transaction(
            self.mediator.origin().into(),
            self.id,
            AffirmLeg::mediator(TransactionLegId(leg_id as _)),
        ));
    }

    pub fn sender_unaffirm(&self, leg_id: u64) {
        assert_ok!(Module::<T>::unaffirm_transaction(
            self.issuer.origin().into(),
            self.id,
            UnaffirmLeg::sender(TransactionLegId(leg_id as _)),
        ));
    }

    pub fn receiver_unaffirm(&self, leg_id: u64) {
        assert_ok!(Module::<T>::unaffirm_transaction(
            self.investor.origin().into(),
            self.id,
            UnaffirmLeg::receiver(TransactionLegId(leg_id as _)),
        ));
    }

    pub fn mediator_unaffirm(&self, leg_id: u64) {
        assert_ok!(Module::<T>::unaffirm_transaction(
            self.mediator.origin().into(),
            self.id,
            UnaffirmLeg::mediator(TransactionLegId(leg_id as _)),
        ));
    }

    pub fn affirm_leg(&self, leg_id: u64, rng: &mut StdRng) {
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
        assert_ok!(Module::<T>::execute_transaction(
            self.issuer.origin().into(),
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
        let account = mediator.account();
    }: _(mediator.origin(), account)

    create_confidential_asset {
        let ticker = Ticker::from_slice_truncated(b"A".as_ref());
        let issuer = user::<T>("issuer", SEED);
    }: _(issuer.origin(), AssetName(b"Name".to_vec()), ticker, AssetType::default())

    mint_confidential_asset {
        let mut rng = StdRng::from_seed([10u8; 32]);
        let issuer = ConfidentialUser::<T>::new("issuer", &mut rng);
        let ticker = Ticker::from_slice_truncated(b"A".as_ref());
        create_confidential_token(
            &issuer.user,
            b"Name".as_slice(),
            ticker,
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
    }: _(tx.issuer.origin(), tx.issuer.account(), tx.ticker)

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
            b"Name".as_slice(),
            ticker,
        );
        let mut venues = Vec::new();
        for i in 0 .. v {
            venues.push(VenueId(i.into()));
        }
        let s_venues = venues.clone();
    }: _(issuer.origin(), ticker, s_venues)
    verify {
        for v in venues.iter() {
            assert!(Module::<T>::venue_allow_list(ticker, v), "Fail: allow_venue dispatch");
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
            b"Name".as_slice(),
            ticker,
        );
        let mut venues = Vec::new();
        for i in 0 .. v {
            venues.push(VenueId(i.into()));
        }
        assert_ok!(Module::<T>::allow_venues(
            issuer.origin().into(),
            ticker,
            venues.clone(),
        ));
        let s_venues = venues.clone();
    }: _(issuer.origin(), ticker, s_venues)
    verify {
        for v in venues.iter() {
            assert!(!Module::<T>::venue_allow_list(ticker, v), "Fail: allow_venue dispatch");
        }
    }

    add_transaction {
        // Number of legs in transaction.
        let l in 0 .. T::MaxNumberOfLegs::get();

        let mut rng = StdRng::from_seed([10u8; 32]);

        // Setup for transaction.
        let tx = TransactionState::<T>::new_legs(l, &mut rng);

    }: _(tx.issuer.origin(), tx.venue_id, tx.legs, Some(Memo([7u8; 32])))

    sender_affirm_transaction {
        let mut rng = StdRng::from_seed([10u8; 32]);

        // Setup for transaction.
        let mut tx = TransactionState::<T>::new(&mut rng);
        tx.add_transaction();

        let affirm = tx.sender_proof(0, &mut rng);
    }: affirm_transaction(tx.issuer.origin(), tx.id, affirm)

    receiver_affirm_transaction {
        let mut rng = StdRng::from_seed([10u8; 32]);

        // Setup for transaction.
        let mut tx = TransactionState::<T>::new(&mut rng);
        tx.add_transaction();
        tx.sender_affirm(0, &mut rng);

        let affirm = AffirmLeg::receiver(TransactionLegId(0));
    }: affirm_transaction(tx.investor.origin(), tx.id, affirm)

    mediator_affirm_transaction {
        let mut rng = StdRng::from_seed([10u8; 32]);

        // Setup for transaction.
        let mut tx = TransactionState::<T>::new(&mut rng);
        tx.add_transaction();
        tx.sender_affirm(0, &mut rng);
        tx.receiver_affirm(0);

        let affirm = AffirmLeg::mediator(TransactionLegId(0));
    }: affirm_transaction(tx.mediator.origin(), tx.id, affirm)

    sender_unaffirm_transaction {
        let mut rng = StdRng::from_seed([10u8; 32]);

        // Setup for transaction.
        let mut tx = TransactionState::<T>::new(&mut rng);
        tx.add_transaction();

        tx.sender_affirm(0, &mut rng);
        let unaffirm = UnaffirmLeg::sender(TransactionLegId(0));
    }: unaffirm_transaction(tx.issuer.origin(), tx.id, unaffirm)

    receiver_unaffirm_transaction {
        let mut rng = StdRng::from_seed([10u8; 32]);

        // Setup for transaction.
        let mut tx = TransactionState::<T>::new(&mut rng);
        tx.add_transaction();
        tx.sender_affirm(0, &mut rng);
        tx.receiver_affirm(0);

        let unaffirm = UnaffirmLeg::receiver(TransactionLegId(0));
    }: unaffirm_transaction(tx.investor.origin(), tx.id, unaffirm)

    mediator_unaffirm_transaction {
        let mut rng = StdRng::from_seed([10u8; 32]);

        // Setup for transaction.
        let mut tx = TransactionState::<T>::new(&mut rng);
        tx.add_transaction();
        tx.affirm_leg(0, &mut rng);

        let unaffirm = UnaffirmLeg::mediator(TransactionLegId(0));
    }: unaffirm_transaction(tx.mediator.origin(), tx.id, unaffirm)

    execute_transaction {
        let l in 0..T::MaxNumberOfLegs::get();

        let mut rng = StdRng::from_seed([10u8; 32]);

        // Setup for transaction.
        let mut tx = TransactionState::<T>::new_legs(l, &mut rng);
        tx.add_transaction();
        tx.affirm_legs(&mut rng);
    }: _(tx.issuer.origin(), tx.id, l)

    reject_transaction {
        let l in 1..T::MaxNumberOfLegs::get();

        let mut rng = StdRng::from_seed([10u8; 32]);

        // Setup for transaction.
        let mut tx = TransactionState::<T>::new_legs(l, &mut rng);
        tx.add_transaction();
        tx.affirm_legs(&mut rng);
    }: _(tx.mediator.origin(), tx.id, l)
}
