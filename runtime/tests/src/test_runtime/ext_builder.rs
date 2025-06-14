use frame_support::dispatch::Weight;
use frame_support::pallet_prelude::GenesisBuild;
use sp_io::TestExternalities;
use sp_keyring::AccountKeyring;
use sp_runtime::Storage;
use sp_std::prelude::Vec;
use sp_std::{cell::RefCell, convert::From, iter};

use pallet_asset::{self as asset, TickerRegistrationConfig};
use pallet_balances as balances;
use pallet_committee as committee;
use pallet_group as group;
use pallet_identity as identity;
use pallet_pips as pips;
use polymesh_common_utilities::protocol_fee::ProtocolOp;
use polymesh_primitives::{
    constants::currency::POLY, identity_id::GenesisIdentityRecord, AccountId, IdentityId, PosRatio,
    SecondaryKey, SystematicIssuers, GC_DID,
};

use crate::test_runtime::TestRuntime;

/// Identity information.
#[derive(Clone, PartialEq, Debug)]
pub struct IdentityRecord {
    primary_key: AccountId,
    secondary_keys: Vec<SecondaryKey<AccountId>>,
}

/// A prime number fee to test the split between multiple recipients.
pub const PROTOCOL_OP_BASE_FEE: u128 = 41;

struct BuilderVoteThreshold {
    pub numerator: u32,
    pub denominator: u32,
}

impl Default for BuilderVoteThreshold {
    fn default() -> Self {
        BuilderVoteThreshold {
            numerator: 2,
            denominator: 3,
        }
    }
}

#[derive(Clone)]
pub struct MockProtocolBaseFees(pub Vec<(ProtocolOp, u128)>);

impl Default for MockProtocolBaseFees {
    fn default() -> Self {
        let ops = vec![
            ProtocolOp::AssetRegisterTicker,
            ProtocolOp::AssetIssue,
            ProtocolOp::AssetAddDocuments,
            ProtocolOp::AssetCreateAsset,
            ProtocolOp::CheckpointCreateSchedule,
            ProtocolOp::ComplianceManagerAddComplianceRequirement,
            ProtocolOp::IdentityCddRegisterDid,
            ProtocolOp::IdentityAddClaim,
            ProtocolOp::IdentityAddSecondaryKeysWithAuthorization,
            ProtocolOp::PipsPropose,
            ProtocolOp::ContractsPutCode,
            ProtocolOp::CorporateBallotAttachBallot,
            ProtocolOp::CapitalDistributionDistribute,
        ];
        let fees = ops
            .into_iter()
            .zip(iter::repeat(PROTOCOL_OP_BASE_FEE))
            .collect();
        MockProtocolBaseFees(fees)
    }
}

#[derive(Default)]
pub struct ExtBuilder {
    /// Minimum weight for the extrinsic (see `weight_to_fee` below).
    extrinsic_base_weight: Weight,
    /// The transaction fee per byte.
    /// Transactions with bigger payloads will have a bigger `len_fee`.
    /// This is calculated as `transaction_byte_fee * tx.len()`.
    transaction_byte_fee: u128,
    /// Contributes to the `weight_fee`, indicating the compute requirements of a transaction.
    /// A more resource-intensive transaction will have a higher `weight_fee`.
    weight_to_fee: u128,
    /// Scaling factor for initial balances on genesis.
    balance_factor: u128,
    /// When `false`, no balances will be initialized on genesis.
    monied: bool,
    /// CDD Service provides. Their DID will be generated.
    cdd_providers: Vec<AccountId>,
    /// Governance committee members. Their DID will be generated.
    governance_committee_members: Vec<AccountId>,
    governance_committee_vote_threshold: BuilderVoteThreshold,
    /// Regular users. Their DID will be generated.
    regular_users: Vec<IdentityRecord>,

    protocol_base_fees: MockProtocolBaseFees,
    protocol_coefficient: PosRatio,
    adjust: Option<Box<dyn FnOnce(&mut Storage)>>,
}

thread_local! {
    pub static EXTRINSIC_BASE_WEIGHT: RefCell<Weight> = RefCell::new(Weight::zero());
    pub static TRANSACTION_BYTE_FEE: RefCell<u128> = RefCell::new(0);
    pub static WEIGHT_TO_FEE: RefCell<u128> = RefCell::new(0);
}

impl ExtBuilder {
    /// It sets `providers` as CDD providers.
    pub fn cdd_providers(mut self, providers: Vec<AccountId>) -> Self {
        self.cdd_providers = providers;
        self.cdd_providers.sort();
        self
    }

    fn set_associated_consts(&self) {
        EXTRINSIC_BASE_WEIGHT.with(|v| *v.borrow_mut() = self.extrinsic_base_weight);
        TRANSACTION_BYTE_FEE.with(|v| *v.borrow_mut() = self.transaction_byte_fee);
        WEIGHT_TO_FEE.with(|v| *v.borrow_mut() = self.weight_to_fee);
    }

    fn make_balances(&self) -> Vec<(AccountId, u128)> {
        if self.monied {
            vec![
                (
                    AccountKeyring::Alice.to_account_id(),
                    1_000 * POLY * self.balance_factor,
                ),
                (
                    AccountKeyring::Bob.to_account_id(),
                    2_000 * POLY * self.balance_factor,
                ),
                (
                    AccountKeyring::Charlie.to_account_id(),
                    3_000 * POLY * self.balance_factor,
                ),
                (
                    AccountKeyring::Dave.to_account_id(),
                    4_000 * POLY * self.balance_factor,
                ),
                // CDD Accounts
                (AccountKeyring::Eve.to_account_id(), 1_000_000),
                (AccountKeyring::Ferdie.to_account_id(), 1_000_000),
            ]
        } else {
            vec![]
        }
    }

    /// Generates a mapping between DID and Identity info.
    ///
    /// DIDs are generated sequentially from `offset`.
    fn make_identities(
        identities: impl Iterator<Item = AccountId>,
        offset: usize,
        issuers: Vec<IdentityId>,
    ) -> Vec<GenesisIdentityRecord<AccountId>> {
        identities
            .enumerate()
            .map(|(idx, primary_key)| {
                let did_index = (idx + offset + 1) as u128;
                let did = IdentityId::from(did_index);

                GenesisIdentityRecord {
                    primary_key: Some(primary_key),
                    issuers: issuers.clone(),
                    did,
                    ..Default::default()
                }
            })
            .collect()
    }

    fn build_identity_genesis(
        &self,
        storage: &mut Storage,
        identities: Vec<GenesisIdentityRecord<AccountId>>,
    ) {
        // New identities are just `system users` + `regular users`.
        identity::GenesisConfig::<TestRuntime> {
            identities,
            ..Default::default()
        }
        .assimilate_storage(storage)
        .unwrap();
    }

    fn build_balances_genesis(&self, storage: &mut Storage) {
        balances::GenesisConfig::<TestRuntime> {
            balances: self.make_balances(),
        }
        .assimilate_storage(storage)
        .unwrap();
    }

    fn build_asset_genesis(&self, storage: &mut Storage) {
        let ticker_registration_config = TickerRegistrationConfig {
            max_ticker_length: 8,
            registration_length: Some(10000),
        };
        let genesis = asset::GenesisConfig {
            ticker_registration_config,
            reserved_country_currency_codes: vec![],
            asset_metadata: vec![],
        };
        GenesisBuild::<TestRuntime>::assimilate_storage(&genesis, storage).unwrap();
    }

    /// For each `cdd_providers`:
    ///     1. A new `IdentityId` is generated (from 1 to n),
    ///     2. CDD provider's account key is linked to its new Identity ID.
    ///     3. That Identity ID is added as member of CDD provider group.
    fn build_cdd_providers_genesis(
        &self,
        storage: &mut Storage,
        identities: &[GenesisIdentityRecord<AccountId>],
    ) {
        let mut cdd_ids = identities
            .iter()
            .map(|gen_id| gen_id.did)
            .collect::<Vec<_>>();
        cdd_ids.push(GC_DID);
        cdd_ids.sort();

        group::GenesisConfig::<TestRuntime, group::Instance2> {
            active_members_limit: u32::MAX,
            active_members: cdd_ids,
            ..Default::default()
        }
        .assimilate_storage(storage)
        .unwrap();
    }

    fn build_committee_genesis(
        &self,
        storage: &mut Storage,
        identities: &[GenesisIdentityRecord<AccountId>],
    ) {
        let mut gc_ids = identities
            .iter()
            .map(|gen_id| gen_id.did)
            .collect::<Vec<_>>();
        gc_ids.sort();

        group::GenesisConfig::<TestRuntime, group::Instance1> {
            active_members_limit: u32::MAX,
            active_members: gc_ids.clone(),
            ..Default::default()
        }
        .assimilate_storage(storage)
        .unwrap();

        committee::GenesisConfig::<TestRuntime, committee::Instance1> {
            members: gc_ids,
            vote_threshold: (
                self.governance_committee_vote_threshold.numerator,
                self.governance_committee_vote_threshold.denominator,
            ),
            release_coordinator: IdentityId::from(999),
            ..Default::default()
        }
        .assimilate_storage(storage)
        .unwrap();
    }

    fn build_protocol_fee_genesis(&self, storage: &mut Storage) {
        let genesis = pallet_protocol_fee::GenesisConfig {
            base_fees: self.protocol_base_fees.0.clone(),
            coefficient: self.protocol_coefficient,
        };
        GenesisBuild::<TestRuntime>::assimilate_storage(&genesis, storage).unwrap();
    }

    fn build_pips_genesis(&self, storage: &mut Storage) {
        pips::GenesisConfig::<TestRuntime> {
            prune_historical_pips: false,
            min_proposal_deposit: 50,
            default_enactment_period: 100,
            max_pip_skip_count: 1,
            active_pip_limit: 5,
            pending_pip_expiry: <_>::default(),
        }
        .assimilate_storage(storage)
        .unwrap();
    }

    /// Create externalities.
    pub fn build(self) -> TestExternalities {
        self.set_associated_consts();

        // Regular users should intersect neither with CDD providers nor with GC members.
        assert!(!self
            .regular_users
            .iter()
            .any(|id| self.cdd_providers.contains(&id.primary_key)
                || self.governance_committee_members.contains(&id.primary_key)));

        // System identities.
        let cdd_identities = Self::make_identities(self.cdd_providers.iter().cloned(), 0, vec![]);
        let gc_only_accs = self
            .governance_committee_members
            .iter()
            .filter(|acc| !self.cdd_providers.contains(acc))
            .cloned()
            .collect::<Vec<_>>();
        let gc_only_identities =
            Self::make_identities(gc_only_accs.iter().cloned(), cdd_identities.len(), vec![]);
        let gc_and_cdd_identities = cdd_identities.iter().filter(|gen_id| {
            self.governance_committee_members
                .contains(gen_id.primary_key.as_ref().unwrap())
        });
        let gc_full_identities = gc_only_identities
            .iter()
            .chain(gc_and_cdd_identities)
            .cloned()
            .collect::<Vec<_>>();

        //  User identities.
        let issuer_did = cdd_identities
            .iter()
            .map(|gen_id| gen_id.did)
            .next()
            .unwrap_or(SystematicIssuers::CDDProvider.as_id());
        let regular_accounts = self.regular_users.iter().map(|id| id.primary_key.clone());

        // Create regular user identities + .
        let mut user_identities = Self::make_identities(
            regular_accounts,
            cdd_identities.len() + gc_only_identities.len(),
            vec![issuer_did],
        );
        // Add secondary keys (and permissions) to new identites.
        for user_id in user_identities.iter_mut() {
            if let Some(user) = self
                .regular_users
                .iter()
                .find(|ru| Some(&ru.primary_key) == user_id.primary_key.as_ref())
            {
                user_id.secondary_keys = user.secondary_keys.clone();
            }
        }

        let identities = cdd_identities
            .iter()
            .chain(gc_only_identities.iter())
            .chain(user_identities.iter())
            .cloned()
            .collect();

        // Create storage and assimilate each genesis.
        let mut storage = frame_system::GenesisConfig::default()
            .build_storage::<TestRuntime>()
            .expect("TestRuntime cannot build its own storage");

        self.build_identity_genesis(&mut storage, identities);
        self.build_balances_genesis(&mut storage);
        self.build_asset_genesis(&mut storage);
        self.build_cdd_providers_genesis(&mut storage, cdd_identities.as_slice());
        self.build_committee_genesis(&mut storage, gc_full_identities.as_slice());
        self.build_protocol_fee_genesis(&mut storage);
        self.build_pips_genesis(&mut storage);

        if let Some(adjust) = self.adjust {
            adjust(&mut storage);
        }

        sp_io::TestExternalities::new(storage)
    }
}
