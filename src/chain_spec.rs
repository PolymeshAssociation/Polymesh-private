use codec::{Decode, Encode};
use pallet_asset::TickerRegistrationConfig;
use pallet_im_online::sr25519::AuthorityId as ImOnlineId;
use polymesh_common_utilities::{
    constants::{currency::ONE_POLY, TREASURY_PALLET_ID},
    protocol_fee::ProtocolOp,
    MaybeBlock, SystematicIssuers,
};
use polymesh_primitives::{
    asset_metadata::{AssetMetadataName, AssetMetadataSpec},
    identity_id::GenesisIdentityRecord,
    AccountId, IdentityId, Moment, PosRatio, SecondaryKey, Signature, Ticker,
};
use sc_chain_spec::{ChainSpecExtension, ChainType};
use sc_consensus_grandpa::AuthorityId as GrandpaId;
use sc_service::Properties;
use sc_telemetry::TelemetryEndpoints;
use serde_json::json;
use sp_authority_discovery::AuthorityId as AuthorityDiscoveryId;
use sp_consensus_babe::AuthorityId as BabeId;
use sp_core::{sr25519, Pair, Public};
use sp_runtime::traits::{AccountIdConversion, IdentifyAccount, Verify};
#[cfg(feature = "std")]
use sp_runtime::{Deserialize, Serialize};
use std::convert::TryInto;

use crate::cli::{CustomChainConfig, InitialIdentity};

const DEFAULT_TOKEN_SYMBOL: &str = "POLYX";

// The URL for the telemetry server.
const STAGING_TELEMETRY_URL: &str = "wss://telemetry.polymesh.network/submit/";

const BOOTSTRAP_KEYS: u128 = 6_000 * ONE_POLY;
const BOOTSTRAP_TREASURY: u128 = 17_500_000 * ONE_POLY;

const DEV_KEYS: u128 = 30_000_000 * ONE_POLY;
const DEV_TREASURY: u128 = 50_000_000 * ONE_POLY;

/// Node `ChainSpec` extensions.
///
/// Additional parameters for some Substrate core modules,
/// customizable from the chain spec.
#[derive(Default, Clone, Serialize, Deserialize, ChainSpecExtension)]
#[serde(rename_all = "camelCase")]
pub struct Extensions {
    /// The light sync state.
    ///
    /// This value will be set by the `sync-state rpc` implementation.
    pub light_sync_state: sc_sync_state_rpc::LightSyncStateExtension,
}

pub type GenericChainSpec<R> = sc_service::GenericChainSpec<R, Extensions>;

/// Generate a crypto pair from seed.
pub fn get_from_seed<TPublic: Public>(seed: &str) -> <TPublic::Pair as Pair>::Public {
    TPublic::Pair::from_string(&format!("//{}", seed), None)
        .expect("static values are valid; qed")
        .public()
}

type AccountPublic = <Signature as Verify>::Signer;

/// Generate an account ID from seed.
pub fn get_account_id_from_seed<TPublic: Public>(seed: &str) -> AccountId
where
    AccountPublic: From<<TPublic::Pair as Pair>::Public>,
{
    AccountPublic::from(get_from_seed::<TPublic>(seed)).into_account()
}

fn seeded_acc_id(seed: &str) -> AccountId {
    get_account_id_from_seed::<sr25519::Public>(seed)
}

/// Generate an Aura authority key.
pub fn get_authority_keys_from_seed(s: &str, uniq: bool) -> InitialAuth {
    let stash_acc_id = seeded_acc_id(&format!("{}//stash", s));
    let acc_id = seeded_acc_id(s);

    let (grandpa_id, babe_id, im_online_id, discovery_id) = if uniq {
        (
            get_from_seed::<GrandpaId>(&format!("{}//gran", s)),
            get_from_seed::<BabeId>(&format!("{}//babe", s)),
            get_from_seed::<ImOnlineId>(&format!("{}//imon", s)),
            get_from_seed::<AuthorityDiscoveryId>(&format!("{}//auth", s)),
        )
    } else {
        (
            get_from_seed::<GrandpaId>(s),
            get_from_seed::<BabeId>(s),
            get_from_seed::<ImOnlineId>(s),
            get_from_seed::<AuthorityDiscoveryId>(s),
        )
    };

    (
        stash_acc_id,
        acc_id,
        grandpa_id,
        babe_id,
        im_online_id,
        discovery_id,
    )
}

/// Returns the following JSON object:
///
/// {
///     "ss58Format": `ss58_prefix`,
///     "tokenDecimals": 6,
///     "tokenSymbol": `token_symbol`
/// }
///
/// If `token_symbol` is `None`, defaults to POLYX.
fn polymesh_properties(ss58_prefix: u8, token_symbol: Option<&str>) -> Properties {
    json!(
    {
        "ss58Format": ss58_prefix,
        "tokenDecimals": 6,
        "tokenSymbol": token_symbol.unwrap_or(DEFAULT_TOKEN_SYMBOL)
    })
    .as_object()
    .unwrap()
    .clone()
}

macro_rules! session_keys {
    () => {
        fn session_keys(
            grandpa: GrandpaId,
            babe: BabeId,
            im_online: ImOnlineId,
            authority_discovery: AuthorityDiscoveryId,
        ) -> rt::SessionKeys {
            rt::SessionKeys {
                babe,
                grandpa,
                im_online,
                authority_discovery,
            }
        }
    };
}

macro_rules! asset {
    () => {
        pallet_asset::GenesisConfig {
            ticker_registration_config: ticker_registration_config(),
            reserved_country_currency_codes: currency_codes(),
            asset_metadata: asset_metadata(),
        }
    };
}

fn ticker_registration_config() -> TickerRegistrationConfig<Moment> {
    TickerRegistrationConfig {
        max_ticker_length: 12,
        registration_length: Some(5_184_000_000),
    }
}

fn currency_codes() -> Vec<Ticker> {
    // Fiat Currency Struct
    #[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
    #[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
    pub struct FiatCurrency<String> {
        pub codes: Vec<String>,
    }

    let currency_file = include_str!("data/currency_symbols.json");
    let currency_data: FiatCurrency<String> = serde_json::from_str(&currency_file).unwrap();
    currency_data
        .codes
        .into_iter()
        .map(|y| Ticker::from_slice_truncated(y.as_bytes()))
        .collect()
}

fn asset_metadata() -> Vec<(AssetMetadataName, AssetMetadataSpec)> {
    let metadata_json = include_str!("data/asset_metadata.json");
    serde_json::from_str(&metadata_json).expect("Asset Metadata")
}

macro_rules! checkpoint {
    () => {{
        // We use a weekly complexity. That is, >= 7 days apart per CP is OK.
        use polymesh_primitives::calendar::{CalendarPeriod, CalendarUnit::Week};
        let period = CalendarPeriod {
            unit: Week,
            amount: 1,
        };
        pallet_asset::checkpoint::GenesisConfig {
            schedules_max_complexity: period.complexity(),
        }
    }};
}

type InitialAuth = (
    AccountId,
    AccountId,
    GrandpaId,
    BabeId,
    ImOnlineId,
    AuthorityDiscoveryId,
);

// alias type to make clippy happy.
type GenesisProcessedData = (
    Vec<GenesisIdentityRecord<AccountId>>,
    Vec<(AccountId, u128)>,
);

fn adjust_last(bytes: &mut [u8], n: u8) -> &str {
    bytes[bytes.len() - 1] = n + b'0';
    core::str::from_utf8(bytes).unwrap()
}

/// The data for the settings set at genesis.
struct CustomGenesisProcessedData {
    pub(crate) identity_records: Vec<GenesisIdentityRecord<AccountId>>,
    pub(crate) initial_validators: Vec<AccountId>,
    pub(crate) balances: Vec<(AccountId, u128)>,
    pub(crate) polymesh_committe_members: Vec<IdentityId>,
    pub(crate) upgrade_committee_members: Vec<IdentityId>,
    pub(crate) technical_committee_members: Vec<IdentityId>,
}

/// Returns [`CustomGenesisProcessedData`] containing the records for the identities created at
/// genesis, their balance and the committee members.
fn genesis_identities_and_balances(
    initial_identities: Vec<InitialIdentity>,
    sudo_account: Option<AccountId>,
    treasury_initial_funds: u128,
    initial_funds: u128,
) -> CustomGenesisProcessedData {
    let mut nonce = 1;
    let mut genesis_validators = Vec::new();
    let mut genesis_identities = Vec::new();
    let mut genesis_balances = Vec::new();

    let mut polymesh_committe_members = Vec::new();
    let mut upgrade_committee_members = Vec::new();
    let mut technical_committee_members = Vec::new();

    for initial_id in initial_identities {
        let mut genesis_record = GenesisIdentityRecord::new(nonce, initial_id.account_id.clone());

        if initial_id.is_cdd_provider {
            genesis_record
                .issuers
                .push(SystematicIssuers::CDDProvider.as_id());
        }

        if initial_id.is_validator {
            genesis_validators.push(initial_id.account_id.clone());
        }

        if initial_id.polymesh_committee_member {
            polymesh_committe_members.push(genesis_record.did);
        }

        if initial_id.upgrade_committee_member {
            upgrade_committee_members.push(genesis_record.did);
        }

        if initial_id.technical_committee_member {
            technical_committee_members.push(genesis_record.did);
        }

        genesis_identities.push(genesis_record);
        genesis_balances.push((initial_id.account_id, initial_funds));
        nonce += 1;
    }

    // Set sudo genesis record
    if let Some(sudo_account) = sudo_account {
        let mut sudo_genesis_record = GenesisIdentityRecord::new(nonce, sudo_account.clone());
        sudo_genesis_record
            .issuers
            .push(SystematicIssuers::CDDProvider.as_id());
        genesis_identities.push(sudo_genesis_record);
        genesis_balances.push((sudo_account, initial_funds));
    }

    genesis_balances.push((
        TREASURY_PALLET_ID.into_account_truncating(),
        treasury_initial_funds,
    ));

    CustomGenesisProcessedData {
        identity_records: genesis_identities,
        initial_validators: genesis_validators,
        balances: genesis_balances,
        polymesh_committe_members,
        upgrade_committee_members,
        technical_committee_members,
    }
}

fn genesis_processed_data(
    initial_authorities: &Vec<InitialAuth>,
    root_key: AccountId, //polymesh_5
    treasury_amount: u128,
    key_amount: u128,
) -> GenesisProcessedData {
    // Identities and their roles
    // 1 = [Polymesh] GenesisCouncil (1 of 3) + UpgradeCommittee (1 of 1) + TechnicalCommittee (1 of 1) + GCReleaseCoordinator
    // 2 = GenesisCouncil (2 of 3)
    // 3 = GenesisCouncil (3 of 3)
    // 4 = Operator
    // 5 = Sudo

    // Identity_01
    // Primary Key: polymesh_1

    // Identity_02
    // Primary Key: polymesh_2

    // Identity_03
    // Primary Key: polymesh_3

    // Identity_04
    // Primary Key: polymesh_4
    // Secondary Keys: Alice, Alice//stash, Bob, Bob//stash, Charlie, Charlie//stash

    // Identity_05
    // Primary Key: polymesh_5

    let mut identities = Vec::new();
    let mut balances = Vec::new();
    let mut keys = Vec::new();

    let mut create_id = |nonce: u8, primary_key: AccountId| {
        keys.push(primary_key.clone());
        balances.push((primary_key.clone(), key_amount));
        identities.push(GenesisIdentityRecord::new(nonce, primary_key));
    };

    // Creating Identities 1-4 (GC + Operators)
    for i in 1..5u8 {
        create_id(i, seeded_acc_id(adjust_last(&mut { *b"polymesh_0" }, i)));
    }

    // Creating identity for sudo
    create_id(5u8, root_key);

    for (account, stash, _, _, _, _) in initial_authorities {
        // Make stash and controller 4th Identity's secondary keys.
        let mut push_key = |key: &AccountId| {
            balances.push((key.clone(), key_amount));
            identities[3]
                .secondary_keys
                .push(SecondaryKey::from_account_id_with_full_perms(key.clone()))
        };
        push_key(account);
        push_key(stash);
    }

    // Give CDD issuer to operator and sudo since it won't receive CDD from the group automatically
    identities[3]
        .issuers
        .push(SystematicIssuers::CDDProvider.as_id());

    // Give CDD issuer to operator and sudo since it won't receive CDD from the group automatically
    identities[4]
        .issuers
        .push(SystematicIssuers::CDDProvider.as_id());

    // Treasury
    balances.push((
        TREASURY_PALLET_ID.into_account_truncating(),
        treasury_amount,
    ));

    (identities, balances)
}

#[cfg(not(feature = "ci-runtime"))]
fn dev_genesis_processed_data(
    initial_authorities: &Vec<InitialAuth>,
    other_funded_accounts: Vec<AccountId>,
    treasury_amount: u128,
    key_amount: u128,
) -> GenesisProcessedData {
    let mut identity = GenesisIdentityRecord::new(1u8, initial_authorities[0].0.clone());
    let mut balances = Vec::new();

    identity
        .secondary_keys
        .reserve(initial_authorities.len() * 2 + other_funded_accounts.len());
    let mut add_sk = |acc: AccountId| {
        balances.push((acc.clone(), key_amount));
        identity
            .secondary_keys
            .push(SecondaryKey::from_account_id_with_full_perms(acc))
    };
    for (account, stash, _, _, _, _) in initial_authorities {
        add_sk(account.clone());
        add_sk(stash.clone());
    }

    for account in other_funded_accounts {
        add_sk(account);
    }

    // The 0th key is the primary key
    identity.secondary_keys.remove(0);

    // Treasury
    balances.push((
        TREASURY_PALLET_ID.into_account_truncating(),
        treasury_amount,
    ));

    (vec![identity], balances)
}

fn frame(wasm_binary: Option<&[u8]>) -> frame_system::GenesisConfig {
    frame_system::GenesisConfig {
        code: wasm_binary.expect("WASM binary was not generated").to_vec(),
    }
}

macro_rules! session {
    ($inits:expr, $build:expr) => {
        pallet_session::GenesisConfig {
            keys: $inits
                .iter()
                .map(|x| {
                    let sks = $build(x.2.clone(), x.3.clone(), x.4.clone(), x.5.clone());
                    (x.0.clone(), x.0.clone(), sks)
                })
                .collect::<Vec<_>>(),
        }
    };
}

macro_rules! pips {
    ($period:expr, $expiry:expr, $limit:expr) => {
        pallet_pips::GenesisConfig {
            prune_historical_pips: false,
            min_proposal_deposit: 2_000_000_000,
            default_enactment_period: $period,
            max_pip_skip_count: 2,
            active_pip_limit: $limit,
            pending_pip_expiry: $expiry,
        }
    };
}

macro_rules! group_membership {
    ($($member:expr),*) => {
        pallet_group::GenesisConfig {
            active_members_limit: 20,
            active_members: vec![$(IdentityId::from($member)),*],
            phantom: Default::default(),
        }
    };
}

macro_rules! corporate_actions {
    () => {
        pallet_corporate_actions::GenesisConfig {
            max_details_length: 1024,
        }
    };
}

macro_rules! committee {
    ($rc:expr) => {
        committee!($rc, (1, 2))
    };
    ($rc:expr, $vote:expr) => {
        pallet_committee::GenesisConfig {
            vote_threshold: $vote,
            members: vec![],
            release_coordinator: IdentityId::from($rc),
            expires_after: <_>::default(),
            phantom: Default::default(),
        }
    };
}

fn protocol_fees() -> Vec<(ProtocolOp, u128)> {
    vec![
        (ProtocolOp::AssetCreateAsset, 2_500 * 1_000_000),
        (ProtocolOp::AssetRegisterTicker, 500 * 1_000_000),
    ]
}

macro_rules! protocol_fee {
    () => {
        pallet_protocol_fee::GenesisConfig {
            base_fees: protocol_fees(),
            coefficient: PosRatio(1, 1),
        }
    };
}

macro_rules! polymesh_contracts {
    ($root_key:expr) => {
        polymesh_contracts::GenesisConfig {
            call_whitelist: contracts_call_whitelist(),
            upgradable_code: contracts_upgradable_code(),
            upgradable_description: "POLY"
                .as_bytes()
                .try_into()
                .expect("Wrong Length - should be length 4"),
            upgradable_major: 6,
            upgradable_owner: $root_key,
        }
    };
}

fn contracts_upgradable_code() -> Vec<u8> {
    // NB - Contract should match the `upgradable_major` version above.
    let upgradable_code = include_bytes!("data/contracts/polymesh_ink_6.wasm").to_vec();
    upgradable_code
}

fn contracts_call_whitelist() -> Vec<polymesh_contracts::ExtrinsicId> {
    let whitelist_file = include_str!("data/contracts_call_whitelist.json");
    serde_json::from_str::<Vec<polymesh_contracts::ExtrinsicId>>(&whitelist_file)
        .expect("Failed to read contracts call whitelist")
}

#[cfg(not(feature = "ci-runtime"))]
pub mod develop {
    use super::*;
    use polymesh_private_runtime_develop::{self as rt, constants::time};
    use sp_runtime::FixedU128;

    pub type ChainSpec = GenericChainSpec<rt::runtime::GenesisConfig>;

    session_keys!();

    fn genesis(
        initial_authorities: Vec<InitialAuth>,
        root_key: AccountId,
        other_funded_accounts: Vec<AccountId>,
        treasury_amount: u128,
        key_amount: u128,
    ) -> rt::runtime::GenesisConfig {
        let (identities, balances) = dev_genesis_processed_data(
            &initial_authorities,
            other_funded_accounts,
            treasury_amount,
            key_amount,
        );

        rt::runtime::GenesisConfig {
            system: frame(rt::WASM_BINARY),
            asset: asset!(),
            checkpoint: checkpoint!(),
            identity: pallet_identity::GenesisConfig {
                identities,
                ..Default::default()
            },
            balances: rt::runtime::BalancesConfig { balances },
            indices: pallet_indices::GenesisConfig { indices: vec![] },
            sudo: pallet_sudo::GenesisConfig {
                key: Some(root_key.clone()),
            },
            session: session!(initial_authorities, session_keys),
            pips: pips!(time::MINUTES, MaybeBlock::None, 25),
            im_online: Default::default(),
            authority_discovery: Default::default(),
            validator_set: validator_set::GenesisConfig {
                initial_validators: initial_authorities
                    .iter()
                    .map(|x| x.0.clone())
                    .collect::<Vec<_>>(),
            },
            babe: pallet_babe::GenesisConfig {
                authorities: vec![],
                epoch_config: Some(rt::runtime::BABE_GENESIS_EPOCH_CONFIG),
            },
            grandpa: Default::default(),
            // Governance Council:
            committee_membership: group_membership!(1),
            polymesh_committee: committee!(1),
            // CDD providers
            cdd_service_providers: group_membership!(1),
            // Technical Committee:
            technical_committee_membership: group_membership!(1),
            technical_committee: committee!(1),
            // Upgrade Committee:
            upgrade_committee_membership: group_membership!(1),
            upgrade_committee: committee!(1),
            protocol_fee: protocol_fee!(),
            settlement: Default::default(),
            portfolio: Default::default(),
            statistics: Default::default(),
            multi_sig: Default::default(),
            corporate_action: corporate_actions!(),
            polymesh_contracts: polymesh_contracts!(Some(root_key)),
            ..Default::default()
        }
    }

    fn develop_genesis() -> rt::runtime::GenesisConfig {
        genesis(
            vec![get_authority_keys_from_seed("Alice", false)],
            seeded_acc_id("Alice"),
            vec![
                seeded_acc_id("Bob"),
                seeded_acc_id("Charlie"),
                seeded_acc_id("Dave"),
                seeded_acc_id("Eve"),
            ],
            DEV_TREASURY,
            DEV_KEYS,
        )
    }

    fn config(
        name: &str,
        id: &str,
        ctype: ChainType,
        genesis: impl 'static + Sync + Send + Fn() -> rt::runtime::GenesisConfig,
    ) -> ChainSpec {
        let props = Some(polymesh_properties(42, None));
        ChainSpec::from_genesis(
            name,
            id,
            ctype,
            genesis,
            vec![],
            None,
            None,
            None,
            props,
            <_>::default(),
        )
    }

    pub fn develop_config() -> ChainSpec {
        config(
            "Development",
            "dev",
            ChainType::Development,
            develop_genesis,
        )
    }

    fn local_genesis() -> rt::runtime::GenesisConfig {
        genesis(
            vec![
                get_authority_keys_from_seed("Alice", false),
                get_authority_keys_from_seed("Bob", false),
                get_authority_keys_from_seed("Charlie", false),
            ],
            seeded_acc_id("Alice"),
            vec![seeded_acc_id("Dave"), seeded_acc_id("Eve")],
            DEV_TREASURY,
            DEV_KEYS,
        )
    }

    pub fn local_config() -> ChainSpec {
        config(
            "Local Development",
            "local_dev",
            ChainType::Local,
            local_genesis,
        )
    }

    /// Returns [`ChainSpec`] based on `chain_config` (see [`CustomChainConfig`]).
    pub fn custom_config(custom_chain_config: CustomChainConfig) -> ChainSpec {
        let chain_config = custom_chain_config.clone();

        let genesis_constructor = move || -> rt::runtime::GenesisConfig {
            let genesis_settings = custom_genesis(chain_config.clone());

            rt::runtime::GenesisConfig {
                system: frame(rt::WASM_BINARY),
                asset: asset!(),
                checkpoint: checkpoint!(),
                identity: pallet_identity::GenesisConfig {
                    identities: genesis_settings.processed_data.identity_records,
                    ..Default::default()
                },
                balances: rt::runtime::BalancesConfig {
                    balances: genesis_settings.processed_data.balances,
                },
                transaction_payment: pallet_transaction_payment::GenesisConfig {
                    multiplier: FixedU128::from(1),
                    disable_fees: genesis_settings.disable_fees,
                },
                indices: pallet_indices::GenesisConfig { indices: vec![] },
                sudo: pallet_sudo::GenesisConfig {
                    key: genesis_settings.sudo_account.clone(),
                },
                session: unimplemented!(),
                pips: pips!(time::MINUTES, MaybeBlock::None, 25),
                im_online: Default::default(),
                authority_discovery: Default::default(),
                validator_set: validator_set::GenesisConfig {
                    initial_validators: genesis_settings.processed_data.initial_validators,
                },
                babe: pallet_babe::GenesisConfig {
                    authorities: vec![],
                    epoch_config: Some(rt::runtime::BABE_GENESIS_EPOCH_CONFIG),
                },
                grandpa: Default::default(),
                committee_membership: pallet_group::GenesisConfig {
                    active_members_limit: 20,
                    active_members: genesis_settings.processed_data.polymesh_committe_members,
                    phantom: Default::default(),
                },
                polymesh_committee: pallet_committee::GenesisConfig {
                    vote_threshold: (2, 3),
                    release_coordinator: genesis_settings.polymesh_coordinator,
                    ..Default::default()
                },
                cdd_service_providers: group_membership!(1),
                technical_committee_membership: pallet_group::GenesisConfig {
                    active_members_limit: 20,
                    active_members: genesis_settings.processed_data.technical_committee_members,
                    phantom: Default::default(),
                },
                technical_committee: pallet_committee::GenesisConfig {
                    vote_threshold: (1, 2),
                    release_coordinator: genesis_settings.technical_coordinator,
                    ..Default::default()
                },
                upgrade_committee_membership: pallet_group::GenesisConfig {
                    active_members_limit: 20,
                    active_members: genesis_settings.processed_data.upgrade_committee_members,
                    phantom: Default::default(),
                },
                upgrade_committee: pallet_committee::GenesisConfig {
                    vote_threshold: (1, 2),
                    release_coordinator: genesis_settings.upgrade_coordinator,
                    ..Default::default()
                },
                protocol_fee: protocol_fee!(),
                settlement: Default::default(),
                portfolio: Default::default(),
                statistics: Default::default(),
                multi_sig: Default::default(),
                corporate_action: corporate_actions!(),
                polymesh_contracts: polymesh_contracts!(genesis_settings.sudo_account),
                ..Default::default()
            }
        };

        ChainSpec::from_genesis(
            custom_chain_config.chain_name.as_str(),
            custom_chain_config.chain_id.as_str(),
            custom_chain_config.chain_type,
            genesis_constructor,
            custom_chain_config.boot_nodes.unwrap_or_default(),
            custom_chain_config.telemetry_endpoints,
            custom_chain_config.protocol_id.as_deref(),
            None,
            Some(polymesh_properties(
                custom_chain_config.account_ss58_prefix.unwrap_or(42),
                custom_chain_config.token_symbol.as_deref(),
            )),
            Default::default(),
        )
    }

    /// The data that will be used for setting the genesis config.
    struct CustomGenesisSettings {
        pub(crate) processed_data: CustomGenesisProcessedData,
        pub(crate) polymesh_coordinator: IdentityId,
        pub(crate) technical_coordinator: IdentityId,
        pub(crate) upgrade_coordinator: IdentityId,
        pub(crate) disable_fees: bool,
        pub(crate) sudo_account: Option<AccountId>,
    }

    /// Returns [`CustomGenesisSettings`] containing the data for creating the genesis config.
    fn custom_genesis(chain_config: CustomChainConfig) -> CustomGenesisSettings {
        // Sets the sudo account for the chain
        let sudo_account = {
            if chain_config.disable_sudo.unwrap_or(false) {
                None
            } else {
                Some(
                    chain_config
                        .sudo_account
                        .clone()
                        .unwrap_or(seeded_acc_id("Eve")),
                )
            }
        };
        // Gets the initial account ids and balances
        let initial_identities = {
            match chain_config.initial_identities {
                Some(initial_identities) => initial_identities,
                None => unimplemented!(),
            }
        };
        let processed_data = genesis_identities_and_balances(
            initial_identities,
            sudo_account.clone(),
            BOOTSTRAP_TREASURY,
            chain_config.initial_funds.unwrap_or(BOOTSTRAP_KEYS),
        );

        // Find the identity of the release coordinators
        let mut upgrade_coordinator = None;
        let mut polymesh_coordinator = None;
        let mut technical_coordinator = None;

        for genesis_id_record in &processed_data.identity_records {
            if genesis_id_record.primary_key == chain_config.polymesh_release_coordinator {
                polymesh_coordinator = Some(genesis_id_record.did);
            }
            if genesis_id_record.primary_key == chain_config.technical_release_coordinator {
                technical_coordinator = Some(genesis_id_record.did);
            }
            if genesis_id_record.primary_key == chain_config.technical_release_coordinator {
                upgrade_coordinator = Some(genesis_id_record.did);
            }
        }

        CustomGenesisSettings {
            processed_data,
            polymesh_coordinator: polymesh_coordinator.unwrap_or(IdentityId::from(1)),
            technical_coordinator: technical_coordinator.unwrap_or(IdentityId::from(1)),
            upgrade_coordinator: upgrade_coordinator.unwrap_or(IdentityId::from(1)),
            disable_fees: chain_config.disable_fees.unwrap_or(false),
            sudo_account,
        }
    }
}

pub mod production {
    use super::*;
    use polymesh_private_runtime_production::{self as rt, constants::time};

    pub type ChainSpec = GenericChainSpec<rt::runtime::GenesisConfig>;

    session_keys!();

    fn genesis(
        initial_authorities: Vec<InitialAuth>,
        root_key: AccountId,
        treasury_amount: u128,
        key_amount: u128,
    ) -> rt::runtime::GenesisConfig {
        let (identities, balances) = genesis_processed_data(
            &initial_authorities,
            root_key.clone(),
            treasury_amount,
            key_amount,
        );

        rt::runtime::GenesisConfig {
            system: frame(rt::WASM_BINARY),
            asset: asset!(),
            checkpoint: checkpoint!(),
            identity: pallet_identity::GenesisConfig {
                identities,
                ..Default::default()
            },
            balances: rt::runtime::BalancesConfig { balances },
            indices: pallet_indices::GenesisConfig { indices: vec![] },
            session: session!(initial_authorities, session_keys),
            pips: pips!(time::DAYS * 30, MaybeBlock::Some(time::DAYS * 90), 1000),
            im_online: Default::default(),
            authority_discovery: Default::default(),
            validator_set: validator_set::GenesisConfig {
                initial_validators: initial_authorities
                    .iter()
                    .map(|x| x.0.clone())
                    .collect::<Vec<_>>(),
            },
            babe: pallet_babe::GenesisConfig {
                authorities: vec![],
                epoch_config: Some(rt::runtime::BABE_GENESIS_EPOCH_CONFIG),
            },
            grandpa: Default::default(),
            // Governing council
            committee_membership: group_membership!(1, 2, 3), // 3 GC members
            polymesh_committee: committee!(1, (2, 3)),        // RC = 1, 2/3 votes required
            // CDD providers
            cdd_service_providers: group_membership!(1), // GC_1 is also a CDD provider
            // Technical Committee:
            technical_committee_membership: group_membership!(1), // One GC member
            technical_committee: committee!(1),                   // 1/2 votes required
            // Upgrade Committee:
            upgrade_committee_membership: group_membership!(1), // One GC member
            upgrade_committee: committee!(1),                   // 1/2 votes required
            protocol_fee: protocol_fee!(),
            settlement: Default::default(),
            portfolio: Default::default(),
            statistics: Default::default(),
            multi_sig: Default::default(),
            corporate_action: corporate_actions!(),
            polymesh_contracts: polymesh_contracts!(Some(root_key)),
            ..Default::default()
        }
    }

    fn bootstrap_genesis() -> rt::runtime::GenesisConfig {
        genesis(
            vec![
                get_authority_keys_from_seed("Alice", false),
                get_authority_keys_from_seed("Bob", false),
                get_authority_keys_from_seed("Charlie", false),
            ],
            seeded_acc_id("polymesh_5"),
            BOOTSTRAP_TREASURY,
            BOOTSTRAP_KEYS,
        )
    }

    pub fn bootstrap_config() -> ChainSpec {
        // provide boot nodes
        let boot_nodes = vec![
            "/dns4/production-bootnode-001.polymesh.network/tcp/443/wss/p2p/12D3KooWDiaRBvzjt1p95mTqJETxJw3nz1E6fF2Yf62ojimEGJS7".parse().expect("Unable to parse bootnode"),
            "/dns4/production-bootnode-002.polymesh.network/tcp/443/wss/p2p/12D3KooWN9E6gtgybnXwDVNMUGwSA82pzBj72ibGYfZuomyEDQTU".parse().expect("Unable to parse bootnode"),
            "/dns4/production-bootnode-003.polymesh.network/tcp/443/wss/p2p/12D3KooWQ3K8jGadCQSVhihLEsJfSz3TJGgBHMU3vTtK3jd2Wq5E".parse().expect("Unable to parse bootnode"),
            "/dns4/production-bootnode-004.polymesh.network/tcp/443/wss/p2p/12D3KooWAjLb7S2FKk1Bxyw3vkaqgcSpjfxHwpGvqcXACFYSK8Xq".parse().expect("Unable to parse bootnode"),
            "/dns4/production-bootnode-005.polymesh.network/tcp/443/wss/p2p/12D3KooWKvXCP5b5PW4tHFAYyFVk3kRhwF3qXJbnVcPSGHP6Zmjg".parse().expect("Unable to parse bootnode"),
            "/dns4/production-bootnode-006.polymesh.network/tcp/443/wss/p2p/12D3KooWBQhDAjfo13dM4nsogXD39F5TcN9iTVzjXgPqFn9Yaccz".parse().expect("Unable to parse bootnode"),
            "/dns4/production-bootnode-007.polymesh.network/tcp/443/wss/p2p/12D3KooWMwFdYC53MqdyR9WYvJiPfxfYXh65NfY9QSuZeyKa53fg".parse().expect("Unable to parse bootnode"),
            "/dns4/production-bootnode-001.polymesh.network/tcp/30333/p2p/12D3KooWDiaRBvzjt1p95mTqJETxJw3nz1E6fF2Yf62ojimEGJS7".parse().expect("Unable to parse bootnode"),
            "/dns4/production-bootnode-002.polymesh.network/tcp/30333/p2p/12D3KooWN9E6gtgybnXwDVNMUGwSA82pzBj72ibGYfZuomyEDQTU".parse().expect("Unable to parse bootnode"),
            "/dns4/production-bootnode-003.polymesh.network/tcp/30333/p2p/12D3KooWQ3K8jGadCQSVhihLEsJfSz3TJGgBHMU3vTtK3jd2Wq5E".parse().expect("Unable to parse bootnode"),
            "/dns4/production-bootnode-004.polymesh.network/tcp/30333/p2p/12D3KooWAjLb7S2FKk1Bxyw3vkaqgcSpjfxHwpGvqcXACFYSK8Xq".parse().expect("Unable to parse bootnode"),
            "/dns4/production-bootnode-005.polymesh.network/tcp/30333/p2p/12D3KooWKvXCP5b5PW4tHFAYyFVk3kRhwF3qXJbnVcPSGHP6Zmjg".parse().expect("Unable to parse bootnode"),
            "/dns4/production-bootnode-006.polymesh.network/tcp/30333/p2p/12D3KooWBQhDAjfo13dM4nsogXD39F5TcN9iTVzjXgPqFn9Yaccz".parse().expect("Unable to parse bootnode"),
            "/dns4/production-bootnode-007.polymesh.network/tcp/30333/p2p/12D3KooWMwFdYC53MqdyR9WYvJiPfxfYXh65NfY9QSuZeyKa53fg".parse().expect("Unable to parse bootnode"),
        ];
        ChainSpec::from_genesis(
            "Polymesh Private Production",
            "production",
            ChainType::Live,
            bootstrap_genesis,
            boot_nodes,
            Some(
                TelemetryEndpoints::new(vec![(STAGING_TELEMETRY_URL.to_string(), 0)])
                    .expect("Production bootstrap telemetry url is valid; qed"),
            ),
            Some(&*"/polymesh/production"),
            None,
            Some(polymesh_properties(12, None)),
            Default::default(),
        )
    }

    fn develop_genesis() -> rt::runtime::GenesisConfig {
        genesis(
            vec![get_authority_keys_from_seed("Alice", false)],
            seeded_acc_id("Eve"),
            BOOTSTRAP_TREASURY,
            BOOTSTRAP_KEYS,
        )
    }

    pub fn develop_config() -> ChainSpec {
        // provide boot nodes
        let boot_nodes = vec![];
        ChainSpec::from_genesis(
            "Polymesh Private Production Develop",
            "dev_production",
            ChainType::Development,
            develop_genesis,
            boot_nodes,
            None,
            None,
            None,
            Some(polymesh_properties(12, None)),
            Default::default(),
        )
    }

    fn local_genesis() -> rt::runtime::GenesisConfig {
        genesis(
            vec![
                get_authority_keys_from_seed("Alice", false),
                get_authority_keys_from_seed("Bob", false),
                get_authority_keys_from_seed("Charlie", false),
            ],
            seeded_acc_id("Eve"),
            BOOTSTRAP_TREASURY,
            BOOTSTRAP_KEYS,
        )
    }

    pub fn local_config() -> ChainSpec {
        // provide boot nodes
        let boot_nodes = vec![];
        ChainSpec::from_genesis(
            "Polymesh Private Production Local",
            "local_production",
            ChainType::Local,
            local_genesis,
            boot_nodes,
            None,
            None,
            None,
            Some(polymesh_properties(12, None)),
            Default::default(),
        )
    }
}

#[cfg(feature = "ci-runtime")]
pub mod develop {
    use super::*;
    use polymesh_private_runtime_develop::{self as rt, constants::time};

    pub type ChainSpec = GenericChainSpec<rt::runtime::GenesisConfig>;

    session_keys!();

    fn genesis(
        initial_authorities: Vec<InitialAuth>,
        root_key: AccountId,
        treasury_amount: u128,
        key_amount: u128,
    ) -> rt::runtime::GenesisConfig {
        let (identities, balances) = genesis_processed_data(
            &initial_authorities,
            root_key.clone(),
            treasury_amount,
            key_amount,
        );

        rt::runtime::GenesisConfig {
            system: frame(rt::WASM_BINARY),
            asset: asset!(),
            checkpoint: checkpoint!(),
            identity: pallet_identity::GenesisConfig {
                identities,
                ..Default::default()
            },
            balances: rt::runtime::BalancesConfig { balances },
            indices: pallet_indices::GenesisConfig { indices: vec![] },
            sudo: pallet_sudo::GenesisConfig {
                key: Some(root_key.clone()),
            },
            session: session!(initial_authorities, session_keys),
            pips: pips!(time::DAYS * 7, MaybeBlock::None, 1000),
            im_online: Default::default(),
            authority_discovery: Default::default(),
            validator_set: validator_set::GenesisConfig {
                initial_validators: initial_authorities
                    .iter()
                    .map(|x| x.0.clone())
                    .collect::<Vec<_>>(),
            },
            babe: pallet_babe::GenesisConfig {
                authorities: vec![],
                epoch_config: Some(rt::runtime::BABE_GENESIS_EPOCH_CONFIG),
            },
            grandpa: Default::default(),
            // Governing council
            committee_membership: group_membership!(1, 2, 3, 5),
            polymesh_committee: committee!(1, (2, 4)),
            // CDD providers
            cdd_service_providers: group_membership!(1, 2, 3, 5),
            // Technical Committee:
            technical_committee_membership: group_membership!(3, 5),
            technical_committee: committee!(5),
            // Upgrade Committee:
            upgrade_committee_membership: group_membership!(1, 5),
            upgrade_committee: committee!(5),
            protocol_fee: protocol_fee!(),
            settlement: Default::default(),
            portfolio: Default::default(),
            statistics: Default::default(),
            multi_sig: pallet_multisig::GenesisConfig {
                transaction_version: 1,
            },
            corporate_action: corporate_actions!(),
            polymesh_contracts: polymesh_contracts!(Some(root_key)),
            ..Default::default()
        }
    }

    fn develop_genesis() -> rt::runtime::GenesisConfig {
        genesis(
            vec![get_authority_keys_from_seed("Bob", false)],
            seeded_acc_id("Alice"),
            DEV_TREASURY,
            DEV_KEYS,
        )
    }

    pub fn develop_config() -> ChainSpec {
        // provide boot nodes
        let boot_nodes = vec![];
        ChainSpec::from_genesis(
            "Polymesh Private CI Develop",
            "dev_ci",
            ChainType::Development,
            develop_genesis,
            boot_nodes,
            None,
            None,
            None,
            Some(polymesh_props(42)),
            Default::default(),
        )
    }

    fn local_genesis() -> rt::runtime::GenesisConfig {
        genesis(
            vec![
                get_authority_keys_from_seed("Alice", false),
                get_authority_keys_from_seed("Bob", false),
                get_authority_keys_from_seed("Charlie", false),
            ],
            seeded_acc_id("Alice"),
            DEV_TREASURY,
            DEV_KEYS,
        )
    }

    pub fn local_config() -> ChainSpec {
        // provide boot nodes
        let boot_nodes = vec![];
        ChainSpec::from_genesis(
            "Polymesh Private CI Local",
            "local_ci",
            ChainType::Local,
            local_genesis,
            boot_nodes,
            None,
            None,
            None,
            Some(polymesh_props(42)),
            Default::default(),
        )
    }
}
