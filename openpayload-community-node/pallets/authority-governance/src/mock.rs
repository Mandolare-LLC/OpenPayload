use crate as pallet_authority_governance;
use frame_support::{
    derive_impl,
    traits::{ConstBool, ConstU32, ConstU64},
};
use sp_runtime::BuildStorage;

pub type AccountId = u64;
type Block = frame_system::mocking::MockBlock<Test>;

#[frame_support::runtime]
mod runtime {
    #[runtime::runtime]
    #[runtime::derive(RuntimeCall, RuntimeEvent, RuntimeError, RuntimeOrigin, RuntimeTask)]
    pub struct Test;

    #[runtime::pallet_index(0)]
    pub type System = frame_system::Pallet<Test>;

    #[runtime::pallet_index(1)]
    pub type Timestamp = pallet_timestamp::Pallet<Test>;

    #[runtime::pallet_index(2)]
    pub type Aura = pallet_aura::Pallet<Test>;

    #[runtime::pallet_index(3)]
    pub type Grandpa = pallet_grandpa::Pallet<Test>;

    #[runtime::pallet_index(4)]
    pub type AuthorityGovernance = pallet_authority_governance::Pallet<Test>;
}

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type AccountId = AccountId;
    type Block = Block;
}

impl pallet_timestamp::Config for Test {
    type Moment = u64;
    type OnTimestampSet = Aura;
    type MinimumPeriod = ConstU64<3_000>;
    type WeightInfo = ();
}

impl pallet_aura::Config for Test {
    type AuthorityId = sp_consensus_aura::sr25519::AuthorityId;
    type DisabledValidators = ();
    type MaxAuthorities = ConstU32<32>;
    type AllowMultipleBlocksPerSlot = ConstBool<false>;
    type SlotDuration = ConstU64<6_000>;
}

impl pallet_grandpa::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = ();
    type MaxAuthorities = ConstU32<32>;
    type MaxNominators = ConstU32<0>;
    type MaxSetIdSessionEntries = ConstU64<0>;
    type KeyOwnerProof = sp_core::Void;
    type EquivocationReportSystem = ();
}

impl pallet_authority_governance::Config for Test {
    type AuthorityOrigin = frame_system::EnsureRoot<AccountId>;
    type MinAuthorities = ConstU32<4>;
    type MaxAuthorities = ConstU32<32>;
    type MinAuthorityChangeDelay = ConstU64<2>;
}

pub fn authority_pair(
    aura: sp_keyring::Sr25519Keyring,
    grandpa: sp_keyring::Ed25519Keyring,
) -> crate::AuthorityPair {
    crate::AuthorityPair {
        aura: aura.public().into(),
        grandpa: grandpa.public().into(),
    }
}

pub fn initial_authorities() -> Vec<crate::AuthorityPair> {
    vec![
        authority_pair(
            sp_keyring::Sr25519Keyring::Alice,
            sp_keyring::Ed25519Keyring::Alice,
        ),
        authority_pair(
            sp_keyring::Sr25519Keyring::Bob,
            sp_keyring::Ed25519Keyring::Bob,
        ),
        authority_pair(
            sp_keyring::Sr25519Keyring::Charlie,
            sp_keyring::Ed25519Keyring::Charlie,
        ),
        authority_pair(
            sp_keyring::Sr25519Keyring::Dave,
            sp_keyring::Ed25519Keyring::Dave,
        ),
    ]
}

pub fn replacement_authorities() -> Vec<crate::AuthorityPair> {
    vec![
        authority_pair(
            sp_keyring::Sr25519Keyring::Eve,
            sp_keyring::Ed25519Keyring::Eve,
        ),
        authority_pair(
            sp_keyring::Sr25519Keyring::Ferdie,
            sp_keyring::Ed25519Keyring::Ferdie,
        ),
        authority_pair(
            sp_keyring::Sr25519Keyring::One,
            sp_keyring::Ed25519Keyring::One,
        ),
        authority_pair(
            sp_keyring::Sr25519Keyring::Two,
            sp_keyring::Ed25519Keyring::Two,
        ),
    ]
}

pub fn new_test_ext() -> sp_io::TestExternalities {
    let initial = initial_authorities();
    let mut storage = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();

    pallet_aura::GenesisConfig::<Test> {
        authorities: initial
            .iter()
            .map(|authority| authority.aura.clone())
            .collect(),
    }
    .assimilate_storage(&mut storage)
    .unwrap();

    pallet_grandpa::GenesisConfig::<Test> {
        authorities: initial
            .iter()
            .map(|authority| (authority.grandpa.clone(), 1))
            .collect(),
        _config: Default::default(),
    }
    .assimilate_storage(&mut storage)
    .unwrap();

    storage.into()
}
