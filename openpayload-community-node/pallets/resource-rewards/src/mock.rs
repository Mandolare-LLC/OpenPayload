use crate as pallet_resource_rewards;
use frame_support::{
    derive_impl, parameter_types,
    traits::{ConstU128, ConstU32, ConstU64},
    PalletId,
};
use sp_runtime::BuildStorage;

#[cfg(feature = "runtime-benchmarks")]
use sp_core::{ed25519, ByteArray, Pair};

pub type AccountId = u64;
pub type Balance = u128;
type Block = frame_system::mocking::MockBlock<Test>;

#[frame_support::runtime]
mod runtime {
    #[runtime::runtime]
    #[runtime::derive(
        RuntimeCall,
        RuntimeEvent,
        RuntimeError,
        RuntimeOrigin,
        RuntimeFreezeReason,
        RuntimeHoldReason,
        RuntimeSlashReason,
        RuntimeLockId,
        RuntimeTask,
        RuntimeViewFunction
    )]
    pub struct Test;

    #[runtime::pallet_index(0)]
    pub type System = frame_system::Pallet<Test>;

    #[runtime::pallet_index(1)]
    pub type Timestamp = pallet_timestamp::Pallet<Test>;

    #[runtime::pallet_index(2)]
    pub type Balances = pallet_balances::Pallet<Test>;

    #[runtime::pallet_index(3)]
    pub type DidRegistry = pallet_did_registry::Pallet<Test>;

    #[runtime::pallet_index(4)]
    pub type DeliveryPolicy = pallet_delivery_policy::Pallet<Test>;

    #[runtime::pallet_index(5)]
    pub type Opal = pallet_opal::Pallet<Test>;

    #[runtime::pallet_index(6)]
    pub type ResourceRewards = pallet_resource_rewards::Pallet<Test>;
}

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type AccountId = AccountId;
    type Block = Block;
    type AccountData = pallet_balances::AccountData<Balance>;
}

impl pallet_timestamp::Config for Test {
    type Moment = u64;
    type OnTimestampSet = ();
    type MinimumPeriod = ConstU64<1>;
    type WeightInfo = ();
}

impl pallet_balances::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type Balance = Balance;
    type DustRemoval = ();
    type ExistentialDeposit = ConstU128<1>;
    type AccountStore = System;
    type WeightInfo = ();
    type MaxLocks = ();
    type MaxReserves = ();
    type ReserveIdentifier = [u8; 8];
    type FreezeIdentifier = RuntimeFreezeReason;
    type MaxFreezes = frame_support::traits::ConstU32<0>;
    type RuntimeHoldReason = RuntimeHoldReason;
    type RuntimeFreezeReason = RuntimeFreezeReason;
    type DoneSlashHandler = ();
}

parameter_types! {
    pub const MaxDocLen: u32 = 16_384;
    pub const MaxTtl: u64 = 10_000;
    pub const MaxReleaseFee: Balance = 1_000;
    pub const TestRewardPalletId: PalletId = PalletId(*b"op/rewar");
}

impl pallet_did_registry::Config for Test {
    type PolicyCleanup = DeliveryPolicy;
    type RetirementGuard = ();
    type MaxDidLen = frame_support::traits::ConstU32<128>;
    type MaxDevices = frame_support::traits::ConstU32<10>;
    type MaxAliasLen = frame_support::traits::ConstU32<64>;
    type MaxAliases = frame_support::traits::ConstU32<8>;
    type MaxContexts = frame_support::traits::ConstU32<4>;
    type MaxContextLen = frame_support::traits::ConstU32<64>;
    type MaxIdLen = frame_support::traits::ConstU32<64>;
    type MaxControllerRefs = frame_support::traits::ConstU32<4>;
    type MaxControllerLen = frame_support::traits::ConstU32<64>;
    type MaxVMs = frame_support::traits::ConstU32<5>;
    type MaxKAs = frame_support::traits::ConstU32<5>;
    type MaxVMTypeLen = frame_support::traits::ConstU32<64>;
    type MaxKeyMultibaseLen = frame_support::traits::ConstU32<128>;
    type MaxRefsPerRel = frame_support::traits::ConstU32<4>;
    type MaxServices = frame_support::traits::ConstU32<4>;
    type MaxServiceAuthorizationKeys = frame_support::traits::ConstU32<8>;
    type MaxServiceTypeLen = frame_support::traits::ConstU32<64>;
    type MaxServiceEndpointLen = frame_support::traits::ConstU32<128>;
    type MaxServiceEndpointUrlLen = frame_support::traits::ConstU32<128>;
    type MaxDocLen = MaxDocLen;
    type MaxKaTypeLen = frame_support::traits::ConstU32<64>;
    type MaxServiceEndpoints = frame_support::traits::ConstU32<5>;
    type MaxPolicyRefs = frame_support::traits::ConstU32<4>;
    type MaxPolicyRefLen = frame_support::traits::ConstU32<128>;
}

impl pallet_delivery_policy::Config for Test {
    type Balance = Balance;
    type DidProvider = DidRegistry;
    type ApplicationProvider = ();
    type PersonaAttestationProvider = ();
    type PersonaAttestorOrigin = frame_system::EnsureRoot<AccountId>;
    type WeightInfo = ();
    type MaxDidLen = frame_support::traits::ConstU32<128>;
    type MaxTtl = MaxTtl;
    type MaxMessageBytes = frame_support::traits::ConstU32<1_048_576>;
    type MaxReplication = frame_support::traits::ConstU8<8>;
    type MaxHeaderPreviewBytes = frame_support::traits::ConstU32<4096>;
    type MaxReleaseFee = MaxReleaseFee;
    type MaxPersonaLen = frame_support::traits::ConstU32<253>;
    type MaxPersonaControllerKeys = frame_support::traits::ConstU32<8>;
    type MaxPolicyIdLen = frame_support::traits::ConstU32<32>;
    type MaxPolicyRules = frame_support::traits::ConstU32<32>;
    type MaxRuleIdLen = frame_support::traits::ConstU32<64>;
    type MaxRuleConditions = frame_support::traits::ConstU32<8>;
    type MaxConditionRecipients = frame_support::traits::ConstU32<16>;
    type MaxTagLen = frame_support::traits::ConstU32<96>;
    type MaxServiceRefLen = frame_support::traits::ConstU32<128>;
    type MaxRouteTargets = frame_support::traits::ConstU32<16>;
    type MaxDeliverySteps = frame_support::traits::ConstU32<32>;
    type MaxDeliveryTransitions = frame_support::traits::ConstU32<64>;
    type MaxPolicyValidationUnits = frame_support::traits::ConstU32<4096>;
    type MaxTtlSeconds = frame_support::traits::ConstU32<172_800>;
    type MaxPolicyTtlSeconds = frame_support::traits::ConstU32<300>;
    type MaxHttpEnvelopeBytes = frame_support::traits::ConstU32<26_214_400>;
    type MaxUnchunkedMessageBytes = frame_support::traits::ConstU32<16_777_216>;
    type MaxChunkBytes = frame_support::traits::ConstU32<2_097_152>;
    type MaxReplicas = frame_support::traits::ConstU8<4>;
}

impl pallet_opal::Config for Test {
    type Balance = Balance;
    type Currency = Balances;
    type TokenGovernanceOrigin = frame_system::EnsureRoot<AccountId>;
    type MaxAccountingRefLen = frame_support::traits::ConstU32<96>;
}

impl pallet_resource_rewards::Config for Test {
    type GovernanceOrigin = frame_system::EnsureRoot<AccountId>;
    type DidProvider = DidRegistry;
    type WeightInfo = ();
    #[cfg(feature = "runtime-benchmarks")]
    type BenchmarkHelper = TestBenchmarkHelper;
    type MaxDidLen = ConstU32<128>;
    type MaxNodeIdLen = ConstU32<64>;
    type MaxMessageIdLen = ConstU32<64>;
    type MaxEndpointLen = ConstU32<128>;
    type MaxRegionLen = ConstU32<32>;
    type MaxJurisdictionLen = ConstU32<32>;
    type MaxClusterLen = ConstU32<32>;
    type MaxNetworkRangeLen = ConstU32<32>;
    type MaxTtlTiers = ConstU32<8>;
    type MaxProofHashLen = ConstU32<64>;
    type MaxSignatureLen = ConstU32<96>;
    type MaxReportsPerNodeEpoch = ConstU32<8>;
    type EpochDuration = ConstU64<10>;
    type CacheRewardHistoryRetentionEpochs = ConstU64<2>;
    type MaxPruneKeysPerCall = ConstU32<1>;
    type BaseEpochReward = ConstU128<100>;
    type RewardStorageUnitBytes = ConstU64<1_000>;
    type MaxStorageMultiplierPpm = ConstU32<4_000_000>;
    type MinOutageReporters = ConstU32<2>;
    type MinOutageWeight = ConstU32<2>;
    type RelayPenaltyPerWeightPpm = ConstU32<100_000>;
    type MaxRelayPenaltyPpm = ConstU32<300_000>;
    type FalseReportPenaltyPpm = ConstU32<100_000>;
    type RewardPalletId = TestRewardPalletId;
    type MaxMessageSizeBytes = ConstU64<100>;
    type TriggerTicketsPerEpoch = ConstU32<6>;
    type RequiredTriggerAttestations = ConstU32<2>;
    type TriggerRetentionBlocks = ConstU64<1>;
    type EvidenceWindowEpochs = ConstU64<1>;
    type RewardFinalizationWindowEpochs = ConstU64<1>;
    type EpochsPerRewardYear = ConstU64<10>;
    type GenesisRewardReserve = ConstU128<10_000>;
    type AnnualFixedEmission = ConstU128<1_000>;
    type SupplementalInflationPpm = ConstU32<20_000>;
}

#[cfg(feature = "runtime-benchmarks")]
pub struct TestBenchmarkHelper;

#[cfg(feature = "runtime-benchmarks")]
impl pallet_resource_rewards::BenchmarkHelper<AccountId> for TestBenchmarkHelper {
    fn install_did(account: &AccountId, did: &[u8], seed: u32) {
        let pair = ed25519::Pair::from_seed(&[(seed % 251) as u8; 32]);
        let did = pallet_did_registry::DidOf::<Test>::try_from(did.to_vec())
            .expect("benchmark DID fits the test runtime bound");
        pallet_did_registry::Dids::<Test>::insert(
            did,
            pallet_did_registry::DidRecord::<Test> {
                owner: Some(*account),
                aliases: None,
                devices: None,
                document: None,
                version: 1,
                updated_at: 0,
                root_pubkey: Some(
                    pair.public()
                        .to_raw_vec()
                        .try_into()
                        .expect("ed25519 public key has the required length"),
                ),
                delivery_policy_links: None,
                deactivated: false,
            },
        );
    }

    fn sign(seed: u32, payload: &[u8]) -> Vec<u8> {
        ed25519::Pair::from_seed(&[(seed % 251) as u8; 32])
            .sign(payload)
            .to_raw_vec()
    }
}

pub fn new_test_ext() -> sp_io::TestExternalities {
    new_test_ext_with_validators(Vec::new(), false)
}

pub fn new_test_ext_with_validators(
    approved_validators: Vec<AccountId>,
    validator_activity_paused: bool,
) -> sp_io::TestExternalities {
    let mut storage = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();
    pallet_balances::GenesisConfig::<Test> {
        balances: vec![(1, 1_000), (2, 1_000), (3, 1_000), (4, 1_000), (9, 1_000)],
        dev_accounts: None,
    }
    .assimilate_storage(&mut storage)
    .unwrap();
    pallet_opal::GenesisConfig::<Test> {
        retrieval_burns_enabled: true,
        _config: Default::default(),
    }
    .assimilate_storage(&mut storage)
    .unwrap();
    pallet_resource_rewards::GenesisConfig::<Test> {
        approved_validators,
        validator_activity_paused,
        cache_trigger_evidence_enabled: true,
        reward_payments_paused: false,
        reward_payments_start_epoch: Some(0),
        reward_policy_version: 1,
        root_sponsor: Some(3),
        cache_reward_history_retention_epochs: 2,
    }
    .assimilate_storage(&mut storage)
    .unwrap();
    storage.into()
}
