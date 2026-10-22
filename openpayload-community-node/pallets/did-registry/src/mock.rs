use crate as pallet_did_registry;
use frame_support::{derive_impl, parameter_types, traits::ConstU64};
use sp_runtime::BuildStorage;

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
    pub type DidRegistry = pallet_did_registry::Pallet<Test>;
}

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
}

impl pallet_timestamp::Config for Test {
    type Moment = u64;
    type OnTimestampSet = ();
    type MinimumPeriod = ConstU64<1>;
    type WeightInfo = ();
}

pub struct TestRetirementGuard;

impl pallet_did_registry::DidRetirementGuard for TestRetirementGuard {
    fn can_retire(did: &[u8]) -> bool {
        sp_io::storage::get(b"test:application-control-did").as_deref() != Some(did)
    }
}

parameter_types! {
    pub const MaxDocLen: u32 = 327_680;
}

impl pallet_did_registry::Config for Test {
    #[cfg(feature = "runtime-benchmarks")]
    type BenchmarkHelper = TestBenchmarkHelper;
    type PolicyCleanup = ();
    type RetirementGuard = TestRetirementGuard;
    type MaxDidLen = frame_support::traits::ConstU32<128>;
    type MaxLegacyDevices = frame_support::traits::ConstU32<10>;
    type MaxAliasLen = frame_support::traits::ConstU32<64>;
    type MaxAliases = frame_support::traits::ConstU32<8>;
    type MaxContexts = frame_support::traits::ConstU32<4>;
    type MaxContextLen = frame_support::traits::ConstU32<64>;
    type MaxIdLen = frame_support::traits::ConstU32<64>;
    type MaxControllerRefs = frame_support::traits::ConstU32<4>;
    type MaxControllerLen = frame_support::traits::ConstU32<64>;
    type MaxVMs = frame_support::traits::ConstU32<5>;
    type MaxKAs = frame_support::traits::ConstU32<64>;
    type MaxVMTypeLen = frame_support::traits::ConstU32<64>;
    type MaxKeyMultibaseLen = frame_support::traits::ConstU32<4096>;
    type MaxRefsPerRel = frame_support::traits::ConstU32<4>;
    type MaxServices = frame_support::traits::ConstU32<4>;
    type MaxServiceAuthorizationKeys = frame_support::traits::ConstU32<8>;
    type MaxServiceTypeLen = frame_support::traits::ConstU32<64>;
    type MaxServiceEndpointLen = frame_support::traits::ConstU32<128>;
    type MaxServiceEndpointUrlLen = frame_support::traits::ConstU32<4096>;
    type MaxDocLen = MaxDocLen;
    type MaxKaTypeLen = frame_support::traits::ConstU32<64>;
    type MaxServiceEndpoints = frame_support::traits::ConstU32<5>;
    type MaxPolicyRefs = frame_support::traits::ConstU32<4>;
    type MaxPolicyRefLen = frame_support::traits::ConstU32<128>;
}

pub fn new_test_ext() -> sp_io::TestExternalities {
    frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap()
        .into()
}

#[cfg(feature = "runtime-benchmarks")]
pub struct TestBenchmarkHelper;
#[cfg(feature = "runtime-benchmarks")]
impl pallet_did_registry::BenchmarkHelper for TestBenchmarkHelper {
    fn public() -> Vec<u8> {
        use sp_core::{ByteArray, Pair};
        sp_core::ed25519::Pair::from_seed(&[125; 32])
            .public()
            .to_raw_vec()
    }
    fn sign(payload: &[u8]) -> Vec<u8> {
        use sp_core::{ByteArray, Pair};
        sp_core::ed25519::Pair::from_seed(&[125; 32])
            .sign(payload)
            .to_raw_vec()
    }
}
