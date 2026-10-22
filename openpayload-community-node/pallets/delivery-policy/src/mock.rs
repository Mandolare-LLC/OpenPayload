use crate as pallet_delivery_policy;
use crate::ApplicationProvider;
use crate::DidProvider;
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
    pub type DeliveryPolicy = pallet_delivery_policy::Pallet<Test>;
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

pub struct MockDidProvider;
impl DidProvider<u64> for MockDidProvider {
    fn did_exists(did: &[u8]) -> bool {
        did != b"did:openpayload:missing"
    }

    fn can_update_policy(who: &u64, did: &[u8]) -> bool {
        match did {
            b"did:bob" => *who == 2,
            _ => *who == 1,
        }
    }

    fn verify_did_signature(
        _did: &[u8],
        _signer_key_id: &[u8],
        signed_payload: &[u8],
        signature: &[u8],
    ) -> bool {
        if signature == signed_payload { return true; } // frozen legacy fixtures
        use sp_core::Pair;
        let seed = if _did == b"did:bob" { 9 } else { 7 };
        let expected = [_did, b"#keys-1"].concat();
        let Ok(sig) = sp_core::ed25519::Signature::try_from(signature) else { return false; };
        _signer_key_id == expected && sp_core::ed25519::Pair::verify(&sig, signed_payload,
            &sp_core::ed25519::Pair::from_seed(&[seed;32]).public())
    }
}

pub struct MockApplicationProvider;
impl ApplicationProvider for MockApplicationProvider {
    fn active_control_did(application_id: &[u8]) -> Option<Vec<u8>> {
        #[cfg(feature = "runtime-benchmarks")]
        if application_id == b"benchmark" {
            return Some(b"did:openpayload:1111111111111111111111".to_vec());
        }
        (application_id == b"talaria").then(|| b"did:alice".to_vec())
    }
    fn verified_domain(application_id: &[u8]) -> Option<Vec<u8>> {
        if application_id != b"talaria" { return None; }
        let domain = crate::PersonaOf::<Test>::try_from(b"push.example.com".to_vec()).ok()?;
        crate::Personas::<Test>::get(domain).and_then(|record| {
            (record.active && record.operator_did.as_slice() == b"did:alice"
                && record.verification_expires_at > Timestamp::get())
                .then(|| b"push.example.com".to_vec())
        })
    }
}

parameter_types! {
    pub const MaxTtl: u64 = 1_000;
    pub const MaxReleaseFee: u128 = 1_000;
}

impl pallet_delivery_policy::Config for Test {
    type MaxPolicyDocumentBytes = frame_support::traits::ConstU32<65536>;
    #[cfg(feature = "runtime-benchmarks")]
    type BenchmarkHelper = TestPolicyBenchmarkHelper;
    type Balance = u128;
    type DidProvider = MockDidProvider;
    type ApplicationProvider = MockApplicationProvider;
    type DnssecTrustAnchorOrigin = frame_system::EnsureRoot<u64>;
    type WeightInfo = ();
    type MaxDidLen = frame_support::traits::ConstU32<64>;
    type MaxTtl = MaxTtl;
    type MaxMessageBytes = frame_support::traits::ConstU32<1_048_576>;
    type MaxReplication = frame_support::traits::ConstU8<5>;
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

pub fn new_test_ext() -> sp_io::TestExternalities {
    frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap()
        .into()
}

#[cfg(feature = "runtime-benchmarks")]
pub struct TestPolicyBenchmarkHelper;
#[cfg(feature = "runtime-benchmarks")]
impl crate::BenchmarkHelper for TestPolicyBenchmarkHelper {
    fn install(_did: &[u8], _application: &[u8]) {}
    fn sign(payload: &[u8]) -> Vec<u8> { use sp_core::Pair; sp_core::ed25519::Pair::from_seed(&[7;32]).sign(payload).0.to_vec() }
    fn signer() -> Vec<u8> { b"did:openpayload:1111111111111111111111#keys-1".to_vec() }
}
