use crate as pallet_application_registry;
use frame_support::{derive_impl, parameter_types};
use sp_core::{ed25519, Pair};
use sp_runtime::BuildStorage;

type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
    pub enum Test {
        System: frame_system,
        Timestamp: pallet_timestamp,
        ApplicationRegistry: pallet_application_registry,
    }
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
}

#[derive_impl(pallet_timestamp::config_preludes::TestDefaultConfig)]
impl pallet_timestamp::Config for Test {}

pub struct TestDidProvider;

pub struct TestDomainProvider;
impl pallet_application_registry::DomainProvider for TestDomainProvider {
    fn controlled_domain(domain: &[u8], control_did: &[u8]) -> bool {
        domain == b"push.example.com" && control_did == b"did:openpayload:1111111111111111111111"
    }
}

impl pallet_delivery_policy::DidProvider<u64> for TestDidProvider {
    fn did_exists(did: &[u8]) -> bool {
        did.starts_with(b"did:openpayload:")
    }

    fn can_update_policy(_who: &u64, _did: &[u8]) -> bool {
        false
    }

    fn verify_did_signature(
        did: &[u8],
        signer_key_id: &[u8],
        signed_payload: &[u8],
        signature: &[u8],
    ) -> bool {
        let seed = match did {
            b"did:openpayload:1111111111111111111111" => 1,
            b"did:openpayload:2222222222222222222222" => 2,
            b"did:openpayload:3333333333333333333333" => 3,
            _ => return false,
        };
        let mut expected_id = did.to_vec();
        expected_id.extend(b"#keys-1");
        let Ok(signature) = ed25519::Signature::try_from(signature) else {
            return false;
        };
        (signer_key_id == expected_id || signer_key_id == b"root" || signer_key_id == b"#v4")
            && ed25519::Pair::verify(
                &signature,
                signed_payload,
                &ed25519::Pair::from_seed(&[seed; 32]).public(),
            )
    }
}

parameter_types! {
    pub const MaxApplicationIdLen: u32 = 64;
    pub const MaxDidLen: u32 = 128;
    pub const MaxKeyIdLen: u32 = 96;
    pub const MaxSignatureLen: u32 = 128;
    pub const MaxApplicationsPerControlDid: u32 = 2;
    pub const MaxPolicyDocumentLen: u32 = 4096;
    pub const MaxPolicyTtlSeconds: u32 = 300;
    pub const MaxDomainLen: u32 = 253;
    pub const MaxLinkedDids: u32 = 8;
}

impl pallet_application_registry::Config for Test {
    #[cfg(feature = "runtime-benchmarks")]
    type BenchmarkHelper = TestBenchmarkHelper;
    type DidProvider = TestDidProvider;
    type DomainProvider = TestDomainProvider;
    type PolicyCleanup = ();
    type GovernanceOrigin = frame_system::EnsureRoot<u64>;
    type WeightInfo = ();
    type MaxApplicationIdLen = MaxApplicationIdLen;
    type MaxDidLen = MaxDidLen;
    type MaxKeyIdLen = MaxKeyIdLen;
    type MaxSignatureLen = MaxSignatureLen;
    type MaxApplicationsPerControlDid = MaxApplicationsPerControlDid;
    type MaxPolicyDocumentLen = MaxPolicyDocumentLen;
    type MaxPolicyTtlSeconds = MaxPolicyTtlSeconds;
    type MaxDomainLen = MaxDomainLen;
    type MaxLinkedDids = MaxLinkedDids;
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
impl crate::BenchmarkHelper for TestBenchmarkHelper {
    fn install_did(_did: &[u8], _seed: u32) {}
    fn sign(seed: u32, payload: &[u8]) -> Vec<u8> {
        ed25519::Pair::from_seed(&[seed as u8; 32])
            .sign(payload)
            .0
            .to_vec()
    }
}
