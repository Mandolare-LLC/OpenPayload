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
        signature == signed_payload
    }
}

pub struct MockApplicationProvider;
impl ApplicationProvider for MockApplicationProvider {
    fn active_control_did(application_id: &[u8]) -> Option<Vec<u8>> {
        (application_id == b"talaria").then(|| b"did:alice".to_vec())
    }
    fn verified_domain(application_id: &[u8]) -> Option<Vec<u8>> {
        if application_id != b"talaria" {
            return None;
        }
        let domain = crate::PersonaOf::<Test>::try_from(b"push.example.com".to_vec()).ok()?;
        crate::Personas::<Test>::get(domain).and_then(|record| {
            (record.active
                && record.operator_did.as_slice() == b"did:alice"
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
    type Balance = u128;
    type DidProvider = MockDidProvider;
    type ApplicationProvider = MockApplicationProvider;
    type PersonaAttestationProvider = ();
    type PersonaAttestorOrigin = frame_system::EnsureRoot<u64>;
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
