#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::too_many_arguments)]

extern crate alloc;

use alloc::vec::Vec;
use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use frame_support::{
    pallet_prelude::*,
    traits::{EnsureOrigin, GetStorageVersion, StorageVersion},
    BoundedVec, CloneNoBound, DebugNoBound, EqNoBound, PartialEqNoBound,
};
use frame_system::pallet_prelude::*;
use scale_info::TypeInfo;
use sp_runtime::traits::{AtLeast32BitUnsigned, Zero};
use sp_runtime::transaction_validity::{
    InvalidTransaction, TransactionValidity, TransactionValidityWithRefund, ValidTransaction,
};
use sp_runtime::SaturatedConversion;

pub use pallet::*;

pub mod weights;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

pub trait DidProvider<AccountId> {
    fn did_exists(did: &[u8]) -> bool;
    fn can_update_policy(who: &AccountId, did: &[u8]) -> bool;
    fn verify_did_signature(
        did: &[u8],
        signer_key_id: &[u8],
        signed_payload: &[u8],
        signature: &[u8],
    ) -> bool;

    fn service_supports_delivery(
        did: &[u8],
        _service_id: &[u8],
        _kind: DeliveryServiceKind,
    ) -> bool {
        // Implementations that do not model typed services still must prove
        // that the target DID exists. Production runtimes should override
        // this with a single lookup that also validates service id and type.
        Self::did_exists(did)
    }
}

/// The registry owns application identity; policy storage only asks who may
/// control an active application. Returning None disables its policy.
pub trait ApplicationProvider {
    fn active_control_did(application_id: &[u8]) -> Option<Vec<u8>>;
    fn verified_domain(_application_id: &[u8]) -> Option<Vec<u8>> {
        None
    }
    fn authorized_send_target(application_id: &[u8], target: &[u8]) -> bool {
        Self::active_control_did(application_id).is_some_and(|control| control.as_slice() == target)
    }
}

impl ApplicationProvider for () {
    fn active_control_did(_application_id: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

#[derive(Encode, Decode, DecodeWithMemTracking, Clone, Copy, PartialEq, Eq, Debug, TypeInfo)]
pub enum DeliveryServiceKind {
    Relay,
    Cache,
    Archive,
    ApplicationControl,
}

/// Verifies a directory/validator attestation that DNS ownership was checked
/// off-chain. The runtime deliberately never performs DNS itself.
pub trait PersonaAttestationProvider<AccountId> {
    fn verify_attestation(attestor: &AccountId, payload: &[u8], signature: &[u8]) -> bool;
}

impl<AccountId> PersonaAttestationProvider<AccountId> for () {
    fn verify_attestation(_attestor: &AccountId, payload: &[u8], signature: &[u8]) -> bool {
        // Useful for pallet-only tests. Production runtimes must provide an
        // implementation backed by an admitted validator/directory identity.
        payload == signature
    }
}

/// Clock-time and transport limits returned by the runtime API. All byte
/// fields describe decoded payload sizes except `max_http_envelope_bytes`.
///
/// `max_message_bytes` and `max_chunks` remain in the SCALE shape for wire
/// compatibility with V2 clients. They are always emitted as their integer
/// maxima and MUST NOT be interpreted as aggregate-message admission limits.
#[derive(
    Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, Debug, TypeInfo, MaxEncodedLen,
)]
pub struct DeliveryConstraints {
    pub requested_cache_seconds: u32,
    pub effective_ttl_seconds: u32,
    pub max_http_envelope_bytes: u32,
    pub max_unchunked_message_bytes: u32,
    pub max_chunk_bytes: u32,
    /// Deprecated compatibility field; always `u32::MAX`.
    pub max_message_bytes: u32,
    /// Deprecated compatibility field; always `u16::MAX`.
    pub max_chunks: u16,
    pub max_replicas: u8,
}

#[derive(Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, Debug, TypeInfo)]
pub enum ResolvedPolicySourceView {
    Did(Vec<u8>),
    Persona(Vec<u8>),
}

#[derive(Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, Debug, TypeInfo)]
pub struct RouteTargetView {
    pub service_did: Vec<u8>,
    pub service_id: Vec<u8>,
    pub priority: u16,
    pub weight: u16,
}

#[derive(Encode, Decode, DecodeWithMemTracking, Clone, Copy, PartialEq, Eq, Debug, TypeInfo)]
pub enum CacheSelectionView {
    Priority,
    Weighted,
}

#[derive(Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, Debug, TypeInfo)]
pub enum DeliveryStepOperationView {
    Forward {
        targets: Vec<RouteTargetView>,
    },
    Store {
        targets: Vec<RouteTargetView>,
        desired_replicas: u8,
        required_replicas: u8,
        selection: CacheSelectionView,
    },
    Archive {
        targets: Vec<RouteTargetView>,
    },
    Send {
        recipient_did: Vec<u8>,
        payload_template: Vec<u8>,
    },
    Call {
        service_did: Vec<u8>,
        service_id: Vec<u8>,
        registered_domain: Vec<u8>,
        payload_template: Vec<u8>,
    },
    RequireProfile,
}

#[derive(Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, Debug, TypeInfo)]
pub struct DeliveryStepView {
    pub id: Vec<u8>,
    pub operation: DeliveryStepOperationView,
}

#[derive(Encode, Decode, DecodeWithMemTracking, Clone, Copy, PartialEq, Eq, Debug, TypeInfo)]
pub enum TransitionTriggerView {
    Success,
    Failure,
    Always,
}

#[derive(Encode, Decode, DecodeWithMemTracking, Clone, Copy, PartialEq, Eq, Debug, TypeInfo)]
pub enum TransitionModeView {
    Next,
    Fork,
}

#[derive(Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, Debug, TypeInfo)]
pub struct DeliveryTransitionView {
    pub from: Vec<u8>,
    pub to: Vec<u8>,
    pub trigger: TransitionTriggerView,
    pub mode: TransitionModeView,
}

#[derive(Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, Debug, TypeInfo)]
pub enum PolicyActionView {
    DeliveryPlanV1 {
        entry_step: Vec<u8>,
        steps: Vec<DeliveryStepView>,
        transitions: Vec<DeliveryTransitionView>,
    },
    RejectV1 {
        reason_code: u16,
    },
    BaseDidDeliveryV1,
}

#[derive(Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, Debug, TypeInfo)]
pub struct ResolvedDeliveryPolicyView {
    pub source: ResolvedPolicySourceView,
    pub policy_id: Vec<u8>,
    pub policy_revision: u64,
    pub rule_id: Vec<u8>,
    pub rule_priority: u32,
    pub action: PolicyActionView,
    pub effective_constraints: DeliveryConstraints,
    pub policy_ttl_seconds: u32,
}

sp_api::decl_runtime_apis! {
    /// Deterministically resolves the winning policy at the queried block.
    /// Clients should call this against finalized state through `state_call`.
    pub trait DeliveryPolicyRuntimeApi {
        fn resolve_delivery_policy(
            recipient: Vec<u8>,
            persona: Option<Vec<u8>>,
            tag: Option<Vec<u8>>,
        ) -> Option<ResolvedDeliveryPolicyView>;
    }
}

impl<AccountId> DidProvider<AccountId> for () {
    fn did_exists(_did: &[u8]) -> bool {
        true
    }

    fn can_update_policy(_who: &AccountId, _did: &[u8]) -> bool {
        true
    }

    fn verify_did_signature(
        _did: &[u8],
        _signer_key_id: &[u8],
        _signed_payload: &[u8],
        _signature: &[u8],
    ) -> bool {
        true
    }
}

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use crate::weights::WeightInfo as _;

    const STORAGE_VERSION: StorageVersion = StorageVersion::new(5);
    const MIGRATED_POLICY_TTL_SECONDS: u32 = 60;
    const UNBOUNDED_MESSAGE_BYTES_COMPAT: u32 = u32::MAX;
    const UNBOUNDED_CHUNKS_COMPAT: u16 = u16::MAX;
    const PERSONA_ATTESTATION_DOMAIN: &[u8] = b"openpayload:persona:dns:v1";

    #[cfg(feature = "try-runtime")]
    #[derive(Encode, Decode, PartialEq, Eq)]
    struct MigrationSnapshot {
        recipient_policies: u64,
        tag_policies: u64,
        legacy_persona_policies: u64,
        policy_nonces: u64,
        did_delivery_constraints: u64,
        personas: u64,
        persona_nonces: u64,
        persona_operator_nonces: u64,
        persona_attestors: u64,
        did_policies_v2: u64,
        persona_policies_v2: u64,
        policy_v2_nonces: u64,
    }

    pub type DidOf<T> = BoundedVec<u8, <T as Config>::MaxDidLen>;
    pub type BalanceOf<T> = <T as Config>::Balance;
    pub type SignerKeyId = BoundedVec<u8, ConstU32<256>>;
    pub type PersonaOf<T> = BoundedVec<u8, <T as Config>::MaxPersonaLen>;
    pub type PolicyIdOf<T> = BoundedVec<u8, <T as Config>::MaxPolicyIdLen>;
    pub type RuleIdOf<T> = BoundedVec<u8, <T as Config>::MaxRuleIdLen>;
    pub type TagOf<T> = BoundedVec<u8, <T as Config>::MaxTagLen>;
    pub type ApplicationIdOf = BoundedVec<u8, ConstU32<64>>;
    pub type PayloadTemplateOf = BoundedVec<u8, ConstU32<4096>>;
    pub type ServiceRefOf<T> = BoundedVec<u8, <T as Config>::MaxServiceRefLen>;
    pub type ControllerKeysOf<T> = BoundedVec<SignerKeyId, <T as Config>::MaxPersonaControllerKeys>;

    #[derive(
        Encode,
        Decode,
        DecodeWithMemTracking,
        CloneNoBound,
        PartialEqNoBound,
        EqNoBound,
        DebugNoBound,
        TypeInfo,
        MaxEncodedLen,
    )]
    #[scale_info(skip_type_params(T))]
    #[codec(mel_bound())]
    #[codec(decode_bound())]
    #[codec(decode_with_mem_tracking_bound())]
    pub enum PolicyScopeV2<T: Config> {
        Did(DidOf<T>),
        Persona(PersonaOf<T>),
    }

    #[derive(
        Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, Debug, TypeInfo, MaxEncodedLen,
    )]
    pub struct RequestedDeliveryConstraints {
        pub requested_cache_seconds: u32,
        pub max_http_envelope_bytes: u32,
        pub max_unchunked_message_bytes: u32,
        pub max_chunk_bytes: u32,
        /// Deprecated compatibility field. The runtime accepts but ignores it.
        pub max_message_bytes: u32,
        /// Deprecated compatibility field. The runtime accepts but ignores it.
        pub max_chunks: u16,
        pub max_replicas: u8,
    }

    #[derive(
        Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, Debug, TypeInfo, MaxEncodedLen,
    )]
    pub struct DeliveryConstraintOverrides {
        pub requested_cache_seconds: Option<u32>,
        pub max_http_envelope_bytes: Option<u32>,
        pub max_unchunked_message_bytes: Option<u32>,
        pub max_chunk_bytes: Option<u32>,
        /// Deprecated compatibility field. The runtime accepts but ignores it.
        pub max_message_bytes: Option<u32>,
        /// Deprecated compatibility field. The runtime accepts but ignores it.
        pub max_chunks: Option<u16>,
        pub max_replicas: Option<u8>,
    }

    #[derive(
        Encode,
        Decode,
        DecodeWithMemTracking,
        CloneNoBound,
        PartialEqNoBound,
        EqNoBound,
        DebugNoBound,
        TypeInfo,
        MaxEncodedLen,
    )]
    #[scale_info(skip_type_params(T))]
    #[codec(mel_bound())]
    #[codec(decode_bound())]
    #[codec(decode_with_mem_tracking_bound())]
    pub enum PolicyCondition<T: Config> {
        TagEquals(TagOf<T>),
        TagPrefix(TagOf<T>),
        TagAbsent,
        RecipientEquals(DidOf<T>),
        RecipientIn(BoundedVec<DidOf<T>, T::MaxConditionRecipients>),
        EventEquals(PolicyEvent),
    }

    #[derive(
        Encode,
        Decode,
        DecodeWithMemTracking,
        Clone,
        Copy,
        PartialEq,
        Eq,
        Debug,
        TypeInfo,
        MaxEncodedLen,
    )]
    pub enum PolicyEvent {
        RelayDelivered,
        CacheStored,
        RelayAccepted,
    }

    #[derive(
        Encode,
        Decode,
        DecodeWithMemTracking,
        CloneNoBound,
        PartialEqNoBound,
        EqNoBound,
        DebugNoBound,
        TypeInfo,
        MaxEncodedLen,
    )]
    #[scale_info(skip_type_params(T))]
    #[codec(mel_bound())]
    #[codec(decode_bound())]
    #[codec(decode_with_mem_tracking_bound())]
    pub struct RouteTarget<T: Config> {
        pub service_did: DidOf<T>,
        pub service_id: ServiceRefOf<T>,
        pub priority: u16,
        pub weight: u16,
    }

    #[derive(
        Encode,
        Decode,
        DecodeWithMemTracking,
        Clone,
        Copy,
        PartialEq,
        Eq,
        Debug,
        TypeInfo,
        MaxEncodedLen,
    )]
    pub enum CacheSelection {
        Priority,
        Weighted,
    }

    #[derive(
        Encode,
        Decode,
        DecodeWithMemTracking,
        CloneNoBound,
        PartialEqNoBound,
        EqNoBound,
        DebugNoBound,
        TypeInfo,
        MaxEncodedLen,
    )]
    #[scale_info(skip_type_params(T))]
    #[codec(mel_bound())]
    #[codec(decode_bound())]
    #[codec(decode_with_mem_tracking_bound())]
    pub enum DeliveryStepOperation<T: Config> {
        Forward {
            targets: BoundedVec<RouteTarget<T>, T::MaxRouteTargets>,
        },
        Store {
            targets: BoundedVec<RouteTarget<T>, T::MaxRouteTargets>,
            desired_replicas: u8,
            required_replicas: u8,
            selection: CacheSelection,
        },
        Archive {
            targets: BoundedVec<RouteTarget<T>, T::MaxRouteTargets>,
        },
        Send {
            recipient_did: DidOf<T>,
            payload_template: PayloadTemplateOf,
        },
        Call {
            service_did: DidOf<T>,
            service_id: ServiceRefOf<T>,
            registered_domain: PersonaOf<T>,
            payload_template: PayloadTemplateOf,
        },
        /// Requires the public Persona release profile before route steps run.
        RequireProfile,
    }

    #[derive(
        Encode,
        Decode,
        DecodeWithMemTracking,
        CloneNoBound,
        PartialEqNoBound,
        EqNoBound,
        DebugNoBound,
        TypeInfo,
        MaxEncodedLen,
    )]
    #[scale_info(skip_type_params(T))]
    #[codec(mel_bound())]
    #[codec(decode_bound())]
    #[codec(decode_with_mem_tracking_bound())]
    pub struct DeliveryStep<T: Config> {
        pub id: RuleIdOf<T>,
        pub operation: DeliveryStepOperation<T>,
    }

    #[derive(
        Encode,
        Decode,
        DecodeWithMemTracking,
        Clone,
        Copy,
        PartialEq,
        Eq,
        Debug,
        TypeInfo,
        MaxEncodedLen,
    )]
    pub enum TransitionTrigger {
        Success,
        Failure,
        Always,
    }

    #[derive(
        Encode,
        Decode,
        DecodeWithMemTracking,
        Clone,
        Copy,
        PartialEq,
        Eq,
        Debug,
        TypeInfo,
        MaxEncodedLen,
    )]
    pub enum TransitionMode {
        Next,
        Fork,
    }

    #[derive(
        Encode,
        Decode,
        DecodeWithMemTracking,
        CloneNoBound,
        PartialEqNoBound,
        EqNoBound,
        DebugNoBound,
        TypeInfo,
        MaxEncodedLen,
    )]
    #[scale_info(skip_type_params(T))]
    #[codec(mel_bound())]
    #[codec(decode_bound())]
    #[codec(decode_with_mem_tracking_bound())]
    pub struct DeliveryTransition<T: Config> {
        pub from: RuleIdOf<T>,
        pub to: RuleIdOf<T>,
        pub trigger: TransitionTrigger,
        pub mode: TransitionMode,
    }

    #[derive(
        Encode,
        Decode,
        DecodeWithMemTracking,
        CloneNoBound,
        PartialEqNoBound,
        EqNoBound,
        DebugNoBound,
        TypeInfo,
        MaxEncodedLen,
    )]
    #[scale_info(skip_type_params(T))]
    #[codec(mel_bound())]
    #[codec(decode_bound())]
    #[codec(decode_with_mem_tracking_bound())]
    pub struct DeliveryPlanV1<T: Config> {
        pub entry_step: RuleIdOf<T>,
        pub steps: BoundedVec<DeliveryStep<T>, T::MaxDeliverySteps>,
        pub transitions: BoundedVec<DeliveryTransition<T>, T::MaxDeliveryTransitions>,
    }

    #[derive(
        Encode,
        Decode,
        DecodeWithMemTracking,
        CloneNoBound,
        PartialEqNoBound,
        EqNoBound,
        DebugNoBound,
        TypeInfo,
        MaxEncodedLen,
    )]
    #[scale_info(skip_type_params(T))]
    #[codec(mel_bound())]
    #[codec(decode_bound())]
    #[codec(decode_with_mem_tracking_bound())]
    pub enum PolicyActionV2<T: Config> {
        DeliveryPlanV1(DeliveryPlanV1<T>),
        RejectV1 { reason_code: u16 },
        BaseDidDeliveryV1,
    }

    #[derive(
        Encode,
        Decode,
        DecodeWithMemTracking,
        CloneNoBound,
        PartialEqNoBound,
        EqNoBound,
        DebugNoBound,
        TypeInfo,
        MaxEncodedLen,
    )]
    #[scale_info(skip_type_params(T))]
    #[codec(mel_bound())]
    #[codec(decode_bound())]
    #[codec(decode_with_mem_tracking_bound())]
    pub struct PolicyRule<T: Config> {
        pub id: RuleIdOf<T>,
        pub priority: u32,
        pub conditions: BoundedVec<PolicyCondition<T>, T::MaxRuleConditions>,
        pub action: PolicyActionV2<T>,
        pub constraint_overrides: Option<DeliveryConstraintOverrides>,
    }

    #[derive(
        Encode,
        Decode,
        DecodeWithMemTracking,
        CloneNoBound,
        PartialEqNoBound,
        EqNoBound,
        DebugNoBound,
        TypeInfo,
        MaxEncodedLen,
    )]
    #[scale_info(skip_type_params(T))]
    #[codec(mel_bound())]
    #[codec(decode_bound())]
    #[codec(decode_with_mem_tracking_bound())]
    pub struct DeliveryPolicyV2<T: Config> {
        pub policy_id: PolicyIdOf<T>,
        pub scope: PolicyScopeV2<T>,
        pub revision: u64,
        pub operator_did: DidOf<T>,
        pub ruleset: BoundedVec<PolicyRule<T>, T::MaxPolicyRules>,
        pub policy_ttl_seconds: u32,
    }

    #[derive(
        Encode,
        Decode,
        DecodeWithMemTracking,
        CloneNoBound,
        PartialEqNoBound,
        EqNoBound,
        DebugNoBound,
        TypeInfo,
        MaxEncodedLen,
    )]
    #[scale_info(skip_type_params(T))]
    #[codec(mel_bound())]
    #[codec(decode_bound())]
    #[codec(decode_with_mem_tracking_bound())]
    pub enum PolicyScopeV3<T: Config> {
        Did(DidOf<T>),
        Persona(PersonaOf<T>),
        Application(ApplicationIdOf),
    }

    #[derive(
        Encode,
        Decode,
        DecodeWithMemTracking,
        CloneNoBound,
        PartialEqNoBound,
        EqNoBound,
        DebugNoBound,
        TypeInfo,
        MaxEncodedLen,
    )]
    #[scale_info(skip_type_params(T))]
    #[codec(mel_bound())]
    #[codec(decode_bound())]
    #[codec(decode_with_mem_tracking_bound())]
    pub struct DeliveryPolicyV3<T: Config> {
        pub policy_id: PolicyIdOf<T>,
        pub scope: PolicyScopeV3<T>,
        pub revision: u64,
        pub operator_did: DidOf<T>,
        pub ruleset: BoundedVec<PolicyRule<T>, T::MaxPolicyRules>,
        pub policy_ttl_seconds: u32,
    }

    #[derive(
        Encode,
        Decode,
        DecodeWithMemTracking,
        CloneNoBound,
        PartialEqNoBound,
        EqNoBound,
        DebugNoBound,
        TypeInfo,
        MaxEncodedLen,
    )]
    #[scale_info(skip_type_params(T))]
    #[codec(mel_bound())]
    #[codec(decode_bound())]
    #[codec(decode_with_mem_tracking_bound())]
    pub enum PolicyV3Operation<T: Config> {
        SetPolicy(DeliveryPolicyV3<T>),
        ClearPolicy(PolicyScopeV3<T>),
    }

    #[derive(
        Encode,
        Decode,
        DecodeWithMemTracking,
        CloneNoBound,
        PartialEqNoBound,
        EqNoBound,
        DebugNoBound,
        TypeInfo,
    )]
    #[scale_info(skip_type_params(T))]
    #[codec(mel_bound())]
    #[codec(decode_bound())]
    #[codec(decode_with_mem_tracking_bound())]
    pub struct PolicyV3AuthorizationPayload<T: Config> {
        pub operator_did: DidOf<T>,
        pub operation: PolicyV3Operation<T>,
        pub nonce: u64,
        pub valid_until: u64,
        pub signer_key_id: SignerKeyId,
    }

    #[derive(Decode)]
    #[codec(decode_bound())]
    struct LegacyDeliveryPolicyV2<T: Config> {
        policy_id: PolicyIdOf<T>,
        scope: PolicyScopeV2<T>,
        revision: u64,
        operator_did: DidOf<T>,
        ruleset: BoundedVec<PolicyRule<T>, T::MaxPolicyRules>,
    }

    #[derive(
        Encode,
        Decode,
        DecodeWithMemTracking,
        CloneNoBound,
        PartialEqNoBound,
        EqNoBound,
        DebugNoBound,
        TypeInfo,
        MaxEncodedLen,
    )]
    #[scale_info(skip_type_params(T))]
    #[codec(mel_bound())]
    #[codec(decode_bound())]
    #[codec(decode_with_mem_tracking_bound())]
    pub struct PersonaRecord<T: Config> {
        pub operator_did: DidOf<T>,
        pub controller_key_ids: ControllerKeysOf<T>,
        pub controller_threshold: u8,
        pub delivery_constraints: Option<DeliveryConstraints>,
        pub dns_proof_hash: [u8; 32],
        pub verified_at: u64,
        pub verification_expires_at: u64,
        pub revision: u64,
        pub active: bool,
    }

    #[derive(
        Encode,
        Decode,
        DecodeWithMemTracking,
        CloneNoBound,
        PartialEqNoBound,
        EqNoBound,
        DebugNoBound,
        TypeInfo,
        MaxEncodedLen,
    )]
    #[scale_info(skip_type_params(T))]
    #[codec(mel_bound())]
    #[codec(decode_bound())]
    #[codec(decode_with_mem_tracking_bound())]
    pub struct PersonaAttestationPayload<T: Config> {
        pub domain: BoundedVec<u8, ConstU32<64>>,
        pub genesis_hash: T::Hash,
        pub persona: PersonaOf<T>,
        pub operator_did: DidOf<T>,
        pub dns_proof_hash: [u8; 32],
        pub challenge_nonce: u64,
        pub verification_expires_at: u64,
    }

    #[derive(
        Encode,
        Decode,
        DecodeWithMemTracking,
        CloneNoBound,
        PartialEqNoBound,
        EqNoBound,
        DebugNoBound,
        TypeInfo,
        MaxEncodedLen,
    )]
    #[scale_info(skip_type_params(T))]
    #[codec(mel_bound())]
    #[codec(decode_bound())]
    #[codec(decode_with_mem_tracking_bound())]
    pub struct ResolvedDeliveryPolicy<T: Config> {
        pub source: PolicyScopeV2<T>,
        pub policy_id: PolicyIdOf<T>,
        pub policy_revision: u64,
        pub rule_id: RuleIdOf<T>,
        pub rule_priority: u32,
        pub action: PolicyActionV2<T>,
        pub effective_constraints: DeliveryConstraints,
        pub policy_ttl_seconds: u32,
    }

    #[derive(
        Encode,
        Decode,
        DecodeWithMemTracking,
        CloneNoBound,
        PartialEqNoBound,
        EqNoBound,
        DebugNoBound,
        TypeInfo,
    )]
    #[scale_info(skip_type_params(T))]
    #[codec(mel_bound())]
    #[codec(decode_bound())]
    #[codec(decode_with_mem_tracking_bound())]
    pub enum PolicyV2Operation<T: Config> {
        SetPolicy(DeliveryPolicyV2<T>),
        ClearPolicy(PolicyScopeV2<T>),
        SetDidConstraints {
            did: DidOf<T>,
            constraints: RequestedDeliveryConstraints,
        },
        SetPersonaConstraints {
            persona: PersonaOf<T>,
            constraints: RequestedDeliveryConstraints,
        },
    }

    #[derive(
        Encode,
        Decode,
        DecodeWithMemTracking,
        CloneNoBound,
        PartialEqNoBound,
        EqNoBound,
        DebugNoBound,
        TypeInfo,
    )]
    #[scale_info(skip_type_params(T))]
    #[codec(mel_bound())]
    #[codec(decode_bound())]
    #[codec(decode_with_mem_tracking_bound())]
    pub struct PolicyV2AuthorizationPayload<T: Config> {
        pub operator_did: DidOf<T>,
        pub operation: PolicyV2Operation<T>,
        pub nonce: u64,
        pub valid_until: u64,
        pub signer_key_id: SignerKeyId,
    }

    #[derive(
        Encode,
        Decode,
        DecodeWithMemTracking,
        CloneNoBound,
        PartialEqNoBound,
        EqNoBound,
        DebugNoBound,
        TypeInfo,
    )]
    #[scale_info(skip_type_params(T))]
    #[codec(mel_bound())]
    #[codec(decode_bound())]
    #[codec(decode_with_mem_tracking_bound())]
    pub enum PersonaOperation<T: Config> {
        Register {
            persona: PersonaOf<T>,
            controller_key_ids: ControllerKeysOf<T>,
            controller_threshold: u8,
            constraints: Option<RequestedDeliveryConstraints>,
            dns_proof_hash: [u8; 32],
            challenge_nonce: u64,
            verification_expires_at: u64,
            attestor: T::AccountId,
            attestation_signature: Vec<u8>,
        },
        Renew {
            persona: PersonaOf<T>,
            constraints: Option<RequestedDeliveryConstraints>,
            dns_proof_hash: [u8; 32],
            challenge_nonce: u64,
            verification_expires_at: u64,
            attestor: T::AccountId,
            attestation_signature: Vec<u8>,
        },
        Revoke {
            persona: PersonaOf<T>,
        },
        RotateControllers {
            persona: PersonaOf<T>,
            controller_key_ids: ControllerKeysOf<T>,
            controller_threshold: u8,
        },
        Transfer {
            persona: PersonaOf<T>,
            new_operator_did: DidOf<T>,
            new_controller_key_ids: ControllerKeysOf<T>,
            new_controller_threshold: u8,
            constraints: Option<RequestedDeliveryConstraints>,
            dns_proof_hash: [u8; 32],
            challenge_nonce: u64,
            verification_expires_at: u64,
            attestor: T::AccountId,
            attestation_signature: Vec<u8>,
            new_operator_signer_key_id: SignerKeyId,
            new_operator_signature: Vec<u8>,
        },
        RegisterNamed {
            persona: PersonaOf<T>,
            controller_key_ids: ControllerKeysOf<T>,
            controller_threshold: u8,
            constraints: Option<RequestedDeliveryConstraints>,
        },
    }

    #[derive(
        Encode,
        Decode,
        DecodeWithMemTracking,
        CloneNoBound,
        PartialEqNoBound,
        EqNoBound,
        DebugNoBound,
        TypeInfo,
    )]
    #[scale_info(skip_type_params(T))]
    #[codec(mel_bound())]
    #[codec(decode_bound())]
    #[codec(decode_with_mem_tracking_bound())]
    pub struct PersonaAuthorizationPayload<T: Config> {
        pub operator_did: DidOf<T>,
        pub operation: PersonaOperation<T>,
        pub nonce: u64,
        pub valid_until: u64,
        pub signer_key_id: SignerKeyId,
    }

    #[derive(
        Encode,
        Decode,
        DecodeWithMemTracking,
        CloneNoBound,
        PartialEqNoBound,
        EqNoBound,
        DebugNoBound,
        TypeInfo,
    )]
    #[scale_info(skip_type_params(T))]
    #[codec(mel_bound())]
    #[codec(decode_bound())]
    #[codec(decode_with_mem_tracking_bound())]
    pub struct PersonaTransferAcceptancePayload<T: Config> {
        pub domain: BoundedVec<u8, ConstU32<64>>,
        pub genesis_hash: T::Hash,
        pub persona: PersonaOf<T>,
        pub current_operator_did: DidOf<T>,
        pub new_operator_did: DidOf<T>,
        pub new_controller_key_ids: ControllerKeysOf<T>,
        pub new_controller_threshold: u8,
        pub constraints: Option<RequestedDeliveryConstraints>,
        pub dns_proof_hash: [u8; 32],
        pub challenge_nonce: u64,
        pub verification_expires_at: u64,
        pub new_operator_signer_key_id: SignerKeyId,
    }

    #[derive(
        Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, Debug, TypeInfo, MaxEncodedLen,
    )]
    pub enum ExpirationBehavior {
        DeleteOnExpiry,
        KeepHeaderPreview,
        TombstoneReference,
    }

    #[derive(
        Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, Debug, TypeInfo, MaxEncodedLen,
    )]
    pub struct ReleasePricing<Balance> {
        pub base_fee: Balance,
        pub per_kib_fee: Balance,
    }

    #[derive(
        Encode,
        Decode,
        DecodeWithMemTracking,
        Clone,
        PartialEq,
        Eq,
        DebugNoBound,
        TypeInfo,
        MaxEncodedLen,
    )]
    #[scale_info(skip_type_params(T))]
    #[codec(mel_bound())]
    #[codec(decode_bound())]
    #[codec(decode_with_mem_tracking_bound())]
    pub struct DeliveryPolicy<T: Config> {
        pub effective_ttl: BlockNumberFor<T>,
        pub max_message_bytes: u32,
        pub cache_eligible: bool,
        pub replication: Option<u8>,
        pub encrypted_header_preview_bytes: Option<u32>,
        pub release_pricing: Option<ReleasePricing<BalanceOf<T>>>,
        pub expiration_behavior: Option<ExpirationBehavior>,
    }

    #[derive(
        Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, Debug, TypeInfo, MaxEncodedLen,
    )]
    pub enum PolicyScope {
        Recipient,
        Tag,
        Persona,
    }

    #[derive(
        Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, DebugNoBound, TypeInfo,
    )]
    #[scale_info(skip_type_params(T))]
    #[codec(mel_bound())]
    #[codec(decode_bound())]
    #[codec(decode_with_mem_tracking_bound())]
    pub enum PolicyAction<T: Config> {
        SetRecipient(DeliveryPolicy<T>),
        ClearRecipient,
        SetTag(DeliveryPolicy<T>),
        SetPersona(DeliveryPolicy<T>),
    }

    #[derive(
        Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, DebugNoBound, TypeInfo,
    )]
    #[scale_info(skip_type_params(T))]
    #[codec(mel_bound())]
    #[codec(decode_bound())]
    #[codec(decode_with_mem_tracking_bound())]
    pub struct PolicyAuthorizationPayload<T: Config> {
        pub did: DidOf<T>,
        pub action: PolicyAction<T>,
        pub nonce: u64,
        pub valid_until: u64,
        pub signer_key_id: SignerKeyId,
    }

    #[pallet::config]
    pub trait Config:
        frame_system::Config<RuntimeEvent: From<Event<Self>>> + pallet_timestamp::Config
    {
        type Balance: Parameter
            + Member
            + AtLeast32BitUnsigned
            + Default
            + Copy
            + DecodeWithMemTracking
            + MaxEncodedLen
            + TypeInfo;
        type DidProvider: DidProvider<Self::AccountId>;
        type ApplicationProvider: ApplicationProvider;
        type PersonaAttestationProvider: PersonaAttestationProvider<Self::AccountId>;
        type PersonaAttestorOrigin: EnsureOrigin<Self::RuntimeOrigin>;
        type WeightInfo: weights::WeightInfo;

        #[pallet::constant]
        type MaxDidLen: Get<u32>;
        #[pallet::constant]
        type MaxTtl: Get<BlockNumberFor<Self>>;
        #[pallet::constant]
        type MaxMessageBytes: Get<u32>;
        #[pallet::constant]
        type MaxReplication: Get<u8>;
        #[pallet::constant]
        type MaxHeaderPreviewBytes: Get<u32>;
        #[pallet::constant]
        type MaxReleaseFee: Get<Self::Balance>;

        // Policy V2 and Persona bounds. These are deliberately runtime
        // constants so metadata exposes the network's validation envelope.
        #[pallet::constant]
        type MaxPersonaLen: Get<u32>;
        #[pallet::constant]
        type MaxPersonaControllerKeys: Get<u32>;
        #[pallet::constant]
        type MaxPolicyIdLen: Get<u32>;
        #[pallet::constant]
        type MaxPolicyRules: Get<u32>;
        #[pallet::constant]
        type MaxRuleIdLen: Get<u32>;
        #[pallet::constant]
        type MaxRuleConditions: Get<u32>;
        #[pallet::constant]
        type MaxConditionRecipients: Get<u32>;
        #[pallet::constant]
        type MaxTagLen: Get<u32>;
        #[pallet::constant]
        type MaxServiceRefLen: Get<u32>;
        #[pallet::constant]
        type MaxRouteTargets: Get<u32>;
        #[pallet::constant]
        type MaxDeliverySteps: Get<u32>;
        #[pallet::constant]
        type MaxDeliveryTransitions: Get<u32>;
        /// Aggregate structural work accepted in one policy. Per-field bounds
        /// alone multiply (rules x steps x targets), so this ceiling prevents
        /// a validly encoded policy from creating unbounded validation work.
        #[pallet::constant]
        type MaxPolicyValidationUnits: Get<u32>;
        #[pallet::constant]
        type MaxTtlSeconds: Get<u32>;
        #[pallet::constant]
        type MaxPolicyTtlSeconds: Get<u32>;
        #[pallet::constant]
        type MaxHttpEnvelopeBytes: Get<u32>;
        #[pallet::constant]
        type MaxUnchunkedMessageBytes: Get<u32>;
        #[pallet::constant]
        type MaxChunkBytes: Get<u32>;
        #[pallet::constant]
        type MaxReplicas: Get<u8>;
    }

    #[pallet::pallet]
    #[pallet::storage_version(STORAGE_VERSION)]
    pub struct Pallet<T>(_);

    #[pallet::storage]
    pub type RecipientPolicies<T: Config> =
        StorageMap<_, Blake2_128Concat, DidOf<T>, DeliveryPolicy<T>, OptionQuery>;

    #[pallet::storage]
    pub type TagPolicies<T: Config> =
        StorageMap<_, Blake2_128Concat, DidOf<T>, DeliveryPolicy<T>, OptionQuery>;

    #[pallet::storage]
    pub type PersonaPolicies<T: Config> =
        StorageMap<_, Blake2_128Concat, DidOf<T>, DeliveryPolicy<T>, OptionQuery>;

    #[pallet::storage]
    pub type PolicyNonces<T: Config> = StorageMap<_, Blake2_128Concat, DidOf<T>, u64, ValueQuery>;

    /// DID-level transport constraints. A missing value means network maxima.
    /// Kept in companion storage so the live DID record encoding is unchanged.
    #[pallet::storage]
    #[pallet::getter(fn did_delivery_constraints)]
    pub type DidDeliveryConstraints<T: Config> =
        StorageMap<_, Blake2_128Concat, DidOf<T>, DeliveryConstraints, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn persona)]
    pub type Personas<T: Config> =
        StorageMap<_, Blake2_128Concat, PersonaOf<T>, PersonaRecord<T>, OptionQuery>;

    /// Companion marker leaves the deployed PersonaRecord SCALE encoding
    /// untouched. Unmarked records remain DNS-verified Personas.
    #[pallet::storage]
    #[pallet::getter(fn non_dns_persona)]
    pub type NonDnsPersonas<T: Config> =
        StorageMap<_, Blake2_128Concat, PersonaOf<T>, (), OptionQuery>;

    #[pallet::storage]
    pub type PersonaNonces<T: Config> =
        StorageMap<_, Blake2_128Concat, PersonaOf<T>, u64, ValueQuery>;

    #[pallet::storage]
    pub type PersonaOperatorNonces<T: Config> =
        StorageMap<_, Blake2_128Concat, DidOf<T>, u64, ValueQuery>;

    /// Governance-admitted Directory/validator accounts permitted to attest
    /// off-chain DNS validation. Admission and cryptographic verification are
    /// independent checks.
    #[pallet::storage]
    #[pallet::getter(fn persona_attestor)]
    pub type PersonaAttestors<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, (), OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn did_policy_v2)]
    pub type DidPoliciesV2<T: Config> =
        StorageMap<_, Blake2_128Concat, DidOf<T>, DeliveryPolicyV2<T>, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn persona_policy_v2)]
    pub type PersonaPoliciesV2<T: Config> =
        StorageMap<_, Blake2_128Concat, PersonaOf<T>, DeliveryPolicyV2<T>, OptionQuery>;

    #[pallet::storage]
    pub type PolicyV2Nonces<T: Config> = StorageMap<_, Blake2_128Concat, DidOf<T>, u64, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn policy_v3)]
    pub type PoliciesV3<T: Config> =
        StorageMap<_, Blake2_128Concat, PolicyScopeV3<T>, DeliveryPolicyV3<T>, OptionQuery>;

    #[pallet::storage]
    pub type PolicyV3Nonces<T: Config> = StorageMap<_, Blake2_128Concat, DidOf<T>, u64, ValueQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        PolicySet {
            scope: PolicyScope,
            did: DidOf<T>,
        },
        PolicyCleared {
            scope: PolicyScope,
            did: DidOf<T>,
        },
        DidDeliveryConstraintsSet {
            did: DidOf<T>,
        },
        PersonaRegistered {
            persona: PersonaOf<T>,
            operator_did: DidOf<T>,
        },
        PersonaRenewed {
            persona: PersonaOf<T>,
            revision: u64,
        },
        PersonaRevoked {
            persona: PersonaOf<T>,
        },
        PersonaControllersRotated {
            persona: PersonaOf<T>,
            revision: u64,
        },
        PersonaTransferred {
            persona: PersonaOf<T>,
            previous_operator_did: DidOf<T>,
            new_operator_did: DidOf<T>,
            revision: u64,
        },
        PersonaAttestorUpdated {
            attestor: T::AccountId,
            approved: bool,
        },
        PolicyV2Set {
            scope: PolicyScopeV2<T>,
            policy_id: PolicyIdOf<T>,
            revision: u64,
        },
        PolicyV2Cleared {
            scope: PolicyScopeV2<T>,
        },
        PolicyV3Set {
            scope: PolicyScopeV3<T>,
            policy_id: PolicyIdOf<T>,
            revision: u64,
        },
        PolicyV3Cleared {
            scope: PolicyScopeV3<T>,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        DidTooLong,
        DidNotFound,
        NotPolicyController,
        InvalidTtl,
        MaxMessageSizeExceeded,
        InvalidReplication,
        HeaderPreviewTooLarge,
        ReleaseFeeTooLarge,
        PolicyNotFound,
        InvalidPolicyPayload,
        InvalidPolicyNonce,
        PolicyAuthorizationExpired,
        InvalidSignature,
        InvalidConstraints,
        InvalidPersona,
        PersonaAlreadyExists,
        PersonaNotFound,
        PersonaInactive,
        PersonaVerificationExpired,
        InvalidPersonaController,
        InvalidPersonaAttestation,
        PersonaAttestorNotApproved,
        InvalidPersonaNonce,
        InvalidPersonaPayload,
        InvalidPersonaOperatorNonce,
        InvalidPolicyId,
        InvalidPolicyScope,
        InvalidPolicyRevision,
        InvalidPolicyTtl,
        EmptyRuleset,
        DuplicateRuleId,
        InvalidTag,
        InvalidCondition,
        InvalidDeliveryPlan,
        DuplicateStepId,
        DeliveryPlanCycle,
        InvalidRouteTarget,
        ConstraintOverrideExceedsScope,
        InvalidPolicyV2Payload,
        InvalidPolicyV2Nonce,
        LegacyPolicyDeprecated,
        InvalidRulePriority,
        MultipleForwardSteps,
        PolicyTooComplex,
        InvalidCallDomain,
        InvalidPayloadTemplate,
        InvalidPolicyV3Payload,
        InvalidPolicyV3Nonce,
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_runtime_upgrade() -> Weight {
            let on_chain = Pallet::<T>::on_chain_storage_version();
            let mut migrated = 0u64;
            if on_chain < StorageVersion::new(4) {
                DidPoliciesV2::<T>::translate::<LegacyDeliveryPolicyV2<T>, _>(|_, old| {
                    migrated = migrated.saturating_add(1);
                    Some(DeliveryPolicyV2 {
                        policy_id: old.policy_id,
                        scope: old.scope,
                        revision: old.revision,
                        operator_did: old.operator_did,
                        ruleset: old.ruleset,
                        policy_ttl_seconds: MIGRATED_POLICY_TTL_SECONDS,
                    })
                });
                PersonaPoliciesV2::<T>::translate::<LegacyDeliveryPolicyV2<T>, _>(|_, old| {
                    migrated = migrated.saturating_add(1);
                    Some(DeliveryPolicyV2 {
                        policy_id: old.policy_id,
                        scope: old.scope,
                        revision: old.revision,
                        operator_did: old.operator_did,
                        ruleset: old.ruleset,
                        policy_ttl_seconds: MIGRATED_POLICY_TTL_SECONDS,
                    })
                });
            }
            if on_chain < STORAGE_VERSION {
                for (did, old) in DidPoliciesV2::<T>::iter() {
                    let scope = PolicyScopeV3::Did(did);
                    if let Ok(policy_id) = Self::expected_policy_id_v3(&scope) {
                        PoliciesV3::<T>::insert(
                            &scope,
                            DeliveryPolicyV3 {
                                policy_id,
                                scope: scope.clone(),
                                revision: old.revision,
                                operator_did: old.operator_did,
                                ruleset: old.ruleset,
                                policy_ttl_seconds: old.policy_ttl_seconds,
                            },
                        );
                        migrated = migrated.saturating_add(1);
                    }
                }
                for (persona, old) in PersonaPoliciesV2::<T>::iter() {
                    let scope = PolicyScopeV3::Persona(persona);
                    if let Ok(policy_id) = Self::expected_policy_id_v3(&scope) {
                        PoliciesV3::<T>::insert(
                            &scope,
                            DeliveryPolicyV3 {
                                policy_id,
                                scope: scope.clone(),
                                revision: old.revision,
                                operator_did: old.operator_did,
                                ruleset: old.ruleset,
                                policy_ttl_seconds: old.policy_ttl_seconds,
                            },
                        );
                        migrated = migrated.saturating_add(1);
                    }
                }
                STORAGE_VERSION.put::<Pallet<T>>();
                return T::DbWeight::get()
                    .reads_writes(migrated.saturating_mul(2) + 1, migrated + 1);
            }
            T::DbWeight::get().reads(1)
        }

        #[cfg(feature = "try-runtime")]
        fn pre_upgrade() -> Result<Vec<u8>, sp_runtime::TryRuntimeError> {
            ensure!(
                Pallet::<T>::on_chain_storage_version() <= STORAGE_VERSION,
                "delivery-policy on-chain storage version is newer than this runtime"
            );
            Ok((
                (Pallet::<T>::on_chain_storage_version() < STORAGE_VERSION),
                Self::migration_snapshot(),
            )
                .encode())
        }

        #[cfg(feature = "try-runtime")]
        fn post_upgrade(state: Vec<u8>) -> Result<(), sp_runtime::TryRuntimeError> {
            let (migrating, before) = <(bool, MigrationSnapshot)>::decode(&mut &state[..])
                .map_err(|_| "invalid delivery-policy pre-upgrade state")?;
            let after = Self::migration_snapshot();
            ensure!(
                before == after,
                "delivery-policy legacy storage changed during V3 migration"
            );
            if migrating {
                let did_count = PoliciesV3::<T>::iter_keys()
                    .filter(|scope| matches!(scope, PolicyScopeV3::Did(_)))
                    .count() as u64;
                let persona_count = PoliciesV3::<T>::iter_keys()
                    .filter(|scope| matches!(scope, PolicyScopeV3::Persona(_)))
                    .count() as u64;
                ensure!(
                    did_count == after.did_policies_v2,
                    "V3 DID migration count differs from V2 source"
                );
                ensure!(
                    persona_count == after.persona_policies_v2,
                    "V3 Persona migration count differs from V2 source"
                );
            }
            ensure!(
                Pallet::<T>::on_chain_storage_version() == STORAGE_VERSION,
                "delivery-policy storage version was not installed"
            );
            Ok(())
        }
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(
            T::DbWeight::get().reads_writes(2, 1)
                .saturating_add(Weight::from_parts(50_000_000, 0))
        )]
        pub fn set_delivery_policy(
            origin: OriginFor<T>,
            did: Vec<u8>,
            policy: DeliveryPolicy<T>,
        ) -> DispatchResult {
            let _ = (origin, did, policy);
            Err(Error::<T>::LegacyPolicyDeprecated.into())
        }

        #[pallet::call_index(1)]
        #[pallet::weight(T::DbWeight::get().reads_writes(2, 1))]
        pub fn clear_delivery_policy(origin: OriginFor<T>, did: Vec<u8>) -> DispatchResult {
            let did = Self::ensure_policy_controller(origin, did)?;
            ensure!(
                RecipientPolicies::<T>::contains_key(&did),
                Error::<T>::PolicyNotFound
            );
            RecipientPolicies::<T>::remove(&did);
            Self::deposit_event(Event::PolicyCleared {
                scope: PolicyScope::Recipient,
                did,
            });
            Ok(())
        }

        #[pallet::call_index(2)]
        #[pallet::weight(T::DbWeight::get().reads_writes(2, 1))]
        pub fn set_tag_policy(
            origin: OriginFor<T>,
            tag_did: Vec<u8>,
            policy: DeliveryPolicy<T>,
        ) -> DispatchResult {
            let _ = (origin, tag_did, policy);
            Err(Error::<T>::LegacyPolicyDeprecated.into())
        }

        #[pallet::call_index(3)]
        #[pallet::weight(T::DbWeight::get().reads_writes(2, 1))]
        pub fn set_persona_policy(
            origin: OriginFor<T>,
            persona_did: Vec<u8>,
            policy: DeliveryPolicy<T>,
        ) -> DispatchResult {
            let _ = (origin, persona_did, policy);
            Err(Error::<T>::LegacyPolicyDeprecated.into())
        }

        /// Apply a delivery-policy action using a DID root/authorized-key
        /// proof. Account-controller calls remain available above for direct
        /// chain integrations.
        #[pallet::call_index(4)]
        #[pallet::weight(T::DbWeight::get().reads_writes(3,1))]
        #[pallet::authorize(|_source, signed_payload, signature, signer_key_id| {
            Self::authorize_unsigned_call(&Call::apply_policy_with_proof {
                signed_payload: signed_payload.clone(),
                signature: signature.clone(),
                signer_key_id: signer_key_id.clone(),
            })
        })]
        #[pallet::weight_of_authorize(T::DbWeight::get().reads(2))]
        pub fn apply_policy_with_proof(
            origin: OriginFor<T>,
            signed_payload: Vec<u8>,
            signature: Vec<u8>,
            signer_key_id: Vec<u8>,
        ) -> DispatchResult {
            Self::ensure_unsigned_or_authorized(origin)?;
            let payload =
                Self::validate_policy_authorization(&signed_payload, &signature, &signer_key_id)?;
            let did = payload.did.clone();
            match payload.action {
                PolicyAction::SetRecipient(policy) => {
                    let _ = policy;
                    return Err(Error::<T>::LegacyPolicyDeprecated.into());
                }
                PolicyAction::ClearRecipient => {
                    ensure!(
                        RecipientPolicies::<T>::contains_key(&did),
                        Error::<T>::PolicyNotFound
                    );
                    RecipientPolicies::<T>::remove(&did);
                    Self::deposit_event(Event::PolicyCleared {
                        scope: PolicyScope::Recipient,
                        did: did.clone(),
                    });
                }
                PolicyAction::SetTag(policy) => {
                    let _ = policy;
                    return Err(Error::<T>::LegacyPolicyDeprecated.into());
                }
                PolicyAction::SetPersona(policy) => {
                    let _ = policy;
                    return Err(Error::<T>::LegacyPolicyDeprecated.into());
                }
            }
            PolicyNonces::<T>::insert(&did, payload.nonce.saturating_add(1));
            Ok(())
        }

        /// Set DID-level clock-time and transport limits. The stored effective
        /// TTL is always derived by the chain from the requested and network
        /// maxima.
        #[pallet::call_index(5)]
        #[pallet::weight(<T as Config>::WeightInfo::set_did_delivery_constraints())]
        pub fn set_did_delivery_constraints(
            origin: OriginFor<T>,
            did: Vec<u8>,
            constraints: RequestedDeliveryConstraints,
        ) -> DispatchResult {
            let did = Self::ensure_policy_controller(origin, did)?;
            let constraints = Self::validated_constraints(&constraints)?;
            DidDeliveryConstraints::<T>::insert(&did, constraints);
            Self::deposit_event(Event::DidDeliveryConstraintsSet { did });
            Ok(())
        }

        /// Register a globally unique, DNS-backed Persona. DNS is resolved by
        /// an admitted directory/validator and its canonical attestation is
        /// verified here; the runtime never attempts network I/O.
        #[pallet::call_index(6)]
        #[pallet::weight(<T as Config>::WeightInfo::register_persona())]
        #[allow(clippy::too_many_arguments)]
        pub fn register_persona(
            origin: OriginFor<T>,
            persona: Vec<u8>,
            operator_did: Vec<u8>,
            controller_key_ids: Vec<Vec<u8>>,
            controller_threshold: u8,
            constraints: Option<RequestedDeliveryConstraints>,
            dns_proof_hash: [u8; 32],
            challenge_nonce: u64,
            verification_expires_at: u64,
            attestor: T::AccountId,
            attestation_signature: Vec<u8>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let persona = Self::canonical_persona(&persona)?;
            ensure!(persona.contains(&b'.'), Error::<T>::InvalidPersona);
            ensure!(
                !Personas::<T>::contains_key(&persona),
                Error::<T>::PersonaAlreadyExists
            );
            let operator_did = Self::did_from_vec(operator_did)?;
            ensure!(
                T::DidProvider::did_exists(operator_did.as_slice()),
                Error::<T>::DidNotFound
            );
            ensure!(
                T::DidProvider::can_update_policy(&who, operator_did.as_slice()),
                Error::<T>::NotPolicyController
            );
            let controllers = Self::controller_keys(controller_key_ids, controller_threshold)?;
            let constraints = constraints
                .as_ref()
                .map(Self::validated_constraints)
                .transpose()?;
            Self::verify_persona_attestation(
                &persona,
                &operator_did,
                dns_proof_hash,
                challenge_nonce,
                verification_expires_at,
                &attestor,
                &attestation_signature,
            )?;
            let now = pallet_timestamp::Pallet::<T>::get().saturated_into::<u64>();
            Personas::<T>::insert(
                &persona,
                PersonaRecord::<T> {
                    operator_did: operator_did.clone(),
                    controller_key_ids: controllers,
                    controller_threshold,
                    delivery_constraints: constraints,
                    dns_proof_hash,
                    verified_at: now,
                    verification_expires_at,
                    revision: 1,
                    active: true,
                },
            );
            PersonaNonces::<T>::insert(&persona, challenge_nonce.saturating_add(1));
            Self::deposit_event(Event::PersonaRegistered {
                persona,
                operator_did,
            });
            Ok(())
        }

        #[pallet::call_index(7)]
        #[pallet::weight(<T as Config>::WeightInfo::renew_persona())]
        #[allow(clippy::too_many_arguments)]
        pub fn renew_persona(
            origin: OriginFor<T>,
            persona: Vec<u8>,
            constraints: Option<RequestedDeliveryConstraints>,
            dns_proof_hash: [u8; 32],
            challenge_nonce: u64,
            verification_expires_at: u64,
            attestor: T::AccountId,
            attestation_signature: Vec<u8>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let persona = Self::canonical_persona(&persona)?;
            ensure!(
                !NonDnsPersonas::<T>::contains_key(&persona),
                Error::<T>::InvalidPersona
            );
            let mut record = Personas::<T>::get(&persona).ok_or(Error::<T>::PersonaNotFound)?;
            ensure!(
                T::DidProvider::can_update_policy(&who, record.operator_did.as_slice()),
                Error::<T>::NotPolicyController
            );
            Self::verify_persona_attestation(
                &persona,
                &record.operator_did,
                dns_proof_hash,
                challenge_nonce,
                verification_expires_at,
                &attestor,
                &attestation_signature,
            )?;
            if let Some(constraints) = constraints.as_ref() {
                record.delivery_constraints = Some(Self::validated_constraints(constraints)?);
            }
            record.dns_proof_hash = dns_proof_hash;
            record.verified_at = pallet_timestamp::Pallet::<T>::get().saturated_into::<u64>();
            record.verification_expires_at = verification_expires_at;
            record.revision = record.revision.saturating_add(1);
            record.active = true;
            let revision = record.revision;
            Personas::<T>::insert(&persona, record);
            PersonaNonces::<T>::insert(&persona, challenge_nonce.saturating_add(1));
            Self::deposit_event(Event::PersonaRenewed { persona, revision });
            Ok(())
        }

        #[pallet::call_index(8)]
        #[pallet::weight(<T as Config>::WeightInfo::revoke_persona())]
        pub fn revoke_persona(origin: OriginFor<T>, persona: Vec<u8>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let persona = Self::canonical_persona(&persona)?;
            Personas::<T>::try_mutate(&persona, |maybe| -> DispatchResult {
                let record = maybe.as_mut().ok_or(Error::<T>::PersonaNotFound)?;
                ensure!(record.active, Error::<T>::PersonaInactive);
                ensure!(
                    T::DidProvider::can_update_policy(&who, record.operator_did.as_slice()),
                    Error::<T>::NotPolicyController
                );
                record.active = false;
                record.revision = record.revision.saturating_add(1);
                Ok(())
            })?;
            Self::deposit_event(Event::PersonaRevoked { persona });
            Ok(())
        }

        #[pallet::call_index(9)]
        #[pallet::weight(<T as Config>::WeightInfo::set_did_policy_v2())]
        pub fn set_did_policy_v2(
            origin: OriginFor<T>,
            did: Vec<u8>,
            policy: DeliveryPolicyV2<T>,
        ) -> DispatchResult {
            let did = Self::ensure_policy_controller(origin, did)?;
            ensure!(policy.operator_did == did, Error::<T>::InvalidPolicyScope);
            ensure!(
                policy.scope == PolicyScopeV2::Did(did.clone()),
                Error::<T>::InvalidPolicyScope
            );
            Self::store_policy_v2(policy)
        }

        #[pallet::call_index(10)]
        #[pallet::weight(<T as Config>::WeightInfo::clear_did_policy_v2())]
        pub fn clear_did_policy_v2(origin: OriginFor<T>, did: Vec<u8>) -> DispatchResult {
            let did = Self::ensure_policy_controller(origin, did)?;
            ensure!(
                DidPoliciesV2::<T>::contains_key(&did),
                Error::<T>::PolicyNotFound
            );
            DidPoliciesV2::<T>::remove(&did);
            PoliciesV3::<T>::remove(PolicyScopeV3::Did(did.clone()));
            Self::deposit_event(Event::PolicyV2Cleared {
                scope: PolicyScopeV2::Did(did),
            });
            Ok(())
        }

        #[pallet::call_index(11)]
        #[pallet::weight(<T as Config>::WeightInfo::set_persona_policy_v2())]
        pub fn set_persona_policy_v2(
            origin: OriginFor<T>,
            persona: Vec<u8>,
            policy: DeliveryPolicyV2<T>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let persona = Self::canonical_persona(&persona)?;
            let record = Self::active_persona(&persona)?;
            ensure!(
                T::DidProvider::can_update_policy(&who, record.operator_did.as_slice()),
                Error::<T>::NotPolicyController
            );
            ensure!(
                policy.operator_did == record.operator_did
                    && policy.scope == PolicyScopeV2::Persona(persona),
                Error::<T>::InvalidPolicyScope
            );
            Self::store_policy_v2(policy)
        }

        #[pallet::call_index(12)]
        #[pallet::weight(<T as Config>::WeightInfo::clear_persona_policy_v2())]
        pub fn clear_persona_policy_v2(origin: OriginFor<T>, persona: Vec<u8>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let persona = Self::canonical_persona(&persona)?;
            let record = Personas::<T>::get(&persona).ok_or(Error::<T>::PersonaNotFound)?;
            ensure!(
                T::DidProvider::can_update_policy(&who, record.operator_did.as_slice()),
                Error::<T>::NotPolicyController
            );
            ensure!(
                PersonaPoliciesV2::<T>::contains_key(&persona),
                Error::<T>::PolicyNotFound
            );
            PersonaPoliciesV2::<T>::remove(&persona);
            PoliciesV3::<T>::remove(PolicyScopeV3::Persona(persona.clone()));
            Self::deposit_event(Event::PolicyV2Cleared {
                scope: PolicyScopeV2::Persona(persona),
            });
            Ok(())
        }

        #[pallet::call_index(13)]
        #[pallet::weight(<T as Config>::WeightInfo::apply_policy_v2_with_proof())]
        #[pallet::authorize(|_source, signed_payload, signature, signer_key_id| {
            Self::authorize_unsigned_v2_call(&Call::apply_policy_v2_with_proof {
                signed_payload: signed_payload.clone(),
                signature: signature.clone(),
                signer_key_id: signer_key_id.clone(),
            })
        })]
        #[pallet::weight_of_authorize(<T as Config>::WeightInfo::authorize_apply_policy_v2_with_proof())]
        pub fn apply_policy_v2_with_proof(
            origin: OriginFor<T>,
            signed_payload: Vec<u8>,
            signature: Vec<u8>,
            signer_key_id: Vec<u8>,
        ) -> DispatchResult {
            Self::ensure_unsigned_or_authorized(origin)?;
            let payload = Self::validate_policy_v2_authorization(
                &signed_payload,
                &signature,
                &signer_key_id,
            )?;
            let operator_did = payload.operator_did.clone();
            Self::apply_policy_v2_operation(&operator_did, payload.operation)?;
            PolicyV2Nonces::<T>::insert(&operator_did, payload.nonce.saturating_add(1));
            Ok(())
        }

        #[pallet::call_index(14)]
        #[pallet::weight(<T as Config>::WeightInfo::set_persona_delivery_constraints())]
        pub fn set_persona_delivery_constraints(
            origin: OriginFor<T>,
            persona: Vec<u8>,
            constraints: RequestedDeliveryConstraints,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let persona = Self::canonical_persona(&persona)?;
            Personas::<T>::try_mutate(&persona, |maybe| -> DispatchResult {
                let record = maybe.as_mut().ok_or(Error::<T>::PersonaNotFound)?;
                ensure!(record.active, Error::<T>::PersonaInactive);
                ensure!(
                    T::DidProvider::can_update_policy(&who, record.operator_did.as_slice()),
                    Error::<T>::NotPolicyController
                );
                record.delivery_constraints = Some(Self::validated_constraints(&constraints)?);
                record.revision = record.revision.saturating_add(1);
                Ok(())
            })
        }

        /// Persona registration/renewal/revocation path for HTTP Directory
        /// requests. The operator's DID key authorizes the mutation while the
        /// nested admitted-validator signature independently attests DNS.
        #[pallet::call_index(15)]
        #[pallet::weight(<T as Config>::WeightInfo::apply_persona_with_proof())]
        #[pallet::authorize(|_source, signed_payload, signature, signer_key_id| {
            Self::authorize_unsigned_persona_call(&Call::apply_persona_with_proof {
                signed_payload: signed_payload.clone(),
                signature: signature.clone(),
                signer_key_id: signer_key_id.clone(),
            })
        })]
        #[pallet::weight_of_authorize(<T as Config>::WeightInfo::authorize_apply_persona_with_proof())]
        pub fn apply_persona_with_proof(
            origin: OriginFor<T>,
            signed_payload: Vec<u8>,
            signature: Vec<u8>,
            signer_key_id: Vec<u8>,
        ) -> DispatchResult {
            Self::ensure_unsigned_or_authorized(origin)?;
            let payload =
                Self::validate_persona_authorization(&signed_payload, &signature, &signer_key_id)?;
            let operator_did = payload.operator_did.clone();
            Self::apply_persona_operation(&operator_did, payload.operation)?;
            PersonaOperatorNonces::<T>::insert(&operator_did, payload.nonce.saturating_add(1));
            Ok(())
        }

        /// Governance admission for accounts allowed to attest DNS checks.
        #[pallet::call_index(16)]
        #[pallet::weight(<T as Config>::WeightInfo::set_persona_attestor())]
        pub fn set_persona_attestor(
            origin: OriginFor<T>,
            attestor: T::AccountId,
            approved: bool,
        ) -> DispatchResult {
            T::PersonaAttestorOrigin::ensure_origin(origin)?;
            if approved {
                PersonaAttestors::<T>::insert(&attestor, ());
            } else {
                PersonaAttestors::<T>::remove(&attestor);
            }
            Self::deposit_event(Event::PersonaAttestorUpdated { attestor, approved });
            Ok(())
        }

        #[pallet::call_index(17)]
        #[pallet::weight(T::DbWeight::get().reads_writes(8, 3)
            .saturating_add(Weight::from_parts(150_000_000, 0)))]
        #[pallet::authorize(|_source, signed_payload, signature, signer_key_id| {
            Self::authorize_unsigned_v3_call(&Call::apply_policy_v3_with_proof {
                signed_payload: signed_payload.clone(),
                signature: signature.clone(),
                signer_key_id: signer_key_id.clone(),
            })
        })]
        #[pallet::weight_of_authorize(T::DbWeight::get().reads(5))]
        pub fn apply_policy_v3_with_proof(
            origin: OriginFor<T>,
            signed_payload: Vec<u8>,
            signature: Vec<u8>,
            signer_key_id: Vec<u8>,
        ) -> DispatchResult {
            Self::ensure_unsigned_or_authorized(origin)?;
            let payload = Self::validate_policy_v3_authorization(
                &signed_payload,
                &signature,
                &signer_key_id,
            )?;
            let owner = payload.operator_did.clone();
            match payload.operation {
                PolicyV3Operation::SetPolicy(policy) => Self::store_policy_v3(policy)?,
                PolicyV3Operation::ClearPolicy(scope) => {
                    ensure!(
                        Self::policy_v3_owner(&scope)? == owner,
                        Error::<T>::InvalidPolicyScope
                    );
                    ensure!(
                        PoliciesV3::<T>::contains_key(&scope),
                        Error::<T>::PolicyNotFound
                    );
                    match &scope {
                        PolicyScopeV3::Did(did) => DidPoliciesV2::<T>::remove(did),
                        PolicyScopeV3::Persona(persona) => PersonaPoliciesV2::<T>::remove(persona),
                        PolicyScopeV3::Application(_) => {}
                    }
                    PoliciesV3::<T>::remove(&scope);
                    Self::deposit_event(Event::PolicyV3Cleared { scope });
                }
            }
            PolicyV3Nonces::<T>::insert(owner, payload.nonce.saturating_add(1));
            Ok(())
        }

        /// Register a non-DNS collective name. Its operator controls the
        /// policy; recipient membership remains entirely off chain.
        #[pallet::call_index(18)]
        #[pallet::weight(<T as Config>::WeightInfo::register_persona())]
        pub fn register_named_persona(
            origin: OriginFor<T>,
            persona: Vec<u8>,
            operator_did: Vec<u8>,
            controller_key_ids: Vec<Vec<u8>>,
            controller_threshold: u8,
            constraints: Option<RequestedDeliveryConstraints>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let persona = Self::canonical_persona(&persona)?;
            ensure!(!persona.contains(&b'.'), Error::<T>::InvalidPersona);
            ensure!(
                !Personas::<T>::contains_key(&persona),
                Error::<T>::PersonaAlreadyExists
            );
            let operator_did = Self::did_from_vec(operator_did)?;
            ensure!(
                T::DidProvider::did_exists(operator_did.as_slice()),
                Error::<T>::DidNotFound
            );
            ensure!(
                T::DidProvider::can_update_policy(&who, operator_did.as_slice()),
                Error::<T>::NotPolicyController
            );
            let controllers = Self::controller_keys(controller_key_ids, controller_threshold)?;
            let constraints = constraints
                .as_ref()
                .map(Self::validated_constraints)
                .transpose()?;
            Personas::<T>::insert(
                &persona,
                PersonaRecord::<T> {
                    operator_did: operator_did.clone(),
                    controller_key_ids: controllers,
                    controller_threshold,
                    delivery_constraints: constraints,
                    dns_proof_hash: [0; 32],
                    verified_at: 0,
                    verification_expires_at: 0,
                    revision: 1,
                    active: true,
                },
            );
            NonDnsPersonas::<T>::insert(&persona, ());
            Self::deposit_event(Event::PersonaRegistered {
                persona,
                operator_did,
            });
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        /// Remove every delivery-policy entry whose storage key is this DID.
        ///
        /// This is called by the DID registry when a root-authorized deletion
        /// removes the DID itself. Persona records and persona V2 policies are
        /// keyed by DNS persona rather than DID and are intentionally not
        /// scanned here.
        pub fn remove_did_state(raw_did: &[u8]) {
            let Ok(did) = DidOf::<T>::try_from(raw_did.to_vec()) else {
                return;
            };
            RecipientPolicies::<T>::remove(&did);
            TagPolicies::<T>::remove(&did);
            PersonaPolicies::<T>::remove(&did);
            PolicyNonces::<T>::remove(&did);
            DidDeliveryConstraints::<T>::remove(&did);
            PersonaOperatorNonces::<T>::remove(&did);
            DidPoliciesV2::<T>::remove(&did);
            PolicyV2Nonces::<T>::remove(&did);
            PoliciesV3::<T>::remove(PolicyScopeV3::Did(did.clone()));
            PolicyV3Nonces::<T>::remove(&did);
        }

        #[cfg(feature = "try-runtime")]
        fn migration_snapshot() -> MigrationSnapshot {
            MigrationSnapshot {
                recipient_policies: RecipientPolicies::<T>::iter_keys().count() as u64,
                tag_policies: TagPolicies::<T>::iter_keys().count() as u64,
                legacy_persona_policies: PersonaPolicies::<T>::iter_keys().count() as u64,
                policy_nonces: PolicyNonces::<T>::iter_keys().count() as u64,
                did_delivery_constraints: DidDeliveryConstraints::<T>::iter_keys().count() as u64,
                personas: Personas::<T>::iter_keys().count() as u64,
                persona_nonces: PersonaNonces::<T>::iter_keys().count() as u64,
                persona_operator_nonces: PersonaOperatorNonces::<T>::iter_keys().count() as u64,
                persona_attestors: PersonaAttestors::<T>::iter_keys().count() as u64,
                did_policies_v2: DidPoliciesV2::<T>::iter_keys().count() as u64,
                persona_policies_v2: PersonaPoliciesV2::<T>::iter_keys().count() as u64,
                policy_v2_nonces: PolicyV2Nonces::<T>::iter_keys().count() as u64,
            }
        }

        fn ensure_unsigned_or_authorized(origin: OriginFor<T>) -> DispatchResult {
            match origin.into() {
                Ok(frame_system::RawOrigin::None) | Ok(frame_system::RawOrigin::Authorized) => {
                    Ok(())
                }
                _ => Err(sp_runtime::DispatchError::BadOrigin),
            }
        }

        fn decode_policy_payload(
            signed_payload: &[u8],
        ) -> Result<PolicyAuthorizationPayload<T>, Error<T>> {
            let mut bytes = signed_payload;
            let payload = PolicyAuthorizationPayload::<T>::decode(&mut bytes)
                .map_err(|_| Error::<T>::InvalidPolicyPayload)?;
            ensure!(bytes.is_empty(), Error::<T>::InvalidPolicyPayload);
            ensure!(
                payload.encode() == signed_payload,
                Error::<T>::InvalidPolicyPayload
            );
            Ok(payload)
        }

        fn validate_policy_authorization(
            signed_payload: &[u8],
            signature: &[u8],
            signer_key_id: &[u8],
        ) -> Result<PolicyAuthorizationPayload<T>, Error<T>> {
            let signer_key_id_b = SignerKeyId::try_from(signer_key_id.to_vec())
                .map_err(|_| Error::<T>::InvalidPolicyPayload)?;
            let payload = Self::decode_policy_payload(signed_payload)?;
            ensure!(
                payload.signer_key_id == signer_key_id_b,
                Error::<T>::InvalidPolicyPayload
            );
            ensure!(
                payload.valid_until > pallet_timestamp::Pallet::<T>::get().saturated_into::<u64>(),
                Error::<T>::PolicyAuthorizationExpired
            );
            ensure!(
                T::DidProvider::did_exists(payload.did.as_slice()),
                Error::<T>::DidNotFound
            );
            ensure!(
                payload.nonce == PolicyNonces::<T>::get(&payload.did),
                Error::<T>::InvalidPolicyNonce
            );
            ensure!(
                T::DidProvider::verify_did_signature(
                    payload.did.as_slice(),
                    signer_key_id,
                    signed_payload,
                    signature,
                ),
                Error::<T>::InvalidSignature
            );
            Ok(payload)
        }

        pub(crate) fn authorize_unsigned_call(call: &Call<T>) -> TransactionValidityWithRefund {
            Self::validate_unsigned_call(call).map(|validity| (validity, Weight::zero()))
        }

        pub(crate) fn authorize_unsigned_v2_call(call: &Call<T>) -> TransactionValidityWithRefund {
            Self::validate_unsigned_call(call).map(|validity| (validity, Weight::zero()))
        }

        pub(crate) fn authorize_unsigned_v3_call(call: &Call<T>) -> TransactionValidityWithRefund {
            Self::validate_unsigned_call(call).map(|validity| (validity, Weight::zero()))
        }

        pub(crate) fn authorize_unsigned_persona_call(
            call: &Call<T>,
        ) -> TransactionValidityWithRefund {
            Self::validate_unsigned_call(call).map(|validity| (validity, Weight::zero()))
        }

        pub(crate) fn validate_unsigned_call(call: &Call<T>) -> TransactionValidity {
            match call {
                Call::apply_policy_with_proof {
                    signed_payload,
                    signature,
                    signer_key_id,
                } => {
                    let payload = match Self::validate_policy_authorization(
                        signed_payload,
                        signature,
                        signer_key_id,
                    ) {
                        Ok(payload) => payload,
                        Err(_) => return InvalidTransaction::BadProof.into(),
                    };
                    ValidTransaction::with_tag_prefix("OpenPayloadPolicy")
                        .priority(900)
                        .and_provides((payload.did, payload.nonce))
                        .longevity(64)
                        .propagate(true)
                        .build()
                }
                Call::apply_policy_v2_with_proof {
                    signed_payload,
                    signature,
                    signer_key_id,
                } => {
                    let payload = match Self::validate_policy_v2_authorization(
                        signed_payload,
                        signature,
                        signer_key_id,
                    ) {
                        Ok(payload) => payload,
                        Err(_) => return InvalidTransaction::BadProof.into(),
                    };
                    ValidTransaction::with_tag_prefix("OpenPayloadPolicyV2")
                        .priority(950)
                        .and_provides((payload.operator_did, payload.nonce))
                        .longevity(64)
                        .propagate(true)
                        .build()
                }
                Call::apply_policy_v3_with_proof {
                    signed_payload,
                    signature,
                    signer_key_id,
                } => {
                    let payload = match Self::validate_policy_v3_authorization(
                        signed_payload,
                        signature,
                        signer_key_id,
                    ) {
                        Ok(payload) => payload,
                        Err(_) => return InvalidTransaction::BadProof.into(),
                    };
                    ValidTransaction::with_tag_prefix("OpenPayloadPolicyV3")
                        .priority(950)
                        .and_provides((payload.operator_did, payload.nonce))
                        .longevity(64)
                        .propagate(true)
                        .build()
                }
                Call::apply_persona_with_proof {
                    signed_payload,
                    signature,
                    signer_key_id,
                } => {
                    let payload = match Self::validate_persona_authorization(
                        signed_payload,
                        signature,
                        signer_key_id,
                    ) {
                        Ok(payload) => payload,
                        Err(_) => return InvalidTransaction::BadProof.into(),
                    };
                    ValidTransaction::with_tag_prefix("OpenPayloadPersona")
                        .priority(975)
                        .and_provides((payload.operator_did, payload.nonce))
                        .longevity(64)
                        .propagate(true)
                        .build()
                }
                _ => InvalidTransaction::Call.into(),
            }
        }

        pub fn resolve_policy(
            recipient: &[u8],
            tag: Option<&[u8]>,
            persona: Option<&[u8]>,
        ) -> Option<DeliveryPolicy<T>> {
            if let Some(persona) = persona.and_then(Self::did_from_slice) {
                if let Some(policy) = PersonaPolicies::<T>::get(persona) {
                    return Some(policy);
                }
            }

            if let Some(tag) = tag.and_then(Self::did_from_slice) {
                if let Some(policy) = TagPolicies::<T>::get(tag) {
                    return Some(policy);
                }
            }

            Self::did_from_slice(recipient).and_then(RecipientPolicies::<T>::get)
        }

        pub fn recipient_policy(did: &[u8]) -> Option<DeliveryPolicy<T>> {
            Self::did_from_slice(did).and_then(RecipientPolicies::<T>::get)
        }

        pub fn tag_policy(did: &[u8]) -> Option<DeliveryPolicy<T>> {
            Self::did_from_slice(did).and_then(TagPolicies::<T>::get)
        }

        pub fn persona_policy(did: &[u8]) -> Option<DeliveryPolicy<T>> {
            Self::did_from_slice(did).and_then(PersonaPolicies::<T>::get)
        }

        fn ensure_policy_controller(
            origin: OriginFor<T>,
            did: Vec<u8>,
        ) -> Result<DidOf<T>, DispatchError> {
            let who = ensure_signed(origin)?;
            let did_b = DidOf::<T>::try_from(did).map_err(|_| Error::<T>::DidTooLong)?;
            ensure!(
                T::DidProvider::did_exists(did_b.as_slice()),
                Error::<T>::DidNotFound
            );
            ensure!(
                T::DidProvider::can_update_policy(&who, did_b.as_slice()),
                Error::<T>::NotPolicyController
            );
            Ok(did_b)
        }

        fn did_from_slice(did: &[u8]) -> Option<DidOf<T>> {
            DidOf::<T>::try_from(did.to_vec()).ok()
        }

        fn did_from_vec(did: Vec<u8>) -> Result<DidOf<T>, DispatchError> {
            DidOf::<T>::try_from(did).map_err(|_| Error::<T>::DidTooLong.into())
        }

        fn canonical_persona(raw: &[u8]) -> Result<PersonaOf<T>, DispatchError> {
            let mut value = raw;
            while value.first().is_some_and(u8::is_ascii_whitespace) {
                value = &value[1..];
            }
            while value.last().is_some_and(u8::is_ascii_whitespace) {
                value = &value[..value.len() - 1];
            }
            if value.last() == Some(&b'.') {
                value = &value[..value.len().saturating_sub(1)];
            }
            ensure!(
                !value.is_empty() && value.len() <= 253,
                Error::<T>::InvalidPersona
            );

            let mut canonical = Vec::with_capacity(value.len());
            let mut label_len = 0usize;
            let mut label_start = true;
            let mut saw_dot = false;
            let mut previous = 0u8;
            for byte in value {
                ensure!(byte.is_ascii(), Error::<T>::InvalidPersona);
                let byte = byte.to_ascii_lowercase();
                if byte == b'.' {
                    ensure!(
                        !label_start && label_len <= 63 && previous != b'-',
                        Error::<T>::InvalidPersona
                    );
                    saw_dot = true;
                    label_len = 0;
                    label_start = true;
                } else {
                    ensure!(
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-',
                        Error::<T>::InvalidPersona
                    );
                    ensure!(!(label_start && byte == b'-'), Error::<T>::InvalidPersona);
                    label_start = false;
                    label_len = label_len.saturating_add(1);
                    ensure!(label_len <= 63, Error::<T>::InvalidPersona);
                }
                previous = byte;
                canonical.push(byte);
            }
            ensure!(!label_start && previous != b'-', Error::<T>::InvalidPersona);
            let top_level_label = canonical
                .rsplit(|byte| *byte == b'.')
                .next()
                .ok_or(Error::<T>::InvalidPersona)?;
            ensure!(
                !saw_dot || top_level_label.iter().any(u8::is_ascii_lowercase),
                Error::<T>::InvalidPersona
            );
            PersonaOf::<T>::try_from(canonical).map_err(|_| Error::<T>::InvalidPersona.into())
        }

        fn validate_tag(tag: &[u8]) -> Result<(), DispatchError> {
            ensure!(!tag.is_empty(), Error::<T>::InvalidTag);
            let decoded = core::str::from_utf8(tag).map_err(|_| Error::<T>::InvalidTag)?;
            ensure!(
                !decoded.chars().any(|character| character.is_control()),
                Error::<T>::InvalidTag
            );
            Ok(())
        }

        fn controller_keys(
            raw: Vec<Vec<u8>>,
            threshold: u8,
        ) -> Result<ControllerKeysOf<T>, DispatchError> {
            ensure!(!raw.is_empty(), Error::<T>::InvalidPersonaController);
            ensure!(
                threshold == 1 && usize::from(threshold) <= raw.len(),
                Error::<T>::InvalidPersonaController
            );
            let mut keys = ControllerKeysOf::<T>::default();
            for key in raw {
                ensure!(!key.is_empty(), Error::<T>::InvalidPersonaController);
                let key =
                    SignerKeyId::try_from(key).map_err(|_| Error::<T>::InvalidPersonaController)?;
                ensure!(!keys.contains(&key), Error::<T>::InvalidPersonaController);
                keys.try_push(key)
                    .map_err(|_| Error::<T>::InvalidPersonaController)?;
            }
            Ok(keys)
        }

        #[allow(clippy::too_many_arguments)]
        fn verify_persona_attestation(
            persona: &PersonaOf<T>,
            operator_did: &DidOf<T>,
            dns_proof_hash: [u8; 32],
            challenge_nonce: u64,
            verification_expires_at: u64,
            attestor: &T::AccountId,
            signature: &[u8],
        ) -> DispatchResult {
            ensure!(
                challenge_nonce == PersonaNonces::<T>::get(persona),
                Error::<T>::InvalidPersonaNonce
            );
            let now = pallet_timestamp::Pallet::<T>::get().saturated_into::<u64>();
            ensure!(
                verification_expires_at > now,
                Error::<T>::PersonaVerificationExpired
            );
            ensure!(
                PersonaAttestors::<T>::contains_key(attestor),
                Error::<T>::PersonaAttestorNotApproved
            );
            let payload = PersonaAttestationPayload::<T> {
                domain: BoundedVec::truncate_from(PERSONA_ATTESTATION_DOMAIN.to_vec()),
                genesis_hash: frame_system::Pallet::<T>::block_hash(BlockNumberFor::<T>::zero()),
                persona: persona.clone(),
                operator_did: operator_did.clone(),
                dns_proof_hash,
                challenge_nonce,
                verification_expires_at,
            }
            .encode();
            ensure!(
                T::PersonaAttestationProvider::verify_attestation(attestor, &payload, signature),
                Error::<T>::InvalidPersonaAttestation
            );
            Ok(())
        }

        fn network_constraints() -> DeliveryConstraints {
            DeliveryConstraints {
                requested_cache_seconds: T::MaxTtlSeconds::get(),
                effective_ttl_seconds: T::MaxTtlSeconds::get(),
                max_http_envelope_bytes: T::MaxHttpEnvelopeBytes::get(),
                max_unchunked_message_bytes: T::MaxUnchunkedMessageBytes::get(),
                max_chunk_bytes: T::MaxChunkBytes::get(),
                max_message_bytes: UNBOUNDED_MESSAGE_BYTES_COMPAT,
                max_chunks: UNBOUNDED_CHUNKS_COMPAT,
                max_replicas: T::MaxReplicas::get(),
            }
        }

        fn validated_constraints(
            requested: &RequestedDeliveryConstraints,
        ) -> Result<DeliveryConstraints, DispatchError> {
            ensure!(
                requested.requested_cache_seconds > 0
                    && requested.max_http_envelope_bytes > 0
                    && requested.max_http_envelope_bytes <= T::MaxHttpEnvelopeBytes::get()
                    && requested.max_unchunked_message_bytes > 0
                    && requested.max_unchunked_message_bytes <= T::MaxUnchunkedMessageBytes::get()
                    && requested.max_chunk_bytes > 0
                    && requested.max_chunk_bytes <= T::MaxChunkBytes::get()
                    && requested.max_replicas > 0
                    && requested.max_replicas <= T::MaxReplicas::get(),
                Error::<T>::InvalidConstraints
            );
            ensure!(
                requested.max_unchunked_message_bytes <= requested.max_http_envelope_bytes
                    && requested.max_chunk_bytes <= requested.max_unchunked_message_bytes,
                Error::<T>::InvalidConstraints
            );
            Ok(DeliveryConstraints {
                requested_cache_seconds: requested.requested_cache_seconds,
                effective_ttl_seconds: requested
                    .requested_cache_seconds
                    .min(T::MaxTtlSeconds::get()),
                max_http_envelope_bytes: requested.max_http_envelope_bytes,
                max_unchunked_message_bytes: requested.max_unchunked_message_bytes,
                max_chunk_bytes: requested.max_chunk_bytes,
                max_message_bytes: UNBOUNDED_MESSAGE_BYTES_COMPAT,
                max_chunks: UNBOUNDED_CHUNKS_COMPAT,
                max_replicas: requested.max_replicas,
            })
        }

        fn minimum_constraints(
            left: DeliveryConstraints,
            right: DeliveryConstraints,
        ) -> DeliveryConstraints {
            let max_http_envelope_bytes = left
                .max_http_envelope_bytes
                .min(right.max_http_envelope_bytes);
            let max_unchunked_message_bytes = left
                .max_unchunked_message_bytes
                .min(right.max_unchunked_message_bytes)
                .min(max_http_envelope_bytes);
            let max_chunk_bytes = left
                .max_chunk_bytes
                .min(right.max_chunk_bytes)
                .min(max_unchunked_message_bytes);
            DeliveryConstraints {
                requested_cache_seconds: left
                    .requested_cache_seconds
                    .min(right.requested_cache_seconds),
                effective_ttl_seconds: left.effective_ttl_seconds.min(right.effective_ttl_seconds),
                max_http_envelope_bytes,
                max_unchunked_message_bytes,
                max_chunk_bytes,
                max_message_bytes: UNBOUNDED_MESSAGE_BYTES_COMPAT,
                max_chunks: UNBOUNDED_CHUNKS_COMPAT,
                max_replicas: left.max_replicas.min(right.max_replicas),
            }
        }

        fn normalized_constraints(mut constraints: DeliveryConstraints) -> DeliveryConstraints {
            constraints.max_message_bytes = UNBOUNDED_MESSAGE_BYTES_COMPAT;
            constraints.max_chunks = UNBOUNDED_CHUNKS_COMPAT;
            constraints
        }

        fn apply_constraint_overrides(
            base: &DeliveryConstraints,
            overrides: Option<&DeliveryConstraintOverrides>,
        ) -> Result<DeliveryConstraints, DispatchError> {
            let Some(overrides) = overrides else {
                return Ok(base.clone());
            };
            macro_rules! narrowed {
                ($field:ident) => {
                    match overrides.$field {
                        Some(value) => {
                            ensure!(
                                value > 0 && value <= base.$field,
                                Error::<T>::ConstraintOverrideExceedsScope
                            );
                            value
                        }
                        None => base.$field,
                    }
                };
            }
            let requested_cache_seconds = narrowed!(requested_cache_seconds);
            let resolved = DeliveryConstraints {
                requested_cache_seconds,
                effective_ttl_seconds: requested_cache_seconds.min(base.effective_ttl_seconds),
                max_http_envelope_bytes: narrowed!(max_http_envelope_bytes),
                max_unchunked_message_bytes: narrowed!(max_unchunked_message_bytes),
                max_chunk_bytes: narrowed!(max_chunk_bytes),
                max_message_bytes: UNBOUNDED_MESSAGE_BYTES_COMPAT,
                max_chunks: UNBOUNDED_CHUNKS_COMPAT,
                max_replicas: narrowed!(max_replicas),
            };
            ensure!(
                resolved.max_unchunked_message_bytes <= resolved.max_http_envelope_bytes
                    && resolved.max_chunk_bytes <= resolved.max_unchunked_message_bytes,
                Error::<T>::InvalidConstraints
            );
            Ok(resolved)
        }

        /// Apply a previously validated rule override to the effective
        /// constraints for the addressed recipient. A Persona rule is
        /// validated against its Persona scope when written, but the
        /// recipient DID can impose a tighter limit at resolution time. Those
        /// tighter limits clamp the rule instead of invalidating the Persona
        /// winner and accidentally falling through to a DID policy.
        fn clamp_constraint_overrides(
            base: &DeliveryConstraints,
            overrides: Option<&DeliveryConstraintOverrides>,
        ) -> DeliveryConstraints {
            let Some(overrides) = overrides else {
                return base.clone();
            };
            macro_rules! clamped {
                ($field:ident) => {
                    overrides.$field.unwrap_or(base.$field).min(base.$field)
                };
            }
            let requested_cache_seconds = clamped!(requested_cache_seconds);
            let override_ceiling = DeliveryConstraints {
                requested_cache_seconds,
                effective_ttl_seconds: requested_cache_seconds.min(base.effective_ttl_seconds),
                max_http_envelope_bytes: clamped!(max_http_envelope_bytes),
                max_unchunked_message_bytes: clamped!(max_unchunked_message_bytes),
                max_chunk_bytes: clamped!(max_chunk_bytes),
                max_message_bytes: UNBOUNDED_MESSAGE_BYTES_COMPAT,
                max_chunks: UNBOUNDED_CHUNKS_COMPAT,
                max_replicas: clamped!(max_replicas),
            };
            // Reuse the intersection normalizer for the active per-envelope,
            // per-chunk, TTL, and replication constraints.
            Self::minimum_constraints(base.clone(), override_ceiling)
        }

        fn active_persona(persona: &PersonaOf<T>) -> Result<PersonaRecord<T>, DispatchError> {
            let record = Personas::<T>::get(persona).ok_or(Error::<T>::PersonaNotFound)?;
            ensure!(record.active, Error::<T>::PersonaInactive);
            if !NonDnsPersonas::<T>::contains_key(persona) {
                ensure!(
                    record.verification_expires_at
                        > pallet_timestamp::Pallet::<T>::get().saturated_into::<u64>(),
                    Error::<T>::PersonaVerificationExpired
                );
            }
            Ok(record)
        }

        fn expected_policy_id(scope: &PolicyScopeV2<T>) -> Result<PolicyIdOf<T>, DispatchError> {
            use sp_runtime::traits::Hash as _;
            let mut payload = b"openpayload:delivery-policy:v2:".to_vec();
            payload.extend_from_slice(&scope.encode());
            PolicyIdOf::<T>::try_from(T::Hashing::hash(&payload).as_ref().to_vec())
                .map_err(|_| Error::<T>::InvalidPolicyId.into())
        }

        fn expected_policy_id_v3(scope: &PolicyScopeV3<T>) -> Result<PolicyIdOf<T>, DispatchError> {
            use sp_runtime::traits::Hash as _;
            let mut payload = b"openpayload:delivery-policy:v3:".to_vec();
            payload.extend_from_slice(&scope.encode());
            PolicyIdOf::<T>::try_from(T::Hashing::hash(&payload).as_ref().to_vec())
                .map_err(|_| Error::<T>::InvalidPolicyId.into())
        }

        fn policy_v3_owner(scope: &PolicyScopeV3<T>) -> Result<DidOf<T>, DispatchError> {
            match scope {
                PolicyScopeV3::Did(did) => {
                    ensure!(
                        T::DidProvider::did_exists(did.as_slice()),
                        Error::<T>::DidNotFound
                    );
                    Ok(did.clone())
                }
                PolicyScopeV3::Persona(persona) => Ok(Self::active_persona(persona)?.operator_did),
                PolicyScopeV3::Application(id) => {
                    ensure!(
                        !id.is_empty()
                            && id.iter().all(|byte| {
                                byte.is_ascii_lowercase()
                                    || byte.is_ascii_digit()
                                    || matches!(*byte, b'.' | b'_' | b'-')
                            }),
                        Error::<T>::InvalidPolicyScope
                    );
                    let owner = T::ApplicationProvider::active_control_did(id.as_slice())
                        .ok_or(Error::<T>::InvalidPolicyScope)?;
                    DidOf::<T>::try_from(owner).map_err(|_| Error::<T>::InvalidPolicyScope.into())
                }
            }
        }

        fn validate_policy_v3(policy: &DeliveryPolicyV3<T>) -> DispatchResult {
            ensure!(
                policy.policy_id == Self::expected_policy_id_v3(&policy.scope)?,
                Error::<T>::InvalidPolicyId
            );
            ensure!(
                policy.operator_did == Self::policy_v3_owner(&policy.scope)?,
                Error::<T>::InvalidPolicyScope
            );
            ensure!(!policy.ruleset.is_empty(), Error::<T>::EmptyRuleset);
            ensure!(
                policy.policy_ttl_seconds > 0
                    && policy.policy_ttl_seconds <= T::MaxPolicyTtlSeconds::get(),
                Error::<T>::InvalidPolicyTtl
            );
            let expected_revision = PoliciesV3::<T>::get(&policy.scope)
                .map(|current| current.revision.saturating_add(1))
                .unwrap_or(1);
            ensure!(
                policy.revision == expected_revision,
                Error::<T>::InvalidPolicyRevision
            );
            let mut units = policy.ruleset.len() as u32;
            let scope_constraints = match &policy.scope {
                PolicyScopeV3::Did(did) => {
                    DidDeliveryConstraints::<T>::get(did).unwrap_or_else(Self::network_constraints)
                }
                PolicyScopeV3::Persona(persona) => Self::active_persona(persona)?
                    .delivery_constraints
                    .unwrap_or_else(Self::network_constraints),
                PolicyScopeV3::Application(_) => Self::network_constraints(),
            };
            for (index, rule) in policy.ruleset.iter().enumerate() {
                ensure!(
                    !rule.id.is_empty()
                        && rule.priority <= u32::from(u16::MAX)
                        && !policy.ruleset[..index].iter().any(|old| old.id == rule.id),
                    Error::<T>::DuplicateRuleId
                );
                units = units.saturating_add(rule.conditions.len() as u32);
                for condition in &rule.conditions {
                    Self::validate_condition(condition)?;
                }
                let is_application = matches!(policy.scope, PolicyScopeV3::Application(_));
                ensure!(
                    !is_application || rule.constraint_overrides.is_none(),
                    Error::<T>::InvalidPolicyScope
                );
                let constraints = Self::apply_constraint_overrides(
                    &scope_constraints,
                    rule.constraint_overrides.as_ref(),
                )?;
                if is_application {
                    ensure!(
                        matches!(rule.action, PolicyActionV2::DeliveryPlanV1(_)),
                        Error::<T>::InvalidPolicyScope
                    );
                }
                Self::validate_action(&rule.action, constraints.max_replicas)?;
                if let PolicyActionV2::DeliveryPlanV1(plan) = &rule.action {
                    let require_steps: Vec<_> = plan
                        .steps
                        .iter()
                        .filter(|step| {
                            matches!(step.operation, DeliveryStepOperation::RequireProfile)
                        })
                        .collect();
                    if !require_steps.is_empty() {
                        ensure!(
                            matches!(policy.scope, PolicyScopeV3::Persona(_))
                                && require_steps.len() == 1
                                && plan.entry_step == require_steps[0].id
                                && plan.steps.iter().any(|step| matches!(
                                    step.operation,
                                    DeliveryStepOperation::Forward { .. }
                                        | DeliveryStepOperation::Store { .. }
                                ))
                                && plan
                                    .transitions
                                    .iter()
                                    .filter(|edge| edge.from == require_steps[0].id)
                                    .all(|edge| matches!(edge.trigger, TransitionTrigger::Success)),
                            Error::<T>::InvalidDeliveryPlan
                        );
                    }
                    units = units
                        .saturating_add(plan.steps.len() as u32)
                        .saturating_add(plan.transitions.len() as u32);
                    let event_bound = rule
                        .conditions
                        .iter()
                        .any(|condition| matches!(condition, PolicyCondition::EventEquals(_)));
                    let has_control_step = plan.steps.iter().any(|step| {
                        matches!(
                            step.operation,
                            DeliveryStepOperation::Send { .. } | DeliveryStepOperation::Call { .. }
                        )
                    });
                    ensure!(
                        (!has_control_step || event_bound)
                            && (!event_bound
                                || plan.steps.iter().all(|step| matches!(
                                    step.operation,
                                    DeliveryStepOperation::Send { .. }
                                        | DeliveryStepOperation::Call { .. }
                                ))),
                        Error::<T>::InvalidDeliveryPlan
                    );
                    for step in &plan.steps {
                        match &step.operation {
                            DeliveryStepOperation::Forward { targets }
                            | DeliveryStepOperation::Store { targets, .. }
                            | DeliveryStepOperation::Archive { targets } => {
                                ensure!(!is_application, Error::<T>::InvalidPolicyScope);
                                units = units.saturating_add(targets.len() as u32);
                            }
                            DeliveryStepOperation::Call {
                                registered_domain, ..
                            } => {
                                if let PolicyScopeV3::Application(application_id) = &policy.scope {
                                    ensure!(
                                        T::ApplicationProvider::verified_domain(
                                            application_id.as_slice()
                                        )
                                        .is_some_and(
                                            |name| name.as_slice() == registered_domain.as_slice()
                                        ),
                                        Error::<T>::InvalidCallDomain
                                    );
                                } else {
                                    let registration = Self::active_persona(registered_domain)?;
                                    ensure!(
                                        registration.operator_did == policy.operator_did,
                                        Error::<T>::InvalidCallDomain
                                    );
                                }
                            }
                            DeliveryStepOperation::Send { recipient_did, .. } => {
                                if let PolicyScopeV3::Application(application_id) = &policy.scope {
                                    ensure!(
                                        T::ApplicationProvider::authorized_send_target(
                                            application_id.as_slice(),
                                            recipient_did.as_slice()
                                        ),
                                        Error::<T>::InvalidPolicyScope
                                    );
                                }
                            }
                            DeliveryStepOperation::RequireProfile => {
                                ensure!(
                                    !event_bound && !is_application,
                                    Error::<T>::InvalidDeliveryPlan
                                );
                            }
                        }
                    }
                }
            }
            ensure!(
                units <= T::MaxPolicyValidationUnits::get(),
                Error::<T>::PolicyTooComplex
            );
            Ok(())
        }

        fn store_policy_v3(policy: DeliveryPolicyV3<T>) -> DispatchResult {
            Self::validate_policy_v3(&policy)?;
            let scope = policy.scope.clone();
            let policy_id = policy.policy_id.clone();
            let revision = policy.revision;
            match &scope {
                PolicyScopeV3::Did(did) => DidPoliciesV2::<T>::remove(did),
                PolicyScopeV3::Persona(persona) => PersonaPoliciesV2::<T>::remove(persona),
                PolicyScopeV3::Application(_) => {}
            }
            PoliciesV3::<T>::insert(&scope, policy);
            Self::deposit_event(Event::PolicyV3Set {
                scope,
                policy_id,
                revision,
            });
            Ok(())
        }

        fn scope_constraints(
            scope: &PolicyScopeV2<T>,
        ) -> Result<DeliveryConstraints, DispatchError> {
            let network = Self::network_constraints();
            match scope {
                PolicyScopeV2::Did(did) => {
                    Ok(DidDeliveryConstraints::<T>::get(did).unwrap_or(network))
                }
                PolicyScopeV2::Persona(persona) => {
                    let record = Self::active_persona(persona)?;
                    Ok(record.delivery_constraints.unwrap_or(network))
                }
            }
        }

        fn store_policy_v2(policy: DeliveryPolicyV2<T>) -> DispatchResult {
            Self::validate_policy_v2(&policy)?;
            let scope = policy.scope.clone();
            let policy_id = policy.policy_id.clone();
            let revision = policy.revision;
            let v3_scope = match &scope {
                PolicyScopeV2::Did(did) => PolicyScopeV3::Did(did.clone()),
                PolicyScopeV2::Persona(persona) => PolicyScopeV3::Persona(persona.clone()),
            };
            let v3_expected = PoliciesV3::<T>::get(&v3_scope)
                .map(|current| current.revision.saturating_add(1))
                .unwrap_or(1);
            ensure!(revision == v3_expected, Error::<T>::InvalidPolicyRevision);
            let v3 = DeliveryPolicyV3::<T> {
                policy_id: Self::expected_policy_id_v3(&v3_scope)?,
                scope: v3_scope.clone(),
                revision,
                operator_did: policy.operator_did.clone(),
                ruleset: policy.ruleset.clone(),
                policy_ttl_seconds: policy.policy_ttl_seconds,
            };
            PoliciesV3::<T>::insert(v3_scope, v3);
            match &scope {
                PolicyScopeV2::Did(did) => DidPoliciesV2::<T>::insert(did, policy),
                PolicyScopeV2::Persona(persona) => PersonaPoliciesV2::<T>::insert(persona, policy),
            }
            Self::deposit_event(Event::PolicyV2Set {
                scope,
                policy_id,
                revision,
            });
            Ok(())
        }

        fn validate_policy_v2(policy: &DeliveryPolicyV2<T>) -> DispatchResult {
            ensure!(
                policy.policy_id == Self::expected_policy_id(&policy.scope)?,
                Error::<T>::InvalidPolicyId
            );
            ensure!(!policy.ruleset.is_empty(), Error::<T>::EmptyRuleset);
            ensure!(
                policy.policy_ttl_seconds > 0
                    && policy.policy_ttl_seconds <= T::MaxPolicyTtlSeconds::get(),
                Error::<T>::InvalidPolicyTtl
            );
            ensure!(
                Self::policy_validation_units(policy) <= T::MaxPolicyValidationUnits::get(),
                Error::<T>::PolicyTooComplex
            );
            match &policy.scope {
                PolicyScopeV2::Did(did) => {
                    ensure!(
                        T::DidProvider::did_exists(did.as_slice()) && policy.operator_did == *did,
                        Error::<T>::InvalidPolicyScope
                    );
                    let expected_revision = DidPoliciesV2::<T>::get(did)
                        .map(|current| current.revision.saturating_add(1))
                        .unwrap_or(1);
                    ensure!(
                        policy.revision == expected_revision,
                        Error::<T>::InvalidPolicyRevision
                    );
                }
                PolicyScopeV2::Persona(persona) => {
                    let record = Self::active_persona(persona)?;
                    ensure!(
                        policy.operator_did == record.operator_did,
                        Error::<T>::InvalidPolicyScope
                    );
                    let expected_revision = PersonaPoliciesV2::<T>::get(persona)
                        .map(|current| current.revision.saturating_add(1))
                        .unwrap_or(1);
                    ensure!(
                        policy.revision == expected_revision,
                        Error::<T>::InvalidPolicyRevision
                    );
                }
            }
            let constraints = Self::scope_constraints(&policy.scope)?;
            for (index, rule) in policy.ruleset.iter().enumerate() {
                ensure!(!rule.id.is_empty(), Error::<T>::DuplicateRuleId);
                ensure!(
                    rule.priority <= u32::from(u16::MAX),
                    Error::<T>::InvalidRulePriority
                );
                ensure!(
                    !policy.ruleset[..index]
                        .iter()
                        .any(|existing| existing.id == rule.id),
                    Error::<T>::DuplicateRuleId
                );
                for condition in &rule.conditions {
                    ensure!(
                        !matches!(condition, PolicyCondition::EventEquals(_)),
                        Error::<T>::InvalidCondition
                    );
                    Self::validate_condition(condition)?;
                }
                let effective_constraints = Self::apply_constraint_overrides(
                    &constraints,
                    rule.constraint_overrides.as_ref(),
                )?;
                Self::validate_action(&rule.action, effective_constraints.max_replicas)?;
                if let PolicyActionV2::DeliveryPlanV1(plan) = &rule.action {
                    ensure!(
                        plan.steps.iter().all(|step| !matches!(
                            step.operation,
                            DeliveryStepOperation::Send { .. }
                                | DeliveryStepOperation::Call { .. }
                                | DeliveryStepOperation::RequireProfile
                        )),
                        Error::<T>::InvalidDeliveryPlan
                    );
                }
            }
            Ok(())
        }

        fn policy_validation_units(policy: &DeliveryPolicyV2<T>) -> u32 {
            let mut units = policy.ruleset.len() as u32;
            for rule in &policy.ruleset {
                units = units.saturating_add(rule.conditions.len() as u32);
                for condition in &rule.conditions {
                    if let PolicyCondition::RecipientIn(recipients) = condition {
                        units = units.saturating_add(recipients.len() as u32);
                    }
                }
                if let PolicyActionV2::DeliveryPlanV1(plan) = &rule.action {
                    units = units
                        .saturating_add(plan.steps.len() as u32)
                        .saturating_add(plan.transitions.len() as u32);
                    for step in &plan.steps {
                        let targets = match &step.operation {
                            DeliveryStepOperation::Forward { targets }
                            | DeliveryStepOperation::Archive { targets }
                            | DeliveryStepOperation::Store { targets, .. } => targets,
                            DeliveryStepOperation::Send { .. }
                            | DeliveryStepOperation::Call { .. }
                            | DeliveryStepOperation::RequireProfile => continue,
                        };
                        units = units.saturating_add(targets.len() as u32);
                    }
                }
            }
            units
        }

        fn validate_condition(condition: &PolicyCondition<T>) -> DispatchResult {
            match condition {
                PolicyCondition::TagEquals(tag) | PolicyCondition::TagPrefix(tag) => {
                    Self::validate_tag(tag.as_slice())?;
                }
                PolicyCondition::TagAbsent => {}
                PolicyCondition::EventEquals(_) => {}
                PolicyCondition::RecipientEquals(did) => ensure!(
                    T::DidProvider::did_exists(did.as_slice()),
                    Error::<T>::InvalidCondition
                ),
                PolicyCondition::RecipientIn(dids) => {
                    ensure!(!dids.is_empty(), Error::<T>::InvalidCondition);
                    for did in dids {
                        ensure!(
                            T::DidProvider::did_exists(did.as_slice()),
                            Error::<T>::InvalidCondition
                        );
                    }
                }
            }
            Ok(())
        }

        fn valid_payload_template(raw: &[u8]) -> bool {
            fn walk(value: &serde_json::Value, depth: u8, nodes: &mut u16) -> bool {
                if depth > 16 || *nodes >= 256 {
                    return false;
                }
                *nodes += 1;
                match value {
                    serde_json::Value::Object(fields) if fields.contains_key("$from") => {
                        fields.len() == 1
                            && fields["$from"].as_str().is_some_and(|pointer| {
                                pointer.len() <= 256
                                    && (pointer.starts_with("/envelope/")
                                        || pointer.starts_with("/event/")
                                        || pointer.starts_with("/policy/")
                                        || pointer.starts_with("/node/"))
                            })
                    }
                    serde_json::Value::Object(fields) => fields
                        .iter()
                        .all(|(key, value)| key.len() <= 128 && walk(value, depth + 1, nodes)),
                    serde_json::Value::Array(values) => {
                        values.iter().all(|value| walk(value, depth + 1, nodes))
                    }
                    serde_json::Value::String(value) => value.len() <= 2048,
                    _ => true,
                }
            }
            let Ok(value) = serde_json::from_slice::<serde_json::Value>(raw) else {
                return false;
            };
            value.is_object() && walk(&value, 0, &mut 0)
        }

        fn validate_action(action: &PolicyActionV2<T>, max_replicas: u8) -> DispatchResult {
            if let PolicyActionV2::DeliveryPlanV1(plan) = action {
                Self::validate_delivery_plan(plan, max_replicas)?;
            }
            Ok(())
        }

        fn validate_route_targets(
            targets: &[RouteTarget<T>],
            kind: DeliveryServiceKind,
        ) -> DispatchResult {
            ensure!(!targets.is_empty(), Error::<T>::InvalidRouteTarget);
            for (index, target) in targets.iter().enumerate() {
                ensure!(
                    !target.service_id.is_empty()
                        && T::DidProvider::service_supports_delivery(
                            target.service_did.as_slice(),
                            target.service_id.as_slice(),
                            kind,
                        )
                        && target.weight > 0,
                    Error::<T>::InvalidRouteTarget
                );
                ensure!(
                    !targets[..index].iter().any(|existing| {
                        existing.service_did == target.service_did
                            && existing.service_id == target.service_id
                    }),
                    Error::<T>::InvalidRouteTarget
                );
            }
            Ok(())
        }

        fn validate_delivery_plan(plan: &DeliveryPlanV1<T>, max_replicas: u8) -> DispatchResult {
            ensure!(!plan.steps.is_empty(), Error::<T>::InvalidDeliveryPlan);
            let entry = plan
                .steps
                .iter()
                .position(|step| step.id == plan.entry_step)
                .ok_or(Error::<T>::InvalidDeliveryPlan)?;
            let mut forward_steps = 0u8;
            for (index, step) in plan.steps.iter().enumerate() {
                ensure!(!step.id.is_empty(), Error::<T>::DuplicateStepId);
                ensure!(
                    !plan.steps[..index]
                        .iter()
                        .any(|existing| existing.id == step.id),
                    Error::<T>::DuplicateStepId
                );
                match &step.operation {
                    DeliveryStepOperation::Forward { targets } => {
                        forward_steps = forward_steps.saturating_add(1);
                        ensure!(forward_steps <= 1, Error::<T>::MultipleForwardSteps);
                        Self::validate_route_targets(
                            targets.as_slice(),
                            DeliveryServiceKind::Relay,
                        )?;
                    }
                    DeliveryStepOperation::Store {
                        targets,
                        desired_replicas,
                        required_replicas,
                        selection: _,
                    } => {
                        Self::validate_route_targets(
                            targets.as_slice(),
                            DeliveryServiceKind::Cache,
                        )?;
                        ensure!(
                            *desired_replicas > 0
                                && *desired_replicas <= max_replicas
                                && *required_replicas > 0
                                && *required_replicas <= *desired_replicas
                                && usize::from(*desired_replicas) <= targets.len(),
                            Error::<T>::InvalidDeliveryPlan
                        );
                    }
                    DeliveryStepOperation::Archive { targets } => {
                        Self::validate_route_targets(
                            targets.as_slice(),
                            DeliveryServiceKind::Archive,
                        )?;
                    }
                    DeliveryStepOperation::Send {
                        recipient_did,
                        payload_template,
                    } => {
                        ensure!(
                            T::DidProvider::did_exists(recipient_did.as_slice())
                                && Self::valid_payload_template(payload_template.as_slice()),
                            Error::<T>::InvalidPayloadTemplate
                        );
                    }
                    DeliveryStepOperation::Call {
                        service_did,
                        service_id,
                        registered_domain,
                        payload_template,
                    } => {
                        ensure!(
                            T::DidProvider::service_supports_delivery(
                                service_did.as_slice(),
                                service_id.as_slice(),
                                DeliveryServiceKind::ApplicationControl,
                            ),
                            Error::<T>::InvalidRouteTarget
                        );
                        ensure!(
                            registered_domain.contains(&b'.'),
                            Error::<T>::InvalidCallDomain
                        );
                        ensure!(
                            Self::valid_payload_template(payload_template.as_slice()),
                            Error::<T>::InvalidPayloadTemplate
                        );
                    }
                    DeliveryStepOperation::RequireProfile => {}
                }
            }

            let count = plan.steps.len();
            let mut indegree = alloc::vec![0u32; count];
            let mut outgoing: Vec<Vec<usize>> = Vec::with_capacity(count);
            outgoing.resize_with(count, Vec::new);
            for (transition_index, transition) in plan.transitions.iter().enumerate() {
                let from = plan
                    .steps
                    .iter()
                    .position(|step| step.id == transition.from)
                    .ok_or(Error::<T>::InvalidDeliveryPlan)?;
                let to = plan
                    .steps
                    .iter()
                    .position(|step| step.id == transition.to)
                    .ok_or(Error::<T>::InvalidDeliveryPlan)?;
                ensure!(from != to, Error::<T>::DeliveryPlanCycle);
                if transition.mode == TransitionMode::Next {
                    ensure!(
                        !plan.transitions[..transition_index].iter().any(|existing| {
                            existing.from == transition.from
                                && existing.mode == TransitionMode::Next
                                && Self::transition_triggers_overlap(
                                    existing.trigger,
                                    transition.trigger,
                                )
                        }),
                        Error::<T>::InvalidDeliveryPlan
                    );
                }
                ensure!(
                    !outgoing[from].contains(&to),
                    Error::<T>::InvalidDeliveryPlan
                );
                outgoing[from].push(to);
                indegree[to] = indegree[to].saturating_add(1);
            }

            // All encoded steps must be reachable from the declared entry.
            let mut reachable = alloc::vec![false; count];
            let mut stack = Vec::with_capacity(count);
            stack.push(entry);
            while let Some(index) = stack.pop() {
                if reachable[index] {
                    continue;
                }
                reachable[index] = true;
                stack.extend_from_slice(&outgoing[index]);
            }
            ensure!(
                reachable.iter().all(|value| *value),
                Error::<T>::InvalidDeliveryPlan
            );

            // Kahn's algorithm gives a deterministic bounded DAG check.
            let mut queue = Vec::new();
            for (index, value) in indegree.iter().enumerate() {
                if *value == 0 {
                    queue.push(index);
                }
            }
            let mut visited = 0usize;
            while let Some(index) = queue.pop() {
                visited = visited.saturating_add(1);
                for to in &outgoing[index] {
                    indegree[*to] = indegree[*to].saturating_sub(1);
                    if indegree[*to] == 0 {
                        queue.push(*to);
                    }
                }
            }
            ensure!(visited == count, Error::<T>::DeliveryPlanCycle);
            ensure!(
                outgoing.iter().any(Vec::is_empty),
                Error::<T>::InvalidDeliveryPlan
            );
            Ok(())
        }

        fn transition_triggers_overlap(left: TransitionTrigger, right: TransitionTrigger) -> bool {
            left == TransitionTrigger::Always || right == TransitionTrigger::Always || left == right
        }

        fn decode_policy_v2_payload(
            signed_payload: &[u8],
        ) -> Result<PolicyV2AuthorizationPayload<T>, Error<T>> {
            let mut bytes = signed_payload;
            let payload = PolicyV2AuthorizationPayload::<T>::decode(&mut bytes)
                .map_err(|_| Error::<T>::InvalidPolicyV2Payload)?;
            ensure!(bytes.is_empty(), Error::<T>::InvalidPolicyV2Payload);
            ensure!(
                payload.encode() == signed_payload,
                Error::<T>::InvalidPolicyV2Payload
            );
            Ok(payload)
        }

        fn validate_policy_v3_authorization(
            signed_payload: &[u8],
            signature: &[u8],
            signer_key_id: &[u8],
        ) -> Result<PolicyV3AuthorizationPayload<T>, Error<T>> {
            let signer_key = SignerKeyId::try_from(signer_key_id.to_vec())
                .map_err(|_| Error::<T>::InvalidPolicyV3Payload)?;
            let mut bytes = signed_payload;
            let payload = PolicyV3AuthorizationPayload::<T>::decode(&mut bytes)
                .map_err(|_| Error::<T>::InvalidPolicyV3Payload)?;
            ensure!(
                bytes.is_empty()
                    && payload.encode() == signed_payload
                    && payload.signer_key_id == signer_key,
                Error::<T>::InvalidPolicyV3Payload
            );
            ensure!(
                payload.valid_until > pallet_timestamp::Pallet::<T>::get().saturated_into::<u64>(),
                Error::<T>::PolicyAuthorizationExpired
            );
            ensure!(
                payload.nonce == PolicyV3Nonces::<T>::get(&payload.operator_did),
                Error::<T>::InvalidPolicyV3Nonce
            );
            let scope = match &payload.operation {
                PolicyV3Operation::SetPolicy(policy) => &policy.scope,
                PolicyV3Operation::ClearPolicy(scope) => scope,
            };
            let owner = Self::policy_v3_owner(scope).map_err(|_| Error::<T>::InvalidPolicyScope)?;
            ensure!(
                payload.operator_did == owner,
                Error::<T>::InvalidPolicyScope
            );
            if let PolicyScopeV3::Persona(persona) = scope {
                let record =
                    Self::active_persona(persona).map_err(|_| Error::<T>::PersonaInactive)?;
                ensure!(
                    record.controller_key_ids.contains(&signer_key),
                    Error::<T>::InvalidPersonaController
                );
            }
            ensure!(
                T::DidProvider::verify_did_signature(
                    payload.operator_did.as_slice(),
                    signer_key_id,
                    signed_payload,
                    signature,
                ),
                Error::<T>::InvalidSignature
            );
            Ok(payload)
        }

        fn validate_policy_v2_authorization(
            signed_payload: &[u8],
            signature: &[u8],
            signer_key_id: &[u8],
        ) -> Result<PolicyV2AuthorizationPayload<T>, Error<T>> {
            let signer_key_id_b = SignerKeyId::try_from(signer_key_id.to_vec())
                .map_err(|_| Error::<T>::InvalidPolicyV2Payload)?;
            let payload = Self::decode_policy_v2_payload(signed_payload)?;
            ensure!(
                payload.signer_key_id == signer_key_id_b,
                Error::<T>::InvalidPolicyV2Payload
            );
            ensure!(
                payload.valid_until > pallet_timestamp::Pallet::<T>::get().saturated_into::<u64>(),
                Error::<T>::PolicyAuthorizationExpired
            );
            ensure!(
                T::DidProvider::did_exists(payload.operator_did.as_slice()),
                Error::<T>::DidNotFound
            );
            ensure!(
                payload.nonce == PolicyV2Nonces::<T>::get(&payload.operator_did),
                Error::<T>::InvalidPolicyV2Nonce
            );
            Self::ensure_policy_v2_signer_authorized(
                &payload.operator_did,
                &payload.operation,
                &signer_key_id_b,
            )?;
            ensure!(
                T::DidProvider::verify_did_signature(
                    payload.operator_did.as_slice(),
                    signer_key_id,
                    signed_payload,
                    signature,
                ),
                Error::<T>::InvalidSignature
            );
            Ok(payload)
        }

        fn decode_persona_payload(
            signed_payload: &[u8],
        ) -> Result<PersonaAuthorizationPayload<T>, Error<T>> {
            let mut bytes = signed_payload;
            let payload = PersonaAuthorizationPayload::<T>::decode(&mut bytes)
                .map_err(|_| Error::<T>::InvalidPersonaPayload)?;
            ensure!(bytes.is_empty(), Error::<T>::InvalidPersonaPayload);
            ensure!(
                payload.encode() == signed_payload,
                Error::<T>::InvalidPersonaPayload
            );
            Ok(payload)
        }

        fn validate_persona_authorization(
            signed_payload: &[u8],
            signature: &[u8],
            signer_key_id: &[u8],
        ) -> Result<PersonaAuthorizationPayload<T>, Error<T>> {
            let signer_key_id_b = SignerKeyId::try_from(signer_key_id.to_vec())
                .map_err(|_| Error::<T>::InvalidPersonaPayload)?;
            let payload = Self::decode_persona_payload(signed_payload)?;
            ensure!(
                payload.signer_key_id == signer_key_id_b,
                Error::<T>::InvalidPersonaPayload
            );
            ensure!(
                payload.valid_until > pallet_timestamp::Pallet::<T>::get().saturated_into::<u64>(),
                Error::<T>::PolicyAuthorizationExpired
            );
            ensure!(
                T::DidProvider::did_exists(payload.operator_did.as_slice()),
                Error::<T>::DidNotFound
            );
            ensure!(
                payload.nonce == PersonaOperatorNonces::<T>::get(&payload.operator_did),
                Error::<T>::InvalidPersonaOperatorNonce
            );
            Self::ensure_persona_signer_authorized(
                &payload.operator_did,
                &payload.operation,
                &signer_key_id_b,
            )?;
            ensure!(
                T::DidProvider::verify_did_signature(
                    payload.operator_did.as_slice(),
                    signer_key_id,
                    signed_payload,
                    signature,
                ),
                Error::<T>::InvalidSignature
            );
            Ok(payload)
        }

        fn ensure_policy_v2_signer_authorized(
            operator_did: &DidOf<T>,
            operation: &PolicyV2Operation<T>,
            signer_key_id: &SignerKeyId,
        ) -> Result<(), Error<T>> {
            let persona = match operation {
                PolicyV2Operation::SetPolicy(policy) => match &policy.scope {
                    PolicyScopeV2::Persona(persona) => Some(persona),
                    PolicyScopeV2::Did(_) => None,
                },
                PolicyV2Operation::ClearPolicy(PolicyScopeV2::Persona(persona))
                | PolicyV2Operation::SetPersonaConstraints { persona, .. } => Some(persona),
                PolicyV2Operation::ClearPolicy(PolicyScopeV2::Did(_))
                | PolicyV2Operation::SetDidConstraints { .. } => None,
            };
            if let Some(persona) = persona {
                let record = Personas::<T>::get(persona).ok_or(Error::<T>::PersonaNotFound)?;
                ensure!(
                    record.operator_did == *operator_did
                        && record.controller_threshold == 1
                        && record.controller_key_ids.contains(signer_key_id),
                    Error::<T>::InvalidPersonaController
                );
            }
            Ok(())
        }

        fn ensure_persona_signer_authorized(
            operator_did: &DidOf<T>,
            operation: &PersonaOperation<T>,
            signer_key_id: &SignerKeyId,
        ) -> Result<(), Error<T>> {
            match operation {
                PersonaOperation::Register {
                    controller_key_ids,
                    controller_threshold,
                    ..
                }
                | PersonaOperation::RegisterNamed {
                    controller_key_ids,
                    controller_threshold,
                    ..
                } => ensure!(
                    *controller_threshold == 1 && controller_key_ids.contains(signer_key_id),
                    Error::<T>::InvalidPersonaController
                ),
                PersonaOperation::Renew { persona, .. }
                | PersonaOperation::Revoke { persona }
                | PersonaOperation::Transfer { persona, .. } => {
                    let record = Personas::<T>::get(persona).ok_or(Error::<T>::PersonaNotFound)?;
                    ensure!(
                        record.operator_did == *operator_did
                            && record.controller_threshold == 1
                            && record.controller_key_ids.contains(signer_key_id),
                        Error::<T>::InvalidPersonaController
                    );
                }
                PersonaOperation::RotateControllers {
                    persona,
                    controller_key_ids,
                    ..
                } => {
                    let record = Personas::<T>::get(persona).ok_or(Error::<T>::PersonaNotFound)?;
                    ensure!(
                        record.operator_did == *operator_did
                            && record.controller_threshold == 1
                            && record.controller_key_ids.contains(signer_key_id)
                            // Rotations are deliberately staged: the key that
                            // authorizes this change must remain a controller.
                            // A newly added DID key can authorize a later
                            // rotation that removes the previous key.
                            && controller_key_ids.contains(signer_key_id),
                        Error::<T>::InvalidPersonaController
                    );
                }
            }
            Ok(())
        }

        fn validate_controller_keys(keys: &ControllerKeysOf<T>, threshold: u8) -> DispatchResult {
            ensure!(!keys.is_empty(), Error::<T>::InvalidPersonaController);
            ensure!(
                threshold == 1 && usize::from(threshold) <= keys.len(),
                Error::<T>::InvalidPersonaController
            );
            for (index, key) in keys.iter().enumerate() {
                ensure!(!key.is_empty(), Error::<T>::InvalidPersonaController);
                ensure!(
                    !keys[..index].contains(key),
                    Error::<T>::InvalidPersonaController
                );
            }
            Ok(())
        }

        fn apply_persona_operation(
            operator_did: &DidOf<T>,
            operation: PersonaOperation<T>,
        ) -> DispatchResult {
            match operation {
                PersonaOperation::RegisterNamed {
                    persona,
                    controller_key_ids,
                    controller_threshold,
                    constraints,
                } => {
                    ensure!(
                        Self::canonical_persona(persona.as_slice())? == persona
                            && !persona.contains(&b'.'),
                        Error::<T>::InvalidPersona
                    );
                    ensure!(
                        !Personas::<T>::contains_key(&persona),
                        Error::<T>::PersonaAlreadyExists
                    );
                    Self::validate_controller_keys(&controller_key_ids, controller_threshold)?;
                    let constraints = constraints
                        .as_ref()
                        .map(Self::validated_constraints)
                        .transpose()?;
                    Personas::<T>::insert(
                        &persona,
                        PersonaRecord::<T> {
                            operator_did: operator_did.clone(),
                            controller_key_ids,
                            controller_threshold,
                            delivery_constraints: constraints,
                            dns_proof_hash: [0; 32],
                            verified_at: 0,
                            verification_expires_at: 0,
                            revision: 1,
                            active: true,
                        },
                    );
                    NonDnsPersonas::<T>::insert(&persona, ());
                    Self::deposit_event(Event::PersonaRegistered {
                        persona,
                        operator_did: operator_did.clone(),
                    });
                }
                PersonaOperation::Register {
                    persona,
                    controller_key_ids,
                    controller_threshold,
                    constraints,
                    dns_proof_hash,
                    challenge_nonce,
                    verification_expires_at,
                    attestor,
                    attestation_signature,
                } => {
                    ensure!(persona.contains(&b'.'), Error::<T>::InvalidPersona);
                    ensure!(
                        Self::canonical_persona(persona.as_slice())? == persona,
                        Error::<T>::InvalidPersona
                    );
                    ensure!(
                        !Personas::<T>::contains_key(&persona),
                        Error::<T>::PersonaAlreadyExists
                    );
                    Self::validate_controller_keys(&controller_key_ids, controller_threshold)?;
                    let constraints = constraints
                        .as_ref()
                        .map(Self::validated_constraints)
                        .transpose()?;
                    Self::verify_persona_attestation(
                        &persona,
                        operator_did,
                        dns_proof_hash,
                        challenge_nonce,
                        verification_expires_at,
                        &attestor,
                        &attestation_signature,
                    )?;
                    let now = pallet_timestamp::Pallet::<T>::get().saturated_into::<u64>();
                    Personas::<T>::insert(
                        &persona,
                        PersonaRecord::<T> {
                            operator_did: operator_did.clone(),
                            controller_key_ids,
                            controller_threshold,
                            delivery_constraints: constraints,
                            dns_proof_hash,
                            verified_at: now,
                            verification_expires_at,
                            revision: 1,
                            active: true,
                        },
                    );
                    PersonaNonces::<T>::insert(&persona, challenge_nonce.saturating_add(1));
                    Self::deposit_event(Event::PersonaRegistered {
                        persona,
                        operator_did: operator_did.clone(),
                    });
                }
                PersonaOperation::Renew {
                    persona,
                    constraints,
                    dns_proof_hash,
                    challenge_nonce,
                    verification_expires_at,
                    attestor,
                    attestation_signature,
                } => {
                    ensure!(
                        !NonDnsPersonas::<T>::contains_key(&persona),
                        Error::<T>::InvalidPersona
                    );
                    ensure!(
                        Self::canonical_persona(persona.as_slice())? == persona,
                        Error::<T>::InvalidPersona
                    );
                    let mut record =
                        Personas::<T>::get(&persona).ok_or(Error::<T>::PersonaNotFound)?;
                    ensure!(
                        record.operator_did == *operator_did,
                        Error::<T>::InvalidPersonaController
                    );
                    Self::verify_persona_attestation(
                        &persona,
                        operator_did,
                        dns_proof_hash,
                        challenge_nonce,
                        verification_expires_at,
                        &attestor,
                        &attestation_signature,
                    )?;
                    if let Some(constraints) = constraints.as_ref() {
                        record.delivery_constraints =
                            Some(Self::validated_constraints(constraints)?);
                    }
                    record.dns_proof_hash = dns_proof_hash;
                    record.verified_at =
                        pallet_timestamp::Pallet::<T>::get().saturated_into::<u64>();
                    record.verification_expires_at = verification_expires_at;
                    record.revision = record.revision.saturating_add(1);
                    record.active = true;
                    let revision = record.revision;
                    Personas::<T>::insert(&persona, record);
                    PersonaNonces::<T>::insert(&persona, challenge_nonce.saturating_add(1));
                    Self::deposit_event(Event::PersonaRenewed { persona, revision });
                }
                PersonaOperation::Revoke { persona } => {
                    Personas::<T>::try_mutate(&persona, |maybe| -> DispatchResult {
                        let record = maybe.as_mut().ok_or(Error::<T>::PersonaNotFound)?;
                        ensure!(record.active, Error::<T>::PersonaInactive);
                        ensure!(
                            record.operator_did == *operator_did,
                            Error::<T>::InvalidPersonaController
                        );
                        record.active = false;
                        record.revision = record.revision.saturating_add(1);
                        Ok(())
                    })?;
                    Self::deposit_event(Event::PersonaRevoked { persona });
                }
                PersonaOperation::RotateControllers {
                    persona,
                    controller_key_ids,
                    controller_threshold,
                } => {
                    Self::validate_controller_keys(&controller_key_ids, controller_threshold)?;
                    let revision = Personas::<T>::try_mutate(
                        &persona,
                        |maybe| -> Result<u64, DispatchError> {
                            let record = maybe.as_mut().ok_or(Error::<T>::PersonaNotFound)?;
                            ensure!(record.active, Error::<T>::PersonaInactive);
                            ensure!(
                                record.operator_did == *operator_did,
                                Error::<T>::InvalidPersonaController
                            );
                            record.controller_key_ids = controller_key_ids;
                            record.controller_threshold = controller_threshold;
                            record.revision = record.revision.saturating_add(1);
                            Ok(record.revision)
                        },
                    )?;
                    Self::deposit_event(Event::PersonaControllersRotated { persona, revision });
                }
                PersonaOperation::Transfer {
                    persona,
                    new_operator_did,
                    new_controller_key_ids,
                    new_controller_threshold,
                    constraints,
                    dns_proof_hash,
                    challenge_nonce,
                    verification_expires_at,
                    attestor,
                    attestation_signature,
                    new_operator_signer_key_id,
                    new_operator_signature,
                } => {
                    let existing = Self::active_persona(&persona)?;
                    ensure!(
                        existing.operator_did == *operator_did
                            && new_operator_did != *operator_did
                            && T::DidProvider::did_exists(new_operator_did.as_slice()),
                        Error::<T>::InvalidPersonaController
                    );
                    Self::validate_controller_keys(
                        &new_controller_key_ids,
                        new_controller_threshold,
                    )?;
                    ensure!(
                        new_controller_key_ids.contains(&new_operator_signer_key_id),
                        Error::<T>::InvalidPersonaController
                    );
                    let resolved_constraints = constraints
                        .as_ref()
                        .map(Self::validated_constraints)
                        .transpose()?;
                    Self::verify_persona_attestation(
                        &persona,
                        &new_operator_did,
                        dns_proof_hash,
                        challenge_nonce,
                        verification_expires_at,
                        &attestor,
                        &attestation_signature,
                    )?;
                    let acceptance = PersonaTransferAcceptancePayload::<T> {
                        domain: BoundedVec::truncate_from(
                            b"openpayload:persona:transfer:v1".to_vec(),
                        ),
                        genesis_hash: frame_system::Pallet::<T>::block_hash(
                            BlockNumberFor::<T>::zero(),
                        ),
                        persona: persona.clone(),
                        current_operator_did: operator_did.clone(),
                        new_operator_did: new_operator_did.clone(),
                        new_controller_key_ids: new_controller_key_ids.clone(),
                        new_controller_threshold,
                        constraints: constraints.clone(),
                        dns_proof_hash,
                        challenge_nonce,
                        verification_expires_at,
                        new_operator_signer_key_id: new_operator_signer_key_id.clone(),
                    }
                    .encode();
                    ensure!(
                        T::DidProvider::verify_did_signature(
                            new_operator_did.as_slice(),
                            new_operator_signer_key_id.as_slice(),
                            &acceptance,
                            &new_operator_signature,
                        ),
                        Error::<T>::InvalidSignature
                    );

                    let now = pallet_timestamp::Pallet::<T>::get().saturated_into::<u64>();
                    let revision = existing.revision.saturating_add(1);
                    Personas::<T>::insert(
                        &persona,
                        PersonaRecord::<T> {
                            operator_did: new_operator_did.clone(),
                            controller_key_ids: new_controller_key_ids,
                            controller_threshold: new_controller_threshold,
                            delivery_constraints: resolved_constraints,
                            dns_proof_hash,
                            verified_at: now,
                            verification_expires_at,
                            revision,
                            active: true,
                        },
                    );
                    PersonaNonces::<T>::insert(&persona, challenge_nonce.saturating_add(1));
                    if PersonaPoliciesV2::<T>::take(&persona).is_some() {
                        Self::deposit_event(Event::PolicyV2Cleared {
                            scope: PolicyScopeV2::Persona(persona.clone()),
                        });
                    }
                    PoliciesV3::<T>::remove(PolicyScopeV3::Persona(persona.clone()));
                    Self::deposit_event(Event::PersonaTransferred {
                        persona,
                        previous_operator_did: operator_did.clone(),
                        new_operator_did,
                        revision,
                    });
                }
            }
            Ok(())
        }

        fn apply_policy_v2_operation(
            operator_did: &DidOf<T>,
            operation: PolicyV2Operation<T>,
        ) -> DispatchResult {
            match operation {
                PolicyV2Operation::SetPolicy(policy) => {
                    ensure!(
                        policy.operator_did == *operator_did,
                        Error::<T>::InvalidPolicyScope
                    );
                    match &policy.scope {
                        PolicyScopeV2::Did(did) => {
                            ensure!(did == operator_did, Error::<T>::InvalidPolicyScope)
                        }
                        PolicyScopeV2::Persona(persona) => {
                            let record = Self::active_persona(persona)?;
                            ensure!(
                                record.operator_did == *operator_did,
                                Error::<T>::InvalidPolicyScope
                            );
                        }
                    }
                    Self::store_policy_v2(policy)?;
                }
                PolicyV2Operation::ClearPolicy(scope) => match scope {
                    PolicyScopeV2::Did(did) => {
                        ensure!(did == *operator_did, Error::<T>::InvalidPolicyScope);
                        ensure!(
                            DidPoliciesV2::<T>::contains_key(&did),
                            Error::<T>::PolicyNotFound
                        );
                        DidPoliciesV2::<T>::remove(&did);
                        PoliciesV3::<T>::remove(PolicyScopeV3::Did(did.clone()));
                        Self::deposit_event(Event::PolicyV2Cleared {
                            scope: PolicyScopeV2::Did(did),
                        });
                    }
                    PolicyScopeV2::Persona(persona) => {
                        let record =
                            Personas::<T>::get(&persona).ok_or(Error::<T>::PersonaNotFound)?;
                        ensure!(
                            record.operator_did == *operator_did,
                            Error::<T>::InvalidPolicyScope
                        );
                        ensure!(
                            PersonaPoliciesV2::<T>::contains_key(&persona),
                            Error::<T>::PolicyNotFound
                        );
                        PersonaPoliciesV2::<T>::remove(&persona);
                        PoliciesV3::<T>::remove(PolicyScopeV3::Persona(persona.clone()));
                        Self::deposit_event(Event::PolicyV2Cleared {
                            scope: PolicyScopeV2::Persona(persona),
                        });
                    }
                },
                PolicyV2Operation::SetDidConstraints { did, constraints } => {
                    ensure!(did == *operator_did, Error::<T>::InvalidPolicyScope);
                    DidDeliveryConstraints::<T>::insert(
                        &did,
                        Self::validated_constraints(&constraints)?,
                    );
                    Self::deposit_event(Event::DidDeliveryConstraintsSet { did });
                }
                PolicyV2Operation::SetPersonaConstraints {
                    persona,
                    constraints,
                } => {
                    Personas::<T>::try_mutate(&persona, |maybe| -> DispatchResult {
                        let record = maybe.as_mut().ok_or(Error::<T>::PersonaNotFound)?;
                        ensure!(record.active, Error::<T>::PersonaInactive);
                        ensure!(
                            record.operator_did == *operator_did,
                            Error::<T>::InvalidPolicyScope
                        );
                        record.delivery_constraints =
                            Some(Self::validated_constraints(&constraints)?);
                        record.revision = record.revision.saturating_add(1);
                        Ok(())
                    })?;
                }
            }
            Ok(())
        }

        fn condition_matches(
            condition: &PolicyCondition<T>,
            recipient: &DidOf<T>,
            tag: Option<&TagOf<T>>,
        ) -> bool {
            match condition {
                PolicyCondition::TagEquals(expected) => tag == Some(expected),
                PolicyCondition::TagPrefix(prefix) => tag
                    .map(|tag| tag.as_slice().starts_with(prefix.as_slice()))
                    .unwrap_or(false),
                PolicyCondition::TagAbsent => tag.is_none(),
                PolicyCondition::RecipientEquals(expected) => recipient == expected,
                PolicyCondition::RecipientIn(expected) => expected.contains(recipient),
                PolicyCondition::EventEquals(_) => false,
            }
        }

        fn winning_rule<'a>(
            policy: &'a DeliveryPolicyV2<T>,
            recipient: &DidOf<T>,
            tag: Option<&TagOf<T>>,
        ) -> Option<&'a PolicyRule<T>> {
            let mut winner: Option<&PolicyRule<T>> = None;
            for rule in &policy.ruleset {
                if !rule
                    .conditions
                    .iter()
                    .all(|condition| Self::condition_matches(condition, recipient, tag))
                {
                    continue;
                }
                if winner
                    .map(|current| rule.priority > current.priority)
                    .unwrap_or(true)
                {
                    winner = Some(rule);
                }
            }
            winner
        }

        fn resolved_from(
            policy: DeliveryPolicyV2<T>,
            source: PolicyScopeV2<T>,
            recipient: &DidOf<T>,
            tag: Option<&TagOf<T>>,
            constraints: DeliveryConstraints,
        ) -> Option<ResolvedDeliveryPolicy<T>> {
            let rule = Self::winning_rule(&policy, recipient, tag)?;
            let effective_constraints =
                Self::clamp_constraint_overrides(&constraints, rule.constraint_overrides.as_ref());
            Some(ResolvedDeliveryPolicy::<T> {
                source,
                policy_id: policy.policy_id.clone(),
                policy_revision: policy.revision,
                rule_id: rule.id.clone(),
                rule_priority: rule.priority,
                action: rule.action.clone(),
                effective_constraints,
                policy_ttl_seconds: policy.policy_ttl_seconds,
            })
        }

        fn resolved_from_v3(
            policy: DeliveryPolicyV3<T>,
            source: PolicyScopeV2<T>,
            recipient: &DidOf<T>,
            tag: Option<&TagOf<T>>,
            constraints: DeliveryConstraints,
        ) -> Option<ResolvedDeliveryPolicy<T>> {
            Self::resolved_from(
                DeliveryPolicyV2 {
                    policy_id: policy.policy_id,
                    scope: source.clone(),
                    revision: policy.revision,
                    operator_did: policy.operator_did,
                    ruleset: policy.ruleset,
                    policy_ttl_seconds: policy.policy_ttl_seconds,
                },
                source,
                recipient,
                tag,
                constraints,
            )
        }

        /// Resolve Persona first, then DID. Tags are match conditions only and
        /// never identify a policy storage scope. Equal priorities retain
        /// ruleset order because replacement requires a strictly higher value.
        pub fn resolve_policy_v2(
            recipient: &[u8],
            persona: Option<&[u8]>,
            tag: Option<&[u8]>,
        ) -> Option<ResolvedDeliveryPolicy<T>> {
            let recipient = Self::did_from_slice(recipient)?;
            let tag = match tag {
                Some(raw) => {
                    Self::validate_tag(raw).ok()?;
                    Some(TagOf::<T>::try_from(raw.to_vec()).ok()?)
                }
                None => None,
            };
            let configured_did_constraints =
                DidDeliveryConstraints::<T>::get(&recipient).map(Self::normalized_constraints);
            let did_constraints = configured_did_constraints
                .clone()
                .unwrap_or_else(Self::network_constraints);
            let mut addressed_constraints = did_constraints.clone();

            if let Some(raw_persona) = persona {
                let persona = Self::canonical_persona(raw_persona).ok()?;
                let record = Self::active_persona(&persona).ok()?;
                addressed_constraints = match (
                    configured_did_constraints.clone(),
                    record
                        .delivery_constraints
                        .clone()
                        .map(Self::normalized_constraints),
                ) {
                    (Some(did), Some(persona)) => Self::minimum_constraints(did, persona),
                    (Some(did), None) => did,
                    (None, Some(persona)) => persona,
                    (None, None) => Self::network_constraints(),
                };
                if let Some(policy) = PoliciesV3::<T>::get(PolicyScopeV3::Persona(persona.clone()))
                {
                    if let Some(resolved) = Self::resolved_from_v3(
                        policy,
                        PolicyScopeV2::Persona(persona.clone()),
                        &recipient,
                        tag.as_ref(),
                        addressed_constraints.clone(),
                    ) {
                        return Some(resolved);
                    }
                } else if let Some(policy) = PersonaPoliciesV2::<T>::get(&persona) {
                    if let Some(resolved) = Self::resolved_from(
                        policy,
                        PolicyScopeV2::Persona(persona),
                        &recipient,
                        tag.as_ref(),
                        addressed_constraints.clone(),
                    ) {
                        return Some(resolved);
                    }
                }
            }

            if let Some(policy) = PoliciesV3::<T>::get(PolicyScopeV3::Did(recipient.clone())) {
                Self::resolved_from_v3(
                    policy,
                    PolicyScopeV2::Did(recipient.clone()),
                    &recipient,
                    tag.as_ref(),
                    addressed_constraints,
                )
            } else {
                DidPoliciesV2::<T>::get(&recipient).and_then(|policy| {
                    Self::resolved_from(
                        policy,
                        PolicyScopeV2::Did(recipient.clone()),
                        &recipient,
                        tag.as_ref(),
                        addressed_constraints,
                    )
                })
            }
        }

        pub fn resolved_policy_view(
            recipient: Vec<u8>,
            persona: Option<Vec<u8>>,
            tag: Option<Vec<u8>>,
        ) -> Option<ResolvedDeliveryPolicyView> {
            let resolved = Self::resolve_policy_v2(&recipient, persona.as_deref(), tag.as_deref())?;
            Some(ResolvedDeliveryPolicyView {
                source: match resolved.source {
                    PolicyScopeV2::Did(did) => ResolvedPolicySourceView::Did(did.into_inner()),
                    PolicyScopeV2::Persona(persona) => {
                        ResolvedPolicySourceView::Persona(persona.into_inner())
                    }
                },
                policy_id: resolved.policy_id.into_inner(),
                policy_revision: resolved.policy_revision,
                rule_id: resolved.rule_id.into_inner(),
                rule_priority: resolved.rule_priority,
                action: Self::action_view(resolved.action),
                effective_constraints: resolved.effective_constraints,
                policy_ttl_seconds: resolved.policy_ttl_seconds,
            })
        }

        fn action_view(action: PolicyActionV2<T>) -> PolicyActionView {
            match action {
                PolicyActionV2::DeliveryPlanV1(plan) => PolicyActionView::DeliveryPlanV1 {
                    entry_step: plan.entry_step.into_inner(),
                    steps: plan
                        .steps
                        .into_iter()
                        .map(|step| DeliveryStepView {
                            id: step.id.into_inner(),
                            operation: match step.operation {
                                DeliveryStepOperation::Forward { targets } => {
                                    DeliveryStepOperationView::Forward {
                                        targets: targets
                                            .into_iter()
                                            .map(Self::route_target_view)
                                            .collect(),
                                    }
                                }
                                DeliveryStepOperation::Store {
                                    targets,
                                    desired_replicas,
                                    required_replicas,
                                    selection,
                                } => DeliveryStepOperationView::Store {
                                    targets: targets
                                        .into_iter()
                                        .map(Self::route_target_view)
                                        .collect(),
                                    desired_replicas,
                                    required_replicas,
                                    selection: match selection {
                                        CacheSelection::Priority => CacheSelectionView::Priority,
                                        CacheSelection::Weighted => CacheSelectionView::Weighted,
                                    },
                                },
                                DeliveryStepOperation::Archive { targets } => {
                                    DeliveryStepOperationView::Archive {
                                        targets: targets
                                            .into_iter()
                                            .map(Self::route_target_view)
                                            .collect(),
                                    }
                                }
                                DeliveryStepOperation::Send {
                                    recipient_did,
                                    payload_template,
                                } => DeliveryStepOperationView::Send {
                                    recipient_did: recipient_did.into_inner(),
                                    payload_template: payload_template.into_inner(),
                                },
                                DeliveryStepOperation::Call {
                                    service_did,
                                    service_id,
                                    registered_domain,
                                    payload_template,
                                } => DeliveryStepOperationView::Call {
                                    service_did: service_did.into_inner(),
                                    service_id: service_id.into_inner(),
                                    registered_domain: registered_domain.into_inner(),
                                    payload_template: payload_template.into_inner(),
                                },
                                DeliveryStepOperation::RequireProfile => {
                                    DeliveryStepOperationView::RequireProfile
                                }
                            },
                        })
                        .collect(),
                    transitions: plan
                        .transitions
                        .into_iter()
                        .map(|transition| DeliveryTransitionView {
                            from: transition.from.into_inner(),
                            to: transition.to.into_inner(),
                            trigger: match transition.trigger {
                                TransitionTrigger::Success => TransitionTriggerView::Success,
                                TransitionTrigger::Failure => TransitionTriggerView::Failure,
                                TransitionTrigger::Always => TransitionTriggerView::Always,
                            },
                            mode: match transition.mode {
                                TransitionMode::Next => TransitionModeView::Next,
                                TransitionMode::Fork => TransitionModeView::Fork,
                            },
                        })
                        .collect(),
                },
                PolicyActionV2::RejectV1 { reason_code } => {
                    PolicyActionView::RejectV1 { reason_code }
                }
                PolicyActionV2::BaseDidDeliveryV1 => PolicyActionView::BaseDidDeliveryV1,
            }
        }

        fn route_target_view(target: RouteTarget<T>) -> RouteTargetView {
            RouteTargetView {
                service_did: target.service_did.into_inner(),
                service_id: target.service_id.into_inner(),
                priority: target.priority,
                weight: target.weight,
            }
        }
    }
}
