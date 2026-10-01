use crate::{
    mock::*, CacheSelection, DeliveryConstraintOverrides, DeliveryPlanV1,
    DeliveryPolicy as DeliveryPolicyData, DeliveryPolicyV2, DeliveryStep, DeliveryStepOperation,
    DeliveryStepOperationView, DidDeliveryConstraints, DidOf, DidPoliciesV2, Error,
    ExpirationBehavior, PersonaAttestationPayload, PersonaAuthorizationPayload, PersonaOf,
    PersonaOperation, PersonaOperatorNonces, PersonaPolicies, PersonaPoliciesV2,
    PersonaTransferAcceptancePayload, Personas, PolicyAction, PolicyActionV2, PolicyActionView,
    PolicyAuthorizationPayload, PolicyCondition, PolicyIdOf, PolicyNonces, PolicyRule,
    PolicyScopeV2, PolicyV2AuthorizationPayload, PolicyV2Nonces, PolicyV2Operation,
    RecipientPolicies, ReleasePricing, RequestedDeliveryConstraints, RouteTarget, RuleIdOf, TagOf,
    TagPolicies, TransitionMode, TransitionTrigger,
};

#[test]
fn v3_application_call_requires_a_domain_owned_by_its_control_did() {
    new_test_ext().execute_with(|| {
        Timestamp::set_timestamp(1);
        let domain = persona(b"push.example.com");
        let make_registration = |owner: &[u8]| crate::PersonaRecord::<Test> {
            operator_did: did(owner),
            controller_key_ids: vec![b"did:alice#keys-1".to_vec().try_into().unwrap()]
                .try_into()
                .unwrap(),
            controller_threshold: 1,
            delivery_constraints: None,
            dns_proof_hash: [1; 32],
            verified_at: 1,
            verification_expires_at: 10_000,
            revision: 1,
            active: true,
        };
        Personas::<Test>::insert(&domain, make_registration(b"did:bob"));
        let scope = crate::PolicyScopeV3::Application(b"talaria".to_vec().try_into().unwrap());
        let mut id_input = b"openpayload:delivery-policy:v3:".to_vec();
        id_input.extend_from_slice(&scope.encode());
        let policy_id = <Test as frame_system::Config>::Hashing::hash(&id_input)
            .as_ref()
            .to_vec()
            .try_into()
            .unwrap();
        let step = DeliveryStep::<Test> {
            id: rule_id(b"call"),
            operation: DeliveryStepOperation::Call {
                service_did: did(b"did:service"),
                service_id: b"did:service#control".to_vec().try_into().unwrap(),
                registered_domain: domain.clone(),
                payload_template: br#"{"action":"sendPush"}"#.to_vec().try_into().unwrap(),
            },
        };
        let plan = DeliveryPlanV1::<Test> {
            entry_step: rule_id(b"call"),
            steps: vec![step].try_into().unwrap(),
            transitions: Vec::new().try_into().unwrap(),
        };
        let policy = crate::DeliveryPolicyV3::<Test> {
            policy_id,
            scope,
            revision: 1,
            operator_did: did(b"did:alice"),
            ruleset: vec![PolicyRule {
                id: rule_id(b"on-store"),
                priority: 100,
                conditions: vec![PolicyCondition::EventEquals(
                    crate::PolicyEvent::CacheStored,
                )]
                .try_into()
                .unwrap(),
                action: PolicyActionV2::DeliveryPlanV1(plan),
                constraint_overrides: None,
            }]
            .try_into()
            .unwrap(),
            policy_ttl_seconds: 60,
        };
        let proof = crate::PolicyV3AuthorizationPayload::<Test> {
            operator_did: did(b"did:alice"),
            operation: crate::PolicyV3Operation::SetPolicy(policy.clone()),
            nonce: 0,
            valid_until: 5_000,
            signer_key_id: b"did:alice#keys-1".to_vec().try_into().unwrap(),
        }
        .encode();
        assert_noop!(
            DeliveryPolicy::apply_policy_v3_with_proof(
                RuntimeOrigin::none(),
                proof.clone(),
                proof.clone(),
                b"did:alice#keys-1".to_vec()
            ),
            Error::<Test>::InvalidCallDomain
        );
        let mut inactive = make_registration(b"did:alice");
        inactive.active = false;
        Personas::<Test>::insert(&domain, inactive);
        assert_noop!(
            DeliveryPolicy::apply_policy_v3_with_proof(
                RuntimeOrigin::none(),
                proof.clone(),
                proof.clone(),
                b"did:alice#keys-1".to_vec()
            ),
            Error::<Test>::InvalidCallDomain
        );
        Personas::<Test>::insert(&domain, make_registration(b"did:alice"));
        assert_ok!(DeliveryPolicy::apply_policy_v3_with_proof(
            RuntimeOrigin::none(),
            proof.clone(),
            proof,
            b"did:alice#keys-1".to_vec()
        ));
        assert_eq!(crate::PoliciesV3::<Test>::iter_keys().count(), 1);
    });
}
use codec::Encode;
use frame_support::{
    assert_noop, assert_ok,
    traits::{GetStorageVersion, Hooks, StorageVersion},
    BoundedVec,
};
use sp_runtime::traits::Hash;

#[test]
fn named_persona_is_active_without_dns_and_cannot_claim_a_domain() {
    new_test_ext().execute_with(|| {
        let name = b"compliance".to_vec();
        assert_ok!(DeliveryPolicy::register_named_persona(
            RuntimeOrigin::signed(1),
            name.clone(),
            b"did:alice".to_vec(),
            vec![b"did:alice#keys-1".to_vec()],
            1,
            None
        ));
        let key = persona(&name);
        assert!(crate::NonDnsPersonas::<Test>::contains_key(&key));
        assert!(Personas::<Test>::get(&key).unwrap().active);
        assert_noop!(
            DeliveryPolicy::register_named_persona(
                RuntimeOrigin::signed(1),
                b"example.com".to_vec(),
                b"did:alice".to_vec(),
                vec![b"did:alice#keys-1".to_vec()],
                1,
                None
            ),
            Error::<Test>::InvalidPersona
        );
        assert_noop!(
            DeliveryPolicy::register_persona(
                RuntimeOrigin::signed(1),
                b"compliance".to_vec(),
                b"did:alice".to_vec(),
                vec![b"did:alice#keys-1".to_vec()],
                1,
                None,
                [1; 32],
                0,
                10_000,
                1,
                Vec::new()
            ),
            Error::<Test>::InvalidPersona
        );
    });
}

#[test]
fn named_persona_accepts_did_signed_proof_and_consumes_nonce() {
    new_test_ext().execute_with(|| {
        Timestamp::set_timestamp(1);
        let signer = b"did:alice#keys-1".to_vec();
        let proof = PersonaAuthorizationPayload::<Test> {
            operator_did: did(b"did:alice"),
            operation: PersonaOperation::RegisterNamed {
                persona: persona(b"compliance"),
                controller_key_ids: vec![signer.clone().try_into().unwrap()].try_into().unwrap(),
                controller_threshold: 1,
                constraints: None,
            },
            nonce: 0,
            valid_until: 5_000,
            signer_key_id: signer.clone().try_into().unwrap(),
        }
        .encode();
        assert_ok!(DeliveryPolicy::apply_persona_with_proof(
            RuntimeOrigin::none(),
            proof.clone(),
            proof,
            signer
        ));
        assert!(crate::NonDnsPersonas::<Test>::contains_key(persona(
            b"compliance"
        )));
        assert_eq!(PersonaOperatorNonces::<Test>::get(did(b"did:alice")), 1);
    });
}

#[test]
fn persona_profile_requires_a_recipient_route() {
    new_test_ext().execute_with(|| {
        assert_ok!(DeliveryPolicy::register_named_persona(
            RuntimeOrigin::signed(1),
            b"compliance".to_vec(),
            b"did:alice".to_vec(),
            vec![b"did:alice#keys-1".to_vec()],
            1,
            None
        ));
        let scope = crate::PolicyScopeV3::Persona(persona(b"compliance"));
        let mut id_input = b"openpayload:delivery-policy:v3:".to_vec();
        id_input.extend_from_slice(&scope.encode());
        let policy_id = <Test as frame_system::Config>::Hashing::hash(&id_input)
            .as_ref()
            .to_vec()
            .try_into()
            .unwrap();
        let profile = DeliveryStep::<Test> {
            id: rule_id(b"profile"),
            operation: DeliveryStepOperation::RequireProfile,
        };
        let mut plan = DeliveryPlanV1::<Test> {
            entry_step: profile.id.clone(),
            steps: vec![profile].try_into().unwrap(),
            transitions: Vec::new().try_into().unwrap(),
        };
        let mut policy = crate::DeliveryPolicyV3::<Test> {
            policy_id,
            scope,
            revision: 1,
            operator_did: did(b"did:alice"),
            ruleset: vec![PolicyRule {
                id: rule_id(b"gate"),
                priority: 1,
                conditions: BoundedVec::default(),
                action: PolicyActionV2::DeliveryPlanV1(plan.clone()),
                constraint_overrides: None,
            }]
            .try_into()
            .unwrap(),
            policy_ttl_seconds: 60,
        };
        let authorize = |policy: crate::DeliveryPolicyV3<Test>| {
            crate::PolicyV3AuthorizationPayload::<Test> {
                operator_did: did(b"did:alice"),
                operation: crate::PolicyV3Operation::SetPolicy(policy),
                nonce: 0,
                valid_until: 5_000,
                signer_key_id: b"did:alice#keys-1".to_vec().try_into().unwrap(),
            }
            .encode()
        };
        let proof = authorize(policy.clone());
        assert_noop!(
            DeliveryPolicy::apply_policy_v3_with_proof(
                RuntimeOrigin::none(),
                proof.clone(),
                proof.clone(),
                b"did:alice#keys-1".to_vec()
            ),
            Error::<Test>::InvalidDeliveryPlan
        );

        plan.steps
            .try_push(DeliveryStep {
                id: rule_id(b"deliver"),
                operation: DeliveryStepOperation::Forward {
                    targets: vec![RouteTarget::<Test> {
                        service_did: did(b"did:relay"),
                        service_id: b"relay-primary".to_vec().try_into().unwrap(),
                        priority: 1,
                        weight: 1,
                    }]
                    .try_into()
                    .unwrap(),
                },
            })
            .unwrap();
        plan.transitions
            .try_push(crate::DeliveryTransition::<Test> {
                from: rule_id(b"profile"),
                to: rule_id(b"deliver"),
                trigger: TransitionTrigger::Success,
                mode: TransitionMode::Next,
            })
            .unwrap();
        policy.ruleset[0].action = PolicyActionV2::DeliveryPlanV1(plan);
        let proof = authorize(policy);
        assert_ok!(DeliveryPolicy::apply_policy_v3_with_proof(
            RuntimeOrigin::none(),
            proof.clone(),
            proof,
            b"did:alice#keys-1".to_vec()
        ));
    });
}

fn did(raw: &[u8]) -> DidOf<Test> {
    raw.to_vec().try_into().unwrap()
}

fn policy(ttl: u64) -> DeliveryPolicyData<Test> {
    DeliveryPolicyData {
        effective_ttl: ttl,
        max_message_bytes: 1024,
        cache_eligible: true,
        replication: Some(2),
        encrypted_header_preview_bytes: Some(256),
        release_pricing: Some(ReleasePricing {
            base_fee: 10,
            per_kib_fee: 1,
        }),
        expiration_behavior: Some(ExpirationBehavior::DeleteOnExpiry),
    }
}

fn requested_constraints(ttl: u32) -> RequestedDeliveryConstraints {
    RequestedDeliveryConstraints {
        requested_cache_seconds: ttl,
        max_http_envelope_bytes: 26_214_400,
        max_unchunked_message_bytes: 16_777_216,
        max_chunk_bytes: 2_097_152,
        max_message_bytes: 67_108_864,
        max_chunks: 32,
        max_replicas: 4,
    }
}

fn persona(raw: &[u8]) -> PersonaOf<Test> {
    raw.to_vec().try_into().unwrap()
}

fn rule_id(raw: &[u8]) -> RuleIdOf<Test> {
    raw.to_vec().try_into().unwrap()
}

fn policy_id(scope: &PolicyScopeV2<Test>) -> PolicyIdOf<Test> {
    let mut payload = b"openpayload:delivery-policy:v2:".to_vec();
    payload.extend_from_slice(&scope.encode());
    let hash = <Test as frame_system::Config>::Hashing::hash(&payload);
    hash.as_ref().to_vec().try_into().unwrap()
}

fn policy_v2(
    scope: PolicyScopeV2<Test>,
    operator_did: &[u8],
    revision: u64,
    rules: Vec<PolicyRule<Test>>,
) -> DeliveryPolicyV2<Test> {
    DeliveryPolicyV2 {
        policy_id: policy_id(&scope),
        scope,
        revision,
        operator_did: did(operator_did),
        ruleset: rules.try_into().unwrap(),
        policy_ttl_seconds: 60,
    }
}

fn base_rule(id: &[u8], priority: u32, conditions: Vec<PolicyCondition<Test>>) -> PolicyRule<Test> {
    PolicyRule {
        id: rule_id(id),
        priority,
        conditions: conditions.try_into().unwrap(),
        action: PolicyActionV2::BaseDidDeliveryV1,
        constraint_overrides: None,
    }
}

fn persona_attestation(
    persona: &PersonaOf<Test>,
    operator_did: &DidOf<Test>,
    proof: [u8; 32],
    nonce: u64,
    expires_at: u64,
) -> Vec<u8> {
    PersonaAttestationPayload::<Test> {
        domain: BoundedVec::truncate_from(b"openpayload:persona:dns:v1".to_vec()),
        genesis_hash: System::block_hash(0u64),
        persona: persona.clone(),
        operator_did: operator_did.clone(),
        dns_proof_hash: proof,
        challenge_nonce: nonce,
        verification_expires_at: expires_at,
    }
    .encode()
}

fn approve_attestor(account: u64) {
    assert_ok!(DeliveryPolicy::set_persona_attestor(
        RuntimeOrigin::root(),
        account,
        true,
    ));
}

fn signed_policy_payload(
    did_value: &[u8],
    action: PolicyAction<Test>,
    nonce: u64,
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let signer_key_id = b"did:alice#keys-1".to_vec();
    let payload = PolicyAuthorizationPayload::<Test> {
        did: did(did_value),
        action,
        nonce,
        valid_until: 10_000,
        signer_key_id: signer_key_id.clone().try_into().unwrap(),
    }
    .encode();
    // The mock DID provider treats an exact payload copy as a valid signature.
    (payload.clone(), payload, signer_key_id)
}

#[test]
fn all_legacy_v1_policy_writes_are_deprecated() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            DeliveryPolicy::set_delivery_policy(
                RuntimeOrigin::signed(1),
                b"did:alice".to_vec(),
                policy(10),
            ),
            Error::<Test>::LegacyPolicyDeprecated
        );
        assert_noop!(
            DeliveryPolicy::set_tag_policy(
                RuntimeOrigin::signed(1),
                b"did:tag".to_vec(),
                policy(10),
            ),
            Error::<Test>::LegacyPolicyDeprecated
        );
        assert_noop!(
            DeliveryPolicy::set_persona_policy(
                RuntimeOrigin::signed(1),
                b"did:persona".to_vec(),
                policy(10),
            ),
            Error::<Test>::LegacyPolicyDeprecated
        );
        assert!(RecipientPolicies::<Test>::iter().next().is_none());
        assert!(crate::TagPolicies::<Test>::iter().next().is_none());
        assert!(crate::PersonaPolicies::<Test>::iter().next().is_none());
    });
}

#[test]
fn legacy_proof_cannot_create_v1_policy_but_can_clear_preserved_state() {
    new_test_ext().execute_with(|| {
        Timestamp::set_timestamp(1);
        let did_value = b"did:alice";
        let (payload, signature, signer_key_id) =
            signed_policy_payload(did_value, PolicyAction::SetRecipient(policy(25)), 0);

        assert_noop!(
            DeliveryPolicy::apply_policy_with_proof(
                RuntimeOrigin::none(),
                payload,
                signature,
                signer_key_id,
            ),
            Error::<Test>::LegacyPolicyDeprecated
        );
        assert_eq!(PolicyNonces::<Test>::get(did(did_value)), 0);

        RecipientPolicies::<Test>::insert(did(did_value), policy(25));
        let (payload, signature, signer_key_id) =
            signed_policy_payload(did_value, PolicyAction::ClearRecipient, 0);
        assert_ok!(DeliveryPolicy::apply_policy_with_proof(
            RuntimeOrigin::none(),
            payload,
            signature,
            signer_key_id,
        ));
        assert!(!RecipientPolicies::<Test>::contains_key(did(did_value)));
        assert_eq!(PolicyNonces::<Test>::get(did(did_value)), 1);
    });
}

#[test]
fn did_key_policy_proof_rejects_replay_and_invalid_signature() {
    new_test_ext().execute_with(|| {
        Timestamp::set_timestamp(1);
        let did_value = b"did:alice";
        RecipientPolicies::<Test>::insert(did(did_value), policy(25));
        let (payload, signature, signer_key_id) =
            signed_policy_payload(did_value, PolicyAction::ClearRecipient, 0);
        assert_ok!(DeliveryPolicy::apply_policy_with_proof(
            RuntimeOrigin::none(),
            payload.clone(),
            signature,
            signer_key_id.clone(),
        ));

        assert_noop!(
            DeliveryPolicy::apply_policy_with_proof(
                RuntimeOrigin::none(),
                payload,
                b"invalid".to_vec(),
                signer_key_id.clone(),
            ),
            Error::<Test>::InvalidPolicyNonce
        );

        RecipientPolicies::<Test>::insert(did(did_value), policy(25));
        let (payload, _, signer_key_id) =
            signed_policy_payload(did_value, PolicyAction::ClearRecipient, 1);
        assert_noop!(
            DeliveryPolicy::apply_policy_with_proof(
                RuntimeOrigin::none(),
                payload,
                b"invalid".to_vec(),
                signer_key_id,
            ),
            Error::<Test>::InvalidSignature
        );
    });
}

#[test]
fn v2_did_policy_proof_sets_policy_and_rejects_replay() {
    new_test_ext().execute_with(|| {
        Timestamp::set_timestamp(10);
        let operator = did(b"did:alice");
        let signer_key_id = b"did:alice#policy-1".to_vec();
        let scope = PolicyScopeV2::Did(operator.clone());
        let authorization = PolicyV2AuthorizationPayload::<Test> {
            operator_did: operator.clone(),
            operation: PolicyV2Operation::SetPolicy(policy_v2(
                scope,
                operator.as_slice(),
                1,
                vec![base_rule(b"proof", 1, Vec::new())],
            )),
            nonce: 0,
            valid_until: 1_000,
            signer_key_id: signer_key_id.clone().try_into().unwrap(),
        }
        .encode();

        assert_ok!(DeliveryPolicy::apply_policy_v2_with_proof(
            RuntimeOrigin::none(),
            authorization.clone(),
            authorization.clone(),
            signer_key_id.clone(),
        ));
        assert!(DidPoliciesV2::<Test>::contains_key(&operator));
        assert_eq!(PolicyV2Nonces::<Test>::get(&operator), 1);

        assert_noop!(
            DeliveryPolicy::apply_policy_v2_with_proof(
                RuntimeOrigin::none(),
                authorization.clone(),
                authorization,
                signer_key_id,
            ),
            Error::<Test>::InvalidPolicyV2Nonce
        );
    });
}

#[test]
fn v2_policy_lookup_ttl_is_bounded_and_exposed_in_resolution() {
    new_test_ext().execute_with(|| {
        let operator = did(b"did:alice");
        let scope = PolicyScopeV2::Did(operator.clone());
        let mut policy = policy_v2(
            scope,
            operator.as_slice(),
            1,
            vec![base_rule(b"default", 1, Vec::new())],
        );
        policy.policy_ttl_seconds = 0;
        assert_noop!(
            DeliveryPolicy::set_did_policy_v2(
                RuntimeOrigin::signed(1),
                operator.to_vec(),
                policy.clone()
            ),
            Error::<Test>::InvalidPolicyTtl
        );
        policy.policy_ttl_seconds = 301;
        assert_noop!(
            DeliveryPolicy::set_did_policy_v2(
                RuntimeOrigin::signed(1),
                operator.to_vec(),
                policy.clone()
            ),
            Error::<Test>::InvalidPolicyTtl
        );
        policy.policy_ttl_seconds = 45;
        assert_ok!(DeliveryPolicy::set_did_policy_v2(
            RuntimeOrigin::signed(1),
            operator.to_vec(),
            policy
        ));
        let resolved = DeliveryPolicy::resolved_policy_view(operator.to_vec(), None, None)
            .expect("matching DID policy");
        assert_eq!(resolved.policy_ttl_seconds, 45);
    });
}

#[test]
fn v2_constraints_are_clock_time_and_bounded_by_network_limits() {
    new_test_ext().execute_with(|| {
        assert_ok!(DeliveryPolicy::set_did_delivery_constraints(
            RuntimeOrigin::signed(1),
            b"did:alice".to_vec(),
            requested_constraints(604_800),
        ));
        let stored = DidDeliveryConstraints::<Test>::get(did(b"did:alice")).unwrap();
        assert_eq!(stored.requested_cache_seconds, 604_800);
        assert_eq!(stored.effective_ttl_seconds, 172_800);
        assert_eq!(stored.max_chunk_bytes, 2_097_152);
        assert_eq!(stored.max_replicas, 4);
        let scope = PolicyScopeV2::Did(did(b"did:alice"));
        assert_ok!(DeliveryPolicy::set_did_policy_v2(
            RuntimeOrigin::signed(1),
            b"did:alice".to_vec(),
            policy_v2(
                scope,
                b"did:alice",
                1,
                vec![base_rule(b"default", 1, Vec::new())],
            ),
        ));
        let resolved = DeliveryPolicy::resolve_policy_v2(b"did:alice", None, None).unwrap();
        assert_eq!(
            resolved.effective_constraints.requested_cache_seconds,
            604_800
        );
        assert_eq!(
            resolved.effective_constraints.effective_ttl_seconds,
            172_800
        );

        let mut invalid = requested_constraints(86_400);
        invalid.max_chunk_bytes = 2_097_153;
        assert_noop!(
            DeliveryPolicy::set_did_delivery_constraints(
                RuntimeOrigin::signed(1),
                b"did:alice".to_vec(),
                invalid,
            ),
            Error::<Test>::InvalidConstraints
        );

        let mut invalid_envelope = requested_constraints(86_400);
        invalid_envelope.max_http_envelope_bytes = 8 * 1024 * 1024;
        assert_noop!(
            DeliveryPolicy::set_did_delivery_constraints(
                RuntimeOrigin::signed(1),
                b"did:alice".to_vec(),
                invalid_envelope,
            ),
            Error::<Test>::InvalidConstraints
        );
    });
}

#[test]
fn persona_registration_is_unique_canonical_and_dns_attested() {
    new_test_ext().execute_with(|| {
        Timestamp::set_timestamp(10);
        approve_attestor(99);
        let canonical = persona(b"example.com");
        let operator = did(b"did:alice");
        let proof = [7u8; 32];
        let attestation = persona_attestation(&canonical, &operator, proof, 0, 10_000);

        assert_ok!(DeliveryPolicy::register_persona(
            RuntimeOrigin::signed(1),
            b"Example.COM.".to_vec(),
            b"did:alice".to_vec(),
            vec![b"did:alice#policy-1".to_vec()],
            1,
            Some(requested_constraints(48_000)),
            proof,
            0,
            10_000,
            99,
            attestation,
        ));
        let record = Personas::<Test>::get(&canonical).unwrap();
        assert_eq!(record.operator_did, operator);
        assert_eq!(
            record.delivery_constraints.unwrap().effective_ttl_seconds,
            48_000
        );

        let next_attestation = persona_attestation(&canonical, &operator, proof, 1, 20_000);
        assert_noop!(
            DeliveryPolicy::register_persona(
                RuntimeOrigin::signed(1),
                b"example.com".to_vec(),
                b"did:alice".to_vec(),
                vec![b"did:alice#policy-1".to_vec()],
                1,
                None,
                proof,
                1,
                20_000,
                99,
                next_attestation,
            ),
            Error::<Test>::PersonaAlreadyExists
        );

        assert_noop!(
            DeliveryPolicy::register_persona(
                RuntimeOrigin::signed(1),
                b"not-a-domain".to_vec(),
                b"did:alice".to_vec(),
                vec![b"did:alice#policy-1".to_vec()],
                1,
                None,
                proof,
                0,
                10_000,
                99,
                Vec::new(),
            ),
            Error::<Test>::InvalidPersona
        );
        assert_noop!(
            DeliveryPolicy::register_persona(
                RuntimeOrigin::signed(1),
                b"127.0.0.1".to_vec(),
                b"did:alice".to_vec(),
                vec![b"did:alice#policy-1".to_vec()],
                1,
                None,
                proof,
                0,
                10_000,
                99,
                Vec::new(),
            ),
            Error::<Test>::InvalidPersona
        );
    });
}

#[test]
fn persona_proof_path_requires_operator_and_dns_attestor_signatures() {
    new_test_ext().execute_with(|| {
        Timestamp::set_timestamp(10);
        approve_attestor(99);
        let persona_id = persona(b"proof.example");
        let operator = did(b"did:alice");
        let proof = [11u8; 32];
        let attestation = persona_attestation(&persona_id, &operator, proof, 0, 10_000);
        let signer_key_id = b"did:alice#policy-1".to_vec();
        let payload = PersonaAuthorizationPayload::<Test> {
            operator_did: operator.clone(),
            operation: PersonaOperation::Register {
                persona: persona_id.clone(),
                controller_key_ids: vec![signer_key_id.clone().try_into().unwrap()]
                    .try_into()
                    .unwrap(),
                controller_threshold: 1,
                constraints: None,
                dns_proof_hash: proof,
                challenge_nonce: 0,
                verification_expires_at: 10_000,
                attestor: 99,
                attestation_signature: attestation,
            },
            nonce: 0,
            valid_until: 1_000,
            signer_key_id: signer_key_id.clone().try_into().unwrap(),
        }
        .encode();

        assert_ok!(DeliveryPolicy::apply_persona_with_proof(
            RuntimeOrigin::none(),
            payload.clone(),
            payload.clone(),
            signer_key_id.clone(),
        ));
        assert!(Personas::<Test>::contains_key(&persona_id));
        assert_eq!(PersonaOperatorNonces::<Test>::get(&operator), 1);

        assert_noop!(
            DeliveryPolicy::apply_persona_with_proof(
                RuntimeOrigin::none(),
                payload.clone(),
                payload,
                signer_key_id,
            ),
            Error::<Test>::InvalidPersonaOperatorNonce
        );
    });
}

#[test]
fn persona_policy_proof_requires_a_registered_controller_key() {
    new_test_ext().execute_with(|| {
        Timestamp::set_timestamp(10);
        approve_attestor(99);
        let persona_id = persona(b"controller.example");
        let operator = did(b"did:alice");
        let controller = b"did:alice#policy-1".to_vec();
        let proof = [12u8; 32];
        let attestation = persona_attestation(&persona_id, &operator, proof, 0, 10_000);
        assert_ok!(DeliveryPolicy::register_persona(
            RuntimeOrigin::signed(1),
            persona_id.to_vec(),
            operator.to_vec(),
            vec![controller.clone()],
            1,
            None,
            proof,
            0,
            10_000,
            99,
            attestation,
        ));

        let scope = PolicyScopeV2::Persona(persona_id.clone());
        let persona_policy = policy_v2(
            scope,
            operator.as_slice(),
            1,
            vec![base_rule(b"controller-proof", 1, Vec::new())],
        );
        let unauthorized = b"did:alice#other".to_vec();
        let unauthorized_payload = PolicyV2AuthorizationPayload::<Test> {
            operator_did: operator.clone(),
            operation: PolicyV2Operation::SetPolicy(persona_policy.clone()),
            nonce: 0,
            valid_until: 1_000,
            signer_key_id: unauthorized.clone().try_into().unwrap(),
        }
        .encode();
        assert_noop!(
            DeliveryPolicy::apply_policy_v2_with_proof(
                RuntimeOrigin::none(),
                unauthorized_payload.clone(),
                unauthorized_payload,
                unauthorized,
            ),
            Error::<Test>::InvalidPersonaController
        );

        let authorized_payload = PolicyV2AuthorizationPayload::<Test> {
            operator_did: operator.clone(),
            operation: PolicyV2Operation::SetPolicy(persona_policy),
            nonce: 0,
            valid_until: 1_000,
            signer_key_id: controller.clone().try_into().unwrap(),
        }
        .encode();
        assert_ok!(DeliveryPolicy::apply_policy_v2_with_proof(
            RuntimeOrigin::none(),
            authorized_payload.clone(),
            authorized_payload,
            controller,
        ));
        assert!(PersonaPoliciesV2::<Test>::contains_key(&persona_id));
        assert_eq!(PolicyV2Nonces::<Test>::get(&operator), 1);
    });
}

#[test]
fn persona_controller_rotation_must_retain_the_authorizing_did_key() {
    new_test_ext().execute_with(|| {
        Timestamp::set_timestamp(10);
        approve_attestor(99);
        let persona_id = persona(b"rotation.example");
        let operator = did(b"did:alice");
        let current_signer = b"did:alice#policy-1".to_vec();
        let next_signer = b"did:alice#policy-2".to_vec();
        let proof = [13u8; 32];
        let attestation = persona_attestation(&persona_id, &operator, proof, 0, 10_000);
        assert_ok!(DeliveryPolicy::register_persona(
            RuntimeOrigin::signed(1),
            persona_id.to_vec(),
            operator.to_vec(),
            vec![current_signer.clone()],
            1,
            None,
            proof,
            0,
            10_000,
            99,
            attestation,
        ));

        let unsafe_rotation = PersonaAuthorizationPayload::<Test> {
            operator_did: operator.clone(),
            operation: PersonaOperation::RotateControllers {
                persona: persona_id.clone(),
                controller_key_ids: vec![next_signer.clone().try_into().unwrap()]
                    .try_into()
                    .unwrap(),
                controller_threshold: 1,
            },
            nonce: 0,
            valid_until: 1_000,
            signer_key_id: current_signer.clone().try_into().unwrap(),
        }
        .encode();
        assert_noop!(
            DeliveryPolicy::apply_persona_with_proof(
                RuntimeOrigin::none(),
                unsafe_rotation.clone(),
                unsafe_rotation,
                current_signer.clone(),
            ),
            Error::<Test>::InvalidPersonaController
        );
        assert_eq!(PersonaOperatorNonces::<Test>::get(&operator), 0);

        let staged_rotation = PersonaAuthorizationPayload::<Test> {
            operator_did: operator.clone(),
            operation: PersonaOperation::RotateControllers {
                persona: persona_id.clone(),
                controller_key_ids: vec![
                    current_signer.clone().try_into().unwrap(),
                    next_signer.try_into().unwrap(),
                ]
                .try_into()
                .unwrap(),
                controller_threshold: 1,
            },
            nonce: 0,
            valid_until: 1_000,
            signer_key_id: current_signer.clone().try_into().unwrap(),
        }
        .encode();
        assert_ok!(DeliveryPolicy::apply_persona_with_proof(
            RuntimeOrigin::none(),
            staged_rotation.clone(),
            staged_rotation,
            current_signer,
        ));

        let rotated = Personas::<Test>::get(&persona_id).expect("persona remains registered");
        assert_eq!(rotated.controller_key_ids.len(), 2);
        assert_eq!(rotated.revision, 2);
        assert_eq!(PersonaOperatorNonces::<Test>::get(&operator), 1);
    });
}

#[test]
fn revoked_persona_rejects_controller_rotation_without_consuming_nonce() {
    new_test_ext().execute_with(|| {
        Timestamp::set_timestamp(10);
        approve_attestor(99);
        let persona_id = persona(b"revoked-rotation.example");
        let operator = did(b"did:alice");
        let signer = b"did:alice#policy-1".to_vec();
        let proof = [14u8; 32];
        let attestation = persona_attestation(&persona_id, &operator, proof, 0, 10_000);
        assert_ok!(DeliveryPolicy::register_persona(
            RuntimeOrigin::signed(1),
            persona_id.to_vec(),
            operator.to_vec(),
            vec![signer.clone()],
            1,
            None,
            proof,
            0,
            10_000,
            99,
            attestation,
        ));
        assert_ok!(DeliveryPolicy::revoke_persona(
            RuntimeOrigin::signed(1),
            persona_id.to_vec(),
        ));

        let rotation = PersonaAuthorizationPayload::<Test> {
            operator_did: operator.clone(),
            operation: PersonaOperation::RotateControllers {
                persona: persona_id.clone(),
                controller_key_ids: vec![signer.clone().try_into().unwrap()].try_into().unwrap(),
                controller_threshold: 1,
            },
            nonce: 0,
            valid_until: 1_000,
            signer_key_id: signer.clone().try_into().unwrap(),
        }
        .encode();
        assert_noop!(
            DeliveryPolicy::apply_persona_with_proof(
                RuntimeOrigin::none(),
                rotation.clone(),
                rotation,
                signer,
            ),
            Error::<Test>::PersonaInactive
        );
        assert_eq!(PersonaOperatorNonces::<Test>::get(&operator), 0);
        assert!(!Personas::<Test>::get(&persona_id).unwrap().active);
    });
}

#[test]
fn revoked_persona_rejects_constraint_update_without_consuming_nonce() {
    new_test_ext().execute_with(|| {
        Timestamp::set_timestamp(10);
        approve_attestor(99);
        let persona_id = persona(b"revoked-constraints.example");
        let operator = did(b"did:alice");
        let signer = b"did:alice#policy-1".to_vec();
        let proof = [15u8; 32];
        let attestation = persona_attestation(&persona_id, &operator, proof, 0, 10_000);
        assert_ok!(DeliveryPolicy::register_persona(
            RuntimeOrigin::signed(1),
            persona_id.to_vec(),
            operator.to_vec(),
            vec![signer.clone()],
            1,
            None,
            proof,
            0,
            10_000,
            99,
            attestation,
        ));
        assert_ok!(DeliveryPolicy::revoke_persona(
            RuntimeOrigin::signed(1),
            persona_id.to_vec(),
        ));

        let update = PolicyV2AuthorizationPayload::<Test> {
            operator_did: operator.clone(),
            operation: PolicyV2Operation::SetPersonaConstraints {
                persona: persona_id.clone(),
                constraints: requested_constraints(3_600),
            },
            nonce: 0,
            valid_until: 1_000,
            signer_key_id: signer.clone().try_into().unwrap(),
        }
        .encode();
        assert_noop!(
            DeliveryPolicy::apply_policy_v2_with_proof(
                RuntimeOrigin::none(),
                update.clone(),
                update,
                signer,
            ),
            Error::<Test>::PersonaInactive
        );
        assert_eq!(PolicyV2Nonces::<Test>::get(&operator), 0);
        let record = Personas::<Test>::get(&persona_id).unwrap();
        assert!(!record.active);
        assert!(record.delivery_constraints.is_none());
    });
}

#[test]
fn revoked_persona_can_renew_and_reactivate() {
    new_test_ext().execute_with(|| {
        Timestamp::set_timestamp(10);
        approve_attestor(99);
        let persona_id = persona(b"revoked-renewal.example");
        let operator = did(b"did:alice");
        let signer = b"did:alice#policy-1".to_vec();
        let registration_proof = [16u8; 32];
        let registration_attestation =
            persona_attestation(&persona_id, &operator, registration_proof, 0, 10_000);
        assert_ok!(DeliveryPolicy::register_persona(
            RuntimeOrigin::signed(1),
            persona_id.to_vec(),
            operator.to_vec(),
            vec![signer.clone()],
            1,
            None,
            registration_proof,
            0,
            10_000,
            99,
            registration_attestation,
        ));
        assert_ok!(DeliveryPolicy::revoke_persona(
            RuntimeOrigin::signed(1),
            persona_id.to_vec(),
        ));

        let renewal_proof = [17u8; 32];
        let renewal_attestation =
            persona_attestation(&persona_id, &operator, renewal_proof, 1, 20_000);
        let renewal = PersonaAuthorizationPayload::<Test> {
            operator_did: operator.clone(),
            operation: PersonaOperation::Renew {
                persona: persona_id.clone(),
                constraints: Some(requested_constraints(7_200)),
                dns_proof_hash: renewal_proof,
                challenge_nonce: 1,
                verification_expires_at: 20_000,
                attestor: 99,
                attestation_signature: renewal_attestation,
            },
            nonce: 0,
            valid_until: 1_000,
            signer_key_id: signer.clone().try_into().unwrap(),
        }
        .encode();
        assert_ok!(DeliveryPolicy::apply_persona_with_proof(
            RuntimeOrigin::none(),
            renewal.clone(),
            renewal,
            signer,
        ));

        let renewed = Personas::<Test>::get(&persona_id).unwrap();
        assert!(renewed.active);
        assert_eq!(renewed.verification_expires_at, 20_000);
        assert_eq!(
            renewed.delivery_constraints.unwrap().effective_ttl_seconds,
            7_200
        );
        assert_eq!(PersonaOperatorNonces::<Test>::get(&operator), 1);
    });
}

#[test]
fn persona_transfer_requires_both_operators_and_fresh_dns_attestation() {
    new_test_ext().execute_with(|| {
        Timestamp::set_timestamp(10);
        approve_attestor(99);

        let persona_id = persona(b"transfer.example");
        let current_operator = did(b"did:alice");
        let current_signer = b"did:alice#policy-1".to_vec();
        let registration_proof = [21u8; 32];
        let registration_attestation = persona_attestation(
            &persona_id,
            &current_operator,
            registration_proof,
            0,
            10_000,
        );
        assert_ok!(DeliveryPolicy::register_persona(
            RuntimeOrigin::signed(1),
            persona_id.to_vec(),
            current_operator.to_vec(),
            vec![current_signer.clone()],
            1,
            None,
            registration_proof,
            0,
            10_000,
            99,
            registration_attestation,
        ));

        let persona_scope = PolicyScopeV2::Persona(persona_id.clone());
        assert_ok!(DeliveryPolicy::set_persona_policy_v2(
            RuntimeOrigin::signed(1),
            persona_id.to_vec(),
            policy_v2(
                persona_scope,
                current_operator.as_slice(),
                1,
                vec![base_rule(b"old-owner-policy", 1, Vec::new())],
            ),
        ));

        let new_operator = did(b"did:bob");
        let new_signer = b"did:bob#policy-1".to_vec();
        let new_controllers: crate::ControllerKeysOf<Test> =
            vec![new_signer.clone().try_into().unwrap()]
                .try_into()
                .unwrap();
        let transfer_proof = [22u8; 32];
        let transfer_attestation =
            persona_attestation(&persona_id, &new_operator, transfer_proof, 1, 20_000);
        let acceptance = PersonaTransferAcceptancePayload::<Test> {
            domain: BoundedVec::truncate_from(b"openpayload:persona:transfer:v1".to_vec()),
            genesis_hash: System::block_hash(0u64),
            persona: persona_id.clone(),
            current_operator_did: current_operator.clone(),
            new_operator_did: new_operator.clone(),
            new_controller_key_ids: new_controllers.clone(),
            new_controller_threshold: 1,
            constraints: None,
            dns_proof_hash: transfer_proof,
            challenge_nonce: 1,
            verification_expires_at: 20_000,
            new_operator_signer_key_id: new_signer.clone().try_into().unwrap(),
        }
        .encode();
        let authorization = PersonaAuthorizationPayload::<Test> {
            operator_did: current_operator.clone(),
            operation: PersonaOperation::Transfer {
                persona: persona_id.clone(),
                new_operator_did: new_operator.clone(),
                new_controller_key_ids: new_controllers,
                new_controller_threshold: 1,
                constraints: None,
                dns_proof_hash: transfer_proof,
                challenge_nonce: 1,
                verification_expires_at: 20_000,
                attestor: 99,
                attestation_signature: transfer_attestation,
                new_operator_signer_key_id: new_signer.try_into().unwrap(),
                new_operator_signature: acceptance,
            },
            nonce: 0,
            valid_until: 1_000,
            signer_key_id: current_signer.clone().try_into().unwrap(),
        }
        .encode();

        assert_ok!(DeliveryPolicy::apply_persona_with_proof(
            RuntimeOrigin::none(),
            authorization.clone(),
            authorization,
            current_signer,
        ));

        let transferred = Personas::<Test>::get(&persona_id).expect("persona remains active");
        assert_eq!(transferred.operator_did, new_operator);
        assert_eq!(transferred.revision, 2);
        assert!(transferred.active);
        assert!(PersonaPoliciesV2::<Test>::get(&persona_id).is_none());
        assert_eq!(PersonaOperatorNonces::<Test>::get(&current_operator), 1);
    });
}

#[test]
fn v2_resolution_uses_persona_then_did_and_tag_is_only_a_condition() {
    new_test_ext().execute_with(|| {
        Timestamp::set_timestamp(10);
        approve_attestor(99);
        let persona_id = persona(b"example.com");
        let operator = did(b"did:alice");
        let proof = [9u8; 32];
        let attestation = persona_attestation(&persona_id, &operator, proof, 0, 10_000);
        assert_ok!(DeliveryPolicy::register_persona(
            RuntimeOrigin::signed(1),
            persona_id.to_vec(),
            operator.to_vec(),
            vec![b"did:alice#policy-1".to_vec()],
            1,
            None,
            proof,
            0,
            10_000,
            99,
            attestation,
        ));

        let recipient = did(b"did:recipient");
        let did_scope = PolicyScopeV2::Did(recipient.clone());
        assert_ok!(DeliveryPolicy::set_did_policy_v2(
            RuntimeOrigin::signed(1),
            recipient.to_vec(),
            policy_v2(
                did_scope,
                recipient.as_slice(),
                1,
                vec![base_rule(b"did-default", 10, Vec::new())],
            ),
        ));

        let legal_tag: TagOf<Test> = b"Legal".to_vec().try_into().unwrap();
        let persona_scope = PolicyScopeV2::Persona(persona_id.clone());
        assert_ok!(DeliveryPolicy::set_persona_policy_v2(
            RuntimeOrigin::signed(1),
            persona_id.to_vec(),
            policy_v2(
                persona_scope,
                operator.as_slice(),
                1,
                vec![
                    base_rule(
                        b"persona-legal-low",
                        20,
                        vec![PolicyCondition::TagEquals(legal_tag.clone())],
                    ),
                    base_rule(
                        b"persona-legal-high",
                        100,
                        vec![PolicyCondition::TagEquals(legal_tag)],
                    ),
                ],
            ),
        ));

        let winning = DeliveryPolicy::resolve_policy_v2(
            recipient.as_slice(),
            Some(persona_id.as_slice()),
            Some(b"Legal"),
        )
        .unwrap();
        assert_eq!(winning.rule_id.as_slice(), b"persona-legal-high");
        assert!(matches!(winning.source, PolicyScopeV2::Persona(_)));

        let fallback = DeliveryPolicy::resolve_policy_v2(
            recipient.as_slice(),
            Some(persona_id.as_slice()),
            Some(b"Confidential"),
        )
        .unwrap();
        assert_eq!(fallback.rule_id.as_slice(), b"did-default");
        assert!(matches!(fallback.source, PolicyScopeV2::Did(_)));
    });
}

#[test]
fn merged_did_and_persona_constraints_ignore_legacy_aggregate_fields() {
    new_test_ext().execute_with(|| {
        Timestamp::set_timestamp(10);
        approve_attestor(99);

        let recipient = did(b"did:recipient");
        let mut did_constraints = requested_constraints(86_400);
        did_constraints.max_chunks = 16;
        did_constraints.max_message_bytes = 32 * 1024 * 1024;
        assert_ok!(DeliveryPolicy::set_did_delivery_constraints(
            RuntimeOrigin::signed(1),
            recipient.to_vec(),
            did_constraints,
        ));

        let persona_id = persona(b"merge.example");
        let operator = did(b"did:alice");
        let proof = [31u8; 32];
        let attestation = persona_attestation(&persona_id, &operator, proof, 0, 10_000);
        let mut persona_constraints = requested_constraints(86_400);
        persona_constraints.max_chunk_bytes = 1024 * 1024;
        persona_constraints.max_message_bytes = 32 * 1024 * 1024;
        assert_ok!(DeliveryPolicy::register_persona(
            RuntimeOrigin::signed(1),
            persona_id.to_vec(),
            operator.to_vec(),
            vec![b"did:alice#policy-1".to_vec()],
            1,
            Some(persona_constraints),
            proof,
            0,
            10_000,
            99,
            attestation,
        ));
        let scope = PolicyScopeV2::Persona(persona_id.clone());
        assert_ok!(DeliveryPolicy::set_persona_policy_v2(
            RuntimeOrigin::signed(1),
            persona_id.to_vec(),
            policy_v2(
                scope,
                operator.as_slice(),
                1,
                vec![base_rule(b"merge", 1, Vec::new())],
            ),
        ));

        let resolved = DeliveryPolicy::resolve_policy_v2(
            recipient.as_slice(),
            Some(persona_id.as_slice()),
            None,
        )
        .unwrap();
        let constraints = resolved.effective_constraints;
        assert_eq!(constraints.max_chunk_bytes, 1024 * 1024);
        assert_eq!(constraints.max_chunks, u16::MAX);
        assert_eq!(constraints.max_message_bytes, u32::MAX);
        assert_eq!(constraints.max_unchunked_message_bytes, 16 * 1024 * 1024);
    });
}

#[test]
fn did_fallback_keeps_addressed_persona_constraints() {
    new_test_ext().execute_with(|| {
        Timestamp::set_timestamp(10);
        approve_attestor(99);

        let recipient = did(b"did:recipient");
        let did_scope = PolicyScopeV2::Did(recipient.clone());
        assert_ok!(DeliveryPolicy::set_did_policy_v2(
            RuntimeOrigin::signed(1),
            recipient.to_vec(),
            policy_v2(
                did_scope,
                recipient.as_slice(),
                1,
                vec![base_rule(b"did-default", 10, Vec::new())],
            ),
        ));

        let persona_id = persona(b"bounded.example");
        let operator = did(b"did:alice");
        let proof = [41u8; 32];
        let attestation = persona_attestation(&persona_id, &operator, proof, 0, 10_000);
        let mut persona_constraints = requested_constraints(3_600);
        persona_constraints.max_replicas = 2;
        assert_ok!(DeliveryPolicy::register_persona(
            RuntimeOrigin::signed(1),
            persona_id.to_vec(),
            operator.to_vec(),
            vec![b"did:alice#policy-1".to_vec()],
            1,
            Some(persona_constraints),
            proof,
            0,
            10_000,
            99,
            attestation,
        ));

        let legal_tag: TagOf<Test> = b"Legal".to_vec().try_into().unwrap();
        let persona_scope = PolicyScopeV2::Persona(persona_id.clone());
        assert_ok!(DeliveryPolicy::set_persona_policy_v2(
            RuntimeOrigin::signed(1),
            persona_id.to_vec(),
            policy_v2(
                persona_scope,
                operator.as_slice(),
                1,
                vec![base_rule(
                    b"persona-legal",
                    100,
                    vec![PolicyCondition::TagEquals(legal_tag)],
                )],
            ),
        ));

        let fallback = DeliveryPolicy::resolve_policy_v2(
            recipient.as_slice(),
            Some(persona_id.as_slice()),
            Some(b"Confidential"),
        )
        .expect("DID rule falls through");
        assert!(matches!(fallback.source, PolicyScopeV2::Did(_)));
        assert_eq!(fallback.effective_constraints.effective_ttl_seconds, 3_600);
        assert_eq!(fallback.effective_constraints.max_replicas, 2);
    });
}

#[test]
fn persona_override_is_clamped_by_recipient_without_losing_persona_precedence() {
    new_test_ext().execute_with(|| {
        Timestamp::set_timestamp(10);
        approve_attestor(99);

        let recipient = did(b"did:recipient");
        let mut did_constraints = requested_constraints(3_600);
        did_constraints.max_http_envelope_bytes = 8 * 1024 * 1024;
        did_constraints.max_unchunked_message_bytes = 6 * 1024 * 1024;
        did_constraints.max_chunk_bytes = 1024 * 1024;
        did_constraints.max_message_bytes = 8 * 1024 * 1024;
        did_constraints.max_chunks = 8;
        did_constraints.max_replicas = 2;
        assert_ok!(DeliveryPolicy::set_did_delivery_constraints(
            RuntimeOrigin::signed(1),
            recipient.to_vec(),
            did_constraints,
        ));
        let did_scope = PolicyScopeV2::Did(recipient.clone());
        assert_ok!(DeliveryPolicy::set_did_policy_v2(
            RuntimeOrigin::signed(1),
            recipient.to_vec(),
            policy_v2(
                did_scope,
                recipient.as_slice(),
                1,
                vec![base_rule(b"did-fallback", 1, Vec::new())],
            ),
        ));

        let persona_id = persona(b"override-clamp.example");
        let operator = did(b"did:alice");
        let proof = [42u8; 32];
        let attestation = persona_attestation(&persona_id, &operator, proof, 0, 10_000);
        let mut persona_constraints = requested_constraints(86_400);
        persona_constraints.max_replicas = 4;
        assert_ok!(DeliveryPolicy::register_persona(
            RuntimeOrigin::signed(1),
            persona_id.to_vec(),
            operator.to_vec(),
            vec![b"did:alice#policy-1".to_vec()],
            1,
            Some(persona_constraints),
            proof,
            0,
            10_000,
            99,
            attestation,
        ));

        let mut persona_rule = base_rule(b"persona-winner", 100, Vec::new());
        persona_rule.constraint_overrides = Some(DeliveryConstraintOverrides {
            requested_cache_seconds: Some(7_200),
            max_http_envelope_bytes: Some(16 * 1024 * 1024),
            max_unchunked_message_bytes: Some(12 * 1024 * 1024),
            max_chunk_bytes: Some(1_572_864),
            max_message_bytes: Some(32 * 1024 * 1024),
            max_chunks: Some(24),
            max_replicas: Some(3),
        });
        let persona_scope = PolicyScopeV2::Persona(persona_id.clone());
        assert_ok!(DeliveryPolicy::set_persona_policy_v2(
            RuntimeOrigin::signed(1),
            persona_id.to_vec(),
            policy_v2(persona_scope, operator.as_slice(), 1, vec![persona_rule],),
        ));

        let resolved = DeliveryPolicy::resolve_policy_v2(
            recipient.as_slice(),
            Some(persona_id.as_slice()),
            None,
        )
        .expect("Persona rule must remain the winner");
        assert!(matches!(resolved.source, PolicyScopeV2::Persona(_)));
        assert_eq!(resolved.rule_id.as_slice(), b"persona-winner");
        let effective = resolved.effective_constraints;
        assert_eq!(effective.requested_cache_seconds, 3_600);
        assert_eq!(effective.effective_ttl_seconds, 3_600);
        assert_eq!(effective.max_http_envelope_bytes, 8 * 1024 * 1024);
        assert_eq!(effective.max_unchunked_message_bytes, 6 * 1024 * 1024);
        assert_eq!(effective.max_chunk_bytes, 1024 * 1024);
        assert_eq!(effective.max_message_bytes, u32::MAX);
        assert_eq!(effective.max_chunks, u16::MAX);
        assert_eq!(effective.max_replicas, 2);
    });
}

#[test]
fn legacy_aggregate_fields_are_accepted_but_never_enforced_or_resolved() {
    new_test_ext().execute_with(|| {
        let mut constraints = requested_constraints(86_400);
        constraints.max_message_bytes = 0;
        constraints.max_chunks = 0;
        assert_ok!(DeliveryPolicy::set_did_delivery_constraints(
            RuntimeOrigin::signed(1),
            b"did:alice".to_vec(),
            constraints,
        ));

        let stored = DidDeliveryConstraints::<Test>::get(did(b"did:alice")).unwrap();
        assert_eq!(stored.max_message_bytes, u32::MAX);
        assert_eq!(stored.max_chunks, u16::MAX);

        let scope = PolicyScopeV2::Did(did(b"did:alice"));
        let mut rule = base_rule(b"compat", 1, Vec::new());
        rule.constraint_overrides = Some(DeliveryConstraintOverrides {
            requested_cache_seconds: None,
            max_http_envelope_bytes: None,
            max_unchunked_message_bytes: None,
            max_chunk_bytes: None,
            max_message_bytes: Some(1),
            max_chunks: Some(1),
            max_replicas: None,
        });
        assert_ok!(DeliveryPolicy::set_did_policy_v2(
            RuntimeOrigin::signed(1),
            b"did:alice".to_vec(),
            policy_v2(scope, b"did:alice", 1, vec![rule]),
        ));
        let resolved = DeliveryPolicy::resolve_policy_v2(b"did:alice", None, None).unwrap();
        assert_eq!(resolved.effective_constraints.max_message_bytes, u32::MAX);
        assert_eq!(resolved.effective_constraints.max_chunks, u16::MAX);
    });
}

#[test]
fn rule_priority_is_bounded_for_directory_interop() {
    new_test_ext().execute_with(|| {
        let scope = PolicyScopeV2::Did(did(b"did:alice"));
        assert_ok!(DeliveryPolicy::set_did_policy_v2(
            RuntimeOrigin::signed(1),
            b"did:alice".to_vec(),
            policy_v2(
                scope.clone(),
                b"did:alice",
                1,
                vec![base_rule(b"max-priority", u32::from(u16::MAX), Vec::new())],
            ),
        ));
        assert_noop!(
            DeliveryPolicy::set_did_policy_v2(
                RuntimeOrigin::signed(1),
                b"did:alice".to_vec(),
                policy_v2(
                    scope,
                    b"did:alice",
                    2,
                    vec![base_rule(
                        b"too-high-priority",
                        u32::from(u16::MAX) + 1,
                        Vec::new(),
                    )],
                ),
            ),
            Error::<Test>::InvalidRulePriority
        );
    });
}

#[test]
fn rule_overrides_can_only_narrow_scope_constraints() {
    new_test_ext().execute_with(|| {
        assert_ok!(DeliveryPolicy::set_did_delivery_constraints(
            RuntimeOrigin::signed(1),
            b"did:alice".to_vec(),
            requested_constraints(86_400),
        ));
        let scope = PolicyScopeV2::Did(did(b"did:alice"));
        let mut rule = base_rule(b"narrow", 1, Vec::new());
        rule.constraint_overrides = Some(DeliveryConstraintOverrides {
            requested_cache_seconds: Some(3_600),
            max_http_envelope_bytes: None,
            max_unchunked_message_bytes: None,
            max_chunk_bytes: None,
            max_message_bytes: None,
            max_chunks: None,
            max_replicas: Some(2),
        });
        assert_ok!(DeliveryPolicy::set_did_policy_v2(
            RuntimeOrigin::signed(1),
            b"did:alice".to_vec(),
            policy_v2(scope, b"did:alice", 1, vec![rule]),
        ));
        let resolved = DeliveryPolicy::resolve_policy_v2(b"did:alice", None, None).unwrap();
        assert_eq!(resolved.effective_constraints.effective_ttl_seconds, 3_600);
        assert_eq!(resolved.effective_constraints.max_replicas, 2);

        let scope = PolicyScopeV2::Did(did(b"did:bob"));
        let mut invalid = base_rule(b"widen", 1, Vec::new());
        invalid.constraint_overrides = Some(DeliveryConstraintOverrides {
            requested_cache_seconds: Some(172_801),
            max_http_envelope_bytes: None,
            max_unchunked_message_bytes: None,
            max_chunk_bytes: None,
            max_message_bytes: None,
            max_chunks: None,
            max_replicas: None,
        });
        assert_noop!(
            DeliveryPolicy::set_did_policy_v2(
                RuntimeOrigin::signed(2),
                b"did:bob".to_vec(),
                policy_v2(scope, b"did:bob", 1, vec![invalid]),
            ),
            Error::<Test>::ConstraintOverrideExceedsScope
        );
    });
}

#[test]
fn delivery_plan_rejects_cycles_and_invalid_replication() {
    new_test_ext().execute_with(|| {
        let relay_target = RouteTarget::<Test> {
            service_did: did(b"did:relay"),
            service_id: b"relay-primary".to_vec().try_into().unwrap(),
            priority: 1,
            weight: 1,
        };
        let archive_target = RouteTarget::<Test> {
            service_did: did(b"did:archive"),
            service_id: b"archive-primary".to_vec().try_into().unwrap(),
            priority: 1,
            weight: 1,
        };
        let steps: BoundedVec<DeliveryStep<Test>, _> = vec![
            DeliveryStep {
                id: rule_id(b"a"),
                operation: DeliveryStepOperation::Forward {
                    targets: vec![relay_target].try_into().unwrap(),
                },
            },
            DeliveryStep {
                id: rule_id(b"b"),
                operation: DeliveryStepOperation::Archive {
                    targets: vec![archive_target].try_into().unwrap(),
                },
            },
        ]
        .try_into()
        .unwrap();
        let transitions = vec![
            crate::DeliveryTransition::<Test> {
                from: rule_id(b"a"),
                to: rule_id(b"b"),
                trigger: TransitionTrigger::Success,
                mode: TransitionMode::Next,
            },
            crate::DeliveryTransition::<Test> {
                from: rule_id(b"b"),
                to: rule_id(b"a"),
                trigger: TransitionTrigger::Failure,
                mode: TransitionMode::Next,
            },
        ]
        .try_into()
        .unwrap();
        let rule = PolicyRule::<Test> {
            id: rule_id(b"cyclic"),
            priority: 1,
            conditions: BoundedVec::default(),
            action: PolicyActionV2::DeliveryPlanV1(DeliveryPlanV1 {
                entry_step: rule_id(b"a"),
                steps,
                transitions,
            }),
            constraint_overrides: None,
        };
        let scope = PolicyScopeV2::Did(did(b"did:alice"));
        assert_noop!(
            DeliveryPolicy::set_did_policy_v2(
                RuntimeOrigin::signed(1),
                b"did:alice".to_vec(),
                policy_v2(scope, b"did:alice", 1, vec![rule]),
            ),
            Error::<Test>::DeliveryPlanCycle
        );
    });
}

#[test]
fn delivery_plan_accepts_zero_forward_steps() {
    new_test_ext().execute_with(|| {
        let cache_target = RouteTarget::<Test> {
            service_did: did(b"did:cache"),
            service_id: b"cache-primary".to_vec().try_into().unwrap(),
            priority: 1,
            weight: 1,
        };
        let rule = PolicyRule::<Test> {
            id: rule_id(b"store-only"),
            priority: 1,
            conditions: BoundedVec::default(),
            action: PolicyActionV2::DeliveryPlanV1(DeliveryPlanV1 {
                entry_step: rule_id(b"store"),
                steps: vec![DeliveryStep {
                    id: rule_id(b"store"),
                    operation: DeliveryStepOperation::Store {
                        targets: vec![cache_target].try_into().unwrap(),
                        desired_replicas: 1,
                        required_replicas: 1,
                        selection: CacheSelection::Priority,
                    },
                }]
                .try_into()
                .unwrap(),
                transitions: BoundedVec::default(),
            }),
            constraint_overrides: None,
        };
        let scope = PolicyScopeV2::Did(did(b"did:alice"));

        assert_ok!(DeliveryPolicy::set_did_policy_v2(
            RuntimeOrigin::signed(1),
            b"did:alice".to_vec(),
            policy_v2(scope, b"did:alice", 1, vec![rule]),
        ));
    });
}

#[test]
fn delivery_plan_accepts_one_forward_step() {
    new_test_ext().execute_with(|| {
        let relay_target = RouteTarget::<Test> {
            service_did: did(b"did:relay"),
            service_id: b"relay-primary".to_vec().try_into().unwrap(),
            priority: 1,
            weight: 1,
        };
        let rule = PolicyRule::<Test> {
            id: rule_id(b"forward-only"),
            priority: 1,
            conditions: BoundedVec::default(),
            action: PolicyActionV2::DeliveryPlanV1(DeliveryPlanV1 {
                entry_step: rule_id(b"forward"),
                steps: vec![DeliveryStep {
                    id: rule_id(b"forward"),
                    operation: DeliveryStepOperation::Forward {
                        targets: vec![relay_target].try_into().unwrap(),
                    },
                }]
                .try_into()
                .unwrap(),
                transitions: BoundedVec::default(),
            }),
            constraint_overrides: None,
        };
        let scope = PolicyScopeV2::Did(did(b"did:alice"));

        assert_ok!(DeliveryPolicy::set_did_policy_v2(
            RuntimeOrigin::signed(1),
            b"did:alice".to_vec(),
            policy_v2(scope, b"did:alice", 1, vec![rule]),
        ));
    });
}

#[test]
fn delivery_target_service_check_also_requires_an_existing_active_did() {
    new_test_ext().execute_with(|| {
        let target = RouteTarget::<Test> {
            service_did: did(b"did:openpayload:missing"),
            service_id: b"#relay".to_vec().try_into().unwrap(),
            priority: 1,
            weight: 1,
        };
        let rule = PolicyRule::<Test> {
            id: rule_id(b"missing-target"),
            priority: 1,
            conditions: BoundedVec::default(),
            action: PolicyActionV2::DeliveryPlanV1(DeliveryPlanV1 {
                entry_step: rule_id(b"forward"),
                steps: vec![DeliveryStep {
                    id: rule_id(b"forward"),
                    operation: DeliveryStepOperation::Forward {
                        targets: vec![target].try_into().unwrap(),
                    },
                }]
                .try_into()
                .unwrap(),
                transitions: BoundedVec::default(),
            }),
            constraint_overrides: None,
        };
        let scope = PolicyScopeV2::Did(did(b"did:alice"));

        assert_noop!(
            DeliveryPolicy::set_did_policy_v2(
                RuntimeOrigin::signed(1),
                b"did:alice".to_vec(),
                policy_v2(scope, b"did:alice", 1, vec![rule]),
            ),
            Error::<Test>::InvalidRouteTarget
        );
    });
}

#[test]
fn aggregate_policy_complexity_bounds_nested_rules_steps_and_targets() {
    new_test_ext().execute_with(|| {
        let mut rules = Vec::new();
        for rule_index in 0..8u8 {
            let mut steps = Vec::new();
            for step_index in 0..32u8 {
                let mut targets = Vec::new();
                for target_index in 0..16u8 {
                    targets.push(RouteTarget::<Test> {
                        service_did: did(b"did:service"),
                        service_id: format!("#cache-{target_index}")
                            .into_bytes()
                            .try_into()
                            .unwrap(),
                        priority: u16::from(target_index),
                        weight: 1,
                    });
                }
                steps.push(DeliveryStep::<Test> {
                    id: rule_id(format!("step-{step_index}").as_bytes()),
                    operation: DeliveryStepOperation::Archive {
                        targets: targets.try_into().unwrap(),
                    },
                });
            }
            rules.push(PolicyRule::<Test> {
                id: rule_id(format!("rule-{rule_index}").as_bytes()),
                priority: u32::from(rule_index),
                conditions: BoundedVec::default(),
                action: PolicyActionV2::DeliveryPlanV1(DeliveryPlanV1 {
                    entry_step: rule_id(b"step-0"),
                    steps: steps.try_into().unwrap(),
                    transitions: BoundedVec::default(),
                }),
                constraint_overrides: None,
            });
        }
        let scope = PolicyScopeV2::Did(did(b"did:alice"));

        assert_noop!(
            DeliveryPolicy::set_did_policy_v2(
                RuntimeOrigin::signed(1),
                b"did:alice".to_vec(),
                policy_v2(scope, b"did:alice", 1, rules),
            ),
            Error::<Test>::PolicyTooComplex
        );
    });
}

#[test]
fn delivery_plan_rejects_two_forward_steps() {
    new_test_ext().execute_with(|| {
        let relay_target = RouteTarget::<Test> {
            service_did: did(b"did:relay"),
            service_id: b"relay-primary".to_vec().try_into().unwrap(),
            priority: 1,
            weight: 1,
        };
        let steps = vec![
            DeliveryStep::<Test> {
                id: rule_id(b"first-forward"),
                operation: DeliveryStepOperation::Forward {
                    targets: vec![relay_target.clone()].try_into().unwrap(),
                },
            },
            DeliveryStep::<Test> {
                id: rule_id(b"second-forward"),
                operation: DeliveryStepOperation::Forward {
                    targets: vec![relay_target].try_into().unwrap(),
                },
            },
        ]
        .try_into()
        .unwrap();
        let transitions = vec![crate::DeliveryTransition::<Test> {
            from: rule_id(b"first-forward"),
            to: rule_id(b"second-forward"),
            trigger: TransitionTrigger::Success,
            mode: TransitionMode::Next,
        }]
        .try_into()
        .unwrap();
        let rule = PolicyRule::<Test> {
            id: rule_id(b"two-forwards"),
            priority: 1,
            conditions: BoundedVec::default(),
            action: PolicyActionV2::DeliveryPlanV1(DeliveryPlanV1 {
                entry_step: rule_id(b"first-forward"),
                steps,
                transitions,
            }),
            constraint_overrides: None,
        };
        let scope = PolicyScopeV2::Did(did(b"did:alice"));

        assert_noop!(
            DeliveryPolicy::set_did_policy_v2(
                RuntimeOrigin::signed(1),
                b"did:alice".to_vec(),
                policy_v2(scope, b"did:alice", 1, vec![rule]),
            ),
            Error::<Test>::MultipleForwardSteps
        );
    });
}

#[test]
fn delivery_plan_rejects_overlapping_next_transitions() {
    new_test_ext().execute_with(|| {
        let archive_target = RouteTarget::<Test> {
            service_did: did(b"did:archive"),
            service_id: b"archive-primary".to_vec().try_into().unwrap(),
            priority: 1,
            weight: 1,
        };
        let steps = [
            b"entry".as_slice(),
            b"success".as_slice(),
            b"fallback".as_slice(),
        ]
        .into_iter()
        .map(|id| DeliveryStep::<Test> {
            id: rule_id(id),
            operation: DeliveryStepOperation::Archive {
                targets: vec![archive_target.clone()].try_into().unwrap(),
            },
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
        let transitions = vec![
            crate::DeliveryTransition::<Test> {
                from: rule_id(b"entry"),
                to: rule_id(b"success"),
                trigger: TransitionTrigger::Success,
                mode: TransitionMode::Next,
            },
            crate::DeliveryTransition::<Test> {
                from: rule_id(b"entry"),
                to: rule_id(b"fallback"),
                trigger: TransitionTrigger::Always,
                mode: TransitionMode::Next,
            },
        ]
        .try_into()
        .unwrap();
        let rule = PolicyRule::<Test> {
            id: rule_id(b"ambiguous-next"),
            priority: 1,
            conditions: BoundedVec::default(),
            action: PolicyActionV2::DeliveryPlanV1(DeliveryPlanV1 {
                entry_step: rule_id(b"entry"),
                steps,
                transitions,
            }),
            constraint_overrides: None,
        };
        let scope = PolicyScopeV2::Did(did(b"did:alice"));

        assert_noop!(
            DeliveryPolicy::set_did_policy_v2(
                RuntimeOrigin::signed(1),
                b"did:alice".to_vec(),
                policy_v2(scope, b"did:alice", 1, vec![rule]),
            ),
            Error::<Test>::InvalidDeliveryPlan
        );
    });
}

#[test]
fn runtime_view_preserves_store_archive_and_full_u16_weights() {
    new_test_ext().execute_with(|| {
        let store_target = RouteTarget::<Test> {
            service_did: did(b"did:cache"),
            service_id: b"cache-primary".to_vec().try_into().unwrap(),
            priority: u16::MAX,
            weight: u16::MAX,
        };
        let archive_target = RouteTarget::<Test> {
            service_did: did(b"did:archive"),
            service_id: b"archive-legal".to_vec().try_into().unwrap(),
            priority: 5,
            weight: 1,
        };
        let steps = vec![
            DeliveryStep::<Test> {
                id: rule_id(b"store"),
                operation: DeliveryStepOperation::Store {
                    targets: vec![store_target].try_into().unwrap(),
                    desired_replicas: 1,
                    required_replicas: 1,
                    selection: CacheSelection::Weighted,
                },
            },
            DeliveryStep::<Test> {
                id: rule_id(b"archive"),
                operation: DeliveryStepOperation::Archive {
                    targets: vec![archive_target].try_into().unwrap(),
                },
            },
        ]
        .try_into()
        .unwrap();
        let transitions = vec![crate::DeliveryTransition::<Test> {
            from: rule_id(b"store"),
            to: rule_id(b"archive"),
            trigger: TransitionTrigger::Success,
            mode: TransitionMode::Next,
        }]
        .try_into()
        .unwrap();
        let rule = PolicyRule::<Test> {
            id: rule_id(b"delivery"),
            priority: 100,
            conditions: BoundedVec::default(),
            action: PolicyActionV2::DeliveryPlanV1(DeliveryPlanV1 {
                entry_step: rule_id(b"store"),
                steps,
                transitions,
            }),
            constraint_overrides: None,
        };
        let scope = PolicyScopeV2::Did(did(b"did:alice"));
        assert_ok!(DeliveryPolicy::set_did_policy_v2(
            RuntimeOrigin::signed(1),
            b"did:alice".to_vec(),
            policy_v2(scope, b"did:alice", 1, vec![rule]),
        ));

        let view = DeliveryPolicy::resolved_policy_view(b"did:alice".to_vec(), None, None)
            .expect("policy resolves");
        let PolicyActionView::DeliveryPlanV1 { steps, .. } = view.action else {
            panic!("expected DeliveryPlanV1")
        };
        match &steps[0].operation {
            DeliveryStepOperationView::Store {
                targets,
                selection: crate::CacheSelectionView::Weighted,
                ..
            } => {
                assert_eq!(targets[0].priority, u16::MAX);
                assert_eq!(targets[0].weight, u16::MAX);
            }
            _ => panic!("expected weighted Store"),
        }
        assert!(matches!(
            steps[1].operation,
            DeliveryStepOperationView::Archive { .. }
        ));
    });
}

#[test]
fn semantic_v3_migration_preserves_legacy_storage() {
    new_test_ext().execute_with(|| {
        StorageVersion::new(0).put::<DeliveryPolicy>();
        RecipientPolicies::<Test>::insert(did(b"did:alice"), policy(25));
        DeliveryPolicy::on_runtime_upgrade();
        assert_eq!(
            DeliveryPolicy::on_chain_storage_version(),
            StorageVersion::new(5)
        );
        assert_eq!(
            RecipientPolicies::<Test>::get(did(b"did:alice"))
                .unwrap()
                .effective_ttl,
            25
        );
        assert!(DidPoliciesV2::<Test>::get(did(b"did:alice")).is_none());
        assert!(PersonaPoliciesV2::<Test>::iter().next().is_none());
    });
}

#[test]
fn v4_migration_adds_policy_lookup_ttl_to_existing_v2_record() {
    new_test_ext().execute_with(|| {
        StorageVersion::new(3).put::<DeliveryPolicy>();
        let alice = did(b"did:alice");
        let policy = policy_v2(
            PolicyScopeV2::Did(alice.clone()),
            b"did:alice",
            1,
            vec![base_rule(b"default", 1, Vec::new())],
        );
        let mut old_encoded = policy.encode();
        old_encoded.truncate(old_encoded.len() - 4);
        sp_io::storage::set(&DidPoliciesV2::<Test>::hashed_key_for(&alice), &old_encoded);

        DeliveryPolicy::on_runtime_upgrade();

        let migrated = DidPoliciesV2::<Test>::get(&alice).expect("policy migrated");
        assert_eq!(migrated.policy_ttl_seconds, 60);
        assert_eq!(migrated.revision, 1);
        assert!(DeliveryPolicy::resolve_policy_v2(b"did:alice", None, None).is_some());
    });
}

#[test]
fn removing_did_state_clears_all_did_keyed_policies_constraints_and_nonces() {
    new_test_ext().execute_with(|| {
        let raw_did = b"did:alice";
        let did = did(raw_did);
        RecipientPolicies::<Test>::insert(&did, policy(25));
        TagPolicies::<Test>::insert(&did, policy(20));
        PersonaPolicies::<Test>::insert(&did, policy(15));
        PolicyNonces::<Test>::insert(&did, 1);
        DidDeliveryConstraints::<Test>::insert(
            &did,
            crate::DeliveryConstraints {
                requested_cache_seconds: 3_600,
                effective_ttl_seconds: 3_600,
                max_http_envelope_bytes: 1_024,
                max_unchunked_message_bytes: 1_024,
                max_chunk_bytes: 512,
                max_message_bytes: u32::MAX,
                max_chunks: u16::MAX,
                max_replicas: 2,
            },
        );
        PersonaOperatorNonces::<Test>::insert(&did, 2);
        DidPoliciesV2::<Test>::insert(
            &did,
            policy_v2(
                PolicyScopeV2::Did(did.clone()),
                raw_did,
                1,
                vec![base_rule(b"default", 1, Vec::new())],
            ),
        );
        PolicyV2Nonces::<Test>::insert(&did, 3);

        DeliveryPolicy::remove_did_state(raw_did);

        assert!(!RecipientPolicies::<Test>::contains_key(&did));
        assert!(!TagPolicies::<Test>::contains_key(&did));
        assert!(!PersonaPolicies::<Test>::contains_key(&did));
        assert!(!PolicyNonces::<Test>::contains_key(&did));
        assert!(!DidDeliveryConstraints::<Test>::contains_key(&did));
        assert!(!PersonaOperatorNonces::<Test>::contains_key(&did));
        assert!(!DidPoliciesV2::<Test>::contains_key(&did));
        assert!(!PolicyV2Nonces::<Test>::contains_key(&did));
    });
}

#[test]
fn semantic_v3_resolution_normalizes_preupgrade_aggregate_fields() {
    new_test_ext().execute_with(|| {
        StorageVersion::new(2).put::<DeliveryPolicy>();
        DidDeliveryConstraints::<Test>::insert(
            did(b"did:alice"),
            crate::DeliveryConstraints {
                requested_cache_seconds: 86_400,
                effective_ttl_seconds: 86_400,
                max_http_envelope_bytes: 26_214_400,
                max_unchunked_message_bytes: 16_777_216,
                max_chunk_bytes: 2_097_152,
                max_message_bytes: 67_108_864,
                max_chunks: 32,
                max_replicas: 4,
            },
        );
        let scope = PolicyScopeV2::Did(did(b"did:alice"));
        DidPoliciesV2::<Test>::insert(
            did(b"did:alice"),
            policy_v2(
                scope,
                b"did:alice",
                1,
                vec![base_rule(b"default", 1, Vec::new())],
            ),
        );

        DeliveryPolicy::on_runtime_upgrade();
        let resolved = DeliveryPolicy::resolve_policy_v2(b"did:alice", None, None).unwrap();

        assert_eq!(resolved.effective_constraints.max_message_bytes, u32::MAX);
        assert_eq!(resolved.effective_constraints.max_chunks, u16::MAX);
        assert_eq!(
            DeliveryPolicy::on_chain_storage_version(),
            StorageVersion::new(5)
        );
    });
}

#[cfg(feature = "try-runtime")]
#[test]
fn semantic_v3_try_runtime_guard_checks_version_and_all_pallet_storage() {
    new_test_ext().execute_with(|| {
        StorageVersion::new(0).put::<DeliveryPolicy>();
        RecipientPolicies::<Test>::insert(did(b"did:alice"), policy(25));
        PolicyNonces::<Test>::insert(did(b"did:alice"), 7);

        let state = DeliveryPolicy::pre_upgrade().expect("supported pre-upgrade state");
        DeliveryPolicy::on_runtime_upgrade();
        DeliveryPolicy::post_upgrade(state).expect("semantic migration preserves pallet storage");

        let state = DeliveryPolicy::pre_upgrade().expect("current storage version is supported");
        PolicyV2Nonces::<Test>::insert(did(b"did:alice"), 1);
        assert!(DeliveryPolicy::post_upgrade(state).is_err());

        StorageVersion::new(5).put::<DeliveryPolicy>();
        assert!(DeliveryPolicy::pre_upgrade().is_err());
    });
}

#[test]
fn legacy_and_v2_call_indices_are_stable() {
    let legacy = crate::Call::<Test>::set_delivery_policy {
        did: b"did:alice".to_vec(),
        policy: policy(25),
    };
    let constraints = crate::Call::<Test>::set_did_delivery_constraints {
        did: b"did:alice".to_vec(),
        constraints: requested_constraints(3_600),
    };
    let persona_proof = crate::Call::<Test>::apply_persona_with_proof {
        signed_payload: Vec::new(),
        signature: Vec::new(),
        signer_key_id: Vec::new(),
    };
    let attestor = crate::Call::<Test>::set_persona_attestor {
        attestor: 99,
        approved: true,
    };
    assert_eq!(legacy.encode()[0], 0);
    assert_eq!(constraints.encode()[0], 5);
    assert_eq!(persona_proof.encode()[0], 15);
    assert_eq!(attestor.encode()[0], 16);
}
