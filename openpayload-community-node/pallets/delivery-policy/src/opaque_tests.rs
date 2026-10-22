use super::*;
use crate::mock::DeliveryPolicy;
use crate::mock::*;
use codec::Encode;
use frame_support::{
    assert_noop, assert_ok,
    traits::{Hooks, StorageVersion},
};
use sp_core::{ed25519, Pair};

fn did(value: &[u8]) -> DidOf<Test> {
    value.to_vec().try_into().unwrap()
}
fn scope() -> PolicyScopeV3<Test> {
    PolicyScopeV3::Did(did(b"did:alice"))
}
fn proof(operation: PolicyDocumentOperation<Test>) -> PolicyDocumentAuthorizationPayload<Test> {
    PolicyDocumentAuthorizationPayload {
        domain: POLICY_DOCUMENT_PROOF_DOMAIN.to_vec().try_into().unwrap(),
        genesis_hash: System::block_hash(0),
        operator_did: did(b"did:alice"),
        signer_key_id: b"did:alice#keys-1".to_vec().try_into().unwrap(),
        operation,
        nonce: PolicyV4Nonces::<Test>::get(did(b"did:alice")),
        valid_until: 60_000,
    }
}
fn set(bytes: &[u8], revision: u64) -> PolicyDocumentAuthorizationPayload<Test> {
    proof(PolicyDocumentOperation::Set {
        scope: scope(),
        revision,
        document: bytes.to_vec().try_into().unwrap(),
    })
}
fn signed(p: &PolicyDocumentAuthorizationPayload<Test>) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let bytes = p.encode();
    let sig = ed25519::Pair::from_seed(&[7; 32]).sign(&bytes).0.to_vec();
    (bytes, sig, p.signer_key_id.to_vec())
}
fn submit(p: &PolicyDocumentAuthorizationPayload<Test>) -> frame_support::dispatch::DispatchResult {
    let (bytes, sig, key) = signed(p);
    DeliveryPolicy::apply_policy_document_with_proof(RuntimeOrigin::none(), bytes, sig, key)
}

#[test]
fn raw_bytes_and_future_formats_are_opaque_and_integrity_is_exact() {
    new_test_ext().execute_with(|| {
        let bytes = b"\0\xffnot JSON: future-format:v99; Call=https://unrelated.example/";
        assert_ok!(submit(&set(bytes, 1)));
        let record = PoliciesV4::<Test>::get(scope()).unwrap();
        assert_eq!(record.document.as_slice(), bytes);
        assert_eq!(record.content_hash, sp_io::hashing::blake2_256(bytes));
        assert_eq!(record.revision, 1);
        assert_eq!(PolicyV4Nonces::<Test>::get(did(b"did:alice")), 1);
        assert!(PolicyV3Nonces::<Test>::get(did(b"did:alice")) == 0);
    });
}

#[test]
fn clear_masks_legacy_and_keeps_revision_monotonic() {
    new_test_ext().execute_with(|| {
        // Preserve arbitrary old SCALE bytes without decoding or rewriting them.
        let old_key = PoliciesV3::<Test>::hashed_key_for(scope());
        sp_io::storage::set(&old_key, b"frozen legacy fixture");
        assert_ok!(submit(&proof(PolicyDocumentOperation::Clear {
            scope: scope(),
            revision: 1
        })));
        let cleared = PoliciesV4::<Test>::get(scope()).unwrap();
        assert!(cleared.document.is_empty());
        assert_eq!(cleared.content_hash, sp_io::hashing::blake2_256(&[]));
        assert_eq!(
            sp_io::storage::get(&old_key).unwrap().as_ref(),
            b"frozen legacy fixture"
        );
        assert!(DeliveryPolicy::has_policy_document_override(
            b"did:alice",
            None
        ));
        assert_noop!(
            submit(&set(b"new bytes", 1)),
            Error::<Test>::InvalidPolicyDocumentRevision
        );
        assert_ok!(submit(&set(b"new bytes", 2)));
        assert_eq!(PoliciesV4::<Test>::get(scope()).unwrap().revision, 2);
    });
}

#[test]
fn tampering_chain_scope_owner_key_nonce_expiry_and_revision_are_rejected() {
    new_test_ext().execute_with(|| {
        let original = set(b"exact bytes", 1);
        let (bytes, sig, key) = signed(&original);
        let mut other = original.clone();
        other.operation = PolicyDocumentOperation::Set {
            scope: scope(),
            revision: 1,
            document: b"changed bytes".to_vec().try_into().unwrap(),
        };
        assert_noop!(
            DeliveryPolicy::apply_policy_document_with_proof(
                RuntimeOrigin::none(),
                other.encode(),
                sig.clone(),
                key.clone()
            ),
            Error::<Test>::InvalidSignature
        );
        other = original.clone();
        other.genesis_hash = [3; 32].into();
        assert_noop!(submit(&other), Error::<Test>::PolicyDocumentWrongChain);
        other = original.clone();
        other.operator_did = did(b"did:bob");
        assert_noop!(submit(&other), Error::<Test>::NotPolicyController);
        other = original.clone();
        other.valid_until = 0;
        assert_noop!(
            submit(&other),
            Error::<Test>::PolicyDocumentAuthorizationExpired
        );
        other = original.clone();
        other.valid_until = 600_001;
        assert_noop!(
            submit(&other),
            Error::<Test>::PolicyDocumentAuthorizationExpired
        );
        other = original.clone();
        other.nonce = 1;
        assert_noop!(submit(&other), Error::<Test>::InvalidPolicyDocumentNonce);
        let mut bad = bytes.clone();
        bad.push(0);
        assert_noop!(
            DeliveryPolicy::apply_policy_document_with_proof(
                RuntimeOrigin::none(),
                bad,
                sig.clone(),
                key.clone()
            ),
            Error::<Test>::InvalidPolicyDocumentProof
        );
        assert_noop!(
            DeliveryPolicy::apply_policy_document_with_proof(
                RuntimeOrigin::none(),
                bytes.clone(),
                sig.clone(),
                b"other".to_vec()
            ),
            Error::<Test>::InvalidPolicyDocumentProof
        );
        assert_noop!(
            DeliveryPolicy::apply_policy_document_with_proof(
                RuntimeOrigin::signed(1),
                bytes,
                sig,
                key
            ),
            sp_runtime::DispatchError::BadOrigin
        );
        assert_ok!(submit(&original));
        assert_noop!(submit(&original), Error::<Test>::InvalidPolicyDocumentNonce);
    });
}

#[test]
fn pool_deduplicates_owner_nonces_and_invalid_proofs_cannot_enter() {
    new_test_ext().execute_with(|| {
        let a = set(b"one", 1);
        let mut b = a.clone();
        b.operation = PolicyDocumentOperation::Set {
            scope: PolicyScopeV3::Application(b"talaria".to_vec().try_into().unwrap()),
            revision: 1,
            document: b"two".to_vec().try_into().unwrap(),
        };
        let (pa, sa, ka) = signed(&a);
        let (pb, sb, kb) = signed(&b);
        let va = DeliveryPolicy::authorize_policy_document(&pa, &sa, &ka)
            .unwrap()
            .0;
        let vb = DeliveryPolicy::authorize_policy_document(&pb, &sb, &kb)
            .unwrap()
            .0;
        assert_eq!(va.provides, vb.provides);
        assert!(DeliveryPolicy::authorize_policy_document(&pa, &[0; 64], &ka).is_err());
    });
}

#[test]
fn bounds_empty_sets_and_counter_exhaustion_are_atomic() {
    new_test_ext().execute_with(|| {
        assert_noop!(submit(&set(b"", 1)), Error::<Test>::EmptyPolicyDocument);
        assert!(PolicyDocumentOf::<Test>::try_from(vec![0; 65_537]).is_err());
        PolicyV4Nonces::<Test>::insert(did(b"did:alice"), u64::MAX);
        assert_noop!(
            submit(&set(b"x", 1)),
            Error::<Test>::PolicyDocumentNonceOverflow
        );
        assert!(!PoliciesV4::<Test>::contains_key(scope()));
        PolicyV4Nonces::<Test>::insert(did(b"did:alice"), 0);
        assert_ok!(submit(&set(&vec![0xff; 65_536], 1)));
        PoliciesV4::<Test>::mutate(scope(), |p| p.as_mut().unwrap().revision = u64::MAX);
        assert_noop!(
            submit(&set(b"x", u64::MAX)),
            Error::<Test>::PolicyDocumentRevisionOverflow
        );
    });
}

#[test]
fn application_and_persona_authority_is_derived_from_current_registry_state() {
    new_test_ext().execute_with(|| {
        let mut app = set(b"opaque application", 1);
        app.operation = PolicyDocumentOperation::Set {
            scope: PolicyScopeV3::Application(b"talaria".to_vec().try_into().unwrap()),
            revision: 1,
            document: b"opaque application".to_vec().try_into().unwrap(),
        };
        assert_ok!(submit(&app));
        let name: PersonaOf<Test> = b"example.com".to_vec().try_into().unwrap();
        Personas::<Test>::insert(
            &name,
            PersonaRecord::<Test> {
                operator_did: did(b"did:alice"),
                controller_key_ids: vec![b"other".to_vec().try_into().unwrap()]
                    .try_into()
                    .unwrap(),
                controller_threshold: 1,
                delivery_constraints: None,
                dns_proof_hash: [0; 32],
                verified_at: 0,
                verification_expires_at: 100_000,
                revision: 1,
                active: true,
            },
        );
        let mut p = proof(PolicyDocumentOperation::Set {
            scope: PolicyScopeV3::Persona(name.clone()),
            revision: 1,
            document: b"persona".to_vec().try_into().unwrap(),
        });
        assert_noop!(submit(&p), Error::<Test>::InvalidPersonaController);
        Personas::<Test>::mutate(&name, |r| {
            r.as_mut().unwrap().controller_key_ids =
                vec![p.signer_key_id.to_vec().try_into().unwrap()]
                    .try_into()
                    .unwrap()
        });
        assert_ok!(submit(&p));
        Personas::<Test>::mutate(&name, |r| r.as_mut().unwrap().active = false);
        p.nonce += 1;
        p.operation = PolicyDocumentOperation::Clear {
            scope: PolicyScopeV3::Persona(name),
            revision: 2,
        };
        assert_noop!(submit(&p), Error::<Test>::PersonaInactive);
    });
}

#[test]
fn lifecycle_clear_retains_marker_and_owner_nonce_and_upgrade_preserves_bytes() {
    new_test_ext().execute_with(|| {
        assert_ok!(submit(&set(b"document", 1)));
        let key = PoliciesV4::<Test>::hashed_key_for(scope());
        let before = sp_io::storage::get(&key).unwrap();
        let old_key = PoliciesV3::<Test>::hashed_key_for(scope());
        sp_io::storage::set(&old_key, b"frozen typed bytes");
        StorageVersion::new(7).put::<DeliveryPolicy>();
        #[cfg(feature = "try-runtime")]
        let migration = DeliveryPolicy::pre_upgrade().unwrap();
        DeliveryPolicy::on_runtime_upgrade();
        #[cfg(feature = "try-runtime")]
        DeliveryPolicy::post_upgrade(migration).unwrap();
        assert_eq!(sp_io::storage::get(&key).unwrap(), before);
        assert_eq!(
            sp_io::storage::get(&old_key).unwrap().as_ref(),
            b"frozen typed bytes"
        );
        DeliveryPolicy::remove_did_state(b"did:alice");
        let record = PoliciesV4::<Test>::get(scope()).unwrap();
        assert!(record.document.is_empty());
        assert_eq!(record.revision, 2);
        assert_eq!(PolicyV4Nonces::<Test>::get(did(b"did:alice")), 1);
    });
}

#[test]
#[should_panic(expected = "OpaquePolicyRequiresOffchainResolution")]
fn old_typed_resolver_fails_closed_even_for_an_explicit_clear() {
    new_test_ext().execute_with(|| {
        assert_ok!(submit(&proof(PolicyDocumentOperation::Clear {
            scope: scope(),
            revision: 1
        })));
        let _ = DeliveryPolicy::resolved_policy_view(b"did:alice".to_vec(), None, None);
    });
}

#[test]
fn legacy_write_calls_are_retired_and_not_admitted_to_the_pool() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            DeliveryPolicy::clear_delivery_policy(RuntimeOrigin::signed(1), b"did:alice".to_vec()),
            Error::<Test>::LegacyPolicyWriteDisabled
        );
        assert_noop!(
            DeliveryPolicy::clear_did_policy_v2(RuntimeOrigin::signed(1), b"did:alice".to_vec()),
            Error::<Test>::LegacyPolicyWriteDisabled
        );
        let typed = crate::DeliveryPolicyV2::<Test> {
            policy_id: vec![0; 32].try_into().unwrap(),
            scope: PolicyScopeV2::Did(did(b"did:alice")),
            revision: 1,
            operator_did: did(b"did:alice"),
            ruleset: Default::default(),
            policy_ttl_seconds: 60,
        };
        assert_noop!(
            DeliveryPolicy::set_did_policy_v2(
                RuntimeOrigin::signed(1),
                b"did:alice".to_vec(),
                typed.clone()
            ),
            Error::<Test>::LegacyPolicyWriteDisabled
        );
        assert_noop!(
            DeliveryPolicy::set_persona_policy_v2(
                RuntimeOrigin::signed(1),
                b"example.com".to_vec(),
                typed
            ),
            Error::<Test>::LegacyPolicyWriteDisabled
        );
        assert_noop!(
            DeliveryPolicy::clear_persona_policy_v2(
                RuntimeOrigin::signed(1),
                b"example.com".to_vec()
            ),
            Error::<Test>::LegacyPolicyWriteDisabled
        );
        let legacy = crate::DeliveryPolicy::<Test> {
            effective_ttl: 1,
            max_message_bytes: 1,
            cache_eligible: false,
            replication: None,
            encrypted_header_preview_bytes: None,
            release_pricing: None,
            expiration_behavior: None,
        };
        assert_noop!(
            DeliveryPolicy::set_tag_policy(
                RuntimeOrigin::signed(1),
                b"did:alice".to_vec(),
                legacy.clone()
            ),
            Error::<Test>::LegacyPolicyWriteDisabled
        );
        assert_noop!(
            DeliveryPolicy::set_delivery_policy(
                RuntimeOrigin::signed(1),
                b"did:alice".to_vec(),
                legacy.clone()
            ),
            Error::<Test>::LegacyPolicyDeprecated
        );
        assert_noop!(
            DeliveryPolicy::set_persona_policy(
                RuntimeOrigin::signed(1),
                b"did:alice".to_vec(),
                legacy
            ),
            Error::<Test>::LegacyPolicyDeprecated
        );
        assert_eq!(
            Call::<Test>::apply_policy_document_with_proof {
                signed_payload: vec![],
                signature: vec![],
                signer_key_id: vec![]
            }
            .encode()[0],
            22
        );
        for call in [
            Call::<Test>::apply_policy_with_proof {
                signed_payload: vec![],
                signature: vec![],
                signer_key_id: vec![],
            },
            Call::<Test>::apply_policy_v2_with_proof {
                signed_payload: vec![],
                signature: vec![],
                signer_key_id: vec![],
            },
            Call::<Test>::apply_policy_v3_with_proof {
                signed_payload: vec![],
                signature: vec![],
                signer_key_id: vec![],
            },
        ] {
            assert!(DeliveryPolicy::validate_unsigned_call(&call).is_err());
        }
    });
}

#[test]
fn independent_java_wire_fixture_matches_set_clear_and_stored_record() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/policy-document-v4-wire.json")).unwrap();
    let string = |name: &str| fixture[name].as_str().unwrap().as_bytes().to_vec();
    let hex = |name: &str| {
        let text = fixture[name].as_str().unwrap().strip_prefix("0x").unwrap();
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect::<Vec<u8>>()
    };
    let document: PolicyDocumentOf<Test> = hex("document_hex").try_into().unwrap();
    let owner: DidOf<Test> = string("owner").try_into().unwrap();
    let app = PolicyScopeV3::Application(string("application_id").try_into().unwrap());
    let mut payload = PolicyDocumentAuthorizationPayload::<Test> {
        domain: POLICY_DOCUMENT_PROOF_DOMAIN.to_vec().try_into().unwrap(),
        genesis_hash: [0x11; 32].into(),
        operator_did: owner.clone(),
        signer_key_id: string("signer_key_id").try_into().unwrap(),
        operation: PolicyDocumentOperation::Set {
            scope: app.clone(),
            revision: 1,
            document: document.clone(),
        },
        nonce: 7,
        valid_until: 1_800_000_000_000,
    };
    assert_eq!(payload.encode(), hex("set_payload_hex"));
    let encoded_scope = app.encode();
    let mut expected_key = sp_io::hashing::twox_128(b"DeliveryPolicy").to_vec();
    expected_key.extend_from_slice(&sp_io::hashing::twox_128(b"PoliciesV4"));
    expected_key.extend_from_slice(&sp_io::hashing::blake2_128(&encoded_scope));
    expected_key.extend_from_slice(&encoded_scope);
    assert_eq!(PoliciesV4::<Test>::hashed_key_for(&app), expected_key);

    payload.operation = PolicyDocumentOperation::Clear {
        scope: app,
        revision: 1,
    };
    assert_eq!(payload.encode(), hex("clear_payload_hex"));
    let record = PolicyDocumentRecord::<Test> {
        revision: 1,
        operator_did: owner,
        content_hash: sp_io::hashing::blake2_256(&document),
        document,
    };
    assert_eq!(record.content_hash.as_slice(), hex("content_hash"));
    assert_eq!(record.encode(), hex("stored_record_hex"));
}
