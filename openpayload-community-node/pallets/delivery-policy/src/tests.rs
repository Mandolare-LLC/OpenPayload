// Typed-policy mutation tests below exercise cfg(test) frozen fixtures. Production
// entry points are retired; opaque_tests verifies their rejection and the new path.
use crate::{
    mock::*, CacheSelection, DeliveryConstraintOverrides, DeliveryPlanV1,
    DeliveryPolicy as DeliveryPolicyData, DeliveryPolicyV2, DeliveryStep, DeliveryStepOperation,
    DeliveryStepOperationView, DidDeliveryConstraints, DidOf, DidPoliciesV2, Error,
    ExpirationBehavior, PersonaAuthorizationPayload, PersonaOf,
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
                url: b"https://api.push.example.com/v1/calls".to_vec().try_into().unwrap(),
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
            DeliveryPolicy::legacy_fixture_apply_policy_v3_with_proof(
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
            DeliveryPolicy::legacy_fixture_apply_policy_v3_with_proof(
                RuntimeOrigin::none(),
                proof.clone(),
                proof.clone(),
                b"did:alice#keys-1".to_vec()
            ),
            Error::<Test>::InvalidCallDomain
        );
        Personas::<Test>::insert(&domain, make_registration(b"did:alice"));
        for url in [b"https://evilpush.example.com/v1/calls".as_slice(),
            b"https://push.example.com.evil.chat/v1/calls", b"http://push.example.com/v1/calls"] {
            let mut invalid = policy.clone();
            if let PolicyActionV2::DeliveryPlanV1(plan) = &mut invalid.ruleset[0].action {
                if let DeliveryStepOperation::Call { url: target, .. } = &mut plan.steps[0].operation {
                    *target = url.to_vec().try_into().unwrap();
                }
            }
            let invalid_proof = crate::PolicyV3AuthorizationPayload::<Test> {
                operator_did: did(b"did:alice"), operation: crate::PolicyV3Operation::SetPolicy(invalid),
                nonce: 0, valid_until: 5_000, signer_key_id: b"did:alice#keys-1".to_vec().try_into().unwrap(),
            }.encode();
            assert_noop!(DeliveryPolicy::legacy_fixture_apply_policy_v3_with_proof(RuntimeOrigin::none(),
                invalid_proof.clone(), invalid_proof, b"did:alice#keys-1".to_vec()), Error::<Test>::InvalidCallDomain);
        }
        assert_ok!(DeliveryPolicy::legacy_fixture_apply_policy_v3_with_proof(
            RuntimeOrigin::none(),
            proof.clone(),
            proof,
            b"did:alice#keys-1".to_vec()
        ));
        assert_eq!(crate::PoliciesV3::<Test>::iter_keys().count(), 1);
    });
}

#[test]
fn call_variant_four_encodes_only_url_and_payload() {
    let operation = DeliveryStepOperation::<Test>::Call {
        url: b"https://api.talaria.chat/v1/calls".to_vec().try_into().unwrap(),
        payload_template: b"{}".to_vec().try_into().unwrap(),
    };
    let mut expected = vec![4, 132]; // variant 4, compact length 33
    expected.extend_from_slice(b"https://api.talaria.chat/v1/calls");
    expected.extend_from_slice(&[8, b'{', b'}']);
    assert_eq!(operation.encode(), expected);
}

#[cfg(feature = "try-runtime")]
#[test]
fn url_call_upgrade_precheck_rejects_nonempty_policy_maps_without_decoding_values() {
    for item in 0..3 {
        new_test_ext().execute_with(|| {
            StorageVersion::new(6).put::<DeliveryPolicy>();
            assert!(DeliveryPolicy::pre_upgrade().is_ok());
            let key = match item {
                0 => DidPoliciesV2::<Test>::hashed_key_for(did(b"did:alice")),
                1 => PersonaPoliciesV2::<Test>::hashed_key_for(persona(b"example.com")),
                _ => crate::PoliciesV3::<Test>::hashed_key_for(crate::PolicyScopeV3::<Test>::Application(
                    b"talaria".to_vec().try_into().unwrap())),
            };
            sp_io::storage::set(&key, b"old policy encoding");
            assert!(DeliveryPolicy::pre_upgrade().is_err());
        });
    }
}
use codec::Encode;
use frame_support::{
    assert_noop, assert_ok,
    traits::{GetStorageVersion, Hooks, StorageVersion},
    BoundedVec,
};
use sp_runtime::traits::Hash;

fn dnssec_key(zone: &str, seed: u8) -> (p256::ecdsa::SigningKey, dnssec_prover::rr::DnsKey) {
    let signer = p256::ecdsa::SigningKey::from_bytes((&[seed; 32]).into()).unwrap();
    let public = signer.verifying_key().to_encoded_point(false);
    let key = dnssec_prover::rr::DnsKey { name: zone.try_into().unwrap(), flags: 257,
        protocol: 3, alg: 13, pubkey: public.as_bytes()[1..].to_vec() };
    (signer, key)
}

fn dnssec_ds(key: &dnssec_prover::rr::DnsKey) -> dnssec_prover::rr::DS {
    use dnssec_prover::rr::Record;
    let mut rdata = Vec::new(); key.write_u16_len_prefixed_data(&mut rdata);
    let mut material = Vec::new(); dnssec_prover::ser::write_rr(key, 300, &mut material);
    let name_len = material.len() - rdata.len() - 8;
    let mut input = material[..name_len].to_vec(); input.extend_from_slice(&rdata[2..]);
    dnssec_prover::rr::DS { name: key.name.clone(), key_tag: key.key_tag(), alg: 13,
        digest_type: 2, digest: sp_io::hashing::sha2_256(&input).to_vec() }
}

fn dnssec_sign<R: dnssec_prover::rr::Record>(record: &R, key: &dnssec_prover::rr::DnsKey,
    signer: &p256::ecdsa::SigningKey, inception: u32, expiration: u32) -> dnssec_prover::rr::RRSig {
    use dnssec_prover::rr::Record;
    use p256::ecdsa::signature::Signer;
    let mut sig = dnssec_prover::rr::RRSig { name: record.name().clone(), ty: record.ty(),
        alg: 13, labels: record.name().as_str().split('.').filter(|part| !part.is_empty()).count() as u8,
        orig_ttl: 300, expiration, inception, key_tag: key.key_tag(), key_name: key.name.clone(), signature: Vec::new() };
    let mut header = Vec::new(); sig.write_u16_len_prefixed_data(&mut header);
    let mut input = header[2..].to_vec(); dnssec_prover::ser::write_rr(record, 300, &mut input);
    let signature: p256::ecdsa::Signature = signer.sign(&input);
    sig.signature = signature.to_bytes().to_vec(); sig
}

fn install_test_dnssec_root() {
    let (_, root) = dnssec_key(".", 42);
    let ds = dnssec_ds(&root);
    assert_ok!(DeliveryPolicy::set_dnssec_root_trust_anchor(RuntimeOrigin::root(), ds.key_tag,
        crate::DnssecRootTrustAnchor { algorithm: 13, digest: ds.digest.try_into().unwrap(), valid_from: 0, valid_until: 0 }));
}

#[test]
fn dnssec_preflight_rejects_unsigned_forged_expired_and_untrusted_records() {
    new_test_ext().execute_with(|| {
        Timestamp::set_timestamp(1_700_000_100_000);
        let name = "_openpayload-persona.example.com.";
        let value = b"a request-bound challenge";
        let proof = signed_dnssec_txt(name, value, 1_700_000_001, 1_700_001_000);
        assert_eq!(DeliveryPolicy::verify_dnssec_txt(name.as_bytes().to_vec(), value.to_vec(), proof.clone()), None);
        install_test_dnssec_root();
        let (_, root) = dnssec_key(".", 42);
        let records = dnssec_prover::ser::parse_rr_stream(&proof).unwrap();
        let checked = dnssec_prover::validation::verify_rr_stream_with_trust_anchors(&records, &[dnssec_ds(&root)]);
        assert!(checked.is_ok(), "upstream proof check: {checked:?}");
        assert_eq!(DeliveryPolicy::verify_dnssec_txt(name.as_bytes().to_vec(), value.to_vec(), proof.clone()), Some(1_700_001_000_000));
        assert_eq!(DeliveryPolicy::verify_dnssec_txt(name.as_bytes().to_vec(), b"forged".to_vec(), proof.clone()), None);
        let mut corrupted = proof.clone(); let last = corrupted.len() - 1; corrupted[last] ^= 1;
        assert_eq!(DeliveryPolicy::verify_dnssec_txt(name.as_bytes().to_vec(), value.to_vec(), corrupted), None);
        assert_eq!(DeliveryPolicy::verify_dnssec_txt(name.as_bytes().to_vec(), value.to_vec(), vec![0; 65537]), None);
        Timestamp::set_timestamp(1_700_001_000_000);
        assert_eq!(DeliveryPolicy::verify_dnssec_txt(name.as_bytes().to_vec(), value.to_vec(), proof), None);
    });
}

#[test]
fn dnssec_root_management_requires_governance_and_honors_activation_retirement() {
    new_test_ext().execute_with(|| {
        let (_, root) = dnssec_key(".", 42); let ds = dnssec_ds(&root);
        let anchor = crate::DnssecRootTrustAnchor { algorithm: 13, digest: ds.digest.try_into().unwrap(), valid_from: 1_700_000_010_000, valid_until: 1_700_000_020_000 };
        assert!(DeliveryPolicy::set_dnssec_root_trust_anchor(RuntimeOrigin::signed(1), ds.key_tag, anchor.clone()).is_err());
        assert_ok!(DeliveryPolicy::set_dnssec_root_trust_anchor(RuntimeOrigin::root(), ds.key_tag, anchor));
        let name = "_openpayload-persona.example.com."; let value = b"challenge";
        let proof = signed_dnssec_txt(name, value, 1_700_000_000, 2_000_000_000);
        let verify = || DeliveryPolicy::verify_dnssec_txt(name.as_bytes().to_vec(), value.to_vec(), proof.clone());
        Timestamp::set_timestamp(1_700_000_009_999); assert_eq!(verify(), None);
        Timestamp::set_timestamp(1_700_000_010_000); assert_eq!(verify(), Some(1_700_000_000_000 + 48 * 3_600_000));
        Timestamp::set_timestamp(1_700_000_020_000); assert_eq!(verify(), None);
        assert_noop!(DeliveryPolicy::set_persona_attestor(RuntimeOrigin::root(), 99, true), Error::<Test>::DnssecRequired);
        assert_ok!(DeliveryPolicy::remove_dnssec_root_trust_anchor(RuntimeOrigin::root(), ds.key_tag));
        assert!(crate::DnssecRootTrustAnchors::<Test>::iter_keys().next().is_none());
    });
}

#[test]
fn dnssec_persona_registration_and_renewal_bind_did_action_nonce_and_genesis() {
    new_test_ext().execute_with(|| {
        Timestamp::set_timestamp(1_700_000_010_000); install_test_dnssec_root();
        let name = persona(b"example.com"); let owner = did(b"did:alice");
        let expiry = 1_700_001_000_000;
        let (hash, proof) = dnssec_evidence(&name, &owner, b"register_persona", 0, expiry, &[0; 32]);
        let register = |proof_hash, evidence| DeliveryPolicy::register_persona(RuntimeOrigin::signed(1),
            name.to_vec(), owner.to_vec(), vec![b"did:alice#root".to_vec()], 1, None,
            proof_hash, 0, 1_700_002_000_000, expiry, evidence);
        assert_noop!(register([1; 32], proof.clone()), Error::<Test>::InvalidDnssecProof);
        let (_, wrong_action) = dnssec_evidence(&name, &owner, b"renew_persona", 0, expiry, &[0; 32]);
        assert_noop!(register(hash, wrong_action), Error::<Test>::InvalidDnssecProof);
        let (_, other_did) = dnssec_evidence(&name, &did(b"did:bob"), b"register_persona", 0, expiry, &[0; 32]);
        assert_noop!(register(hash, other_did), Error::<Test>::InvalidDnssecProof);
        assert_ok!(register(hash, proof.clone()));
        assert_noop!(register(hash, proof.clone()), Error::<Test>::PersonaAlreadyExists);
        assert_noop!(DeliveryPolicy::renew_persona(RuntimeOrigin::signed(1), name.to_vec(), None,
            hash, 0, 1_700_002_000_000, expiry, proof), Error::<Test>::InvalidPersonaNonce);
        let (hash, proof) = dnssec_evidence(&name, &owner, b"renew_persona", 1, expiry, &[0; 32]);
        assert_ok!(DeliveryPolicy::renew_persona(RuntimeOrigin::signed(1), name.to_vec(), None,
            hash, 1, 1_700_002_000_000, expiry, proof));
        assert_eq!(crate::PersonaNonces::<Test>::get(&name), 2);
    });
}

fn recovery_dnssec_proof(name: &PersonaOf<Test>, id: [u8; 32]) -> crate::PersonaRecoveryProof {
    let expires = Timestamp::get() + 48 * 3_600_000;
    let nonce = crate::PersonaNonces::<Test>::get(name);
    let (hash, proof) = dnssec_evidence(name, &did(b"did:bob"), b"recover_persona", nonce, expires, &id);
    crate::PersonaRecoveryProof { factors: 1, proof_hash: hash, proof_valid_until: expires,
        verification_expires_at: Timestamp::get() + 365 * 86_400_000, challenge_nonce: nonce,
        challenge_expires_at: expires, dnssec_proof: proof }
}

#[test]
fn dnssec_recovery_requires_delay_fresh_proof_and_preserves_or_clears_policy() {
    for preserve in [true, false] {
        new_test_ext().execute_with(|| {
            Timestamp::set_timestamp(1_700_000_010_000); install_test_dnssec_root();
            let name = recovery_registration(); let id = [7; 32];
            let policy = policy_v2(PolicyScopeV2::Persona(name.clone()), b"did:alice", 4,
                vec![base_rule(b"preserve-rule", 1, Vec::new())]);
            PersonaPoliciesV2::<Test>::insert(&name, policy.clone());
            let scope = crate::PolicyScopeV3::Persona(name.clone());
            let mut id_material = b"openpayload:delivery-policy:v3:".to_vec(); id_material.extend_from_slice(&scope.encode());
            let graph = crate::DeliveryPolicyV3::<Test> {
                policy_id: <Test as frame_system::Config>::Hashing::hash(&id_material).as_ref().to_vec().try_into().unwrap(),
                scope: scope.clone(), operator_did: did(b"did:alice"), revision: 9,
                ruleset: vec![base_rule(b"edited-v3-graph", 7, Vec::new())].try_into().unwrap(), policy_ttl_seconds: 90,
            };
            crate::PoliciesV3::<Test>::insert(&scope, graph.clone());
            let raw=crate::PolicyDocumentRecord::<Test> { revision:12,operator_did:did(b"did:alice"),content_hash:sp_io::hashing::blake2_256(b"opaque bytes"),document:b"opaque bytes".to_vec().try_into().unwrap() };
            crate::PoliciesV4::<Test>::insert(&scope,raw.clone());
            let start = |proof| PersonaOperation::StartRecovery { persona: name.clone(), recovery_id: id,
                controller_key_ids: vec![b"did:bob#root".to_vec().try_into().unwrap()].try_into().unwrap(),
                controller_threshold: 1, preserve_policy: preserve, proof };
            let mut email = recovery_dnssec_proof(&name, id); email.factors = 3;
            assert_noop!(recovery_call(b"did:bob", start(email)), Error::<Test>::InvalidRecoveryProof);
            assert_ok!(recovery_call(b"did:bob", start(recovery_dnssec_proof(&name, id))));
            // Legacy records have the same layout but no DNSSEC admission marker.
            crate::DnssecRecoveryIds::<Test>::remove(&name, id);
            assert_noop!(recovery_call(b"did:bob", PersonaOperation::ProveRecovery { persona: name.clone(),
                recovery_id: id, proof: recovery_dnssec_proof(&name, id) }), Error::<Test>::DnssecRequired);
            crate::DnssecRecoveryIds::<Test>::insert(&name, id, ());
            assert_ok!(recovery_call(b"did:alice", PersonaOperation::CancelRecovery { persona: name.clone(), recovery_id: id }));
            assert_noop!(recovery_call(b"did:bob", PersonaOperation::FinalizeRecovery { persona: name.clone(), recovery_id: id }), Error::<Test>::RecoveryNotReady);
            Timestamp::set_timestamp(1_700_000_010_000 + 7 * 86_400_000);
            assert_noop!(recovery_call(b"did:bob", PersonaOperation::FinalizeRecovery { persona: name.clone(), recovery_id: id }), Error::<Test>::RecoveryNotReady);
            assert_ok!(recovery_call(b"did:bob", PersonaOperation::ProveRecovery { persona: name.clone(), recovery_id: id, proof: recovery_dnssec_proof(&name, id) }));
            assert_ok!(recovery_call(b"did:bob", PersonaOperation::FinalizeRecovery { persona: name.clone(), recovery_id: id }));
            assert_eq!(Personas::<Test>::get(&name).unwrap().operator_did, did(b"did:bob"));
            assert!(crate::PersonaRecoveryIds::<Test>::get(&name).is_empty());
            assert!(!crate::DnssecRecoveryIds::<Test>::contains_key(&name, id));
            let current_raw=crate::PoliciesV4::<Test>::get(&scope).unwrap();
            if preserve {
                let mut expected_raw=raw;expected_raw.operator_did=did(b"did:bob");
                assert_eq!(current_raw,expected_raw);
                let mut expected = policy; expected.operator_did = did(b"did:bob");
                assert_eq!(PersonaPoliciesV2::<Test>::get(&name), Some(expected));
                let mut expected_graph = graph; expected_graph.operator_did = did(b"did:bob");
                assert_eq!(crate::PoliciesV3::<Test>::get(&scope), Some(expected_graph));
            } else {
                assert!(current_raw.document.is_empty());assert_eq!(current_raw.revision,13);
                assert_eq!(current_raw.content_hash,sp_io::hashing::blake2_256(&[]));
                assert!(PersonaPoliciesV2::<Test>::get(&name).is_none());
                assert!(crate::PoliciesV3::<Test>::get(&scope).is_none());
            }
        });
    }
}

fn signed_dnssec_txt(name: &str, value: &[u8], inception: u32, expiration: u32) -> Vec<u8> {
    let zone = name.split_once('.').unwrap().1;
    signed_dnssec_txt_in_zone(name, value, inception, expiration, zone)
}

fn signed_dnssec_txt_in_zone(name: &str, value: &[u8], inception: u32, expiration: u32, zone: &str) -> Vec<u8> {
    use dnssec_prover::rr::{Txt, RR};
    let (root_signer, root) = dnssec_key(".", 42);
    let (child_signer, child) = dnssec_key(zone, 43);
    let ds = dnssec_ds(&child);
    let txt = Txt { name: name.try_into().unwrap(), data: value.try_into().unwrap() };
    let records = vec![
        RR::RRSig(dnssec_sign(&root, &root, &root_signer, inception, expiration)), RR::DnsKey(root.clone()),
        RR::RRSig(dnssec_sign(&ds, &root, &root_signer, inception, expiration)), RR::DS(ds),
        RR::RRSig(dnssec_sign(&child, &child, &child_signer, inception, expiration)), RR::DnsKey(child.clone()),
        RR::RRSig(dnssec_sign(&txt, &child, &child_signer, inception, expiration)), RR::Txt(txt),
    ];
    let mut wire = Vec::new(); for rr in records { dnssec_prover::ser::write_rr(&rr, 300, &mut wire); }
    wire
}

fn dnssec_evidence(persona: &PersonaOf<Test>, operator: &DidOf<Test>, action: &[u8], nonce: u64,
    expires: u64, id: &[u8; 32]) -> ([u8; 32], BoundedVec<u8, frame_support::traits::ConstU32<65536>>) {
    let value = crate::dnssec::challenge_value(System::block_hash(0u64).as_ref(), persona, operator,
        action, nonce, expires, id);
    let mut name = b"_openpayload-persona.".to_vec(); name.extend_from_slice(persona);
    let mut material = name.clone(); material.push(b'\n'); material.extend_from_slice(&value);
    name.push(b'.');
    let proof = signed_dnssec_txt(core::str::from_utf8(&name).unwrap(), &value, (Timestamp::get() / 1000) as u32, 2_000_000_000);
    (sp_io::hashing::sha2_256(&material), proof.try_into().unwrap())
}

// Policy tests seed an already-confirmed Persona. DNSSEC admission is covered separately.
fn seed_persona_fixture(origin: RuntimeOrigin, raw_persona: Vec<u8>, raw_operator: Vec<u8>,
    controllers: Vec<Vec<u8>>, threshold: u8, constraints: Option<RequestedDeliveryConstraints>, expiry: u64)
    -> frame_support::dispatch::DispatchResult {
    let canonical = String::from_utf8(raw_persona).unwrap().trim_end_matches('.').to_ascii_lowercase();
    if !canonical.contains('.') { return Err(Error::<Test>::InvalidPersona.into()); }
    let name = persona(canonical.as_bytes()); let operator = did(&raw_operator);
    let record = crate::PersonaRecord::<Test> { operator_did: operator,
        controller_key_ids: controllers.into_iter().map(|key| key.try_into().unwrap()).collect::<Vec<_>>().try_into().unwrap(),
        controller_threshold: threshold, delivery_constraints: None, dns_proof_hash: [0; 32],
        verified_at: Timestamp::get(), verification_expires_at: expiry, revision: 1, active: true };
    Personas::<Test>::insert(&name, record);
    if let Some(constraints) = constraints {
        DeliveryPolicy::set_persona_delivery_constraints(origin, name.to_vec(), constraints)?;
        Personas::<Test>::mutate(&name, |record| record.as_mut().unwrap().revision = 1);
    }
    Ok(())
}

#[test]
fn named_persona_is_active_without_dns_and_cannot_claim_a_domain() {
    new_test_ext().execute_with(|| {
        let name = b"compliance".to_vec();
        assert_ok!(DeliveryPolicy::register_named_persona(
            RuntimeOrigin::signed(1), name.clone(), b"did:alice".to_vec(),
            vec![b"did:alice#keys-1".to_vec()], 1, None));
        let key = persona(&name);
        assert!(crate::NonDnsPersonas::<Test>::contains_key(&key));
        assert!(Personas::<Test>::get(&key).unwrap().active);
        assert_noop!(DeliveryPolicy::register_named_persona(
            RuntimeOrigin::signed(1), b"example.com".to_vec(), b"did:alice".to_vec(),
            vec![b"did:alice#keys-1".to_vec()], 1, None),
            Error::<Test>::InvalidPersona);
        assert_noop!(seed_persona_fixture(RuntimeOrigin::signed(1),
            b"compliance".to_vec(),
            b"did:alice".to_vec(),
            vec![b"did:alice#keys-1".to_vec()],
            1,
            None,
            10_000),
            Error::<Test>::InvalidPersona);
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
                controller_key_ids: vec![signer.clone().try_into().unwrap()]
                    .try_into().unwrap(),
                controller_threshold: 1,
                constraints: None,
            },
            nonce: 0,
            valid_until: 5_000,
            signer_key_id: signer.clone().try_into().unwrap(),
        }.encode();
        assert_ok!(DeliveryPolicy::apply_persona_with_proof(
            RuntimeOrigin::none(), proof.clone(), proof, signer));
        assert!(crate::NonDnsPersonas::<Test>::contains_key(persona(b"compliance")));
        assert_eq!(PersonaOperatorNonces::<Test>::get(did(b"did:alice")), 1);
    });
}

#[test]
fn persona_profile_requires_a_recipient_route() {
    new_test_ext().execute_with(|| {
        assert_ok!(DeliveryPolicy::register_named_persona(
            RuntimeOrigin::signed(1), b"compliance".to_vec(), b"did:alice".to_vec(),
            vec![b"did:alice#keys-1".to_vec()], 1, None));
        let scope = crate::PolicyScopeV3::Persona(persona(b"compliance"));
        let mut id_input = b"openpayload:delivery-policy:v3:".to_vec();
        id_input.extend_from_slice(&scope.encode());
        let policy_id = <Test as frame_system::Config>::Hashing::hash(&id_input)
            .as_ref().to_vec().try_into().unwrap();
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
            policy_id, scope, revision: 1, operator_did: did(b"did:alice"),
            ruleset: vec![PolicyRule {
                id: rule_id(b"gate"), priority: 1, conditions: BoundedVec::default(),
                action: PolicyActionV2::DeliveryPlanV1(plan.clone()),
                constraint_overrides: None,
            }].try_into().unwrap(),
            policy_ttl_seconds: 60,
        };
        let authorize = |policy: crate::DeliveryPolicyV3<Test>| {
            crate::PolicyV3AuthorizationPayload::<Test> {
                operator_did: did(b"did:alice"),
                operation: crate::PolicyV3Operation::SetPolicy(policy),
                nonce: 0, valid_until: 5_000,
                signer_key_id: b"did:alice#keys-1".to_vec().try_into().unwrap(),
            }.encode()
        };
        let proof = authorize(policy.clone());
        assert_noop!(DeliveryPolicy::legacy_fixture_apply_policy_v3_with_proof(
            RuntimeOrigin::none(), proof.clone(), proof.clone(),
            b"did:alice#keys-1".to_vec()), Error::<Test>::InvalidDeliveryPlan);

        plan.steps.try_push(DeliveryStep {
            id: rule_id(b"deliver"),
            operation: DeliveryStepOperation::Forward {
                targets: vec![RouteTarget::<Test> {
                    service_did: did(b"did:relay"),
                    service_id: b"relay-primary".to_vec().try_into().unwrap(),
                    priority: 1, weight: 1,
                }].try_into().unwrap(),
            },
        }).unwrap();
        plan.transitions.try_push(crate::DeliveryTransition::<Test> {
            from: rule_id(b"profile"), to: rule_id(b"deliver"),
            trigger: TransitionTrigger::Success, mode: TransitionMode::Next,
        }).unwrap();
        policy.ruleset[0].action = PolicyActionV2::DeliveryPlanV1(plan);
        let proof = authorize(policy);
        assert_ok!(DeliveryPolicy::legacy_fixture_apply_policy_v3_with_proof(
            RuntimeOrigin::none(), proof.clone(), proof,
            b"did:alice#keys-1".to_vec()));
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
            DeliveryPolicy::legacy_fixture_set_tag_policy(
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
            DeliveryPolicy::legacy_fixture_apply_policy_with_proof(
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
        assert_ok!(DeliveryPolicy::legacy_fixture_apply_policy_with_proof(
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
        assert_ok!(DeliveryPolicy::legacy_fixture_apply_policy_with_proof(
            RuntimeOrigin::none(),
            payload.clone(),
            signature,
            signer_key_id.clone(),
        ));

        assert_noop!(
            DeliveryPolicy::legacy_fixture_apply_policy_with_proof(
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
            DeliveryPolicy::legacy_fixture_apply_policy_with_proof(
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

        assert_ok!(DeliveryPolicy::legacy_fixture_apply_policy_v2_with_proof(
            RuntimeOrigin::none(),
            authorization.clone(),
            authorization.clone(),
            signer_key_id.clone(),
        ));
        assert!(DidPoliciesV2::<Test>::contains_key(&operator));
        assert_eq!(PolicyV2Nonces::<Test>::get(&operator), 1);

        assert_noop!(
            DeliveryPolicy::legacy_fixture_apply_policy_v2_with_proof(
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
            DeliveryPolicy::legacy_fixture_set_did_policy_v2(
                RuntimeOrigin::signed(1),
                operator.to_vec(),
                policy.clone()
            ),
            Error::<Test>::InvalidPolicyTtl
        );
        policy.policy_ttl_seconds = 301;
        assert_noop!(
            DeliveryPolicy::legacy_fixture_set_did_policy_v2(
                RuntimeOrigin::signed(1),
                operator.to_vec(),
                policy.clone()
            ),
            Error::<Test>::InvalidPolicyTtl
        );
        policy.policy_ttl_seconds = 45;
        assert_ok!(DeliveryPolicy::legacy_fixture_set_did_policy_v2(
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
        assert_ok!(DeliveryPolicy::legacy_fixture_set_did_policy_v2(
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
fn persona_policy_proof_requires_a_registered_controller_key() {
    new_test_ext().execute_with(|| {
        Timestamp::set_timestamp(10);
        let persona_id = persona(b"controller.example");
        let operator = did(b"did:alice");
        let controller = b"did:alice#policy-1".to_vec();
        assert_ok!(seed_persona_fixture(RuntimeOrigin::signed(1),
            persona_id.to_vec(),
            operator.to_vec(),
            vec![controller.clone()],
            1,
            None,
            10_000));

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
            DeliveryPolicy::legacy_fixture_apply_policy_v2_with_proof(
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
        assert_ok!(DeliveryPolicy::legacy_fixture_apply_policy_v2_with_proof(
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
        let persona_id = persona(b"rotation.example");
        let operator = did(b"did:alice");
        let current_signer = b"did:alice#policy-1".to_vec();
        let next_signer = b"did:alice#policy-2".to_vec();
        assert_ok!(seed_persona_fixture(RuntimeOrigin::signed(1),
            persona_id.to_vec(),
            operator.to_vec(),
            vec![current_signer.clone()],
            1,
            None,
            10_000));

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
        let persona_id = persona(b"revoked-rotation.example");
        let operator = did(b"did:alice");
        let signer = b"did:alice#policy-1".to_vec();
        assert_ok!(seed_persona_fixture(RuntimeOrigin::signed(1),
            persona_id.to_vec(),
            operator.to_vec(),
            vec![signer.clone()],
            1,
            None,
            10_000));
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
        let persona_id = persona(b"revoked-constraints.example");
        let operator = did(b"did:alice");
        let signer = b"did:alice#policy-1".to_vec();
        assert_ok!(seed_persona_fixture(RuntimeOrigin::signed(1),
            persona_id.to_vec(),
            operator.to_vec(),
            vec![signer.clone()],
            1,
            None,
            10_000));
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
            DeliveryPolicy::legacy_fixture_apply_policy_v2_with_proof(
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
fn v2_resolution_uses_persona_then_did_and_tag_is_only_a_condition() {
    new_test_ext().execute_with(|| {
        Timestamp::set_timestamp(10);
        let persona_id = persona(b"example.com");
        let operator = did(b"did:alice");
        assert_ok!(seed_persona_fixture(RuntimeOrigin::signed(1),
            persona_id.to_vec(),
            operator.to_vec(),
            vec![b"did:alice#policy-1".to_vec()],
            1,
            None,
            10_000));

        let recipient = did(b"did:recipient");
        let did_scope = PolicyScopeV2::Did(recipient.clone());
        assert_ok!(DeliveryPolicy::legacy_fixture_set_did_policy_v2(
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
        assert_ok!(DeliveryPolicy::legacy_fixture_set_persona_policy_v2(
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
        let mut persona_constraints = requested_constraints(86_400);
        persona_constraints.max_chunk_bytes = 1024 * 1024;
        persona_constraints.max_message_bytes = 32 * 1024 * 1024;
        assert_ok!(seed_persona_fixture(RuntimeOrigin::signed(1),
            persona_id.to_vec(),
            operator.to_vec(),
            vec![b"did:alice#policy-1".to_vec()],
            1,
            Some(persona_constraints),
            10_000));
        let scope = PolicyScopeV2::Persona(persona_id.clone());
        assert_ok!(DeliveryPolicy::legacy_fixture_set_persona_policy_v2(
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

        let recipient = did(b"did:recipient");
        let did_scope = PolicyScopeV2::Did(recipient.clone());
        assert_ok!(DeliveryPolicy::legacy_fixture_set_did_policy_v2(
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
        let mut persona_constraints = requested_constraints(3_600);
        persona_constraints.max_replicas = 2;
        assert_ok!(seed_persona_fixture(RuntimeOrigin::signed(1),
            persona_id.to_vec(),
            operator.to_vec(),
            vec![b"did:alice#policy-1".to_vec()],
            1,
            Some(persona_constraints),
            10_000));

        let legal_tag: TagOf<Test> = b"Legal".to_vec().try_into().unwrap();
        let persona_scope = PolicyScopeV2::Persona(persona_id.clone());
        assert_ok!(DeliveryPolicy::legacy_fixture_set_persona_policy_v2(
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
        assert_ok!(DeliveryPolicy::legacy_fixture_set_did_policy_v2(
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
        let mut persona_constraints = requested_constraints(86_400);
        persona_constraints.max_replicas = 4;
        assert_ok!(seed_persona_fixture(RuntimeOrigin::signed(1),
            persona_id.to_vec(),
            operator.to_vec(),
            vec![b"did:alice#policy-1".to_vec()],
            1,
            Some(persona_constraints),
            10_000));

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
        assert_ok!(DeliveryPolicy::legacy_fixture_set_persona_policy_v2(
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
        assert_ok!(DeliveryPolicy::legacy_fixture_set_did_policy_v2(
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
        assert_ok!(DeliveryPolicy::legacy_fixture_set_did_policy_v2(
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
            DeliveryPolicy::legacy_fixture_set_did_policy_v2(
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
        assert_ok!(DeliveryPolicy::legacy_fixture_set_did_policy_v2(
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
            DeliveryPolicy::legacy_fixture_set_did_policy_v2(
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
            DeliveryPolicy::legacy_fixture_set_did_policy_v2(
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

        assert_ok!(DeliveryPolicy::legacy_fixture_set_did_policy_v2(
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

        assert_ok!(DeliveryPolicy::legacy_fixture_set_did_policy_v2(
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
            DeliveryPolicy::legacy_fixture_set_did_policy_v2(
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
            DeliveryPolicy::legacy_fixture_set_did_policy_v2(
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
            DeliveryPolicy::legacy_fixture_set_did_policy_v2(
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
            DeliveryPolicy::legacy_fixture_set_did_policy_v2(
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
        assert_ok!(DeliveryPolicy::legacy_fixture_set_did_policy_v2(
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
            StorageVersion::new(8)
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
            StorageVersion::new(8)
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

        StorageVersion::new(9).put::<DeliveryPolicy>();
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

fn recovery_registration() -> PersonaOf<Test> {
    let name = persona(b"recovery.example");
    Personas::<Test>::insert(&name, crate::PersonaRecord::<Test> {
        operator_did: did(b"did:alice"),
        controller_key_ids: vec![b"did:alice#root".to_vec().try_into().unwrap()].try_into().unwrap(),
        controller_threshold: 1, delivery_constraints: None, dns_proof_hash: [1; 32],
        verified_at: 1, verification_expires_at: 2, revision: 1, active: false,
    }); // Recovery is also available after expiry/revocation.
    name
}



fn recovery_call(operator: &[u8], operation: PersonaOperation<Test>) -> frame_support::dispatch::DispatchResult {
    let owner = did(operator);
    let mut key = operator.to_vec(); key.extend_from_slice(b"#root");
    let payload = PersonaAuthorizationPayload::<Test> { operator_did: owner.clone(), operation,
        nonce: PersonaOperatorNonces::<Test>::get(&owner), valid_until: Timestamp::get() + 300000,
        signer_key_id: key.clone().try_into().unwrap() }.encode();
    DeliveryPolicy::apply_persona_with_proof(RuntimeOrigin::none(), payload.clone(), payload, key)
}










#[test]
fn dnssec_challenge_matches_directory_golden_vector() {
    assert_eq!(core::str::from_utf8(&crate::dnssec::challenge_value(&[0x11; 32], b"example.com",
        b"did:openpayload:2222222222222222222222", b"register_persona", 4, 1_790_000_100_000, &[0; 32])).unwrap(),
        "openpayload-persona-dnssec-v1=7ae31c3cb38bb82e66d205c4a8a0343d22b5dfc3466031b67b20136cc50465a7");
}

#[test]
fn dnssec_rejects_signatures_outside_label_boundaries_and_untrusted_root_keys() {
    new_test_ext().execute_with(|| {
        Timestamp::set_timestamp(1_700_000_100_000); install_test_dnssec_root();
        let name = "_openpayload-persona.notexample.com.";
        // Fixture signer is example.com: a string suffix must not establish zone authority.
        let proof = signed_dnssec_txt_in_zone(name, b"test", 1_600_000_000, 2_000_000_000, "example.com.");
        assert_eq!(DeliveryPolicy::verify_dnssec_txt(name.as_bytes().to_vec(), b"test".to_vec(), proof), None);
        let (_, rogue) = dnssec_key(".", 44); let ds = dnssec_ds(&rogue);
        let _ = crate::DnssecRootTrustAnchors::<Test>::clear(8, None);
        assert_ok!(DeliveryPolicy::set_dnssec_root_trust_anchor(RuntimeOrigin::root(), ds.key_tag,
            crate::DnssecRootTrustAnchor { algorithm: 13, digest: ds.digest.try_into().unwrap(), valid_from: 0, valid_until: 0 }));
        let name = "_openpayload-persona.example.com.";
        assert_eq!(DeliveryPolicy::verify_dnssec_txt(name.as_bytes().to_vec(), b"test".to_vec(),
            signed_dnssec_txt(name, b"test", 1_600_000_000, 2_000_000_000)), None);
    });
}

#[test]
fn dnssec_unsigned_pool_admission_requires_valid_evidence_and_operator_signature() {
    new_test_ext().execute_with(|| {
        Timestamp::set_timestamp(1_700_000_010_000); install_test_dnssec_root();
        let name = persona(b"example.com"); let owner = did(b"did:alice"); let expiry = 1_700_001_000_000;
        let (hash, proof) = dnssec_evidence(&name, &owner, b"register_persona", 0, expiry, &[0; 32]);
        let operation = PersonaOperation::Register { persona: name.clone(), controller_key_ids:
            vec![b"did:alice#root".to_vec().try_into().unwrap()].try_into().unwrap(), controller_threshold: 1,
            constraints: None, dns_proof_hash: hash, challenge_nonce: 0, verification_expires_at: expiry,
            challenge_expires_at: expiry, dnssec_proof: proof };
        let payload = PersonaAuthorizationPayload::<Test> { operator_did: owner, operation: operation.clone(),
            nonce: 0, valid_until: expiry, signer_key_id: b"did:alice#root".to_vec().try_into().unwrap() };
        let bytes = payload.encode();
        let call = crate::Call::<Test>::apply_persona_with_proof { signed_payload: bytes.clone(), signature: bytes.clone(), signer_key_id: b"did:alice#root".to_vec() };
        assert!(DeliveryPolicy::legacy_fixture_validate_unsigned_call(&call).is_ok());
        let bad_signature = crate::Call::<Test>::apply_persona_with_proof { signed_payload: bytes.clone(), signature: vec![], signer_key_id: b"did:alice#root".to_vec() };
        assert!(DeliveryPolicy::legacy_fixture_validate_unsigned_call(&bad_signature).is_err());
        let mut wrong = payload;
        if let PersonaOperation::Register { dnssec_proof, .. } = &mut wrong.operation { *dnssec_proof = vec![1, 2, 3].try_into().unwrap(); }
        let bad = wrong.encode();
        assert!(DeliveryPolicy::legacy_fixture_validate_unsigned_call(&crate::Call::<Test>::apply_persona_with_proof {
            signed_payload: bad.clone(), signature: bad, signer_key_id: b"did:alice#root".to_vec() }).is_err());
        // A proof built for a different genesis must not be reusable even when the DID signs it.
        frame_system::BlockHash::<Test>::insert(0, <Test as frame_system::Config>::Hashing::hash(&[0x11; 32]));
        assert_noop!(recovery_call(b"did:alice", operation), Error::<Test>::InvalidDnssecProof);
        assert!(!Personas::<Test>::contains_key(name));
    });
}

#[test]
fn dnssec_transfer_requires_fresh_proof_and_both_operator_signatures() {
    new_test_ext().execute_with(|| {
        Timestamp::set_timestamp(1_700_000_010_000); install_test_dnssec_root();
        let name = persona(b"example.com"); let expiry = 1_700_001_000_000;
        seed_persona_fixture(RuntimeOrigin::signed(1), name.to_vec(), b"did:alice".to_vec(),
            vec![b"did:alice#root".to_vec()], 1, None, expiry).unwrap();
        let keys: crate::ControllerKeysOf<Test> = vec![b"did:bob#root".to_vec().try_into().unwrap()].try_into().unwrap();
        let (hash, proof) = dnssec_evidence(&name, &did(b"did:bob"), b"transfer_persona", 0, expiry, &[0; 32]);
        let acceptance = PersonaTransferAcceptancePayload::<Test> { domain: b"openpayload:persona:transfer:v1".to_vec().try_into().unwrap(),
            genesis_hash: System::block_hash(0u64), persona: name.clone(), current_operator_did: did(b"did:alice"),
            new_operator_did: did(b"did:bob"), new_controller_key_ids: keys.clone(), new_controller_threshold: 1,
            constraints: None, dns_proof_hash: hash, challenge_nonce: 0, verification_expires_at: expiry,
            new_operator_signer_key_id: b"did:bob#root".to_vec().try_into().unwrap() }.encode();
        let transfer = |signature: Vec<u8>| PersonaOperation::Transfer { persona: name.clone(), new_operator_did: did(b"did:bob"),
            new_controller_key_ids: keys.clone(), new_controller_threshold: 1, constraints: None,
            dns_proof_hash: hash, challenge_nonce: 0, verification_expires_at: expiry, challenge_expires_at: expiry,
            dnssec_proof: proof.clone(), new_operator_signer_key_id: b"did:bob#root".to_vec().try_into().unwrap(),
            new_operator_signature: signature };
        let scope=crate::PolicyScopeV3::Persona(name.clone());
        crate::PoliciesV4::<Test>::insert(&scope,crate::PolicyDocumentRecord::<Test> {
            revision:3,operator_did:did(b"did:alice"),content_hash:sp_io::hashing::blake2_256(b"old"),document:b"old".to_vec().try_into().unwrap(),
        });
        assert_noop!(recovery_call(b"did:alice", transfer(vec![0])), Error::<Test>::InvalidSignature);
        assert_ok!(recovery_call(b"did:alice", transfer(acceptance)));
        assert_eq!(Personas::<Test>::get(name).unwrap().operator_did, did(b"did:bob"));
        let raw=crate::PoliciesV4::<Test>::get(scope).unwrap();
        assert!(raw.document.is_empty());assert_eq!(raw.revision,4);
        assert_eq!(raw.content_hash,sp_io::hashing::blake2_256(&[]));
    });
}

#[test]
fn dnssec_txt_observation_cannot_outlive_48_hours_even_with_long_signatures() {
    new_test_ext().execute_with(|| {
        install_test_dnssec_root();
        let name = "_openpayload-persona.example.com.";
        let value = b"long-lived signature";
        let proof = signed_dnssec_txt(name, value, 1_700_000_000, 2_000_000_000);
        Timestamp::set_timestamp(1_700_000_000_000 + 48 * 3_600_000 - 1);
        assert_eq!(DeliveryPolicy::verify_dnssec_txt(name.as_bytes().to_vec(), value.to_vec(), proof.clone()),
            Some(1_700_000_000_000 + 48 * 3_600_000));
        Timestamp::set_timestamp(1_700_000_000_000 + 48 * 3_600_000);
        assert_eq!(DeliveryPolicy::verify_dnssec_txt(name.as_bytes().to_vec(), value.to_vec(), proof), None);
    });
}

#[test]
fn dnssec_v6_upgrade_preserves_edited_v3_policies_in_existing_v5_storage() {
    new_test_ext().execute_with(|| {
        StorageVersion::new(5).put::<DeliveryPolicy>();
        let name = persona(b"example.com"); let scope = crate::PolicyScopeV3::Persona(name.clone());
        let legacy = policy_v2(PolicyScopeV2::Persona(name.clone()), b"did:alice", 4,
            vec![base_rule(b"old-v2-rule", 1, Vec::new())]);
        PersonaPoliciesV2::<Test>::insert(&name, legacy.clone());
        let mut id_material = b"openpayload:delivery-policy:v3:".to_vec(); id_material.extend_from_slice(&scope.encode());
        let edited = crate::DeliveryPolicyV3::<Test> {
            policy_id: <Test as frame_system::Config>::Hashing::hash(&id_material).as_ref().to_vec().try_into().unwrap(),
            scope: scope.clone(), operator_did: did(b"did:alice"), revision: 9,
            ruleset: vec![base_rule(b"edited-v3-rule", 7, Vec::new())].try_into().unwrap(), policy_ttl_seconds: 90,
        };
        crate::PoliciesV3::<Test>::insert(&scope, edited.clone());
        DeliveryPolicy::on_runtime_upgrade();
        assert_eq!(DeliveryPolicy::on_chain_storage_version(), StorageVersion::new(8));
        assert_eq!(PersonaPoliciesV2::<Test>::get(&name), Some(legacy));
        assert_eq!(crate::PoliciesV3::<Test>::get(&scope), Some(edited));
    });
}
