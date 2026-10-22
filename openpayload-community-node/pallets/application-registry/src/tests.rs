use crate::{mock::*, *};
use frame_support::{
    assert_noop, assert_ok,
    traits::{GetStorageVersion, Hooks, StorageVersion},
};
use sp_core::{ed25519, Pair};

fn app(value: &[u8]) -> ApplicationIdOf<Test> {
    value.to_vec().try_into().unwrap()
}
fn did(value: &[u8]) -> DidOf<Test> {
    value.to_vec().try_into().unwrap()
}
fn key(d: &[u8]) -> KeyIdOf<Test> {
    [d, b"#keys-1"].concat().try_into().unwrap()
}
fn proof(operation: ApplicationOperation<Test>) -> ApplicationAuthorizationPayload<Test> {
    let owner = did(b"did:openpayload:1111111111111111111111");
    let linked = matches!(&operation, ApplicationOperation::SetLinkedDid { .. });
    ApplicationAuthorizationPayload {
        genesis_hash: System::block_hash(0),
        signer_key_id: key(&owner),
        linked_signer_key_id: linked.then(|| key(b"did:openpayload:3333333333333333333333")),
        nonce: AuthorizationNonces::<Test>::get(&owner),
        operator_did: owner,
        operation,
        valid_until: 60_000,
    }
}
fn signature(bytes: &[u8], seed: u8) -> SignatureOf<Test> {
    ed25519::Pair::from_seed(&[seed; 32])
        .sign(bytes)
        .0
        .to_vec()
        .try_into()
        .unwrap()
}
fn submit(
    proof: &ApplicationAuthorizationPayload<Test>,
) -> frame_support::dispatch::DispatchResult {
    let bytes = ApplicationRegistry::proof_payload(proof);
    let linked = if proof.linked_signer_key_id.is_some() {
        signature(&bytes, 3)
    } else {
        Default::default()
    };
    ApplicationRegistry::apply_application_with_proof(
        RuntimeOrigin::none(),
        bytes.clone(),
        signature(&bytes, 1),
        linked,
    )
}
fn register() {
    assert_ok!(submit(&proof(ApplicationOperation::Register {
        application_id: app(b"talaria")
    })));
}

#[test]
fn storage_encoding_and_version_do_not_change_for_proof_transport() {
    new_test_ext().execute_with(|| {
        StorageVersion::new(2).put::<ApplicationRegistry>();
        register();
        let record = Applications::<Test>::get(app(b"talaria")).unwrap();
        let nonce = AuthorizationNonces::<Test>::get(did(b"did:openpayload:1111111111111111111111"));
        ApplicationRegistry::on_runtime_upgrade();
        assert_eq!(
            ApplicationRegistry::on_chain_storage_version(),
            StorageVersion::new(2)
        );
        assert_eq!(
            Applications::<Test>::get(app(b"talaria")).unwrap().revision,
            record.revision
        );
        assert_eq!(
            AuthorizationNonces::<Test>::get(did(b"did:openpayload:1111111111111111111111")),
            nonce
        );
    });
}

#[test]
fn registers_without_account_then_tombstones_and_rejects_resurrection() {
    new_test_ext().execute_with(|| {
        register();
        assert_eq!(
            Applications::<Test>::get(app(b"talaria")).unwrap().revision,
            1
        );
        assert_eq!(
            AuthorizationNonces::<Test>::get(did(b"did:openpayload:1111111111111111111111")),
            1
        );
        assert_ok!(submit(&proof(ApplicationOperation::SetStatus {
            application_id: app(b"talaria"),
            status: ApplicationStatus::Tombstoned
        })));
        assert_noop!(
            submit(&proof(ApplicationOperation::SetStatus {
                application_id: app(b"talaria"),
                status: ApplicationStatus::Active
            })),
            Error::<Test>::ApplicationTombstoned
        );
        assert!(ApplicationsByControlDid::<Test>::get(did(b"did:openpayload:1111111111111111111111")).is_empty());
    });
}

#[test]
fn domain_control_and_both_linked_did_consents_are_required_in_pool_and_dispatch() {
    new_test_ext().execute_with(|| {
        register();
        let bad_domain = proof(ApplicationOperation::SetDomain {
            application_id: app(b"talaria"),
            domain: Some(b"other.example.com".to_vec().try_into().unwrap()),
        });
        let bytes = ApplicationRegistry::proof_payload(&bad_domain);
        assert!(ApplicationRegistry::authorize_application(
            &bytes,
            &signature(&bytes, 1),
            &Default::default()
        )
        .is_err());
        assert_noop!(submit(&bad_domain), Error::<Test>::DomainNotControlled);
        assert_ok!(submit(&proof(ApplicationOperation::SetDomain {
            application_id: app(b"talaria"),
            domain: Some(b"push.example.com".to_vec().try_into().unwrap())
        })));
        let link = proof(ApplicationOperation::SetLinkedDid {
            application_id: app(b"talaria"),
            linked_did: did(b"did:openpayload:3333333333333333333333"),
            enabled: true,
        });
        let bytes = ApplicationRegistry::proof_payload(&link);
        assert_noop!(
            ApplicationRegistry::apply_application_with_proof(
                RuntimeOrigin::none(),
                bytes.clone(),
                signature(&bytes, 1),
                signature(&bytes, 2)
            ),
            Error::<Test>::InvalidAuthorization
        );
        assert!(ApplicationRegistry::authorize_application(
            &bytes,
            &signature(&bytes, 1),
            &signature(&bytes, 2)
        )
        .is_err());
        assert_ok!(submit(&link));
        assert_eq!(
            ApplicationLinkedDids::<Test>::get(app(b"talaria")),
            vec![did(b"did:openpayload:3333333333333333333333")]
        );
        assert_ok!(submit(&proof(ApplicationOperation::Update {
            application_id: app(b"talaria"),
            new_control_did: did(b"did:openpayload:2222222222222222222222")
        })));
        assert!(ApplicationDomains::<Test>::get(app(b"talaria")).is_none());
        assert!(ApplicationLinkedDids::<Test>::get(app(b"talaria")).is_empty());
    });
}

#[test]
fn proof_binds_exact_operation_owner_scope_keys_chain_nonce_and_expiry() {
    new_test_ext().execute_with(|| {
        let original = proof(ApplicationOperation::Register {
            application_id: app(b"talaria"),
        });
        let original_bytes = ApplicationRegistry::proof_payload(&original);
        let sig = signature(&original_bytes, 1);
        let mut changed = original.clone();
        changed.operation = ApplicationOperation::Register {
            application_id: app(b"stolen"),
        };
        assert_noop!(
            ApplicationRegistry::apply_application_with_proof(
                RuntimeOrigin::none(),
                ApplicationRegistry::proof_payload(&changed),
                sig.clone(),
                Default::default()
            ),
            Error::<Test>::InvalidAuthorization
        );
        changed = original.clone();
        changed.operator_did = did(b"did:openpayload:2222222222222222222222");
        changed.signer_key_id = key(&changed.operator_did);
        assert_noop!(submit(&changed), Error::<Test>::InvalidAuthorization);
        changed = original.clone();
        changed.genesis_hash = [99; 32].into();
        assert_noop!(submit(&changed), Error::<Test>::WrongChain);
        changed = original.clone();
        changed.valid_until = 0;
        assert_noop!(submit(&changed), Error::<Test>::AuthorizationExpired);
        changed = original.clone();
        changed.valid_until = 600_001;
        assert_noop!(submit(&changed), Error::<Test>::AuthorizationExpired);
        changed = original.clone();
        changed.nonce = 1;
        assert_noop!(submit(&changed), Error::<Test>::InvalidAuthorizationNonce);
        let mut noncanonical = original_bytes.clone();
        noncanonical.push(0);
        assert_noop!(
            ApplicationRegistry::apply_application_with_proof(
                RuntimeOrigin::none(),
                noncanonical,
                sig.clone(),
                Default::default()
            ),
            Error::<Test>::InvalidProofPayload
        );
        assert_noop!(
            ApplicationRegistry::apply_application_with_proof(
                RuntimeOrigin::signed(1),
                original_bytes.clone(),
                sig.clone(),
                Default::default()
            ),
            sp_runtime::DispatchError::BadOrigin
        );
        assert_ok!(ApplicationRegistry::apply_application_with_proof(
            frame_system::RawOrigin::Authorized.into(),
            original_bytes.clone(),
            sig.clone(),
            Default::default()
        ));
        assert_noop!(submit(&original), Error::<Test>::InvalidAuthorizationNonce);
    });
}

#[test]
fn transaction_pool_deduplicates_operations_by_controller_nonce_and_rechecks_at_dispatch() {
    new_test_ext().execute_with(|| {
        let first = proof(ApplicationOperation::Register {
            application_id: app(b"one"),
        });
        let second = proof(ApplicationOperation::Register {
            application_id: app(b"two"),
        });
        let a = ApplicationRegistry::proof_payload(&first);
        let b = ApplicationRegistry::proof_payload(&second);
        let va =
            ApplicationRegistry::authorize_application(&a, &signature(&a, 1), &Default::default())
                .unwrap()
                .0;
        let vb =
            ApplicationRegistry::authorize_application(&b, &signature(&b, 1), &Default::default())
                .unwrap()
                .0;
        assert_eq!(va.provides, vb.provides);
        assert_ok!(submit(&first));
        assert_noop!(submit(&second), Error::<Test>::InvalidAuthorizationNonce);
    });
}

#[test]
fn governance_authority_and_deprecated_routes_remain_separate() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            ApplicationRegistry::register_application(
                RuntimeOrigin::signed(1),
                app(b"talaria"),
                did(b"did:openpayload:1111111111111111111111"),
                key(b"did:openpayload:1111111111111111111111"),
                Default::default()
            ),
            Error::<Test>::ProofRequired
        );
        register();
        assert_noop!(
            ApplicationRegistry::force_set_application_status(
                RuntimeOrigin::none(),
                app(b"talaria"),
                ApplicationStatus::Suspended
            ),
            sp_runtime::DispatchError::BadOrigin
        );
        assert_noop!(
            ApplicationRegistry::force_set_application_status(
                RuntimeOrigin::signed(1),
                app(b"talaria"),
                ApplicationStatus::Suspended
            ),
            sp_runtime::DispatchError::BadOrigin
        );
        assert_ok!(ApplicationRegistry::force_set_application_status(
            RuntimeOrigin::root(),
            app(b"talaria"),
            ApplicationStatus::Suspended
        ));
        assert_eq!(
            AuthorizationNonces::<Test>::get(did(b"did:openpayload:1111111111111111111111")),
            1
        );
        assert_noop!(
            ApplicationRegistry::clear_application_policy(
                RuntimeOrigin::none(),
                app(b"talaria"),
                key(b"did:openpayload:1111111111111111111111"),
                Default::default()
            ),
            Error::<Test>::LegacyPolicyDeprecated
        );
    });
}

#[test]
fn exhausted_nonces_and_capacity_do_not_leave_partial_writes() {
    new_test_ext().execute_with(|| {
        AuthorizationNonces::<Test>::insert(did(b"did:openpayload:1111111111111111111111"), u64::MAX);
        assert_noop!(
            submit(&proof(ApplicationOperation::Register {
                application_id: app(b"talaria")
            })),
            Error::<Test>::AuthorizationNonceOverflow
        );
        assert!(Applications::<Test>::get(app(b"talaria")).is_none());
        AuthorizationNonces::<Test>::insert(did(b"did:openpayload:1111111111111111111111"), 0);
        register();
        assert_ok!(submit(&proof(ApplicationOperation::Register {
            application_id: app(b"two")
        })));
        assert_noop!(
            submit(&proof(ApplicationOperation::Register {
                application_id: app(b"three")
            })),
            Error::<Test>::TooManyApplicationsForControlDid
        );
        assert_eq!(
            AuthorizationNonces::<Test>::get(did(b"did:openpayload:1111111111111111111111")),
            2
        );
    });
}
