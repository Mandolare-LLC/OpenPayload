use crate::{
    mock::*, ApplicationDomains, ApplicationLinkedDids, ApplicationPolicies, ApplicationStatus,
    Applications, ApplicationsByControlDid, AuthorizationNonces, Error,
};
use frame_support::{
    assert_noop, assert_ok,
    traits::{GetStorageVersion, Hooks, StorageVersion},
    BoundedVec,
};

#[test]
fn new_pallet_installs_storage_version_on_runtime_upgrade() {
    new_test_ext().execute_with(|| {
        StorageVersion::new(0).put::<ApplicationRegistry>();
        ApplicationRegistry::on_runtime_upgrade();
        assert_eq!(
            ApplicationRegistry::on_chain_storage_version(),
            StorageVersion::new(2)
        );
    });
}

fn application_id(value: &[u8]) -> BoundedVec<u8, MaxApplicationIdLen> {
    value.to_vec().try_into().unwrap()
}

fn did(value: &[u8]) -> BoundedVec<u8, MaxDidLen> {
    value.to_vec().try_into().unwrap()
}

fn key_id() -> BoundedVec<u8, MaxKeyIdLen> {
    b"did:openpayload:control#keys-1".to_vec().try_into().unwrap()
}

fn signature(value: &[u8]) -> BoundedVec<u8, MaxSignatureLen> {
    value.to_vec().try_into().unwrap()
}

#[test]
fn registers_and_tombstones_application_with_did_proof() {
    new_test_ext().execute_with(|| {
        let app = application_id(b"talaria");
        let control = did(b"did:openpayload:control");
        assert_ok!(ApplicationRegistry::register_application(
            RuntimeOrigin::signed(1),
            app.clone(),
            control.clone(),
            key_id(),
            signature(b"valid"),
        ));
        let record = Applications::<Test>::get(&app).unwrap();
        assert_eq!(record.status, ApplicationStatus::Active);
        assert_eq!(record.revision, 1);
        assert_eq!(AuthorizationNonces::<Test>::get(&control), 1);

        assert_ok!(ApplicationRegistry::set_application_status(
            RuntimeOrigin::signed(1),
            app.clone(),
            ApplicationStatus::Tombstoned,
            key_id(),
            signature(b"valid"),
        ));
        assert_noop!(
            ApplicationRegistry::set_application_status(
                RuntimeOrigin::signed(1),
                app,
                ApplicationStatus::Active,
                key_id(),
                signature(b"valid"),
            ),
            Error::<Test>::ApplicationTombstoned
        );
    });
}

#[test]
fn domain_and_linked_send_dids_are_separate_and_cleared_on_control_change() {
    new_test_ext().execute_with(|| {
        let app = application_id(b"talaria");
        let control = did(b"did:openpayload:control");
        assert_ok!(ApplicationRegistry::register_application(
            RuntimeOrigin::signed(1),
            app.clone(),
            control.clone(),
            key_id(),
            signature(b"valid")
        ));
        let domain = b"push.example.com".to_vec().try_into().unwrap();
        assert_noop!(
            ApplicationRegistry::set_application_domain(
                RuntimeOrigin::signed(1),
                app.clone(),
                Some(b"other.example.com".to_vec().try_into().unwrap()),
                key_id(),
                signature(b"valid")
            ),
            Error::<Test>::DomainNotControlled
        );
        assert_ok!(ApplicationRegistry::set_application_domain(
            RuntimeOrigin::signed(1),
            app.clone(),
            Some(domain),
            key_id(),
            signature(b"valid")
        ));
        let target = did(b"did:openpayload:push");
        assert_ok!(ApplicationRegistry::set_application_linked_did(
            RuntimeOrigin::signed(1),
            app.clone(),
            target.clone(),
            true,
            key_id(),
            signature(b"valid"),
            key_id(),
            signature(b"valid")
        ));
        assert_eq!(
            ApplicationDomains::<Test>::get(&app).unwrap().as_slice(),
            b"push.example.com"
        );
        assert_eq!(
            ApplicationLinkedDids::<Test>::get(&app).as_slice(),
            &[target]
        );
        assert_ok!(ApplicationRegistry::update_application(
            RuntimeOrigin::signed(1),
            app.clone(),
            did(b"did:openpayload:other"),
            key_id(),
            signature(b"valid")
        ));
        assert!(ApplicationDomains::<Test>::get(&app).is_none());
        assert!(ApplicationLinkedDids::<Test>::get(&app).is_empty());
    });
}

#[test]
fn rejects_invalid_id_and_signature() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            ApplicationRegistry::register_application(
                RuntimeOrigin::signed(1),
                application_id(b"Talaria Push"),
                did(b"did:openpayload:control"),
                key_id(),
                signature(b"valid"),
            ),
            Error::<Test>::InvalidApplicationId
        );
        assert_noop!(
            ApplicationRegistry::register_application(
                RuntimeOrigin::signed(1),
                application_id(b"talaria"),
                did(b"did:openpayload:control"),
                key_id(),
                signature(b"invalid"),
            ),
            Error::<Test>::InvalidAuthorization
        );
    });
}

#[test]
fn legacy_application_policy_writes_are_disabled() {
    new_test_ext().execute_with(|| {
        let app = application_id(b"talaria");
        let control = did(b"did:openpayload:control");
        assert_ok!(ApplicationRegistry::register_application(
            RuntimeOrigin::signed(1),
            app.clone(),
            control.clone(),
            key_id(),
            signature(b"valid")
        ));
        assert_noop!(
            ApplicationRegistry::set_application_policy(
                RuntimeOrigin::signed(1),
                app.clone(),
                301,
                b"{}".to_vec().try_into().unwrap(),
                key_id(),
                signature(b"valid")
            ),
            Error::<Test>::LegacyPolicyDeprecated
        );
        assert_noop!(
            ApplicationRegistry::set_application_policy(
                RuntimeOrigin::signed(1),
                app.clone(),
                60,
                b"{\"on_cache_store\":{\"action\":\"sendPush\"}}"
                    .to_vec()
                    .try_into()
                    .unwrap(),
                key_id(),
                signature(b"valid")
            ),
            Error::<Test>::LegacyPolicyDeprecated
        );
        assert!(ApplicationPolicies::<Test>::get(&app).is_none());
        assert_eq!(AuthorizationNonces::<Test>::get(&control), 1);
        assert_ok!(ApplicationRegistry::set_application_status(
            RuntimeOrigin::signed(1),
            app.clone(),
            ApplicationStatus::Tombstoned,
            key_id(),
            signature(b"valid")
        ));
        assert!(ApplicationPolicies::<Test>::get(&app).is_none());
        assert!(ApplicationsByControlDid::<Test>::get(&control).is_empty());
    });
}

#[test]
fn changing_control_did_clears_previous_controller_policy() {
    new_test_ext().execute_with(|| {
        let app = application_id(b"talaria");
        assert_ok!(ApplicationRegistry::register_application(
            RuntimeOrigin::signed(1),
            app.clone(),
            did(b"did:openpayload:control"),
            key_id(),
            signature(b"valid")
        ));
        assert_noop!(
            ApplicationRegistry::set_application_policy(
                RuntimeOrigin::signed(1),
                app.clone(),
                60,
                b"{}".to_vec().try_into().unwrap(),
                key_id(),
                signature(b"valid")
            ),
            Error::<Test>::LegacyPolicyDeprecated
        );
        assert_ok!(ApplicationRegistry::update_application(
            RuntimeOrigin::signed(1),
            app.clone(),
            did(b"did:openpayload:new-control"),
            key_id(),
            signature(b"valid")
        ));
        assert!(ApplicationPolicies::<Test>::get(&app).is_none());
    });
}
