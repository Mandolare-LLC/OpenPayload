use crate::{
    mock::*, AliasAction, AliasAuthorizationPayload, AliasIndex, AliasNonces, AliasOf,
    ControlAction, ControlAuthorizationPayload, ControlNonces, DeviceIdOf, DidOf, Dids,
    DocumentAction, DocumentAuthorizationPayload, DocumentNonces, Error, KeyAgreement,
    RootPubkeyAuthorizationPayload, RootPubkeyNonces, Service, VerificationMethod,
};
use codec::Encode;
use frame_support::{assert_noop, assert_ok, traits::Get};
use sp_core::{ed25519, ByteArray, Pair};

const NOW_MILLIS: u64 = 1_700_000_000_000;
const FUTURE_MILLIS: u64 = NOW_MILLIS + 60_000;
const PAST_MILLIS: u64 = NOW_MILLIS - 1;

fn did(raw: &[u8]) -> DidOf<Test> {
    raw.to_vec().try_into().unwrap()
}

fn alias(raw: &[u8]) -> AliasOf<Test> {
    raw.to_vec().try_into().unwrap()
}

fn id(raw: &[u8]) -> crate::IdStrOf<Test> {
    raw.to_vec().try_into().unwrap()
}

fn root_pair() -> ed25519::Pair {
    ed25519::Pair::from_seed(&[7u8; 32])
}

fn alternate_pair() -> ed25519::Pair {
    ed25519::Pair::from_seed(&[9u8; 32])
}

fn registration_signature(pair: &ed25519::Pair, raw_did: &[u8], timestamp: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(raw_did);
    payload.push(b'|');
    payload.extend_from_slice(timestamp);
    pair.sign(&payload).to_raw_vec()
}

fn register_with_root(raw_did: &[u8], pair: &ed25519::Pair) {
    let timestamp = b"0".to_vec();
    let signature = registration_signature(pair, raw_did, &timestamp);
    assert_ok!(DidRegistry::register_with_proof(
        RuntimeOrigin::signed(1),
        raw_did.to_vec(),
        None,
        timestamp,
        pair.public().to_raw_vec(),
        signature,
    ));
}

#[test]
fn registration_accepts_operator_selected_platforms_with_base58_addresses() {
    new_test_ext().execute_with(|| {
        let pair = root_pair();
        let raw_did = b"did:research:L5bBGBeKawAN2JtBv9rEzP";

        register_with_root(raw_did, &pair);

        assert!(Dids::<Test>::contains_key(did(raw_did)));
    });
}

#[test]
fn registration_rejects_noncanonical_dids() {
    new_test_ext().execute_with(|| {
        let pair = root_pair();
        let invalid_dids: Vec<Vec<u8>> = vec![
            b"openpayload:L5bBGBeKawAN2JtBv9rEzP".to_vec(),
            b"did:OpenPayload:L5bBGBeKawAN2JtBv9rEzP".to_vec(),
            b"did:openpayload:device:L5bBGBeKawAN2JtBv9rEzP".to_vec(),
            b"did:openpayload:L5bBGBeKawAN2JtBv9rEz0".to_vec(),
            b"did:openpayload:short".to_vec(),
            format!("did:{}:L5bBGBeKawAN2JtBv9rEzP", "a".repeat(33)).into_bytes(),
            format!("did:openpayload:{}", "1".repeat(97)).into_bytes(),
        ];

        for raw_did in invalid_dids {
            let timestamp = b"0".to_vec();
            let signature = registration_signature(&pair, &raw_did, &timestamp);
            assert_noop!(
                DidRegistry::register_with_proof(
                    RuntimeOrigin::signed(1),
                    raw_did,
                    None,
                    timestamp,
                    pair.public().to_raw_vec(),
                    signature,
                ),
                Error::<Test>::InvalidDidFormat
            );
        }
    });
}

fn alias_payload(
    action: AliasAction,
    raw_did: &[u8],
    raw_alias: Option<&[u8]>,
    raw_old_alias: Option<&[u8]>,
    raw_new_alias: Option<&[u8]>,
    nonce: u64,
) -> AliasAuthorizationPayload<Test> {
    alias_payload_until(
        action,
        raw_did,
        raw_alias,
        raw_old_alias,
        raw_new_alias,
        nonce,
        FUTURE_MILLIS,
    )
}

fn alias_payload_until(
    action: AliasAction,
    raw_did: &[u8],
    raw_alias: Option<&[u8]>,
    raw_old_alias: Option<&[u8]>,
    raw_new_alias: Option<&[u8]>,
    nonce: u64,
    valid_until: u64,
) -> AliasAuthorizationPayload<Test> {
    AliasAuthorizationPayload {
        did: did(raw_did),
        action,
        alias: raw_alias.map(alias),
        old_alias: raw_old_alias.map(alias),
        new_alias: raw_new_alias.map(alias),
        nonce,
        valid_until,
        signer_key_id: b"root".to_vec().try_into().unwrap(),
    }
}

fn signed_alias_payload(
    pair: &ed25519::Pair,
    payload: AliasAuthorizationPayload<Test>,
) -> (Vec<u8>, Vec<u8>) {
    let encoded = payload.encode();
    let signature = pair.sign(&encoded);
    (encoded, signature.to_raw_vec())
}

fn signed_control_payload(
    pair: &ed25519::Pair,
    raw_did: &[u8],
    action: ControlAction<Test>,
    nonce: u64,
) -> (Vec<u8>, Vec<u8>) {
    let encoded = ControlAuthorizationPayload::<Test> {
        did: did(raw_did),
        action,
        nonce,
        valid_until: FUTURE_MILLIS,
        signer_key_id: id(b"root"),
    }
    .encode();
    let signature = pair.sign(&encoded).to_raw_vec();
    (encoded, signature)
}

fn verification_method(raw_id: &[u8], raw_did: &[u8], seed: u8) -> VerificationMethod<Test> {
    VerificationMethod {
        id: id(raw_id),
        type_: b"Ed25519VerificationKey2020".to_vec().try_into().unwrap(),
        controller: id(raw_did),
        public_key_multibase: vec![seed; 32].try_into().unwrap(),
    }
}

fn verification_method_with_key(
    raw_id: &[u8],
    raw_did: &[u8],
    public_key_multibase: Vec<u8>,
) -> VerificationMethod<Test> {
    VerificationMethod {
        id: id(raw_id),
        type_: b"Ed25519VerificationKey2020".to_vec().try_into().unwrap(),
        controller: id(raw_did),
        public_key_multibase: public_key_multibase.try_into().unwrap(),
    }
}

fn service(
    raw_id: &[u8],
    raw_type: &[u8],
    raw_endpoint: &[u8],
    authorization: Option<Vec<&[u8]>>,
    priority: Option<u32>,
) -> Service<Test> {
    Service {
        id: id(raw_id),
        type_: raw_type.to_vec().try_into().unwrap(),
        service_endpoint: vec![raw_endpoint.to_vec().try_into().unwrap()]
            .try_into()
            .unwrap(),
        authorization: authorization.map(|refs| {
            refs.into_iter()
                .map(id)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap()
        }),
        priority,
    }
}

fn max_service_authorization_keys() -> u32 {
    <<Test as crate::Config>::MaxServiceAuthorizationKeys as Get<u32>>::get()
}

fn document_payload(
    action: DocumentAction,
    raw_did: &[u8],
    method: Option<VerificationMethod<Test>>,
    raw_id: Option<&[u8]>,
    nonce: u64,
) -> DocumentAuthorizationPayload<Test> {
    document_payload_until(
        action,
        raw_did,
        method,
        raw_id,
        nonce,
        FUTURE_MILLIS,
        b"root",
    )
}

fn document_payload_until(
    action: DocumentAction,
    raw_did: &[u8],
    method: Option<VerificationMethod<Test>>,
    raw_id: Option<&[u8]>,
    nonce: u64,
    valid_until: u64,
    signer_key_id: &[u8],
) -> DocumentAuthorizationPayload<Test> {
    DocumentAuthorizationPayload {
        did: did(raw_did),
        action,
        verification_method: method,
        key_agreement: None,
        service: None,
        id: raw_id.map(id),
        nonce,
        valid_until,
        signer_key_id: signer_key_id.to_vec().try_into().unwrap(),
    }
}

fn document_service_payload(
    action: DocumentAction,
    raw_did: &[u8],
    service: Service<Test>,
    nonce: u64,
) -> DocumentAuthorizationPayload<Test> {
    DocumentAuthorizationPayload {
        did: did(raw_did),
        action,
        verification_method: None,
        key_agreement: None,
        service: Some(service),
        id: None,
        nonce,
        valid_until: FUTURE_MILLIS,
        signer_key_id: b"root".to_vec().try_into().unwrap(),
    }
}

fn signed_document_payload(
    pair: &ed25519::Pair,
    payload: DocumentAuthorizationPayload<Test>,
) -> (Vec<u8>, Vec<u8>) {
    let encoded = payload.encode();
    let signature = pair.sign(&encoded);
    (encoded, signature.to_raw_vec())
}

fn root_pubkey_payload(
    raw_did: &[u8],
    new_root_pubkey: Vec<u8>,
    nonce: u64,
) -> RootPubkeyAuthorizationPayload<Test> {
    root_pubkey_payload_until(raw_did, new_root_pubkey, nonce, FUTURE_MILLIS)
}

fn root_pubkey_payload_until(
    raw_did: &[u8],
    new_root_pubkey: Vec<u8>,
    nonce: u64,
    valid_until: u64,
) -> RootPubkeyAuthorizationPayload<Test> {
    RootPubkeyAuthorizationPayload {
        did: did(raw_did),
        new_root_pubkey: new_root_pubkey.try_into().unwrap(),
        nonce,
        valid_until,
        signer_key_id: b"root".to_vec().try_into().unwrap(),
    }
}

fn signed_root_pubkey_payload(
    pair: &ed25519::Pair,
    payload: RootPubkeyAuthorizationPayload<Test>,
) -> (Vec<u8>, Vec<u8>) {
    let encoded = payload.encode();
    let signature = pair.sign(&encoded);
    (encoded, signature.to_raw_vec())
}

fn add_alias_with_nonce(pair: &ed25519::Pair, raw_did: &[u8], raw_alias: &[u8], nonce: u64) {
    let (payload, signature) = signed_alias_payload(
        pair,
        alias_payload(
            AliasAction::Add,
            raw_did,
            Some(raw_alias),
            None,
            None,
            nonce,
        ),
    );
    assert_ok!(DidRegistry::add_alias(
        RuntimeOrigin::none(),
        raw_did.to_vec(),
        raw_alias.to_vec(),
        payload,
        signature,
        b"root".to_vec(),
    ));
}

fn multibase_ed25519_public_key(pair: &ed25519::Pair) -> Vec<u8> {
    let mut multicodec = vec![0xed, 0x01];
    multicodec.extend_from_slice(pair.public().as_slice());
    let mut encoded = b"z".to_vec();
    encoded.extend_from_slice(&base58btc_encode(&multicodec));
    encoded
}

fn base58btc_encode(data: &[u8]) -> Vec<u8> {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut digits = Vec::<u8>::new();
    for byte in data {
        let mut carry = *byte as u32;
        for digit in &mut digits {
            let value = (*digit as u32) * 256 + carry;
            *digit = (value % 58) as u8;
            carry = value / 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let leading_zeros = data.iter().take_while(|byte| **byte == 0).count();
    digits.resize(digits.len() + leading_zeros, 0);
    digits
        .iter()
        .rev()
        .map(|digit| ALPHABET[*digit as usize])
        .collect()
}

#[test]
fn owner_can_set_and_clear_delivery_policy_links() {
    new_test_ext().execute_with(|| {
        let pair = root_pair();
        register_with_root(b"did:openpayload:entity1po1icy111", &pair);

        assert_ok!(DidRegistry::set_delivery_policy_links(
            RuntimeOrigin::signed(1),
            b"did:openpayload:entity1po1icy111".to_vec(),
            Some(b"did:openpayload:entity1po1icy111".to_vec()),
            vec![b"did:openpayload:tag1work11111111".to_vec()],
            vec![b"did:openpayload:persona1private1".to_vec()],
        ));

        let record = Dids::<Test>::get(did(b"did:openpayload:entity1po1icy111")).unwrap();
        let links = record.delivery_policy_links.unwrap();
        assert_eq!(
            links.recipient_policy.unwrap().as_slice(),
            b"did:openpayload:entity1po1icy111"
        );
        assert_eq!(
            links.tag_policies[0].as_slice(),
            b"did:openpayload:tag1work11111111"
        );
        assert_eq!(
            links.persona_policies[0].as_slice(),
            b"did:openpayload:persona1private1"
        );

        assert_ok!(DidRegistry::clear_delivery_policy_links(
            RuntimeOrigin::signed(1),
            b"did:openpayload:entity1po1icy111".to_vec()
        ));
        assert!(Dids::<Test>::get(did(b"did:openpayload:entity1po1icy111"))
            .unwrap()
            .delivery_policy_links
            .is_none());
    });
}

#[test]
fn device_crud_supports_create_read_update_tombstone_restore_and_remove() {
    new_test_ext().execute_with(|| {
        let pair = root_pair();
        let raw_did = b"did:openpayload:entity1device1crud";
        register_with_root(raw_did, &pair);

        assert_ok!(DidRegistry::add_device(
            RuntimeOrigin::signed(1),
            raw_did.to_vec(),
            b"device-a".to_vec(),
        ));
        assert!(DidRegistry::device_of(raw_did, b"device-a").is_some());

        assert_ok!(DidRegistry::update_device(
            RuntimeOrigin::signed(1),
            raw_did.to_vec(),
            b"device-a".to_vec(),
            b"device-b".to_vec(),
        ));
        assert!(DidRegistry::device_of(raw_did, b"device-a").is_none());
        assert!(DidRegistry::device_of(raw_did, b"device-b").is_some());

        assert_ok!(DidRegistry::tombstone_device(
            RuntimeOrigin::signed(1),
            raw_did.to_vec(),
            b"device-b".to_vec(),
        ));
        assert!(
            DidRegistry::device_of(raw_did, b"device-b")
                .unwrap()
                .tombstoned
        );

        assert_ok!(DidRegistry::add_device(
            RuntimeOrigin::signed(1),
            raw_did.to_vec(),
            b"device-b".to_vec(),
        ));
        assert!(
            !DidRegistry::device_of(raw_did, b"device-b")
                .unwrap()
                .tombstoned
        );

        assert_ok!(DidRegistry::remove_device(
            RuntimeOrigin::signed(1),
            raw_did.to_vec(),
            b"device-b".to_vec(),
        ));
        assert!(DidRegistry::device_of(raw_did, b"device-b").is_none());
        assert!(DidRegistry::devices_of(raw_did).is_none());
    });
}

#[test]
fn device_update_rejects_duplicate_target_and_non_owner() {
    new_test_ext().execute_with(|| {
        let pair = root_pair();
        let raw_did = b"did:openpayload:entity1device1guards";
        register_with_root(raw_did, &pair);

        assert_ok!(DidRegistry::add_device(
            RuntimeOrigin::signed(1),
            raw_did.to_vec(),
            b"device-a".to_vec(),
        ));
        assert_ok!(DidRegistry::add_device(
            RuntimeOrigin::signed(1),
            raw_did.to_vec(),
            b"device-b".to_vec(),
        ));

        assert_noop!(
            DidRegistry::update_device(
                RuntimeOrigin::signed(1),
                raw_did.to_vec(),
                b"device-a".to_vec(),
                b"device-b".to_vec(),
            ),
            Error::<Test>::DeviceAlreadyExists
        );
        assert_noop!(
            DidRegistry::remove_device(
                RuntimeOrigin::signed(2),
                raw_did.to_vec(),
                b"device-a".to_vec(),
            ),
            Error::<Test>::NotDidOwner
        );
    });
}

#[test]
fn deactivate_did_preserves_record_but_blocks_future_mutations() {
    new_test_ext().execute_with(|| {
        let pair = root_pair();
        let raw_did = b"did:openpayload:entity1deactivate";
        register_with_root(raw_did, &pair);

        assert!(DidRegistry::did_exists(raw_did));
        assert!(!DidRegistry::is_deactivated(raw_did));
        assert!(DidRegistry::can_update_did(&1, raw_did));

        assert_ok!(DidRegistry::deactivate_did(
            RuntimeOrigin::signed(1),
            raw_did.to_vec()
        ));

        assert!(DidRegistry::did_exists(raw_did));
        assert!(DidRegistry::is_deactivated(raw_did));
        assert!(!DidRegistry::can_update_did(&1, raw_did));
        assert!(!<DidRegistry as pallet_delivery_policy::DidProvider<u64>>::did_exists(raw_did));
        assert!(Dids::<Test>::get(did(raw_did)).unwrap().deactivated);

        assert_noop!(
            DidRegistry::set_alias(
                RuntimeOrigin::signed(1),
                raw_did.to_vec(),
                b"blocked".to_vec(),
            ),
            Error::<Test>::DidDeactivated
        );

        let (payload, signature) = signed_alias_payload(
            &pair,
            alias_payload(AliasAction::Add, raw_did, Some(b"blocked"), None, None, 0),
        );
        assert_noop!(
            DidRegistry::add_alias(
                RuntimeOrigin::none(),
                raw_did.to_vec(),
                b"blocked".to_vec(),
                payload,
                signature,
                b"root".to_vec(),
            ),
            Error::<Test>::DidDeactivated
        );

        assert_noop!(
            DidRegistry::deactivate_did(RuntimeOrigin::signed(1), raw_did.to_vec()),
            Error::<Test>::DidAlreadyDeactivated
        );
    });
}

#[test]
fn register_with_proof_requires_root_pubkey() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            DidRegistry::register_with_proof(
                RuntimeOrigin::signed(1),
                b"did:openpayload:entity1root1required".to_vec(),
                None,
                b"0".to_vec(),
                vec![1u8; 31],
                vec![0u8; 64],
            ),
            Error::<Test>::InvalidRootPubkey
        );

        let pair = root_pair();
        register_with_root(b"did:openpayload:entity1root1required", &pair);
        assert!(
            Dids::<Test>::get(did(b"did:openpayload:entity1root1required"))
                .unwrap()
                .root_pubkey
                .is_some()
        );
    });
}

#[test]
fn update_root_pubkey_succeeds_and_updates_record_timestamp() {
    new_test_ext().execute_with(|| {
        let pair = root_pair();
        register_with_root(b"did:openpayload:entity1root1rotate", &pair);
        let before = Dids::<Test>::get(did(b"did:openpayload:entity1root1rotate"))
            .unwrap()
            .updated_at;
        Timestamp::set_timestamp(before + 10);

        let new_root = vec![42u8; 32];
        let (payload, signature) = signed_root_pubkey_payload(
            &pair,
            root_pubkey_payload(b"did:openpayload:entity1root1rotate", new_root.clone(), 0),
        );

        assert_ok!(DidRegistry::update_root_pubkey(
            RuntimeOrigin::none(),
            b"did:openpayload:entity1root1rotate".to_vec(),
            new_root.clone(),
            payload,
            signature,
            b"root".to_vec(),
        ));

        let record = Dids::<Test>::get(did(b"did:openpayload:entity1root1rotate")).unwrap();
        assert_eq!(record.root_pubkey.unwrap().as_slice(), new_root.as_slice());
        assert!(record.updated_at > before);
        assert_eq!(
            RootPubkeyNonces::<Test>::get(did(b"did:openpayload:entity1root1rotate")),
            1
        );
    });
}

#[test]
fn add_alias_succeeds_with_valid_did_owner_signature() {
    new_test_ext().execute_with(|| {
        let pair = root_pair();
        register_with_root(b"did:openpayload:entity1111111111", &pair);

        let (payload, signature) = signed_alias_payload(
            &pair,
            alias_payload(
                AliasAction::Add,
                b"did:openpayload:entity1111111111",
                Some(b"salesgroup"),
                None,
                None,
                0,
            ),
        );

        assert_ok!(DidRegistry::add_alias(
            RuntimeOrigin::none(),
            b"did:openpayload:entity1111111111".to_vec(),
            b" SalesGroup ".to_vec(),
            payload,
            signature,
            b"root".to_vec(),
        ));

        assert_eq!(
            AliasIndex::<Test>::get(alias(b"salesgroup")),
            Some(did(b"did:openpayload:entity1111111111"))
        );
        assert_eq!(
            AliasNonces::<Test>::get(did(b"did:openpayload:entity1111111111")),
            1
        );
        assert_eq!(
            Dids::<Test>::get(did(b"did:openpayload:entity1111111111"))
                .unwrap()
                .aliases
                .unwrap()[0]
                .as_slice(),
            b"salesgroup"
        );
    });
}

#[test]
fn add_alias_fails_with_invalid_signature() {
    new_test_ext().execute_with(|| {
        let pair = root_pair();
        let wrong_pair = alternate_pair();
        register_with_root(b"did:openpayload:entity1112111111", &pair);

        let (payload, signature) = signed_alias_payload(
            &wrong_pair,
            alias_payload(
                AliasAction::Add,
                b"did:openpayload:entity1112111111",
                Some(b"vehicle_001"),
                None,
                None,
                0,
            ),
        );

        assert_noop!(
            DidRegistry::add_alias(
                RuntimeOrigin::none(),
                b"did:openpayload:entity1112111111".to_vec(),
                b"vehicle_001".to_vec(),
                payload,
                signature,
                b"root".to_vec(),
            ),
            Error::<Test>::InvalidSignature
        );
    });
}

#[test]
fn add_alias_fails_for_unknown_did() {
    new_test_ext().execute_with(|| {
        let pair = root_pair();
        let (payload, signature) = signed_alias_payload(
            &pair,
            alias_payload(
                AliasAction::Add,
                b"did:openpayload:missing111111111",
                Some(b"user_a"),
                None,
                None,
                0,
            ),
        );

        assert_noop!(
            DidRegistry::add_alias(
                RuntimeOrigin::none(),
                b"did:openpayload:missing111111111".to_vec(),
                b"user_a".to_vec(),
                payload,
                signature,
                b"root".to_vec(),
            ),
            Error::<Test>::DidNotFound
        );
    });
}

#[test]
fn add_alias_fails_for_malformed_alias() {
    new_test_ext().execute_with(|| {
        let pair = root_pair();
        register_with_root(b"did:openpayload:entity1113111111", &pair);
        let (payload, signature) = signed_alias_payload(
            &pair,
            alias_payload(
                AliasAction::Add,
                b"did:openpayload:entity1113111111",
                Some(b"user_a"),
                None,
                None,
                0,
            ),
        );

        assert_noop!(
            DidRegistry::add_alias(
                RuntimeOrigin::none(),
                b"did:openpayload:entity1113111111".to_vec(),
                b"bad alias".to_vec(),
                payload,
                signature,
                b"root".to_vec(),
            ),
            Error::<Test>::InvalidAlias
        );
    });
}

#[test]
fn update_alias_succeeds() {
    new_test_ext().execute_with(|| {
        let pair = root_pair();
        register_with_root(b"did:openpayload:entity1114111111", &pair);
        add_alias_with_nonce(&pair, b"did:openpayload:entity1114111111", b"user_a", 0);

        let (payload, signature) = signed_alias_payload(
            &pair,
            alias_payload(
                AliasAction::Update,
                b"did:openpayload:entity1114111111",
                None,
                Some(b"user_a"),
                Some(b"user_a-community"),
                1,
            ),
        );

        assert_ok!(DidRegistry::update_alias(
            RuntimeOrigin::none(),
            b"did:openpayload:entity1114111111".to_vec(),
            b"user_a".to_vec(),
            b"user_a-community".to_vec(),
            payload,
            signature,
            b"root".to_vec(),
        ));

        assert!(AliasIndex::<Test>::get(alias(b"user_a")).is_none());
        assert_eq!(
            AliasIndex::<Test>::get(alias(b"user_a-community")),
            Some(did(b"did:openpayload:entity1114111111"))
        );
    });
}

#[test]
fn remove_alias_succeeds() {
    new_test_ext().execute_with(|| {
        let pair = root_pair();
        register_with_root(b"did:openpayload:entity1115111111", &pair);
        add_alias_with_nonce(
            &pair,
            b"did:openpayload:entity1115111111",
            b"vehicle_001",
            0,
        );

        let (payload, signature) = signed_alias_payload(
            &pair,
            alias_payload(
                AliasAction::Remove,
                b"did:openpayload:entity1115111111",
                Some(b"vehicle_001"),
                None,
                None,
                1,
            ),
        );

        assert_ok!(DidRegistry::remove_alias(
            RuntimeOrigin::none(),
            b"did:openpayload:entity1115111111".to_vec(),
            b"vehicle_001".to_vec(),
            payload,
            signature,
            b"root".to_vec(),
        ));

        assert!(AliasIndex::<Test>::get(alias(b"vehicle_001")).is_none());
        assert!(Dids::<Test>::get(did(b"did:openpayload:entity1115111111"))
            .unwrap()
            .aliases
            .is_none());
    });
}

#[test]
fn replay_of_same_signed_payload_fails() {
    new_test_ext().execute_with(|| {
        let pair = root_pair();
        register_with_root(b"did:openpayload:entity1116111111", &pair);
        let (payload, signature) = signed_alias_payload(
            &pair,
            alias_payload(
                AliasAction::Add,
                b"did:openpayload:entity1116111111",
                Some(b"user_a"),
                None,
                None,
                0,
            ),
        );

        assert_ok!(DidRegistry::add_alias(
            RuntimeOrigin::none(),
            b"did:openpayload:entity1116111111".to_vec(),
            b"user_a".to_vec(),
            payload.clone(),
            signature.clone(),
            b"root".to_vec(),
        ));
        assert_noop!(
            DidRegistry::add_alias(
                RuntimeOrigin::none(),
                b"did:openpayload:entity1116111111".to_vec(),
                b"user_a".to_vec(),
                payload,
                signature,
                b"root".to_vec(),
            ),
            Error::<Test>::InvalidAliasNonce
        );
    });
}

#[test]
fn unsigned_alias_extrinsic_validation_rejects_invalid_embedded_authorization() {
    new_test_ext().execute_with(|| {
        let pair = root_pair();
        let wrong_pair = alternate_pair();
        register_with_root(b"did:openpayload:entity1117111111", &pair);
        let (payload, signature) = signed_alias_payload(
            &wrong_pair,
            alias_payload(
                AliasAction::Add,
                b"did:openpayload:entity1117111111",
                Some(b"user_a"),
                None,
                None,
                0,
            ),
        );
        let call = crate::Call::<Test>::add_alias {
            did: b"did:openpayload:entity1117111111".to_vec(),
            alias: b"user_a".to_vec(),
            signed_payload: payload,
            signature,
            signer_key_id: b"root".to_vec(),
        };

        assert!(DidRegistry::validate_unsigned_call(&call).is_err());
    });
}

#[test]
fn alias_normalization_behaves_consistently() {
    new_test_ext().execute_with(|| {
        let pair = root_pair();
        register_with_root(b"did:openpayload:entity1118111111", &pair);

        let (payload, signature) = signed_alias_payload(
            &pair,
            alias_payload(
                AliasAction::Add,
                b"did:openpayload:entity1118111111",
                Some(b"salesgroup"),
                None,
                None,
                0,
            ),
        );
        assert_ok!(DidRegistry::add_alias(
            RuntimeOrigin::none(),
            b"did:openpayload:entity1118111111".to_vec(),
            b" SalesGroup ".to_vec(),
            payload,
            signature,
            b"root".to_vec(),
        ));
        assert_eq!(
            DidRegistry::did_for_alias(b"SALESgroup"),
            Some(did(b"did:openpayload:entity1118111111"))
        );

        let (payload, signature) = signed_alias_payload(
            &pair,
            alias_payload(
                AliasAction::Add,
                b"did:openpayload:entity1118111111",
                Some(b"SalesGroup"),
                None,
                None,
                1,
            ),
        );
        assert_noop!(
            DidRegistry::add_alias(
                RuntimeOrigin::none(),
                b"did:openpayload:entity1118111111".to_vec(),
                b" SalesGroup ".to_vec(),
                payload,
                signature,
                b"root".to_vec(),
            ),
            Error::<Test>::InvalidAliasPayload
        );
    });
}

#[test]
fn aliases_reject_delivery_target_delimiters() {
    new_test_ext().execute_with(|| {
        let pair = root_pair();
        let raw_did = b"did:openpayload:entity1a1iasde1imit";
        register_with_root(raw_did, &pair);

        for invalid in [b"sales@example.com".as_slice(), b"sales#legal".as_slice()] {
            assert_noop!(
                DidRegistry::set_alias(
                    RuntimeOrigin::signed(1),
                    raw_did.to_vec(),
                    invalid.to_vec(),
                ),
                Error::<Test>::InvalidAlias
            );
        }
    });
}

#[test]
fn add_verification_method_and_authentication_succeed() {
    new_test_ext().execute_with(|| {
        let pair = root_pair();
        register_with_root(b"did:openpayload:entity1doc111111", &pair);
        let method = verification_method(
            b"did:openpayload:entity1doc111111#device_001",
            b"did:openpayload:entity1doc111111",
            11,
        );

        let (payload, signature) = signed_document_payload(
            &pair,
            document_payload(
                DocumentAction::AddVerificationMethod,
                b"did:openpayload:entity1doc111111",
                Some(method.clone()),
                None,
                0,
            ),
        );
        assert_ok!(DidRegistry::add_verification_method(
            RuntimeOrigin::none(),
            b"did:openpayload:entity1doc111111".to_vec(),
            method,
            payload,
            signature,
            b"root".to_vec(),
        ));

        let (payload, signature) = signed_document_payload(
            &pair,
            document_payload(
                DocumentAction::AddAuthentication,
                b"did:openpayload:entity1doc111111",
                None,
                Some(b"did:openpayload:entity1doc111111#device_001"),
                1,
            ),
        );
        assert_ok!(DidRegistry::add_authentication(
            RuntimeOrigin::none(),
            b"did:openpayload:entity1doc111111".to_vec(),
            b"did:openpayload:entity1doc111111#device_001".to_vec(),
            payload,
            signature,
            b"root".to_vec(),
        ));

        let doc = Dids::<Test>::get(did(b"did:openpayload:entity1doc111111"))
            .unwrap()
            .document
            .unwrap();
        assert_eq!(doc.verification_method.len(), 1);
        assert_eq!(
            doc.authentication.unwrap()[0].as_slice(),
            b"did:openpayload:entity1doc111111#device_001"
        );
        assert_eq!(
            DocumentNonces::<Test>::get(did(b"did:openpayload:entity1doc111111")),
            2
        );
    });
}

#[test]
fn add_service_with_authorization_and_priority_succeeds() {
    new_test_ext().execute_with(|| {
        let pair = root_pair();
        register_with_root(b"did:openpayload:entity1svc111111", &pair);
        let svc = service(
            b"did:openpayload:entity1svc111111#cache",
            b"OpenPayloadCacheService",
            b"https://cache.example.net:7004",
            Some(vec![b"did:openpayload:entity1svc111111#keys-1"]),
            Some(100),
        );
        let (payload, signature) = signed_document_payload(
            &pair,
            document_service_payload(
                DocumentAction::AddService,
                b"did:openpayload:entity1svc111111",
                svc.clone(),
                0,
            ),
        );

        assert_ok!(DidRegistry::add_service(
            RuntimeOrigin::none(),
            b"did:openpayload:entity1svc111111".to_vec(),
            svc,
            payload,
            signature,
            b"root".to_vec(),
        ));

        let doc = Dids::<Test>::get(did(b"did:openpayload:entity1svc111111"))
            .unwrap()
            .document
            .unwrap();
        let stored = &doc.service.unwrap()[0];
        assert_eq!(
            stored.authorization.as_ref().unwrap()[0].as_slice(),
            b"did:openpayload:entity1svc111111#keys-1"
        );
        assert_eq!(stored.priority, Some(100));
        assert!(
            <DidRegistry as pallet_delivery_policy::DidProvider<u64>>::service_supports_delivery(
                b"did:openpayload:entity1svc111111",
                b"did:openpayload:entity1svc111111#cache",
                pallet_delivery_policy::DeliveryServiceKind::Cache,
            )
        );
        assert!(
            !<DidRegistry as pallet_delivery_policy::DidProvider<u64>>::service_supports_delivery(
                b"did:openpayload:entity1svc111111",
                b"did:openpayload:entity1svc111111#cache",
                pallet_delivery_policy::DeliveryServiceKind::Relay,
            )
        );
        assert!(
            !<DidRegistry as pallet_delivery_policy::DidProvider<u64>>::service_supports_delivery(
                b"did:openpayload:entity1svc111111",
                b"did:openpayload:entity1svc111111#missing",
                pallet_delivery_policy::DeliveryServiceKind::Cache,
            )
        );
    });
}

#[test]
fn update_service_with_authorization_and_priority_succeeds() {
    new_test_ext().execute_with(|| {
        let pair = root_pair();
        register_with_root(b"did:openpayload:entity1svc111211", &pair);
        let svc = service(
            b"did:openpayload:entity1svc111211#relay",
            b"OpenPayloadRelayService",
            b"https://relay.example.net:7001",
            None,
            None,
        );
        let (payload, signature) = signed_document_payload(
            &pair,
            document_service_payload(
                DocumentAction::AddService,
                b"did:openpayload:entity1svc111211",
                svc.clone(),
                0,
            ),
        );
        assert_ok!(DidRegistry::add_service(
            RuntimeOrigin::none(),
            b"did:openpayload:entity1svc111211".to_vec(),
            svc,
            payload,
            signature,
            b"root".to_vec(),
        ));

        let updated = service(
            b"did:openpayload:entity1svc111211#relay",
            b"OpenPayloadRelayService",
            b"https://relay-2.example.net:7001",
            Some(vec![b"did:openpayload:entity1svc111211#keys-1"]),
            Some(u32::MAX),
        );
        let (payload, signature) = signed_document_payload(
            &pair,
            document_service_payload(
                DocumentAction::UpdateService,
                b"did:openpayload:entity1svc111211",
                updated.clone(),
                1,
            ),
        );
        assert_ok!(DidRegistry::update_service(
            RuntimeOrigin::none(),
            b"did:openpayload:entity1svc111211".to_vec(),
            updated,
            payload,
            signature,
            b"root".to_vec(),
        ));

        let doc = Dids::<Test>::get(did(b"did:openpayload:entity1svc111211"))
            .unwrap()
            .document
            .unwrap();
        let stored = &doc.service.unwrap()[0];
        assert_eq!(
            stored.service_endpoint[0].as_slice(),
            b"https://relay-2.example.net:7001"
        );
        assert_eq!(
            stored.authorization.as_ref().unwrap()[0].as_slice(),
            b"did:openpayload:entity1svc111211#keys-1"
        );
        assert_eq!(stored.priority, Some(u32::MAX));
    });
}

#[test]
fn legacy_service_without_authorization_or_priority_still_succeeds() {
    new_test_ext().execute_with(|| {
        let pair = root_pair();
        register_with_root(b"did:openpayload:entity1svc111311", &pair);
        let svc = service(
            b"did:openpayload:entity1svc111311#directory",
            b"OpenPayloadDirectory",
            b"https://directory.example",
            None,
            None,
        );
        let (payload, signature) = signed_document_payload(
            &pair,
            document_service_payload(
                DocumentAction::AddService,
                b"did:openpayload:entity1svc111311",
                svc.clone(),
                0,
            ),
        );
        assert_ok!(DidRegistry::add_service(
            RuntimeOrigin::none(),
            b"did:openpayload:entity1svc111311".to_vec(),
            svc,
            payload,
            signature,
            b"root".to_vec(),
        ));

        let updated = service(
            b"did:openpayload:entity1svc111311#directory",
            b"OpenPayloadDirectory",
            b"https://directory-2.example",
            None,
            None,
        );
        let (payload, signature) = signed_document_payload(
            &pair,
            document_service_payload(
                DocumentAction::UpdateService,
                b"did:openpayload:entity1svc111311",
                updated.clone(),
                1,
            ),
        );
        assert_ok!(DidRegistry::update_service(
            RuntimeOrigin::none(),
            b"did:openpayload:entity1svc111311".to_vec(),
            updated,
            payload,
            signature,
            b"root".to_vec(),
        ));

        let doc = Dids::<Test>::get(did(b"did:openpayload:entity1svc111311"))
            .unwrap()
            .document
            .unwrap();
        let stored = &doc.service.unwrap()[0];
        assert!(stored.authorization.is_none());
        assert!(stored.priority.is_none());
    });
}

#[test]
fn service_with_max_authorization_keys_is_accepted() {
    new_test_ext().execute_with(|| {
        let pair = root_pair();
        register_with_root(b"did:openpayload:entity1svc111411", &pair);
        let authorization = (0..max_service_authorization_keys())
            .map(|index| id(format!("did:openpayload:entity1svc111411#keys-{index}").as_bytes()))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let svc = Service::<Test> {
            id: id(b"did:openpayload:entity1svc111411#cache"),
            type_: b"OpenPayloadCacheService".to_vec().try_into().unwrap(),
            service_endpoint: vec![b"https://cache.example.net:7004"
                .to_vec()
                .try_into()
                .unwrap()]
            .try_into()
            .unwrap(),
            authorization: Some(authorization),
            priority: Some(1),
        };
        let (payload, signature) = signed_document_payload(
            &pair,
            document_service_payload(
                DocumentAction::AddService,
                b"did:openpayload:entity1svc111411",
                svc.clone(),
                0,
            ),
        );

        assert_ok!(DidRegistry::add_service(
            RuntimeOrigin::none(),
            b"did:openpayload:entity1svc111411".to_vec(),
            svc,
            payload,
            signature,
            b"root".to_vec(),
        ));

        let doc = Dids::<Test>::get(did(b"did:openpayload:entity1svc111411"))
            .unwrap()
            .document
            .unwrap();
        assert_eq!(
            doc.service.unwrap()[0]
                .authorization
                .as_ref()
                .unwrap()
                .len() as u32,
            max_service_authorization_keys()
        );
    });
}

#[test]
fn service_authorization_rejects_empty_reference_and_excess_entries() {
    new_test_ext().execute_with(|| {
        let pair = root_pair();
        register_with_root(b"did:openpayload:entity1svc111511", &pair);
        let svc = Service::<Test> {
            id: id(b"did:openpayload:entity1svc111511#cache"),
            type_: b"OpenPayloadCacheService".to_vec().try_into().unwrap(),
            service_endpoint: vec![b"https://cache.example.net:7004"
                .to_vec()
                .try_into()
                .unwrap()]
            .try_into()
            .unwrap(),
            authorization: Some(vec![id(b"")].try_into().unwrap()),
            priority: None,
        };
        let (payload, signature) = signed_document_payload(
            &pair,
            document_service_payload(
                DocumentAction::AddService,
                b"did:openpayload:entity1svc111511",
                svc.clone(),
                0,
            ),
        );

        assert_noop!(
            DidRegistry::add_service(
                RuntimeOrigin::none(),
                b"did:openpayload:entity1svc111511".to_vec(),
                svc,
                payload,
                signature,
                b"root".to_vec(),
            ),
            Error::<Test>::InvalidDocument
        );

        let too_many = (0..(max_service_authorization_keys() + 1))
            .map(|index| id(format!("did:openpayload:entity1svc111511#keys-{index}").as_bytes()))
            .collect::<Vec<_>>();
        assert!(crate::SvcAuthorizationOf::<Test>::try_from(too_many).is_err());
    });
}

#[test]
fn document_patch_replay_fails() {
    new_test_ext().execute_with(|| {
        let pair = root_pair();
        register_with_root(b"did:openpayload:entity1doc111211", &pair);
        let method = verification_method(
            b"did:openpayload:entity1doc111211#device_001",
            b"did:openpayload:entity1doc111211",
            12,
        );
        let (payload, signature) = signed_document_payload(
            &pair,
            document_payload(
                DocumentAction::AddVerificationMethod,
                b"did:openpayload:entity1doc111211",
                Some(method.clone()),
                None,
                0,
            ),
        );

        assert_ok!(DidRegistry::add_verification_method(
            RuntimeOrigin::none(),
            b"did:openpayload:entity1doc111211".to_vec(),
            method.clone(),
            payload.clone(),
            signature.clone(),
            b"root".to_vec(),
        ));
        assert_noop!(
            DidRegistry::add_verification_method(
                RuntimeOrigin::none(),
                b"did:openpayload:entity1doc111211".to_vec(),
                method,
                payload,
                signature,
                b"root".to_vec(),
            ),
            Error::<Test>::InvalidDocumentNonce
        );
    });
}

#[test]
fn unsigned_document_patch_validation_rejects_invalid_embedded_authorization() {
    new_test_ext().execute_with(|| {
        let pair = root_pair();
        let wrong_pair = alternate_pair();
        register_with_root(b"did:openpayload:entity1doc111311", &pair);
        let method = verification_method(
            b"did:openpayload:entity1doc111311#device_001",
            b"did:openpayload:entity1doc111311",
            13,
        );
        let (payload, signature) = signed_document_payload(
            &wrong_pair,
            document_payload(
                DocumentAction::AddVerificationMethod,
                b"did:openpayload:entity1doc111311",
                Some(method.clone()),
                None,
                0,
            ),
        );
        let call = crate::Call::<Test>::add_verification_method {
            did: b"did:openpayload:entity1doc111311".to_vec(),
            method,
            signed_payload: payload,
            signature,
            signer_key_id: b"root".to_vec(),
        };

        assert!(DidRegistry::validate_unsigned_call(&call).is_err());
    });
}

#[test]
fn authorization_expiry_uses_epoch_millis_timestamp() {
    new_test_ext().execute_with(|| {
        Timestamp::set_timestamp(NOW_MILLIS);
        let pair = root_pair();
        register_with_root(b"did:openpayload:entity1expiry111", &pair);

        let (payload, signature) = signed_alias_payload(
            &pair,
            alias_payload_until(
                AliasAction::Add,
                b"did:openpayload:entity1expiry111",
                Some(b"current"),
                None,
                None,
                0,
                NOW_MILLIS,
            ),
        );
        assert_noop!(
            DidRegistry::add_alias(
                RuntimeOrigin::none(),
                b"did:openpayload:entity1expiry111".to_vec(),
                b"current".to_vec(),
                payload,
                signature,
                b"root".to_vec(),
            ),
            Error::<Test>::AliasAuthorizationExpired
        );
        assert_eq!(
            AliasNonces::<Test>::get(did(b"did:openpayload:entity1expiry111")),
            0
        );

        let method = verification_method(
            b"did:openpayload:entity1expiry111#device",
            b"did:openpayload:entity1expiry111",
            21,
        );
        let (payload, signature) = signed_document_payload(
            &pair,
            document_payload_until(
                DocumentAction::AddVerificationMethod,
                b"did:openpayload:entity1expiry111",
                Some(method.clone()),
                None,
                0,
                PAST_MILLIS,
                b"root",
            ),
        );
        assert_noop!(
            DidRegistry::add_verification_method(
                RuntimeOrigin::none(),
                b"did:openpayload:entity1expiry111".to_vec(),
                method,
                payload,
                signature,
                b"root".to_vec(),
            ),
            Error::<Test>::DocumentAuthorizationExpired
        );
        assert_eq!(
            DocumentNonces::<Test>::get(did(b"did:openpayload:entity1expiry111")),
            0
        );

        let new_root = vec![42u8; 32];
        let (payload, signature) = signed_root_pubkey_payload(
            &pair,
            root_pubkey_payload_until(
                b"did:openpayload:entity1expiry111",
                new_root.clone(),
                0,
                PAST_MILLIS,
            ),
        );
        assert_noop!(
            DidRegistry::update_root_pubkey(
                RuntimeOrigin::none(),
                b"did:openpayload:entity1expiry111".to_vec(),
                new_root,
                payload,
                signature,
                b"root".to_vec(),
            ),
            Error::<Test>::RootPubkeyAuthorizationExpired
        );
        assert_eq!(
            RootPubkeyNonces::<Test>::get(did(b"did:openpayload:entity1expiry111")),
            0
        );
    });
}

#[test]
fn future_epoch_millis_payload_is_accepted_and_increments_nonce_after_success() {
    new_test_ext().execute_with(|| {
        Timestamp::set_timestamp(NOW_MILLIS);
        let pair = root_pair();
        register_with_root(b"did:openpayload:entity1future111", &pair);

        add_alias_with_nonce(
            &pair,
            b"did:openpayload:entity1future111",
            b"future_alias",
            0,
        );
        assert_eq!(
            AliasNonces::<Test>::get(did(b"did:openpayload:entity1future111")),
            1
        );

        let method = verification_method(
            b"did:openpayload:entity1future111#device",
            b"did:openpayload:entity1future111",
            22,
        );
        let (payload, signature) = signed_document_payload(
            &pair,
            document_payload(
                DocumentAction::AddVerificationMethod,
                b"did:openpayload:entity1future111",
                Some(method.clone()),
                None,
                0,
            ),
        );
        assert_ok!(DidRegistry::add_verification_method(
            RuntimeOrigin::none(),
            b"did:openpayload:entity1future111".to_vec(),
            method,
            payload,
            signature,
            b"root".to_vec(),
        ));
        assert_eq!(
            DocumentNonces::<Test>::get(did(b"did:openpayload:entity1future111")),
            1
        );

        let new_root = vec![23u8; 32];
        let (payload, signature) = signed_root_pubkey_payload(
            &pair,
            root_pubkey_payload(b"did:openpayload:entity1future111", new_root.clone(), 0),
        );
        assert_ok!(DidRegistry::update_root_pubkey(
            RuntimeOrigin::none(),
            b"did:openpayload:entity1future111".to_vec(),
            new_root,
            payload,
            signature,
            b"root".to_vec(),
        ));
        assert_eq!(
            RootPubkeyNonces::<Test>::get(did(b"did:openpayload:entity1future111")),
            1
        );
    });
}

#[test]
fn valid_until_scale_encoding_is_u64_little_endian() {
    new_test_ext().execute_with(|| {
        let valid_until = 0x0102_0304_0506_0708u64;
        let payload = alias_payload_until(
            AliasAction::Add,
            b"did:openpayload:entity1sca1e1111",
            Some(b"scale"),
            None,
            None,
            0,
            valid_until,
        )
        .encode();
        let mut expected_suffix = valid_until.to_le_bytes().to_vec();
        expected_suffix.extend_from_slice(&[16, b'r', b'o', b'o', b't']);
        assert!(payload.ends_with(&expected_suffix));
    });
}

#[test]
fn did_registry_call_indices_remain_unchanged() {
    new_test_ext().execute_with(|| {
        let method = verification_method(
            b"did:openpayload:entity1index1111#vm",
            b"did:openpayload:entity1index1111",
            31,
        );
        let key_agreement = KeyAgreement::<Test> {
            id: id(b"did:openpayload:entity1index1111#ka"),
            type_: b"X25519KeyAgreementKey2020".to_vec().try_into().unwrap(),
            controller: id(b"did:openpayload:entity1index1111"),
            public_key_multibase: vec![32u8; 32].try_into().unwrap(),
        };
        let service = Service::<Test> {
            id: id(b"did:openpayload:entity1index1111#svc"),
            type_: b"OpenPayloadDirectory".to_vec().try_into().unwrap(),
            service_endpoint: vec![b"https://directory.example".to_vec().try_into().unwrap()]
                .try_into()
                .unwrap(),
            authorization: None,
            priority: None,
        };

        let calls: Vec<(crate::Call<Test>, u8)> = vec![
            (
                crate::Call::<Test>::set_document_with_proof {
                    did: vec![],
                    doc_blob: vec![],
                    timestamp: vec![],
                    pubkey: vec![],
                    signature: vec![],
                },
                5,
            ),
            (
                crate::Call::<Test>::register_with_document_proof {
                    did: vec![],
                    alias: None,
                    timestamp: vec![],
                    pubkey: vec![],
                    signature: vec![],
                    doc_blob: vec![],
                },
                6,
            ),
            (
                crate::Call::<Test>::register_with_proof {
                    did: vec![],
                    alias: None,
                    timestamp: vec![],
                    pubkey: vec![],
                    signature: vec![],
                },
                10,
            ),
            (
                crate::Call::<Test>::add_alias {
                    did: vec![],
                    alias: vec![],
                    signed_payload: vec![],
                    signature: vec![],
                    signer_key_id: vec![],
                },
                11,
            ),
            (
                crate::Call::<Test>::update_alias {
                    did: vec![],
                    old_alias: vec![],
                    new_alias: vec![],
                    signed_payload: vec![],
                    signature: vec![],
                    signer_key_id: vec![],
                },
                12,
            ),
            (
                crate::Call::<Test>::remove_alias {
                    did: vec![],
                    alias: vec![],
                    signed_payload: vec![],
                    signature: vec![],
                    signer_key_id: vec![],
                },
                13,
            ),
            (
                crate::Call::<Test>::add_verification_method {
                    did: vec![],
                    method: method.clone(),
                    signed_payload: vec![],
                    signature: vec![],
                    signer_key_id: vec![],
                },
                14,
            ),
            (
                crate::Call::<Test>::update_verification_method {
                    did: vec![],
                    method,
                    signed_payload: vec![],
                    signature: vec![],
                    signer_key_id: vec![],
                },
                15,
            ),
            (
                crate::Call::<Test>::remove_verification_method {
                    did: vec![],
                    method_id: vec![],
                    signed_payload: vec![],
                    signature: vec![],
                    signer_key_id: vec![],
                },
                16,
            ),
            (
                crate::Call::<Test>::add_authentication {
                    did: vec![],
                    method_id: vec![],
                    signed_payload: vec![],
                    signature: vec![],
                    signer_key_id: vec![],
                },
                17,
            ),
            (
                crate::Call::<Test>::remove_authentication {
                    did: vec![],
                    method_id: vec![],
                    signed_payload: vec![],
                    signature: vec![],
                    signer_key_id: vec![],
                },
                18,
            ),
            (
                crate::Call::<Test>::add_key_agreement {
                    did: vec![],
                    key_agreement: key_agreement.clone(),
                    signed_payload: vec![],
                    signature: vec![],
                    signer_key_id: vec![],
                },
                19,
            ),
            (
                crate::Call::<Test>::update_key_agreement {
                    did: vec![],
                    key_agreement,
                    signed_payload: vec![],
                    signature: vec![],
                    signer_key_id: vec![],
                },
                20,
            ),
            (
                crate::Call::<Test>::remove_key_agreement {
                    did: vec![],
                    key_agreement_id: vec![],
                    signed_payload: vec![],
                    signature: vec![],
                    signer_key_id: vec![],
                },
                21,
            ),
            (
                crate::Call::<Test>::add_service {
                    did: vec![],
                    service: service.clone(),
                    signed_payload: vec![],
                    signature: vec![],
                    signer_key_id: vec![],
                },
                22,
            ),
            (
                crate::Call::<Test>::update_service {
                    did: vec![],
                    service,
                    signed_payload: vec![],
                    signature: vec![],
                    signer_key_id: vec![],
                },
                23,
            ),
            (
                crate::Call::<Test>::remove_service {
                    did: vec![],
                    service_id: vec![],
                    signed_payload: vec![],
                    signature: vec![],
                    signer_key_id: vec![],
                },
                24,
            ),
            (
                crate::Call::<Test>::update_root_pubkey {
                    did: vec![],
                    new_root_pubkey: vec![],
                    signed_payload: vec![],
                    signature: vec![],
                    signer_key_id: vec![],
                },
                25,
            ),
            (crate::Call::<Test>::deactivate_did { did: vec![] }, 26),
            (
                crate::Call::<Test>::update_device {
                    did: vec![],
                    old_device_id: vec![],
                    new_device_id: vec![],
                },
                27,
            ),
            (
                crate::Call::<Test>::remove_device {
                    did: vec![],
                    device_id: vec![],
                },
                28,
            ),
            (
                crate::Call::<Test>::apply_control_with_proof {
                    signed_payload: vec![],
                    signature: vec![],
                    signer_key_id: vec![],
                },
                29,
            ),
        ];

        for (call, expected_index) in calls {
            assert_eq!(call.encode()[0], expected_index);
        }
    });
}

#[test]
fn non_root_signer_accepts_base58btc_multibase_public_key() {
    new_test_ext().execute_with(|| {
        Timestamp::set_timestamp(NOW_MILLIS);
        let root = root_pair();
        let device = alternate_pair();
        let raw_did = b"did:openpayload:entity1mu1tibase";
        let signer_id = b"did:openpayload:entity1mu1tibase#device";
        register_with_root(raw_did, &root);

        let method =
            verification_method_with_key(signer_id, raw_did, multibase_ed25519_public_key(&device));
        let (payload, signature) = signed_document_payload(
            &root,
            document_payload(
                DocumentAction::AddVerificationMethod,
                raw_did,
                Some(method.clone()),
                None,
                0,
            ),
        );
        assert_ok!(DidRegistry::add_verification_method(
            RuntimeOrigin::none(),
            raw_did.to_vec(),
            method,
            payload,
            signature,
            b"root".to_vec(),
        ));

        let (payload, signature) = signed_document_payload(
            &device,
            document_payload_until(
                DocumentAction::AddAuthentication,
                raw_did,
                None,
                Some(signer_id),
                1,
                FUTURE_MILLIS,
                signer_id,
            ),
        );
        assert_ok!(DidRegistry::add_authentication(
            RuntimeOrigin::none(),
            raw_did.to_vec(),
            signer_id.to_vec(),
            payload,
            signature,
            signer_id.to_vec(),
        ));
        assert_eq!(DocumentNonces::<Test>::get(did(raw_did)), 2);
    });
}

#[test]
fn non_owner_cannot_change_policy_links() {
    new_test_ext().execute_with(|| {
        let pair = root_pair();
        register_with_root(b"did:openpayload:entity1po1icy111", &pair);

        assert_noop!(
            DidRegistry::set_delivery_policy_links(
                RuntimeOrigin::signed(2),
                b"did:openpayload:entity1po1icy111".to_vec(),
                Some(b"did:openpayload:entity1po1icy111".to_vec()),
                vec![],
                vec![],
            ),
            Error::<Test>::NotDidOwner
        );
    });
}

#[test]
fn signed_mutations_require_owner() {
    new_test_ext().execute_with(|| {
        let pair = root_pair();
        register_with_root(b"did:openpayload:entity1a1ias1111", &pair);

        assert_noop!(
            DidRegistry::set_alias(
                RuntimeOrigin::signed(2),
                b"did:openpayload:entity1a1ias1111".to_vec(),
                b"user_a".to_vec()
            ),
            Error::<Test>::NotDidOwner
        );
        assert_ok!(DidRegistry::set_alias(
            RuntimeOrigin::signed(1),
            b"did:openpayload:entity1a1ias1111".to_vec(),
            b"user_a".to_vec()
        ));
    });
}

#[test]
fn control_proof_manages_devices_without_using_account_owner_origin() {
    new_test_ext().execute_with(|| {
        let pair = root_pair();
        let raw_did = b"did:openpayload:entity1proof1device";
        register_with_root(raw_did, &pair);
        let device_id: DeviceIdOf = b"phone-1".to_vec().try_into().unwrap();
        let (payload, signature) = signed_control_payload(
            &pair,
            raw_did,
            ControlAction::AddDevice {
                device_id: device_id.clone(),
            },
            0,
        );

        assert_ok!(DidRegistry::apply_control_with_proof(
            RuntimeOrigin::none(),
            payload,
            signature,
            b"root".to_vec(),
        ));

        let record = Dids::<Test>::get(did(raw_did)).unwrap();
        assert_eq!(record.devices.unwrap()[0].device_id, device_id);
        assert_eq!(ControlNonces::<Test>::get(did(raw_did)), 1);
    });
}

#[test]
fn root_authorized_delete_removes_did_aliases_devices_links_and_nonces() {
    new_test_ext().execute_with(|| {
        let pair = root_pair();
        let raw_did = b"did:openpayload:entity1de1ete1cascade";
        let raw_alias = b"delete-me";
        register_with_root(raw_did, &pair);
        add_alias_with_nonce(&pair, raw_did, raw_alias, 0);

        let device_id: DeviceIdOf = b"phone-1".to_vec().try_into().unwrap();
        let (payload, signature) =
            signed_control_payload(&pair, raw_did, ControlAction::AddDevice { device_id }, 0);
        assert_ok!(DidRegistry::apply_control_with_proof(
            RuntimeOrigin::none(),
            payload,
            signature,
            b"root".to_vec(),
        ));
        assert_ok!(DidRegistry::set_delivery_policy_links(
            RuntimeOrigin::signed(1),
            raw_did.to_vec(),
            Some(b"recipient-policy".to_vec()),
            vec![b"tag-policy".to_vec()],
            vec![b"persona-policy".to_vec()],
        ));
        DocumentNonces::<Test>::insert(did(raw_did), 3);
        RootPubkeyNonces::<Test>::insert(did(raw_did), 4);

        let (payload, signature) =
            signed_control_payload(&pair, raw_did, ControlAction::DeleteDid, 1);
        assert_ok!(DidRegistry::apply_control_with_proof(
            RuntimeOrigin::none(),
            payload,
            signature,
            b"root".to_vec(),
        ));

        assert!(!Dids::<Test>::contains_key(did(raw_did)));
        assert!(!AliasIndex::<Test>::contains_key(alias(raw_alias)));
        assert!(!AliasNonces::<Test>::contains_key(did(raw_did)));
        assert!(!DocumentNonces::<Test>::contains_key(did(raw_did)));
        assert!(!RootPubkeyNonces::<Test>::contains_key(did(raw_did)));
        assert!(!ControlNonces::<Test>::contains_key(did(raw_did)));
        assert_eq!(ControlAction::<Test>::DeleteDid.encode()[0], 7);
    });
}

#[test]
fn delete_refuses_a_did_that_still_controls_an_application() {
    new_test_ext().execute_with(|| {
        let pair = root_pair();
        let raw_did = b"did:openpayload:entity1de1ete1cascade";
        register_with_root(raw_did, &pair);
        sp_io::storage::set(b"test:application-control-did", raw_did);
        assert_noop!(
            DidRegistry::deactivate_did(RuntimeOrigin::signed(1), raw_did.to_vec()),
            Error::<Test>::DidControlsApplication
        );
        let (deactivate_payload, deactivate_signature) =
            signed_control_payload(&pair, raw_did, ControlAction::DeactivateDid, 0);
        assert_noop!(
            DidRegistry::apply_control_with_proof(
                RuntimeOrigin::none(),
                deactivate_payload,
                deactivate_signature,
                b"root".to_vec(),
            ),
            Error::<Test>::DidControlsApplication
        );
        assert!(!Dids::<Test>::get(did(raw_did)).unwrap().deactivated);
        let (payload, signature) =
            signed_control_payload(&pair, raw_did, ControlAction::DeleteDid, 0);

        assert_noop!(
            DidRegistry::apply_control_with_proof(
                RuntimeOrigin::none(),
                payload.clone(),
                signature.clone(),
                b"root".to_vec(),
            ),
            Error::<Test>::DidControlsApplication
        );
        assert!(Dids::<Test>::contains_key(did(raw_did)));
        assert_eq!(ControlNonces::<Test>::get(did(raw_did)), 0);

        sp_io::storage::clear(b"test:application-control-did");
        assert_ok!(DidRegistry::apply_control_with_proof(
            RuntimeOrigin::none(),
            payload,
            signature,
            b"root".to_vec(),
        ));
        assert!(!Dids::<Test>::contains_key(did(raw_did)));
    });
}

#[test]
fn delete_requires_a_valid_root_authorization() {
    new_test_ext().execute_with(|| {
        let pair = root_pair();
        let raw_did = b"did:openpayload:entity1de1ete1auth";
        register_with_root(raw_did, &pair);
        let (payload, signature) =
            signed_control_payload(&alternate_pair(), raw_did, ControlAction::DeleteDid, 0);

        assert_noop!(
            DidRegistry::apply_control_with_proof(
                RuntimeOrigin::none(),
                payload,
                signature,
                b"root".to_vec(),
            ),
            Error::<Test>::InvalidSignature
        );
        assert!(Dids::<Test>::contains_key(did(raw_did)));
    });
}

#[test]
fn control_proof_rejects_replay_and_invalid_signer() {
    new_test_ext().execute_with(|| {
        let pair = root_pair();
        let wrong_pair = alternate_pair();
        let raw_did = b"did:openpayload:entity1proof1contro1";
        register_with_root(raw_did, &pair);
        let (payload, wrong_signature) =
            signed_control_payload(&wrong_pair, raw_did, ControlAction::DeactivateDid, 0);
        assert_noop!(
            DidRegistry::apply_control_with_proof(
                RuntimeOrigin::none(),
                payload,
                wrong_signature,
                b"root".to_vec(),
            ),
            Error::<Test>::InvalidSignature
        );

        let (payload, signature) =
            signed_control_payload(&pair, raw_did, ControlAction::DeactivateDid, 0);
        assert_ok!(DidRegistry::apply_control_with_proof(
            RuntimeOrigin::none(),
            payload.clone(),
            signature.clone(),
            b"root".to_vec(),
        ));
        assert_noop!(
            DidRegistry::apply_control_with_proof(
                RuntimeOrigin::none(),
                payload,
                signature,
                b"root".to_vec(),
            ),
            Error::<Test>::DidDeactivated
        );
    });
}
