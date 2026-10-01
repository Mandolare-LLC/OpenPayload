use crate::{
    mock::*, ActiveRewardPolicyVersion, AvailabilitySummaries, CacheQueueDepthEpoch,
    CacheQueueDepthEpochs, CacheRewardHistoryRetentionEpochsValue, CacheRewardRecord,
    CacheRewardRecords, CacheTriggerEvidenceEnabled, CacheTriggerReceipt, CacheTriggerTicket,
    CacheTriggerTicketById, CacheTriggerTickets, EpochRawRewardRecordCounts, EpochRawRewardTotals,
    EpochSettlements, Error, NextRewardEpochToClose, NodeRole, Nodes, OperatorByDid,
    OperatorQueueDepthEpoch, OperatorQueueDepthEpochs, Operators, OutageAggregates,
    OutstandingRewardLiabilities, PendingRootSponsor, ProbeResult, RewardEligibleCaches,
    RewardPaymentsPaused, RewardPaymentsStartEpoch, RewardYearStates, RootSponsor,
    SponsorAuthorities,
};
use codec::Encode;
use frame_support::{
    assert_noop, assert_ok,
    traits::{GetStorageVersion, StorageVersion},
};
use pallet_delivery_policy::{
    DeliveryPolicy as Policy, Error as DeliveryPolicyError, ExpirationBehavior, ReleasePricing,
};
use sp_core::{ed25519, ByteArray, Pair};

fn did(raw: &[u8]) -> crate::DidOf<Test> {
    raw.to_vec().try_into().unwrap()
}

fn node_id(raw: &[u8]) -> crate::NodeIdOf<Test> {
    raw.to_vec().try_into().unwrap()
}

fn policy(ttl: u64, burn: Balance) -> Policy<Test> {
    Policy {
        effective_ttl: ttl,
        max_message_bytes: 2048,
        cache_eligible: true,
        replication: Some(2),
        encrypted_header_preview_bytes: Some(256),
        release_pricing: Some(ReleasePricing {
            base_fee: burn,
            per_kib_fee: 1,
        }),
        expiration_behavior: Some(ExpirationBehavior::DeleteOnExpiry),
    }
}

fn registration_signature(pair: &ed25519::Pair, did: &[u8], timestamp: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(did);
    payload.push(b'|');
    payload.extend_from_slice(timestamp);
    pair.sign(&payload).to_raw_vec()
}

fn register_did(raw_did: &[u8], seed: u8) {
    let pair = ed25519::Pair::from_seed(&[seed; 32]);
    let timestamp = b"0".to_vec();
    let signature = registration_signature(&pair, raw_did, &timestamp);
    assert_ok!(DidRegistry::register_with_proof(
        RuntimeOrigin::signed(1),
        raw_did.to_vec(),
        None,
        timestamp,
        pair.public().to_raw_vec(),
        signature,
    ));
}

fn set_epoch(epoch: u64) {
    System::set_block_number(epoch * 10);
}

fn sig(seed: u8) -> Vec<u8> {
    vec![seed; 64]
}

fn register_operator(account: AccountId, did: &[u8]) {
    let root = ed25519::Pair::from_seed(&[account as u8; 32]);
    let timestamp = b"0".to_vec();
    let registration_signature = registration_signature(&root, did, &timestamp);
    assert_ok!(DidRegistry::register_with_proof(
        RuntimeOrigin::signed(account),
        did.to_vec(),
        None,
        timestamp,
        root.public().to_raw_vec(),
        registration_signature,
    ));
    let bond = Some(100);
    let authorization = ResourceRewards::operator_registration_payload(&account, did, &bond);
    let did_root_signature = root.sign(&authorization).to_raw_vec();
    assert_ok!(ResourceRewards::register_operator(
        RuntimeOrigin::signed(account),
        did.to_vec(),
        bond,
        did_root_signature,
    ));
}

#[allow(clippy::too_many_arguments)]
fn register_node(
    account: AccountId,
    operator_did: &[u8],
    node_id: &[u8],
    role: NodeRole,
    capacity: u64,
    region: &[u8],
    cluster: &[u8],
    network: &[u8],
) {
    assert_ok!(ResourceRewards::register_node(
        RuntimeOrigin::signed(account),
        operator_did.to_vec(),
        node_id.to_vec(),
        role,
        b"https://node.example".to_vec(),
        capacity,
        region.to_vec(),
        b"US".to_vec(),
        vec![60, 3600],
        cluster.to_vec(),
        network.to_vec(),
    ));
}

fn register_cache_and_validator() {
    register_operator(9, b"did:openpayload:operator1cache19");
    register_operator(1, b"did:openpayload:operator1va1idator11");
    assert_ok!(ResourceRewards::set_validator_approval(
        RuntimeOrigin::root(),
        1,
        true,
    ));
    register_node(
        9,
        b"did:openpayload:operator1cache19",
        b"cache-9",
        NodeRole::Cache,
        3_000,
        b"iad",
        b"cache-a",
        b"10.0.0.0/24",
    );
    register_node(
        1,
        b"did:openpayload:operator1va1idator11",
        b"validator-1",
        NodeRole::Validator,
        0,
        b"ord",
        b"validator-a",
        b"10.1.0.0/24",
    );
}

fn register_additional_validator(
    account: AccountId,
    operator_did: &[u8],
    validator_node_id: &[u8],
) {
    register_operator(account, operator_did);
    assert_ok!(ResourceRewards::set_validator_approval(
        RuntimeOrigin::root(),
        account,
        true,
    ));
    register_node(
        account,
        operator_did,
        validator_node_id,
        NodeRole::Validator,
        0,
        b"ord",
        b"validator-extra",
        b"10.4.0.0/24",
    );
}

fn submit_success_probe(epoch: u64) {
    assert_ok!(ResourceRewards::submit_validator_probe(
        RuntimeOrigin::signed(1),
        b"validator-1".to_vec(),
        b"cache-9".to_vec(),
        epoch,
        epoch * 100,
        epoch * 100 + 10,
        ProbeResult::Success,
        sig(1),
    ));
}

fn register_second_validator() {
    register_additional_validator(2, b"did:openpayload:operator1va1idator12", b"validator-2");
}

fn register_relays() {
    register_operator(2, b"did:openpayload:operator1re1ay12");
    register_operator(3, b"did:openpayload:operator1re1ay13");
    register_node(
        2,
        b"did:openpayload:operator1re1ay12",
        b"relay-2",
        NodeRole::Relay,
        0,
        b"sfo",
        b"relay-a",
        b"10.2.0.0/24",
    );
    register_node(
        3,
        b"did:openpayload:operator1re1ay13",
        b"relay-3",
        NodeRole::Relay,
        0,
        b"lhr",
        b"relay-b",
        b"10.3.0.0/24",
    );
}

fn submit_relay_report(account: AccountId, relay: &[u8], epoch: u64, first: u64) {
    assert_ok!(ResourceRewards::submit_relay_outage_report(
        RuntimeOrigin::signed(account),
        relay.to_vec(),
        b"cache-9".to_vec(),
        epoch,
        crate::FailureCategory::Timeout,
        1,
        first,
        first + 10,
        sig(account as u8),
    ));
}

#[test]
fn did_policy_registration_and_cache_policy_lookup_remain_method_agnostic() {
    new_test_ext().execute_with(|| {
        register_did(b"did:openpayload:recipient1111111", 1);
        register_did(b"did:openpayload:tag1work11111111", 2);
        register_did(b"did:openpayload:persona1private1", 3);
        assert_ok!(DidRegistry::set_delivery_policy_links(
            RuntimeOrigin::signed(1),
            b"did:openpayload:recipient1111111".to_vec(),
            Some(b"did:openpayload:recipient1111111".to_vec()),
            vec![b"did:openpayload:tag1work11111111".to_vec()],
            vec![b"did:openpayload:persona1private1".to_vec()],
        ));

        assert_noop!(
            DeliveryPolicy::set_delivery_policy(
                RuntimeOrigin::signed(1),
                b"did:openpayload:recipient1111111".to_vec(),
                policy(100, 10),
            ),
            DeliveryPolicyError::<Test>::LegacyPolicyDeprecated
        );
        assert_noop!(
            DeliveryPolicy::set_tag_policy(
                RuntimeOrigin::signed(1),
                b"did:openpayload:tag1work11111111".to_vec(),
                policy(50, 5),
            ),
            DeliveryPolicyError::<Test>::LegacyPolicyDeprecated
        );
        assert_noop!(
            DeliveryPolicy::set_persona_policy(
                RuntimeOrigin::signed(1),
                b"did:openpayload:persona1private1".to_vec(),
                policy(25, 2),
            ),
            DeliveryPolicyError::<Test>::LegacyPolicyDeprecated
        );
        assert!(
            DeliveryPolicy::resolve_policy_v2(b"did:openpayload:recipient1111111", None, None,)
                .is_none()
        );
    });
}

#[test]
fn operator_and_node_registration_store_resource_metadata() {
    new_test_ext().execute_with(|| {
        register_cache_and_validator();

        assert!(OperatorByDid::<Test>::contains_key(did(
            b"did:openpayload:operator1cache19"
        )));
        let node = Nodes::<Test>::get(node_id(b"cache-9")).unwrap();
        assert_eq!(node.node_role, NodeRole::Cache);
        assert_eq!(node.declared_capacity, 3_000);
        assert_eq!(node.supported_ttl_tiers.len(), 2);
    });
}

#[test]
fn operator_registration_requires_an_active_did_root_authorization() {
    new_test_ext().execute_with(|| {
        let account = 7;
        let raw_did = b"did:openpayload:operator1binding17";
        let bond = Some(100);

        assert_noop!(
            ResourceRewards::register_operator(
                RuntimeOrigin::signed(account),
                raw_did.to_vec(),
                bond,
                vec![0; 64],
            ),
            Error::<Test>::OperatorDidNotRegistered
        );

        let root = ed25519::Pair::from_seed(&[7; 32]);
        let timestamp = b"0".to_vec();
        assert_ok!(DidRegistry::register_with_proof(
            RuntimeOrigin::signed(account),
            raw_did.to_vec(),
            None,
            timestamp.clone(),
            root.public().to_raw_vec(),
            registration_signature(&root, raw_did, &timestamp),
        ));

        let authorization =
            ResourceRewards::operator_registration_payload(&account, raw_did, &bond);
        let wrong_root = ed25519::Pair::from_seed(&[8; 32]);
        assert_noop!(
            ResourceRewards::register_operator(
                RuntimeOrigin::signed(account),
                raw_did.to_vec(),
                bond,
                wrong_root.sign(&authorization).to_raw_vec(),
            ),
            Error::<Test>::InvalidOperatorDidSignature
        );

        assert_noop!(
            ResourceRewards::register_operator(
                RuntimeOrigin::signed(account),
                raw_did.to_vec(),
                Some(101),
                root.sign(&authorization).to_raw_vec(),
            ),
            Error::<Test>::InvalidOperatorDidSignature
        );

        assert_noop!(
            ResourceRewards::register_operator(
                RuntimeOrigin::signed(8),
                raw_did.to_vec(),
                bond,
                root.sign(&authorization).to_raw_vec(),
            ),
            Error::<Test>::InvalidOperatorDidSignature
        );

        assert_ok!(ResourceRewards::register_operator(
            RuntimeOrigin::signed(account),
            raw_did.to_vec(),
            bond,
            root.sign(&authorization).to_raw_vec(),
        ));
        assert_eq!(OperatorByDid::<Test>::get(did(raw_did)), Some(account));
    });
}

#[test]
fn deactivated_did_cannot_be_bound_to_an_operator() {
    new_test_ext().execute_with(|| {
        let account = 6;
        let raw_did = b"did:openpayload:operator1inactive16";
        let bond = Some(100);
        let root = ed25519::Pair::from_seed(&[6; 32]);
        let timestamp = b"0".to_vec();
        assert_ok!(DidRegistry::register_with_proof(
            RuntimeOrigin::signed(account),
            raw_did.to_vec(),
            None,
            timestamp.clone(),
            root.public().to_raw_vec(),
            registration_signature(&root, raw_did, &timestamp),
        ));
        assert_ok!(DidRegistry::deactivate_did(
            RuntimeOrigin::signed(account),
            raw_did.to_vec(),
        ));

        let authorization =
            ResourceRewards::operator_registration_payload(&account, raw_did, &bond);
        assert_noop!(
            ResourceRewards::register_operator(
                RuntimeOrigin::signed(account),
                raw_did.to_vec(),
                bond,
                root.sign(&authorization).to_raw_vec(),
            ),
            Error::<Test>::OperatorDidNotRegistered
        );
    });
}

#[test]
fn availability_scoring_uses_validator_results() {
    new_test_ext().execute_with(|| {
        set_epoch(2);
        register_cache_and_validator();
        submit_success_probe(2);

        let summary = AvailabilitySummaries::<Test>::get(node_id(b"cache-9"), 2);
        assert_eq!(summary.validator_probe_count, 1);
        assert_eq!(summary.availability_score_ppm, 1_000_000);

        assert_ok!(ResourceRewards::submit_validator_probe(
            RuntimeOrigin::signed(1),
            b"validator-1".to_vec(),
            b"cache-9".to_vec(),
            2,
            250,
            260,
            ProbeResult::Timeout,
            sig(9),
        ));
        let summary = AvailabilitySummaries::<Test>::get(node_id(b"cache-9"), 2);
        assert_eq!(summary.availability_score_ppm, 200_000);
    });
}

#[test]
fn validator_success_outweighs_single_relay_report_but_corroborated_reports_penalize() {
    new_test_ext().execute_with(|| {
        set_epoch(3);
        register_cache_and_validator();
        register_relays();
        submit_success_probe(3);

        submit_relay_report(2, b"relay-2", 3, 300);
        let summary = AvailabilitySummaries::<Test>::get(node_id(b"cache-9"), 3);
        assert_eq!(summary.relay_report_count, 1);
        assert_eq!(summary.relay_failure_weight, 0);
        assert_eq!(summary.availability_score_ppm, 1_000_000);

        submit_relay_report(3, b"relay-3", 3, 320);
        let summary = AvailabilitySummaries::<Test>::get(node_id(b"cache-9"), 3);
        assert_eq!(summary.relay_report_count, 2);
        assert_eq!(summary.relay_failure_weight, 2);
        assert_eq!(summary.availability_score_ppm, 800_000);
    });
}

#[test]
fn self_declared_topology_does_not_change_relay_report_weight() {
    new_test_ext().execute_with(|| {
        set_epoch(4);
        register_cache_and_validator();
        register_operator(2, b"did:openpayload:operator1re1ay1same1topo1ogy");
        register_operator(3, b"did:openpayload:operator1re1ay1other1topo1ogy");
        register_node(
            2,
            b"did:openpayload:operator1re1ay1same1topo1ogy",
            b"relay-same-topology",
            NodeRole::Relay,
            0,
            b"iad",
            b"cache-a",
            b"10.0.0.0/24",
        );
        register_node(
            3,
            b"did:openpayload:operator1re1ay1other1topo1ogy",
            b"relay-other-topology",
            NodeRole::Relay,
            0,
            b"lhr",
            b"relay-b",
            b"10.3.0.0/24",
        );

        submit_relay_report(2, b"relay-same-topology", 4, 400);
        submit_relay_report(3, b"relay-other-topology", 4, 420);

        let aggregate = OutageAggregates::<Test>::get(node_id(b"cache-9"), 4);
        assert_eq!(aggregate.reporter_count, 2);
        assert_eq!(aggregate.independent_weight, 2);
        assert_eq!(aggregate.reporters[0].weight, aggregate.reporters[1].weight);

        let summary = AvailabilitySummaries::<Test>::get(node_id(b"cache-9"), 4);
        assert_eq!(summary.relay_failure_weight, 2);
    });
}

#[test]
fn same_operator_relay_report_has_zero_economic_weight() {
    new_test_ext().execute_with(|| {
        set_epoch(4);
        register_cache_and_validator();
        submit_success_probe(4);
        register_node(
            9,
            b"did:openpayload:operator1cache19",
            b"relay-owned-by-target",
            NodeRole::Relay,
            0,
            b"lhr",
            b"unrelated-cluster",
            b"192.0.2.0/24",
        );
        register_operator(2, b"did:openpayload:operator1re1ay1independent");
        register_node(
            2,
            b"did:openpayload:operator1re1ay1independent",
            b"relay-independent",
            NodeRole::Relay,
            0,
            b"iad",
            b"cache-a",
            b"10.0.0.0/24",
        );

        submit_relay_report(9, b"relay-owned-by-target", 4, 400);
        submit_relay_report(2, b"relay-independent", 4, 420);

        let aggregate = OutageAggregates::<Test>::get(node_id(b"cache-9"), 4);
        assert_eq!(aggregate.reporter_count, 2);
        assert_eq!(aggregate.reporters[0].weight, 0);
        assert_eq!(aggregate.reporters[1].weight, 1);
        assert_eq!(aggregate.independent_weight, 1);

        let summary = AvailabilitySummaries::<Test>::get(node_id(b"cache-9"), 4);
        assert_eq!(summary.relay_failure_weight, 0);
        assert_eq!(summary.availability_score_ppm, 1_000_000);
    });
}

#[test]
fn duplicate_relay_report_for_same_window_is_rejected() {
    new_test_ext().execute_with(|| {
        set_epoch(4);
        register_cache_and_validator();
        register_relays();
        submit_relay_report(2, b"relay-2", 4, 400);

        assert_noop!(
            ResourceRewards::submit_relay_outage_report(
                RuntimeOrigin::signed(2),
                b"relay-2".to_vec(),
                b"cache-9".to_vec(),
                4,
                crate::FailureCategory::Timeout,
                2,
                400,
                410,
                sig(2),
            ),
            Error::<Test>::DuplicateReport
        );
    });
}

#[test]
fn false_reporters_lose_credibility_when_validator_success_contradicts_reports() {
    new_test_ext().execute_with(|| {
        set_epoch(8);
        register_cache_and_validator();
        register_relays();
        submit_relay_report(2, b"relay-2", 8, 800);
        submit_relay_report(3, b"relay-3", 8, 820);

        assert_eq!(
            Operators::<Test>::get(2).unwrap().credibility_ppm,
            1_000_000
        );
        submit_success_probe(8);
        assert_eq!(Operators::<Test>::get(2).unwrap().credibility_ppm, 900_000);
        assert_eq!(Operators::<Test>::get(3).unwrap().credibility_ppm, 900_000);
    });
}

#[test]
fn validator_role_requires_governance_approval_and_revocation_stops_polling() {
    new_test_ext().execute_with(|| {
        register_operator(1, b"did:openpayload:operator1va1idator11");
        assert_noop!(
            ResourceRewards::register_node(
                RuntimeOrigin::signed(1),
                b"did:openpayload:operator1va1idator11".to_vec(),
                b"validator-1".to_vec(),
                NodeRole::Validator,
                b"https://validator.example".to_vec(),
                0,
                b"ord".to_vec(),
                b"US".to_vec(),
                vec![],
                b"validator-a".to_vec(),
                b"10.1.0.0/24".to_vec(),
            ),
            Error::<Test>::ValidatorNotApproved
        );

        assert_ok!(ResourceRewards::set_validator_approval(
            RuntimeOrigin::root(),
            1,
            true,
        ));
        register_node(
            1,
            b"did:openpayload:operator1va1idator11",
            b"validator-1",
            NodeRole::Validator,
            0,
            b"ord",
            b"validator-a",
            b"10.1.0.0/24",
        );
        assert_noop!(
            ResourceRewards::register_node(
                RuntimeOrigin::signed(1),
                b"did:openpayload:operator1va1idator11".to_vec(),
                b"validator-1-duplicate".to_vec(),
                NodeRole::Validator,
                b"https://validator-duplicate.example".to_vec(),
                0,
                b"ord".to_vec(),
                b"US".to_vec(),
                vec![],
                b"validator-a".to_vec(),
                b"10.2.0.0/24".to_vec(),
            ),
            Error::<Test>::ValidatorNodeAlreadyRegistered
        );
        assert_ok!(ResourceRewards::set_validator_approval(
            RuntimeOrigin::root(),
            1,
            false,
        ));
        assert_noop!(
            ResourceRewards::submit_validator_probe(
                RuntimeOrigin::signed(1),
                b"validator-1".to_vec(),
                b"validator-1".to_vec(),
                0,
                0,
                1,
                ProbeResult::Success,
                sig(1),
            ),
            Error::<Test>::ValidatorNotApproved
        );
    });
}

fn new_reward_record(
    operator: AccountId,
    raw_amount: Balance,
    raw_prefix_before: Balance,
) -> CacheRewardRecord<Test> {
    CacheRewardRecord::<Test> {
        operator,
        average_bytes: 1_000,
        quality_ppm: 1_000_000,
        storage_multiplier_ppm: 1_000_000,
        raw_amount,
        raw_prefix_before,
        policy_version: 1,
        claimed_amount: None,
    }
}

#[test]
fn permanent_genesis_has_active_evidence_root_sponsor_and_noninflationary_first_year() {
    new_test_ext().execute_with(|| {
        assert_eq!(
            ResourceRewards::in_code_storage_version(),
            StorageVersion::new(2)
        );
        assert!(CacheTriggerEvidenceEnabled::<Test>::get());
        assert!(!RewardPaymentsPaused::<Test>::get());
        assert_eq!(RewardPaymentsStartEpoch::<Test>::get(), Some(0));
        assert_eq!(ActiveRewardPolicyVersion::<Test>::get(), 1);
        assert_eq!(RootSponsor::<Test>::get(), Some(3));
        assert_eq!(NextRewardEpochToClose::<Test>::get(), 0);
        let year = RewardYearStates::<Test>::get(0).unwrap();
        assert_eq!(year.opening_free_reserve, 10_000);
        assert_eq!(year.supplemental_cap, 0);
        assert_eq!(
            Balances::free_balance(ResourceRewards::reward_pot_account()),
            10_000
        );
    });
}

#[test]
fn sponsor_delegation_has_no_ceiling_or_cascade_and_root_transfer_is_two_step() {
    new_test_ext().execute_with(|| {
        register_operator(9, b"did:openpayload:operator1cache19");
        for cache in [b"cache-a".as_slice(), b"cache-b".as_slice()] {
            register_node(
                9,
                b"did:openpayload:operator1cache19",
                cache,
                NodeRole::Cache,
                0,
                b"iad",
                b"cache-a",
                b"10.0.0.0/24",
            );
        }
        assert_ok!(ResourceRewards::set_sponsor_authority(
            RuntimeOrigin::signed(3),
            4,
            true,
            true,
        ));
        assert_noop!(
            ResourceRewards::set_sponsor_authority(RuntimeOrigin::signed(4), 4, true, true,),
            Error::<Test>::SponsorSelfGrantForbidden
        );
        assert_ok!(ResourceRewards::set_sponsor_authority(
            RuntimeOrigin::signed(3),
            6,
            true,
            false,
        ));
        assert_noop!(
            ResourceRewards::set_sponsor_authority(RuntimeOrigin::signed(4), 6, true, true,),
            Error::<Test>::SponsorAuthorityAlreadyExists
        );
        assert_ok!(ResourceRewards::set_sponsor_authority(
            RuntimeOrigin::signed(4),
            5,
            true,
            false,
        ));
        assert_ok!(ResourceRewards::admit_reward_eligible_cache(
            RuntimeOrigin::signed(5),
            b"cache-a".to_vec(),
        ));
        assert_noop!(
            ResourceRewards::revoke_reward_eligible_cache(
                RuntimeOrigin::signed(6),
                b"cache-a".to_vec(),
            ),
            Error::<Test>::SponsorNotAuthorized
        );
        assert_ok!(ResourceRewards::set_sponsor_authority(
            RuntimeOrigin::signed(3),
            4,
            false,
            false,
        ));
        assert!(SponsorAuthorities::<Test>::contains_key(5));
        assert_ok!(ResourceRewards::admit_reward_eligible_cache(
            RuntimeOrigin::signed(5),
            b"cache-b".to_vec(),
        ));
        assert_ok!(ResourceRewards::revoke_reward_eligible_cache(
            RuntimeOrigin::signed(5),
            b"cache-a".to_vec(),
        ));
        set_epoch(4);
        assert_ok!(ResourceRewards::admit_reward_eligible_cache(
            RuntimeOrigin::signed(5),
            b"cache-a".to_vec(),
        ));
        assert_eq!(
            RewardEligibleCaches::<Test>::get(node_id(b"cache-a"))
                .unwrap()
                .admitted_epoch,
            5
        );
        assert_ok!(ResourceRewards::propose_root_sponsor(
            RuntimeOrigin::signed(3),
            4,
        ));
        assert_eq!(PendingRootSponsor::<Test>::get(), Some(4));
        assert_ok!(ResourceRewards::accept_root_sponsor(RuntimeOrigin::signed(
            4
        )));
        assert_eq!(RootSponsor::<Test>::get(), Some(4));
    });
}

#[test]
fn strict_six_ticket_rule_and_operator_aggregation_drive_raw_rewards() {
    new_test_ext().execute_with(|| {
        register_operator(9, b"did:openpayload:operator1cache19");
        for cache in [b"cache-a".as_slice(), b"cache-b".as_slice()] {
            register_node(
                9,
                b"did:openpayload:operator1cache19",
                cache,
                NodeRole::Cache,
                0,
                b"iad",
                b"cache-a",
                b"10.0.0.0/24",
            );
            assert_ok!(ResourceRewards::admit_reward_eligible_cache(
                RuntimeOrigin::signed(3),
                cache.to_vec(),
            ));
        }
        CacheQueueDepthEpochs::<Test>::insert(
            node_id(b"cache-a"),
            1,
            CacheQueueDepthEpoch {
                tickets_issued: 6,
                tickets_verified: 6,
                depth_sum: 90,
                ..Default::default()
            },
        );
        CacheQueueDepthEpochs::<Test>::insert(
            node_id(b"cache-b"),
            1,
            CacheQueueDepthEpoch {
                tickets_issued: 6,
                tickets_verified: 5,
                depth_sum: 75,
                ..Default::default()
            },
        );
        set_epoch(3);
        for cache in [b"cache-a".as_slice(), b"cache-b".as_slice()] {
            assert_ok!(ResourceRewards::finalize_cache_queue_depth_epoch(
                RuntimeOrigin::signed(4),
                cache.to_vec(),
                1,
            ));
        }
        assert_eq!(
            CacheQueueDepthEpochs::<Test>::get(node_id(b"cache-a"), 1).average_bytes,
            1_500
        );
        assert_eq!(
            CacheQueueDepthEpochs::<Test>::get(node_id(b"cache-b"), 1).average_bytes,
            0
        );
        set_epoch(4);
        assert_ok!(ResourceRewards::freeze_operator_queue_depth_epoch(
            RuntimeOrigin::signed(4),
            9,
            1,
        ));
        assert_eq!(
            OperatorQueueDepthEpochs::<Test>::get(9, 1).multiplier_ppm,
            1_375_000
        );
        for cache in [b"cache-a".as_slice(), b"cache-b".as_slice()] {
            assert_ok!(ResourceRewards::finalize_cache_raw_reward(
                RuntimeOrigin::signed(4),
                cache.to_vec(),
                1,
            ));
        }
        assert_eq!(
            CacheRewardRecords::<Test>::get(node_id(b"cache-a"), 1)
                .unwrap()
                .raw_amount,
            137
        );
        let failed = CacheRewardRecords::<Test>::get(node_id(b"cache-b"), 1).unwrap();
        assert_eq!(failed.quality_ppm, 0);
        assert_eq!(failed.raw_amount, 0);
    });
}

#[test]
fn readmission_waits_until_the_prior_eligibility_interval_is_finalized() {
    new_test_ext().execute_with(|| {
        register_operator(9, b"did:openpayload:operator1cache19");
        register_node(
            9,
            b"did:openpayload:operator1cache19",
            b"cache-a",
            NodeRole::Cache,
            0,
            b"iad",
            b"cache-a",
            b"10.0.0.0/24",
        );
        assert_ok!(ResourceRewards::admit_reward_eligible_cache(
            RuntimeOrigin::signed(3),
            b"cache-a".to_vec(),
        ));
        set_epoch(1);
        assert_ok!(ResourceRewards::revoke_reward_eligible_cache(
            RuntimeOrigin::signed(3),
            b"cache-a".to_vec(),
        ));
        CacheQueueDepthEpochs::<Test>::insert(
            node_id(b"cache-a"),
            1,
            CacheQueueDepthEpoch {
                tickets_issued: 6,
                tickets_verified: 6,
                depth_sum: 60,
                ..Default::default()
            },
        );
        set_epoch(3);
        assert_ok!(ResourceRewards::finalize_cache_queue_depth_epoch(
            RuntimeOrigin::signed(4),
            b"cache-a".to_vec(),
            1,
        ));
        set_epoch(4);
        assert_ok!(ResourceRewards::freeze_operator_queue_depth_epoch(
            RuntimeOrigin::signed(4),
            9,
            1,
        ));
        assert_ok!(ResourceRewards::finalize_cache_raw_reward(
            RuntimeOrigin::signed(4),
            b"cache-a".to_vec(),
            1,
        ));
        assert!(CacheRewardRecords::<Test>::contains_key(
            node_id(b"cache-a"),
            1
        ));
        assert_noop!(
            ResourceRewards::admit_reward_eligible_cache(
                RuntimeOrigin::signed(3),
                b"cache-a".to_vec(),
            ),
            Error::<Test>::CacheReadmissionTooEarly
        );
        set_epoch(5);
        assert_ok!(ResourceRewards::admit_reward_eligible_cache(
            RuntimeOrigin::signed(3),
            b"cache-a".to_vec(),
        ));
    });
}

#[test]
fn sequential_epoch_close_freezes_proportional_claims_without_claim_order_advantage() {
    new_test_ext().execute_with(|| {
        EpochRawRewardTotals::<Test>::insert(0, 2_000);
        EpochRawRewardRecordCounts::<Test>::insert(0, 2);
        CacheRewardRecords::<Test>::insert(node_id(b"cache-a"), 0, new_reward_record(1, 1_000, 0));
        CacheRewardRecords::<Test>::insert(
            node_id(b"cache-b"),
            0,
            new_reward_record(2, 1_000, 1_000),
        );
        set_epoch(5);
        assert_noop!(
            ResourceRewards::close_reward_epoch(RuntimeOrigin::signed(4), 1),
            Error::<Test>::InvalidEpoch
        );
        assert_ok!(ResourceRewards::close_reward_epoch(
            RuntimeOrigin::signed(4),
            0
        ));
        assert_eq!(
            EpochSettlements::<Test>::get(0).unwrap().distributable,
            1_000
        );
        assert_ok!(ResourceRewards::claim_cache_reward(
            RuntimeOrigin::signed(4),
            b"cache-b".to_vec(),
            0
        ));
        assert_ok!(ResourceRewards::claim_cache_reward(
            RuntimeOrigin::signed(4),
            b"cache-a".to_vec(),
            0
        ));
        assert_eq!(
            CacheRewardRecords::<Test>::get(node_id(b"cache-a"), 0)
                .unwrap()
                .claimed_amount,
            Some(500)
        );
        assert_eq!(
            CacheRewardRecords::<Test>::get(node_id(b"cache-b"), 0)
                .unwrap()
                .claimed_amount,
            Some(500)
        );
        assert_eq!(OutstandingRewardLiabilities::<Test>::get(), 0);
    });
}

#[test]
fn later_reward_year_mints_fixed_emission_once_and_computes_shortage_cap() {
    new_test_ext().execute_with(|| {
        let issuance_before = Balances::total_issuance();
        set_epoch(20);
        for epoch in 0..=10 {
            assert_ok!(ResourceRewards::close_reward_epoch(
                RuntimeOrigin::signed(4),
                epoch,
            ));
        }
        let year_one = RewardYearStates::<Test>::get(1).unwrap();
        assert_eq!(year_one.fixed_emission_minted, 1_000);
        assert_eq!(
            year_one.supplemental_cap,
            (issuance_before + 1_000) * 20_000 / 1_000_000
        );
        assert_eq!(Balances::total_issuance(), issuance_before + 1_000);
        assert_noop!(
            ResourceRewards::close_reward_epoch(RuntimeOrigin::signed(4), 10),
            Error::<Test>::InvalidEpoch
        );
    });
}

#[test]
fn reward_pause_blocks_liability_commitment() {
    new_test_ext().execute_with(|| {
        RewardPaymentsPaused::<Test>::put(true);
        set_epoch(4);
        assert_noop!(
            ResourceRewards::close_reward_epoch(RuntimeOrigin::signed(4), 0),
            Error::<Test>::RewardPaymentsPaused
        );
        assert_eq!(OutstandingRewardLiabilities::<Test>::get(), 0);
    });
}

#[test]
fn reward_payments_cannot_be_unpaused_without_a_root_sponsor() {
    new_test_ext().execute_with(|| {
        RewardPaymentsPaused::<Test>::put(true);
        RootSponsor::<Test>::kill();

        assert_noop!(
            ResourceRewards::set_reward_payments_paused(RuntimeOrigin::root(), false),
            Error::<Test>::RootSponsorNotConfigured
        );
        assert!(RewardPaymentsPaused::<Test>::get());
    });
}

#[test]
fn cache_history_pruning_is_independent_and_operator_aggregate_is_removable() {
    new_test_ext().execute_with(|| {
        CacheRewardRecords::<Test>::insert(
            node_id(b"cache-a"),
            0,
            CacheRewardRecord::<Test> {
                claimed_amount: Some(0),
                ..new_reward_record(1, 0, 0)
            },
        );
        set_epoch(4);
        assert_ok!(ResourceRewards::close_reward_epoch(
            RuntimeOrigin::signed(4),
            0
        ));
        assert_ok!(ResourceRewards::prune_cache_reward_history(
            RuntimeOrigin::signed(4),
            b"cache-a".to_vec(),
            0,
        ));
        assert!(!CacheRewardRecords::<Test>::contains_key(
            node_id(b"cache-a"),
            0
        ));
        set_epoch(5);
        assert_ok!(ResourceRewards::close_reward_epoch(
            RuntimeOrigin::signed(4),
            1
        ));
        assert_ok!(ResourceRewards::prune_cache_reward_history(
            RuntimeOrigin::signed(4),
            b"cache-with-no-record".to_vec(),
            1,
        ));
        assert_ok!(ResourceRewards::prune_operator_queue_depth_history(
            RuntimeOrigin::signed(4),
            1,
            0,
        ));
    });
}

#[test]
fn operator_history_obeys_the_same_retention_boundary_as_cache_history() {
    new_test_ext().execute_with(|| {
        CacheRewardHistoryRetentionEpochsValue::<Test>::put(10);
        OperatorQueueDepthEpochs::<Test>::insert(
            1,
            0,
            OperatorQueueDepthEpoch {
                frozen: true,
                ..Default::default()
            },
        );
        set_epoch(4);
        assert_ok!(ResourceRewards::close_reward_epoch(
            RuntimeOrigin::signed(4),
            0
        ));
        assert_noop!(
            ResourceRewards::prune_operator_queue_depth_history(RuntimeOrigin::signed(4), 1, 0,),
            Error::<Test>::CacheRewardHistoryRetentionActive
        );
        set_epoch(11);
        assert_ok!(ResourceRewards::prune_operator_queue_depth_history(
            RuntimeOrigin::signed(4),
            1,
            0,
        ));
        assert!(!OperatorQueueDepthEpochs::<Test>::contains_key(1, 0));
    });
}

#[test]
fn failed_claim_transfer_rolls_back_claim_and_accrual_state() {
    new_test_ext().execute_with(|| {
        let cache = node_id(b"cache-a");
        CacheRewardRecords::<Test>::insert(&cache, 0, new_reward_record(1, 100, 0));
        EpochSettlements::<Test>::insert(
            0,
            crate::EpochSettlement {
                reward_year: 0,
                raw_total: 100,
                distributable: 100,
                record_count: 1,
                claimed_count: 0,
                claimed_total: 0,
                closed: true,
            },
        );
        let pot = ResourceRewards::reward_pot_account();
        assert_ok!(Balances::force_set_balance(RuntimeOrigin::root(), pot, 0));
        assert_noop!(
            ResourceRewards::claim_cache_reward(RuntimeOrigin::signed(4), b"cache-a".to_vec(), 0,),
            Error::<Test>::RewardReserveInvariantViolated
        );
        assert_eq!(
            CacheRewardRecords::<Test>::get(&cache, 0)
                .unwrap()
                .claimed_amount,
            None
        );
        let settlement = EpochSettlements::<Test>::get(0).unwrap();
        assert_eq!(settlement.claimed_count, 0);
        assert_eq!(settlement.claimed_total, 0);
        assert_eq!(crate::OperatorAccruedRewards::<Test>::get(1), 0);
    });
}

#[test]
fn mismatched_positive_trigger_evidence_fails_fast_and_cannot_be_overridden() {
    new_test_ext().execute_with(|| {
        register_cache_and_validator();
        register_second_validator();
        assert_ok!(ResourceRewards::admit_reward_eligible_cache(
            RuntimeOrigin::signed(3),
            b"cache-9".to_vec(),
        ));
        let cache = node_id(b"cache-9");
        let ticket_id: crate::ProofHashOf<Test> = vec![21; 32].try_into().unwrap();
        let receipt_hash: crate::ProofHashOf<Test> = vec![22; 32].try_into().unwrap();
        CacheTriggerTickets::<Test>::insert(
            &cache,
            (1, 0),
            CacheTriggerTicket::<Test> {
                ticket_id: ticket_id.clone(),
                cache_node_id: cache.clone(),
                recipient_did: did(b"did:openpayload:operator1cache19"),
                trigger_message_hash: vec![23; 32].try_into().unwrap(),
                epoch: 1,
                slot: 0,
                issued_at: 10,
                retention_check_at: 11,
                expires_at: 12,
                issuer_validator_node_id: node_id(b"validator-1"),
                issuer_signature: sig(1).try_into().unwrap(),
                receipt: Some(CacheTriggerReceipt::<Test> {
                    ticket_id: ticket_id.clone(),
                    cache_node_id: cache.clone(),
                    message_id: b"random-message-id".to_vec().try_into().unwrap(),
                    queue_depth_before: 10,
                    queue_depth_after: 11,
                    accepted_at: 10,
                    stored_at: 10,
                    receipt_hash,
                    signature: sig(9).try_into().unwrap(),
                }),
                positive_attestations: 0,
                negative_attestations: 0,
                canonical_evidence_hash: None,
                verified: false,
                failed: false,
            },
        );
        CacheTriggerTicketById::<Test>::insert(&ticket_id, (cache.clone(), 1, 0));
        set_epoch(2);
        for (account, validator, evidence_hash) in [
            (1, b"validator-1".as_slice(), vec![22u8; 32]),
            (2, b"validator-2".as_slice(), vec![32u8; 32]),
        ] {
            let evidence_hash: crate::ProofHashOf<Test> = evidence_hash.try_into().unwrap();
            let validator_node = node_id(validator);
            let payload = ResourceRewards::cache_trigger_attestation_payload(
                &ticket_id,
                &validator_node,
                true,
                true,
                true,
                true,
                &evidence_hash,
            );
            let pair = ed25519::Pair::from_seed(&[account as u8; 32]);
            assert_ok!(ResourceRewards::attest_cache_trigger_ticket(
                RuntimeOrigin::signed(account),
                validator.to_vec(),
                ticket_id.to_vec(),
                true,
                true,
                true,
                true,
                evidence_hash.to_vec(),
                pair.sign(&payload).to_raw_vec(),
            ));
        }
        let ticket = CacheTriggerTickets::<Test>::get(cache, (1, 0)).unwrap();
        assert_eq!(ticket.positive_attestations, 1);
        assert_eq!(ticket.negative_attestations, 1);
        assert!(ticket.failed);
        assert!(!ticket.verified);
    });
}

#[test]
fn signed_trigger_receipt_and_two_matching_attestations_complete_one_ticket() {
    new_test_ext().execute_with(|| {
        register_cache_and_validator();
        register_second_validator();
        assert_ok!(ResourceRewards::admit_reward_eligible_cache(
            RuntimeOrigin::signed(3),
            b"cache-9".to_vec(),
        ));
        System::set_block_number(10);
        let cache = node_id(b"cache-9");
        let validator = node_id(b"validator-1");
        let recipient = did(b"did:openpayload:operator1cache19");
        let trigger_hash: crate::ProofHashOf<Test> = vec![0xaa; 32].try_into().unwrap();
        let (_, _, anchor) = ResourceRewards::trigger_slot_window(&cache, 1, 0);
        let ticket_id =
            ResourceRewards::canonical_cache_trigger_ticket_id(&cache, 1, 0, &anchor).unwrap();
        let issuance_payload = ResourceRewards::cache_trigger_issuance_payload(
            &1,
            &ticket_id,
            &validator,
            &cache,
            &recipient,
            &trigger_hash,
            3,
            0,
            1,
            0,
        );
        let validator_pair = ed25519::Pair::from_seed(&[1; 32]);
        assert_ok!(ResourceRewards::issue_cache_trigger_ticket(
            RuntimeOrigin::signed(1),
            validator.to_vec(),
            cache.to_vec(),
            recipient.to_vec(),
            trigger_hash.to_vec(),
            3,
            0,
            validator_pair.sign(&issuance_payload).to_raw_vec(),
        ));

        let message_id = b"550e8400-e29b-41d4-a716-446655440001".to_vec();
        let bounded_message_id: crate::MessageIdOf<Test> = message_id.clone().try_into().unwrap();
        let receipt_hash: crate::ProofHashOf<Test> = vec![0xbb; 32].try_into().unwrap();
        let ticket = CacheTriggerTickets::<Test>::get(&cache, (1, 0)).unwrap();
        let cache_pair = ed25519::Pair::from_seed(&[9; 32]);
        let zero_time_payload = ResourceRewards::cache_trigger_receipt_payload(
            &ticket,
            &bounded_message_id,
            41,
            42,
            0,
            0,
            &receipt_hash,
        );
        assert_noop!(
            ResourceRewards::submit_cache_trigger_receipt(
                RuntimeOrigin::signed(9),
                cache.to_vec(),
                ticket_id.to_vec(),
                message_id.clone(),
                41,
                42,
                0,
                0,
                receipt_hash.to_vec(),
                cache_pair.sign(&zero_time_payload).to_raw_vec(),
            ),
            Error::<Test>::InvalidCacheTriggerReceipt
        );
        let receipt_payload = ResourceRewards::cache_trigger_receipt_payload(
            &ticket,
            &bounded_message_id,
            41,
            42,
            1_000,
            1_001,
            &receipt_hash,
        );
        assert_ok!(ResourceRewards::submit_cache_trigger_receipt(
            RuntimeOrigin::signed(9),
            cache.to_vec(),
            ticket_id.to_vec(),
            message_id,
            41,
            42,
            1_000,
            1_001,
            receipt_hash.to_vec(),
            cache_pair.sign(&receipt_payload).to_raw_vec(),
        ));

        System::set_block_number(20);
        let evidence_hash = receipt_hash;
        for (account, validator_raw) in [
            (1, b"validator-1".as_slice()),
            (2, b"validator-2".as_slice()),
        ] {
            let validator_node = node_id(validator_raw);
            let payload = ResourceRewards::cache_trigger_attestation_payload(
                &ticket_id,
                &validator_node,
                true,
                true,
                true,
                true,
                &evidence_hash,
            );
            let pair = ed25519::Pair::from_seed(&[account as u8; 32]);
            assert_ok!(ResourceRewards::attest_cache_trigger_ticket(
                RuntimeOrigin::signed(account),
                validator_raw.to_vec(),
                ticket_id.to_vec(),
                true,
                true,
                true,
                true,
                evidence_hash.to_vec(),
                pair.sign(&payload).to_raw_vec(),
            ));
        }
        let ticket = CacheTriggerTickets::<Test>::get(&cache, (1, 0)).unwrap();
        assert!(ticket.verified);
        assert!(!ticket.failed);
        assert_eq!(ticket.receipt.unwrap().message_id, bounded_message_id);
        let summary = CacheQueueDepthEpochs::<Test>::get(&cache, 1);
        assert_eq!(summary.tickets_issued, 1);
        assert_eq!(summary.tickets_verified, 1);
        assert_eq!(summary.depth_sum, 41);
    });
}

#[test]
fn scheduling_a_future_policy_sets_the_first_epoch_to_close() {
    new_test_ext().execute_with(|| {
        RewardPaymentsStartEpoch::<Test>::kill();
        ActiveRewardPolicyVersion::<Test>::put(0);
        NextRewardEpochToClose::<Test>::put(0);
        set_epoch(1);
        assert_ok!(ResourceRewards::schedule_reward_payments(
            RuntimeOrigin::root(),
            3,
            7,
        ));
        assert_eq!(RewardPaymentsStartEpoch::<Test>::get(), Some(3));
        assert_eq!(NextRewardEpochToClose::<Test>::get(), 3);
    });
}

#[test]
fn trigger_recipient_must_be_the_target_cache_operator_did() {
    new_test_ext().execute_with(|| {
        register_cache_and_validator();
        register_did(b"did:openpayload:operator1va1idator12", 8);
        assert_ok!(ResourceRewards::admit_reward_eligible_cache(
            RuntimeOrigin::signed(3),
            b"cache-9".to_vec(),
        ));
        System::set_block_number(10);
        assert_noop!(
            ResourceRewards::issue_cache_trigger_ticket(
                RuntimeOrigin::signed(1),
                b"validator-1".to_vec(),
                b"cache-9".to_vec(),
                b"did:openpayload:operator1va1idator12".to_vec(),
                vec![1; 32],
                3,
                0,
                sig(1),
            ),
            Error::<Test>::CacheTriggerRecipientMismatch
        );
    });
}

#[test]
fn trigger_opening_is_in_first_half_and_leaves_at_least_half_the_slot() {
    new_test_ext().execute_with(|| {
        let cache = node_id(b"cache-window");
        let duration = 10u64;
        let slots = 6u64;
        for slot in 0..slots {
            let (opening, end, _) = ResourceRewards::trigger_slot_window(&cache, 1, slot as u32);
            let start = duration + duration * slot / slots;
            let expected_end = duration + duration * (slot + 1) / slots;
            let width = expected_end - start;
            let opening_range = width.div_ceil(2);
            assert!(opening >= start);
            assert!(opening < start + opening_range);
            assert_eq!(end, expected_end);
            assert!(end - opening >= width.div_ceil(2));
        }
    });
}

#[test]
fn u256_mul_div_and_cumulative_allocation_are_exact_near_u128_limit() {
    new_test_ext().execute_with(|| {
        let value = u128::MAX - 7;
        assert_eq!(
            ResourceRewards::mul_div_u128(value, 20_000, 1_000_000),
            ((sp_core::U256::from(value) * sp_core::U256::from(20_000u128))
                / sp_core::U256::from(1_000_000u128))
            .as_u128()
        );

        let raw_total = u128::MAX - 1;
        let distributable = u128::MAX - 123;
        let first_raw = raw_total / 2;
        let second_raw = raw_total - first_raw;
        let first =
            ResourceRewards::proportional_position_amount(distributable, raw_total, 0, first_raw);
        let second = ResourceRewards::proportional_position_amount(
            distributable,
            raw_total,
            first_raw,
            second_raw,
        );
        assert_eq!(first + second, distributable);
    });
}

fn bytes_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn cache_trigger_scale_payload_golden_vectors() {
    new_test_ext().execute_with(|| {
        let validator_account = 1u64;
        let ticket_id: crate::ProofHashOf<Test> = vec![0x11; 32].try_into().unwrap();
        let validator_node = node_id(b"validator-1");
        let cache_node = node_id(b"cache-1");
        let recipient = did(b"did:openpayload:recipient");
        let trigger_hash: crate::ProofHashOf<Test> = vec![0x22; 32].try_into().unwrap();
        let issuance = ResourceRewards::cache_trigger_issuance_payload(
            &validator_account,
            &ticket_id,
            &validator_node,
            &cache_node,
            &recipient,
            &trigger_hash,
            10,
            7,
            3,
            2,
        );

        let ticket = CacheTriggerTicket::<Test> {
            ticket_id: ticket_id.clone(),
            cache_node_id: cache_node.clone(),
            recipient_did: recipient,
            trigger_message_hash: trigger_hash,
            epoch: 3,
            slot: 2,
            issued_at: 30,
            retention_check_at: 31,
            expires_at: 40,
            issuer_validator_node_id: validator_node.clone(),
            issuer_signature: sig(1).try_into().unwrap(),
            receipt: None,
            positive_attestations: 0,
            negative_attestations: 0,
            canonical_evidence_hash: None,
            verified: false,
            failed: false,
        };
        let message_id: crate::MessageIdOf<Test> = b"550e8400-e29b-41d4-a716-446655440000"
            .to_vec()
            .try_into()
            .unwrap();
        let receipt_hash: crate::ProofHashOf<Test> = vec![0x33; 32].try_into().unwrap();
        let receipt = ResourceRewards::cache_trigger_receipt_payload(
            &ticket,
            &message_id,
            41,
            42,
            30,
            30,
            &receipt_hash,
        );
        let evidence_hash: crate::ProofHashOf<Test> = vec![0x44; 32].try_into().unwrap();
        let attestation = ResourceRewards::cache_trigger_attestation_payload(
            &ticket_id,
            &validator_node,
            true,
            true,
            true,
            true,
            &evidence_hash,
        );

        assert_eq!(
            bytes_hex(&issuance),
            "d86f70656e7061796c6f61643a7265736f757263652d726577617264733a63616368652d747269676765722d69737375616e63653a7631454545454545454545454545454545454545454545454545454545454545454501000000000000008011111111111111111111111111111111111111111111111111111111111111112c76616c696461746f722d311c63616368652d31646469643a6f70656e7061796c6f61643a726563697069656e748022222222222222222222222222222222222222222222222222222222222222220a0000000700000000000000030000000000000002000000"
        );
        assert_eq!(
            bytes_hex(&receipt),
            "d46f70656e7061796c6f61643a7265736f757263652d726577617264733a63616368652d747269676765722d726563656970743a763145454545454545454545454545454545454545454545454545454545454545458011111111111111111111111111111111111111111111111111111111111111111c63616368652d318022222222222222222222222222222222222222222222222222222222222222229035353065383430302d653239622d343164342d613731362d3434363635353434303030300300000000000000020000001e000000000000001f00000000000000280000000000000029000000000000002a000000000000001e000000000000001e00000000000000803333333333333333333333333333333333333333333333333333333333333333"
        );
        assert_eq!(
            bytes_hex(&attestation),
            "e46f70656e7061796c6f61643a7265736f757263652d726577617264733a63616368652d747269676765722d6174746573746174696f6e3a763145454545454545454545454545454545454545454545454545454545454545458011111111111111111111111111111111111111111111111111111111111111112c76616c696461746f722d3101010101804444444444444444444444444444444444444444444444444444444444444444"
        );

        let production_issuance = (
            crate::CACHE_TRIGGER_ISSUANCE_DOMAIN,
            sp_core::H256::repeat_byte(0x45),
            [0x55u8; 32],
            &ticket_id,
            &validator_node,
            &cache_node,
            &ticket.recipient_did,
            &ticket.trigger_message_hash,
            10u32,
            7u64,
            3u64,
            2u32,
        )
            .encode();
        let production_receipt = (
            crate::CACHE_TRIGGER_RECEIPT_DOMAIN,
            sp_core::H256::repeat_byte(0x45),
            &ticket_id,
            &cache_node,
            &ticket.trigger_message_hash,
            &message_id,
            3u64,
            2u32,
            30u32,
            31u32,
            40u32,
            41u64,
            42u64,
            30u64,
            30u64,
            &receipt_hash,
        )
            .encode();
        let slot_anchor = sp_core::H256::repeat_byte(0x66);
        let slot_opening = ResourceRewards::trigger_slot_opening_from_anchor(
            &cache_node,
            7,
            3,
            1_000,
            1_100,
            &slot_anchor,
        );
        let canonical_ticket = ResourceRewards::canonical_cache_trigger_ticket_id(
            &cache_node,
            7,
            3,
            &slot_anchor,
        )
        .unwrap();
        assert_eq!(
            bytes_hex(&production_issuance),
            "d86f70656e7061796c6f61643a7265736f757263652d726577617264733a63616368652d747269676765722d69737375616e63653a7631454545454545454545454545454545454545454545454545454545454545454555555555555555555555555555555555555555555555555555555555555555558011111111111111111111111111111111111111111111111111111111111111112c76616c696461746f722d311c63616368652d31646469643a6f70656e7061796c6f61643a726563697069656e748022222222222222222222222222222222222222222222222222222222222222220a0000000700000000000000030000000000000002000000"
        );
        assert_eq!(
            bytes_hex(&production_receipt),
            "d46f70656e7061796c6f61643a7265736f757263652d726577617264733a63616368652d747269676765722d726563656970743a763145454545454545454545454545454545454545454545454545454545454545458011111111111111111111111111111111111111111111111111111111111111111c63616368652d318022222222222222222222222222222222222222222222222222222222222222229035353065383430302d653239622d343164342d613731362d3434363635353434303030300300000000000000020000001e0000001f0000002800000029000000000000002a000000000000001e000000000000001e00000000000000803333333333333333333333333333333333333333333333333333333333333333"
        );
        assert_eq!(slot_opening, 1_003);
        assert_eq!(
            bytes_hex(&canonical_ticket),
            "057cf81f24ed2f9248c1797375fbb8f2fee2ddf7cc82dc87b0d87ae1899490d7"
        );
    });
}
