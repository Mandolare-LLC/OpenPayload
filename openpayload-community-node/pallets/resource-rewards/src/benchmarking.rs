//! FRAME v2 benchmarks for the permanent sponsor, Cache-trigger, settlement, and pruning calls.

use super::*;
use alloc::vec;
use frame_benchmarking::{account, v2::*};
use frame_support::traits::{Currency, Get};
use frame_system::RawOrigin;
use sp_runtime::traits::{Bounded, SaturatedConversion, Saturating, Zero};

const CACHE_SEED: u32 = 11;
const VALIDATOR_SEED: u32 = 12;

struct Actor<T: Config> {
    account: T::AccountId,
    did: DidOf<T>,
    node_id: NodeIdOf<T>,
    seed: u32,
}

fn max_bytes<S: Get<u32>>(fill: u8) -> BoundedVec<u8, S> {
    vec![fill; S::get() as usize]
        .try_into()
        .expect("benchmark value is exactly the configured bound")
}

fn benchmark_did<T: Config>(seed: u32) -> DidOf<T> {
    const BASE58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut raw = b"did:openpayload:".to_vec();
    let max = T::MaxDidLen::get() as usize;
    assert!(max >= raw.len().saturating_add(16));
    raw.resize(max, b'1');
    let mut encoded_seed = seed as usize;
    for byte in raw.iter_mut().rev().take(6) {
        *byte = BASE58[encoded_seed % BASE58.len()];
        encoded_seed /= BASE58.len();
    }
    raw.try_into()
        .expect("benchmark DID is exactly the configured bound")
}

fn benchmark_node_id<T: Config>(seed: u32) -> NodeIdOf<T> {
    let mut node_id = vec![b'n'; T::MaxNodeIdLen::get() as usize];
    assert!(!node_id.is_empty());
    if let Some(last) = node_id.last_mut() {
        *last = b'a'.saturating_add((seed % 26) as u8);
    }
    node_id
        .try_into()
        .expect("benchmark node id is exactly the configured bound")
}

fn install_actor<T: Config>(
    label: &'static str,
    index: u32,
    seed: u32,
    role: NodeRole,
) -> Actor<T> {
    let account: T::AccountId = account(label, index, seed);
    let did = benchmark_did::<T>(seed);
    let node_id = benchmark_node_id::<T>(seed);
    T::BenchmarkHelper::install_did(&account, did.as_slice(), seed);
    let registered_at = frame_system::Pallet::<T>::block_number();
    Operators::<T>::insert(
        &account,
        OperatorInfo::<T> {
            account: account.clone(),
            operator_did: did.clone(),
            bond: None,
            registered_at,
            status: OperatorStatus::Active,
            credibility_ppm: PPM as u32,
        },
    );
    OperatorByDid::<T>::insert(&did, &account);
    Nodes::<T>::insert(
        &node_id,
        NodeInfo::<T> {
            operator: account.clone(),
            operator_did: did.clone(),
            node_id: node_id.clone(),
            node_role: role,
            endpoint: max_bytes::<<T as Config>::MaxEndpointLen>(b'e'),
            declared_capacity: u64::MAX,
            region: max_bytes::<<T as Config>::MaxRegionLen>(b'r'),
            jurisdiction: max_bytes::<<T as Config>::MaxJurisdictionLen>(b'j'),
            supported_ttl_tiers: vec![u32::MAX; T::MaxTtlTiers::get() as usize]
                .try_into()
                .expect("benchmark TTL list is exactly the configured bound"),
            relay_cluster: max_bytes::<<T as Config>::MaxClusterLen>(b'c'),
            network_range: max_bytes::<<T as Config>::MaxNetworkRangeLen>(b'w'),
            registered_at,
            status: OperatorStatus::Active,
        },
    );
    if role == NodeRole::Validator {
        ValidatorNodeByOperator::<T>::insert(&account, &node_id);
        ApprovedValidatorAccounts::<T>::insert(&account, ());
    }
    Actor {
        account,
        did,
        node_id,
        seed,
    }
}

fn set_epoch<T: Config>(epoch: u64) {
    let duration = T::EpochDuration::get().saturated_into::<u64>().max(1);
    frame_system::Pallet::<T>::set_block_number(
        epoch
            .saturating_mul(duration)
            .saturated_into::<BlockNumberFor<T>>(),
    );
}

fn enable_rewards<T: Config>() {
    ValidatorActivityPaused::<T>::put(false);
    CacheTriggerEvidenceEnabled::<T>::put(true);
    RewardPaymentsPaused::<T>::put(false);
    RewardPaymentsStartEpoch::<T>::put(0);
    ActiveRewardPolicyVersion::<T>::put(1);
}

fn admit_at<T: Config>(cache: &Actor<T>, sponsor: &T::AccountId, epoch: u64) {
    RewardEligibleCaches::<T>::insert(
        &cache.node_id,
        CacheEligibility::<T> {
            admitted_by: sponsor.clone(),
            admitted_epoch: epoch,
            revoked_by: None,
            revoked_epoch: None,
        },
    );
}

fn prepare_trigger<T: Config>() -> (Actor<T>, Actor<T>, u64, u32, ProofHashOf<T>, Vec<u8>, u32) {
    enable_rewards::<T>();
    let cache = install_actor::<T>("cache", 0, CACHE_SEED, NodeRole::Cache);
    let validator = install_actor::<T>("validator", 0, VALIDATOR_SEED, NodeRole::Validator);
    let epoch = 1;
    admit_at::<T>(&cache, &validator.account, 0);
    set_epoch::<T>(epoch);
    let slot = 0;
    let (opening, _, anchor) = Pallet::<T>::trigger_slot_window(&cache.node_id, epoch, slot);
    frame_system::Pallet::<T>::set_block_number(opening.saturated_into::<BlockNumberFor<T>>());
    let ticket_id =
        Pallet::<T>::canonical_cache_trigger_ticket_id(&cache.node_id, epoch, slot, &anchor)
            .expect("benchmark ticket id fits the configured proof-hash bound");
    let trigger_message_hash = vec![0x42; 32];
    let retention = T::TriggerRetentionBlocks::get().saturated_into::<u64>();
    let ttl_blocks = retention.saturating_add(1).min(u32::MAX as u64) as u32;
    (
        cache,
        validator,
        epoch,
        slot,
        ticket_id,
        trigger_message_hash,
        ttl_blocks,
    )
}

fn issue_prepared_trigger<T: Config>() -> (Actor<T>, Actor<T>, CacheTriggerTicket<T>) {
    let (cache, validator, epoch, slot, ticket_id, trigger_hash, ttl_blocks) =
        prepare_trigger::<T>();
    let trigger_hash_bounded: ProofHashOf<T> = trigger_hash
        .clone()
        .try_into()
        .expect("32-byte trigger hash fits proof-hash bound");
    let payload = Pallet::<T>::cache_trigger_issuance_payload(
        &validator.account,
        &ticket_id,
        &validator.node_id,
        &cache.node_id,
        &cache.did,
        &trigger_hash_bounded,
        ttl_blocks,
        0,
        epoch,
        slot,
    );
    let signature = T::BenchmarkHelper::sign(validator.seed, &payload);
    Pallet::<T>::issue_cache_trigger_ticket(
        RawOrigin::Signed(validator.account.clone()).into(),
        validator.node_id.clone().into_inner(),
        cache.node_id.clone().into_inner(),
        cache.did.clone().into_inner(),
        trigger_hash,
        ttl_blocks,
        0,
        signature,
    )
    .expect("benchmark trigger issuance succeeds");
    let ticket = CacheTriggerTickets::<T>::get(&cache.node_id, (epoch, slot))
        .expect("issued benchmark ticket exists");
    (cache, validator, ticket)
}

fn submit_prepared_receipt<T: Config>() -> (Actor<T>, Actor<T>, CacheTriggerTicket<T>) {
    let (cache, validator, ticket) = issue_prepared_trigger::<T>();
    let message_id: MessageIdOf<T> = max_bytes::<<T as Config>::MaxMessageIdLen>(b'm');
    let receipt_hash: ProofHashOf<T> = vec![0x51; 32]
        .try_into()
        .expect("32-byte receipt hash fits proof-hash bound");
    let payload = Pallet::<T>::cache_trigger_receipt_payload(
        &ticket,
        &message_id,
        u64::MAX - 1,
        u64::MAX,
        1,
        u64::MAX,
        &receipt_hash,
    );
    let signature = T::BenchmarkHelper::sign(cache.seed, &payload);
    Pallet::<T>::submit_cache_trigger_receipt(
        RawOrigin::Signed(cache.account.clone()).into(),
        cache.node_id.clone().into_inner(),
        ticket.ticket_id.clone().into_inner(),
        message_id.into_inner(),
        u64::MAX - 1,
        u64::MAX,
        1,
        u64::MAX,
        receipt_hash.into_inner(),
        signature,
    )
    .expect("benchmark trigger receipt succeeds");
    let ticket = CacheTriggerTickets::<T>::get(&cache.node_id, (ticket.epoch, ticket.slot))
        .expect("receipted benchmark ticket exists");
    (cache, validator, ticket)
}

fn maximal_historical_ticket<T: Config>(
    cache: &Actor<T>,
    epoch: u64,
    slot: u32,
) -> CacheTriggerTicket<T> {
    let ticket_id: ProofHashOf<T> = vec![slot.saturating_add(1) as u8; 32]
        .try_into()
        .expect("32-byte ticket id fits proof-hash bound");
    let receipt_hash: ProofHashOf<T> = vec![0x62; 32]
        .try_into()
        .expect("32-byte receipt hash fits proof-hash bound");
    let message_id: MessageIdOf<T> = max_bytes::<<T as Config>::MaxMessageIdLen>(b'm');
    let signature: SignatureOf<T> = max_bytes::<<T as Config>::MaxSignatureLen>(b's');
    CacheTriggerTicket::<T> {
        ticket_id: ticket_id.clone(),
        cache_node_id: cache.node_id.clone(),
        recipient_did: cache.did.clone(),
        trigger_message_hash: vec![0x41; 32]
            .try_into()
            .expect("32-byte trigger hash fits proof-hash bound"),
        epoch,
        slot,
        issued_at: Zero::zero(),
        retention_check_at: Zero::zero(),
        expires_at: Zero::zero(),
        issuer_validator_node_id: benchmark_node_id::<T>(99),
        issuer_signature: signature.clone(),
        receipt: Some(CacheTriggerReceipt::<T> {
            ticket_id,
            cache_node_id: cache.node_id.clone(),
            message_id,
            queue_depth_before: u64::MAX - 1,
            queue_depth_after: u64::MAX,
            accepted_at: 1,
            stored_at: u64::MAX,
            receipt_hash: receipt_hash.clone(),
            signature,
        }),
        positive_attestations: T::RequiredTriggerAttestations::get(),
        negative_attestations: 0,
        canonical_evidence_hash: Some(receipt_hash),
        verified: true,
        failed: false,
    }
}

#[benchmarks]
mod benchmarks {
    use super::*;

    #[benchmark]
    fn set_sponsor_authority() {
        set_epoch::<T>(1);
        let root: T::AccountId = account("root", 0, 1);
        let caller: T::AccountId = account("delegating-sponsor", 0, 2);
        let sponsor: T::AccountId = account("new-sponsor", 0, 3);
        RootSponsor::<T>::put(root);
        SponsorAuthorities::<T>::insert(
            &caller,
            SponsorAuthority {
                granted_by: caller.clone(),
                can_delegate: true,
                granted_at_epoch: 0,
            },
        );

        #[extrinsic_call]
        _(RawOrigin::Signed(caller), sponsor.clone(), true, true);

        assert!(SponsorAuthorities::<T>::contains_key(sponsor));
    }

    #[benchmark]
    fn admit_reward_eligible_cache() {
        let root: T::AccountId = account("root", 0, 1);
        let sponsor: T::AccountId = account("sponsor", 0, 2);
        RootSponsor::<T>::put(&root);
        SponsorAuthorities::<T>::insert(
            &sponsor,
            SponsorAuthority {
                granted_by: root,
                can_delegate: false,
                granted_at_epoch: 0,
            },
        );
        let cache = install_actor::<T>("cache", 0, CACHE_SEED, NodeRole::Cache);
        let revoked_epoch = 1;
        let current_epoch = revoked_epoch
            .saturating_add(T::EvidenceWindowEpochs::get())
            .saturating_add(2)
            .saturating_add(T::RewardFinalizationWindowEpochs::get().max(1));
        set_epoch::<T>(current_epoch);
        RewardEligibleCaches::<T>::insert(
            &cache.node_id,
            CacheEligibility::<T> {
                admitted_by: sponsor.clone(),
                admitted_epoch: 0,
                revoked_by: Some(sponsor.clone()),
                revoked_epoch: Some(revoked_epoch),
            },
        );

        #[extrinsic_call]
        _(
            RawOrigin::Signed(sponsor),
            cache.node_id.clone().into_inner(),
        );

        assert_eq!(
            RewardEligibleCaches::<T>::get(&cache.node_id)
                .expect("benchmark eligibility exists")
                .revoked_epoch,
            None
        );
    }

    #[benchmark]
    fn revoke_reward_eligible_cache() {
        let root: T::AccountId = account("root", 0, 1);
        let sponsor: T::AccountId = account("sponsor", 0, 2);
        RootSponsor::<T>::put(&root);
        SponsorAuthorities::<T>::insert(
            &sponsor,
            SponsorAuthority {
                granted_by: root,
                can_delegate: false,
                granted_at_epoch: 0,
            },
        );
        let cache = install_actor::<T>("cache", 0, CACHE_SEED, NodeRole::Cache);
        admit_at::<T>(&cache, &sponsor, 0);
        set_epoch::<T>(1);

        #[extrinsic_call]
        _(
            RawOrigin::Signed(sponsor),
            cache.node_id.clone().into_inner(),
        );

        assert!(RewardEligibleCaches::<T>::get(&cache.node_id)
            .expect("benchmark eligibility exists")
            .revoked_epoch
            .is_some());
    }

    #[benchmark]
    fn propose_root_sponsor() {
        let root: T::AccountId = account("root", 0, 1);
        let proposed: T::AccountId = account("proposed-root", 0, 2);
        RootSponsor::<T>::put(&root);

        #[extrinsic_call]
        _(RawOrigin::Signed(root), proposed.clone());

        assert_eq!(PendingRootSponsor::<T>::get(), Some(proposed));
    }

    #[benchmark]
    fn accept_root_sponsor() {
        let root: T::AccountId = account("root", 0, 1);
        let proposed: T::AccountId = account("proposed-root", 0, 2);
        RootSponsor::<T>::put(root);
        PendingRootSponsor::<T>::put(&proposed);

        #[extrinsic_call]
        _(RawOrigin::Signed(proposed.clone()));

        assert_eq!(RootSponsor::<T>::get(), Some(proposed));
        assert!(PendingRootSponsor::<T>::get().is_none());
    }

    #[benchmark]
    fn issue_cache_trigger_ticket() {
        let (cache, validator, epoch, slot, ticket_id, trigger_hash, ttl_blocks) =
            prepare_trigger::<T>();
        let trigger_hash_bounded: ProofHashOf<T> = trigger_hash
            .clone()
            .try_into()
            .expect("32-byte trigger hash fits proof-hash bound");
        let payload = Pallet::<T>::cache_trigger_issuance_payload(
            &validator.account,
            &ticket_id,
            &validator.node_id,
            &cache.node_id,
            &cache.did,
            &trigger_hash_bounded,
            ttl_blocks,
            0,
            epoch,
            slot,
        );
        let signature = T::BenchmarkHelper::sign(validator.seed, &payload);

        #[extrinsic_call]
        _(
            RawOrigin::Signed(validator.account),
            validator.node_id.into_inner(),
            cache.node_id.clone().into_inner(),
            cache.did.into_inner(),
            trigger_hash,
            ttl_blocks,
            0,
            signature,
        );

        assert!(CacheTriggerTickets::<T>::contains_key(
            cache.node_id,
            (epoch, slot)
        ));
    }

    #[benchmark]
    fn submit_cache_trigger_receipt() {
        let (cache, _validator, ticket) = issue_prepared_trigger::<T>();
        let message_id: MessageIdOf<T> = max_bytes::<<T as Config>::MaxMessageIdLen>(b'm');
        let receipt_hash: ProofHashOf<T> = vec![0x51; 32]
            .try_into()
            .expect("32-byte receipt hash fits proof-hash bound");
        let payload = Pallet::<T>::cache_trigger_receipt_payload(
            &ticket,
            &message_id,
            u64::MAX - 1,
            u64::MAX,
            1,
            u64::MAX,
            &receipt_hash,
        );
        let signature = T::BenchmarkHelper::sign(cache.seed, &payload);

        #[extrinsic_call]
        _(
            RawOrigin::Signed(cache.account),
            cache.node_id.clone().into_inner(),
            ticket.ticket_id.into_inner(),
            message_id.into_inner(),
            u64::MAX - 1,
            u64::MAX,
            1,
            u64::MAX,
            receipt_hash.into_inner(),
            signature,
        );

        assert!(
            CacheTriggerTickets::<T>::get(cache.node_id, (ticket.epoch, ticket.slot))
                .expect("benchmark ticket exists")
                .receipt
                .is_some()
        );
    }

    #[benchmark]
    fn attest_cache_trigger_ticket() {
        let (cache, validator, mut ticket) = submit_prepared_receipt::<T>();
        let receipt_hash = ticket
            .receipt
            .as_ref()
            .expect("benchmark receipt exists")
            .receipt_hash
            .clone();
        ticket.positive_attestations = T::RequiredTriggerAttestations::get()
            .max(1)
            .saturating_sub(1);
        ticket.canonical_evidence_hash = Some(receipt_hash.clone());
        CacheTriggerTickets::<T>::insert(&cache.node_id, (ticket.epoch, ticket.slot), &ticket);
        frame_system::Pallet::<T>::set_block_number(ticket.expires_at.saturating_add(1u32.into()));
        let payload = Pallet::<T>::cache_trigger_attestation_payload(
            &ticket.ticket_id,
            &validator.node_id,
            true,
            true,
            true,
            true,
            &receipt_hash,
        );
        let signature = T::BenchmarkHelper::sign(validator.seed, &payload);

        #[extrinsic_call]
        _(
            RawOrigin::Signed(validator.account),
            validator.node_id.into_inner(),
            ticket.ticket_id.clone().into_inner(),
            true,
            true,
            true,
            true,
            receipt_hash.into_inner(),
            signature,
        );

        assert!(
            CacheTriggerTickets::<T>::get(cache.node_id, (ticket.epoch, ticket.slot))
                .expect("benchmark ticket exists")
                .verified
        );
    }

    #[benchmark]
    fn finalize_cache_queue_depth_epoch() {
        let keeper: T::AccountId = account("keeper", 0, 1);
        let sponsor: T::AccountId = account("sponsor", 0, 2);
        let cache = install_actor::<T>("cache", 0, CACHE_SEED, NodeRole::Cache);
        let epoch = 1;
        admit_at::<T>(&cache, &sponsor, 0);
        CacheQueueDepthEpochs::<T>::insert(
            &cache.node_id,
            epoch,
            CacheQueueDepthEpoch {
                tickets_issued: T::TriggerTicketsPerEpoch::get(),
                tickets_verified: T::TriggerTicketsPerEpoch::get(),
                depth_sum: u128::MAX,
                ..Default::default()
            },
        );
        let current = epoch
            .saturating_add(T::EvidenceWindowEpochs::get())
            .saturating_add(1);
        set_epoch::<T>(current);

        #[extrinsic_call]
        _(
            RawOrigin::Signed(keeper),
            cache.node_id.clone().into_inner(),
            epoch,
        );

        assert!(CacheQueueDepthEpochs::<T>::get(cache.node_id, epoch).finalized);
    }

    #[benchmark]
    fn freeze_operator_queue_depth_epoch() {
        let keeper: T::AccountId = account("keeper", 0, 1);
        let operator: T::AccountId = account("operator", 0, 2);
        let epoch = 1;
        OperatorQueueDepthEpochs::<T>::insert(
            &operator,
            epoch,
            OperatorQueueDepthEpoch {
                total_average_bytes: u128::MAX,
                finalized_nodes: u32::MAX,
                frozen: false,
                multiplier_ppm: 0,
            },
        );
        set_epoch::<T>(
            epoch
                .saturating_add(T::EvidenceWindowEpochs::get())
                .saturating_add(2),
        );

        #[extrinsic_call]
        _(RawOrigin::Signed(keeper), operator.clone(), epoch);

        assert!(OperatorQueueDepthEpochs::<T>::get(operator, epoch).frozen);
    }

    #[benchmark]
    fn finalize_cache_raw_reward() {
        enable_rewards::<T>();
        let keeper: T::AccountId = account("keeper", 0, 1);
        let sponsor: T::AccountId = account("sponsor", 0, 2);
        let cache = install_actor::<T>("cache", 0, CACHE_SEED, NodeRole::Cache);
        let epoch = 1;
        admit_at::<T>(&cache, &sponsor, 0);
        CacheQueueDepthEpochs::<T>::insert(
            &cache.node_id,
            epoch,
            CacheQueueDepthEpoch {
                tickets_issued: T::TriggerTicketsPerEpoch::get(),
                tickets_verified: T::TriggerTicketsPerEpoch::get(),
                depth_sum: 1,
                finalized: true,
                average_depth: u64::MAX,
                average_bytes: u128::MAX,
            },
        );
        OperatorQueueDepthEpochs::<T>::insert(
            &cache.account,
            epoch,
            OperatorQueueDepthEpoch {
                total_average_bytes: u128::MAX,
                finalized_nodes: 1,
                frozen: true,
                multiplier_ppm: T::MaxStorageMultiplierPpm::get(),
            },
        );
        set_epoch::<T>(
            epoch
                .saturating_add(T::EvidenceWindowEpochs::get())
                .saturating_add(2),
        );

        #[extrinsic_call]
        _(
            RawOrigin::Signed(keeper),
            cache.node_id.clone().into_inner(),
            epoch,
        );

        assert!(CacheRewardRecords::<T>::contains_key(cache.node_id, epoch));
    }

    #[benchmark]
    fn close_reward_epoch() {
        enable_rewards::<T>();
        let keeper: T::AccountId = account("keeper", 0, 1);
        let epochs_per_year = T::EpochsPerRewardYear::get().max(1);
        let epoch = epochs_per_year.saturating_mul(2).saturating_sub(1);
        NextRewardEpochToClose::<T>::put(epoch);
        LastInitializedRewardYear::<T>::put(0);
        RewardYearStates::<T>::remove(1);
        EpochSettlements::<T>::remove(epoch);
        EpochRawRewardTotals::<T>::insert(epoch, BalanceOf::<T>::max_value());
        EpochRawRewardRecordCounts::<T>::insert(epoch, u64::MAX);
        set_epoch::<T>(
            epoch
                .saturating_add(T::EvidenceWindowEpochs::get())
                .saturating_add(2)
                .saturating_add(T::RewardFinalizationWindowEpochs::get().max(1)),
        );

        #[extrinsic_call]
        _(RawOrigin::Signed(keeper), epoch);

        assert!(EpochSettlements::<T>::contains_key(epoch));
        assert!(RewardYearStates::<T>::contains_key(1));
    }

    #[benchmark]
    fn claim_cache_reward() {
        enable_rewards::<T>();
        let keeper: T::AccountId = account("keeper", 0, 1);
        let operator: T::AccountId = account("operator", 0, 2);
        let cache_node_id = benchmark_node_id::<T>(CACHE_SEED);
        let epoch = 1;
        let amount = T::BaseEpochReward::get();
        let _ = T::Currency::deposit_creating(&operator, T::Currency::minimum_balance());
        let _ = T::Currency::deposit_creating(&Pallet::<T>::reward_pot_account(), amount);
        OutstandingRewardLiabilities::<T>::put(amount);
        CacheRewardRecords::<T>::insert(
            &cache_node_id,
            epoch,
            CacheRewardRecord::<T> {
                operator: operator.clone(),
                average_bytes: T::RewardStorageUnitBytes::get() as u128,
                quality_ppm: PPM as u32,
                storage_multiplier_ppm: PPM as u32,
                raw_amount: amount,
                raw_prefix_before: Zero::zero(),
                policy_version: 1,
                claimed_amount: None,
            },
        );
        EpochSettlements::<T>::insert(
            epoch,
            EpochSettlement {
                reward_year: 0,
                raw_total: amount,
                distributable: amount,
                record_count: 1,
                claimed_count: 0,
                claimed_total: Zero::zero(),
                closed: true,
            },
        );

        #[extrinsic_call]
        _(
            RawOrigin::Signed(keeper),
            cache_node_id.clone().into_inner(),
            epoch,
        );

        assert_eq!(
            CacheRewardRecords::<T>::get(cache_node_id, epoch)
                .expect("benchmark reward exists")
                .claimed_amount,
            Some(amount)
        );
        assert!(OperatorAccruedRewards::<T>::get(operator).is_zero());
    }

    #[benchmark]
    fn withdraw_accrued_reward() {
        enable_rewards::<T>();
        let operator: T::AccountId = account("operator", 0, 2);
        let amount = T::BaseEpochReward::get();
        let _ = T::Currency::deposit_creating(&operator, T::Currency::minimum_balance());
        let _ = T::Currency::deposit_creating(&Pallet::<T>::reward_pot_account(), amount);
        OperatorAccruedRewards::<T>::insert(&operator, amount);
        OutstandingRewardLiabilities::<T>::put(amount);

        #[extrinsic_call]
        _(RawOrigin::Signed(operator.clone()));

        assert!(OperatorAccruedRewards::<T>::get(operator).is_zero());
    }

    #[benchmark]
    fn prune_cache_reward_history() {
        let keeper: T::AccountId = account("keeper", 0, 1);
        let sponsor: T::AccountId = account("sponsor", 0, 2);
        let cache = install_actor::<T>("cache", 0, CACHE_SEED, NodeRole::Cache);
        let epoch = 1;
        let amount = T::BaseEpochReward::get();
        EpochSettlements::<T>::insert(
            epoch,
            EpochSettlement {
                reward_year: 0,
                raw_total: amount,
                distributable: amount,
                record_count: 1,
                claimed_count: 1,
                claimed_total: amount,
                closed: true,
            },
        );
        CacheRewardRecords::<T>::insert(
            &cache.node_id,
            epoch,
            CacheRewardRecord::<T> {
                operator: cache.account.clone(),
                average_bytes: u128::MAX,
                quality_ppm: PPM as u32,
                storage_multiplier_ppm: T::MaxStorageMultiplierPpm::get(),
                raw_amount: amount,
                raw_prefix_before: Zero::zero(),
                policy_version: 1,
                claimed_amount: Some(amount),
            },
        );
        admit_at::<T>(&cache, &sponsor, 0);
        for slot in 0..T::TriggerTicketsPerEpoch::get() {
            let ticket = maximal_historical_ticket::<T>(&cache, epoch, slot);
            CacheTriggerTicketById::<T>::insert(
                &ticket.ticket_id,
                (cache.node_id.clone(), epoch, slot),
            );
            CacheTriggerTickets::<T>::insert(&cache.node_id, (epoch, slot), &ticket);
            for key in 0..T::MaxPruneKeysPerCall::get().max(1) {
                let did = benchmark_did::<T>(100 + slot.saturating_mul(32) + key);
                CacheTriggerAttestations::<T>::insert(
                    &ticket.ticket_id,
                    did,
                    CacheTriggerAttestation::<T> {
                        validator_node_id: benchmark_node_id::<T>(100 + key),
                        accepted: true,
                        retained: true,
                        retrieved: true,
                        purged: true,
                        evidence_hash: vec![0x62; 32]
                            .try_into()
                            .expect("32-byte evidence hash fits proof-hash bound"),
                        signature: max_bytes::<<T as Config>::MaxSignatureLen>(b's'),
                    },
                );
            }
        }
        CacheQueueDepthEpochs::<T>::insert(
            &cache.node_id,
            epoch,
            CacheQueueDepthEpoch {
                tickets_issued: T::TriggerTicketsPerEpoch::get(),
                tickets_verified: T::TriggerTicketsPerEpoch::get(),
                depth_sum: u128::MAX,
                finalized: true,
                average_depth: u64::MAX,
                average_bytes: u128::MAX,
            },
        );
        let after_retention = epoch
            .saturating_add(CacheRewardHistoryRetentionEpochsValue::<T>::get())
            .saturating_add(1);
        let after_settlement = epoch
            .saturating_add(T::EvidenceWindowEpochs::get())
            .saturating_add(2)
            .saturating_add(T::RewardFinalizationWindowEpochs::get().max(1));
        set_epoch::<T>(after_retention.max(after_settlement));

        #[extrinsic_call]
        _(RawOrigin::Signed(keeper), cache.node_id.into_inner(), epoch);
    }

    #[benchmark]
    fn prune_operator_queue_depth_history() {
        let keeper: T::AccountId = account("keeper", 0, 1);
        let operator: T::AccountId = account("operator", 0, 2);
        let epoch = 1;
        EpochSettlements::<T>::insert(
            epoch,
            EpochSettlement {
                reward_year: 0,
                raw_total: Zero::zero(),
                distributable: Zero::zero(),
                record_count: 0,
                claimed_count: 0,
                claimed_total: Zero::zero(),
                closed: true,
            },
        );
        OperatorQueueDepthEpochs::<T>::insert(
            &operator,
            epoch,
            OperatorQueueDepthEpoch {
                total_average_bytes: u128::MAX,
                finalized_nodes: u32::MAX,
                frozen: true,
                multiplier_ppm: T::MaxStorageMultiplierPpm::get(),
            },
        );
        let after_retention = epoch
            .saturating_add(CacheRewardHistoryRetentionEpochsValue::<T>::get())
            .saturating_add(1);
        let after_settlement = epoch
            .saturating_add(T::EvidenceWindowEpochs::get())
            .saturating_add(2)
            .saturating_add(T::RewardFinalizationWindowEpochs::get().max(1));
        set_epoch::<T>(after_retention.max(after_settlement));

        #[extrinsic_call]
        _(RawOrigin::Signed(keeper), operator.clone(), epoch);

        assert!(!OperatorQueueDepthEpochs::<T>::contains_key(
            operator, epoch
        ));
    }

    impl_benchmark_test_suite!(Pallet, crate::mock::new_test_ext(), crate::mock::Test);
}
