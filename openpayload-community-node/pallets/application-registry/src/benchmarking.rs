//! Conservative envelope: pool validation and dispatch for all five proof operations.
use super::*;
use frame_benchmarking::v2::*;
use frame_support::assert_ok;
use sp_runtime::traits::Zero;

fn bounded<S: Get<u32>>(value: &[u8]) -> BoundedVec<u8, S> {
    value.to_vec().try_into().ok().unwrap()
}

#[benchmarks]
mod benchmarks {
    use super::*;
    #[benchmark]
    fn proof_envelope() {
        let owner: DidOf<T> = bounded(b"did:openpayload:1111111111111111111111");
        let linked: DidOf<T> = bounded(b"did:openpayload:3333333333333333333333");
        T::BenchmarkHelper::install_did(&owner, 1);
        T::BenchmarkHelper::install_did(&linked, 3);
        let application_id: ApplicationIdOf<T> = bounded(b"benchmark");
        T::BenchmarkHelper::install_policy(&application_id,&owner);
        // Fill every index read/rewritten by these operations to its configured bound.
        for control in [&owner, &linked] {
            let mut ids =
                BoundedVec::<ApplicationIdOf<T>, T::MaxApplicationsPerControlDid>::default();
            for _ in 1..T::MaxApplicationsPerControlDid::get() {
                ids.try_push(application_id.clone()).ok().unwrap();
            }
            ApplicationsByControlDid::<T>::insert(control, ids);
        }
        let mut ids = BoundedVec::<DidOf<T>, T::MaxLinkedDids>::default();
        for _ in 1..T::MaxLinkedDids::get() {
            ids.try_push(owner.clone()).ok().unwrap();
        }
        ApplicationLinkedDids::<T>::insert(&application_id, ids);
        let operations = [
            ApplicationOperation::Register {
                application_id: application_id.clone(),
            },
            ApplicationOperation::SetDomain {
                application_id: application_id.clone(),
                domain: None,
            },
            ApplicationOperation::SetLinkedDid {
                application_id: application_id.clone(),
                linked_did: linked.clone(),
                enabled: true,
            },
            ApplicationOperation::Update {
                application_id: application_id.clone(),
                new_control_did: linked,
            },
            ApplicationOperation::SetStatus {
                application_id,
                status: ApplicationStatus::Tombstoned,
            },
        ];
        let mut calls = Vec::new();
        for (index, operation) in operations.into_iter().enumerate() {
            let is_link = matches!(&operation, ApplicationOperation::SetLinkedDid { .. });
            let current = if index == 4 {
                bounded(b"did:openpayload:3333333333333333333333")
            } else {
                owner.clone()
            };
            let seed = if index == 4 { 3 } else { 1 };
            let proof = ApplicationAuthorizationPayload::<T> {
                genesis_hash: frame_system::Pallet::<T>::block_hash(BlockNumberFor::<T>::zero()),
                operator_did: current,
                signer_key_id: bounded(b"#v4"),
                linked_signer_key_id: is_link.then(|| bounded(b"#v4")),
                operation,
                nonce: if index == 4 { 0 } else { index as u64 },
                valid_until: 60_000,
            };
            let payload = Pallet::<T>::proof_payload(&proof);
            let signature: SignatureOf<T> = bounded(&T::BenchmarkHelper::sign(seed, &payload));
            let linked_signature: SignatureOf<T> = if is_link {
                bounded(&T::BenchmarkHelper::sign(3, &payload))
            } else {
                Default::default()
            };
            calls.push((payload, signature, linked_signature));
        }
        #[block]
        {
            for (payload, signature, linked_signature) in calls {
                assert!(Pallet::<T>::authorize_application(
                    &payload,
                    &signature,
                    &linked_signature
                )
                .is_ok());
                assert_ok!(Pallet::<T>::apply_application_with_proof(
                    frame_system::RawOrigin::None.into(),
                    payload,
                    signature,
                    linked_signature
                ));
            }
        }
    }
    impl_benchmark_test_suite!(Pallet, crate::mock::new_test_ext(), crate::mock::Test);
}
