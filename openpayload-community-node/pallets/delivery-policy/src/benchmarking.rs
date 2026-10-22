//! Conservative whole-envelope measurement of authorization and dispatch at every scope.
use super::*;
use alloc::vec;
use frame_benchmarking::v2::*;
use frame_support::assert_ok;
use sp_runtime::traits::Zero;

#[benchmarks]
mod benchmarks {
    use super::*;

    #[benchmark]
    fn policy_document_envelope() {
        let owner: DidOf<T> = b"did:openpayload:1111111111111111111111".to_vec().try_into().ok().unwrap();
        let application = b"benchmark";
        T::BenchmarkHelper::install(&owner, application);
        let signer: PolicyDocumentSigner = T::BenchmarkHelper::signer().try_into().ok().unwrap();
        let persona: PersonaOf<T> = b"policy.example.com".to_vec().try_into().ok().unwrap();
        let mut keys = ControllerKeysOf::<T>::default();
        for _ in 1..T::MaxPersonaControllerKeys::get() {
            keys.try_push(vec![b'x'; 64].try_into().ok().unwrap())
                .ok()
                .unwrap();
        }
        keys.try_push(signer.to_vec().try_into().ok().unwrap())
            .ok()
            .unwrap();
        Personas::<T>::insert(
            &persona,
            PersonaRecord::<T> {
                operator_did: owner.clone(),
                controller_key_ids: keys,
                controller_threshold: 1,
                delivery_constraints: None,
                dns_proof_hash: [0; 32],
                verified_at: 0,
                verification_expires_at: u64::MAX,
                revision: 1,
                active: true,
            },
        );
        let scopes = [
            PolicyScopeV3::Did(owner.clone()),
            PolicyScopeV3::Persona(persona),
            PolicyScopeV3::Application(application.to_vec().try_into().ok().unwrap()),
        ];
        let document: PolicyDocumentOf<T> = vec![0xff; T::MaxPolicyDocumentBytes::get() as usize]
            .try_into()
            .ok()
            .unwrap();
        let mut calls = Vec::new();
        let mut nonce = 0;
        for scope in scopes {
            // Charge reading/replacing the maximum old record, too.
            PoliciesV4::<T>::insert(
                &scope,
                PolicyDocumentRecord::<T> {
                    revision: 1,
                    operator_did: owner.clone(),
                    content_hash: sp_io::hashing::blake2_256(&document),
                    document: document.clone(),
                },
            );
            for revision in 2..=4 {
                let operation = if revision == 3 {
                    PolicyDocumentOperation::Clear {
                        scope: scope.clone(),
                        revision,
                    }
                } else {
                    PolicyDocumentOperation::Set {
                        scope: scope.clone(),
                        revision,
                        document: document.clone(),
                    }
                };
                let proof = PolicyDocumentAuthorizationPayload::<T> {
                    domain: POLICY_DOCUMENT_PROOF_DOMAIN
                        .to_vec()
                        .try_into()
                        .ok()
                        .unwrap(),
                    genesis_hash: frame_system::Pallet::<T>::block_hash(BlockNumberFor::<T>::zero()),
                    operator_did: owner.clone(),
                    signer_key_id: signer.clone(),
                    operation,
                    nonce,
                    valid_until: 60_000,
                };
                let bytes = proof.encode();
                let signature = T::BenchmarkHelper::sign(&bytes);
                calls.push((bytes, signature, signer.to_vec()));
                nonce += 1;
            }
        }
        #[block]
        {
            for (bytes, signature, signer) in calls {
                assert!(
                    Pallet::<T>::authorize_policy_document(&bytes, &signature, &signer).is_ok()
                );
                assert_ok!(Pallet::<T>::apply_policy_document_with_proof(
                    frame_system::RawOrigin::None.into(),
                    bytes,
                    signature,
                    signer
                ));
            }
        }
        assert_eq!(PolicyV4Nonces::<T>::get(owner), 9);
    }
    impl_benchmark_test_suite!(Pallet, crate::mock::new_test_ext(), crate::mock::Test);
}
