//! A shared, deliberately overcharging validation envelope. Each measured block
//! includes pool authorization AND dispatch for registration, full replacement
//! and a patch. Generated measurements are combined with a 2x safety margin;
//! each individual validation annotation pays this entire envelope.
use super::*;
use alloc::{format, vec};
use frame_benchmarking::v2::*;
use frame_system::RawOrigin;
use serde_json::json;

fn bounded<V, S: Get<u32>>(bytes: Vec<V>) -> BoundedVec<V, S> {
    bytes
        .try_into()
        .unwrap_or_else(|_| panic!("benchmark data exceeds configured bound {}", S::get()))
}
fn multibase(bytes: &[u8]) -> Vec<u8> {
    const A: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut digits = Vec::<u8>::new();
    for b in bytes {
        let mut carry = *b as u32;
        for d in &mut digits {
            carry += *d as u32 * 256;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry != 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut result = vec![b'z'];
    result.extend(core::iter::repeat_n(
        b'1',
        bytes.iter().take_while(|b| **b == 0).count(),
    ));
    result.extend(digits.iter().rev().map(|d| A[*d as usize]));
    result
}
fn key<T: Config>(
    did: &[u8],
    id: &[u8],
    material: &[u8],
    overlay: bool,
    padding: usize,
) -> VerificationMethod<T> {
    let type_ = b"Ed25519VerificationKey2020";
    let bytes = if overlay {
        let value = json!({"id":core::str::from_utf8(id).unwrap(),"type":core::str::from_utf8(type_).unwrap(),
            "controller":core::str::from_utf8(did).unwrap(),"publicKeyMultibase":core::str::from_utf8(material).unwrap(),
            "publicKeyJwk":{"values":vec![0;230]},"padding":"a".repeat(padding)});
        [input::KEY_PREFIX, &serde_json::to_vec(&value).unwrap()].concat()
    } else {
        material.to_vec()
    };
    VerificationMethod {
        id: bounded(id.to_vec()),
        type_: bounded(type_.to_vec()),
        controller: bounded(did.to_vec()),
        public_key_multibase: bounded(bytes),
    }
}
fn document<T: Config>(overlay: bool, depth: bool) -> DidDocument<T> {
    let did = b"did:openpayload:111111111111111111111111111111111111111111111111";
    let material = multibase(&T::BenchmarkHelper::public());
    let mut methods = Vec::new();
    let mut agreements = Vec::new();
    for i in 0..T::MaxVMs::get() {
        methods.push(key::<T>(
            did,
            format!("#v{i}").as_bytes(),
            &material,
            true,
            if overlay { 200 } else { 1700 },
        ));
    }
    for i in 0..T::MaxKAs::get() {
        let k = key::<T>(
            did,
            format!("#k{i}").as_bytes(),
            &material,
            overlay,
            if overlay { 2600 } else { 0 },
        );
        agreements.push(KeyAgreement {
            id: k.id,
            type_: bounded(k.type_.into_inner()),
            controller: k.controller,
            public_key_multibase: k.public_key_multibase,
        });
    }
    let authentication: RefListOf<T> = bounded(
        (0..T::MaxRefsPerRel::get().min(T::MaxVMs::get()))
            .map(|i| bounded(format!("#v{i}").into_bytes()))
            .collect(),
    );
    let mut services = Vec::new();
    for i in 0..T::MaxServices::get() {
        let id = format!("#s{i}");
        let endpoint = if overlay {
            let mut data = json!({"values":vec![0;230],"padding":"x".repeat(200)});
            if depth {
                for _ in 0..12 {
                    data = json!({"nested":data});
                }
            }
            let value = json!({"id":id,"type":"OverlayService","serviceEndpoint":data});
            [input::OVERLAY_PREFIX, &serde_json::to_vec(&value).unwrap()].concat()
        } else {
            let mut u = b"https://example.com/".to_vec();
            u.resize(128, b'a');
            u
        };
        services.push(Service::<T> {
            id: bounded(id.into_bytes()),
            type_: bounded(if overlay {
                b"OverlayService".to_vec()
            } else {
                b"OpenPayloadCacheService".to_vec()
            }),
            service_endpoint: bounded(if overlay {
                vec![bounded(endpoint)]
            } else {
                vec![bounded(endpoint); T::MaxServiceEndpoints::get() as usize]
            }),
            authorization: if overlay {
                None
            } else {
                Some(bounded(
                    (0..T::MaxVMs::get())
                        .map(|i| bounded(format!("#v{i}").into_bytes()))
                        .collect(),
                ))
            },
            priority: if overlay { None } else { Some(u32::MAX) },
        });
    }
    let mut doc = DidDocument::<T> {
        id: bounded(did.to_vec()),
        verification_method: bounded(methods),
        authentication: if overlay { Some(authentication) } else { None },
        key_agreement: bounded(agreements),
        service: Some(bounded(services)),
    };
    // Fill the last key to approach the total limit while retaining the 4 KiB
    // component limit. Crypto documents also use an envelope on this last key.
    let index = doc.verification_method.len() - 1;
    let id = doc.verification_method[index].id.clone();
    for n in 0..3000 {
        let candidate = key::<T>(did, &id, &material, true, n);
        if candidate.encoded_size() > 4096 {
            break;
        }
        let old = core::mem::replace(&mut doc.verification_method[index], candidate);
        if doc.encoded_size() > T::MaxDocLen::get() as usize {
            doc.verification_method[index] = old;
            break;
        }
    }
    assert!(doc.encoded_size() <= T::MaxDocLen::get() as usize);
    Pallet::<T>::validate_document_structure(&doc.id, &doc).expect("worst-case fixture validates");
    doc
}
struct Calls<T: Config> {
    register: Call<T>,
    replace: Call<T>,
    patch: Call<T>,
}
fn calls<T: Config>(overlay: bool, depth: bool) -> Calls<T> {
    let doc = document::<T>(overlay, depth);
    let did = doc.id.to_vec();
    let blob = doc.encode();
    let public = T::BenchmarkHelper::public();
    let token = b"v2:0:60000".to_vec();
    let alias = Some(vec![b'a'; T::MaxAliasLen::get() as usize]);
    let registration = registration_payload(&did, alias.as_deref(), &public, &blob, &token);
    let replace_payload = [
        b"openpayload:set_document:v2|".as_slice(),
        &did,
        b"|",
        &sp_io::hashing::blake2_256(&blob),
        b"|",
        &token,
    ]
    .concat();
    // Patch authorization follows the last authenticated method: exercise a
    // non-root signer, including envelope extraction and valid point checking.
    let signer: IdStrOf<T> = doc
        .authentication
        .as_ref()
        .map(|a| a.last().unwrap().clone())
        .unwrap_or_else(|| bounded(b"root".to_vec()));
    let method = doc.verification_method.last().unwrap().clone();
    let payload = DocumentAuthorizationPayload::<T> {
        did: doc.id.clone(),
        action: DocumentAction::UpdateVerificationMethod,
        verification_method: Some(method.clone()),
        key_agreement: None,
        service: None,
        id: None,
        nonce: 1,
        valid_until: 60000,
        signer_key_id: signer.clone(),
    }
    .encode();
    Calls {
        register: Call::register_with_document_proof {
            did: did.clone(),
            alias,
            timestamp: token.clone(),
            pubkey: public.clone(),
            signature: T::BenchmarkHelper::sign(&registration),
            doc_blob: blob.clone(),
        },
        replace: Call::set_document_with_proof {
            did: did.clone(),
            doc_blob: blob,
            timestamp: token,
            pubkey: public,
            signature: T::BenchmarkHelper::sign(&replace_payload),
        },
        patch: Call::update_verification_method {
            did,
            method,
            signed_payload: payload.clone(),
            signature: T::BenchmarkHelper::sign(&payload),
            signer_key_id: signer.to_vec(),
        },
    }
}
fn run<T: Config>(calls: Calls<T>) {
    use frame_support::traits::UnfilteredDispatchable;
    for call in [calls.register, calls.replace, calls.patch] {
        Pallet::<T>::authorize_unsigned_call(&call).expect("pool authorization succeeds");
        call.dispatch_bypass_filter(RawOrigin::None.into())
            .expect("dispatch succeeds");
    }
}
#[benchmarks]
mod benchmarks {
    use super::*;
    use frame_support::traits::{Hooks, UnfilteredDispatchable};
    #[benchmark]
    fn device_registry() {
        let doc = document::<T>(true, false);
        let did = doc.id.clone();
        let legacy: BoundedVec<DeviceInfo, T::MaxLegacyDevices> = bounded(
            (0..T::MaxLegacyDevices::get())
                .map(|n| DeviceInfo {
                    device_id: bounded(format!("legacy-{n}").into_bytes()),
                    added_at: 0,
                    tombstoned: false,
                })
                .collect(),
        );
        let aliases: AliasListOf<T> = bounded(
            (0..T::MaxAliases::get())
                .map(|n| bounded(format!("alias-{n}").into_bytes()))
                .collect(),
        );
        for alias in &aliases {
            AliasIndex::<T>::insert(alias, &did);
        }
        let keys = DeviceKeyAgreementOverride::<T> {
            active: doc.key_agreement[0].clone(),
            rotation: Some(doc.key_agreement[1].clone()),
        };
        Dids::<T>::insert(
            &did,
            DidRecord::<T> {
                owner: None,
                aliases: Some(aliases),
                devices: Some(legacy),
                document: Some(doc),
                version: 1,
                updated_at: 0,
                root_pubkey: Some(bounded(T::BenchmarkHelper::public())),
                delivery_policy_links: None,
                deactivated: false,
            },
        );
        for n in 0..500 {
            let id: DeviceIdOf = bounded(format!("stored-{n}").into_bytes());
            Devices::<T>::insert(
                &did,
                &id,
                DeviceRecord::<T> {
                    info: DeviceInfo {
                        device_id: id.clone(),
                        added_at: 0,
                        tombstoned: false,
                    },
                    key_agreement_override: Some(keys.clone()),
                    revision: 1,
                },
            );
        }
        T::BenchmarkHelper::install_policy(&did);
        let id: DeviceIdOf = bounded(b"new-device".to_vec());
        let renamed: DeviceIdOf = bounded(b"renamed-device".to_vec());
        let actions = [
            ControlAction::AddDevice {
                device_id: id.clone(),
            },
            ControlAction::SetDeviceKeyAgreement {
                device_id: id.clone(),
                key_agreement_override: Some(keys),
            },
            ControlAction::UpdateDevice {
                old_device_id: id,
                new_device_id: renamed.clone(),
            },
            ControlAction::TombstoneDevice {
                device_id: renamed.clone(),
            },
            ControlAction::RemoveDevice { device_id: renamed },
            ControlAction::DeleteDid,
        ];
        let mut calls = Vec::new();
        for (nonce, action) in actions.into_iter().enumerate() {
            let payload = ControlAuthorizationPayload::<T> {
                did: did.clone(),
                action,
                nonce: nonce as u64,
                valid_until: 60_000,
                signer_key_id: bounded(b"root".to_vec()),
            }
            .encode();
            calls.push(Call::apply_control_with_proof {
                signature: T::BenchmarkHelper::sign(&payload),
                signed_payload: payload,
                signer_key_id: b"root".to_vec(),
            });
        }
        #[block]
        {
            for call in calls {
                assert!(Pallet::<T>::authorize_unsigned_call(&call).is_ok());
                frame_support::assert_ok!(call.dispatch_bypass_filter(RawOrigin::None.into()));
            }
            Pallet::<T>::on_idle(1u32.into(), Weight::MAX);
        }
    }
    #[benchmark]
    fn input_crypto() {
        let c = calls::<T>(false, false);
        #[block]
        {
            run(c);
        }
    }
    #[benchmark]
    fn input_overlay() {
        let c = calls::<T>(true, false);
        #[block]
        {
            run(c);
        }
    }
    #[benchmark]
    fn input_depth() {
        let c = calls::<T>(true, true);
        #[block]
        {
            run(c);
        }
    }
    #[benchmark]
    fn input_rejection() {
        let mut doc = document::<T>(true, false);
        let endpoint = &mut doc
            .service
            .as_mut()
            .unwrap()
            .last_mut()
            .unwrap()
            .service_endpoint[0];
        let mut bytes = endpoint.to_vec();
        bytes.pop();
        *endpoint = bounded(bytes);
        let did = doc.id.clone();
        #[block]
        {
            assert!(Pallet::<T>::validate_document_structure(&did, &doc).is_err());
        }
    }
    impl_benchmark_test_suite!(Pallet, crate::mock::new_test_ext(), crate::mock::Test);
}
