#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use frame_support::{
    pallet_prelude::*,
    traits::{EnsureOrigin, StorageVersion},
    BoundedVec, DebugNoBound,
};
use frame_system::pallet_prelude::*;
use scale_info::TypeInfo;
use sp_runtime::{
    traits::{SaturatedConversion, Zero},
    transaction_validity::{InvalidTransaction, TransactionValidityWithRefund, ValidTransaction},
};

pub use pallet::*;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;
mod measured_weights;
pub mod weights;
#[cfg(feature = "runtime-benchmarks")]
pub trait BenchmarkHelper {
    fn install_policy(_application: &[u8], _did: &[u8]) {}
    fn install_did(did: &[u8], seed: u32);
    fn sign(seed: u32, payload: &[u8]) -> Vec<u8>;
}

pub trait ApplicationPolicyCleanup {
    fn clear(application_id: &[u8]);
}

/// DNS proof is checked against finalized chain state by the runtime. The
/// Application keeps its own optional domain; a Persona is only the existing
/// DNS proof source, not the Application's identity or policy scope.
pub trait DomainProvider {
    fn controlled_domain(domain: &[u8], control_did: &[u8]) -> bool;
}

impl DomainProvider for () {
    fn controlled_domain(_domain: &[u8], _control_did: &[u8]) -> bool {
        false
    }
}

impl ApplicationPolicyCleanup for () {
    fn clear(_application_id: &[u8]) {}
}

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use crate::weights::WeightInfo as _;
    use pallet_delivery_policy::DidProvider;

    const PROOF_DOMAIN: &[u8] = b"openpayload:application-registry:v2";
    const MAX_PROOF_BYTES: usize = 2048;
    const MAX_PROOF_LIFETIME_MILLIS: u64 = 600_000;

    const AUTHORIZATION_DOMAIN: &[u8] = b"openpayload:application-registry:v1";
    const STORAGE_VERSION: StorageVersion = StorageVersion::new(2);

    pub type ApplicationIdOf<T> = BoundedVec<u8, <T as Config>::MaxApplicationIdLen>;
    pub type DidOf<T> = BoundedVec<u8, <T as Config>::MaxDidLen>;
    pub type KeyIdOf<T> = BoundedVec<u8, <T as Config>::MaxKeyIdLen>;
    pub type SignatureOf<T> = BoundedVec<u8, <T as Config>::MaxSignatureLen>;
    pub type DomainOf<T> = BoundedVec<u8, <T as Config>::MaxDomainLen>;
    pub type PolicyDocumentOf<T> = BoundedVec<u8, <T as Config>::MaxPolicyDocumentLen>;

    #[derive(
        Encode,
        Decode,
        DecodeWithMemTracking,
        Clone,
        Copy,
        PartialEq,
        Eq,
        Debug,
        TypeInfo,
        MaxEncodedLen,
    )]
    pub enum ApplicationStatus {
        Active,
        Suspended,
        Tombstoned,
    }

    #[derive(
        Encode,
        Decode,
        DecodeWithMemTracking,
        Clone,
        PartialEq,
        Eq,
        DebugNoBound,
        TypeInfo,
        MaxEncodedLen,
    )]
    #[scale_info(skip_type_params(T))]
    #[codec(mel_bound())]
    #[codec(decode_bound())]
    #[codec(decode_with_mem_tracking_bound())]
    pub struct ApplicationRecord<T: Config> {
        pub control_did: DidOf<T>,
        pub status: ApplicationStatus,
        pub revision: u64,
        pub registered_at: BlockNumberFor<T>,
        pub updated_at: BlockNumberFor<T>,
    }

    #[derive(
        Encode,
        Decode,
        DecodeWithMemTracking,
        Clone,
        PartialEq,
        Eq,
        DebugNoBound,
        TypeInfo,
        MaxEncodedLen,
    )]
    #[scale_info(skip_type_params(T))]
    #[codec(mel_bound())]
    #[codec(decode_bound())]
    #[codec(decode_with_mem_tracking_bound())]
    pub struct ApplicationPolicy<T: Config> {
        pub revision: u64,
        pub policy_ttl_seconds: u32,
        pub document: PolicyDocumentOf<T>,
        pub updated_at: BlockNumberFor<T>,
    }

    /// Stable operation discriminants are shared with Directory clients.
    #[derive(
        Encode,
        Decode,
        DecodeWithMemTracking,
        Clone,
        PartialEq,
        Eq,
        DebugNoBound,
        TypeInfo,
        MaxEncodedLen,
    )]
    #[scale_info(skip_type_params(T))]
    #[codec(mel_bound())]
    #[codec(decode_bound())]
    #[codec(decode_with_mem_tracking_bound())]
    pub enum ApplicationOperation<T: Config> {
        Register {
            application_id: ApplicationIdOf<T>,
        },
        Update {
            application_id: ApplicationIdOf<T>,
            new_control_did: DidOf<T>,
        },
        SetStatus {
            application_id: ApplicationIdOf<T>,
            status: ApplicationStatus,
        },
        SetDomain {
            application_id: ApplicationIdOf<T>,
            domain: Option<DomainOf<T>>,
        },
        SetLinkedDid {
            application_id: ApplicationIdOf<T>,
            linked_did: DidOf<T>,
            enabled: bool,
        },
    }

    #[derive(
        Encode,
        Decode,
        DecodeWithMemTracking,
        Clone,
        PartialEq,
        Eq,
        DebugNoBound,
        TypeInfo,
        MaxEncodedLen,
    )]
    #[scale_info(skip_type_params(T))]
    #[codec(mel_bound())]
    #[codec(decode_bound())]
    #[codec(decode_with_mem_tracking_bound())]
    pub struct ApplicationAuthorizationPayload<T: Config> {
        pub genesis_hash: T::Hash,
        pub operator_did: DidOf<T>,
        pub signer_key_id: KeyIdOf<T>,
        pub linked_signer_key_id: Option<KeyIdOf<T>>,
        pub operation: ApplicationOperation<T>,
        pub nonce: u64,
        /// Unix milliseconds, at most ten minutes after chain time.
        pub valid_until: u64,
    }

    #[pallet::config]
    pub trait Config: frame_system::Config + pallet_timestamp::Config {
        #[cfg(feature = "runtime-benchmarks")]
        type BenchmarkHelper: BenchmarkHelper;
        type DidProvider: DidProvider<Self::AccountId>;
        type DomainProvider: DomainProvider;
        type PolicyCleanup: ApplicationPolicyCleanup;
        type GovernanceOrigin: EnsureOrigin<Self::RuntimeOrigin>;
        type WeightInfo: crate::weights::WeightInfo;

        #[pallet::constant]
        type MaxApplicationIdLen: Get<u32>;
        #[pallet::constant]
        type MaxDidLen: Get<u32>;
        #[pallet::constant]
        type MaxKeyIdLen: Get<u32>;
        #[pallet::constant]
        type MaxSignatureLen: Get<u32>;
        #[pallet::constant]
        type MaxApplicationsPerControlDid: Get<u32>;
        #[pallet::constant]
        type MaxPolicyDocumentLen: Get<u32>;
        #[pallet::constant]
        type MaxPolicyTtlSeconds: Get<u32>;
        #[pallet::constant]
        type MaxDomainLen: Get<u32>;
        #[pallet::constant]
        type MaxLinkedDids: Get<u32>;
    }

    #[pallet::pallet]
    #[pallet::storage_version(STORAGE_VERSION)]
    pub struct Pallet<T>(_);

    #[pallet::storage]
    #[pallet::getter(fn application)]
    pub type Applications<T: Config> =
        StorageMap<_, Blake2_128Concat, ApplicationIdOf<T>, ApplicationRecord<T>, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn applications_for_control_did)]
    pub type ApplicationsByControlDid<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        DidOf<T>,
        BoundedVec<ApplicationIdOf<T>, T::MaxApplicationsPerControlDid>,
        ValueQuery,
    >;

    /// The optional DNS namespace is separate from application_id. Absence
    /// grants no Call authority. DNS control is rechecked when used.
    #[pallet::storage]
    #[pallet::getter(fn application_domain)]
    pub type ApplicationDomains<T: Config> =
        StorageMap<_, Blake2_128Concat, ApplicationIdOf<T>, DomainOf<T>, OptionQuery>;

    /// Explicit consent from both the control DID and target DID permits an
    /// Application policy Send step to use that target.
    #[pallet::storage]
    #[pallet::getter(fn linked_did)]
    pub type ApplicationLinkedDids<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        ApplicationIdOf<T>,
        BoundedVec<DidOf<T>, T::MaxLinkedDids>,
        ValueQuery,
    >;

    #[pallet::storage]
    #[pallet::getter(fn authorization_nonce)]
    pub type AuthorizationNonces<T: Config> =
        StorageMap<_, Blake2_128Concat, DidOf<T>, u64, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn application_policy)]
    pub type ApplicationPolicies<T: Config> =
        StorageMap<_, Blake2_128Concat, ApplicationIdOf<T>, ApplicationPolicy<T>, OptionQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        ApplicationRegistered {
            application_id: ApplicationIdOf<T>,
            control_did: DidOf<T>,
        },
        ApplicationUpdated {
            application_id: ApplicationIdOf<T>,
            control_did: DidOf<T>,
            revision: u64,
        },
        ApplicationStatusChanged {
            application_id: ApplicationIdOf<T>,
            status: ApplicationStatus,
            revision: u64,
        },
        ApplicationPolicySet {
            application_id: ApplicationIdOf<T>,
            revision: u64,
        },
        ApplicationPolicyCleared {
            application_id: ApplicationIdOf<T>,
        },
        ApplicationDomainChanged {
            application_id: ApplicationIdOf<T>,
            domain: Option<DomainOf<T>>,
            revision: u64,
        },
        ApplicationLinkedDidChanged {
            application_id: ApplicationIdOf<T>,
            linked_did: DidOf<T>,
            enabled: bool,
            revision: u64,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        InvalidApplicationId,
        ApplicationAlreadyExists,
        ApplicationNotFound,
        ControlDidNotFound,
        InvalidAuthorization,
        AuthorizationNonceOverflow,
        RevisionOverflow,
        TooManyApplicationsForControlDid,
        ApplicationTombstoned,
        InvalidStatusTransition,
        InvalidPolicyTtl,
        EmptyPolicyDocument,
        PolicyNotFound,
        PolicyRevisionOverflow,
        LegacyPolicyDeprecated,
        InvalidDomain,
        DomainNotControlled,
        LinkedDidNotFound,
        TooManyLinkedDids,
        ProofRequired,
        InvalidProofPayload,
        WrongChain,
        AuthorizationExpired,
        InvalidAuthorizationNonce,
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_runtime_upgrade() -> Weight {
            if Pallet::<T>::on_chain_storage_version() < STORAGE_VERSION {
                STORAGE_VERSION.put::<Pallet<T>>();
                return T::DbWeight::get().reads_writes(1, 1);
            }
            T::DbWeight::get().reads(1)
        }

        #[cfg(feature = "try-runtime")]
        fn pre_upgrade() -> Result<Vec<u8>, sp_runtime::TryRuntimeError> {
            ensure!(
                ApplicationPolicies::<T>::iter_keys().next().is_none(),
                "legacy application policies require an explicit migration before V3"
            );
            Ok(Vec::new())
        }

        #[cfg(feature = "try-runtime")]
        fn post_upgrade(_state: Vec<u8>) -> Result<(), sp_runtime::TryRuntimeError> {
            ensure!(
                Pallet::<T>::on_chain_storage_version() == STORAGE_VERSION,
                "application-registry storage version was not installed"
            );
            Ok(())
        }
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(<T as Config>::WeightInfo::register_application())]
        pub fn register_application(
            origin: OriginFor<T>,
            application_id: ApplicationIdOf<T>,
            control_did: DidOf<T>,
            signer_key_id: KeyIdOf<T>,
            signature: SignatureOf<T>,
        ) -> DispatchResult {
            let _ = (
                origin,
                application_id,
                control_did,
                signer_key_id,
                signature,
            );
            Err(Error::<T>::ProofRequired.into())
        }

        #[pallet::call_index(1)]
        #[pallet::weight(<T as Config>::WeightInfo::update_application())]
        pub fn update_application(
            origin: OriginFor<T>,
            application_id: ApplicationIdOf<T>,
            new_control_did: DidOf<T>,
            signer_key_id: KeyIdOf<T>,
            signature: SignatureOf<T>,
        ) -> DispatchResult {
            let _ = (
                origin,
                application_id,
                new_control_did,
                signer_key_id,
                signature,
            );
            Err(Error::<T>::ProofRequired.into())
        }

        #[pallet::call_index(2)]
        #[pallet::weight(<T as Config>::WeightInfo::set_application_status())]
        pub fn set_application_status(
            origin: OriginFor<T>,
            application_id: ApplicationIdOf<T>,
            status: ApplicationStatus,
            signer_key_id: KeyIdOf<T>,
            signature: SignatureOf<T>,
        ) -> DispatchResult {
            let _ = (origin, application_id, status, signer_key_id, signature);
            Err(Error::<T>::ProofRequired.into())
        }

        #[pallet::call_index(3)]
        #[pallet::weight(<T as Config>::WeightInfo::force_set_application_status())]
        pub fn force_set_application_status(
            origin: OriginFor<T>,
            application_id: ApplicationIdOf<T>,
            status: ApplicationStatus,
        ) -> DispatchResult {
            T::GovernanceOrigin::ensure_origin(origin)?;
            let current =
                Applications::<T>::get(&application_id).ok_or(Error::<T>::ApplicationNotFound)?;
            Self::ensure_status_transition(current.status, status)?;
            Self::write_status(application_id, current, status)
        }

        #[pallet::call_index(4)]
        #[pallet::weight(<T as Config>::WeightInfo::set_application_policy())]
        pub fn set_application_policy(
            origin: OriginFor<T>,
            application_id: ApplicationIdOf<T>,
            policy_ttl_seconds: u32,
            document: PolicyDocumentOf<T>,
            signer_key_id: KeyIdOf<T>,
            signature: SignatureOf<T>,
        ) -> DispatchResult {
            let _ = (
                origin,
                application_id,
                policy_ttl_seconds,
                document,
                signer_key_id,
                signature,
            );
            Err(Error::<T>::LegacyPolicyDeprecated.into())
        }

        #[pallet::call_index(5)]
        #[pallet::weight(<T as Config>::WeightInfo::clear_application_policy())]
        pub fn clear_application_policy(
            origin: OriginFor<T>,
            application_id: ApplicationIdOf<T>,
            signer_key_id: KeyIdOf<T>,
            signature: SignatureOf<T>,
        ) -> DispatchResult {
            let _ = (origin, application_id, signer_key_id, signature);
            Err(Error::<T>::LegacyPolicyDeprecated.into())
        }

        /// Bind or clear an optional DNS namespace. The control DID signs the
        /// exact domain and current authorization nonce, so a submitter cannot
        /// substitute another name. DNS authority is checked again on use.
        #[pallet::call_index(6)]
        #[pallet::weight(<T as Config>::WeightInfo::set_application_domain())]
        pub fn set_application_domain(
            origin: OriginFor<T>,
            application_id: ApplicationIdOf<T>,
            domain: Option<DomainOf<T>>,
            signer_key_id: KeyIdOf<T>,
            signature: SignatureOf<T>,
        ) -> DispatchResult {
            let _ = (origin, application_id, domain, signer_key_id, signature);
            Err(Error::<T>::ProofRequired.into())
        }

        #[pallet::call_index(7)]
        #[pallet::weight(<T as Config>::WeightInfo::set_application_linked_did())]
        #[allow(clippy::too_many_arguments)]
        pub fn set_application_linked_did(
            origin: OriginFor<T>,
            application_id: ApplicationIdOf<T>,
            linked_did: DidOf<T>,
            enabled: bool,
            control_signer_key_id: KeyIdOf<T>,
            control_signature: SignatureOf<T>,
            linked_signer_key_id: KeyIdOf<T>,
            linked_signature: SignatureOf<T>,
        ) -> DispatchResult {
            let _ = (
                origin,
                application_id,
                linked_did,
                enabled,
                control_signer_key_id,
                control_signature,
                linked_signer_key_id,
                linked_signature,
            );
            Err(Error::<T>::ProofRequired.into())
        }

        /// Owner-authorized operations use AuthorizeCall without a funded account.
        #[pallet::call_index(8)]
        #[pallet::weight(<T as Config>::WeightInfo::apply_application_with_proof())]
        #[pallet::authorize(|_source, signed_payload, signature, linked_signature| {
            Self::authorize_application(signed_payload, signature, linked_signature)
        })]
        #[pallet::weight_of_authorize(<T as Config>::WeightInfo::authorize_application())]
        #[frame_support::transactional]
        pub fn apply_application_with_proof(
            origin: OriginFor<T>,
            signed_payload: Vec<u8>,
            signature: SignatureOf<T>,
            linked_signature: SignatureOf<T>,
        ) -> DispatchResult {
            match origin.into() {
                Ok(frame_system::RawOrigin::None | frame_system::RawOrigin::Authorized) => {}
                _ => return Err(sp_runtime::DispatchError::BadOrigin),
            }
            let proof =
                Self::validate_application_proof(&signed_payload, &signature, &linked_signature)?;
            Self::apply_application_operation(&proof)?;
            Self::increment_nonce(&proof.operator_did, proof.nonce)
        }
    }

    impl<T: Config> Pallet<T> {
        pub fn proof_payload(proof: &ApplicationAuthorizationPayload<T>) -> Vec<u8> {
            let mut bytes = PROOF_DOMAIN.to_vec().encode();
            bytes.extend(proof.encode());
            bytes
        }

        pub(crate) fn authorize_application(
            signed_payload: &[u8],
            signature: &SignatureOf<T>,
            linked_signature: &SignatureOf<T>,
        ) -> TransactionValidityWithRefund {
            let proof =
                Self::validate_application_proof(signed_payload, signature, linked_signature)
                    .map_err(|_| InvalidTransaction::BadProof)?;
            let validity = ValidTransaction::with_tag_prefix("OpenPayloadApplicationV2")
                .priority(950)
                .and_provides((proof.operator_did, proof.nonce))
                .longevity(1)
                .propagate(true)
                .build()?;
            Ok((validity, Weight::zero()))
        }

        fn validate_application_proof(
            signed_payload: &[u8],
            signature: &SignatureOf<T>,
            linked_signature: &SignatureOf<T>,
        ) -> Result<ApplicationAuthorizationPayload<T>, sp_runtime::DispatchError> {
            ensure!(
                signed_payload.len() <= MAX_PROOF_BYTES,
                Error::<T>::InvalidProofPayload
            );
            let mut input = signed_payload;
            let domain = BoundedVec::<u8, ConstU32<64>>::decode(&mut input)
                .map_err(|_| Error::<T>::InvalidProofPayload)?;
            let proof = ApplicationAuthorizationPayload::<T>::decode(&mut input)
                .map_err(|_| Error::<T>::InvalidProofPayload)?;
            ensure!(
                input.is_empty()
                    && domain.as_slice() == PROOF_DOMAIN
                    && Self::proof_payload(&proof) == signed_payload,
                Error::<T>::InvalidProofPayload
            );
            ensure!(
                proof.genesis_hash
                    == frame_system::Pallet::<T>::block_hash(BlockNumberFor::<T>::zero()),
                Error::<T>::WrongChain
            );
            let now = pallet_timestamp::Pallet::<T>::get().saturated_into::<u64>();
            ensure!(
                proof.valid_until > now
                    && proof.valid_until <= now.saturating_add(MAX_PROOF_LIFETIME_MILLIS),
                Error::<T>::AuthorizationExpired
            );
            ensure!(
                proof.nonce == AuthorizationNonces::<T>::get(&proof.operator_did),
                Error::<T>::InvalidAuthorizationNonce
            );
            ensure!(
                proof.nonce < u64::MAX,
                Error::<T>::AuthorizationNonceOverflow
            );
            ensure!(
                T::DidProvider::did_exists(proof.operator_did.as_slice()),
                Error::<T>::ControlDidNotFound
            );
            Self::validate_operation(&proof)?;
            Self::ensure_authorized(
                &proof.operator_did,
                &proof.signer_key_id,
                signed_payload,
                signature,
            )?;
            match (&proof.operation, &proof.linked_signer_key_id) {
                (ApplicationOperation::SetLinkedDid { linked_did, .. }, Some(key)) => {
                    Self::ensure_authorized(linked_did, key, signed_payload, linked_signature)?;
                }
                (ApplicationOperation::SetLinkedDid { .. }, None) => {
                    return Err(Error::<T>::InvalidAuthorization.into())
                }
                (_, None) if linked_signature.is_empty() => {}
                _ => return Err(Error::<T>::InvalidAuthorization.into()),
            }
            Ok(proof)
        }

        fn validate_operation(proof: &ApplicationAuthorizationPayload<T>) -> DispatchResult {
            use ApplicationOperation::*;
            let application_id = match &proof.operation {
                Register { application_id }
                | Update { application_id, .. }
                | SetStatus { application_id, .. }
                | SetDomain { application_id, .. }
                | SetLinkedDid { application_id, .. } => application_id,
            };
            Self::ensure_valid_application_id(application_id)?;
            if matches!(proof.operation, Register { .. }) {
                ensure!(
                    !Applications::<T>::contains_key(application_id),
                    Error::<T>::ApplicationAlreadyExists
                );
                ensure!(
                    (ApplicationsByControlDid::<T>::get(&proof.operator_did).len() as u32)
                        < T::MaxApplicationsPerControlDid::get(),
                    Error::<T>::TooManyApplicationsForControlDid
                );
                return Ok(());
            }
            let current =
                Applications::<T>::get(application_id).ok_or(Error::<T>::ApplicationNotFound)?;
            ensure!(
                current.control_did == proof.operator_did,
                Error::<T>::InvalidAuthorization
            );
            ensure!(
                current.status != ApplicationStatus::Tombstoned,
                Error::<T>::ApplicationTombstoned
            );
            ensure!(current.revision < u64::MAX, Error::<T>::RevisionOverflow);
            match &proof.operation {
                Update {
                    new_control_did, ..
                } => {
                    ensure!(
                        T::DidProvider::did_exists(new_control_did.as_slice()),
                        Error::<T>::ControlDidNotFound
                    );
                    if new_control_did != &current.control_did {
                        ensure!(
                            (ApplicationsByControlDid::<T>::get(new_control_did).len() as u32)
                                < T::MaxApplicationsPerControlDid::get(),
                            Error::<T>::TooManyApplicationsForControlDid
                        );
                    }
                }
                SetStatus { status, .. } => {
                    Self::ensure_status_transition(current.status, *status)?
                }
                SetDomain {
                    domain: Some(domain),
                    ..
                } => {
                    Self::ensure_valid_domain(domain)?;
                    ensure!(
                        T::DomainProvider::controlled_domain(
                            domain.as_slice(),
                            proof.operator_did.as_slice()
                        ),
                        Error::<T>::DomainNotControlled
                    );
                }
                SetLinkedDid {
                    linked_did,
                    enabled,
                    ..
                } => {
                    ensure!(
                        T::DidProvider::did_exists(linked_did.as_slice()),
                        Error::<T>::LinkedDidNotFound
                    );
                    let ids = ApplicationLinkedDids::<T>::get(application_id);
                    ensure!(
                        !enabled
                            || ids.contains(linked_did)
                            || (ids.len() as u32) < T::MaxLinkedDids::get(),
                        Error::<T>::TooManyLinkedDids
                    );
                }
                _ => {}
            }
            Ok(())
        }

        fn apply_application_operation(
            proof: &ApplicationAuthorizationPayload<T>,
        ) -> DispatchResult {
            use ApplicationOperation::*;
            let now = frame_system::Pallet::<T>::block_number();
            if let Register { application_id } = &proof.operation {
                ApplicationsByControlDid::<T>::try_mutate(&proof.operator_did, |ids| {
                    ids.try_push(application_id.clone())
                        .map_err(|_| Error::<T>::TooManyApplicationsForControlDid)
                })?;
                Applications::<T>::insert(
                    application_id,
                    ApplicationRecord::<T> {
                        control_did: proof.operator_did.clone(),
                        status: ApplicationStatus::Active,
                        revision: 1,
                        registered_at: now,
                        updated_at: now,
                    },
                );
                Self::deposit_event(Event::ApplicationRegistered {
                    application_id: application_id.clone(),
                    control_did: proof.operator_did.clone(),
                });
                return Ok(());
            }
            let application_id = match &proof.operation {
                Update { application_id, .. }
                | SetStatus { application_id, .. }
                | SetDomain { application_id, .. }
                | SetLinkedDid { application_id, .. } => application_id,
                Register { .. } => unreachable!(),
            };
            let mut record =
                Applications::<T>::get(application_id).ok_or(Error::<T>::ApplicationNotFound)?;
            if let SetStatus { status, .. } = &proof.operation {
                return Self::write_status(application_id.clone(), record, *status);
            }
            record.revision = record
                .revision
                .checked_add(1)
                .ok_or(Error::<T>::RevisionOverflow)?;
            record.updated_at = now;
            let revision = record.revision;
            match &proof.operation {
                Update {
                    new_control_did, ..
                } => {
                    if new_control_did != &record.control_did {
                        ApplicationsByControlDid::<T>::try_mutate(new_control_did, |ids| {
                            ids.try_push(application_id.clone())
                                .map_err(|_| Error::<T>::TooManyApplicationsForControlDid)
                        })?;
                        ApplicationsByControlDid::<T>::mutate(&record.control_did, |ids| {
                            ids.retain(|id| id != application_id)
                        });
                        ApplicationPolicies::<T>::remove(application_id);
                        ApplicationDomains::<T>::remove(application_id);
                        ApplicationLinkedDids::<T>::remove(application_id);
                        T::PolicyCleanup::clear(application_id.as_slice());
                        record.control_did = new_control_did.clone();
                    }
                    Self::deposit_event(Event::ApplicationUpdated {
                        application_id: application_id.clone(),
                        control_did: new_control_did.clone(),
                        revision,
                    });
                }
                SetDomain { domain, .. } => {
                    match domain {
                        Some(name) => ApplicationDomains::<T>::insert(application_id, name),
                        None => ApplicationDomains::<T>::remove(application_id),
                    }
                    Self::deposit_event(Event::ApplicationDomainChanged {
                        application_id: application_id.clone(),
                        domain: domain.clone(),
                        revision,
                    });
                }
                SetLinkedDid {
                    linked_did,
                    enabled,
                    ..
                } => {
                    if *enabled {
                        ApplicationLinkedDids::<T>::try_mutate(application_id, |ids| {
                            if !ids.contains(linked_did) {
                                ids.try_push(linked_did.clone())
                                    .map_err(|_| Error::<T>::TooManyLinkedDids)?;
                            }
                            Ok::<(), Error<T>>(())
                        })?;
                    } else {
                        ApplicationLinkedDids::<T>::mutate(application_id, |ids| {
                            ids.retain(|did| did != linked_did)
                        });
                    }
                    Self::deposit_event(Event::ApplicationLinkedDidChanged {
                        application_id: application_id.clone(),
                        linked_did: linked_did.clone(),
                        enabled: *enabled,
                        revision,
                    });
                }
                _ => unreachable!(),
            }
            Applications::<T>::insert(application_id, record);
            Ok(())
        }

        pub fn authorization_payload(
            action: &[u8],
            application_id: &ApplicationIdOf<T>,
            control_did: &DidOf<T>,
            status: ApplicationStatus,
            nonce: u64,
        ) -> Vec<u8> {
            (
                AUTHORIZATION_DOMAIN,
                action,
                application_id,
                control_did,
                status,
                nonce,
            )
                .encode()
        }

        fn ensure_valid_application_id(application_id: &ApplicationIdOf<T>) -> DispatchResult {
            let valid = !application_id.is_empty()
                && application_id.iter().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(*byte, b'.' | b'_' | b'-')
                });
            ensure!(valid, Error::<T>::InvalidApplicationId);
            Ok(())
        }

        fn ensure_valid_domain(domain: &DomainOf<T>) -> DispatchResult {
            let bytes = domain.as_slice();
            ensure!(
                !bytes.is_empty() && bytes.len() <= 253,
                Error::<T>::InvalidDomain
            );
            let mut labels = 0u8;
            for label in bytes.split(|byte| *byte == b'.') {
                ensure!(
                    !label.is_empty()
                        && label.len() <= 63
                        && label[0] != b'-'
                        && label[label.len() - 1] != b'-'
                        && label.iter().all(|byte| byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || *byte == b'-'),
                    Error::<T>::InvalidDomain
                );
                labels = labels.saturating_add(1);
            }
            ensure!(labels >= 2, Error::<T>::InvalidDomain);
            let last = bytes
                .rsplit(|byte| *byte == b'.')
                .next()
                .ok_or(Error::<T>::InvalidDomain)?;
            ensure!(
                last.iter().any(u8::is_ascii_lowercase),
                Error::<T>::InvalidDomain
            );
            Ok(())
        }

        fn ensure_authorized(
            did: &DidOf<T>,
            signer_key_id: &KeyIdOf<T>,
            payload: &[u8],
            signature: &SignatureOf<T>,
        ) -> DispatchResult {
            ensure!(
                T::DidProvider::verify_did_signature(
                    did.as_slice(),
                    signer_key_id.as_slice(),
                    payload,
                    signature.as_slice(),
                ),
                Error::<T>::InvalidAuthorization
            );
            Ok(())
        }

        fn increment_nonce(did: &DidOf<T>, nonce: u64) -> DispatchResult {
            let next = nonce
                .checked_add(1)
                .ok_or(Error::<T>::AuthorizationNonceOverflow)?;
            AuthorizationNonces::<T>::insert(did, next);
            Ok(())
        }

        fn ensure_status_transition(
            current: ApplicationStatus,
            next: ApplicationStatus,
        ) -> DispatchResult {
            ensure!(
                current != ApplicationStatus::Tombstoned,
                Error::<T>::ApplicationTombstoned
            );
            ensure!(current != next, Error::<T>::InvalidStatusTransition);
            Ok(())
        }

        fn write_status(
            application_id: ApplicationIdOf<T>,
            mut current: ApplicationRecord<T>,
            status: ApplicationStatus,
        ) -> DispatchResult {
            current.revision = current
                .revision
                .checked_add(1)
                .ok_or(Error::<T>::RevisionOverflow)?;
            current.status = status;
            current.updated_at = frame_system::Pallet::<T>::block_number();
            let revision = current.revision;
            if status == ApplicationStatus::Tombstoned {
                ApplicationPolicies::<T>::remove(&application_id);
                ApplicationDomains::<T>::remove(&application_id);
                ApplicationLinkedDids::<T>::remove(&application_id);
                T::PolicyCleanup::clear(application_id.as_slice());
                ApplicationsByControlDid::<T>::mutate(&current.control_did, |ids| {
                    ids.retain(|id| id != &application_id)
                });
            }
            Applications::<T>::insert(&application_id, current);
            Self::deposit_event(Event::ApplicationStatusChanged {
                application_id,
                status,
                revision,
            });
            Ok(())
        }
    }
}
