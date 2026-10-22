//! Stable policy storage/authorization envelope. Document bytes are never parsed here.
use super::*;
use sp_runtime::traits::Zero;

pub const POLICY_DOCUMENT_PROOF_DOMAIN: &[u8] = b"openpayload:policy-document:v1";
pub const MAX_POLICY_DOCUMENT_PROOF_BYTES: usize = 66_560;
pub type PolicyDocumentOf<T> = BoundedVec<u8, <T as Config>::MaxPolicyDocumentBytes>;
pub type PolicyDocumentSigner = BoundedVec<u8, ConstU32<64>>;

#[derive(
    Encode,
    Decode,
    DecodeWithMemTracking,
    CloneNoBound,
    PartialEqNoBound,
    EqNoBound,
    DebugNoBound,
    TypeInfo,
    MaxEncodedLen,
)]
#[scale_info(skip_type_params(T))]
#[codec(mel_bound())]
#[codec(decode_bound())]
#[codec(decode_with_mem_tracking_bound())]
pub struct PolicyDocumentRecord<T: Config> {
    pub revision: u64,
    pub operator_did: DidOf<T>,
    pub content_hash: [u8; 32],
    /// Empty only for an explicit retained clear tombstone.
    pub document: PolicyDocumentOf<T>,
}

#[derive(
    Encode,
    Decode,
    DecodeWithMemTracking,
    CloneNoBound,
    PartialEqNoBound,
    EqNoBound,
    DebugNoBound,
    TypeInfo,
    MaxEncodedLen,
)]
#[scale_info(skip_type_params(T))]
#[codec(mel_bound())]
#[codec(decode_bound())]
#[codec(decode_with_mem_tracking_bound())]
pub enum PolicyDocumentOperation<T: Config> {
    Set {
        scope: PolicyScopeV3<T>,
        revision: u64,
        document: PolicyDocumentOf<T>,
    },
    Clear {
        scope: PolicyScopeV3<T>,
        revision: u64,
    },
}

impl<T: Config> PolicyDocumentOperation<T> {
    pub fn scope(&self) -> &PolicyScopeV3<T> {
        match self {
            Self::Set { scope, .. } | Self::Clear { scope, .. } => scope,
        }
    }
    pub fn revision(&self) -> u64 {
        match self {
            Self::Set { revision, .. } | Self::Clear { revision, .. } => *revision,
        }
    }
}

#[derive(
    Encode,
    Decode,
    DecodeWithMemTracking,
    CloneNoBound,
    PartialEqNoBound,
    EqNoBound,
    DebugNoBound,
    TypeInfo,
    MaxEncodedLen,
)]
#[scale_info(skip_type_params(T))]
#[codec(mel_bound())]
#[codec(decode_bound())]
#[codec(decode_with_mem_tracking_bound())]
pub struct PolicyDocumentAuthorizationPayload<T: Config> {
    pub domain: BoundedVec<u8, ConstU32<64>>,
    pub genesis_hash: T::Hash,
    pub operator_did: DidOf<T>,
    pub signer_key_id: PolicyDocumentSigner,
    pub operation: PolicyDocumentOperation<T>,
    pub nonce: u64,
    pub valid_until: u64,
}

impl<T: Config> Pallet<T> {
    pub(crate) fn validate_policy_document_authorization(
        signed_payload: &[u8],
        signature: &[u8],
        signer_key_id: &[u8],
    ) -> Result<PolicyDocumentAuthorizationPayload<T>, DispatchError> {
        ensure!(
            signed_payload.len() <= MAX_POLICY_DOCUMENT_PROOF_BYTES
                && signature.len() == 64
                && !signer_key_id.is_empty()
                && signer_key_id.len() <= 64,
            Error::<T>::InvalidPolicyDocumentProof
        );
        let mut input = signed_payload;
        let proof = PolicyDocumentAuthorizationPayload::<T>::decode(&mut input)
            .map_err(|_| Error::<T>::InvalidPolicyDocumentProof)?;
        ensure!(
            input.is_empty()
                && proof.encode() == signed_payload
                && proof.domain.as_slice() == POLICY_DOCUMENT_PROOF_DOMAIN
                && proof.signer_key_id.as_slice() == signer_key_id,
            Error::<T>::InvalidPolicyDocumentProof
        );
        ensure!(
            proof.genesis_hash
                == frame_system::Pallet::<T>::block_hash(BlockNumberFor::<T>::zero()),
            Error::<T>::PolicyDocumentWrongChain
        );
        let now = pallet_timestamp::Pallet::<T>::get().saturated_into::<u64>();
        ensure!(
            proof.valid_until > now && proof.valid_until <= now.saturating_add(600_000),
            Error::<T>::PolicyDocumentAuthorizationExpired
        );
        ensure!(
            proof.nonce == PolicyV4Nonces::<T>::get(&proof.operator_did),
            Error::<T>::InvalidPolicyDocumentNonce
        );
        ensure!(
            proof.nonce < u64::MAX,
            Error::<T>::PolicyDocumentNonceOverflow
        );
        let scope = proof.operation.scope();
        let current = PoliciesV4::<T>::get(scope).map(|p| p.revision).unwrap_or(0);
        let next = current
            .checked_add(1)
            .ok_or(Error::<T>::PolicyDocumentRevisionOverflow)?;
        ensure!(
            proof.operation.revision() == next,
            Error::<T>::InvalidPolicyDocumentRevision
        );
        if let PolicyDocumentOperation::Set { document, .. } = &proof.operation {
            ensure!(!document.is_empty(), Error::<T>::EmptyPolicyDocument);
        }
        let owner = Self::policy_v3_owner(scope)?;
        ensure!(proof.operator_did == owner, Error::<T>::NotPolicyController);
        ensure!(
            T::DidProvider::did_exists(owner.as_slice()),
            Error::<T>::DidNotFound
        );
        if let PolicyScopeV3::Persona(persona) = scope {
            let record = Self::active_persona(persona)?;
            ensure!(
                record
                    .controller_key_ids
                    .iter()
                    .any(|id| id.as_slice() == signer_key_id),
                Error::<T>::InvalidPersonaController
            );
        }
        ensure!(
            T::DidProvider::verify_did_signature(
                owner.as_slice(),
                signer_key_id,
                signed_payload,
                signature
            ),
            Error::<T>::InvalidSignature
        );
        Ok(proof)
    }

    pub(crate) fn authorize_policy_document(
        signed_payload: &[u8],
        signature: &[u8],
        signer_key_id: &[u8],
    ) -> TransactionValidityWithRefund {
        let proof =
            Self::validate_policy_document_authorization(signed_payload, signature, signer_key_id)
                .map_err(|_| InvalidTransaction::BadProof)?;
        let validity = ValidTransaction::with_tag_prefix("OpenPayloadPolicyDocumentV1")
            .priority(950)
            .and_provides((proof.operator_did, proof.nonce))
            .longevity(1)
            .propagate(true)
            .build()?;
        Ok((validity, Weight::zero()))
    }

    pub(crate) fn store_policy_document(
        proof: PolicyDocumentAuthorizationPayload<T>,
    ) -> DispatchResult {
        let scope = proof.operation.scope().clone();
        let revision = proof.operation.revision();
        let document = match proof.operation {
            PolicyDocumentOperation::Set { document, .. } => document,
            PolicyDocumentOperation::Clear { .. } => PolicyDocumentOf::<T>::default(),
        };
        let content_hash = sp_io::hashing::blake2_256(&document);
        let cleared = document.is_empty();
        PoliciesV4::<T>::insert(
            &scope,
            PolicyDocumentRecord::<T> {
                revision,
                operator_did: proof.operator_did.clone(),
                content_hash,
                document,
            },
        );
        PolicyV4Nonces::<T>::insert(&proof.operator_did, proof.nonce + 1);
        Self::deposit_event(Event::PolicyDocumentChanged {
            scope,
            revision,
            content_hash,
            cleared,
        });
        Ok(())
    }

    /// A lifecycle invalidation cannot expose frozen typed records underneath.
    /// A revision at its maximum remains permanently unwritable after clearing.
    pub fn invalidate_policy_document(scope: &PolicyScopeV3<T>) {
        PoliciesV4::<T>::mutate(scope, |record| {
            if let Some(record) = record {
                record.revision = record.revision.saturating_add(1);
                record.document = Default::default();
                record.content_hash = sp_io::hashing::blake2_256(&[]);
            }
        });
    }

    pub fn has_policy_document_override(recipient: &[u8], persona: Option<&[u8]>) -> bool {
        let did = DidOf::<T>::try_from(recipient.to_vec()).ok();
        did.is_some_and(|did| PoliciesV4::<T>::contains_key(PolicyScopeV3::Did(did)))
            || persona
                .and_then(|name| Self::canonical_persona(name).ok())
                .is_some_and(|name| PoliciesV4::<T>::contains_key(PolicyScopeV3::Persona(name)))
    }
}

#[cfg(feature = "runtime-benchmarks")]
pub trait BenchmarkHelper {
    fn install(did: &[u8], application: &[u8]);
    fn sign(payload: &[u8]) -> Vec<u8>;
    fn signer() -> Vec<u8>;
}

#[cfg(feature = "runtime-benchmarks")]
impl BenchmarkHelper for () {
    fn install(_did: &[u8], _application: &[u8]) {
        panic!("policy benchmark helper is not installed")
    }
    fn sign(_payload: &[u8]) -> Vec<u8> {
        panic!("policy benchmark signer is not installed")
    }
    fn signer() -> Vec<u8> {
        panic!("policy benchmark signer is not installed")
    }
}
