#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::type_complexity)]

extern crate alloc;
use alloc::vec::Vec;
pub use pallet::*;

use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use frame_support::sp_runtime::SaturatedConversion;
use frame_support::{pallet_prelude::*, BoundedVec, DebugNoBound};
use frame_system::pallet_prelude::*;
use scale_info::TypeInfo;
use sp_core::{ed25519, ByteArray};
use sp_io::crypto::ed25519_verify;
use sp_runtime::transaction_validity::{
    InvalidTransaction, TransactionValidity, TransactionValidityWithRefund, ValidTransaction,
};

// Canonical OpenPayload DID grammar:
// `did:<platform>:<base58-address>`.
//
// The platform is intentionally not fixed to `openpayload`; independent networks may
// choose their own lowercase name. Component limits provide deterministic bounds
// below the runtime's overall MaxDidLen limit.
const DID_PREFIX: &[u8] = b"did:";
const MIN_DID_PLATFORM_LEN: usize = 1;
const MAX_DID_PLATFORM_LEN: usize = 32;
const MIN_DID_ADDRESS_LEN: usize = 16;
const MAX_DID_ADDRESS_LEN: usize = 96;

/// Removes policy-pallet state when a DID is permanently deleted.
pub trait DidPolicyCleanup {
    fn remove_for_did(did: &[u8]);
}

/// Refuses retirement while another pallet still needs this DID as a controller.
pub trait DidRetirementGuard {
    fn can_retire(did: &[u8]) -> bool;
}

impl DidRetirementGuard for () {
    fn can_retire(_did: &[u8]) -> bool {
        true
    }
}

impl DidPolicyCleanup for () {
    fn remove_for_did(_did: &[u8]) {}
}

impl<T> DidPolicyCleanup for pallet_delivery_policy::Pallet<T>
where
    T: pallet_delivery_policy::Config,
{
    fn remove_for_did(did: &[u8]) {
        pallet_delivery_policy::Pallet::<T>::remove_did_state(did);
    }
}

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

#[frame_support::pallet]
pub mod pallet {
    use super::*;

    #[pallet::config]
    pub trait Config:
        frame_system::Config<RuntimeEvent: From<Event<Self>>> + pallet_timestamp::Config
    {
        // Length/size limits
        #[pallet::constant]
        type MaxDidLen: Get<u32>;
        #[pallet::constant]
        type MaxDevices: Get<u32>;
        #[pallet::constant]
        type MaxAliasLen: Get<u32>;
        #[pallet::constant]
        type MaxAliases: Get<u32>;
        #[pallet::constant]
        type MaxContexts: Get<u32>;
        #[pallet::constant]
        type MaxContextLen: Get<u32>;
        #[pallet::constant]
        type MaxIdLen: Get<u32>;
        #[pallet::constant]
        type MaxControllerRefs: Get<u32>;
        #[pallet::constant]
        type MaxDocLen: Get<u32>;
        #[pallet::constant]
        type MaxControllerLen: Get<u32>;
        #[pallet::constant]
        type MaxVMs: Get<u32>;
        #[pallet::constant]
        type MaxKAs: Get<u32>;
        #[pallet::constant]
        type MaxVMTypeLen: Get<u32>;
        #[pallet::constant]
        type MaxKaTypeLen: Get<u32>;
        #[pallet::constant]
        type MaxKeyMultibaseLen: Get<u32>;
        #[pallet::constant]
        type MaxRefsPerRel: Get<u32>;
        #[pallet::constant]
        type MaxServices: Get<u32>;
        #[pallet::constant]
        type MaxServiceEndpoints: Get<u32>;
        #[pallet::constant]
        type MaxServiceAuthorizationKeys: Get<u32>;
        #[pallet::constant]
        type MaxServiceTypeLen: Get<u32>;
        #[pallet::constant]
        type MaxServiceEndpointLen: Get<u32>;
        #[pallet::constant]
        type MaxServiceEndpointUrlLen: Get<u32>;
        #[pallet::constant]
        type MaxPolicyRefs: Get<u32>;
        #[pallet::constant]
        type MaxPolicyRefLen: Get<u32>;
        type PolicyCleanup: DidPolicyCleanup;
        type RetirementGuard: DidRetirementGuard;
    }

    pub type DidOf<T> = BoundedVec<u8, <T as Config>::MaxDidLen>;
    pub type AliasOf<T> = BoundedVec<u8, <T as Config>::MaxAliasLen>;
    pub type AliasListOf<T> = BoundedVec<AliasOf<T>, <T as Config>::MaxAliases>;
    pub type IdStrOf<T> = BoundedVec<u8, <T as Config>::MaxIdLen>;
    pub type CtxStrOf<T> = BoundedVec<u8, <T as Config>::MaxContextLen>;
    pub type CtxListOf<T> = BoundedVec<CtxStrOf<T>, <T as Config>::MaxContexts>;
    pub type CtrlStrOf<T> = BoundedVec<u8, <T as Config>::MaxControllerLen>;
    pub type CtrlListOf<T> = BoundedVec<CtrlStrOf<T>, <T as Config>::MaxControllerRefs>;
    pub type VmTypeStrOf<T> = BoundedVec<u8, <T as Config>::MaxVMTypeLen>;
    pub type KaTypeStrOf<T> = BoundedVec<u8, <T as Config>::MaxKaTypeLen>;
    pub type KeyMbStrOf<T> = BoundedVec<u8, <T as Config>::MaxKeyMultibaseLen>;
    pub type RefListOf<T> = BoundedVec<IdStrOf<T>, <T as Config>::MaxRefsPerRel>;
    pub type SvcTypeStrOf<T> = BoundedVec<u8, <T as Config>::MaxServiceTypeLen>;
    pub type SvcEndpointUrlStrOf<T> = BoundedVec<u8, <T as Config>::MaxServiceEndpointUrlLen>;
    pub type SvcEndpointUrlOf<T> =
        BoundedVec<SvcEndpointUrlStrOf<T>, <T as Config>::MaxServiceEndpoints>;
    pub type SvcAuthorizationOf<T> =
        BoundedVec<IdStrOf<T>, <T as Config>::MaxServiceAuthorizationKeys>;
    pub type DocBlobOf<T> = BoundedVec<u8, <T as Config>::MaxDocLen>;
    pub type PolicyRefOf<T> = BoundedVec<u8, <T as Config>::MaxPolicyRefLen>;
    pub type PolicyRefListOf<T> = BoundedVec<PolicyRefOf<T>, <T as Config>::MaxPolicyRefs>;
    pub type RootPubkeyOf = BoundedVec<u8, ConstU32<32>>;
    pub type DeviceIdOf = BoundedVec<u8, ConstU32<64>>;

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
    pub struct VerificationMethod<T: Config> {
        pub id: IdStrOf<T>,
        pub type_: VmTypeStrOf<T>,
        pub controller: IdStrOf<T>,
        pub public_key_multibase: KeyMbStrOf<T>,
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
    pub struct KeyAgreement<T: Config> {
        pub id: IdStrOf<T>,
        pub type_: KaTypeStrOf<T>,
        pub controller: IdStrOf<T>,
        pub public_key_multibase: KeyMbStrOf<T>,
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
    pub struct Service<T: Config> {
        pub id: IdStrOf<T>,
        pub type_: SvcTypeStrOf<T>,
        pub service_endpoint: SvcEndpointUrlOf<T>,
        pub authorization: Option<SvcAuthorizationOf<T>>,
        pub priority: Option<u32>,
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
    pub struct DidDocument<T: Config> {
        pub id: DidOf<T>,
        pub verification_method: BoundedVec<VerificationMethod<T>, <T as Config>::MaxVMs>,
        pub authentication: Option<RefListOf<T>>,
        pub key_agreement: BoundedVec<KeyAgreement<T>, <T as Config>::MaxKAs>,
        pub service: Option<BoundedVec<Service<T>, <T as Config>::MaxServices>>,
    }

    #[derive(
        Clone, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo, Debug, PartialEq, Eq,
    )]
    pub struct DeviceInfo {
        pub device_id: BoundedVec<u8, ConstU32<64>>,
        pub added_at: u64,
        pub tombstoned: bool,
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
    pub struct DeliveryPolicyLinks<T: Config> {
        pub recipient_policy: Option<PolicyRefOf<T>>,
        pub tag_policies: PolicyRefListOf<T>,
        pub persona_policies: PolicyRefListOf<T>,
    }

    #[derive(
        Encode, Decode, DecodeWithMemTracking, Clone, Copy, PartialEq, Eq, Debug, TypeInfo,
    )]
    pub enum AliasAction {
        Add,
        Update,
        Remove,
    }

    #[derive(
        Encode, Decode, DecodeWithMemTracking, Clone, Copy, PartialEq, Eq, Debug, TypeInfo,
    )]
    pub enum DocumentAction {
        AddVerificationMethod,
        UpdateVerificationMethod,
        RemoveVerificationMethod,
        AddAuthentication,
        RemoveAuthentication,
        AddKeyAgreement,
        UpdateKeyAgreement,
        RemoveKeyAgreement,
        AddService,
        UpdateService,
        RemoveService,
    }

    #[derive(
        Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, DebugNoBound, TypeInfo,
    )]
    #[scale_info(skip_type_params(T))]
    #[codec(mel_bound())]
    #[codec(decode_bound())]
    #[codec(decode_with_mem_tracking_bound())]
    pub enum ControlAction<T: Config> {
        AddDevice {
            device_id: DeviceIdOf,
        },
        TombstoneDevice {
            device_id: DeviceIdOf,
        },
        UpdateDevice {
            old_device_id: DeviceIdOf,
            new_device_id: DeviceIdOf,
        },
        RemoveDevice {
            device_id: DeviceIdOf,
        },
        DeactivateDid,
        SetDeliveryPolicyLinks {
            links: DeliveryPolicyLinks<T>,
        },
        ClearDeliveryPolicyLinks,
        DeleteDid,
    }

    #[derive(
        Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, DebugNoBound, TypeInfo,
    )]
    #[scale_info(skip_type_params(T))]
    #[codec(mel_bound())]
    #[codec(decode_bound())]
    #[codec(decode_with_mem_tracking_bound())]
    pub struct AliasAuthorizationPayload<T: Config> {
        pub did: DidOf<T>,
        pub action: AliasAction,
        pub alias: Option<AliasOf<T>>,
        pub old_alias: Option<AliasOf<T>>,
        pub new_alias: Option<AliasOf<T>>,
        pub nonce: u64,
        pub valid_until: u64,
        pub signer_key_id: IdStrOf<T>,
    }

    #[derive(
        Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, DebugNoBound, TypeInfo,
    )]
    #[scale_info(skip_type_params(T))]
    #[codec(mel_bound())]
    #[codec(decode_bound())]
    #[codec(decode_with_mem_tracking_bound())]
    pub struct DocumentAuthorizationPayload<T: Config> {
        pub did: DidOf<T>,
        pub action: DocumentAction,
        pub verification_method: Option<VerificationMethod<T>>,
        pub key_agreement: Option<KeyAgreement<T>>,
        pub service: Option<Service<T>>,
        pub id: Option<IdStrOf<T>>,
        pub nonce: u64,
        pub valid_until: u64,
        pub signer_key_id: IdStrOf<T>,
    }

    #[derive(
        Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, DebugNoBound, TypeInfo,
    )]
    #[scale_info(skip_type_params(T))]
    #[codec(mel_bound())]
    #[codec(decode_bound())]
    #[codec(decode_with_mem_tracking_bound())]
    pub struct RootPubkeyAuthorizationPayload<T: Config> {
        pub did: DidOf<T>,
        pub new_root_pubkey: RootPubkeyOf,
        pub nonce: u64,
        pub valid_until: u64,
        pub signer_key_id: IdStrOf<T>,
    }

    #[derive(
        Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, DebugNoBound, TypeInfo,
    )]
    #[scale_info(skip_type_params(T))]
    #[codec(mel_bound())]
    #[codec(decode_bound())]
    #[codec(decode_with_mem_tracking_bound())]
    pub struct ControlAuthorizationPayload<T: Config> {
        pub did: DidOf<T>,
        pub action: ControlAction<T>,
        pub nonce: u64,
        pub valid_until: u64,
        pub signer_key_id: IdStrOf<T>,
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
    pub struct DidRecord<T: Config> {
        pub owner: Option<T::AccountId>,
        pub aliases: Option<AliasListOf<T>>,
        pub devices: Option<BoundedVec<DeviceInfo, T::MaxDevices>>,
        pub document: Option<DidDocument<T>>,
        pub version: u64,
        pub updated_at: u64,
        pub root_pubkey: Option<RootPubkeyOf>,
        pub delivery_policy_links: Option<DeliveryPolicyLinks<T>>,
        pub deactivated: bool,
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::storage]
    pub type Dids<T: Config> = StorageMap<_, Blake2_128Concat, DidOf<T>, DidRecord<T>, OptionQuery>;

    #[pallet::storage]
    pub type AliasIndex<T: Config> =
        StorageMap<_, Blake2_128Concat, AliasOf<T>, DidOf<T>, OptionQuery>;

    #[pallet::storage]
    pub type AliasNonces<T: Config> = StorageMap<_, Blake2_128Concat, DidOf<T>, u64, ValueQuery>;

    #[pallet::storage]
    pub type DocumentNonces<T: Config> = StorageMap<_, Blake2_128Concat, DidOf<T>, u64, ValueQuery>;

    #[pallet::storage]
    pub type RootPubkeyNonces<T: Config> =
        StorageMap<_, Blake2_128Concat, DidOf<T>, u64, ValueQuery>;

    #[pallet::storage]
    pub type ControlNonces<T: Config> = StorageMap<_, Blake2_128Concat, DidOf<T>, u64, ValueQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        Registered(DidOf<T>, Option<T::AccountId>),
        AliasSet(DidOf<T>, AliasOf<T>),
        AliasAdded(DidOf<T>, AliasOf<T>),
        AliasUpdated(DidOf<T>, AliasOf<T>, AliasOf<T>),
        AliasRemoved(DidOf<T>, AliasOf<T>),
        AliasConflict(DidOf<T>, AliasOf<T>),
        AliasInvalid(DidOf<T>),
        DeviceAdded(DidOf<T>, BoundedVec<u8, ConstU32<64>>),
        DeviceUpdated(
            DidOf<T>,
            BoundedVec<u8, ConstU32<64>>,
            BoundedVec<u8, ConstU32<64>>,
        ),
        DeviceTombstoned(DidOf<T>, BoundedVec<u8, ConstU32<64>>),
        DeviceRemoved(DidOf<T>, BoundedVec<u8, ConstU32<64>>),
        DocumentSet(DidOf<T>),
        VerificationMethodAdded(DidOf<T>, IdStrOf<T>),
        VerificationMethodUpdated(DidOf<T>, IdStrOf<T>),
        VerificationMethodRemoved(DidOf<T>, IdStrOf<T>),
        AuthenticationAdded(DidOf<T>, IdStrOf<T>),
        AuthenticationRemoved(DidOf<T>, IdStrOf<T>),
        KeyAgreementAdded(DidOf<T>, IdStrOf<T>),
        KeyAgreementUpdated(DidOf<T>, IdStrOf<T>),
        KeyAgreementRemoved(DidOf<T>, IdStrOf<T>),
        ServiceAdded(DidOf<T>, IdStrOf<T>),
        ServiceUpdated(DidOf<T>, IdStrOf<T>),
        ServiceRemoved(DidOf<T>, IdStrOf<T>),
        RootPubkeyUpdated(DidOf<T>),
        DeliveryPolicyLinksSet(DidOf<T>),
        DeliveryPolicyLinksCleared(DidOf<T>),
        DidDeactivated(DidOf<T>),
        DidDeleted(DidOf<T>),
    }

    #[pallet::error]
    pub enum Error<T> {
        InvalidSignature,
        InvalidRootPubkey,
        InvalidRootPubkeyPayload,
        InvalidRootPubkeyNonce,
        RootPubkeyAuthorizationExpired,
        InvalidControlPayload,
        InvalidControlNonce,
        ControlAuthorizationExpired,
        SignatureMismatch,
        DidTooLong,
        DidAlreadyExists,
        DidNotFound,
        DidDeactivated,
        DidAlreadyDeactivated,
        TooManyDevices,
        AliasTooLong,
        TooManyAliases,
        InvalidAlias,
        AliasNotFound,
        InvalidAliasPayload,
        InvalidAliasNonce,
        AliasAuthorizationExpired,
        DeviceNotFound,
        DeviceAlreadyExists,
        AliasTaken,
        AliasAlreadyExists,
        InvalidDocument,
        InvalidDocumentPayload,
        InvalidDocumentNonce,
        DocumentAuthorizationExpired,
        VerificationMethodAlreadyExists,
        VerificationMethodNotFound,
        VerificationMethodInUse,
        AuthenticationAlreadyExists,
        AuthenticationNotFound,
        KeyAgreementAlreadyExists,
        KeyAgreementNotFound,
        ServiceAlreadyExists,
        ServiceTooLong,
        ServiceNotFound,
        NotDidOwner,
        PolicyRefTooLong,
        TooManyPolicyRefs,
        InvalidDidFormat,
        DidControlsApplication,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(1)]
        #[pallet::weight(T::DbWeight::get().reads_writes(2,2))]
        pub fn set_alias(origin: OriginFor<T>, did: Vec<u8>, alias: Vec<u8>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let did_b = DidOf::<T>::try_from(did).map_err(|_| Error::<T>::DidTooLong)?;
            let new_alias = Self::normalize_alias(&alias)?;
            ensure!(Dids::<T>::contains_key(&did_b), Error::<T>::DidNotFound);
            Self::ensure_did_owner(&who, &did_b)?;

            if let Some(existing) = AliasIndex::<T>::get(&new_alias) {
                ensure!(existing == did_b, Error::<T>::AliasTaken);
            }

            Dids::<T>::try_mutate(&did_b, |maybe| -> DispatchResult {
                let rec = maybe.as_mut().ok_or(Error::<T>::DidNotFound)?;
                if let Some(old_aliases) = rec.aliases.take() {
                    for old in old_aliases {
                        if old == new_alias {
                            continue;
                        }
                        AliasIndex::<T>::remove(&old);
                    }
                }
                let mut aliases = AliasListOf::<T>::default();
                aliases
                    .try_push(new_alias.clone())
                    .map_err(|_| Error::<T>::TooManyAliases)?;
                rec.aliases = Some(aliases);
                rec.version = rec.version.saturating_add(1);
                rec.updated_at = now_millis::<T>();
                Ok(())
            })?;

            AliasIndex::<T>::insert(&new_alias, did_b.clone());
            Self::deposit_event(Event::AliasSet(did_b, new_alias));
            Ok(())
        }

        #[pallet::call_index(2)]
        #[pallet::weight(T::DbWeight::get().reads_writes(2,2))]
        pub fn add_device(
            origin: OriginFor<T>,
            did: Vec<u8>,
            device_id: Vec<u8>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let did_b = DidOf::<T>::try_from(did).map_err(|_| Error::<T>::DidTooLong)?;
            Self::ensure_did_owner(&who, &did_b)?;
            let dev_b: BoundedVec<u8, ConstU32<64>> =
                device_id.try_into().map_err(|_| Error::<T>::DidTooLong)?;

            Dids::<T>::try_mutate(&did_b, |maybe| -> DispatchResult {
                let rec = maybe.as_mut().ok_or(Error::<T>::DidNotFound)?;
                let mut list = rec.devices.take().unwrap_or_default();
                let mut found = false;
                for d in &mut list {
                    if d.device_id == dev_b {
                        d.tombstoned = false;
                        found = true;
                        break;
                    }
                }
                if !found {
                    ensure!(
                        (list.len() as u32) < T::MaxDevices::get(),
                        Error::<T>::TooManyDevices
                    );
                    list.try_push(DeviceInfo {
                        device_id: dev_b.clone(),
                        added_at: now_millis::<T>(),
                        tombstoned: false,
                    })
                    .map_err(|_| Error::<T>::TooManyDevices)?;
                }
                rec.devices = Some(list);
                rec.version = rec.version.saturating_add(1);
                rec.updated_at = now_millis::<T>();
                Ok(())
            })?;

            Self::deposit_event(Event::DeviceAdded(did_b, dev_b.clone()));
            Ok(())
        }

        #[pallet::call_index(3)]
        #[pallet::weight(T::DbWeight::get().reads_writes(2,2))]
        pub fn tombstone_device(
            origin: OriginFor<T>,
            did: Vec<u8>,
            device_id: Vec<u8>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let did_b = DidOf::<T>::try_from(did).map_err(|_| Error::<T>::DidTooLong)?;
            Self::ensure_did_owner(&who, &did_b)?;
            let dev_b: BoundedVec<u8, ConstU32<64>> =
                device_id.try_into().map_err(|_| Error::<T>::DidTooLong)?;

            Dids::<T>::try_mutate(&did_b, |maybe| -> DispatchResult {
                let rec = maybe.as_mut().ok_or(Error::<T>::DidNotFound)?;
                let mut list = rec.devices.take().ok_or(Error::<T>::DeviceNotFound)?;
                let mut found = false;
                for d in &mut list {
                    if d.device_id == dev_b {
                        d.tombstoned = true;
                        found = true;
                        break;
                    }
                }
                ensure!(found, Error::<T>::DeviceNotFound);
                rec.devices = Some(list);
                rec.version = rec.version.saturating_add(1);
                rec.updated_at = now_millis::<T>();
                Ok(())
            })?;

            Self::deposit_event(Event::DeviceTombstoned(did_b, dev_b.clone()));
            Ok(())
        }

        #[pallet::call_index(26)]
        #[pallet::weight(T::DbWeight::get().reads_writes(2,1))]
        pub fn deactivate_did(origin: OriginFor<T>, did: Vec<u8>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let did_b = DidOf::<T>::try_from(did).map_err(|_| Error::<T>::DidTooLong)?;

            Dids::<T>::try_mutate(&did_b, |maybe| -> DispatchResult {
                let rec = maybe.as_mut().ok_or(Error::<T>::DidNotFound)?;
                ensure!(rec.owner.as_ref() == Some(&who), Error::<T>::NotDidOwner);
                ensure!(!rec.deactivated, Error::<T>::DidAlreadyDeactivated);
                ensure!(
                    T::RetirementGuard::can_retire(did_b.as_slice()),
                    Error::<T>::DidControlsApplication
                );
                rec.deactivated = true;
                rec.version = rec.version.saturating_add(1);
                rec.updated_at = now_millis::<T>();
                Ok(())
            })?;

            Self::deposit_event(Event::DidDeactivated(did_b));
            Ok(())
        }

        #[pallet::call_index(27)]
        #[pallet::weight(T::DbWeight::get().reads_writes(2,2))]
        pub fn update_device(
            origin: OriginFor<T>,
            did: Vec<u8>,
            old_device_id: Vec<u8>,
            new_device_id: Vec<u8>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let did_b = DidOf::<T>::try_from(did).map_err(|_| Error::<T>::DidTooLong)?;
            Self::ensure_did_owner(&who, &did_b)?;
            let old_b = Self::bounded_device_id(old_device_id)?;
            let new_b = Self::bounded_device_id(new_device_id)?;
            ensure!(old_b != new_b, Error::<T>::DeviceAlreadyExists);

            Dids::<T>::try_mutate(&did_b, |maybe| -> DispatchResult {
                let rec = maybe.as_mut().ok_or(Error::<T>::DidNotFound)?;
                let mut list = rec.devices.take().ok_or(Error::<T>::DeviceNotFound)?;
                ensure!(
                    !list.iter().any(|device| device.device_id == new_b),
                    Error::<T>::DeviceAlreadyExists
                );
                let pos = list
                    .iter()
                    .position(|device| device.device_id == old_b)
                    .ok_or(Error::<T>::DeviceNotFound)?;
                list[pos].device_id = new_b.clone();
                rec.devices = Some(list);
                rec.version = rec.version.saturating_add(1);
                rec.updated_at = now_millis::<T>();
                Ok(())
            })?;

            Self::deposit_event(Event::DeviceUpdated(did_b, old_b, new_b));
            Ok(())
        }

        #[pallet::call_index(28)]
        #[pallet::weight(T::DbWeight::get().reads_writes(2,2))]
        pub fn remove_device(
            origin: OriginFor<T>,
            did: Vec<u8>,
            device_id: Vec<u8>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let did_b = DidOf::<T>::try_from(did).map_err(|_| Error::<T>::DidTooLong)?;
            Self::ensure_did_owner(&who, &did_b)?;
            let dev_b = Self::bounded_device_id(device_id)?;

            Dids::<T>::try_mutate(&did_b, |maybe| -> DispatchResult {
                let rec = maybe.as_mut().ok_or(Error::<T>::DidNotFound)?;
                let mut list = rec.devices.take().ok_or(Error::<T>::DeviceNotFound)?;
                let pos = list
                    .iter()
                    .position(|device| device.device_id == dev_b)
                    .ok_or(Error::<T>::DeviceNotFound)?;
                list.remove(pos);
                rec.devices = if list.is_empty() { None } else { Some(list) };
                rec.version = rec.version.saturating_add(1);
                rec.updated_at = now_millis::<T>();
                Ok(())
            })?;

            Self::deposit_event(Event::DeviceRemoved(did_b, dev_b));
            Ok(())
        }

        /// Set the full W3C DID Document (structured) via SCALE-encoded blob
        #[pallet::call_index(4)]
        #[pallet::weight(T::DbWeight::get().reads_writes(2,2))]
        pub fn set_document(
            origin: OriginFor<T>,
            did: Vec<u8>,
            doc_blob: Vec<u8>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let did_b = DidOf::<T>::try_from(did).map_err(|_| Error::<T>::DidTooLong)?;
            Self::ensure_did_owner(&who, &did_b)?;
            let doc_bounded: DocBlobOf<T> = doc_blob
                .try_into()
                .map_err(|_| Error::<T>::InvalidDocument)?;

            // Decode inside the call to avoid generic Debug/TypeInfo bounds on Call
            let mut bytes = &doc_bounded[..];
            let doc =
                DidDocument::<T>::decode(&mut bytes).map_err(|_| Error::<T>::InvalidDocument)?;

            Self::validate_document_structure(&did_b, &doc)?;

            Dids::<T>::try_mutate(&did_b, |maybe| -> DispatchResult {
                let rec = maybe.as_mut().ok_or(Error::<T>::DidNotFound)?;
                Self::ensure_did_active(rec)?;
                rec.document = Some(doc);
                rec.version = rec.version.saturating_add(1);
                rec.updated_at = now_millis::<T>();
                Ok(())
            })?;

            Self::deposit_event(Event::DocumentSet(did_b));
            Ok(())
        }

        /// Set the full W3C DID Document (structured) via SCALE-encoded blob
        #[pallet::call_index(5)]
        #[pallet::weight(T::DbWeight::get().reads_writes(2,2))]
        #[pallet::authorize(|_source, did, doc_blob, timestamp, pubkey, signature| {
            Self::authorize_unsigned_call(&Call::set_document_with_proof {
                did: did.clone(),
                doc_blob: doc_blob.clone(),
                timestamp: timestamp.clone(),
                pubkey: pubkey.clone(),
                signature: signature.clone(),
            })
        })]
        #[pallet::weight_of_authorize(T::DbWeight::get().reads_writes(1,1))]
        pub fn set_document_with_proof(
            origin: OriginFor<T>,
            did: Vec<u8>,
            doc_blob: Vec<u8>,
            timestamp: Vec<u8>,
            pubkey: Vec<u8>,
            signature: Vec<u8>,
        ) -> DispatchResult {
            Self::ensure_unsigned_or_authorized(origin)?;

            // Basic size checks
            ensure!(
                pubkey.len() == 32 && signature.len() == 64,
                Error::<T>::InvalidSignature
            );

            // Bind the signature to DID + content + op + time
            // domain = "openpayload:set_document:v1|"
            let mut payload = Vec::with_capacity(
                b"openpayload:set_document:v1|".len() + did.len() + 1 + 32 + 1 + timestamp.len(),
            );
            payload.extend_from_slice(b"openpayload:set_document:v1|");
            payload.extend_from_slice(&did);
            payload.push(b'|');

            let doc_hash = sp_io::hashing::blake2_256(&doc_blob);
            payload.extend_from_slice(&doc_hash);
            payload.push(b'|');
            payload.extend_from_slice(&timestamp);

            // Decode the document and sanity-check DID binding
            let did_b = DidOf::<T>::try_from(did).map_err(|_| Error::<T>::DidTooLong)?;
            let doc_bounded: DocBlobOf<T> = doc_blob
                .try_into()
                .map_err(|_| Error::<T>::InvalidDocument)?;
            let mut bytes = &doc_bounded[..];
            let doc =
                DidDocument::<T>::decode(&mut bytes).map_err(|_| Error::<T>::InvalidDocument)?;
            Self::validate_document_structure(&did_b, &doc)?;

            // Write the document
            Dids::<T>::try_mutate(&did_b, |maybe| -> DispatchResult {
                let rec = maybe.as_mut().ok_or(Error::<T>::DidNotFound)?;
                Self::ensure_did_active(rec)?;

                let stored_pk = rec.root_pubkey.as_ref().ok_or(Error::<T>::DidNotFound)?;

                // Optional but recommended: enforce the arg pubkey matches the stored one
                ensure!(
                    pubkey.as_slice() == stored_pk.as_slice(),
                    Error::<T>::InvalidSignature
                );

                let ok = ed25519::Signature::from_slice(&signature)
                    .and_then(|sig| {
                        ed25519::Public::from_slice(stored_pk.as_slice()).map(|pk| (sig, pk))
                    })
                    .is_ok_and(|(sig, pk)| ed25519_verify(&sig, &payload, &pk));
                ensure!(ok, Error::<T>::InvalidSignature);

                rec.document = Some(doc);
                rec.version = rec.version.saturating_add(1);
                rec.updated_at = now_millis::<T>();
                Ok(())
            })?;

            Self::deposit_event(Event::DocumentSet(did_b));
            Ok(())
        }

        #[pallet::call_index(6)]
        #[pallet::weight(T::DbWeight::get().reads_writes(3,3))]
        #[pallet::authorize(|_source, did, alias, timestamp, pubkey, signature, doc_blob| {
            Self::authorize_unsigned_call(&Call::register_with_document_proof {
                did: did.clone(),
                alias: alias.clone(),
                timestamp: timestamp.clone(),
                pubkey: pubkey.clone(),
                signature: signature.clone(),
                doc_blob: doc_blob.clone(),
            })
        })]
        #[pallet::weight_of_authorize(T::DbWeight::get().reads_writes(1,1))]
        pub fn register_with_document_proof(
            origin: OriginFor<T>,
            did: Vec<u8>,
            alias: Option<Vec<u8>>,
            timestamp: Vec<u8>,
            pubkey: Vec<u8>,
            signature: Vec<u8>,
            doc_blob: Vec<u8>, // SCALE-encoded DidDocument<T>
        ) -> DispatchResult {
            Self::ensure_unsigned_or_authorized(origin)?;

            Self::do_register(
                None,
                did,
                alias,
                timestamp,
                pubkey,
                signature,
                Some(doc_blob),
            )?;
            Ok(())
        }

        #[pallet::call_index(7)]
        #[pallet::weight(T::DbWeight::get().reads_writes(3,3))]
        pub fn register_with_document_proof_signed(
            origin: OriginFor<T>,
            did: Vec<u8>,
            alias: Option<Vec<u8>>,
            timestamp: Vec<u8>,
            pubkey: Vec<u8>,
            signature: Vec<u8>,
            doc_blob: Vec<u8>, // SCALE-encoded DidDocument<T>
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            Self::do_register(
                Some(who),
                did,
                alias,
                timestamp,
                pubkey,
                signature,
                Some(doc_blob),
            )?;
            Ok(())
        }

        #[pallet::call_index(8)]
        #[pallet::weight(T::DbWeight::get().reads_writes(1,1))]
        pub fn set_delivery_policy_links(
            origin: OriginFor<T>,
            did: Vec<u8>,
            recipient_policy: Option<Vec<u8>>,
            tag_policies: Vec<Vec<u8>>,
            persona_policies: Vec<Vec<u8>>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let did_b = DidOf::<T>::try_from(did).map_err(|_| Error::<T>::DidTooLong)?;
            Self::ensure_did_owner(&who, &did_b)?;
            let links = DeliveryPolicyLinks::<T> {
                recipient_policy: match recipient_policy {
                    Some(raw) => Some(
                        PolicyRefOf::<T>::try_from(raw)
                            .map_err(|_| Error::<T>::PolicyRefTooLong)?,
                    ),
                    None => None,
                },
                tag_policies: Self::bounded_policy_refs(tag_policies)?,
                persona_policies: Self::bounded_policy_refs(persona_policies)?,
            };

            Dids::<T>::try_mutate(&did_b, |maybe| -> DispatchResult {
                let rec = maybe.as_mut().ok_or(Error::<T>::DidNotFound)?;
                rec.delivery_policy_links = Some(links);
                rec.version = rec.version.saturating_add(1);
                rec.updated_at = now_millis::<T>();
                Ok(())
            })?;

            Self::deposit_event(Event::DeliveryPolicyLinksSet(did_b));
            Ok(())
        }

        #[pallet::call_index(9)]
        #[pallet::weight(T::DbWeight::get().reads_writes(1,1))]
        pub fn clear_delivery_policy_links(origin: OriginFor<T>, did: Vec<u8>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let did_b = DidOf::<T>::try_from(did).map_err(|_| Error::<T>::DidTooLong)?;
            Self::ensure_did_owner(&who, &did_b)?;

            Dids::<T>::try_mutate(&did_b, |maybe| -> DispatchResult {
                let rec = maybe.as_mut().ok_or(Error::<T>::DidNotFound)?;
                rec.delivery_policy_links = None;
                rec.version = rec.version.saturating_add(1);
                rec.updated_at = now_millis::<T>();
                Ok(())
            })?;

            Self::deposit_event(Event::DeliveryPolicyLinksCleared(did_b));
            Ok(())
        }

        #[pallet::call_index(10)]
        #[pallet::weight(T::DbWeight::get().reads_writes(2,2))]
        #[pallet::authorize(|_source, did, alias, timestamp, pubkey, signature| {
            Self::authorize_unsigned_call(&Call::register_with_proof {
                did: did.clone(),
                alias: alias.clone(),
                timestamp: timestamp.clone(),
                pubkey: pubkey.clone(),
                signature: signature.clone(),
            })
        })]
        #[pallet::weight_of_authorize(T::DbWeight::get().reads_writes(1,1))]
        pub fn register_with_proof(
            origin: OriginFor<T>,
            did: Vec<u8>,
            alias: Option<Vec<u8>>,
            timestamp: Vec<u8>,
            pubkey: Vec<u8>,
            signature: Vec<u8>,
        ) -> DispatchResult {
            let who = ensure_signed(origin).or_else(|_| {
                T::AccountId::decode(&mut &pubkey[..])
                    .map_err(|_| sp_runtime::DispatchError::from(Error::<T>::SignatureMismatch))
            })?;

            let pk_b = Self::bounded_root_pubkey(pubkey.clone())?;

            let did_b = Self::validated_registration_did(did.clone())?;
            ensure!(
                !Dids::<T>::contains_key(&did_b),
                Error::<T>::DidAlreadyExists
            );

            ensure!(
                verify_did_signature(&did, &timestamp, &pubkey, &signature),
                Error::<T>::InvalidSignature
            );

            let alias_b = if let Some(a) = alias {
                let alias_b = Self::normalize_alias(&a)?;
                if let Some(existing) = AliasIndex::<T>::get(&alias_b) {
                    ensure!(existing == did_b, Error::<T>::AliasTaken);
                }
                AliasIndex::<T>::insert(&alias_b, did_b.clone());
                Some(alias_b)
            } else {
                None
            };

            let rec = DidRecord::<T> {
                owner: Some(who.clone()),
                aliases: Self::single_alias_list(alias_b)?,
                devices: None,
                document: None,
                version: 1,
                updated_at: now_millis::<T>(),
                root_pubkey: Some(pk_b),
                delivery_policy_links: None,
                deactivated: false,
            };

            Dids::<T>::insert(&did_b, rec);
            Self::deposit_event(Event::Registered(did_b.clone(), Some(who)));
            Ok(())
        }

        #[pallet::call_index(11)]
        #[pallet::weight(T::DbWeight::get().reads_writes(3,3))]
        #[pallet::authorize(|_source, did, alias, signed_payload, signature, signer_key_id| {
            Self::authorize_unsigned_call(&Call::add_alias {
                did: did.clone(),
                alias: alias.clone(),
                signed_payload: signed_payload.clone(),
                signature: signature.clone(),
                signer_key_id: signer_key_id.clone(),
            })
        })]
        #[pallet::weight_of_authorize(T::DbWeight::get().reads_writes(1,1))]
        pub fn add_alias(
            origin: OriginFor<T>,
            did: Vec<u8>,
            alias: Vec<u8>,
            signed_payload: Vec<u8>,
            signature: Vec<u8>,
            signer_key_id: Vec<u8>,
        ) -> DispatchResult {
            Self::ensure_unsigned_or_authorized(origin)?;
            let checked = Self::validate_alias_authorization(
                AliasAction::Add,
                &did,
                Some(&alias),
                None,
                None,
                &signed_payload,
                &signature,
                &signer_key_id,
            )?;
            Self::apply_alias_add(checked)
        }

        #[pallet::call_index(12)]
        #[pallet::weight(T::DbWeight::get().reads_writes(3,3))]
        #[pallet::authorize(|_source, did, old_alias, new_alias, signed_payload, signature, signer_key_id| {
            Self::authorize_unsigned_call(&Call::update_alias {
                did: did.clone(),
                old_alias: old_alias.clone(),
                new_alias: new_alias.clone(),
                signed_payload: signed_payload.clone(),
                signature: signature.clone(),
                signer_key_id: signer_key_id.clone(),
            })
        })]
        #[pallet::weight_of_authorize(T::DbWeight::get().reads_writes(1,1))]
        pub fn update_alias(
            origin: OriginFor<T>,
            did: Vec<u8>,
            old_alias: Vec<u8>,
            new_alias: Vec<u8>,
            signed_payload: Vec<u8>,
            signature: Vec<u8>,
            signer_key_id: Vec<u8>,
        ) -> DispatchResult {
            Self::ensure_unsigned_or_authorized(origin)?;
            let checked = Self::validate_alias_authorization(
                AliasAction::Update,
                &did,
                None,
                Some(&old_alias),
                Some(&new_alias),
                &signed_payload,
                &signature,
                &signer_key_id,
            )?;
            Self::apply_alias_update(checked)
        }

        #[pallet::call_index(13)]
        #[pallet::weight(T::DbWeight::get().reads_writes(3,3))]
        #[pallet::authorize(|_source, did, alias, signed_payload, signature, signer_key_id| {
            Self::authorize_unsigned_call(&Call::remove_alias {
                did: did.clone(),
                alias: alias.clone(),
                signed_payload: signed_payload.clone(),
                signature: signature.clone(),
                signer_key_id: signer_key_id.clone(),
            })
        })]
        #[pallet::weight_of_authorize(T::DbWeight::get().reads_writes(1,1))]
        pub fn remove_alias(
            origin: OriginFor<T>,
            did: Vec<u8>,
            alias: Vec<u8>,
            signed_payload: Vec<u8>,
            signature: Vec<u8>,
            signer_key_id: Vec<u8>,
        ) -> DispatchResult {
            Self::ensure_unsigned_or_authorized(origin)?;
            let checked = Self::validate_alias_authorization(
                AliasAction::Remove,
                &did,
                Some(&alias),
                None,
                None,
                &signed_payload,
                &signature,
                &signer_key_id,
            )?;
            Self::apply_alias_remove(checked)
        }

        #[pallet::call_index(14)]
        #[pallet::weight(T::DbWeight::get().reads_writes(2,2))]
        #[pallet::authorize(|_source, did, method, signed_payload, signature, signer_key_id| {
            Self::authorize_unsigned_call(&Call::add_verification_method {
                did: did.clone(),
                method: method.clone(),
                signed_payload: signed_payload.clone(),
                signature: signature.clone(),
                signer_key_id: signer_key_id.clone(),
            })
        })]
        #[pallet::weight_of_authorize(T::DbWeight::get().reads_writes(1,1))]
        pub fn add_verification_method(
            origin: OriginFor<T>,
            did: Vec<u8>,
            method: VerificationMethod<T>,
            signed_payload: Vec<u8>,
            signature: Vec<u8>,
            signer_key_id: Vec<u8>,
        ) -> DispatchResult {
            Self::ensure_unsigned_or_authorized(origin)?;
            let checked = Self::validate_document_authorization(
                DocumentAction::AddVerificationMethod,
                &did,
                Some(&method),
                None,
                None,
                None,
                &signed_payload,
                &signature,
                &signer_key_id,
            )?;
            Self::apply_add_verification_method(checked, method)
        }

        #[pallet::call_index(15)]
        #[pallet::weight(T::DbWeight::get().reads_writes(2,2))]
        #[pallet::authorize(|_source, did, method, signed_payload, signature, signer_key_id| {
            Self::authorize_unsigned_call(&Call::update_verification_method {
                did: did.clone(),
                method: method.clone(),
                signed_payload: signed_payload.clone(),
                signature: signature.clone(),
                signer_key_id: signer_key_id.clone(),
            })
        })]
        #[pallet::weight_of_authorize(T::DbWeight::get().reads_writes(1,1))]
        pub fn update_verification_method(
            origin: OriginFor<T>,
            did: Vec<u8>,
            method: VerificationMethod<T>,
            signed_payload: Vec<u8>,
            signature: Vec<u8>,
            signer_key_id: Vec<u8>,
        ) -> DispatchResult {
            Self::ensure_unsigned_or_authorized(origin)?;
            let checked = Self::validate_document_authorization(
                DocumentAction::UpdateVerificationMethod,
                &did,
                Some(&method),
                None,
                None,
                None,
                &signed_payload,
                &signature,
                &signer_key_id,
            )?;
            Self::apply_update_verification_method(checked, method)
        }

        #[pallet::call_index(16)]
        #[pallet::weight(T::DbWeight::get().reads_writes(2,2))]
        #[pallet::authorize(|_source, did, method_id, signed_payload, signature, signer_key_id| {
            Self::authorize_unsigned_call(&Call::remove_verification_method {
                did: did.clone(),
                method_id: method_id.clone(),
                signed_payload: signed_payload.clone(),
                signature: signature.clone(),
                signer_key_id: signer_key_id.clone(),
            })
        })]
        #[pallet::weight_of_authorize(T::DbWeight::get().reads_writes(1,1))]
        pub fn remove_verification_method(
            origin: OriginFor<T>,
            did: Vec<u8>,
            method_id: Vec<u8>,
            signed_payload: Vec<u8>,
            signature: Vec<u8>,
            signer_key_id: Vec<u8>,
        ) -> DispatchResult {
            Self::ensure_unsigned_or_authorized(origin)?;
            let method_id_b = IdStrOf::<T>::try_from(method_id)
                .map_err(|_| Error::<T>::InvalidDocumentPayload)?;
            let checked = Self::validate_document_authorization(
                DocumentAction::RemoveVerificationMethod,
                &did,
                None,
                None,
                None,
                Some(&method_id_b),
                &signed_payload,
                &signature,
                &signer_key_id,
            )?;
            Self::apply_remove_verification_method(checked, method_id_b)
        }

        #[pallet::call_index(17)]
        #[pallet::weight(T::DbWeight::get().reads_writes(2,2))]
        #[pallet::authorize(|_source, did, method_id, signed_payload, signature, signer_key_id| {
            Self::authorize_unsigned_call(&Call::add_authentication {
                did: did.clone(),
                method_id: method_id.clone(),
                signed_payload: signed_payload.clone(),
                signature: signature.clone(),
                signer_key_id: signer_key_id.clone(),
            })
        })]
        #[pallet::weight_of_authorize(T::DbWeight::get().reads_writes(1,1))]
        pub fn add_authentication(
            origin: OriginFor<T>,
            did: Vec<u8>,
            method_id: Vec<u8>,
            signed_payload: Vec<u8>,
            signature: Vec<u8>,
            signer_key_id: Vec<u8>,
        ) -> DispatchResult {
            Self::ensure_unsigned_or_authorized(origin)?;
            let method_id_b = IdStrOf::<T>::try_from(method_id)
                .map_err(|_| Error::<T>::InvalidDocumentPayload)?;
            let checked = Self::validate_document_authorization(
                DocumentAction::AddAuthentication,
                &did,
                None,
                None,
                None,
                Some(&method_id_b),
                &signed_payload,
                &signature,
                &signer_key_id,
            )?;
            Self::apply_add_authentication(checked, method_id_b)
        }

        #[pallet::call_index(18)]
        #[pallet::weight(T::DbWeight::get().reads_writes(2,2))]
        #[pallet::authorize(|_source, did, method_id, signed_payload, signature, signer_key_id| {
            Self::authorize_unsigned_call(&Call::remove_authentication {
                did: did.clone(),
                method_id: method_id.clone(),
                signed_payload: signed_payload.clone(),
                signature: signature.clone(),
                signer_key_id: signer_key_id.clone(),
            })
        })]
        #[pallet::weight_of_authorize(T::DbWeight::get().reads_writes(1,1))]
        pub fn remove_authentication(
            origin: OriginFor<T>,
            did: Vec<u8>,
            method_id: Vec<u8>,
            signed_payload: Vec<u8>,
            signature: Vec<u8>,
            signer_key_id: Vec<u8>,
        ) -> DispatchResult {
            Self::ensure_unsigned_or_authorized(origin)?;
            let method_id_b = IdStrOf::<T>::try_from(method_id)
                .map_err(|_| Error::<T>::InvalidDocumentPayload)?;
            let checked = Self::validate_document_authorization(
                DocumentAction::RemoveAuthentication,
                &did,
                None,
                None,
                None,
                Some(&method_id_b),
                &signed_payload,
                &signature,
                &signer_key_id,
            )?;
            Self::apply_remove_authentication(checked, method_id_b)
        }

        #[pallet::call_index(19)]
        #[pallet::weight(T::DbWeight::get().reads_writes(2,2))]
        #[pallet::authorize(|_source, did, key_agreement, signed_payload, signature, signer_key_id| {
            Self::authorize_unsigned_call(&Call::add_key_agreement {
                did: did.clone(),
                key_agreement: key_agreement.clone(),
                signed_payload: signed_payload.clone(),
                signature: signature.clone(),
                signer_key_id: signer_key_id.clone(),
            })
        })]
        #[pallet::weight_of_authorize(T::DbWeight::get().reads_writes(1,1))]
        pub fn add_key_agreement(
            origin: OriginFor<T>,
            did: Vec<u8>,
            key_agreement: KeyAgreement<T>,
            signed_payload: Vec<u8>,
            signature: Vec<u8>,
            signer_key_id: Vec<u8>,
        ) -> DispatchResult {
            Self::ensure_unsigned_or_authorized(origin)?;
            let checked = Self::validate_document_authorization(
                DocumentAction::AddKeyAgreement,
                &did,
                None,
                Some(&key_agreement),
                None,
                None,
                &signed_payload,
                &signature,
                &signer_key_id,
            )?;
            Self::apply_add_key_agreement(checked, key_agreement)
        }

        #[pallet::call_index(20)]
        #[pallet::weight(T::DbWeight::get().reads_writes(2,2))]
        #[pallet::authorize(|_source, did, key_agreement, signed_payload, signature, signer_key_id| {
            Self::authorize_unsigned_call(&Call::update_key_agreement {
                did: did.clone(),
                key_agreement: key_agreement.clone(),
                signed_payload: signed_payload.clone(),
                signature: signature.clone(),
                signer_key_id: signer_key_id.clone(),
            })
        })]
        #[pallet::weight_of_authorize(T::DbWeight::get().reads_writes(1,1))]
        pub fn update_key_agreement(
            origin: OriginFor<T>,
            did: Vec<u8>,
            key_agreement: KeyAgreement<T>,
            signed_payload: Vec<u8>,
            signature: Vec<u8>,
            signer_key_id: Vec<u8>,
        ) -> DispatchResult {
            Self::ensure_unsigned_or_authorized(origin)?;
            let checked = Self::validate_document_authorization(
                DocumentAction::UpdateKeyAgreement,
                &did,
                None,
                Some(&key_agreement),
                None,
                None,
                &signed_payload,
                &signature,
                &signer_key_id,
            )?;
            Self::apply_update_key_agreement(checked, key_agreement)
        }

        #[pallet::call_index(21)]
        #[pallet::weight(T::DbWeight::get().reads_writes(2,2))]
        #[pallet::authorize(|_source, did, key_agreement_id, signed_payload, signature, signer_key_id| {
            Self::authorize_unsigned_call(&Call::remove_key_agreement {
                did: did.clone(),
                key_agreement_id: key_agreement_id.clone(),
                signed_payload: signed_payload.clone(),
                signature: signature.clone(),
                signer_key_id: signer_key_id.clone(),
            })
        })]
        #[pallet::weight_of_authorize(T::DbWeight::get().reads_writes(1,1))]
        pub fn remove_key_agreement(
            origin: OriginFor<T>,
            did: Vec<u8>,
            key_agreement_id: Vec<u8>,
            signed_payload: Vec<u8>,
            signature: Vec<u8>,
            signer_key_id: Vec<u8>,
        ) -> DispatchResult {
            Self::ensure_unsigned_or_authorized(origin)?;
            let id_b = IdStrOf::<T>::try_from(key_agreement_id)
                .map_err(|_| Error::<T>::InvalidDocumentPayload)?;
            let checked = Self::validate_document_authorization(
                DocumentAction::RemoveKeyAgreement,
                &did,
                None,
                None,
                None,
                Some(&id_b),
                &signed_payload,
                &signature,
                &signer_key_id,
            )?;
            Self::apply_remove_key_agreement(checked, id_b)
        }

        #[pallet::call_index(22)]
        #[pallet::weight(T::DbWeight::get().reads_writes(2,2))]
        #[pallet::authorize(|_source, did, service, signed_payload, signature, signer_key_id| {
            Self::authorize_unsigned_call(&Call::add_service {
                did: did.clone(),
                service: service.clone(),
                signed_payload: signed_payload.clone(),
                signature: signature.clone(),
                signer_key_id: signer_key_id.clone(),
            })
        })]
        #[pallet::weight_of_authorize(T::DbWeight::get().reads_writes(1,1))]
        pub fn add_service(
            origin: OriginFor<T>,
            did: Vec<u8>,
            service: Service<T>,
            signed_payload: Vec<u8>,
            signature: Vec<u8>,
            signer_key_id: Vec<u8>,
        ) -> DispatchResult {
            Self::ensure_unsigned_or_authorized(origin)?;
            let checked = Self::validate_document_authorization(
                DocumentAction::AddService,
                &did,
                None,
                None,
                Some(&service),
                None,
                &signed_payload,
                &signature,
                &signer_key_id,
            )?;
            Self::apply_add_service(checked, service)
        }

        #[pallet::call_index(23)]
        #[pallet::weight(T::DbWeight::get().reads_writes(2,2))]
        #[pallet::authorize(|_source, did, service, signed_payload, signature, signer_key_id| {
            Self::authorize_unsigned_call(&Call::update_service {
                did: did.clone(),
                service: service.clone(),
                signed_payload: signed_payload.clone(),
                signature: signature.clone(),
                signer_key_id: signer_key_id.clone(),
            })
        })]
        #[pallet::weight_of_authorize(T::DbWeight::get().reads_writes(1,1))]
        pub fn update_service(
            origin: OriginFor<T>,
            did: Vec<u8>,
            service: Service<T>,
            signed_payload: Vec<u8>,
            signature: Vec<u8>,
            signer_key_id: Vec<u8>,
        ) -> DispatchResult {
            Self::ensure_unsigned_or_authorized(origin)?;
            let checked = Self::validate_document_authorization(
                DocumentAction::UpdateService,
                &did,
                None,
                None,
                Some(&service),
                None,
                &signed_payload,
                &signature,
                &signer_key_id,
            )?;
            Self::apply_update_service(checked, service)
        }

        #[pallet::call_index(24)]
        #[pallet::weight(T::DbWeight::get().reads_writes(2,2))]
        #[pallet::authorize(|_source, did, service_id, signed_payload, signature, signer_key_id| {
            Self::authorize_unsigned_call(&Call::remove_service {
                did: did.clone(),
                service_id: service_id.clone(),
                signed_payload: signed_payload.clone(),
                signature: signature.clone(),
                signer_key_id: signer_key_id.clone(),
            })
        })]
        #[pallet::weight_of_authorize(T::DbWeight::get().reads_writes(1,1))]
        pub fn remove_service(
            origin: OriginFor<T>,
            did: Vec<u8>,
            service_id: Vec<u8>,
            signed_payload: Vec<u8>,
            signature: Vec<u8>,
            signer_key_id: Vec<u8>,
        ) -> DispatchResult {
            Self::ensure_unsigned_or_authorized(origin)?;
            let id_b = IdStrOf::<T>::try_from(service_id)
                .map_err(|_| Error::<T>::InvalidDocumentPayload)?;
            let checked = Self::validate_document_authorization(
                DocumentAction::RemoveService,
                &did,
                None,
                None,
                None,
                Some(&id_b),
                &signed_payload,
                &signature,
                &signer_key_id,
            )?;
            Self::apply_remove_service(checked, id_b)
        }

        #[pallet::call_index(25)]
        #[pallet::weight(T::DbWeight::get().reads_writes(2,2))]
        #[pallet::authorize(|_source, did, new_root_pubkey, signed_payload, signature, signer_key_id| {
            Self::authorize_unsigned_call(&Call::update_root_pubkey {
                did: did.clone(),
                new_root_pubkey: new_root_pubkey.clone(),
                signed_payload: signed_payload.clone(),
                signature: signature.clone(),
                signer_key_id: signer_key_id.clone(),
            })
        })]
        #[pallet::weight_of_authorize(T::DbWeight::get().reads_writes(1,1))]
        pub fn update_root_pubkey(
            origin: OriginFor<T>,
            did: Vec<u8>,
            new_root_pubkey: Vec<u8>,
            signed_payload: Vec<u8>,
            signature: Vec<u8>,
            signer_key_id: Vec<u8>,
        ) -> DispatchResult {
            Self::ensure_unsigned_or_authorized(origin)?;
            let new_root_pubkey_b = Self::bounded_root_pubkey(new_root_pubkey)?;
            let checked = Self::validate_root_pubkey_authorization(
                &did,
                &new_root_pubkey_b,
                &signed_payload,
                &signature,
                &signer_key_id,
            )?;
            Self::apply_update_root_pubkey(checked, new_root_pubkey_b)
        }

        /// Apply a DID control action using a proof from the root key or an
        /// authorized verification method. This is the ownerless-DID
        /// counterpart to the account-signed device, deactivation, and policy
        /// link calls above.
        #[pallet::call_index(29)]
        #[pallet::weight(T::DbWeight::get().reads_writes(
            5,
            13u64.saturating_add(T::MaxAliases::get() as u64),
        ))]
        #[pallet::authorize(|_source, signed_payload, signature, signer_key_id| {
            Self::authorize_unsigned_call(&Call::apply_control_with_proof {
                signed_payload: signed_payload.clone(),
                signature: signature.clone(),
                signer_key_id: signer_key_id.clone(),
            })
        })]
        #[pallet::weight_of_authorize(T::DbWeight::get().reads_writes(1,1))]
        pub fn apply_control_with_proof(
            origin: OriginFor<T>,
            signed_payload: Vec<u8>,
            signature: Vec<u8>,
            signer_key_id: Vec<u8>,
        ) -> DispatchResult {
            Self::ensure_unsigned_or_authorized(origin)?;
            let checked =
                Self::validate_control_authorization(&signed_payload, &signature, &signer_key_id)?;
            Self::apply_control_action(checked)
        }
    }

    impl<T: Config> Pallet<T> {
        fn ensure_unsigned_or_authorized(origin: OriginFor<T>) -> DispatchResult {
            match origin.into() {
                Ok(frame_system::RawOrigin::None) | Ok(frame_system::RawOrigin::Authorized) => {
                    Ok(())
                }
                _ => Err(sp_runtime::DispatchError::BadOrigin),
            }
        }

        pub fn did_for_alias(alias: &[u8]) -> Option<DidOf<T>> {
            Self::normalize_alias(alias)
                .ok()
                .and_then(AliasIndex::<T>::get)
        }

        pub fn aliases_of(did: &[u8]) -> Option<AliasListOf<T>> {
            Self::did_from_slice(did)
                .and_then(Dids::<T>::get)
                .and_then(|record| record.aliases)
        }

        pub fn did_exists(did: &[u8]) -> bool {
            Self::did_from_slice(did)
                .map(Dids::<T>::contains_key)
                .unwrap_or(false)
        }

        pub fn is_deactivated(did: &[u8]) -> bool {
            Self::did_from_slice(did)
                .and_then(Dids::<T>::get)
                .map(|record| record.deactivated)
                .unwrap_or(false)
        }

        pub fn device_of(did: &[u8], device_id: &[u8]) -> Option<DeviceInfo> {
            let device_id = Self::bounded_device_id(device_id.to_vec()).ok()?;
            Self::did_from_slice(did)
                .and_then(Dids::<T>::get)
                .and_then(|record| record.devices)
                .and_then(|devices| {
                    devices
                        .into_iter()
                        .find(|device| device.device_id == device_id)
                })
        }

        pub fn devices_of(did: &[u8]) -> Option<BoundedVec<DeviceInfo, T::MaxDevices>> {
            Self::did_from_slice(did)
                .and_then(Dids::<T>::get)
                .and_then(|record| record.devices)
        }

        pub fn owner_of(did: &[u8]) -> Option<T::AccountId> {
            Self::did_from_slice(did)
                .and_then(Dids::<T>::get)
                .and_then(|record| record.owner)
        }

        pub fn can_update_did(who: &T::AccountId, did: &[u8]) -> bool {
            Self::did_from_slice(did)
                .and_then(Dids::<T>::get)
                .map(|record| !record.deactivated && record.owner.as_ref() == Some(who))
                .unwrap_or(false)
        }

        pub fn delivery_policy_links(did: &[u8]) -> Option<DeliveryPolicyLinks<T>> {
            Self::did_from_slice(did)
                .and_then(Dids::<T>::get)
                .and_then(|record| record.delivery_policy_links)
        }

        fn did_from_slice(did: &[u8]) -> Option<DidOf<T>> {
            DidOf::<T>::try_from(did.to_vec()).ok()
        }

        fn ensure_did_owner(who: &T::AccountId, did: &DidOf<T>) -> DispatchResult {
            let rec = Dids::<T>::get(did).ok_or(Error::<T>::DidNotFound)?;
            Self::ensure_did_active(&rec)?;
            ensure!(rec.owner.as_ref() == Some(who), Error::<T>::NotDidOwner);
            Ok(())
        }

        fn ensure_did_active(rec: &DidRecord<T>) -> Result<(), Error<T>> {
            ensure!(!rec.deactivated, Error::<T>::DidDeactivated);
            Ok(())
        }

        fn bounded_device_id(raw: Vec<u8>) -> Result<BoundedVec<u8, ConstU32<64>>, Error<T>> {
            raw.try_into().map_err(|_| Error::<T>::DidTooLong)
        }

        fn bounded_policy_refs(raw_refs: Vec<Vec<u8>>) -> Result<PolicyRefListOf<T>, Error<T>> {
            let mut refs = PolicyRefListOf::<T>::default();
            for raw in raw_refs {
                let policy_ref =
                    PolicyRefOf::<T>::try_from(raw).map_err(|_| Error::<T>::PolicyRefTooLong)?;
                refs.try_push(policy_ref)
                    .map_err(|_| Error::<T>::TooManyPolicyRefs)?;
            }
            Ok(refs)
        }

        fn bounded_root_pubkey(raw: Vec<u8>) -> Result<RootPubkeyOf, Error<T>> {
            ensure!(raw.len() == 32, Error::<T>::InvalidRootPubkey);
            RootPubkeyOf::try_from(raw).map_err(|_| Error::<T>::InvalidRootPubkey)
        }

        fn single_alias_list(
            alias: Option<AliasOf<T>>,
        ) -> Result<Option<AliasListOf<T>>, Error<T>> {
            let Some(alias) = alias else {
                return Ok(None);
            };
            let mut aliases = AliasListOf::<T>::default();
            aliases
                .try_push(alias)
                .map_err(|_| Error::<T>::TooManyAliases)?;
            Ok(Some(aliases))
        }

        fn normalize_alias(raw: &[u8]) -> Result<AliasOf<T>, Error<T>> {
            let trimmed = trim_ascii_whitespace(raw);
            ensure!(!trimmed.is_empty(), Error::<T>::InvalidAlias);

            let mut normalized = Vec::with_capacity(trimmed.len());
            for byte in trimmed {
                ensure!(byte.is_ascii(), Error::<T>::InvalidAlias);
                let lower = byte.to_ascii_lowercase();
                let valid = lower.is_ascii_lowercase()
                    || lower.is_ascii_digit()
                    || matches!(lower, b'_' | b'-' | b'.');
                ensure!(valid, Error::<T>::InvalidAlias);
                normalized.push(lower);
            }

            AliasOf::<T>::try_from(normalized).map_err(|_| Error::<T>::AliasTooLong)
        }

        fn decode_alias_payload(
            signed_payload: &[u8],
        ) -> Result<AliasAuthorizationPayload<T>, Error<T>> {
            let mut bytes = signed_payload;
            let payload = AliasAuthorizationPayload::<T>::decode(&mut bytes)
                .map_err(|_| Error::<T>::InvalidAliasPayload)?;
            ensure!(bytes.is_empty(), Error::<T>::InvalidAliasPayload);
            ensure!(
                payload.encode() == signed_payload,
                Error::<T>::InvalidAliasPayload
            );
            Ok(payload)
        }

        #[allow(clippy::too_many_arguments)]
        fn validate_alias_authorization(
            action: AliasAction,
            did: &[u8],
            alias: Option<&[u8]>,
            old_alias: Option<&[u8]>,
            new_alias: Option<&[u8]>,
            signed_payload: &[u8],
            signature: &[u8],
            signer_key_id: &[u8],
        ) -> Result<CheckedAliasAuthorization<T>, Error<T>> {
            let did_b = DidOf::<T>::try_from(did.to_vec()).map_err(|_| Error::<T>::DidTooLong)?;
            let alias_b = alias.map(Self::normalize_alias).transpose()?;
            let old_alias_b = old_alias.map(Self::normalize_alias).transpose()?;
            let new_alias_b = new_alias.map(Self::normalize_alias).transpose()?;
            let signer_key_id_b = IdStrOf::<T>::try_from(signer_key_id.to_vec())
                .map_err(|_| Error::<T>::InvalidAliasPayload)?;
            let payload = Self::decode_alias_payload(signed_payload)?;

            ensure!(payload.did == did_b, Error::<T>::InvalidAliasPayload);
            ensure!(payload.action == action, Error::<T>::InvalidAliasPayload);
            ensure!(payload.alias == alias_b, Error::<T>::InvalidAliasPayload);
            ensure!(
                payload.old_alias == old_alias_b,
                Error::<T>::InvalidAliasPayload
            );
            ensure!(
                payload.new_alias == new_alias_b,
                Error::<T>::InvalidAliasPayload
            );
            ensure!(
                payload.signer_key_id == signer_key_id_b,
                Error::<T>::InvalidAliasPayload
            );
            ensure!(
                payload.valid_until > now_millis::<T>(),
                Error::<T>::AliasAuthorizationExpired
            );

            let rec = Dids::<T>::get(&did_b).ok_or(Error::<T>::DidNotFound)?;
            Self::ensure_did_active(&rec)?;
            ensure!(
                payload.nonce == AliasNonces::<T>::get(&did_b),
                Error::<T>::InvalidAliasNonce
            );
            ensure!(
                Self::verify_alias_signature(
                    &rec,
                    &did_b,
                    &signer_key_id_b,
                    signed_payload,
                    signature
                ),
                Error::<T>::InvalidSignature
            );

            Ok(CheckedAliasAuthorization {
                did: did_b,
                alias: alias_b,
                old_alias: old_alias_b,
                new_alias: new_alias_b,
                nonce: payload.nonce,
            })
        }

        fn verify_alias_signature(
            rec: &DidRecord<T>,
            did: &DidOf<T>,
            signer_key_id: &IdStrOf<T>,
            signed_payload: &[u8],
            signature: &[u8],
        ) -> bool {
            if signature.len() != 64 {
                return false;
            }
            let Some(pubkey) = Self::authorized_alias_pubkey(rec, did, signer_key_id) else {
                return false;
            };
            ed25519::Signature::from_slice(signature)
                .and_then(|sig| ed25519::Public::from_slice(&pubkey).map(|pk| (sig, pk)))
                .is_ok_and(|(sig, pk)| ed25519_verify(&sig, signed_payload, &pk))
        }

        fn authorized_alias_pubkey(
            rec: &DidRecord<T>,
            did: &DidOf<T>,
            signer_key_id: &IdStrOf<T>,
        ) -> Option<[u8; 32]> {
            if signer_key_id.as_slice() == b"root" {
                let root = rec.root_pubkey.as_ref()?;
                return root.as_slice().try_into().ok();
            }

            let doc = rec.document.as_ref()?;
            doc.verification_method
                .iter()
                .find(|vm| {
                    vm.id.as_slice() == signer_key_id.as_slice()
                        && vm.controller.as_slice() == did.as_slice()
                })
                .and_then(|vm| decode_ed25519_public_key(vm.public_key_multibase.as_slice()))
        }

        fn apply_alias_add(checked: CheckedAliasAuthorization<T>) -> DispatchResult {
            let alias = checked.alias.ok_or(Error::<T>::InvalidAliasPayload)?;
            if let Some(existing) = AliasIndex::<T>::get(&alias) {
                ensure!(existing == checked.did, Error::<T>::AliasTaken);
                return Err(Error::<T>::AliasAlreadyExists.into());
            }

            Dids::<T>::try_mutate(&checked.did, |maybe| -> DispatchResult {
                let rec = maybe.as_mut().ok_or(Error::<T>::DidNotFound)?;
                let mut aliases = rec.aliases.take().unwrap_or_default();
                ensure!(
                    !aliases.iter().any(|existing| existing == &alias),
                    Error::<T>::AliasAlreadyExists
                );
                aliases
                    .try_push(alias.clone())
                    .map_err(|_| Error::<T>::TooManyAliases)?;
                rec.aliases = Some(aliases);
                rec.version = rec.version.saturating_add(1);
                rec.updated_at = now_millis::<T>();
                Ok(())
            })?;

            AliasIndex::<T>::insert(&alias, checked.did.clone());
            AliasNonces::<T>::insert(&checked.did, checked.nonce.saturating_add(1));
            Self::deposit_event(Event::AliasAdded(checked.did, alias));
            Ok(())
        }

        fn apply_alias_update(checked: CheckedAliasAuthorization<T>) -> DispatchResult {
            let old_alias = checked.old_alias.ok_or(Error::<T>::InvalidAliasPayload)?;
            let new_alias = checked.new_alias.ok_or(Error::<T>::InvalidAliasPayload)?;
            ensure!(old_alias != new_alias, Error::<T>::AliasAlreadyExists);
            if let Some(existing) = AliasIndex::<T>::get(&new_alias) {
                ensure!(existing == checked.did, Error::<T>::AliasTaken);
                return Err(Error::<T>::AliasAlreadyExists.into());
            }

            Dids::<T>::try_mutate(&checked.did, |maybe| -> DispatchResult {
                let rec = maybe.as_mut().ok_or(Error::<T>::DidNotFound)?;
                let mut aliases = rec.aliases.take().ok_or(Error::<T>::AliasNotFound)?;
                let pos = aliases
                    .iter()
                    .position(|alias| alias == &old_alias)
                    .ok_or(Error::<T>::AliasNotFound)?;
                aliases[pos] = new_alias.clone();
                rec.aliases = Some(aliases);
                rec.version = rec.version.saturating_add(1);
                rec.updated_at = now_millis::<T>();
                Ok(())
            })?;

            AliasIndex::<T>::remove(&old_alias);
            AliasIndex::<T>::insert(&new_alias, checked.did.clone());
            AliasNonces::<T>::insert(&checked.did, checked.nonce.saturating_add(1));
            Self::deposit_event(Event::AliasUpdated(checked.did, old_alias, new_alias));
            Ok(())
        }

        fn apply_alias_remove(checked: CheckedAliasAuthorization<T>) -> DispatchResult {
            let alias = checked.alias.ok_or(Error::<T>::InvalidAliasPayload)?;

            Dids::<T>::try_mutate(&checked.did, |maybe| -> DispatchResult {
                let rec = maybe.as_mut().ok_or(Error::<T>::DidNotFound)?;
                let mut aliases = rec.aliases.take().ok_or(Error::<T>::AliasNotFound)?;
                let pos = aliases
                    .iter()
                    .position(|existing| existing == &alias)
                    .ok_or(Error::<T>::AliasNotFound)?;
                aliases.remove(pos);
                rec.aliases = if aliases.is_empty() {
                    None
                } else {
                    Some(aliases)
                };
                rec.version = rec.version.saturating_add(1);
                rec.updated_at = now_millis::<T>();
                Ok(())
            })?;

            AliasIndex::<T>::remove(&alias);
            AliasNonces::<T>::insert(&checked.did, checked.nonce.saturating_add(1));
            Self::deposit_event(Event::AliasRemoved(checked.did, alias));
            Ok(())
        }

        fn decode_document_payload(
            signed_payload: &[u8],
        ) -> Result<DocumentAuthorizationPayload<T>, Error<T>> {
            let mut bytes = signed_payload;
            let payload = DocumentAuthorizationPayload::<T>::decode(&mut bytes)
                .map_err(|_| Error::<T>::InvalidDocumentPayload)?;
            ensure!(bytes.is_empty(), Error::<T>::InvalidDocumentPayload);
            ensure!(
                payload.encode() == signed_payload,
                Error::<T>::InvalidDocumentPayload
            );
            Ok(payload)
        }

        #[allow(clippy::too_many_arguments)]
        fn validate_document_authorization(
            action: DocumentAction,
            did: &[u8],
            verification_method: Option<&VerificationMethod<T>>,
            key_agreement: Option<&KeyAgreement<T>>,
            service: Option<&Service<T>>,
            id: Option<&IdStrOf<T>>,
            signed_payload: &[u8],
            signature: &[u8],
            signer_key_id: &[u8],
        ) -> Result<CheckedDocumentAuthorization<T>, Error<T>> {
            let did_b = DidOf::<T>::try_from(did.to_vec()).map_err(|_| Error::<T>::DidTooLong)?;
            let signer_key_id_b = IdStrOf::<T>::try_from(signer_key_id.to_vec())
                .map_err(|_| Error::<T>::InvalidDocumentPayload)?;
            let payload = Self::decode_document_payload(signed_payload)?;

            ensure!(payload.did == did_b, Error::<T>::InvalidDocumentPayload);
            ensure!(payload.action == action, Error::<T>::InvalidDocumentPayload);
            ensure!(
                payload.verification_method.as_ref() == verification_method,
                Error::<T>::InvalidDocumentPayload
            );
            ensure!(
                payload.key_agreement.as_ref() == key_agreement,
                Error::<T>::InvalidDocumentPayload
            );
            ensure!(
                payload.service.as_ref() == service,
                Error::<T>::InvalidDocumentPayload
            );
            ensure!(
                payload.id.as_ref() == id,
                Error::<T>::InvalidDocumentPayload
            );
            ensure!(
                payload.signer_key_id == signer_key_id_b,
                Error::<T>::InvalidDocumentPayload
            );
            ensure!(
                payload.valid_until > now_millis::<T>(),
                Error::<T>::DocumentAuthorizationExpired
            );

            let rec = Dids::<T>::get(&did_b).ok_or(Error::<T>::DidNotFound)?;
            Self::ensure_did_active(&rec)?;
            ensure!(
                payload.nonce == DocumentNonces::<T>::get(&did_b),
                Error::<T>::InvalidDocumentNonce
            );
            ensure!(
                Self::verify_alias_signature(
                    &rec,
                    &did_b,
                    &signer_key_id_b,
                    signed_payload,
                    signature
                ),
                Error::<T>::InvalidSignature
            );

            Ok(CheckedDocumentAuthorization {
                did: did_b,
                nonce: payload.nonce,
            })
        }

        fn empty_document(did: &DidOf<T>) -> DidDocument<T> {
            DidDocument::<T> {
                id: did.clone(),
                verification_method: Default::default(),
                authentication: None,
                key_agreement: Default::default(),
                service: None,
            }
        }

        fn validate_verification_method(
            did: &DidOf<T>,
            method: &VerificationMethod<T>,
        ) -> DispatchResult {
            ensure!(!method.id.is_empty(), Error::<T>::InvalidDocument);
            ensure!(
                method.controller.as_slice() == did.as_slice(),
                Error::<T>::InvalidDocument
            );
            ensure!(!method.type_.is_empty(), Error::<T>::InvalidDocument);
            ensure!(
                !method.public_key_multibase.is_empty(),
                Error::<T>::InvalidDocument
            );
            Ok(())
        }

        fn validate_document_structure(did: &DidOf<T>, doc: &DidDocument<T>) -> DispatchResult {
            ensure!(
                doc.id.as_slice() == did.as_slice(),
                Error::<T>::InvalidDocument
            );

            for (index, method) in doc.verification_method.iter().enumerate() {
                Self::validate_verification_method(did, method)?;
                ensure!(
                    !doc.verification_method
                        .iter()
                        .skip(index + 1)
                        .any(|other| other.id.as_slice() == method.id.as_slice()),
                    Error::<T>::VerificationMethodAlreadyExists
                );
            }

            if let Some(authentication) = doc.authentication.as_ref() {
                for (index, auth_id) in authentication.iter().enumerate() {
                    ensure!(
                        doc.verification_method
                            .iter()
                            .any(|method| method.id.as_slice() == auth_id.as_slice()),
                        Error::<T>::VerificationMethodNotFound
                    );
                    ensure!(
                        !authentication
                            .iter()
                            .skip(index + 1)
                            .any(|other| other == auth_id),
                        Error::<T>::AuthenticationAlreadyExists
                    );
                }
            }

            for (index, key_agreement) in doc.key_agreement.iter().enumerate() {
                Self::validate_key_agreement(did, key_agreement)?;
                ensure!(
                    !doc.key_agreement
                        .iter()
                        .skip(index + 1)
                        .any(|other| other.id.as_slice() == key_agreement.id.as_slice()),
                    Error::<T>::KeyAgreementAlreadyExists
                );
            }

            if let Some(services) = doc.service.as_ref() {
                for (index, service) in services.iter().enumerate() {
                    Self::validate_service(service)?;
                    ensure!(
                        !services
                            .iter()
                            .skip(index + 1)
                            .any(|other| other.id.as_slice() == service.id.as_slice()),
                        Error::<T>::ServiceAlreadyExists
                    );
                }
            }

            Ok(())
        }

        fn validate_key_agreement(
            did: &DidOf<T>,
            key_agreement: &KeyAgreement<T>,
        ) -> DispatchResult {
            ensure!(!key_agreement.id.is_empty(), Error::<T>::InvalidDocument);
            ensure!(
                key_agreement.controller.as_slice() == did.as_slice(),
                Error::<T>::InvalidDocument
            );
            ensure!(!key_agreement.type_.is_empty(), Error::<T>::InvalidDocument);
            ensure!(
                !key_agreement.public_key_multibase.is_empty(),
                Error::<T>::InvalidDocument
            );
            Ok(())
        }

        fn validate_service(service: &Service<T>) -> DispatchResult {
            ensure!(!service.id.is_empty(), Error::<T>::InvalidDocument);
            ensure!(!service.type_.is_empty(), Error::<T>::InvalidDocument);
            ensure!(
                !service.service_endpoint.is_empty(),
                Error::<T>::InvalidDocument
            );
            if let Some(authorization) = service.authorization.as_ref() {
                for key_ref in authorization.iter() {
                    ensure!(!key_ref.is_empty(), Error::<T>::InvalidDocument);
                }
            }
            Ok(())
        }

        fn bump_document_version(rec: &mut DidRecord<T>) {
            rec.version = rec.version.saturating_add(1);
            rec.updated_at = now_millis::<T>();
        }

        fn finish_document_patch(did: &DidOf<T>, nonce: u64) {
            DocumentNonces::<T>::insert(did, nonce.saturating_add(1));
        }

        fn apply_add_verification_method(
            checked: CheckedDocumentAuthorization<T>,
            method: VerificationMethod<T>,
        ) -> DispatchResult {
            Self::validate_verification_method(&checked.did, &method)?;
            let method_id = method.id.clone();
            Dids::<T>::try_mutate(&checked.did, |maybe| -> DispatchResult {
                let rec = maybe.as_mut().ok_or(Error::<T>::DidNotFound)?;
                let mut doc = rec
                    .document
                    .take()
                    .unwrap_or_else(|| Self::empty_document(&checked.did));
                ensure!(
                    !doc.verification_method
                        .iter()
                        .any(|existing| existing.id.as_slice() == method_id.as_slice()),
                    Error::<T>::VerificationMethodAlreadyExists
                );
                doc.verification_method
                    .try_push(method)
                    .map_err(|_| Error::<T>::InvalidDocument)?;
                rec.document = Some(doc);
                Self::bump_document_version(rec);
                Ok(())
            })?;
            Self::finish_document_patch(&checked.did, checked.nonce);
            Self::deposit_event(Event::VerificationMethodAdded(checked.did, method_id));
            Ok(())
        }

        fn apply_update_verification_method(
            checked: CheckedDocumentAuthorization<T>,
            method: VerificationMethod<T>,
        ) -> DispatchResult {
            Self::validate_verification_method(&checked.did, &method)?;
            let method_id = method.id.clone();
            Dids::<T>::try_mutate(&checked.did, |maybe| -> DispatchResult {
                let rec = maybe.as_mut().ok_or(Error::<T>::DidNotFound)?;
                let mut doc = rec.document.take().ok_or(Error::<T>::InvalidDocument)?;
                let pos = doc
                    .verification_method
                    .iter()
                    .position(|existing| existing.id.as_slice() == method_id.as_slice())
                    .ok_or(Error::<T>::VerificationMethodNotFound)?;
                doc.verification_method[pos] = method;
                rec.document = Some(doc);
                Self::bump_document_version(rec);
                Ok(())
            })?;
            Self::finish_document_patch(&checked.did, checked.nonce);
            Self::deposit_event(Event::VerificationMethodUpdated(checked.did, method_id));
            Ok(())
        }

        fn apply_remove_verification_method(
            checked: CheckedDocumentAuthorization<T>,
            method_id: IdStrOf<T>,
        ) -> DispatchResult {
            Dids::<T>::try_mutate(&checked.did, |maybe| -> DispatchResult {
                let rec = maybe.as_mut().ok_or(Error::<T>::DidNotFound)?;
                let mut doc = rec.document.take().ok_or(Error::<T>::InvalidDocument)?;
                if let Some(auth) = doc.authentication.as_ref() {
                    ensure!(
                        !auth.iter().any(|existing| existing == &method_id),
                        Error::<T>::VerificationMethodInUse
                    );
                }
                let pos = doc
                    .verification_method
                    .iter()
                    .position(|existing| existing.id.as_slice() == method_id.as_slice())
                    .ok_or(Error::<T>::VerificationMethodNotFound)?;
                doc.verification_method.remove(pos);
                rec.document = Some(doc);
                Self::bump_document_version(rec);
                Ok(())
            })?;
            Self::finish_document_patch(&checked.did, checked.nonce);
            Self::deposit_event(Event::VerificationMethodRemoved(checked.did, method_id));
            Ok(())
        }

        fn apply_add_authentication(
            checked: CheckedDocumentAuthorization<T>,
            method_id: IdStrOf<T>,
        ) -> DispatchResult {
            Dids::<T>::try_mutate(&checked.did, |maybe| -> DispatchResult {
                let rec = maybe.as_mut().ok_or(Error::<T>::DidNotFound)?;
                let mut doc = rec.document.take().ok_or(Error::<T>::InvalidDocument)?;
                ensure!(
                    doc.verification_method
                        .iter()
                        .any(|method| method.id.as_slice() == method_id.as_slice()),
                    Error::<T>::VerificationMethodNotFound
                );
                let mut auth = doc.authentication.take().unwrap_or_default();
                ensure!(
                    !auth.iter().any(|existing| existing == &method_id),
                    Error::<T>::AuthenticationAlreadyExists
                );
                auth.try_push(method_id.clone())
                    .map_err(|_| Error::<T>::InvalidDocument)?;
                doc.authentication = Some(auth);
                rec.document = Some(doc);
                Self::bump_document_version(rec);
                Ok(())
            })?;
            Self::finish_document_patch(&checked.did, checked.nonce);
            Self::deposit_event(Event::AuthenticationAdded(checked.did, method_id));
            Ok(())
        }

        fn apply_remove_authentication(
            checked: CheckedDocumentAuthorization<T>,
            method_id: IdStrOf<T>,
        ) -> DispatchResult {
            Dids::<T>::try_mutate(&checked.did, |maybe| -> DispatchResult {
                let rec = maybe.as_mut().ok_or(Error::<T>::DidNotFound)?;
                let mut doc = rec.document.take().ok_or(Error::<T>::InvalidDocument)?;
                let mut auth = doc
                    .authentication
                    .take()
                    .ok_or(Error::<T>::AuthenticationNotFound)?;
                let pos = auth
                    .iter()
                    .position(|existing| existing == &method_id)
                    .ok_or(Error::<T>::AuthenticationNotFound)?;
                auth.remove(pos);
                doc.authentication = if auth.is_empty() { None } else { Some(auth) };
                rec.document = Some(doc);
                Self::bump_document_version(rec);
                Ok(())
            })?;
            Self::finish_document_patch(&checked.did, checked.nonce);
            Self::deposit_event(Event::AuthenticationRemoved(checked.did, method_id));
            Ok(())
        }

        fn apply_add_key_agreement(
            checked: CheckedDocumentAuthorization<T>,
            key_agreement: KeyAgreement<T>,
        ) -> DispatchResult {
            Self::validate_key_agreement(&checked.did, &key_agreement)?;
            let key_id = key_agreement.id.clone();
            Dids::<T>::try_mutate(&checked.did, |maybe| -> DispatchResult {
                let rec = maybe.as_mut().ok_or(Error::<T>::DidNotFound)?;
                let mut doc = rec
                    .document
                    .take()
                    .unwrap_or_else(|| Self::empty_document(&checked.did));
                ensure!(
                    !doc.key_agreement
                        .iter()
                        .any(|existing| existing.id.as_slice() == key_id.as_slice()),
                    Error::<T>::KeyAgreementAlreadyExists
                );
                doc.key_agreement
                    .try_push(key_agreement)
                    .map_err(|_| Error::<T>::InvalidDocument)?;
                rec.document = Some(doc);
                Self::bump_document_version(rec);
                Ok(())
            })?;
            Self::finish_document_patch(&checked.did, checked.nonce);
            Self::deposit_event(Event::KeyAgreementAdded(checked.did, key_id));
            Ok(())
        }

        fn apply_update_key_agreement(
            checked: CheckedDocumentAuthorization<T>,
            key_agreement: KeyAgreement<T>,
        ) -> DispatchResult {
            Self::validate_key_agreement(&checked.did, &key_agreement)?;
            let key_id = key_agreement.id.clone();
            Dids::<T>::try_mutate(&checked.did, |maybe| -> DispatchResult {
                let rec = maybe.as_mut().ok_or(Error::<T>::DidNotFound)?;
                let mut doc = rec.document.take().ok_or(Error::<T>::InvalidDocument)?;
                let pos = doc
                    .key_agreement
                    .iter()
                    .position(|existing| existing.id.as_slice() == key_id.as_slice())
                    .ok_or(Error::<T>::KeyAgreementNotFound)?;
                doc.key_agreement[pos] = key_agreement;
                rec.document = Some(doc);
                Self::bump_document_version(rec);
                Ok(())
            })?;
            Self::finish_document_patch(&checked.did, checked.nonce);
            Self::deposit_event(Event::KeyAgreementUpdated(checked.did, key_id));
            Ok(())
        }

        fn apply_remove_key_agreement(
            checked: CheckedDocumentAuthorization<T>,
            key_id: IdStrOf<T>,
        ) -> DispatchResult {
            Dids::<T>::try_mutate(&checked.did, |maybe| -> DispatchResult {
                let rec = maybe.as_mut().ok_or(Error::<T>::DidNotFound)?;
                let mut doc = rec.document.take().ok_or(Error::<T>::InvalidDocument)?;
                let pos = doc
                    .key_agreement
                    .iter()
                    .position(|existing| existing.id.as_slice() == key_id.as_slice())
                    .ok_or(Error::<T>::KeyAgreementNotFound)?;
                doc.key_agreement.remove(pos);
                rec.document = Some(doc);
                Self::bump_document_version(rec);
                Ok(())
            })?;
            Self::finish_document_patch(&checked.did, checked.nonce);
            Self::deposit_event(Event::KeyAgreementRemoved(checked.did, key_id));
            Ok(())
        }

        fn apply_add_service(
            checked: CheckedDocumentAuthorization<T>,
            service: Service<T>,
        ) -> DispatchResult {
            Self::validate_service(&service)?;
            let service_id = service.id.clone();
            Dids::<T>::try_mutate(&checked.did, |maybe| -> DispatchResult {
                let rec = maybe.as_mut().ok_or(Error::<T>::DidNotFound)?;
                let mut doc = rec
                    .document
                    .take()
                    .unwrap_or_else(|| Self::empty_document(&checked.did));
                let mut services = doc.service.take().unwrap_or_default();
                ensure!(
                    !services
                        .iter()
                        .any(|existing| existing.id.as_slice() == service_id.as_slice()),
                    Error::<T>::ServiceAlreadyExists
                );
                services
                    .try_push(service)
                    .map_err(|_| Error::<T>::ServiceTooLong)?;
                doc.service = Some(services);
                rec.document = Some(doc);
                Self::bump_document_version(rec);
                Ok(())
            })?;
            Self::finish_document_patch(&checked.did, checked.nonce);
            Self::deposit_event(Event::ServiceAdded(checked.did, service_id));
            Ok(())
        }

        fn apply_update_service(
            checked: CheckedDocumentAuthorization<T>,
            service: Service<T>,
        ) -> DispatchResult {
            Self::validate_service(&service)?;
            let service_id = service.id.clone();
            Dids::<T>::try_mutate(&checked.did, |maybe| -> DispatchResult {
                let rec = maybe.as_mut().ok_or(Error::<T>::DidNotFound)?;
                let mut doc = rec.document.take().ok_or(Error::<T>::InvalidDocument)?;
                let mut services = doc.service.take().ok_or(Error::<T>::ServiceNotFound)?;
                let pos = services
                    .iter()
                    .position(|existing| existing.id.as_slice() == service_id.as_slice())
                    .ok_or(Error::<T>::ServiceNotFound)?;
                services[pos] = service;
                doc.service = Some(services);
                rec.document = Some(doc);
                Self::bump_document_version(rec);
                Ok(())
            })?;
            Self::finish_document_patch(&checked.did, checked.nonce);
            Self::deposit_event(Event::ServiceUpdated(checked.did, service_id));
            Ok(())
        }

        fn apply_remove_service(
            checked: CheckedDocumentAuthorization<T>,
            service_id: IdStrOf<T>,
        ) -> DispatchResult {
            Dids::<T>::try_mutate(&checked.did, |maybe| -> DispatchResult {
                let rec = maybe.as_mut().ok_or(Error::<T>::DidNotFound)?;
                let mut doc = rec.document.take().ok_or(Error::<T>::InvalidDocument)?;
                let mut services = doc.service.take().ok_or(Error::<T>::ServiceNotFound)?;
                let pos = services
                    .iter()
                    .position(|existing| existing.id.as_slice() == service_id.as_slice())
                    .ok_or(Error::<T>::ServiceNotFound)?;
                services.remove(pos);
                doc.service = if services.is_empty() {
                    None
                } else {
                    Some(services)
                };
                rec.document = Some(doc);
                Self::bump_document_version(rec);
                Ok(())
            })?;
            Self::finish_document_patch(&checked.did, checked.nonce);
            Self::deposit_event(Event::ServiceRemoved(checked.did, service_id));
            Ok(())
        }

        fn decode_root_pubkey_payload(
            signed_payload: &[u8],
        ) -> Result<RootPubkeyAuthorizationPayload<T>, Error<T>> {
            let mut bytes = signed_payload;
            let payload = RootPubkeyAuthorizationPayload::<T>::decode(&mut bytes)
                .map_err(|_| Error::<T>::InvalidRootPubkeyPayload)?;
            ensure!(bytes.is_empty(), Error::<T>::InvalidRootPubkeyPayload);
            ensure!(
                payload.encode() == signed_payload,
                Error::<T>::InvalidRootPubkeyPayload
            );
            Ok(payload)
        }

        fn validate_root_pubkey_authorization(
            did: &[u8],
            new_root_pubkey: &RootPubkeyOf,
            signed_payload: &[u8],
            signature: &[u8],
            signer_key_id: &[u8],
        ) -> Result<CheckedRootPubkeyAuthorization<T>, Error<T>> {
            let did_b = DidOf::<T>::try_from(did.to_vec()).map_err(|_| Error::<T>::DidTooLong)?;
            let signer_key_id_b = IdStrOf::<T>::try_from(signer_key_id.to_vec())
                .map_err(|_| Error::<T>::InvalidRootPubkeyPayload)?;
            let payload = Self::decode_root_pubkey_payload(signed_payload)?;

            ensure!(payload.did == did_b, Error::<T>::InvalidRootPubkeyPayload);
            ensure!(
                payload.new_root_pubkey.as_slice() == new_root_pubkey.as_slice(),
                Error::<T>::InvalidRootPubkeyPayload
            );
            ensure!(
                payload.signer_key_id == signer_key_id_b,
                Error::<T>::InvalidRootPubkeyPayload
            );
            ensure!(
                payload.valid_until > now_millis::<T>(),
                Error::<T>::RootPubkeyAuthorizationExpired
            );

            let rec = Dids::<T>::get(&did_b).ok_or(Error::<T>::DidNotFound)?;
            Self::ensure_did_active(&rec)?;
            ensure!(
                payload.nonce == RootPubkeyNonces::<T>::get(&did_b),
                Error::<T>::InvalidRootPubkeyNonce
            );
            ensure!(
                Self::verify_alias_signature(
                    &rec,
                    &did_b,
                    &signer_key_id_b,
                    signed_payload,
                    signature
                ),
                Error::<T>::InvalidSignature
            );

            Ok(CheckedRootPubkeyAuthorization {
                did: did_b,
                nonce: payload.nonce,
            })
        }

        fn apply_update_root_pubkey(
            checked: CheckedRootPubkeyAuthorization<T>,
            new_root_pubkey: RootPubkeyOf,
        ) -> DispatchResult {
            Dids::<T>::try_mutate(&checked.did, |maybe| -> DispatchResult {
                let rec = maybe.as_mut().ok_or(Error::<T>::DidNotFound)?;
                Self::ensure_did_active(rec)?;
                rec.root_pubkey = Some(new_root_pubkey);
                rec.version = rec.version.saturating_add(1);
                rec.updated_at = now_millis::<T>();
                Ok(())
            })?;
            RootPubkeyNonces::<T>::insert(&checked.did, checked.nonce.saturating_add(1));
            Self::deposit_event(Event::RootPubkeyUpdated(checked.did));
            Ok(())
        }

        fn decode_control_payload(
            signed_payload: &[u8],
        ) -> Result<ControlAuthorizationPayload<T>, Error<T>> {
            let mut bytes = signed_payload;
            let payload = ControlAuthorizationPayload::<T>::decode(&mut bytes)
                .map_err(|_| Error::<T>::InvalidControlPayload)?;
            ensure!(bytes.is_empty(), Error::<T>::InvalidControlPayload);
            ensure!(
                payload.encode() == signed_payload,
                Error::<T>::InvalidControlPayload
            );
            Ok(payload)
        }

        fn validate_control_authorization(
            signed_payload: &[u8],
            signature: &[u8],
            signer_key_id: &[u8],
        ) -> Result<CheckedControlAuthorization<T>, Error<T>> {
            let signer_key_id_b = IdStrOf::<T>::try_from(signer_key_id.to_vec())
                .map_err(|_| Error::<T>::InvalidControlPayload)?;
            let payload = Self::decode_control_payload(signed_payload)?;
            ensure!(
                payload.signer_key_id == signer_key_id_b,
                Error::<T>::InvalidControlPayload
            );
            ensure!(
                payload.valid_until > now_millis::<T>(),
                Error::<T>::ControlAuthorizationExpired
            );
            let rec = Dids::<T>::get(&payload.did).ok_or(Error::<T>::DidNotFound)?;
            Self::ensure_did_active(&rec)?;
            ensure!(
                payload.nonce == ControlNonces::<T>::get(&payload.did),
                Error::<T>::InvalidControlNonce
            );
            ensure!(
                Self::verify_alias_signature(
                    &rec,
                    &payload.did,
                    &signer_key_id_b,
                    signed_payload,
                    signature,
                ),
                Error::<T>::InvalidSignature
            );
            Ok(CheckedControlAuthorization {
                did: payload.did,
                action: payload.action,
                nonce: payload.nonce,
            })
        }

        fn apply_control_action(checked: CheckedControlAuthorization<T>) -> DispatchResult {
            let did = checked.did.clone();
            let deletes_did = matches!(&checked.action, ControlAction::DeleteDid);
            match checked.action {
                ControlAction::AddDevice { device_id } => {
                    Dids::<T>::try_mutate(&did, |maybe| -> DispatchResult {
                        let rec = maybe.as_mut().ok_or(Error::<T>::DidNotFound)?;
                        Self::ensure_did_active(rec)?;
                        let mut devices = rec.devices.take().unwrap_or_default();
                        if let Some(existing) = devices
                            .iter_mut()
                            .find(|device| device.device_id == device_id)
                        {
                            existing.tombstoned = false;
                        } else {
                            devices
                                .try_push(DeviceInfo {
                                    device_id: device_id.clone(),
                                    added_at: now_millis::<T>(),
                                    tombstoned: false,
                                })
                                .map_err(|_| Error::<T>::TooManyDevices)?;
                        }
                        rec.devices = Some(devices);
                        rec.version = rec.version.saturating_add(1);
                        rec.updated_at = now_millis::<T>();
                        Ok(())
                    })?;
                    Self::deposit_event(Event::DeviceAdded(did.clone(), device_id));
                }
                ControlAction::TombstoneDevice { device_id } => {
                    Dids::<T>::try_mutate(&did, |maybe| -> DispatchResult {
                        let rec = maybe.as_mut().ok_or(Error::<T>::DidNotFound)?;
                        Self::ensure_did_active(rec)?;
                        let mut devices = rec.devices.take().ok_or(Error::<T>::DeviceNotFound)?;
                        let device = devices
                            .iter_mut()
                            .find(|device| device.device_id == device_id)
                            .ok_or(Error::<T>::DeviceNotFound)?;
                        device.tombstoned = true;
                        rec.devices = Some(devices);
                        rec.version = rec.version.saturating_add(1);
                        rec.updated_at = now_millis::<T>();
                        Ok(())
                    })?;
                    Self::deposit_event(Event::DeviceTombstoned(did.clone(), device_id));
                }
                ControlAction::UpdateDevice {
                    old_device_id,
                    new_device_id,
                } => {
                    ensure!(
                        old_device_id != new_device_id,
                        Error::<T>::DeviceAlreadyExists
                    );
                    Dids::<T>::try_mutate(&did, |maybe| -> DispatchResult {
                        let rec = maybe.as_mut().ok_or(Error::<T>::DidNotFound)?;
                        Self::ensure_did_active(rec)?;
                        let mut devices = rec.devices.take().ok_or(Error::<T>::DeviceNotFound)?;
                        ensure!(
                            !devices
                                .iter()
                                .any(|device| device.device_id == new_device_id),
                            Error::<T>::DeviceAlreadyExists
                        );
                        let device = devices
                            .iter_mut()
                            .find(|device| device.device_id == old_device_id)
                            .ok_or(Error::<T>::DeviceNotFound)?;
                        device.device_id = new_device_id.clone();
                        rec.devices = Some(devices);
                        rec.version = rec.version.saturating_add(1);
                        rec.updated_at = now_millis::<T>();
                        Ok(())
                    })?;
                    Self::deposit_event(Event::DeviceUpdated(
                        did.clone(),
                        old_device_id,
                        new_device_id,
                    ));
                }
                ControlAction::RemoveDevice { device_id } => {
                    Dids::<T>::try_mutate(&did, |maybe| -> DispatchResult {
                        let rec = maybe.as_mut().ok_or(Error::<T>::DidNotFound)?;
                        Self::ensure_did_active(rec)?;
                        let mut devices = rec.devices.take().ok_or(Error::<T>::DeviceNotFound)?;
                        let position = devices
                            .iter()
                            .position(|device| device.device_id == device_id)
                            .ok_or(Error::<T>::DeviceNotFound)?;
                        devices.remove(position);
                        rec.devices = if devices.is_empty() {
                            None
                        } else {
                            Some(devices)
                        };
                        rec.version = rec.version.saturating_add(1);
                        rec.updated_at = now_millis::<T>();
                        Ok(())
                    })?;
                    Self::deposit_event(Event::DeviceRemoved(did.clone(), device_id));
                }
                ControlAction::DeactivateDid => {
                    ensure!(
                        T::RetirementGuard::can_retire(did.as_slice()),
                        Error::<T>::DidControlsApplication
                    );
                    Dids::<T>::try_mutate(&did, |maybe| -> DispatchResult {
                        let rec = maybe.as_mut().ok_or(Error::<T>::DidNotFound)?;
                        Self::ensure_did_active(rec)?;
                        rec.deactivated = true;
                        rec.version = rec.version.saturating_add(1);
                        rec.updated_at = now_millis::<T>();
                        Ok(())
                    })?;
                    Self::deposit_event(Event::DidDeactivated(did.clone()));
                }
                ControlAction::SetDeliveryPolicyLinks { links } => {
                    Dids::<T>::try_mutate(&did, |maybe| -> DispatchResult {
                        let rec = maybe.as_mut().ok_or(Error::<T>::DidNotFound)?;
                        Self::ensure_did_active(rec)?;
                        rec.delivery_policy_links = Some(links);
                        rec.version = rec.version.saturating_add(1);
                        rec.updated_at = now_millis::<T>();
                        Ok(())
                    })?;
                    Self::deposit_event(Event::DeliveryPolicyLinksSet(did.clone()));
                }
                ControlAction::ClearDeliveryPolicyLinks => {
                    Dids::<T>::try_mutate(&did, |maybe| -> DispatchResult {
                        let rec = maybe.as_mut().ok_or(Error::<T>::DidNotFound)?;
                        Self::ensure_did_active(rec)?;
                        rec.delivery_policy_links = None;
                        rec.version = rec.version.saturating_add(1);
                        rec.updated_at = now_millis::<T>();
                        Ok(())
                    })?;
                    Self::deposit_event(Event::DeliveryPolicyLinksCleared(did.clone()));
                }
                ControlAction::DeleteDid => {
                    ensure!(
                        T::RetirementGuard::can_retire(did.as_slice()),
                        Error::<T>::DidControlsApplication
                    );
                    let record = Dids::<T>::take(&did).ok_or(Error::<T>::DidNotFound)?;
                    for alias in record.aliases.unwrap_or_default() {
                        AliasIndex::<T>::remove(alias);
                    }
                    AliasNonces::<T>::remove(&did);
                    DocumentNonces::<T>::remove(&did);
                    RootPubkeyNonces::<T>::remove(&did);
                    ControlNonces::<T>::remove(&did);
                    T::PolicyCleanup::remove_for_did(did.as_slice());
                    Self::deposit_event(Event::DidDeleted(did.clone()));
                }
            }
            if !deletes_did {
                ControlNonces::<T>::insert(&did, checked.nonce.saturating_add(1));
            }
            Ok(())
        }

        fn do_register(
            owner: Option<T::AccountId>,
            did: Vec<u8>,
            alias: Option<Vec<u8>>,
            timestamp: Vec<u8>,
            pubkey: Vec<u8>,
            signature: Vec<u8>,
            doc_blob: Option<Vec<u8>>,
        ) -> DispatchResult {
            //print("do_register: A reached");

            // 1) bounds
            ensure!(
                pubkey.len() == 32 && signature.len() == 64,
                Error::<T>::InvalidSignature
            );
            let did_b = Self::validated_registration_did(did.clone())?;

            ensure!(
                !Dids::<T>::contains_key(&did_b),
                Error::<T>::DidAlreadyExists
            );
            ensure!(
                verify_did_signature(&did, &timestamp, &pubkey, &signature),
                Error::<T>::InvalidSignature
            );
            //print("do_register: after signature verify");
            // 2) verify signature and (optionally) decode document
            let mut doc_decoded: Option<DidDocument<T>> = None;
            if let Some(ref blob) = doc_blob {
                //print("do_register: cloning blob");
                let bounded: DocBlobOf<T> = blob
                    .clone()
                    .try_into()
                    .map_err(|_| Error::<T>::InvalidDocument)?;
                //print("do_register: creating document");
                let mut bytes = &bounded[..];
                let doc = DidDocument::<T>::decode(&mut bytes)
                    .map_err(|_| Error::<T>::InvalidDocument)?;
                //print("do_register: document created, comparing did");
                Self::validate_document_structure(&did_b, &doc)?;
                doc_decoded = Some(doc);
            }

            let pk_b = Self::bounded_root_pubkey(pubkey.clone())?;

            //print("do_register: after Did blob decode ");
            // 3) soft alias (warn-not-fail)
            let mut alias_b: Option<AliasOf<T>> = None;
            if let Some(a_raw) = alias {
                match Self::normalize_alias(&a_raw) {
                    Ok(a_b) => match AliasIndex::<T>::get(&a_b) {
                        Some(cur) if cur == did_b => {
                            alias_b = Some(a_b.clone());
                            Self::deposit_event(Event::AliasSet(did_b.clone(), a_b));
                        }
                        Some(_other) => {
                            Self::deposit_event(Event::AliasConflict(did_b.clone(), a_b));
                        }
                        None => {
                            AliasIndex::<T>::insert(&a_b, did_b.clone());
                            alias_b = Some(a_b.clone());
                            Self::deposit_event(Event::AliasSet(did_b.clone(), a_b));
                        }
                    },
                    Err(_) => {
                        Self::deposit_event(Event::AliasInvalid(did_b.clone()));
                    }
                }
            }
            //print("do_register: create did record");

            // 4) write
            let rec = DidRecord::<T> {
                owner: owner.clone(),
                aliases: Self::single_alias_list(alias_b)?,
                devices: None,
                document: doc_decoded,
                version: 1,
                updated_at: now_millis::<T>(),
                root_pubkey: Some(pk_b),
                delivery_policy_links: None,
                deactivated: false,
            };
            Dids::<T>::insert(&did_b, rec);
            //print("do_register: Dids insert done");
            Self::deposit_event(Event::Registered(did_b, owner));
            //print("do_register: Events deposit");
            Ok(())
        }
    }

    impl<T: Config> pallet_delivery_policy::DidProvider<T::AccountId> for Pallet<T> {
        fn did_exists(did: &[u8]) -> bool {
            let Ok(did) = DidOf::<T>::try_from(did.to_vec()) else {
                return false;
            };
            Dids::<T>::get(&did)
                .map(|record| !record.deactivated)
                .unwrap_or(false)
        }

        fn can_update_policy(who: &T::AccountId, did: &[u8]) -> bool {
            Pallet::<T>::can_update_did(who, did)
        }

        fn verify_did_signature(
            did: &[u8],
            signer_key_id: &[u8],
            signed_payload: &[u8],
            signature: &[u8],
        ) -> bool {
            let Ok(did_b) = DidOf::<T>::try_from(did.to_vec()) else {
                return false;
            };
            let Ok(signer_key_id_b) = IdStrOf::<T>::try_from(signer_key_id.to_vec()) else {
                return false;
            };
            let Some(record) = Dids::<T>::get(&did_b) else {
                return false;
            };
            !record.deactivated
                && Self::verify_alias_signature(
                    &record,
                    &did_b,
                    &signer_key_id_b,
                    signed_payload,
                    signature,
                )
        }

        fn service_supports_delivery(
            did: &[u8],
            service_id: &[u8],
            kind: pallet_delivery_policy::DeliveryServiceKind,
        ) -> bool {
            let Ok(did) = DidOf::<T>::try_from(did.to_vec()) else {
                return false;
            };
            let expected_type: &[u8] = match kind {
                pallet_delivery_policy::DeliveryServiceKind::Relay => b"OpenPayloadRelayService",
                pallet_delivery_policy::DeliveryServiceKind::Cache => b"OpenPayloadCacheService",
                pallet_delivery_policy::DeliveryServiceKind::Archive => {
                    b"OpenPayloadArchiveService"
                }
                pallet_delivery_policy::DeliveryServiceKind::ApplicationControl => {
                    b"OpenPayloadApplicationControlService"
                }
            };
            Dids::<T>::get(&did)
                .filter(|record| !record.deactivated)
                .and_then(|record| record.document)
                .and_then(|document| document.service)
                .map(|services| {
                    services.iter().any(|service| {
                        service.id.as_slice() == service_id
                            && service.type_.as_slice() == expected_type
                    })
                })
                .unwrap_or(false)
        }
    }

    fn verify_did_signature(did: &[u8], timestamp: &[u8], pubkey: &[u8], signature: &[u8]) -> bool {
        let mut payload = Vec::new();
        payload.extend_from_slice(did);
        payload.push(b'|');
        payload.extend_from_slice(timestamp);

        let sig_result = ed25519::Signature::from_slice(signature);
        let pk_result = ed25519::Public::from_slice(pubkey);

        match (sig_result, pk_result) {
            (Ok(sig), Ok(pk)) => ed25519_verify(&sig, &payload, &pk),
            _ => false,
        }
    }

    fn now_millis<T: Config>() -> u64 {
        pallet_timestamp::Pallet::<T>::get().saturated_into::<u64>()
    }

    fn decode_ed25519_public_key(encoded: &[u8]) -> Option<[u8; 32]> {
        if encoded.len() == 32 {
            return encoded.try_into().ok();
        }

        let multibase_payload = encoded.strip_prefix(b"z")?;
        let decoded = decode_base58btc(multibase_payload)?;
        match decoded.as_slice() {
            raw if raw.len() == 32 => raw.try_into().ok(),
            // Ed25519 public key multicodec prefix 0xed01, commonly encoded as base58btc.
            [0xed, 0x01, key @ ..] if key.len() == 32 => key.try_into().ok(),
            _ => None,
        }
    }

    fn decode_base58btc(input: &[u8]) -> Option<Vec<u8>> {
        let mut decoded = Vec::<u8>::new();
        for char in input {
            let mut carry = base58btc_value(*char)? as u32;
            for byte in decoded.iter_mut().rev() {
                let value = (*byte as u32) * 58 + carry;
                *byte = (value & 0xff) as u8;
                carry = value >> 8;
            }
            while carry > 0 {
                decoded.insert(0, (carry & 0xff) as u8);
                carry >>= 8;
            }
        }

        let leading_zeroes = input.iter().take_while(|byte| **byte == b'1').count();
        let mut output = Vec::with_capacity(leading_zeroes + decoded.len());
        output.resize(leading_zeroes, 0);
        output.extend_from_slice(&decoded);
        Some(output)
    }

    fn base58btc_value(char: u8) -> Option<u8> {
        const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        ALPHABET
            .iter()
            .position(|candidate| *candidate == char)
            .map(|value| value as u8)
    }

    impl<T: Config> Pallet<T> {
        fn validated_registration_did(did: Vec<u8>) -> Result<DidOf<T>, DispatchError> {
            let bounded = DidOf::<T>::try_from(did).map_err(|_| Error::<T>::DidTooLong)?;
            ensure!(
                Self::is_canonical_did(&bounded),
                Error::<T>::InvalidDidFormat
            );
            Ok(bounded)
        }

        fn is_canonical_did(did: &[u8]) -> bool {
            if did.len() > T::MaxDidLen::get() as usize || !did.starts_with(DID_PREFIX) {
                return false;
            }

            let remainder = &did[DID_PREFIX.len()..];
            let Some(separator) = remainder.iter().position(|byte| *byte == b':') else {
                return false;
            };
            let platform = &remainder[..separator];
            let address = &remainder[separator + 1..];

            if address.contains(&b':')
                || !(MIN_DID_PLATFORM_LEN..=MAX_DID_PLATFORM_LEN).contains(&platform.len())
                || !(MIN_DID_ADDRESS_LEN..=MAX_DID_ADDRESS_LEN).contains(&address.len())
            {
                return false;
            }

            platform
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
                && address.iter().all(|byte| base58btc_value(*byte).is_some())
        }

        pub(crate) fn authorize_unsigned_call(call: &Call<T>) -> TransactionValidityWithRefund {
            Self::validate_unsigned_call(call).map(|validity| (validity, Weight::zero()))
        }

        pub(crate) fn validate_unsigned_call(call: &Call<T>) -> TransactionValidity {
            match call {
                Call::register_with_proof { did, timestamp, .. } => {
                    if !Self::is_canonical_did(did) {
                        return InvalidTransaction::BadProof.into();
                    }

                    ValidTransaction::with_tag_prefix("OpenPayloadRegister")
                        .priority(1000) // Higher = more likely to be included
                        .and_provides((did.clone(), timestamp.clone())) // prevents replay
                        .longevity(64) // how long this tx is valid (in blocks)
                        .propagate(true)
                        .build()
                }
                Call::set_document_with_proof {
                    did,
                    timestamp,
                    doc_blob,
                    ..
                } => {
                    if did.is_empty() || did.len() > T::MaxDidLen::get() as usize {
                        return InvalidTransaction::BadProof.into();
                    }
                    // small DoS guard: reject absurd docs early in the pool if you want
                    if doc_blob.len() as u32 > T::MaxDocLen::get() {
                        return InvalidTransaction::ExhaustsResources.into();
                    }
                    ValidTransaction::with_tag_prefix("OpenPayload")
                        .priority(900)
                        .and_provides((b"setdoc", did.clone(), timestamp.clone()))
                        .longevity(64)
                        .propagate(true)
                        .build()
                }
                Call::register_with_document_proof {
                    did,
                    timestamp,
                    doc_blob,
                    ..
                } => {
                    if !Self::is_canonical_did(did) {
                        return InvalidTransaction::BadProof.into();
                    }
                    if (doc_blob.len() as u32) > T::MaxDocLen::get() {
                        return InvalidTransaction::ExhaustsResources.into();
                    }
                    ValidTransaction::with_tag_prefix("OpenPayload")
                        .priority(1000)
                        // prevent exact duplicate in mempool
                        .and_provides((b"regdoc", did.clone(), timestamp.clone()))
                        .longevity(64)
                        .propagate(true)
                        .build()
                }
                Call::add_alias {
                    did,
                    alias,
                    signed_payload,
                    signature,
                    signer_key_id,
                } => Self::validate_unsigned_alias(
                    AliasAction::Add,
                    did,
                    Some(alias),
                    None,
                    None,
                    signed_payload,
                    signature,
                    signer_key_id,
                ),
                Call::update_alias {
                    did,
                    old_alias,
                    new_alias,
                    signed_payload,
                    signature,
                    signer_key_id,
                } => Self::validate_unsigned_alias(
                    AliasAction::Update,
                    did,
                    None,
                    Some(old_alias),
                    Some(new_alias),
                    signed_payload,
                    signature,
                    signer_key_id,
                ),
                Call::remove_alias {
                    did,
                    alias,
                    signed_payload,
                    signature,
                    signer_key_id,
                } => Self::validate_unsigned_alias(
                    AliasAction::Remove,
                    did,
                    Some(alias),
                    None,
                    None,
                    signed_payload,
                    signature,
                    signer_key_id,
                ),
                Call::add_verification_method {
                    did,
                    method,
                    signed_payload,
                    signature,
                    signer_key_id,
                } => Self::validate_unsigned_document(
                    DocumentAction::AddVerificationMethod,
                    did,
                    Some(method),
                    None,
                    None,
                    None,
                    signed_payload,
                    signature,
                    signer_key_id,
                ),
                Call::update_verification_method {
                    did,
                    method,
                    signed_payload,
                    signature,
                    signer_key_id,
                } => Self::validate_unsigned_document(
                    DocumentAction::UpdateVerificationMethod,
                    did,
                    Some(method),
                    None,
                    None,
                    None,
                    signed_payload,
                    signature,
                    signer_key_id,
                ),
                Call::remove_verification_method {
                    did,
                    method_id,
                    signed_payload,
                    signature,
                    signer_key_id,
                } => {
                    let Ok(id_b) = IdStrOf::<T>::try_from(method_id.clone()) else {
                        return InvalidTransaction::BadProof.into();
                    };
                    Self::validate_unsigned_document(
                        DocumentAction::RemoveVerificationMethod,
                        did,
                        None,
                        None,
                        None,
                        Some(&id_b),
                        signed_payload,
                        signature,
                        signer_key_id,
                    )
                }
                Call::add_authentication {
                    did,
                    method_id,
                    signed_payload,
                    signature,
                    signer_key_id,
                } => {
                    let Ok(id_b) = IdStrOf::<T>::try_from(method_id.clone()) else {
                        return InvalidTransaction::BadProof.into();
                    };
                    Self::validate_unsigned_document(
                        DocumentAction::AddAuthentication,
                        did,
                        None,
                        None,
                        None,
                        Some(&id_b),
                        signed_payload,
                        signature,
                        signer_key_id,
                    )
                }
                Call::remove_authentication {
                    did,
                    method_id,
                    signed_payload,
                    signature,
                    signer_key_id,
                } => {
                    let Ok(id_b) = IdStrOf::<T>::try_from(method_id.clone()) else {
                        return InvalidTransaction::BadProof.into();
                    };
                    Self::validate_unsigned_document(
                        DocumentAction::RemoveAuthentication,
                        did,
                        None,
                        None,
                        None,
                        Some(&id_b),
                        signed_payload,
                        signature,
                        signer_key_id,
                    )
                }
                Call::add_key_agreement {
                    did,
                    key_agreement,
                    signed_payload,
                    signature,
                    signer_key_id,
                } => Self::validate_unsigned_document(
                    DocumentAction::AddKeyAgreement,
                    did,
                    None,
                    Some(key_agreement),
                    None,
                    None,
                    signed_payload,
                    signature,
                    signer_key_id,
                ),
                Call::update_key_agreement {
                    did,
                    key_agreement,
                    signed_payload,
                    signature,
                    signer_key_id,
                } => Self::validate_unsigned_document(
                    DocumentAction::UpdateKeyAgreement,
                    did,
                    None,
                    Some(key_agreement),
                    None,
                    None,
                    signed_payload,
                    signature,
                    signer_key_id,
                ),
                Call::remove_key_agreement {
                    did,
                    key_agreement_id,
                    signed_payload,
                    signature,
                    signer_key_id,
                } => {
                    let Ok(id_b) = IdStrOf::<T>::try_from(key_agreement_id.clone()) else {
                        return InvalidTransaction::BadProof.into();
                    };
                    Self::validate_unsigned_document(
                        DocumentAction::RemoveKeyAgreement,
                        did,
                        None,
                        None,
                        None,
                        Some(&id_b),
                        signed_payload,
                        signature,
                        signer_key_id,
                    )
                }
                Call::add_service {
                    did,
                    service,
                    signed_payload,
                    signature,
                    signer_key_id,
                } => Self::validate_unsigned_document(
                    DocumentAction::AddService,
                    did,
                    None,
                    None,
                    Some(service),
                    None,
                    signed_payload,
                    signature,
                    signer_key_id,
                ),
                Call::update_service {
                    did,
                    service,
                    signed_payload,
                    signature,
                    signer_key_id,
                } => Self::validate_unsigned_document(
                    DocumentAction::UpdateService,
                    did,
                    None,
                    None,
                    Some(service),
                    None,
                    signed_payload,
                    signature,
                    signer_key_id,
                ),
                Call::remove_service {
                    did,
                    service_id,
                    signed_payload,
                    signature,
                    signer_key_id,
                } => {
                    let Ok(id_b) = IdStrOf::<T>::try_from(service_id.clone()) else {
                        return InvalidTransaction::BadProof.into();
                    };
                    Self::validate_unsigned_document(
                        DocumentAction::RemoveService,
                        did,
                        None,
                        None,
                        None,
                        Some(&id_b),
                        signed_payload,
                        signature,
                        signer_key_id,
                    )
                }
                Call::update_root_pubkey {
                    did,
                    new_root_pubkey,
                    signed_payload,
                    signature,
                    signer_key_id,
                } => {
                    if new_root_pubkey.len() != 32 {
                        return InvalidTransaction::BadProof.into();
                    }
                    let Ok(new_root_pubkey_b) = RootPubkeyOf::try_from(new_root_pubkey.clone())
                    else {
                        return InvalidTransaction::BadProof.into();
                    };
                    Self::validate_unsigned_root_pubkey(
                        did,
                        &new_root_pubkey_b,
                        signed_payload,
                        signature,
                        signer_key_id,
                    )
                }
                Call::apply_control_with_proof {
                    signed_payload,
                    signature,
                    signer_key_id,
                } => {
                    let checked = match Self::validate_control_authorization(
                        signed_payload,
                        signature,
                        signer_key_id,
                    ) {
                        Ok(checked) => checked,
                        Err(_) => return InvalidTransaction::BadProof.into(),
                    };
                    ValidTransaction::with_tag_prefix("OpenPayloadControl")
                        .priority(900)
                        .and_provides((checked.did, checked.nonce))
                        .longevity(64)
                        .propagate(true)
                        .build()
                }
                _ => InvalidTransaction::Call.into(),
            }
        }

        #[allow(clippy::too_many_arguments)]
        fn validate_unsigned_alias(
            action: AliasAction,
            did: &[u8],
            alias: Option<&Vec<u8>>,
            old_alias: Option<&Vec<u8>>,
            new_alias: Option<&Vec<u8>>,
            signed_payload: &[u8],
            signature: &[u8],
            signer_key_id: &[u8],
        ) -> TransactionValidity {
            let checked = match Self::validate_alias_authorization(
                action,
                did,
                alias.map(Vec::as_slice),
                old_alias.map(Vec::as_slice),
                new_alias.map(Vec::as_slice),
                signed_payload,
                signature,
                signer_key_id,
            ) {
                Ok(checked) => checked,
                Err(_) => return InvalidTransaction::BadProof.into(),
            };

            ValidTransaction::with_tag_prefix("OpenPayloadAlias")
                .priority(950)
                .and_provides((checked.did, checked.nonce, action))
                .longevity(64)
                .propagate(true)
                .build()
        }

        #[allow(clippy::too_many_arguments)]
        fn validate_unsigned_document(
            action: DocumentAction,
            did: &[u8],
            verification_method: Option<&VerificationMethod<T>>,
            key_agreement: Option<&KeyAgreement<T>>,
            service: Option<&Service<T>>,
            id: Option<&IdStrOf<T>>,
            signed_payload: &[u8],
            signature: &[u8],
            signer_key_id: &[u8],
        ) -> TransactionValidity {
            let checked = match Self::validate_document_authorization(
                action,
                did,
                verification_method,
                key_agreement,
                service,
                id,
                signed_payload,
                signature,
                signer_key_id,
            ) {
                Ok(checked) => checked,
                Err(_) => return InvalidTransaction::BadProof.into(),
            };

            ValidTransaction::with_tag_prefix("OpenPayloadDocument")
                .priority(940)
                .and_provides((checked.did, checked.nonce, action))
                .longevity(64)
                .propagate(true)
                .build()
        }

        fn validate_unsigned_root_pubkey(
            did: &[u8],
            new_root_pubkey: &RootPubkeyOf,
            signed_payload: &[u8],
            signature: &[u8],
            signer_key_id: &[u8],
        ) -> TransactionValidity {
            let checked = match Self::validate_root_pubkey_authorization(
                did,
                new_root_pubkey,
                signed_payload,
                signature,
                signer_key_id,
            ) {
                Ok(checked) => checked,
                Err(_) => return InvalidTransaction::BadProof.into(),
            };

            ValidTransaction::with_tag_prefix("OpenPayloadRootPubkey")
                .priority(960)
                .and_provides((checked.did, checked.nonce, b"root-pubkey"))
                .longevity(64)
                .propagate(true)
                .build()
        }
    }

    struct CheckedAliasAuthorization<T: Config> {
        did: DidOf<T>,
        alias: Option<AliasOf<T>>,
        old_alias: Option<AliasOf<T>>,
        new_alias: Option<AliasOf<T>>,
        nonce: u64,
    }

    struct CheckedDocumentAuthorization<T: Config> {
        did: DidOf<T>,
        nonce: u64,
    }

    struct CheckedRootPubkeyAuthorization<T: Config> {
        did: DidOf<T>,
        nonce: u64,
    }

    struct CheckedControlAuthorization<T: Config> {
        did: DidOf<T>,
        action: ControlAction<T>,
        nonce: u64,
    }

    fn trim_ascii_whitespace(raw: &[u8]) -> &[u8] {
        let start = raw
            .iter()
            .position(|byte| !byte.is_ascii_whitespace())
            .unwrap_or(raw.len());
        let end = raw
            .iter()
            .rposition(|byte| !byte.is_ascii_whitespace())
            .map(|pos| pos + 1)
            .unwrap_or(start);
        &raw[start..end]
    }
}
