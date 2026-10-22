#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));

pub mod apis;
#[cfg(feature = "runtime-benchmarks")]
mod benchmarks;
pub mod configs;

extern crate alloc;
use alloc::vec::Vec;
use sp_runtime::{
    generic, impl_opaque_keys,
    traits::{BlakeTwo256, IdentifyAccount, Verify},
    MultiAddress, MultiSignature,
};
#[cfg(feature = "std")]
use sp_version::NativeVersion;
use sp_version::RuntimeVersion;

pub use frame_system::Call as SystemCall;
pub use pallet_balances::Call as BalancesCall;
pub use pallet_timestamp::Call as TimestampCall;
#[cfg(any(feature = "std", test))]
pub use sp_runtime::BuildStorage;

/// Generic Substrate SS58 address format used by the runtime and chain specs.
pub const SS58_PREFIX: u16 = 42;

pub mod genesis_config_presets;

/// Opaque types. These are used by the CLI to instantiate machinery that don't need to know
/// the specifics of the runtime. They can then be made to be agnostic over specific formats
/// of data like extrinsics, allowing for them to continue syncing the network through upgrades
/// to even the core data structures.
pub mod opaque {
    use super::*;
    use sp_runtime::{
        generic,
        traits::{BlakeTwo256, Hash as HashT},
    };

    pub use sp_runtime::OpaqueExtrinsic as UncheckedExtrinsic;

    /// Opaque block header type.
    pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
    /// Opaque block type.
    pub type Block = generic::Block<Header, UncheckedExtrinsic>;
    /// Opaque block identifier type.
    pub type BlockId = generic::BlockId<Block>;
    /// Opaque block hash type.
    pub type Hash = <BlakeTwo256 as HashT>::Output;
}

impl_opaque_keys! {
    pub struct SessionKeys {
        pub aura: Aura,
        pub grandpa: Grandpa,
    }
}

// To learn more about runtime versioning, see:
// https://docs.substrate.io/main-docs/build/upgrade#runtime-versioning
#[sp_version::runtime_version]
pub const VERSION: RuntimeVersion = RuntimeVersion {
    spec_name: alloc::borrow::Cow::Borrowed("openpayload"),
    impl_name: alloc::borrow::Cow::Borrowed("openpayload-runtime"),
    authoring_version: 1,
    // The version of the runtime specification. A full node will not attempt to use its native
    //   runtime in substitute for the on-chain Wasm runtime unless all of `spec_name`,
    //   `spec_version`, and `authoring_version` are the same between Wasm and native.
    // This value is set to 100 to notify Polkadot-JS App (https://polkadot.js.org/apps) to use
    //   the compatible custom types.
    spec_version: 130,
    impl_version: 1,
    apis: apis::RUNTIME_API_VERSIONS,
    transaction_version: 6,
    system_version: 1,
};

mod block_times {
    /// This determines the average expected block time that we are targeting. Blocks will be
    /// produced at a minimum duration defined by `SLOT_DURATION`. `SLOT_DURATION` is picked up by
    /// `pallet_timestamp` which is in turn picked up by `pallet_aura` to implement `fn
    /// slot_duration()`.
    ///
    /// Change this to adjust the block time.
    pub const MILLI_SECS_PER_BLOCK: u64 = 6000;

    // NOTE: Currently it is not possible to change the slot duration after the chain has started.
    // Attempting to do so will brick block production.
    pub const SLOT_DURATION: u64 = MILLI_SECS_PER_BLOCK;
}
pub use block_times::*;

// Time is measured by number of blocks.
pub const MINUTES: BlockNumber = 60_000 / (MILLI_SECS_PER_BLOCK as BlockNumber);
pub const HOURS: BlockNumber = MINUTES * 60;
pub const DAYS: BlockNumber = HOURS * 24;
pub const CACHE_REWARD_HISTORY_RETENTION_EPOCHS: u64 = 720;

pub const BLOCK_HASH_COUNT: BlockNumber = 2400;

// Unit = the base number of indivisible units for balances
pub const UNIT: Balance = 1_000_000_000_000;
pub const MILLI_UNIT: Balance = 1_000_000_000;
pub const MICRO_UNIT: Balance = 1_000_000;

/// Existential deposit.
pub const EXISTENTIAL_DEPOSIT: Balance = MILLI_UNIT;

/// The version information used to identify this runtime when compiled natively.
#[cfg(feature = "std")]
pub fn native_version() -> NativeVersion {
    NativeVersion {
        runtime_version: VERSION,
        can_author_with: Default::default(),
    }
}

/// Alias to 512-bit hash when used in the context of a transaction signature on the chain.
pub type Signature = MultiSignature;

/// Some way of identifying an account on the chain. We intentionally make it equivalent
/// to the public key of our transaction signing scheme.
pub type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;

/// Balance of an account.
pub type Balance = u128;

/// Index of a transaction in the chain.
pub type Nonce = u32;

/// A hash of some data used by the chain.
pub type Hash = sp_core::H256;

/// An index to a block.
pub type BlockNumber = u32;

/// The address format for describing accounts.
pub type Address = MultiAddress<AccountId, ()>;

/// Block header type as expected by this runtime.
pub type Header = generic::Header<BlockNumber, BlakeTwo256>;

/// Block type as expected by this runtime.
pub type Block = generic::Block<Header, UncheckedExtrinsic>;

/// A Block signed with a Justification
pub type SignedBlock = generic::SignedBlock<Block>;

/// BlockId type as expected by this runtime.
pub type BlockId = generic::BlockId<Block>;

/// The `TransactionExtension` to the basic transaction logic.
pub type TxExtension = (
    frame_system::AuthorizeCall<Runtime>,
    frame_system::CheckNonZeroSender<Runtime>,
    frame_system::CheckSpecVersion<Runtime>,
    frame_system::CheckTxVersion<Runtime>,
    frame_system::CheckGenesis<Runtime>,
    frame_system::CheckEra<Runtime>,
    frame_system::CheckNonce<Runtime>,
    frame_system::CheckWeight<Runtime>,
    pallet_transaction_payment::ChargeTransactionPayment<Runtime>,
    frame_metadata_hash_extension::CheckMetadataHash<Runtime>,
    frame_system::WeightReclaim<Runtime>,
);

/// Unchecked extrinsic type as expected by this runtime.
pub type UncheckedExtrinsic =
    generic::UncheckedExtrinsic<Address, RuntimeCall, Signature, TxExtension>;

/// The payload being signed in transactions.
pub type SignedPayload = generic::SignedPayload<RuntimeCall, TxExtension>;

/// All migrations of the runtime, aside from the ones declared in the pallets.
///
/// This can be a tuple of types, each implementing `OnRuntimeUpgrade`.
#[allow(unused_parens)]
type Migrations = ();

/// Executive: handles dispatch to the various modules.
pub type Executive = frame_executive::Executive<
    Runtime,
    Block,
    frame_system::ChainContext<Runtime>,
    Runtime,
    AllPalletsWithSystem,
    Migrations,
>;

// Create the runtime by composing the FRAME pallets that were previously configured.
#[frame_support::runtime]
mod runtime {
    #[runtime::runtime]
    #[runtime::derive(
        RuntimeCall,
        RuntimeEvent,
        RuntimeError,
        RuntimeOrigin,
        RuntimeFreezeReason,
        RuntimeHoldReason,
        RuntimeSlashReason,
        RuntimeLockId,
        RuntimeTask,
        RuntimeViewFunction
    )]
    pub struct Runtime;

    #[runtime::pallet_index(0)]
    pub type System = frame_system;

    #[runtime::pallet_index(1)]
    pub type Timestamp = pallet_timestamp;

    #[runtime::pallet_index(2)]
    pub type Aura = pallet_aura;

    #[runtime::pallet_index(3)]
    pub type Grandpa = pallet_grandpa;

    #[runtime::pallet_index(4)]
    pub type Balances = pallet_balances;

    #[runtime::pallet_index(5)]
    pub type TransactionPayment = pallet_transaction_payment;

    #[runtime::pallet_index(6)]
    pub type Sudo = pallet_sudo;

    // Keep index 7 intentionally unused. Earlier clients encoded DID registry
    // calls at index 8, and compacting the pallet indexes after removing the
    // template pallet breaks those extrinsics at transaction validation time.
    #[runtime::pallet_index(8)]
    pub type DidRegistry = pallet_did_registry;

    #[runtime::pallet_index(9)]
    pub type DeliveryPolicy = pallet_delivery_policy;

    #[runtime::pallet_index(10)]
    pub type Opal = pallet_opal;

    #[runtime::pallet_index(11)]
    pub type ResourceRewards = pallet_resource_rewards;

    // Consensus membership is managed separately from resource validators.
    // Keep existing pallet indexes stable and append governance at index 12.
    #[runtime::pallet_index(12)]
    pub type AuthorityGovernance = pallet_authority_governance;

    #[runtime::pallet_index(13)]
    pub type ApplicationRegistry = pallet_application_registry;
}

// runtime/src/lib.rs

use frame_support::{
    pallet_prelude::ConstU32,
    parameter_types,
    traits::{ConstU128, ConstU64, ConstU8},
    PalletId,
};

parameter_types! {
    pub const ResourceRewardPalletId: PalletId = PalletId(*b"op/rewar");
}
impl pallet_authority_governance::Config for Runtime {
    type AuthorityOrigin = frame_system::EnsureRoot<AccountId>;
    type MinAuthorities = ConstU32<4>;
    type MaxAuthorities = ConstU32<32>;
    type MinAuthorityChangeDelay = ConstU32<{ MINUTES * 10 }>;
}

impl pallet_application_registry::Config for Runtime {
    #[cfg(feature = "runtime-benchmarks")]
    type BenchmarkHelper = ResourceRewardsBenchmarkHelper;
    type DidProvider = DidRegistry;
    type DomainProvider = RuntimeApplicationDomainProvider;
    type PolicyCleanup = RuntimeApplicationPolicyCleanup;
    type GovernanceOrigin = frame_system::EnsureRoot<AccountId>;
    type WeightInfo = pallet_application_registry::weights::SubstrateWeight<Runtime>;
    type MaxApplicationIdLen = ConstU32<64>;
    type MaxDidLen = ConstU32<128>;
    type MaxKeyIdLen = ConstU32<96>;
    type MaxSignatureLen = ConstU32<128>;
    type MaxApplicationsPerControlDid = ConstU32<16>;
    type MaxPolicyDocumentLen = ConstU32<4096>;
    type MaxPolicyTtlSeconds = ConstU32<300>;
    type MaxDomainLen = ConstU32<253>;
    type MaxLinkedDids = ConstU32<16>;
}

pub struct RuntimeApplicationDomainProvider;

impl pallet_application_registry::DomainProvider for RuntimeApplicationDomainProvider {
    fn controlled_domain(domain: &[u8], control_did: &[u8]) -> bool {
        let Ok(name) = pallet_delivery_policy::PersonaOf::<Runtime>::try_from(domain.to_vec())
        else {
            return false;
        };
        pallet_delivery_policy::Personas::<Runtime>::get(name).is_some_and(|record| {
            record.active
                && record.operator_did.as_slice() == control_did
                && record.verification_expires_at > Timestamp::get()
        })
    }
}

pub struct RuntimeApplicationPolicyCleanup;

impl pallet_application_registry::ApplicationPolicyCleanup for RuntimeApplicationPolicyCleanup {
    fn clear(application_id: &[u8]) {
        let Ok(id) = pallet_delivery_policy::ApplicationIdOf::try_from(application_id.to_vec())
        else {
            return;
        };
        let scope = pallet_delivery_policy::PolicyScopeV3::Application(id);
        DeliveryPolicy::invalidate_policy_document(&scope);
        pallet_delivery_policy::PoliciesV3::<Runtime>::remove(scope);
    }
}

pub struct ApplicationControlDidGuard;

impl pallet_did_registry::DidRetirementGuard for ApplicationControlDidGuard {
    fn can_retire(did: &[u8]) -> bool {
        let Ok(did) = pallet_application_registry::DidOf::<Runtime>::try_from(did.to_vec()) else {
            return false;
        };
        pallet_application_registry::ApplicationsByControlDid::<Runtime>::get(did).is_empty()
    }
}

impl pallet_did_registry::Config for Runtime {
    #[cfg(feature = "runtime-benchmarks")]
    type BenchmarkHelper = ResourceRewardsBenchmarkHelper;
    type PolicyCleanup = DeliveryPolicy;
    type RetirementGuard = ApplicationControlDidGuard;
    type MaxDidLen = ConstU32<128>;
    type MaxLegacyDevices = ConstU32<10>;
    type MaxAliasLen = ConstU32<64>;
    type MaxAliases = ConstU32<8>;
    type MaxContexts = ConstU32<4>;
    type MaxContextLen = ConstU32<64>;
    type MaxIdLen = ConstU32<64>;
    type MaxControllerRefs = ConstU32<4>;
    type MaxControllerLen = ConstU32<64>;
    type MaxVMs = ConstU32<5>;
    type MaxKAs = ConstU32<64>;
    type MaxVMTypeLen = ConstU32<64>;
    type MaxKeyMultibaseLen = ConstU32<4096>;
    type MaxRefsPerRel = ConstU32<4>;
    type MaxServices = ConstU32<4>;
    type MaxServiceAuthorizationKeys = ConstU32<8>;
    type MaxServiceTypeLen = ConstU32<64>;
    type MaxServiceEndpointLen = ConstU32<128>;
    type MaxServiceEndpointUrlLen = ConstU32<4096>;
    type MaxDocLen = ConstU32<327680>;
    type MaxKaTypeLen = ConstU32<64>;
    type MaxServiceEndpoints = ConstU32<5>;
    type MaxPolicyRefs = ConstU32<8>;
    type MaxPolicyRefLen = ConstU32<128>;
}

impl pallet_delivery_policy::Config for Runtime {
    type MaxPolicyDocumentBytes = frame_support::traits::ConstU32<65536>;
    #[cfg(feature = "runtime-benchmarks")]
    type BenchmarkHelper = ResourceRewardsBenchmarkHelper;
    type Balance = Balance;
    type DidProvider = DidRegistry;
    type ApplicationProvider = RuntimeApplicationProvider;
    type DnssecTrustAnchorOrigin = frame_system::EnsureRoot<AccountId>;
    type WeightInfo = pallet_delivery_policy::weights::SubstrateWeight<Runtime>;
    type MaxDidLen = ConstU32<128>;
    type MaxTtl = ConstU32<{ 30 * DAYS }>;
    type MaxMessageBytes = ConstU32<{ 16 * 1024 * 1024 }>;
    type MaxReplication = ConstU8<4>;
    type MaxHeaderPreviewBytes = ConstU32<4096>;
    type MaxReleaseFee = ConstU128<{ 1_000 * UNIT }>;
    type MaxPersonaLen = ConstU32<253>;
    type MaxPersonaControllerKeys = ConstU32<8>;
    type MaxPolicyIdLen = ConstU32<32>;
    type MaxPolicyRules = ConstU32<32>;
    type MaxRuleIdLen = ConstU32<64>;
    type MaxRuleConditions = ConstU32<8>;
    type MaxConditionRecipients = ConstU32<16>;
    type MaxTagLen = ConstU32<96>;
    type MaxServiceRefLen = ConstU32<128>;
    type MaxRouteTargets = ConstU32<16>;
    type MaxDeliverySteps = ConstU32<32>;
    type MaxDeliveryTransitions = ConstU32<64>;
    type MaxPolicyValidationUnits = ConstU32<4096>;
    type MaxTtlSeconds = ConstU32<172_800>;
    type MaxPolicyTtlSeconds = ConstU32<300>;
    type MaxHttpEnvelopeBytes = ConstU32<{ 25 * 1024 * 1024 }>;
    type MaxUnchunkedMessageBytes = ConstU32<{ 16 * 1024 * 1024 }>;
    type MaxChunkBytes = ConstU32<{ 2 * 1024 * 1024 }>;
    type MaxReplicas = ConstU8<4>;
}

pub struct RuntimeApplicationProvider;

impl pallet_delivery_policy::ApplicationProvider for RuntimeApplicationProvider {
    fn active_control_did(application_id: &[u8]) -> Option<Vec<u8>> {
        let id = pallet_application_registry::ApplicationIdOf::<Runtime>::try_from(
            application_id.to_vec(),
        )
        .ok()?;
        let record = pallet_application_registry::Applications::<Runtime>::get(id)?;
        if record.status != pallet_application_registry::ApplicationStatus::Active
            || !<DidRegistry as pallet_delivery_policy::DidProvider<AccountId>>::did_exists(
                record.control_did.as_slice(),
            )
        {
            return None;
        }
        Some(record.control_did.into_inner())
    }

    fn verified_domain(application_id: &[u8]) -> Option<Vec<u8>> {
        use pallet_application_registry::DomainProvider as _;
        let id = pallet_application_registry::ApplicationIdOf::<Runtime>::try_from(
            application_id.to_vec(),
        )
        .ok()?;
        let record = pallet_application_registry::Applications::<Runtime>::get(&id)?;
        if record.status != pallet_application_registry::ApplicationStatus::Active
            || !<DidRegistry as pallet_delivery_policy::DidProvider<AccountId>>::did_exists(
                record.control_did.as_slice(),
            )
        {
            return None;
        }
        let domain = pallet_application_registry::ApplicationDomains::<Runtime>::get(id)?;
        RuntimeApplicationDomainProvider::controlled_domain(
            domain.as_slice(),
            record.control_did.as_slice(),
        )
        .then(|| domain.into_inner())
    }

    fn authorized_send_target(application_id: &[u8], target: &[u8]) -> bool {
        let Some(control) = Self::active_control_did(application_id) else {
            return false;
        };
        if control.as_slice() == target {
            return true;
        }
        let Ok(id) = pallet_application_registry::ApplicationIdOf::<Runtime>::try_from(
            application_id.to_vec(),
        ) else {
            return false;
        };
        let Ok(did) = pallet_application_registry::DidOf::<Runtime>::try_from(target.to_vec())
        else {
            return false;
        };
        pallet_application_registry::ApplicationLinkedDids::<Runtime>::get(id).contains(&did)
            && <DidRegistry as pallet_delivery_policy::DidProvider<AccountId>>::did_exists(target)
    }
}

impl pallet_opal::Config for Runtime {
    type Balance = Balance;
    type Currency = Balances;
    type TokenGovernanceOrigin = frame_system::EnsureRoot<AccountId>;
    type MaxAccountingRefLen = ConstU32<128>;
}

#[cfg(feature = "runtime-benchmarks")]
pub struct ResourceRewardsBenchmarkHelper;

#[cfg(feature = "runtime-benchmarks")]
impl ResourceRewardsBenchmarkHelper {
    const KEY_TYPE: sp_core::crypto::KeyTypeId = sp_core::crypto::KeyTypeId(*b"opbm");

    fn key_seed(seed: u32) -> Vec<u8> {
        alloc::format!("//OpenPayloadBenchmark//{seed}").into_bytes()
    }

    fn public(seed: u32) -> sp_core::ed25519::Public {
        sp_io::crypto::ed25519_generate(Self::KEY_TYPE, Some(Self::key_seed(seed)))
    }
}

#[cfg(feature = "runtime-benchmarks")]
impl pallet_resource_rewards::BenchmarkHelper<AccountId> for ResourceRewardsBenchmarkHelper {
    fn install_did(account: &AccountId, did: &[u8], seed: u32) {
        let public = Self::public(seed);
        let did = pallet_did_registry::DidOf::<Runtime>::try_from(did.to_vec())
            .expect("benchmark DID fits the runtime bound");
        pallet_did_registry::Dids::<Runtime>::insert(
            did,
            pallet_did_registry::DidRecord::<Runtime> {
                owner: Some(account.clone()),
                aliases: None,
                devices: None,
                document: None,
                version: 1,
                updated_at: 0,
                root_pubkey: Some(
                    sp_core::ByteArray::to_raw_vec(&public)
                        .try_into()
                        .expect("ed25519 public key has the required length"),
                ),
                delivery_policy_links: None,
                deactivated: false,
            },
        );
    }

    fn sign(seed: u32, payload: &[u8]) -> Vec<u8> {
        sp_core::ByteArray::to_raw_vec(
            &sp_io::crypto::ed25519_sign(Self::KEY_TYPE, &Self::public(seed), payload)
                .expect("benchmark key was installed in the host keystore"),
        )
    }
}

#[cfg(feature = "runtime-benchmarks")]
impl pallet_did_registry::BenchmarkHelper for ResourceRewardsBenchmarkHelper {
    fn install_policy(did: &[u8]) {
        seed_benchmark_policy(pallet_delivery_policy::PolicyScopeV3::Did(did.to_vec().try_into().unwrap()),did);
    }
    fn public() -> Vec<u8> {
        sp_core::ByteArray::to_raw_vec(&Self::public(125))
    }
    fn sign(payload: &[u8]) -> Vec<u8> {
        <Self as pallet_resource_rewards::BenchmarkHelper<AccountId>>::sign(125, payload)
    }
}

#[cfg(feature = "runtime-benchmarks")]
impl pallet_application_registry::BenchmarkHelper for ResourceRewardsBenchmarkHelper {
    fn install_policy(application: &[u8], did: &[u8]) {
        seed_benchmark_policy(pallet_delivery_policy::PolicyScopeV3::Application(application.to_vec().try_into().unwrap()),did);
    }
    fn install_did(did: &[u8], seed: u32) {
        use frame_support::BoundedVec;
        use alloc::{format, vec};
        let account = AccountId::new([0; 32]);
        <Self as pallet_resource_rewards::BenchmarkHelper<AccountId>>::install_did(&account, did, seed);
        let public = Self::public(seed);
        let mut digits = Vec::<u8>::new();
        const BASE58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        for byte in public.0 {
            let mut carry = byte as u32;
            for digit in &mut digits { carry += *digit as u32 * 256; *digit = (carry % 58) as u8; carry /= 58; }
            while carry != 0 { digits.push((carry % 58) as u8); carry /= 58; }
        }
        let mut material = vec![b'z'];
        material.extend(core::iter::repeat_n(b'1', public.0.iter().take_while(|b| **b == 0).count()));
        material.extend(digits.iter().rev().map(|n| BASE58[*n as usize]));
        let multibase = core::str::from_utf8(&material).unwrap();
        let did: pallet_did_registry::DidOf<Runtime> = did.to_vec().try_into().unwrap();
        pallet_did_registry::Dids::<Runtime>::mutate(&did, |record| {
            let record = record.as_mut().unwrap();
            let mut agreements = BoundedVec::default();
            for n in 0..64 {
                agreements.try_push(pallet_did_registry::KeyAgreement::<Runtime> {
                    id: format!("#key-{n}").into_bytes().try_into().unwrap(),
                    type_: b"opaque".to_vec().try_into().unwrap(), controller: did.to_vec().try_into().unwrap(),
                    public_key_multibase: vec![b'z'; 3800].try_into().unwrap(),
                }).unwrap();
            }
            let mut methods = BoundedVec::default();
            for n in 0..5 {
                let id = format!("#v{n}");
                let overlay = serde_json::json!({"id": id, "type": "Ed25519VerificationKey2020",
                    "controller": core::str::from_utf8(&did).unwrap(), "publicKeyMultibase": multibase,
                    "padding": "a".repeat(3200)});
                let mut encoded = b"\0OP:KEY:1:".to_vec(); encoded.extend(serde_json::to_vec(&overlay).unwrap());
                methods.try_push(pallet_did_registry::VerificationMethod::<Runtime> {
                    id: id.into_bytes().try_into().unwrap(), type_: b"Ed25519VerificationKey2020".to_vec().try_into().unwrap(),
                    controller: did.to_vec().try_into().unwrap(), public_key_multibase: encoded.try_into().unwrap(),
                }).unwrap();
            }
            record.document = Some(pallet_did_registry::DidDocument::<Runtime> {
                id: did.clone(), verification_method: methods, authentication: Some((1..5).map(|n| format!("#v{n}").into_bytes().try_into().unwrap()).collect::<Vec<_>>().try_into().unwrap()),
                key_agreement: agreements, service: None,
            });
        });
    }
    fn sign(seed: u32, payload: &[u8]) -> Vec<u8> {
        <Self as pallet_resource_rewards::BenchmarkHelper<AccountId>>::sign(seed, payload)
    }
}

#[cfg(feature = "runtime-benchmarks")]
fn seed_benchmark_policy(scope:pallet_delivery_policy::PolicyScopeV3<Runtime>,did:&[u8]) {
    let document:pallet_delivery_policy::PolicyDocumentOf<Runtime>=alloc::vec![0xff;65536].try_into().unwrap();
    pallet_delivery_policy::PoliciesV4::<Runtime>::insert(scope,pallet_delivery_policy::PolicyDocumentRecord::<Runtime> {
        revision:1,operator_did:did.to_vec().try_into().unwrap(),content_hash:sp_io::hashing::blake2_256(&document),document,
    });
}

#[cfg(feature = "runtime-benchmarks")]
impl pallet_delivery_policy::BenchmarkHelper for ResourceRewardsBenchmarkHelper {
    fn install(did: &[u8], application: &[u8]) {
        <Self as pallet_application_registry::BenchmarkHelper>::install_did(did, 1);
        let id: pallet_application_registry::ApplicationIdOf<Runtime> = application.to_vec().try_into().unwrap();
        pallet_application_registry::Applications::<Runtime>::insert(id, pallet_application_registry::ApplicationRecord::<Runtime> {
            control_did: did.to_vec().try_into().unwrap(), status: pallet_application_registry::ApplicationStatus::Active,
            revision: 1, registered_at: 0, updated_at: 0,
        });
    }
    fn sign(payload: &[u8]) -> Vec<u8> { <Self as pallet_application_registry::BenchmarkHelper>::sign(1, payload) }
    fn signer() -> Vec<u8> { b"#v4".to_vec() }
}

impl pallet_resource_rewards::Config for Runtime {
    type GovernanceOrigin = frame_system::EnsureRoot<AccountId>;
    type DidProvider = DidRegistry;
    type WeightInfo = pallet_resource_rewards::weights::SubstrateWeight<Runtime>;
    #[cfg(feature = "runtime-benchmarks")]
    type BenchmarkHelper = ResourceRewardsBenchmarkHelper;
    type MaxDidLen = ConstU32<128>;
    type MaxNodeIdLen = ConstU32<64>;
    type MaxMessageIdLen = ConstU32<64>;
    type MaxEndpointLen = ConstU32<256>;
    type MaxRegionLen = ConstU32<64>;
    type MaxJurisdictionLen = ConstU32<64>;
    type MaxClusterLen = ConstU32<64>;
    type MaxNetworkRangeLen = ConstU32<64>;
    type MaxTtlTiers = ConstU32<16>;
    type MaxProofHashLen = ConstU32<64>;
    type MaxSignatureLen = ConstU32<128>;
    type MaxReportsPerNodeEpoch = ConstU32<32>;
    type EpochDuration = ConstU32<{ HOURS }>;
    type CacheRewardHistoryRetentionEpochs = ConstU64<CACHE_REWARD_HISTORY_RETENTION_EPOCHS>;
    type MaxPruneKeysPerCall = ConstU32<16>;
    type BaseEpochReward = ConstU128<UNIT>;
    type RewardStorageUnitBytes = ConstU64<100_000_000_000>;
    type MaxStorageMultiplierPpm = ConstU32<4_000_000>;
    type MinOutageReporters = ConstU32<2>;
    type MinOutageWeight = ConstU32<2>;
    type RelayPenaltyPerWeightPpm = ConstU32<25_000>;
    type MaxRelayPenaltyPpm = ConstU32<300_000>;
    type FalseReportPenaltyPpm = ConstU32<50_000>;
    type RewardPalletId = ResourceRewardPalletId;
    type MaxMessageSizeBytes = ConstU64<{ 16 * 1024 * 1024 }>;
    type TriggerTicketsPerEpoch = ConstU32<6>;
    type RequiredTriggerAttestations = ConstU32<2>;
    type TriggerRetentionBlocks = ConstU32<{ MINUTES * 10 }>;
    type EvidenceWindowEpochs = ConstU64<1>;
    type RewardFinalizationWindowEpochs = ConstU64<1>;
    type EpochsPerRewardYear = ConstU64<8_760>;
    type GenesisRewardReserve = ConstU128<{ 1_000_000 * UNIT }>;
    type AnnualFixedEmission = ConstU128<{ 1_000_000 * UNIT }>;
    type SupplementalInflationPpm = ConstU32<20_000>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configs::RuntimeBlockWeights;
    use frame_support::{
        dispatch::DispatchClass,
        storage::unhashed,
        traits::{Get, Hooks, StorageVersion},
    };
    use pallet_delivery_policy::weights::WeightInfo as _;

    #[test]
    fn stored_application_with_legacy_controller_has_no_policy_authority() {
        use pallet_delivery_policy::ApplicationProvider;
        let storage = frame_system::GenesisConfig::<Runtime>::default().build_storage().unwrap();
        sp_io::TestExternalities::new(storage).execute_with(|| {
            let application_id: pallet_application_registry::ApplicationIdOf<Runtime> =
                b"legacy-test".to_vec().try_into().unwrap();
            pallet_application_registry::Applications::<Runtime>::insert(
                application_id,
                pallet_application_registry::ApplicationRecord::<Runtime> {
                    control_did: b"did:talaria:1111111111111111111111".to_vec().try_into().unwrap(),
                    status: pallet_application_registry::ApplicationStatus::Active,
                    revision: 1,
                    registered_at: 0,
                    updated_at: 0,
                },
            );
            assert_eq!(RuntimeApplicationProvider::active_control_did(b"legacy-test"), None);
            assert_eq!(RuntimeApplicationProvider::verified_domain(b"legacy-test"), None);
            assert!(!RuntimeApplicationProvider::authorized_send_target(
                b"legacy-test", b"did:talaria:1111111111111111111111"
            ));
        });
    }

    #[test]
    fn authority_governance_preserves_runtime_compatibility_boundaries() {
        assert_eq!(VERSION.spec_version, 130);
        assert_eq!(VERSION.transaction_version, 6);
        assert_eq!(
            <<Runtime as pallet_resource_rewards::Config>::BaseEpochReward as Get<Balance>>::get(),
            UNIT
        );
        assert_eq!(
            <PalletInfo as frame_support::traits::PalletInfo>::index::<DidRegistry>(),
            Some(8)
        );
        assert_eq!(
            <PalletInfo as frame_support::traits::PalletInfo>::index::<ResourceRewards>(),
            Some(11)
        );
        assert_eq!(
            <PalletInfo as frame_support::traits::PalletInfo>::index::<AuthorityGovernance>(),
            Some(12)
        );
        assert_eq!(
            <<Runtime as pallet_authority_governance::Config>::MinAuthorities as Get<u32>>::get(),
            4
        );
        assert_eq!(
            <<Runtime as pallet_authority_governance::Config>::MinAuthorityChangeDelay as Get<
                BlockNumber,
            >>::get(),
            100
        );
    }

    #[test]
    fn delivery_policy_v2_upgrade_does_not_reencode_live_dids() {
        let storage = frame_system::GenesisConfig::<Runtime>::default()
            .build_storage()
            .unwrap();
        let mut externalities = sp_io::TestExternalities::new(storage);
        externalities.execute_with(|| {
            let did: pallet_did_registry::DidOf<Runtime> = b"did:openpayload:1111111111111111"
                .to_vec()
                .try_into()
                .unwrap();
            let record = pallet_did_registry::DidRecord::<Runtime> {
                owner: None,
                aliases: None,
                devices: None,
                document: None,
                version: 1,
                updated_at: 1,
                root_pubkey: None,
                delivery_policy_links: None,
                deactivated: false,
            };
            pallet_did_registry::Dids::<Runtime>::insert(&did, record);
            let key = pallet_did_registry::Dids::<Runtime>::hashed_key_for(&did);
            let before = unhashed::get_raw(&key).unwrap();

            StorageVersion::new(0).put::<DeliveryPolicy>();
            DeliveryPolicy::on_runtime_upgrade();

            assert_eq!(unhashed::get_raw(&key).unwrap(), before);
        });
    }

    #[test]
    fn application_control_did_guard_reads_registry_index() {
        let storage = frame_system::GenesisConfig::<Runtime>::default()
            .build_storage()
            .unwrap();
        let mut externalities = sp_io::TestExternalities::new(storage);
        externalities.execute_with(|| {
            let did: pallet_application_registry::DidOf<Runtime> =
                b"did:openpayload:1111111111111111"
                    .to_vec()
                    .try_into()
                    .unwrap();
            let app: pallet_application_registry::ApplicationIdOf<Runtime> =
                b"talaria".to_vec().try_into().unwrap();
            assert!(
                <ApplicationControlDidGuard as pallet_did_registry::DidRetirementGuard>::can_retire(
                    did.as_slice()
                )
            );
            pallet_application_registry::ApplicationsByControlDid::<Runtime>::insert(
                &did,
                frame_support::BoundedVec::try_from(vec![app]).unwrap(),
            );
            assert!(
                !<ApplicationControlDidGuard as pallet_did_registry::DidRetirementGuard>::can_retire(
                    did.as_slice()
                )
            );
        });
    }

    #[test]
    fn delivery_policy_v2_reserves_the_mutation_budget_until_benchmarked() {
        type PolicyWeights = <Runtime as pallet_delivery_policy::Config>::WeightInfo;

        let block_weights = RuntimeBlockWeights::get();
        let normal_max = block_weights
            .get(DispatchClass::Normal)
            .max_extrinsic
            .expect("the production runtime bounds Normal extrinsics");
        let encoded_limit = u64::from(*<Runtime as frame_system::Config>::BlockLength::get()
            .max.get(DispatchClass::Normal));
        let mutation_budget = normal_max.saturating_sub(frame_support::weights::Weight::from_parts(
            100_000_000_000, encoded_limit + 1_048_576));

        for direct_mutation in [
            PolicyWeights::set_did_delivery_constraints(),
            PolicyWeights::register_persona(),
            PolicyWeights::renew_persona(),
            PolicyWeights::revoke_persona(),
            PolicyWeights::set_did_policy_v2(),
            PolicyWeights::clear_did_policy_v2(),
            PolicyWeights::set_persona_policy_v2(),
            PolicyWeights::clear_persona_policy_v2(),
            PolicyWeights::set_persona_delivery_constraints(),
            PolicyWeights::set_persona_attestor(),
        ] {
            assert_eq!(direct_mutation, mutation_budget);
        }

        let authorized_total = PolicyWeights::apply_policy_v2_with_proof()
            .saturating_add(PolicyWeights::authorize_apply_policy_v2_with_proof());
        assert!(authorized_total.all_lte(normal_max));
        let rounding_remainder = mutation_budget.saturating_sub(authorized_total);
        assert!(rounding_remainder.ref_time() <= 3);
        assert!(rounding_remainder.proof_size() <= 3);

        let persona_authorized_total = PolicyWeights::apply_persona_with_proof()
            .saturating_add(PolicyWeights::authorize_apply_persona_with_proof());
        assert!(persona_authorized_total.all_lte(normal_max));
        let rounding_remainder = mutation_budget.saturating_sub(persona_authorized_total);
        assert!(rounding_remainder.ref_time() <= 3);
        assert!(rounding_remainder.proof_size() <= 3);
    }

    #[test]
    fn delivery_policy_general_proof_transactions_fit_frame_weight_and_length_checks() {
        use codec::Encode;
        use frame_support::dispatch::GetDispatchInfo;
        use sp_runtime::{generic::Era, traits::TransactionExtension};

        let mut ext = sp_io::TestExternalities::new_empty();
        ext.execute_with(|| {
            let extensions: TxExtension = (
                frame_system::AuthorizeCall::new(),
                frame_system::CheckNonZeroSender::new(),
                frame_system::CheckSpecVersion::new(),
                frame_system::CheckTxVersion::new(),
                frame_system::CheckGenesis::new(),
                frame_system::CheckEra::from(Era::Immortal),
                frame_system::CheckNonce::from(0),
                frame_system::CheckWeight::new(),
                pallet_transaction_payment::ChargeTransactionPayment::from(0),
                frame_metadata_hash_extension::CheckMetadataHash::new(false),
                frame_system::WeightReclaim::new(),
            );
            let calls = [
                RuntimeCall::DeliveryPolicy(pallet_delivery_policy::Call::apply_persona_with_proof {
                    signed_payload: vec![0; 65_536], signature: vec![0; 64], signer_key_id: vec![0; 256],
                }),
                RuntimeCall::DeliveryPolicy(pallet_delivery_policy::Call::apply_policy_v2_with_proof {
                    signed_payload: vec![0; 65_536], signature: vec![0; 64], signer_key_id: vec![0; 256],
                }),
            ];
            for call in calls {
                let mut info = call.get_dispatch_info();
                info.extension_weight = extensions.weight(&call);
                let xt = UncheckedExtrinsic::new_transaction(call, extensions.clone());
                let len = xt.encode().len();
                assert!(frame_system::CheckWeight::<Runtime>::do_validate(&info, len).is_ok(),
                    "General proof must include all framework extensions and its encoded length");
                let max_len = *<Runtime as frame_system::Config>::BlockLength::get()
                    .max.get(DispatchClass::Normal) as usize;
                assert!(frame_system::CheckWeight::<Runtime>::do_validate(&info, max_len).is_ok());
            }
        });
    }
    #[test]
    fn application_owner_proof_runs_through_general_transaction_pipeline_without_funds() {
        use codec::Encode;
        use sp_core::Pair;
        use sp_runtime::{generic::Era, transaction_validity::TransactionSource};
        let storage = frame_system::GenesisConfig::<Runtime>::default().build_storage().unwrap();
        let mut ext = sp_io::TestExternalities::new(storage);
        ext.execute_with(|| {
            // Pool validation initializes the next block; preserve the genesis hash.
            System::set_block_number(1);
            let root = sp_core::ed25519::Pair::from_seed(&[7; 32]);
            let raw = b"did:openpayload:1111111111111111";
            let did: pallet_did_registry::DidOf<Runtime> = raw.to_vec().try_into().unwrap();
            pallet_did_registry::Dids::<Runtime>::insert(&did, pallet_did_registry::DidRecord::<Runtime> {
                owner: None, aliases: None, devices: None, document: None, version: 1, updated_at: 0,
                root_pubkey: Some(root.public().0.to_vec().try_into().unwrap()), delivery_policy_links: None, deactivated: false,
            });
            let application_id: pallet_application_registry::ApplicationIdOf<Runtime> = b"unfunded-proof".to_vec().try_into().unwrap();
            let proof = pallet_application_registry::ApplicationAuthorizationPayload::<Runtime> {
                genesis_hash: System::block_hash(0), operator_did: raw.to_vec().try_into().unwrap(),
                signer_key_id: b"root".to_vec().try_into().unwrap(), linked_signer_key_id: None,
                operation: pallet_application_registry::ApplicationOperation::Register { application_id: application_id.clone() },
                nonce: 0, valid_until: 60_000,
            };
            let payload = ApplicationRegistry::proof_payload(&proof);
            let call = RuntimeCall::ApplicationRegistry(pallet_application_registry::Call::apply_application_with_proof {
                signature: root.sign(&payload).0.to_vec().try_into().unwrap(), signed_payload: payload, linked_signature: Default::default(),
            });
            let extensions: TxExtension = (
                frame_system::AuthorizeCall::new(), frame_system::CheckNonZeroSender::new(),
                frame_system::CheckSpecVersion::new(), frame_system::CheckTxVersion::new(),
                frame_system::CheckGenesis::new(), frame_system::CheckEra::from(Era::Immortal),
                frame_system::CheckNonce::from(0), frame_system::CheckWeight::new(),
                pallet_transaction_payment::ChargeTransactionPayment::from(0),
                frame_metadata_hash_extension::CheckMetadataHash::new(false), frame_system::WeightReclaim::new(),
            );
            let transaction = UncheckedExtrinsic::new_transaction(call, extensions);
            assert_eq!(Balances::total_issuance(), 0);
            let validity = Executive::validate_transaction(TransactionSource::External, transaction.clone(), Hash::default());
            assert!(validity.is_ok(), "General proof rejected: {validity:?}");
            assert!(Executive::apply_extrinsic(transaction.clone()).unwrap().is_ok());
            assert!(pallet_application_registry::Applications::<Runtime>::contains_key(&application_id));
            assert_eq!(pallet_application_registry::AuthorizationNonces::<Runtime>::get(proof.operator_did), 1);
            assert_eq!(Balances::total_issuance(), 0);
            assert!(Executive::validate_transaction(TransactionSource::External, transaction, Hash::default()).is_err());

            // A raw application document uses its own proof/nonce with no payer, and is
            // intentionally invalid JSON: interpretation belongs to services and nodes.
            let scope = pallet_delivery_policy::PolicyScopeV3::Application(application_id.to_vec().try_into().unwrap());
            let document = vec![0xff;65_536];
            let policy = pallet_delivery_policy::PolicyDocumentAuthorizationPayload::<Runtime> {
                domain:pallet_delivery_policy::POLICY_DOCUMENT_PROOF_DOMAIN.to_vec().try_into().unwrap(),
                genesis_hash:System::block_hash(0),operator_did:raw.to_vec().try_into().unwrap(),
                signer_key_id:b"root".to_vec().try_into().unwrap(),
                operation:pallet_delivery_policy::PolicyDocumentOperation::Set { scope:scope.clone(),revision:1,document:document.clone().try_into().unwrap() },
                nonce:0,valid_until:60_000,
            };
            let bytes=policy.encode();
            let call=RuntimeCall::DeliveryPolicy(pallet_delivery_policy::Call::apply_policy_document_with_proof {
                signature:root.sign(&bytes).0.to_vec(),signed_payload:bytes,signer_key_id:b"root".to_vec(),
            });
            let extensions: TxExtension = (
                frame_system::AuthorizeCall::new(), frame_system::CheckNonZeroSender::new(),
                frame_system::CheckSpecVersion::new(), frame_system::CheckTxVersion::new(),
                frame_system::CheckGenesis::new(), frame_system::CheckEra::from(Era::Immortal),
                frame_system::CheckNonce::from(0), frame_system::CheckWeight::new(),
                pallet_transaction_payment::ChargeTransactionPayment::from(0),
                frame_metadata_hash_extension::CheckMetadataHash::new(false), frame_system::WeightReclaim::new(),
            );
            let transaction=UncheckedExtrinsic::new_transaction(call,extensions);
            assert!(Executive::validate_transaction(TransactionSource::External,transaction.clone(),Hash::default()).is_ok());
            assert!(Executive::apply_extrinsic(transaction.clone()).unwrap().is_ok());
            let record=pallet_delivery_policy::PoliciesV4::<Runtime>::get(&scope).unwrap();
            assert_eq!(record.document.to_vec(),document);
            assert_eq!(record.content_hash,sp_io::hashing::blake2_256(&document));
            assert_eq!(Balances::total_issuance(),0);
            assert!(Executive::validate_transaction(TransactionSource::External,transaction,Hash::default()).is_err());
            <RuntimeApplicationPolicyCleanup as pallet_application_registry::ApplicationPolicyCleanup>::clear(&application_id);
            let record=pallet_delivery_policy::PoliciesV4::<Runtime>::get(scope).unwrap();
            assert_eq!(record.revision,2);assert!(record.document.is_empty());
            assert_eq!(pallet_delivery_policy::PolicyV4Nonces::<Runtime>::get(policy.operator_did),1);
        });
    }

}
