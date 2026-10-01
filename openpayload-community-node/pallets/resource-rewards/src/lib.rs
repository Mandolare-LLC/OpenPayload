#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::too_many_arguments)]

extern crate alloc;

use alloc::vec::Vec;
use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use frame_support::{
    pallet_prelude::*,
    traits::{Currency, ExistenceRequirement, StorageVersion},
    BoundedVec, DebugNoBound, PalletId,
};
use frame_system::pallet_prelude::*;
use scale_info::TypeInfo;
use sp_core::U256;
use sp_runtime::{
    traits::{AccountIdConversion, Hash, Saturating, Zero},
    SaturatedConversion,
};

pub use pallet::*;

pub mod weights;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

#[cfg(feature = "runtime-benchmarks")]
pub trait BenchmarkHelper<AccountId> {
    /// Install an active DID with a deterministic benchmark key.
    fn install_did(account: &AccountId, did: &[u8], seed: u32);
    /// Sign a pallet-generated DID authorization payload with that key.
    fn sign(seed: u32, payload: &[u8]) -> Vec<u8>;
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

    pub const PPM: u128 = 1_000_000;
    pub const OPERATOR_REGISTRATION_DOMAIN: &[u8] =
        b"openpayload:resource-rewards:register-operator:v1";
    pub const CACHE_TRIGGER_RECEIPT_DOMAIN: &[u8] =
        b"openpayload:resource-rewards:cache-trigger-receipt:v1";
    pub const CACHE_TRIGGER_ISSUANCE_DOMAIN: &[u8] =
        b"openpayload:resource-rewards:cache-trigger-issuance:v1";
    pub const CACHE_TRIGGER_ATTESTATION_DOMAIN: &[u8] =
        b"openpayload:resource-rewards:cache-trigger-attestation:v1";
    const STORAGE_VERSION: StorageVersion = StorageVersion::new(2);

    pub type BalanceOf<T> = <T as pallet_opal::Config>::Balance;
    pub type DidOf<T> = BoundedVec<u8, <T as Config>::MaxDidLen>;
    pub type NodeIdOf<T> = BoundedVec<u8, <T as Config>::MaxNodeIdLen>;
    pub type MessageIdOf<T> = BoundedVec<u8, <T as Config>::MaxMessageIdLen>;
    pub type EndpointOf<T> = BoundedVec<u8, <T as Config>::MaxEndpointLen>;
    pub type RegionOf<T> = BoundedVec<u8, <T as Config>::MaxRegionLen>;
    pub type JurisdictionOf<T> = BoundedVec<u8, <T as Config>::MaxJurisdictionLen>;
    pub type ClusterOf<T> = BoundedVec<u8, <T as Config>::MaxClusterLen>;
    pub type NetworkRangeOf<T> = BoundedVec<u8, <T as Config>::MaxNetworkRangeLen>;
    pub type TtlTiersOf<T> = BoundedVec<u32, <T as Config>::MaxTtlTiers>;
    pub type ProofHashOf<T> = BoundedVec<u8, <T as Config>::MaxProofHashLen>;
    pub type SignatureOf<T> = BoundedVec<u8, <T as Config>::MaxSignatureLen>;

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
    pub enum NodeRole {
        Cache,
        Relay,
        Directory,
        Validator,
        AllInOne,
    }

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
    pub enum OperatorStatus {
        Active,
        Suspended,
    }

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
    pub enum ProbeResult {
        Success,
        Timeout,
        ConnectionRefused,
        InvalidProtocolResponse,
        Unavailable,
        Overloaded,
        Maintenance,
        LoadShed,
    }

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
    pub enum FailureCategory {
        Timeout,
        Refused,
        Overloaded,
        Backpressure,
        RedirectLoadShed,
        InvalidResponse,
        Unreachable,
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
    pub struct OperatorInfo<T: Config> {
        pub account: T::AccountId,
        pub operator_did: DidOf<T>,
        pub bond: Option<BalanceOf<T>>,
        pub registered_at: BlockNumberFor<T>,
        pub status: OperatorStatus,
        pub credibility_ppm: u32,
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
    pub struct NodeInfo<T: Config> {
        pub operator: T::AccountId,
        pub operator_did: DidOf<T>,
        pub node_id: NodeIdOf<T>,
        pub node_role: NodeRole,
        pub endpoint: EndpointOf<T>,
        pub declared_capacity: u64,
        pub region: RegionOf<T>,
        pub jurisdiction: JurisdictionOf<T>,
        pub supported_ttl_tiers: TtlTiersOf<T>,
        pub relay_cluster: ClusterOf<T>,
        pub network_range: NetworkRangeOf<T>,
        pub registered_at: BlockNumberFor<T>,
        pub status: OperatorStatus,
    }

    /// Delegated admission authority. Revocation is deliberately non-cascading:
    /// authorities granted by this sponsor and caches already admitted remain in
    /// force until they are separately revoked.
    #[derive(
        Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, Debug, TypeInfo, MaxEncodedLen,
    )]
    pub struct SponsorAuthority<AccountId> {
        pub granted_by: AccountId,
        pub can_delegate: bool,
        pub granted_at_epoch: u64,
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
    pub struct CacheEligibility<T: Config> {
        pub admitted_by: T::AccountId,
        /// Admission and revocation take effect at epoch boundaries so the
        /// eligibility of an in-flight epoch cannot be rewritten.
        pub admitted_epoch: u64,
        pub revoked_by: Option<T::AccountId>,
        pub revoked_epoch: Option<u64>,
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
    pub struct CacheTriggerReceipt<T: Config> {
        pub ticket_id: ProofHashOf<T>,
        pub cache_node_id: NodeIdOf<T>,
        pub message_id: MessageIdOf<T>,
        pub queue_depth_before: u64,
        pub queue_depth_after: u64,
        pub accepted_at: u64,
        pub stored_at: u64,
        pub receipt_hash: ProofHashOf<T>,
        pub signature: SignatureOf<T>,
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
    pub struct CacheTriggerTicket<T: Config> {
        pub ticket_id: ProofHashOf<T>,
        pub cache_node_id: NodeIdOf<T>,
        pub recipient_did: DidOf<T>,
        pub trigger_message_hash: ProofHashOf<T>,
        pub epoch: u64,
        pub slot: u32,
        pub issued_at: BlockNumberFor<T>,
        pub retention_check_at: BlockNumberFor<T>,
        pub expires_at: BlockNumberFor<T>,
        pub issuer_validator_node_id: NodeIdOf<T>,
        pub issuer_signature: SignatureOf<T>,
        pub receipt: Option<CacheTriggerReceipt<T>>,
        pub positive_attestations: u32,
        pub negative_attestations: u32,
        pub canonical_evidence_hash: Option<ProofHashOf<T>>,
        pub verified: bool,
        pub failed: bool,
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
    pub struct CacheTriggerAttestation<T: Config> {
        pub validator_node_id: NodeIdOf<T>,
        pub accepted: bool,
        pub retained: bool,
        pub retrieved: bool,
        pub purged: bool,
        pub evidence_hash: ProofHashOf<T>,
        pub signature: SignatureOf<T>,
    }

    #[derive(
        Default,
        Encode,
        Decode,
        DecodeWithMemTracking,
        Clone,
        PartialEq,
        Eq,
        Debug,
        TypeInfo,
        MaxEncodedLen,
    )]
    pub struct CacheQueueDepthEpoch {
        pub tickets_issued: u32,
        pub tickets_verified: u32,
        pub depth_sum: u128,
        pub finalized: bool,
        pub average_depth: u64,
        pub average_bytes: u128,
    }

    #[derive(
        Default,
        Encode,
        Decode,
        DecodeWithMemTracking,
        Clone,
        PartialEq,
        Eq,
        Debug,
        TypeInfo,
        MaxEncodedLen,
    )]
    pub struct OperatorQueueDepthEpoch {
        pub total_average_bytes: u128,
        pub finalized_nodes: u32,
        pub frozen: bool,
        pub multiplier_ppm: u32,
    }

    #[derive(
        Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, Debug, TypeInfo, MaxEncodedLen,
    )]
    pub struct EpochSettlement<Balance> {
        pub reward_year: u64,
        pub raw_total: Balance,
        pub distributable: Balance,
        pub record_count: u64,
        pub claimed_count: u64,
        pub claimed_total: Balance,
        pub closed: bool,
    }

    #[derive(
        Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, Debug, TypeInfo, MaxEncodedLen,
    )]
    pub struct RewardYearState<Balance> {
        pub reward_year: u64,
        pub opening_free_reserve: Balance,
        pub supplemental_cap: Balance,
        pub supplemental_minted: Balance,
        pub committed: Balance,
        pub fixed_emission_minted: Balance,
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
    pub struct CacheRewardRecord<T: Config> {
        pub operator: T::AccountId,
        pub average_bytes: u128,
        pub quality_ppm: u32,
        pub storage_multiplier_ppm: u32,
        pub raw_amount: BalanceOf<T>,
        pub raw_prefix_before: BalanceOf<T>,
        pub policy_version: u32,
        pub claimed_amount: Option<BalanceOf<T>>,
    }

    #[derive(
        Default,
        Encode,
        Decode,
        DecodeWithMemTracking,
        Clone,
        PartialEq,
        Eq,
        Debug,
        TypeInfo,
        MaxEncodedLen,
    )]
    pub struct AvailabilitySummary {
        pub validator_success_weight: u32,
        pub validator_failure_weight: u32,
        pub validator_probe_count: u32,
        pub relay_failure_weight: u32,
        pub relay_report_count: u32,
        pub availability_score_ppm: u32,
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
    pub struct ProbeSubmission<T: Config> {
        pub validator_node_id: NodeIdOf<T>,
        pub target_node_id: NodeIdOf<T>,
        pub epoch: u64,
        pub window_start: u64,
        pub window_end: u64,
        pub result: ProbeResult,
        pub signature: SignatureOf<T>,
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
    pub struct RelayOutageReport<T: Config> {
        pub reporter_relay_node_id: NodeIdOf<T>,
        pub target_node_id: NodeIdOf<T>,
        pub epoch: u64,
        pub failure_category: FailureCategory,
        pub observed_count: u32,
        pub first_observed: u64,
        pub last_observed: u64,
        pub reporter_signature: SignatureOf<T>,
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
    pub struct ReporterSnapshot<T: Config> {
        pub reporter_node_id: NodeIdOf<T>,
        pub operator_did: DidOf<T>,
        pub relay_cluster: ClusterOf<T>,
        pub network_range: NetworkRangeOf<T>,
        pub region: RegionOf<T>,
        pub weight: u32,
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
    pub struct OutageAggregate<T: Config> {
        pub observed_count: u32,
        pub reporter_count: u32,
        pub independent_weight: u32,
        pub reporters: BoundedVec<ReporterSnapshot<T>, <T as Config>::MaxReportsPerNodeEpoch>,
    }

    impl<T: Config> Default for OutageAggregate<T> {
        fn default() -> Self {
            Self {
                observed_count: 0,
                reporter_count: 0,
                independent_weight: 0,
                reporters: BoundedVec::default(),
            }
        }
    }

    #[pallet::config]
    pub trait Config:
        frame_system::Config<RuntimeEvent: From<Event<Self>>> + pallet_opal::Config
    {
        type GovernanceOrigin: EnsureOrigin<Self::RuntimeOrigin>;
        type DidProvider: pallet_delivery_policy::DidProvider<Self::AccountId>;
        type WeightInfo: weights::WeightInfo;

        #[cfg(feature = "runtime-benchmarks")]
        type BenchmarkHelper: BenchmarkHelper<Self::AccountId>;

        #[pallet::constant]
        type MaxDidLen: Get<u32>;
        #[pallet::constant]
        type MaxNodeIdLen: Get<u32>;
        #[pallet::constant]
        type MaxMessageIdLen: Get<u32>;
        #[pallet::constant]
        type MaxEndpointLen: Get<u32>;
        #[pallet::constant]
        type MaxRegionLen: Get<u32>;
        #[pallet::constant]
        type MaxJurisdictionLen: Get<u32>;
        #[pallet::constant]
        type MaxClusterLen: Get<u32>;
        #[pallet::constant]
        type MaxNetworkRangeLen: Get<u32>;
        #[pallet::constant]
        type MaxTtlTiers: Get<u32>;
        type MaxProofHashLen: Get<u32>;
        #[pallet::constant]
        type MaxSignatureLen: Get<u32>;
        #[pallet::constant]
        type MaxReportsPerNodeEpoch: Get<u32>;
        #[pallet::constant]
        type EpochDuration: Get<BlockNumberFor<Self>>;
        #[pallet::constant]
        type CacheRewardHistoryRetentionEpochs: Get<u64>;
        #[pallet::constant]
        type MaxPruneKeysPerCall: Get<u32>;
        #[pallet::constant]
        type BaseEpochReward: Get<BalanceOf<Self>>;
        #[pallet::constant]
        type RewardStorageUnitBytes: Get<u64>;
        #[pallet::constant]
        type MaxStorageMultiplierPpm: Get<u32>;
        #[pallet::constant]
        type MinOutageReporters: Get<u32>;
        #[pallet::constant]
        type MinOutageWeight: Get<u32>;
        #[pallet::constant]
        type RelayPenaltyPerWeightPpm: Get<u32>;
        #[pallet::constant]
        type MaxRelayPenaltyPpm: Get<u32>;
        #[pallet::constant]
        type FalseReportPenaltyPpm: Get<u32>;
        #[pallet::constant]
        type RewardPalletId: Get<PalletId>;
        #[pallet::constant]
        type MaxMessageSizeBytes: Get<u64>;
        #[pallet::constant]
        type TriggerTicketsPerEpoch: Get<u32>;
        #[pallet::constant]
        type RequiredTriggerAttestations: Get<u32>;
        #[pallet::constant]
        type TriggerRetentionBlocks: Get<BlockNumberFor<Self>>;
        #[pallet::constant]
        type EvidenceWindowEpochs: Get<u64>;
        #[pallet::constant]
        type RewardFinalizationWindowEpochs: Get<u64>;
        #[pallet::constant]
        type EpochsPerRewardYear: Get<u64>;
        #[pallet::constant]
        type GenesisRewardReserve: Get<BalanceOf<Self>>;
        #[pallet::constant]
        type AnnualFixedEmission: Get<BalanceOf<Self>>;
        #[pallet::constant]
        type SupplementalInflationPpm: Get<u32>;
    }

    #[pallet::pallet]
    #[pallet::storage_version(STORAGE_VERSION)]
    pub struct Pallet<T>(_);

    #[pallet::storage]
    pub type Operators<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, OperatorInfo<T>, OptionQuery>;

    #[pallet::storage]
    pub type OperatorByDid<T: Config> =
        StorageMap<_, Blake2_128Concat, DidOf<T>, T::AccountId, OptionQuery>;

    #[pallet::storage]
    pub type Nodes<T: Config> =
        StorageMap<_, Blake2_128Concat, NodeIdOf<T>, NodeInfo<T>, OptionQuery>;

    /// One validator identity per admitted operator preserves threshold independence.
    #[pallet::storage]
    pub type ValidatorNodeByOperator<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, NodeIdOf<T>, OptionQuery>;

    /// Resource-validator accounts are admitted and revoked by governance.
    /// Approval should be performed through the offline root/multisig process;
    /// merely registering a node with the Validator role is never sufficient.
    #[pallet::storage]
    pub type ApprovedValidatorAccounts<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, (), OptionQuery>;

    /// Emergency governance switch. While set, all resource-validator actions
    /// and new validator-role registrations are rejected without altering the
    /// approved roster.
    #[pallet::storage]
    pub type ValidatorActivityPaused<T: Config> = StorageValue<_, bool, ValueQuery>;

    /// Active queue-depth trigger evidence switch. This is independent from
    /// the emergency monetary pause so evidence can continue while payouts do not.
    #[pallet::storage]
    #[pallet::getter(fn cache_trigger_evidence_enabled)]
    pub type CacheTriggerEvidenceEnabled<T: Config> = StorageValue<_, bool, ValueQuery>;

    /// Emergency monetary circuit breaker. An active payment schedule is also
    /// required before settlement or minting; permanent genesis may start unpaused.
    #[pallet::storage]
    #[pallet::getter(fn reward_payments_paused)]
    pub type RewardPaymentsPaused<T: Config> = StorageValue<_, bool, ValueQuery>;

    /// Earliest epoch that may ever create a payable reward. Once scheduled it
    /// cannot be moved or removed, preventing alpha evidence from becoming a
    /// retroactive monetary claim after a runtime upgrade.
    #[pallet::storage]
    #[pallet::getter(fn reward_payments_start_epoch)]
    pub type RewardPaymentsStartEpoch<T: Config> = StorageValue<_, u64, OptionQuery>;

    /// Economics identifier committed into every calculated reward and mint
    /// reference. Zero means that no monetary policy has been activated.
    #[pallet::storage]
    #[pallet::getter(fn active_reward_policy_version)]
    pub type ActiveRewardPolicyVersion<T: Config> = StorageValue<_, u32, ValueQuery>;

    #[pallet::type_value]
    pub fn DefaultCacheRewardHistoryRetentionEpochs<T: Config>() -> u64 {
        T::CacheRewardHistoryRetentionEpochs::get()
    }

    /// Chain-specific retention policy. Public presets retain the production
    /// default while disposable development presets may use a short window to
    /// rehearse the complete pruning path.
    #[pallet::storage]
    #[pallet::getter(fn cache_reward_history_retention_epochs)]
    pub type CacheRewardHistoryRetentionEpochsValue<T: Config> =
        StorageValue<_, u64, ValueQuery, DefaultCacheRewardHistoryRetentionEpochs<T>>;

    #[pallet::genesis_config]
    pub struct GenesisConfig<T: Config> {
        pub approved_validators: Vec<T::AccountId>,
        pub validator_activity_paused: bool,
        pub cache_trigger_evidence_enabled: bool,
        pub reward_payments_paused: bool,
        pub reward_payments_start_epoch: Option<u64>,
        pub reward_policy_version: u32,
        pub root_sponsor: Option<T::AccountId>,
        pub cache_reward_history_retention_epochs: u64,
    }

    impl<T: Config> Default for GenesisConfig<T> {
        fn default() -> Self {
            Self {
                approved_validators: Vec::new(),
                validator_activity_paused: false,
                cache_trigger_evidence_enabled: false,
                reward_payments_paused: true,
                reward_payments_start_epoch: None,
                reward_policy_version: 0,
                root_sponsor: None,
                cache_reward_history_retention_epochs: T::CacheRewardHistoryRetentionEpochs::get(),
            }
        }
    }

    #[pallet::genesis_build]
    impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
        fn build(&self) {
            STORAGE_VERSION.put::<Pallet<T>>();
            assert!(
                T::TriggerTicketsPerEpoch::get() > 0,
                "trigger ticket count must be non-zero"
            );
            assert!(
                T::RequiredTriggerAttestations::get() > 0,
                "trigger attestation threshold must be non-zero"
            );
            assert!(
                T::EpochsPerRewardYear::get() > 0,
                "reward year must contain epochs"
            );
            assert!(
                T::SupplementalInflationPpm::get() <= PPM as u32,
                "supplemental inflation exceeds 100 percent"
            );
            assert!(
                self.reward_payments_start_epoch.is_some() == (self.reward_policy_version > 0),
                "reward payment activation epoch and policy version must be configured together"
            );
            if !self.reward_payments_paused {
                assert!(
                    self.reward_payments_start_epoch.is_some()
                        && self.cache_trigger_evidence_enabled
                        && self.root_sponsor.is_some(),
                    "unpaused reward payments require scheduled cache-trigger evidence and a root sponsor"
                );
            }
            for account in &self.approved_validators {
                ApprovedValidatorAccounts::<T>::insert(account, ());
            }
            ValidatorActivityPaused::<T>::put(self.validator_activity_paused);
            CacheTriggerEvidenceEnabled::<T>::put(self.cache_trigger_evidence_enabled);
            RewardPaymentsPaused::<T>::put(self.reward_payments_paused);
            if let Some(start_epoch) = self.reward_payments_start_epoch {
                RewardPaymentsStartEpoch::<T>::put(start_epoch);
                ActiveRewardPolicyVersion::<T>::put(self.reward_policy_version);
            }
            if let Some(root_sponsor) = &self.root_sponsor {
                RootSponsor::<T>::put(root_sponsor);
            }
            CacheRewardHistoryRetentionEpochsValue::<T>::put(
                self.cache_reward_history_retention_epochs,
            );

            let reserve = T::GenesisRewardReserve::get();
            let pot = Pallet::<T>::reward_pot_account();
            let balance_before = T::Currency::free_balance(&pot);
            if !reserve.is_zero() {
                drop(T::Currency::deposit_creating(&pot, reserve));
                let credited = T::Currency::free_balance(&pot).saturating_sub(balance_before);
                assert!(
                    credited == reserve,
                    "genesis reward reserve was not fully credited"
                );
            }
            let opening_free_reserve = T::Currency::free_balance(&pot);
            RewardYearStates::<T>::insert(
                0,
                RewardYearState {
                    reward_year: 0,
                    opening_free_reserve,
                    supplemental_cap: Zero::zero(),
                    supplemental_minted: Zero::zero(),
                    committed: Zero::zero(),
                    fixed_emission_minted: Zero::zero(),
                },
            );
            LastInitializedRewardYear::<T>::put(0);
            NextRewardEpochToClose::<T>::put(self.reward_payments_start_epoch.unwrap_or(0));
        }
    }

    #[pallet::storage]
    pub type AvailabilitySummaries<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        NodeIdOf<T>,
        Blake2_128Concat,
        u64,
        AvailabilitySummary,
        ValueQuery,
    >;

    #[pallet::storage]
    pub type ProbeSubmissions<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        (NodeIdOf<T>, NodeIdOf<T>, u64, u64),
        ProbeSubmission<T>,
        OptionQuery,
    >;

    #[pallet::storage]
    pub type RelayReportSubmissions<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        (NodeIdOf<T>, NodeIdOf<T>, u64, u64, u64),
        RelayOutageReport<T>,
        OptionQuery,
    >;

    #[pallet::storage]
    pub type OutageAggregates<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        NodeIdOf<T>,
        Blake2_128Concat,
        u64,
        OutageAggregate<T>,
        ValueQuery,
    >;
    #[pallet::storage]
    #[pallet::getter(fn root_sponsor)]
    pub type RootSponsor<T: Config> = StorageValue<_, T::AccountId, OptionQuery>;

    #[pallet::storage]
    pub type PendingRootSponsor<T: Config> = StorageValue<_, T::AccountId, OptionQuery>;

    #[pallet::storage]
    pub type SponsorAuthorities<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, SponsorAuthority<T::AccountId>, OptionQuery>;

    #[pallet::storage]
    pub type RewardEligibleCaches<T: Config> =
        StorageMap<_, Blake2_128Concat, NodeIdOf<T>, CacheEligibility<T>, OptionQuery>;

    #[pallet::storage]
    pub type CacheTriggerTickets<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        NodeIdOf<T>,
        Blake2_128Concat,
        (u64, u32),
        CacheTriggerTicket<T>,
        OptionQuery,
    >;

    #[pallet::storage]
    pub type CacheTriggerTicketById<T: Config> =
        StorageMap<_, Blake2_128Concat, ProofHashOf<T>, (NodeIdOf<T>, u64, u32), OptionQuery>;

    /// Public, monotonically increasing anti-replay nonce used in the DID
    /// signature that authorizes a validator's trigger issuance.
    #[pallet::storage]
    pub type ValidatorTriggerNonces<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, u64, ValueQuery>;

    #[pallet::storage]
    pub type CacheTriggerAttestations<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        ProofHashOf<T>,
        Blake2_128Concat,
        DidOf<T>,
        CacheTriggerAttestation<T>,
        OptionQuery,
    >;

    #[pallet::storage]
    pub type CacheQueueDepthEpochs<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        NodeIdOf<T>,
        Blake2_128Concat,
        u64,
        CacheQueueDepthEpoch,
        ValueQuery,
    >;

    #[pallet::storage]
    pub type OperatorQueueDepthEpochs<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        Blake2_128Concat,
        u64,
        OperatorQueueDepthEpoch,
        ValueQuery,
    >;

    #[pallet::storage]
    pub type CacheRewardRecords<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        NodeIdOf<T>,
        Blake2_128Concat,
        u64,
        CacheRewardRecord<T>,
        OptionQuery,
    >;

    #[pallet::storage]
    pub type EpochRawRewardTotals<T: Config> =
        StorageMap<_, Blake2_128Concat, u64, BalanceOf<T>, ValueQuery>;

    #[pallet::storage]
    pub type EpochRawRewardRecordCounts<T: Config> =
        StorageMap<_, Blake2_128Concat, u64, u64, ValueQuery>;

    #[pallet::storage]
    pub type EpochSettlements<T: Config> =
        StorageMap<_, Blake2_128Concat, u64, EpochSettlement<BalanceOf<T>>, OptionQuery>;

    #[pallet::storage]
    pub type RewardYearStates<T: Config> =
        StorageMap<_, Blake2_128Concat, u64, RewardYearState<BalanceOf<T>>, OptionQuery>;

    #[pallet::storage]
    pub type LastInitializedRewardYear<T: Config> = StorageValue<_, u64, ValueQuery>;

    #[pallet::storage]
    pub type NextRewardEpochToClose<T: Config> = StorageValue<_, u64, ValueQuery>;

    #[pallet::storage]
    pub type OutstandingRewardLiabilities<T: Config> = StorageValue<_, BalanceOf<T>, ValueQuery>;

    #[pallet::storage]
    pub type OperatorAccruedRewards<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, BalanceOf<T>, ValueQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        OperatorRegistered {
            operator: T::AccountId,
            operator_did: DidOf<T>,
        },
        NodeRegistered {
            operator: T::AccountId,
            node_id: NodeIdOf<T>,
            node_role: NodeRole,
        },
        ValidatorApprovalChanged {
            account: T::AccountId,
            approved: bool,
        },
        ValidatorActivityPauseChanged {
            paused: bool,
        },
        CacheTriggerEvidenceChanged {
            enabled: bool,
        },
        RewardPaymentsScheduled {
            start_epoch: u64,
            policy_version: u32,
        },
        RewardPaymentsPauseChanged {
            paused: bool,
        },
        ValidatorProbeSubmitted {
            validator_node_id: NodeIdOf<T>,
            target_node_id: NodeIdOf<T>,
            epoch: u64,
            result: ProbeResult,
            availability_score_ppm: u32,
        },
        RelayReportSubmitted {
            reporter_relay_node_id: NodeIdOf<T>,
            target_node_id: NodeIdOf<T>,
            epoch: u64,
            weight: u32,
        },
        ReporterCredibilityAdjusted {
            reporter_node_id: NodeIdOf<T>,
            credibility_ppm: u32,
        },
        SponsorAuthorityChanged {
            sponsor: T::AccountId,
            granted_by: T::AccountId,
            enabled: bool,
            can_delegate: bool,
        },
        RootSponsorTransferProposed {
            current_root: T::AccountId,
            proposed_root: T::AccountId,
        },
        RootSponsorTransferred {
            previous_root: T::AccountId,
            new_root: T::AccountId,
        },
        CacheRewardEligibilityChanged {
            node_id: NodeIdOf<T>,
            sponsor: T::AccountId,
            eligible: bool,
            effective_epoch: u64,
        },
        CacheTriggerTicketIssued {
            ticket_id: ProofHashOf<T>,
            cache_node_id: NodeIdOf<T>,
            epoch: u64,
            slot: u32,
            retention_check_at: BlockNumberFor<T>,
            expires_at: BlockNumberFor<T>,
        },
        CacheTriggerReceiptSubmitted {
            ticket_id: ProofHashOf<T>,
            cache_node_id: NodeIdOf<T>,
            message_id: MessageIdOf<T>,
            queue_depth_before: u64,
            queue_depth_after: u64,
        },
        CacheTriggerTicketAttested {
            ticket_id: ProofHashOf<T>,
            validator_node_id: NodeIdOf<T>,
            success: bool,
            positive_attestations: u32,
            negative_attestations: u32,
            verified: bool,
        },
        CacheQueueDepthEpochFinalized {
            node_id: NodeIdOf<T>,
            epoch: u64,
            tickets_issued: u32,
            tickets_verified: u32,
            average_depth: u64,
            average_bytes: u128,
        },
        OperatorQueueDepthFrozen {
            operator: T::AccountId,
            epoch: u64,
            total_average_bytes: u128,
            multiplier_ppm: u32,
        },
        CacheRawRewardFinalized {
            node_id: NodeIdOf<T>,
            operator: T::AccountId,
            epoch: u64,
            average_bytes: u128,
            quality_ppm: u32,
            storage_multiplier_ppm: u32,
            raw_amount: BalanceOf<T>,
        },
        RewardEpochClosed {
            epoch: u64,
            reward_year: u64,
            raw_total: BalanceOf<T>,
            distributable: BalanceOf<T>,
        },
        CacheRewardClaimed {
            node_id: NodeIdOf<T>,
            operator: T::AccountId,
            epoch: u64,
            amount: BalanceOf<T>,
        },
        AccruedRewardPaid {
            operator: T::AccountId,
            amount: BalanceOf<T>,
        },
        RewardYearInitialized {
            reward_year: u64,
            opening_free_reserve: BalanceOf<T>,
            fixed_emission: BalanceOf<T>,
            supplemental_cap: BalanceOf<T>,
        },
        SupplementalRewardsMinted {
            reward_year: u64,
            amount: BalanceOf<T>,
        },
        CacheRewardHistoryPruned {
            node_id: NodeIdOf<T>,
            epoch: u64,
            ticket_count_removed: u32,
            attestation_keys_removed: u32,
            complete: bool,
        },
        OperatorQueueDepthHistoryPruned {
            operator: T::AccountId,
            epoch: u64,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        OperatorAlreadyRegistered,
        OperatorNotRegistered,
        OperatorDidAlreadyRegistered,
        OperatorDidNotRegistered,
        InvalidOperatorDidSignature,
        NotOperatorOwner,
        UnregisteredNode,
        NodeAlreadyRegistered,
        ValidatorNodeAlreadyRegistered,
        OperatorNotActive,
        UnsupportedNodeRole,
        UnauthorizedReporter,
        UnauthorizedValidator,
        ValidatorNotApproved,
        ValidatorActivityPaused,
        SelfValidationForbidden,
        InvalidEpoch,
        InvalidWindow,
        DuplicateProbe,
        DuplicateReport,
        CacheTriggerEvidenceDisabled,
        TooManyReports,
        DidTooLong,
        NodeIdTooLong,
        EndpointTooLong,
        RegionTooLong,
        JurisdictionTooLong,
        ClusterTooLong,
        NetworkRangeTooLong,
        TooManyTtlTiers,
        ProofHashTooLong,
        InvalidProofHashLength,
        SignatureTooLong,
        RewardPaymentsPaused,
        RewardPaymentPolicyNotScheduled,
        RewardPaymentPolicyAlreadyScheduled,
        InvalidRewardPaymentActivation,
        CacheRewardHistoryRetentionActive,
        RootSponsorNotConfigured,
        NotRootSponsor,
        SponsorNotAuthorized,
        SponsorCannotDelegate,
        SponsorSelfGrantForbidden,
        SponsorAuthorityAlreadyExists,
        SponsorAuthorityNotFound,
        PendingRootSponsorNotFound,
        NotPendingRootSponsor,
        CacheNotRewardEligible,
        CacheAlreadyRewardEligible,
        CacheReadmissionTooEarly,
        CacheEligibilityAlreadyRevoked,
        InvalidTriggerSlot,
        TriggerSlotNotOpen,
        DuplicateCacheTriggerTicket,
        CacheTriggerTicketNotFound,
        CacheTriggerRecipientMismatch,
        CacheTriggerReceiptAlreadySubmitted,
        InvalidCacheTriggerReceipt,
        InvalidCacheTriggerSignature,
        DuplicateCacheTriggerAttestation,
        CacheTriggerTicketAlreadyResolved,
        CacheTriggerAttestationTooEarly,
        CacheTriggerEvidenceWindowClosed,
        InvalidCacheTriggerAttestation,
        InvalidCacheTriggerAttestationSignature,
        CacheQueueDepthAlreadyFinalized,
        OperatorQueueDepthAlreadyFrozen,
        OperatorQueueDepthFreezeTooEarly,
        OperatorQueueDepthNotFrozen,
        CacheRawRewardAlreadyFinalized,
        CacheRawRewardWindowClosed,
        RewardEpochCloseTooEarly,
        RewardEpochAlreadyClosed,
        RewardEpochNotClosed,
        CacheRewardNotFinalized,
        CacheRewardAlreadyClaimed,
        RewardYearNotInitialized,
        RewardYearAlreadyInitialized,
        SupplementalInflationCapExceeded,
        RewardReserveInvariantViolated,
        AccruedRewardBelowExistentialDeposit,
        NoAccruedReward,
        CacheRewardNotClaimed,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(T::DbWeight::get().reads_writes(3, 2))]
        pub fn register_operator(
            origin: OriginFor<T>,
            operator_did: Vec<u8>,
            bond: Option<BalanceOf<T>>,
            did_root_signature: Vec<u8>,
        ) -> DispatchResult {
            let operator = ensure_signed(origin)?;
            ensure!(
                !Operators::<T>::contains_key(&operator),
                Error::<T>::OperatorAlreadyRegistered
            );
            let operator_did = Self::bounded_did(operator_did)?;
            ensure!(
                !OperatorByDid::<T>::contains_key(&operator_did),
                Error::<T>::OperatorDidAlreadyRegistered
            );
            ensure!(
                T::DidProvider::did_exists(&operator_did),
                Error::<T>::OperatorDidNotRegistered
            );
            let authorization =
                Self::operator_registration_payload(&operator, operator_did.as_slice(), &bond);
            ensure!(
                T::DidProvider::verify_did_signature(
                    operator_did.as_slice(),
                    b"root",
                    &authorization,
                    &did_root_signature,
                ),
                Error::<T>::InvalidOperatorDidSignature
            );

            let info = OperatorInfo::<T> {
                account: operator.clone(),
                operator_did: operator_did.clone(),
                bond,
                registered_at: frame_system::Pallet::<T>::block_number(),
                status: OperatorStatus::Active,
                credibility_ppm: PPM as u32,
            };
            Operators::<T>::insert(&operator, info);
            OperatorByDid::<T>::insert(&operator_did, operator.clone());
            Self::deposit_event(Event::OperatorRegistered {
                operator,
                operator_did,
            });
            Ok(())
        }

        #[allow(clippy::too_many_arguments)]
        #[pallet::call_index(1)]
        #[pallet::weight(T::DbWeight::get().reads_writes(3, 2))]
        pub fn register_node(
            origin: OriginFor<T>,
            operator_did: Vec<u8>,
            node_id: Vec<u8>,
            node_role: NodeRole,
            endpoint: Vec<u8>,
            declared_capacity: u64,
            region: Vec<u8>,
            jurisdiction: Vec<u8>,
            supported_ttl_tiers: Vec<u32>,
            relay_cluster: Vec<u8>,
            network_range: Vec<u8>,
        ) -> DispatchResult {
            let operator = ensure_signed(origin)?;
            let operator_info =
                Operators::<T>::get(&operator).ok_or(Error::<T>::OperatorNotRegistered)?;
            ensure!(
                operator_info.status == OperatorStatus::Active,
                Error::<T>::OperatorNotActive
            );

            let operator_did = Self::bounded_did(operator_did)?;
            ensure!(
                operator_info.operator_did == operator_did,
                Error::<T>::NotOperatorOwner
            );
            let node_id = Self::bounded_node_id(node_id)?;
            ensure!(
                !Nodes::<T>::contains_key(&node_id),
                Error::<T>::NodeAlreadyRegistered
            );

            Self::validate_role_capacity(node_role, declared_capacity)?;
            if Self::is_validator_role(node_role) {
                ensure!(
                    !ValidatorActivityPaused::<T>::get(),
                    Error::<T>::ValidatorActivityPaused
                );
                ensure!(
                    ApprovedValidatorAccounts::<T>::contains_key(&operator),
                    Error::<T>::ValidatorNotApproved
                );
                ensure!(
                    !ValidatorNodeByOperator::<T>::contains_key(&operator),
                    Error::<T>::ValidatorNodeAlreadyRegistered
                );
            }

            let info = NodeInfo::<T> {
                operator: operator.clone(),
                operator_did: operator_did.clone(),
                node_id: node_id.clone(),
                node_role,
                endpoint: Self::bounded_endpoint(endpoint)?,
                declared_capacity,
                region: Self::bounded_region(region)?,
                jurisdiction: Self::bounded_jurisdiction(jurisdiction)?,
                supported_ttl_tiers: TtlTiersOf::<T>::try_from(supported_ttl_tiers)
                    .map_err(|_| Error::<T>::TooManyTtlTiers)?,
                relay_cluster: Self::bounded_cluster(relay_cluster)?,
                network_range: Self::bounded_network_range(network_range)?,
                registered_at: frame_system::Pallet::<T>::block_number(),
                status: OperatorStatus::Active,
            };
            Nodes::<T>::insert(&node_id, info);
            if Self::is_validator_role(node_role) {
                ValidatorNodeByOperator::<T>::insert(&operator, &node_id);
            }
            Self::deposit_event(Event::NodeRegistered {
                operator,
                node_id,
                node_role,
            });
            Ok(())
        }

        #[pallet::call_index(2)]
        #[pallet::weight(T::DbWeight::get().reads_writes(5, 3))]
        pub fn submit_validator_probe(
            origin: OriginFor<T>,
            validator_node_id: Vec<u8>,
            target_node_id: Vec<u8>,
            epoch: u64,
            window_start: u64,
            window_end: u64,
            result: ProbeResult,
            signature: Vec<u8>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            Self::ensure_epoch_not_future(epoch)?;
            ensure!(window_start < window_end, Error::<T>::InvalidWindow);
            let validator_node_id = Self::bounded_node_id(validator_node_id)?;
            let target_node_id = Self::bounded_node_id(target_node_id)?;
            Self::ensure_approved_validator(&who, &validator_node_id)?;
            ensure!(
                Nodes::<T>::contains_key(&target_node_id),
                Error::<T>::UnregisteredNode
            );
            let key = (
                validator_node_id.clone(),
                target_node_id.clone(),
                epoch,
                window_start,
            );
            ensure!(
                !ProbeSubmissions::<T>::contains_key(&key),
                Error::<T>::DuplicateProbe
            );

            let submission = ProbeSubmission::<T> {
                validator_node_id: validator_node_id.clone(),
                target_node_id: target_node_id.clone(),
                epoch,
                window_start,
                window_end,
                result,
                signature: Self::bounded_signature(signature)?,
            };
            ProbeSubmissions::<T>::insert(key, submission);

            AvailabilitySummaries::<T>::mutate(&target_node_id, epoch, |summary| {
                summary.validator_probe_count = summary.validator_probe_count.saturating_add(1);
                if Self::probe_is_success(result) {
                    summary.validator_success_weight =
                        summary.validator_success_weight.saturating_add(1);
                } else {
                    summary.validator_failure_weight =
                        summary.validator_failure_weight.saturating_add(4);
                }
                Self::refresh_availability_score(summary);
            });

            if Self::probe_is_success(result) {
                Self::penalize_contradicted_reporters(&target_node_id, epoch);
            }

            let score =
                AvailabilitySummaries::<T>::get(&target_node_id, epoch).availability_score_ppm;
            Self::deposit_event(Event::ValidatorProbeSubmitted {
                validator_node_id,
                target_node_id,
                epoch,
                result,
                availability_score_ppm: score,
            });
            Ok(())
        }

        #[pallet::call_index(3)]
        #[pallet::weight(T::DbWeight::get().reads_writes(6, 4))]
        pub fn submit_relay_outage_report(
            origin: OriginFor<T>,
            reporter_relay_node_id: Vec<u8>,
            target_node_id: Vec<u8>,
            epoch: u64,
            failure_category: FailureCategory,
            observed_count: u32,
            first_observed: u64,
            last_observed: u64,
            reporter_signature: Vec<u8>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            Self::ensure_epoch_not_future(epoch)?;
            ensure!(observed_count > 0, Error::<T>::InvalidWindow);
            ensure!(first_observed <= last_observed, Error::<T>::InvalidWindow);

            let reporter_relay_node_id = Self::bounded_node_id(reporter_relay_node_id)?;
            let target_node_id = Self::bounded_node_id(target_node_id)?;
            let reporter_node = Self::ensure_node_owner_with_role(
                &who,
                &reporter_relay_node_id,
                Self::is_relay_role,
            )
            .map_err(|_| Error::<T>::UnauthorizedReporter)?;
            let target_node =
                Nodes::<T>::get(&target_node_id).ok_or(Error::<T>::UnregisteredNode)?;

            let key = (
                reporter_relay_node_id.clone(),
                target_node_id.clone(),
                epoch,
                first_observed,
                last_observed,
            );
            ensure!(
                !RelayReportSubmissions::<T>::contains_key(&key),
                Error::<T>::DuplicateReport
            );

            let signature = Self::bounded_signature(reporter_signature)?;
            let report = RelayOutageReport::<T> {
                reporter_relay_node_id: reporter_relay_node_id.clone(),
                target_node_id: target_node_id.clone(),
                epoch,
                failure_category,
                observed_count,
                first_observed,
                last_observed,
                reporter_signature: signature,
            };
            RelayReportSubmissions::<T>::insert(key, report);

            let weight = Self::report_weight(&reporter_node, &target_node, observed_count);
            OutageAggregates::<T>::try_mutate(
                &target_node_id,
                epoch,
                |aggregate| -> DispatchResult {
                    aggregate.observed_count =
                        aggregate.observed_count.saturating_add(observed_count);

                    if !aggregate
                        .reporters
                        .iter()
                        .any(|snapshot| snapshot.reporter_node_id == reporter_relay_node_id)
                    {
                        let snapshot = ReporterSnapshot::<T> {
                            reporter_node_id: reporter_relay_node_id.clone(),
                            operator_did: reporter_node.operator_did.clone(),
                            relay_cluster: reporter_node.relay_cluster.clone(),
                            network_range: reporter_node.network_range.clone(),
                            region: reporter_node.region.clone(),
                            weight,
                        };
                        aggregate
                            .reporters
                            .try_push(snapshot)
                            .map_err(|_| Error::<T>::TooManyReports)?;
                        aggregate.reporter_count = aggregate.reporter_count.saturating_add(1);
                        aggregate.independent_weight =
                            aggregate.independent_weight.saturating_add(weight);
                    }
                    Ok(())
                },
            )?;

            let aggregate = OutageAggregates::<T>::get(&target_node_id, epoch);
            AvailabilitySummaries::<T>::mutate(&target_node_id, epoch, |summary| {
                summary.relay_report_count = aggregate.reporter_count;
                summary.relay_failure_weight = if Self::has_corroboration(&aggregate) {
                    aggregate.independent_weight
                } else {
                    0
                };
                Self::refresh_availability_score(summary);
            });

            Self::deposit_event(Event::RelayReportSubmitted {
                reporter_relay_node_id,
                target_node_id,
                epoch,
                weight,
            });
            Ok(())
        }

        #[pallet::call_index(4)]
        #[pallet::weight(T::DbWeight::get().reads_writes(0, 1))]
        pub fn set_validator_approval(
            origin: OriginFor<T>,
            account: T::AccountId,
            approved: bool,
        ) -> DispatchResult {
            T::GovernanceOrigin::ensure_origin(origin)?;
            if approved {
                ApprovedValidatorAccounts::<T>::insert(&account, ());
            } else {
                ApprovedValidatorAccounts::<T>::remove(&account);
            }
            Self::deposit_event(Event::ValidatorApprovalChanged { account, approved });
            Ok(())
        }

        /// Stop or resume every resource-validator action. This is an
        /// emergency control; it preserves the approved account roster so
        /// governance can investigate and selectively revoke before resuming.
        #[pallet::call_index(5)]
        #[pallet::weight(T::DbWeight::get().writes(1))]
        pub fn set_validator_activity_paused(origin: OriginFor<T>, paused: bool) -> DispatchResult {
            T::GovernanceOrigin::ensure_origin(origin)?;
            ValidatorActivityPaused::<T>::put(paused);
            Self::deposit_event(Event::ValidatorActivityPauseChanged { paused });
            Ok(())
        }

        /// Emergency switch for Cache trigger evidence. Disabling evidence
        /// also pauses reward payments so no unfunded evidence gap can arise.
        #[pallet::call_index(6)]
        #[pallet::weight(T::DbWeight::get().reads_writes(2, 2))]
        pub fn set_cache_trigger_evidence_enabled(
            origin: OriginFor<T>,
            enabled: bool,
        ) -> DispatchResult {
            T::GovernanceOrigin::ensure_origin(origin)?;
            if !enabled && !RewardPaymentsPaused::<T>::get() {
                RewardPaymentsPaused::<T>::put(true);
                Self::deposit_event(Event::RewardPaymentsPauseChanged { paused: true });
            }
            CacheTriggerEvidenceEnabled::<T>::put(enabled);
            Self::deposit_event(Event::CacheTriggerEvidenceChanged { enabled });
            Ok(())
        }

        /// Schedule the one-time activation epoch and version for reward
        /// settlement. Evidence collection can remain active before that epoch,
        /// but it can never create a retroactive monetary entitlement.
        #[pallet::call_index(7)]
        #[pallet::weight(T::DbWeight::get().reads_writes(4, 2))]
        pub fn schedule_reward_payments(
            origin: OriginFor<T>,
            start_epoch: u64,
            policy_version: u32,
        ) -> DispatchResult {
            T::GovernanceOrigin::ensure_origin(origin)?;
            ensure!(
                RewardPaymentsStartEpoch::<T>::get().is_none(),
                Error::<T>::RewardPaymentPolicyAlreadyScheduled
            );
            ensure!(
                CacheTriggerEvidenceEnabled::<T>::get(),
                Error::<T>::CacheTriggerEvidenceDisabled
            );
            ensure!(
                policy_version > 0 && start_epoch > Self::current_epoch(),
                Error::<T>::InvalidRewardPaymentActivation
            );
            RewardPaymentsStartEpoch::<T>::put(start_epoch);
            ActiveRewardPolicyVersion::<T>::put(policy_version);
            NextRewardEpochToClose::<T>::put(start_epoch);
            Self::deposit_event(Event::RewardPaymentsScheduled {
                start_epoch,
                policy_version,
            });
            Ok(())
        }

        /// Emergency payment switch. Unpausing requires a previously announced
        /// activation and active Cache queue-depth trigger evidence.
        #[pallet::call_index(8)]
        #[pallet::weight(T::DbWeight::get().reads_writes(4, 1))]
        pub fn set_reward_payments_paused(origin: OriginFor<T>, paused: bool) -> DispatchResult {
            T::GovernanceOrigin::ensure_origin(origin)?;
            if !paused {
                ensure!(
                    RewardPaymentsStartEpoch::<T>::get().is_some()
                        && ActiveRewardPolicyVersion::<T>::get() > 0,
                    Error::<T>::RewardPaymentPolicyNotScheduled
                );
                ensure!(
                    CacheTriggerEvidenceEnabled::<T>::get(),
                    Error::<T>::CacheTriggerEvidenceDisabled
                );
                ensure!(
                    RootSponsor::<T>::get().is_some(),
                    Error::<T>::RootSponsorNotConfigured
                );
            }
            RewardPaymentsPaused::<T>::put(paused);
            Self::deposit_event(Event::RewardPaymentsPauseChanged { paused });
            Ok(())
        }

        #[pallet::call_index(9)]
        #[pallet::weight(T::WeightInfo::set_sponsor_authority())]
        pub fn set_sponsor_authority(
            origin: OriginFor<T>,
            sponsor: T::AccountId,
            enabled: bool,
            can_delegate: bool,
        ) -> DispatchResult {
            let caller = ensure_signed(origin)?;
            let root = RootSponsor::<T>::get().ok_or(Error::<T>::RootSponsorNotConfigured)?;
            if caller != root {
                ensure!(sponsor != caller, Error::<T>::SponsorSelfGrantForbidden);
                let authority = SponsorAuthorities::<T>::get(&caller)
                    .ok_or(Error::<T>::SponsorNotAuthorized)?;
                ensure!(authority.can_delegate, Error::<T>::SponsorCannotDelegate);
                if enabled {
                    ensure!(
                        !SponsorAuthorities::<T>::contains_key(&sponsor),
                        Error::<T>::SponsorAuthorityAlreadyExists
                    );
                } else {
                    let existing = SponsorAuthorities::<T>::get(&sponsor)
                        .ok_or(Error::<T>::SponsorAuthorityNotFound)?;
                    ensure!(
                        existing.granted_by == caller,
                        Error::<T>::SponsorNotAuthorized
                    );
                }
            }
            if enabled {
                SponsorAuthorities::<T>::insert(
                    &sponsor,
                    SponsorAuthority {
                        granted_by: caller.clone(),
                        can_delegate,
                        granted_at_epoch: Self::current_epoch(),
                    },
                );
            } else {
                ensure!(
                    SponsorAuthorities::<T>::contains_key(&sponsor),
                    Error::<T>::SponsorAuthorityNotFound
                );
                SponsorAuthorities::<T>::remove(&sponsor);
            }
            Self::deposit_event(Event::SponsorAuthorityChanged {
                sponsor,
                granted_by: caller,
                enabled,
                can_delegate: enabled && can_delegate,
            });
            Ok(())
        }

        #[pallet::call_index(10)]
        #[pallet::weight(T::WeightInfo::admit_reward_eligible_cache())]
        pub fn admit_reward_eligible_cache(
            origin: OriginFor<T>,
            node_id: Vec<u8>,
        ) -> DispatchResult {
            let sponsor = ensure_signed(origin)?;
            Self::ensure_sponsor(&sponsor)?;
            let node_id = Self::bounded_node_id(node_id)?;
            let node = Nodes::<T>::get(&node_id).ok_or(Error::<T>::UnregisteredNode)?;
            ensure!(
                Self::is_cache_role(node.node_role),
                Error::<T>::UnsupportedNodeRole
            );
            if let Some(existing) = RewardEligibleCaches::<T>::get(&node_id) {
                let revoked_epoch = existing
                    .revoked_epoch
                    .ok_or(Error::<T>::CacheAlreadyRewardEligible)?;
                ensure!(
                    Self::current_epoch() >= revoked_epoch,
                    Error::<T>::CacheAlreadyRewardEligible
                );
                ensure!(
                    Self::current_epoch()
                        >= Self::settlement_close_epoch(revoked_epoch.saturating_sub(1)),
                    Error::<T>::CacheReadmissionTooEarly
                );
            }
            let effective_epoch = Self::current_epoch().saturating_add(1);
            RewardEligibleCaches::<T>::insert(
                &node_id,
                CacheEligibility::<T> {
                    admitted_by: sponsor.clone(),
                    admitted_epoch: effective_epoch,
                    revoked_by: None,
                    revoked_epoch: None,
                },
            );
            Self::deposit_event(Event::CacheRewardEligibilityChanged {
                node_id,
                sponsor,
                eligible: true,
                effective_epoch,
            });
            Ok(())
        }

        #[pallet::call_index(11)]
        #[pallet::weight(T::WeightInfo::revoke_reward_eligible_cache())]
        pub fn revoke_reward_eligible_cache(
            origin: OriginFor<T>,
            node_id: Vec<u8>,
        ) -> DispatchResult {
            let sponsor = ensure_signed(origin)?;
            Self::ensure_sponsor(&sponsor)?;
            let root = RootSponsor::<T>::get().ok_or(Error::<T>::RootSponsorNotConfigured)?;
            let node_id = Self::bounded_node_id(node_id)?;
            let effective_epoch = Self::current_epoch().saturating_add(1);
            RewardEligibleCaches::<T>::try_mutate(&node_id, |maybe| -> DispatchResult {
                let eligibility = maybe.as_mut().ok_or(Error::<T>::CacheNotRewardEligible)?;
                ensure!(
                    sponsor == root || eligibility.admitted_by == sponsor,
                    Error::<T>::SponsorNotAuthorized
                );
                ensure!(
                    eligibility.revoked_epoch.is_none(),
                    Error::<T>::CacheEligibilityAlreadyRevoked
                );
                eligibility.revoked_by = Some(sponsor.clone());
                eligibility.revoked_epoch = Some(effective_epoch);
                Ok(())
            })?;
            Self::deposit_event(Event::CacheRewardEligibilityChanged {
                node_id,
                sponsor,
                eligible: false,
                effective_epoch,
            });
            Ok(())
        }

        #[pallet::call_index(12)]
        #[pallet::weight(T::WeightInfo::propose_root_sponsor())]
        pub fn propose_root_sponsor(
            origin: OriginFor<T>,
            proposed_root: T::AccountId,
        ) -> DispatchResult {
            let current_root = ensure_signed(origin)?;
            ensure!(
                RootSponsor::<T>::get().as_ref() == Some(&current_root),
                Error::<T>::NotRootSponsor
            );
            PendingRootSponsor::<T>::put(&proposed_root);
            Self::deposit_event(Event::RootSponsorTransferProposed {
                current_root,
                proposed_root,
            });
            Ok(())
        }

        #[pallet::call_index(13)]
        #[pallet::weight(T::WeightInfo::accept_root_sponsor())]
        pub fn accept_root_sponsor(origin: OriginFor<T>) -> DispatchResult {
            let new_root = ensure_signed(origin)?;
            let pending =
                PendingRootSponsor::<T>::get().ok_or(Error::<T>::PendingRootSponsorNotFound)?;
            ensure!(pending == new_root, Error::<T>::NotPendingRootSponsor);
            let previous_root =
                RootSponsor::<T>::get().ok_or(Error::<T>::RootSponsorNotConfigured)?;
            RootSponsor::<T>::put(&new_root);
            PendingRootSponsor::<T>::kill();
            Self::deposit_event(Event::RootSponsorTransferred {
                previous_root,
                new_root,
            });
            Ok(())
        }

        #[pallet::call_index(14)]
        #[pallet::weight(T::WeightInfo::issue_cache_trigger_ticket())]
        pub fn issue_cache_trigger_ticket(
            origin: OriginFor<T>,
            validator_node_id: Vec<u8>,
            cache_node_id: Vec<u8>,
            recipient_did: Vec<u8>,
            trigger_message_hash: Vec<u8>,
            ttl_blocks: u32,
            nonce: u64,
            signature: Vec<u8>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            Self::ensure_cache_trigger_evidence_active()?;
            let epoch = Self::current_epoch();
            let slot = Self::current_trigger_slot();
            ensure!(
                slot < T::TriggerTicketsPerEpoch::get(),
                Error::<T>::InvalidTriggerSlot
            );
            let validator_node_id = Self::bounded_node_id(validator_node_id)?;
            let validator = Self::ensure_approved_validator(&who, &validator_node_id)?;
            let cache_node_id = Self::bounded_node_id(cache_node_id)?;
            let cache = Nodes::<T>::get(&cache_node_id).ok_or(Error::<T>::UnregisteredNode)?;
            ensure!(
                Self::is_cache_role(cache.node_role),
                Error::<T>::UnsupportedNodeRole
            );
            ensure!(
                validator.operator != cache.operator,
                Error::<T>::SelfValidationForbidden
            );
            Self::ensure_cache_eligible_at(&cache_node_id, epoch)?;
            let (slot_open, slot_end, epoch_anchor_hash) =
                Self::trigger_slot_window(&cache_node_id, epoch, slot);
            let current_block_u64 =
                frame_system::Pallet::<T>::block_number().saturated_into::<u64>();
            ensure!(
                current_block_u64 >= slot_open && current_block_u64 < slot_end,
                Error::<T>::TriggerSlotNotOpen
            );
            ensure!(
                !CacheTriggerTickets::<T>::contains_key(&cache_node_id, (epoch, slot)),
                Error::<T>::DuplicateCacheTriggerTicket
            );
            let recipient_did = Self::bounded_did(recipient_did)?;
            ensure!(
                recipient_did == cache.operator_did,
                Error::<T>::CacheTriggerRecipientMismatch
            );
            ensure!(
                T::DidProvider::did_exists(&recipient_did),
                Error::<T>::OperatorDidNotRegistered
            );
            let trigger_message_hash = Self::bounded_exact_proof_hash(trigger_message_hash)?;
            ensure!(
                ValidatorTriggerNonces::<T>::get(&who) == nonce,
                Error::<T>::InvalidCacheTriggerSignature
            );
            let issued_at = frame_system::Pallet::<T>::block_number();
            let retention_check_at = issued_at.saturating_add(T::TriggerRetentionBlocks::get());
            let expires_at = issued_at.saturating_add(ttl_blocks.into());
            ensure!(
                ttl_blocks > 0 && expires_at > retention_check_at,
                Error::<T>::InvalidWindow
            );
            ensure!(
                expires_at < Self::evidence_close_block(epoch),
                Error::<T>::CacheTriggerEvidenceWindowClosed
            );
            let ticket_id = Self::canonical_cache_trigger_ticket_id(
                &cache_node_id,
                epoch,
                slot,
                &epoch_anchor_hash,
            )?;
            let signature = Self::bounded_signature(signature)?;
            let signing_payload = Self::cache_trigger_issuance_payload(
                &who,
                &ticket_id,
                &validator_node_id,
                &cache_node_id,
                &recipient_did,
                &trigger_message_hash,
                ttl_blocks,
                nonce,
                epoch,
                slot,
            );
            ensure!(
                T::DidProvider::verify_did_signature(
                    validator.operator_did.as_slice(),
                    b"root",
                    &signing_payload,
                    signature.as_slice(),
                ),
                Error::<T>::InvalidCacheTriggerSignature
            );
            ValidatorTriggerNonces::<T>::insert(&who, nonce.saturating_add(1));
            CacheTriggerTickets::<T>::insert(
                &cache_node_id,
                (epoch, slot),
                CacheTriggerTicket::<T> {
                    ticket_id: ticket_id.clone(),
                    cache_node_id: cache_node_id.clone(),
                    recipient_did,
                    trigger_message_hash,
                    epoch,
                    slot,
                    issued_at,
                    retention_check_at,
                    expires_at,
                    issuer_validator_node_id: validator_node_id,
                    issuer_signature: signature,
                    receipt: None,
                    positive_attestations: 0,
                    negative_attestations: 0,
                    canonical_evidence_hash: None,
                    verified: false,
                    failed: false,
                },
            );
            CacheTriggerTicketById::<T>::insert(&ticket_id, (cache_node_id.clone(), epoch, slot));
            CacheQueueDepthEpochs::<T>::mutate(&cache_node_id, epoch, |summary| {
                summary.tickets_issued = summary.tickets_issued.saturating_add(1);
            });
            Self::deposit_event(Event::CacheTriggerTicketIssued {
                ticket_id,
                cache_node_id,
                epoch,
                slot,
                retention_check_at,
                expires_at,
            });
            Ok(())
        }

        #[pallet::call_index(15)]
        #[pallet::weight(T::WeightInfo::submit_cache_trigger_receipt())]
        pub fn submit_cache_trigger_receipt(
            origin: OriginFor<T>,
            cache_node_id: Vec<u8>,
            ticket_id: Vec<u8>,
            message_id: Vec<u8>,
            queue_depth_before: u64,
            queue_depth_after: u64,
            accepted_at: u64,
            stored_at: u64,
            receipt_hash: Vec<u8>,
            signature: Vec<u8>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            Self::ensure_cache_trigger_evidence_active()?;
            let cache_node_id = Self::bounded_node_id(cache_node_id)?;
            let cache =
                Self::ensure_node_owner_with_role(&who, &cache_node_id, Self::is_cache_role)?;
            let ticket_id = Self::bounded_exact_proof_hash(ticket_id)?;
            let (stored_node_id, epoch, slot) = CacheTriggerTicketById::<T>::get(&ticket_id)
                .ok_or(Error::<T>::CacheTriggerTicketNotFound)?;
            ensure!(
                stored_node_id == cache_node_id,
                Error::<T>::CacheTriggerTicketNotFound
            );
            ensure!(
                Self::current_epoch() <= Self::evidence_close_epoch(epoch),
                Error::<T>::CacheTriggerEvidenceWindowClosed
            );
            let mut ticket = CacheTriggerTickets::<T>::get(&cache_node_id, (epoch, slot))
                .ok_or(Error::<T>::CacheTriggerTicketNotFound)?;
            ensure!(
                ticket.receipt.is_none(),
                Error::<T>::CacheTriggerReceiptAlreadySubmitted
            );
            let message_id = Self::bounded_message_id(message_id)?;
            ensure!(
                queue_depth_after == queue_depth_before.saturating_add(1)
                    && queue_depth_after > queue_depth_before
                    && accepted_at > 0
                    && accepted_at <= stored_at,
                Error::<T>::InvalidCacheTriggerReceipt
            );
            let receipt_hash = Self::bounded_exact_proof_hash(receipt_hash)?;
            let signature = Self::bounded_signature(signature)?;
            let signing_payload = Self::cache_trigger_receipt_payload(
                &ticket,
                &message_id,
                queue_depth_before,
                queue_depth_after,
                accepted_at,
                stored_at,
                &receipt_hash,
            );
            ensure!(
                T::DidProvider::verify_did_signature(
                    cache.operator_did.as_slice(),
                    b"root",
                    &signing_payload,
                    signature.as_slice(),
                ),
                Error::<T>::InvalidCacheTriggerSignature
            );
            ticket.receipt = Some(CacheTriggerReceipt::<T> {
                ticket_id: ticket_id.clone(),
                cache_node_id: cache_node_id.clone(),
                message_id: message_id.clone(),
                queue_depth_before,
                queue_depth_after,
                accepted_at,
                stored_at,
                receipt_hash,
                signature,
            });
            CacheTriggerTickets::<T>::insert(&cache_node_id, (epoch, slot), ticket);
            Self::deposit_event(Event::CacheTriggerReceiptSubmitted {
                ticket_id,
                cache_node_id,
                message_id,
                queue_depth_before,
                queue_depth_after,
            });
            Ok(())
        }

        #[pallet::call_index(16)]
        #[pallet::weight(T::WeightInfo::attest_cache_trigger_ticket())]
        pub fn attest_cache_trigger_ticket(
            origin: OriginFor<T>,
            validator_node_id: Vec<u8>,
            ticket_id: Vec<u8>,
            accepted: bool,
            retained: bool,
            retrieved: bool,
            purged: bool,
            evidence_hash: Vec<u8>,
            signature: Vec<u8>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            Self::ensure_cache_trigger_evidence_active()?;
            let validator_node_id = Self::bounded_node_id(validator_node_id)?;
            let validator = Self::ensure_approved_validator(&who, &validator_node_id)?;
            let ticket_id = Self::bounded_exact_proof_hash(ticket_id)?;
            let (cache_node_id, epoch, slot) = CacheTriggerTicketById::<T>::get(&ticket_id)
                .ok_or(Error::<T>::CacheTriggerTicketNotFound)?;
            ensure!(
                Self::current_epoch() <= Self::evidence_close_epoch(epoch),
                Error::<T>::CacheTriggerEvidenceWindowClosed
            );
            let mut ticket = CacheTriggerTickets::<T>::get(&cache_node_id, (epoch, slot))
                .ok_or(Error::<T>::CacheTriggerTicketNotFound)?;
            let cache = Nodes::<T>::get(&cache_node_id).ok_or(Error::<T>::UnregisteredNode)?;
            ensure!(
                validator.operator != cache.operator,
                Error::<T>::SelfValidationForbidden
            );
            let receipt_hash = ticket
                .receipt
                .as_ref()
                .map(|receipt| receipt.receipt_hash.clone())
                .ok_or(Error::<T>::InvalidCacheTriggerAttestation)?;
            ensure!(
                frame_system::Pallet::<T>::block_number() > ticket.expires_at,
                Error::<T>::CacheTriggerAttestationTooEarly
            );
            ensure!(
                !ticket.verified && !ticket.failed,
                Error::<T>::CacheTriggerTicketAlreadyResolved
            );
            ensure!(
                !CacheTriggerAttestations::<T>::contains_key(&ticket_id, &validator.operator_did),
                Error::<T>::DuplicateCacheTriggerAttestation
            );
            let evidence_hash = Self::bounded_exact_proof_hash(evidence_hash)?;
            let signature = Self::bounded_signature(signature)?;
            let signing_payload = Self::cache_trigger_attestation_payload(
                &ticket_id,
                &validator_node_id,
                accepted,
                retained,
                retrieved,
                purged,
                &evidence_hash,
            );
            ensure!(
                T::DidProvider::verify_did_signature(
                    validator.operator_did.as_slice(),
                    b"root",
                    &signing_payload,
                    signature.as_slice(),
                ),
                Error::<T>::InvalidCacheTriggerAttestationSignature
            );
            let lifecycle_success = accepted && retained && retrieved && purged;
            // The finalized Cache receipt is the validator-independent evidence
            // commitment. Lifecycle observations are carried by the four signed
            // booleans; accepting any other digest would let the first validator
            // choose an unverifiable canonical value.
            let evidence_consistent = evidence_hash == receipt_hash
                && ticket
                    .canonical_evidence_hash
                    .as_ref()
                    .map(|canonical| canonical == &evidence_hash)
                    .unwrap_or(true);
            let success = lifecycle_success && evidence_consistent;
            CacheTriggerAttestations::<T>::insert(
                &ticket_id,
                &validator.operator_did,
                CacheTriggerAttestation::<T> {
                    validator_node_id: validator_node_id.clone(),
                    accepted,
                    retained,
                    retrieved,
                    purged,
                    evidence_hash: evidence_hash.clone(),
                    signature,
                },
            );
            if success {
                if ticket.canonical_evidence_hash.is_none() {
                    ticket.canonical_evidence_hash = Some(evidence_hash.clone());
                }
                ticket.positive_attestations = ticket.positive_attestations.saturating_add(1);
            } else {
                ticket.negative_attestations = ticket.negative_attestations.saturating_add(1);
                // A single independently authenticated lifecycle failure is
                // terminal. Positive votes can never override known failure.
                ticket.failed = true;
            }
            let threshold = T::RequiredTriggerAttestations::get().max(1);
            if !ticket.failed && ticket.positive_attestations >= threshold {
                ticket.verified = true;
                let depth = ticket
                    .receipt
                    .as_ref()
                    .map(|receipt| receipt.queue_depth_before)
                    .ok_or(Error::<T>::InvalidCacheTriggerAttestation)?;
                CacheQueueDepthEpochs::<T>::mutate(&cache_node_id, epoch, |summary| {
                    summary.tickets_verified = summary.tickets_verified.saturating_add(1);
                    summary.depth_sum = summary.depth_sum.saturating_add(depth as u128);
                });
            }
            CacheTriggerTickets::<T>::insert(&cache_node_id, (epoch, slot), &ticket);
            Self::deposit_event(Event::CacheTriggerTicketAttested {
                ticket_id,
                validator_node_id,
                success,
                positive_attestations: ticket.positive_attestations,
                negative_attestations: ticket.negative_attestations,
                verified: ticket.verified,
            });
            Ok(())
        }

        /// Freeze one Cache's strict six-ticket result after the evidence
        /// window. Any signed keeper may call this during the bounded Cache
        /// finalization phase. Missing or failed tickets produce zero bytes.
        #[pallet::call_index(17)]
        #[pallet::weight(T::WeightInfo::finalize_cache_queue_depth_epoch())]
        pub fn finalize_cache_queue_depth_epoch(
            origin: OriginFor<T>,
            cache_node_id: Vec<u8>,
            epoch: u64,
        ) -> DispatchResult {
            let _keeper = ensure_signed(origin)?;
            let current = Self::current_epoch();
            ensure!(
                current > Self::evidence_close_epoch(epoch)
                    && current < Self::operator_freeze_epoch(epoch),
                Error::<T>::CacheRawRewardWindowClosed
            );
            let cache_node_id = Self::bounded_node_id(cache_node_id)?;
            Self::ensure_cache_eligible_at(&cache_node_id, epoch)?;
            let node = Nodes::<T>::get(&cache_node_id).ok_or(Error::<T>::UnregisteredNode)?;
            CacheQueueDepthEpochs::<T>::try_mutate(
                &cache_node_id,
                epoch,
                |summary| -> DispatchResult {
                    ensure!(
                        !summary.finalized,
                        Error::<T>::CacheQueueDepthAlreadyFinalized
                    );
                    let required = T::TriggerTicketsPerEpoch::get().max(1);
                    let complete =
                        summary.tickets_issued == required && summary.tickets_verified == required;
                    summary.average_depth = if complete {
                        summary
                            .depth_sum
                            .checked_div(required as u128)
                            .unwrap_or(0)
                            .min(u64::MAX as u128) as u64
                    } else {
                        0
                    };
                    summary.average_bytes = (summary.average_depth as u128)
                        .saturating_mul(T::MaxMessageSizeBytes::get() as u128);
                    summary.finalized = true;
                    OperatorQueueDepthEpochs::<T>::mutate(
                        &node.operator,
                        epoch,
                        |operator_summary| {
                            operator_summary.total_average_bytes = operator_summary
                                .total_average_bytes
                                .saturating_add(summary.average_bytes);
                            operator_summary.finalized_nodes =
                                operator_summary.finalized_nodes.saturating_add(1);
                        },
                    );
                    Self::deposit_event(Event::CacheQueueDepthEpochFinalized {
                        node_id: cache_node_id.clone(),
                        epoch,
                        tickets_issued: summary.tickets_issued,
                        tickets_verified: summary.tickets_verified,
                        average_depth: summary.average_depth,
                        average_bytes: summary.average_bytes,
                    });
                    Ok(())
                },
            )?;
            Ok(())
        }

        #[pallet::call_index(18)]
        #[pallet::weight(T::WeightInfo::freeze_operator_queue_depth_epoch())]
        pub fn freeze_operator_queue_depth_epoch(
            origin: OriginFor<T>,
            operator: T::AccountId,
            epoch: u64,
        ) -> DispatchResult {
            let _keeper = ensure_signed(origin)?;
            ensure!(
                Self::current_epoch() >= Self::operator_freeze_epoch(epoch),
                Error::<T>::OperatorQueueDepthFreezeTooEarly
            );
            OperatorQueueDepthEpochs::<T>::try_mutate(
                &operator,
                epoch,
                |summary| -> DispatchResult {
                    ensure!(!summary.frozen, Error::<T>::OperatorQueueDepthAlreadyFrozen);
                    summary.multiplier_ppm =
                        Self::queue_depth_storage_multiplier_ppm(summary.total_average_bytes);
                    summary.frozen = true;
                    Self::deposit_event(Event::OperatorQueueDepthFrozen {
                        operator: operator.clone(),
                        epoch,
                        total_average_bytes: summary.total_average_bytes,
                        multiplier_ppm: summary.multiplier_ppm,
                    });
                    Ok(())
                },
            )
        }

        #[pallet::call_index(19)]
        #[pallet::weight(T::WeightInfo::finalize_cache_raw_reward())]
        pub fn finalize_cache_raw_reward(
            origin: OriginFor<T>,
            cache_node_id: Vec<u8>,
            epoch: u64,
        ) -> DispatchResult {
            let _keeper = ensure_signed(origin)?;
            ensure!(
                Self::current_epoch() >= Self::operator_freeze_epoch(epoch)
                    && Self::current_epoch() < Self::settlement_close_epoch(epoch),
                Error::<T>::CacheRawRewardWindowClosed
            );
            let policy_version = Self::ensure_reward_policy_for_epoch(epoch)?;
            let cache_node_id = Self::bounded_node_id(cache_node_id)?;
            ensure!(
                !CacheRewardRecords::<T>::contains_key(&cache_node_id, epoch),
                Error::<T>::CacheRawRewardAlreadyFinalized
            );
            Self::ensure_cache_eligible_at(&cache_node_id, epoch)?;
            let node = Nodes::<T>::get(&cache_node_id).ok_or(Error::<T>::UnregisteredNode)?;
            let node_summary = CacheQueueDepthEpochs::<T>::get(&cache_node_id, epoch);
            ensure!(
                node_summary.finalized,
                Error::<T>::OperatorQueueDepthNotFrozen
            );
            let operator_summary = OperatorQueueDepthEpochs::<T>::get(&node.operator, epoch);
            ensure!(
                operator_summary.frozen,
                Error::<T>::OperatorQueueDepthNotFrozen
            );
            let strict_quality = node_summary.tickets_issued == T::TriggerTicketsPerEpoch::get()
                && node_summary.tickets_verified == T::TriggerTicketsPerEpoch::get();
            let quality_ppm = if strict_quality { PPM as u32 } else { 0 };
            let storage_multiplier_ppm = if strict_quality
                && operator_summary.total_average_bytes > 0
                && node_summary.average_bytes > 0
            {
                (operator_summary.multiplier_ppm as u128)
                    .saturating_mul(node_summary.average_bytes)
                    .checked_div(operator_summary.total_average_bytes)
                    .unwrap_or(0)
                    .min(u32::MAX as u128) as u32
            } else {
                0
            };
            let raw_amount = Self::calculate_amount(quality_ppm, storage_multiplier_ppm);
            let raw_prefix_before = EpochRawRewardTotals::<T>::get(epoch);
            EpochRawRewardTotals::<T>::insert(epoch, raw_prefix_before.saturating_add(raw_amount));
            EpochRawRewardRecordCounts::<T>::mutate(epoch, |count| {
                *count = count.saturating_add(1)
            });
            CacheRewardRecords::<T>::insert(
                &cache_node_id,
                epoch,
                CacheRewardRecord::<T> {
                    operator: node.operator.clone(),
                    average_bytes: node_summary.average_bytes,
                    quality_ppm,
                    storage_multiplier_ppm,
                    raw_amount,
                    raw_prefix_before,
                    policy_version,
                    claimed_amount: None,
                },
            );
            Self::deposit_event(Event::CacheRawRewardFinalized {
                node_id: cache_node_id,
                operator: node.operator,
                epoch,
                average_bytes: node_summary.average_bytes,
                quality_ppm,
                storage_multiplier_ppm,
                raw_amount,
            });
            Ok(())
        }

        #[pallet::call_index(20)]
        #[pallet::weight(T::WeightInfo::close_reward_epoch())]
        #[frame_support::transactional]
        pub fn close_reward_epoch(origin: OriginFor<T>, epoch: u64) -> DispatchResult {
            let _keeper = ensure_signed(origin)?;
            ensure!(
                !RewardPaymentsPaused::<T>::get(),
                Error::<T>::RewardPaymentsPaused
            );
            ensure!(
                Self::current_epoch() >= Self::settlement_close_epoch(epoch),
                Error::<T>::RewardEpochCloseTooEarly
            );
            ensure!(
                epoch == NextRewardEpochToClose::<T>::get(),
                Error::<T>::InvalidEpoch
            );
            ensure!(
                !EpochSettlements::<T>::contains_key(epoch),
                Error::<T>::RewardEpochAlreadyClosed
            );
            let _policy_version = Self::ensure_reward_policy_for_epoch(epoch)?;
            let reward_year = Self::reward_year_for_epoch(epoch);
            if !RewardYearStates::<T>::contains_key(reward_year) {
                Self::initialize_reward_year(reward_year)?;
            }
            let mut year_state = RewardYearStates::<T>::get(reward_year)
                .ok_or(Error::<T>::RewardYearNotInitialized)?;
            let raw_total = EpochRawRewardTotals::<T>::get(epoch);
            let annual_envelope = year_state
                .opening_free_reserve
                .saturating_add(year_state.supplemental_cap);
            let index = epoch
                .checked_rem(T::EpochsPerRewardYear::get().max(1))
                .unwrap_or(0)
                .saturating_add(1);
            let accrued_limit = Self::mul_div_balance_u64(
                annual_envelope,
                index,
                T::EpochsPerRewardYear::get().max(1),
            );
            let available = accrued_limit.saturating_sub(year_state.committed);
            let distributable = raw_total.min(available);
            let pot = Self::reward_pot_account();
            let outstanding = OutstandingRewardLiabilities::<T>::get();
            let free_backing = T::Currency::free_balance(&pot).saturating_sub(outstanding);
            if free_backing < distributable {
                let shortfall = distributable.saturating_sub(free_backing);
                ensure!(
                    year_state.supplemental_minted.saturating_add(shortfall)
                        <= year_state.supplemental_cap,
                    Error::<T>::SupplementalInflationCapExceeded
                );
                let reward_ref = (
                    b"openpayload:supplemental-emission:v1".as_slice(),
                    reward_year,
                    year_state.supplemental_minted,
                    shortfall,
                )
                    .encode();
                pallet_opal::Pallet::<T>::mint_reward_to(&pot, shortfall, reward_ref)?;
                year_state.supplemental_minted =
                    year_state.supplemental_minted.saturating_add(shortfall);
                Self::deposit_event(Event::SupplementalRewardsMinted {
                    reward_year,
                    amount: shortfall,
                });
            }
            year_state.committed = year_state.committed.saturating_add(distributable);
            RewardYearStates::<T>::insert(reward_year, &year_state);
            OutstandingRewardLiabilities::<T>::mutate(|liabilities| {
                *liabilities = liabilities.saturating_add(distributable)
            });
            EpochSettlements::<T>::insert(
                epoch,
                EpochSettlement {
                    reward_year,
                    raw_total,
                    distributable,
                    record_count: EpochRawRewardRecordCounts::<T>::get(epoch),
                    claimed_count: 0,
                    claimed_total: Zero::zero(),
                    closed: true,
                },
            );
            NextRewardEpochToClose::<T>::put(epoch.saturating_add(1));
            Self::deposit_event(Event::RewardEpochClosed {
                epoch,
                reward_year,
                raw_total,
                distributable,
            });
            Ok(())
        }

        #[pallet::call_index(21)]
        #[pallet::weight(T::WeightInfo::claim_cache_reward())]
        #[frame_support::transactional]
        pub fn claim_cache_reward(
            origin: OriginFor<T>,
            cache_node_id: Vec<u8>,
            epoch: u64,
        ) -> DispatchResult {
            let _keeper = ensure_signed(origin)?;
            ensure!(
                !RewardPaymentsPaused::<T>::get(),
                Error::<T>::RewardPaymentsPaused
            );
            let cache_node_id = Self::bounded_node_id(cache_node_id)?;
            let mut record = CacheRewardRecords::<T>::get(&cache_node_id, epoch)
                .ok_or(Error::<T>::CacheRewardNotFinalized)?;
            ensure!(
                record.claimed_amount.is_none(),
                Error::<T>::CacheRewardAlreadyClaimed
            );
            let mut settlement =
                EpochSettlements::<T>::get(epoch).ok_or(Error::<T>::RewardEpochNotClosed)?;
            let amount = Self::proportional_position_amount(
                settlement.distributable,
                settlement.raw_total,
                record.raw_prefix_before,
                record.raw_amount,
            );
            record.claimed_amount = Some(amount);
            settlement.claimed_count = settlement.claimed_count.saturating_add(1);
            settlement.claimed_total = settlement.claimed_total.saturating_add(amount);
            CacheRewardRecords::<T>::insert(&cache_node_id, epoch, &record);
            EpochSettlements::<T>::insert(epoch, &settlement);
            OperatorAccruedRewards::<T>::mutate(&record.operator, |accrued| {
                *accrued = accrued.saturating_add(amount)
            });
            Self::deposit_event(Event::CacheRewardClaimed {
                node_id: cache_node_id,
                operator: record.operator.clone(),
                epoch,
                amount,
            });
            Self::try_pay_accrued(&record.operator)?;
            Ok(())
        }

        #[pallet::call_index(22)]
        #[pallet::weight(T::WeightInfo::withdraw_accrued_reward())]
        pub fn withdraw_accrued_reward(origin: OriginFor<T>) -> DispatchResult {
            let operator = ensure_signed(origin)?;
            ensure!(
                !RewardPaymentsPaused::<T>::get(),
                Error::<T>::RewardPaymentsPaused
            );
            let amount = OperatorAccruedRewards::<T>::get(&operator);
            ensure!(!amount.is_zero(), Error::<T>::NoAccruedReward);
            ensure!(
                !T::Currency::free_balance(&operator).is_zero()
                    || amount >= T::Currency::minimum_balance(),
                Error::<T>::AccruedRewardBelowExistentialDeposit
            );
            Self::pay_accrued(&operator, amount)
        }

        #[pallet::call_index(23)]
        #[pallet::weight(T::WeightInfo::prune_cache_reward_history())]
        pub fn prune_cache_reward_history(
            origin: OriginFor<T>,
            cache_node_id: Vec<u8>,
            epoch: u64,
        ) -> DispatchResult {
            let _keeper = ensure_signed(origin)?;
            ensure!(
                Self::current_epoch()
                    > epoch.saturating_add(CacheRewardHistoryRetentionEpochsValue::<T>::get()),
                Error::<T>::CacheRewardHistoryRetentionActive
            );
            let cache_node_id = Self::bounded_node_id(cache_node_id)?;
            ensure!(
                EpochSettlements::<T>::contains_key(epoch),
                Error::<T>::RewardEpochNotClosed
            );
            if let Some(reward) = CacheRewardRecords::<T>::get(&cache_node_id, epoch) {
                ensure!(
                    reward.claimed_amount.is_some(),
                    Error::<T>::CacheRewardNotClaimed
                );
            }
            let mut ticket_count_removed = 0u32;
            let mut attestation_keys_removed = 0u32;
            let mut complete = true;
            for slot in 0..T::TriggerTicketsPerEpoch::get() {
                let Some(ticket) = CacheTriggerTickets::<T>::get(&cache_node_id, (epoch, slot))
                else {
                    continue;
                };
                let (cursor, _, removed, _) = CacheTriggerAttestations::<T>::clear_prefix(
                    &ticket.ticket_id,
                    T::MaxPruneKeysPerCall::get().max(1),
                    None,
                )
                .deconstruct();
                attestation_keys_removed = attestation_keys_removed.saturating_add(removed);
                if cursor.is_some() {
                    complete = false;
                    continue;
                }
                CacheTriggerTicketById::<T>::remove(&ticket.ticket_id);
                CacheTriggerTickets::<T>::remove(&cache_node_id, (epoch, slot));
                ticket_count_removed = ticket_count_removed.saturating_add(1);
            }
            if complete {
                CacheQueueDepthEpochs::<T>::remove(&cache_node_id, epoch);
                CacheRewardRecords::<T>::remove(&cache_node_id, epoch);
            }
            Self::deposit_event(Event::CacheRewardHistoryPruned {
                node_id: cache_node_id,
                epoch,
                ticket_count_removed,
                attestation_keys_removed,
                complete,
            });
            Ok(())
        }

        #[pallet::call_index(24)]
        #[pallet::weight(T::WeightInfo::prune_operator_queue_depth_history())]
        pub fn prune_operator_queue_depth_history(
            origin: OriginFor<T>,
            operator: T::AccountId,
            epoch: u64,
        ) -> DispatchResult {
            let _keeper = ensure_signed(origin)?;
            ensure!(
                Self::current_epoch()
                    > epoch.saturating_add(CacheRewardHistoryRetentionEpochsValue::<T>::get()),
                Error::<T>::CacheRewardHistoryRetentionActive
            );
            ensure!(
                Self::current_epoch() >= Self::settlement_close_epoch(epoch),
                Error::<T>::CacheRawRewardWindowClosed
            );
            ensure!(
                EpochSettlements::<T>::contains_key(epoch),
                Error::<T>::RewardEpochNotClosed
            );
            OperatorQueueDepthEpochs::<T>::remove(&operator, epoch);
            Self::deposit_event(Event::OperatorQueueDepthHistoryPruned { operator, epoch });
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        /// SCALE-encoded payload signed by the registered DID root key before
        /// an account may bind that DID as its resource-operator identity.
        pub fn operator_registration_payload(
            operator: &T::AccountId,
            operator_did: &[u8],
            bond: &Option<BalanceOf<T>>,
        ) -> Vec<u8> {
            let genesis_hash = frame_system::Pallet::<T>::block_hash(BlockNumberFor::<T>::zero());
            (
                OPERATOR_REGISTRATION_DOMAIN,
                genesis_hash,
                operator,
                operator_did,
                bond,
            )
                .encode()
        }

        pub fn current_epoch() -> u64 {
            let duration = T::EpochDuration::get().saturated_into::<u64>().max(1);
            frame_system::Pallet::<T>::block_number().saturated_into::<u64>() / duration
        }

        pub fn reward_pot_account() -> T::AccountId {
            T::RewardPalletId::get().into_account_truncating()
        }

        pub fn reward_year_for_epoch(epoch: u64) -> u64 {
            epoch / T::EpochsPerRewardYear::get().max(1)
        }

        fn current_trigger_slot() -> u32 {
            let duration = T::EpochDuration::get().saturated_into::<u64>().max(1);
            let slots = T::TriggerTicketsPerEpoch::get().max(1) as u64;
            let block = frame_system::Pallet::<T>::block_number().saturated_into::<u64>();
            let within_epoch = block % duration;
            within_epoch
                .saturating_mul(slots)
                .checked_div(duration)
                .unwrap_or(0)
                .min(slots.saturating_sub(1)) as u32
        }

        /// Return the deterministic opening and exclusive end block for one
        /// Cache's slot, plus the finalized epoch-anchor hash used by the
        /// schedule and canonical ticket id.
        pub fn trigger_slot_window(
            cache_node_id: &NodeIdOf<T>,
            epoch: u64,
            slot: u32,
        ) -> (u64, u64, T::Hash) {
            let duration = T::EpochDuration::get().saturated_into::<u64>().max(1);
            let slots = T::TriggerTicketsPerEpoch::get().max(1) as u64;
            let epoch_start = epoch.saturating_mul(duration);
            let slot_start = epoch_start.saturating_add(
                duration
                    .saturating_mul(slot as u64)
                    .checked_div(slots)
                    .unwrap_or(0),
            );
            let slot_end = epoch_start.saturating_add(
                duration
                    .saturating_mul((slot as u64).saturating_add(1))
                    .checked_div(slots)
                    .unwrap_or(duration),
            );
            let anchor_number = epoch_start.saturating_sub(1);
            let anchor_hash = frame_system::Pallet::<T>::block_hash(
                anchor_number.saturated_into::<BlockNumberFor<T>>(),
            );
            let opening = Self::trigger_slot_opening_from_anchor(
                cache_node_id,
                epoch,
                slot,
                slot_start,
                slot_end,
                &anchor_hash,
            );
            (
                opening,
                slot_end.max(opening.saturating_add(1)),
                anchor_hash,
            )
        }

        pub fn trigger_slot_opening_from_anchor(
            cache_node_id: &NodeIdOf<T>,
            epoch: u64,
            slot: u32,
            slot_start: u64,
            slot_end: u64,
            anchor_hash: &T::Hash,
        ) -> u64 {
            let random = Self::ticket_hash_u64(&(
                b"openpayload:cache-trigger-slot:v1".as_slice(),
                anchor_hash,
                cache_node_id,
                epoch,
                slot,
            ));
            let width = slot_end.saturating_sub(slot_start).max(1);
            // Randomize only within the first half of the slot. This retains
            // unpredictability while guaranteeing at least half of the
            // subwindow remains available for a validator to observe the
            // finalized anchor and submit the trigger.
            let opening_range = width.saturating_add(1).checked_div(2).unwrap_or(1).max(1);
            slot_start.saturating_add(random % opening_range)
        }

        fn evidence_close_epoch(epoch: u64) -> u64 {
            epoch.saturating_add(T::EvidenceWindowEpochs::get())
        }

        fn evidence_close_block(epoch: u64) -> BlockNumberFor<T> {
            let close_epoch = Self::evidence_close_epoch(epoch).saturating_add(1);
            let duration = T::EpochDuration::get().saturated_into::<u64>().max(1);
            close_epoch
                .saturating_mul(duration)
                .saturated_into::<BlockNumberFor<T>>()
        }

        fn operator_freeze_epoch(epoch: u64) -> u64 {
            Self::evidence_close_epoch(epoch).saturating_add(2)
        }

        fn settlement_close_epoch(epoch: u64) -> u64 {
            Self::operator_freeze_epoch(epoch)
                .saturating_add(T::RewardFinalizationWindowEpochs::get().max(1))
        }

        fn ensure_sponsor(who: &T::AccountId) -> DispatchResult {
            let root = RootSponsor::<T>::get().ok_or(Error::<T>::RootSponsorNotConfigured)?;
            ensure!(
                *who == root || SponsorAuthorities::<T>::contains_key(who),
                Error::<T>::SponsorNotAuthorized
            );
            Ok(())
        }

        fn ensure_cache_eligible_at(node_id: &NodeIdOf<T>, epoch: u64) -> DispatchResult {
            let eligibility = RewardEligibleCaches::<T>::get(node_id)
                .ok_or(Error::<T>::CacheNotRewardEligible)?;
            ensure!(
                epoch >= eligibility.admitted_epoch,
                Error::<T>::CacheNotRewardEligible
            );
            ensure!(
                eligibility
                    .revoked_epoch
                    .map(|revoked_epoch| epoch < revoked_epoch)
                    .unwrap_or(true),
                Error::<T>::CacheNotRewardEligible
            );
            Ok(())
        }

        fn ensure_reward_policy_for_epoch(epoch: u64) -> Result<u32, Error<T>> {
            let start_epoch = RewardPaymentsStartEpoch::<T>::get()
                .ok_or(Error::<T>::RewardPaymentPolicyNotScheduled)?;
            ensure!(
                epoch >= start_epoch,
                Error::<T>::InvalidRewardPaymentActivation
            );
            let policy_version = ActiveRewardPolicyVersion::<T>::get();
            ensure!(
                policy_version > 0,
                Error::<T>::RewardPaymentPolicyNotScheduled
            );
            Ok(policy_version)
        }

        pub fn canonical_cache_trigger_ticket_id(
            cache_node_id: &NodeIdOf<T>,
            epoch: u64,
            slot: u32,
            epoch_anchor_hash: &T::Hash,
        ) -> Result<ProofHashOf<T>, Error<T>> {
            let raw_ticket_id = T::Hashing::hash(
                &(
                    CACHE_TRIGGER_ISSUANCE_DOMAIN,
                    frame_system::Pallet::<T>::block_hash(BlockNumberFor::<T>::zero()),
                    epoch_anchor_hash,
                    cache_node_id,
                    epoch,
                    slot,
                )
                    .encode(),
            )
            .encode();
            Self::bounded_exact_proof_hash(raw_ticket_id)
        }

        pub fn cache_trigger_issuance_payload(
            validator_account: &T::AccountId,
            ticket_id: &ProofHashOf<T>,
            validator_node_id: &NodeIdOf<T>,
            cache_node_id: &NodeIdOf<T>,
            recipient_did: &DidOf<T>,
            trigger_message_hash: &ProofHashOf<T>,
            ttl_blocks: u32,
            nonce: u64,
            epoch: u64,
            slot: u32,
        ) -> Vec<u8> {
            let genesis_hash = frame_system::Pallet::<T>::block_hash(BlockNumberFor::<T>::zero());
            (
                CACHE_TRIGGER_ISSUANCE_DOMAIN,
                genesis_hash,
                validator_account,
                ticket_id,
                validator_node_id,
                cache_node_id,
                recipient_did,
                trigger_message_hash,
                ttl_blocks,
                nonce,
                epoch,
                slot,
            )
                .encode()
        }

        pub fn cache_trigger_receipt_payload(
            ticket: &CacheTriggerTicket<T>,
            message_id: &MessageIdOf<T>,
            queue_depth_before: u64,
            queue_depth_after: u64,
            accepted_at: u64,
            stored_at: u64,
            receipt_hash: &ProofHashOf<T>,
        ) -> Vec<u8> {
            let genesis_hash = frame_system::Pallet::<T>::block_hash(BlockNumberFor::<T>::zero());
            (
                CACHE_TRIGGER_RECEIPT_DOMAIN,
                genesis_hash,
                &ticket.ticket_id,
                &ticket.cache_node_id,
                &ticket.trigger_message_hash,
                message_id,
                ticket.epoch,
                ticket.slot,
                ticket.issued_at,
                ticket.retention_check_at,
                ticket.expires_at,
                queue_depth_before,
                queue_depth_after,
                accepted_at,
                stored_at,
                receipt_hash,
            )
                .encode()
        }

        pub fn cache_trigger_attestation_payload(
            ticket_id: &ProofHashOf<T>,
            validator_node_id: &NodeIdOf<T>,
            accepted: bool,
            retained: bool,
            retrieved: bool,
            purged: bool,
            evidence_hash: &ProofHashOf<T>,
        ) -> Vec<u8> {
            let genesis_hash = frame_system::Pallet::<T>::block_hash(BlockNumberFor::<T>::zero());
            (
                CACHE_TRIGGER_ATTESTATION_DOMAIN,
                genesis_hash,
                ticket_id,
                validator_node_id,
                accepted,
                retained,
                retrieved,
                purged,
                evidence_hash,
            )
                .encode()
        }

        fn initialize_reward_year(reward_year: u64) -> DispatchResult {
            ensure!(
                reward_year == LastInitializedRewardYear::<T>::get().saturating_add(1),
                Error::<T>::RewardYearAlreadyInitialized
            );
            let pot = Self::reward_pot_account();
            let fixed = T::AnnualFixedEmission::get();
            if !fixed.is_zero() {
                let reward_ref =
                    (b"openpayload:fixed-emission:v1".as_slice(), reward_year).encode();
                pallet_opal::Pallet::<T>::mint_reward_to(&pot, fixed, reward_ref)?;
            }
            let outstanding = OutstandingRewardLiabilities::<T>::get();
            let opening_free_reserve = T::Currency::free_balance(&pot).saturating_sub(outstanding);
            let issuance = T::Currency::total_issuance();
            let supplemental_cap = Self::mul_div_u128(
                issuance.saturated_into(),
                T::SupplementalInflationPpm::get() as u128,
                PPM,
            )
            .saturated_into();
            RewardYearStates::<T>::insert(
                reward_year,
                RewardYearState {
                    reward_year,
                    opening_free_reserve,
                    supplemental_cap,
                    supplemental_minted: Zero::zero(),
                    committed: Zero::zero(),
                    fixed_emission_minted: fixed,
                },
            );
            LastInitializedRewardYear::<T>::put(reward_year);
            Self::deposit_event(Event::RewardYearInitialized {
                reward_year,
                opening_free_reserve,
                fixed_emission: fixed,
                supplemental_cap,
            });
            Ok(())
        }

        fn mul_div_balance_u64(
            value: BalanceOf<T>,
            numerator: u64,
            denominator: u64,
        ) -> BalanceOf<T> {
            Self::mul_div_u128(
                value.saturated_into(),
                numerator as u128,
                denominator.max(1) as u128,
            )
            .saturated_into()
        }

        pub fn mul_div_u128(value: u128, numerator: u128, denominator: u128) -> u128 {
            if denominator == 0 {
                return 0;
            }
            ((U256::from(value) * U256::from(numerator)) / U256::from(denominator)).as_u128()
        }

        pub fn proportional_position_amount(
            distributable: BalanceOf<T>,
            raw_total: BalanceOf<T>,
            raw_prefix_before: BalanceOf<T>,
            raw_amount: BalanceOf<T>,
        ) -> BalanceOf<T> {
            let total: u128 = raw_total.saturated_into();
            if total == 0 {
                return Zero::zero();
            }
            let distributable: u128 = distributable.saturated_into();
            let before: u128 = raw_prefix_before.saturated_into();
            let after = before
                .saturating_add(raw_amount.saturated_into::<u128>())
                .min(total);
            let denominator = U256::from(total);
            let allocated_before = (U256::from(distributable) * U256::from(before)) / denominator;
            let allocated_after = (U256::from(distributable) * U256::from(after)) / denominator;
            allocated_after
                .saturating_sub(allocated_before)
                .as_u128()
                .saturated_into()
        }

        fn try_pay_accrued(operator: &T::AccountId) -> DispatchResult {
            let amount = OperatorAccruedRewards::<T>::get(operator);
            if amount.is_zero() {
                return Ok(());
            }
            if T::Currency::free_balance(operator).is_zero()
                && amount < T::Currency::minimum_balance()
            {
                return Ok(());
            }
            Self::pay_accrued(operator, amount)
        }

        fn pay_accrued(operator: &T::AccountId, amount: BalanceOf<T>) -> DispatchResult {
            let pot = Self::reward_pot_account();
            ensure!(
                T::Currency::free_balance(&pot) >= amount,
                Error::<T>::RewardReserveInvariantViolated
            );
            T::Currency::transfer(&pot, operator, amount, ExistenceRequirement::AllowDeath)?;
            OperatorAccruedRewards::<T>::remove(operator);
            OutstandingRewardLiabilities::<T>::mutate(|liabilities| {
                *liabilities = liabilities.saturating_sub(amount)
            });
            Self::deposit_event(Event::AccruedRewardPaid {
                operator: operator.clone(),
                amount,
            });
            Ok(())
        }

        fn ticket_hash_u64<E: Encode>(material: &E) -> u64 {
            let hash = T::Hashing::hash(&material.encode()).encode();
            let mut prefix = [0u8; 8];
            let take = hash.len().min(prefix.len());
            prefix[..take].copy_from_slice(&hash[..take]);
            u64::from_le_bytes(prefix)
        }

        fn ensure_epoch_not_future(epoch: u64) -> DispatchResult {
            ensure!(epoch <= Self::current_epoch(), Error::<T>::InvalidEpoch);
            Ok(())
        }

        fn ensure_cache_trigger_evidence_active() -> DispatchResult {
            ensure!(
                CacheTriggerEvidenceEnabled::<T>::get(),
                Error::<T>::CacheTriggerEvidenceDisabled
            );
            ensure!(
                !ValidatorActivityPaused::<T>::get(),
                Error::<T>::ValidatorActivityPaused
            );
            Ok(())
        }

        fn validate_role_capacity(role: NodeRole, declared_capacity: u64) -> DispatchResult {
            // Retained as discovery/compatibility metadata only. Reward
            // eligibility and weight are derived solely from sponsor admission
            // plus verified queue-depth triggers, never this declaration.
            let _ = (role, declared_capacity);
            Ok(())
        }

        fn is_cache_role(role: NodeRole) -> bool {
            matches!(role, NodeRole::Cache | NodeRole::AllInOne)
        }

        fn is_relay_role(role: NodeRole) -> bool {
            matches!(role, NodeRole::Relay | NodeRole::AllInOne)
        }

        fn is_validator_role(role: NodeRole) -> bool {
            matches!(role, NodeRole::Validator | NodeRole::AllInOne)
        }

        fn probe_is_success(result: ProbeResult) -> bool {
            matches!(result, ProbeResult::Success)
        }

        fn ensure_node_owner_with_role(
            who: &T::AccountId,
            node_id: &NodeIdOf<T>,
            role_check: fn(NodeRole) -> bool,
        ) -> Result<NodeInfo<T>, Error<T>> {
            let node = Nodes::<T>::get(node_id).ok_or(Error::<T>::UnregisteredNode)?;
            ensure!(node.operator == *who, Error::<T>::NotOperatorOwner);
            ensure!(
                node.status == OperatorStatus::Active,
                Error::<T>::OperatorNotActive
            );
            ensure!(role_check(node.node_role), Error::<T>::UnsupportedNodeRole);
            Ok(node)
        }

        fn ensure_approved_validator(
            who: &T::AccountId,
            node_id: &NodeIdOf<T>,
        ) -> Result<NodeInfo<T>, Error<T>> {
            ensure!(
                !ValidatorActivityPaused::<T>::get(),
                Error::<T>::ValidatorActivityPaused
            );
            ensure!(
                ApprovedValidatorAccounts::<T>::contains_key(who),
                Error::<T>::ValidatorNotApproved
            );
            Self::ensure_node_owner_with_role(who, node_id, Self::is_validator_role)
                .map_err(|_| Error::<T>::UnauthorizedValidator)
        }

        fn report_weight(reporter: &NodeInfo<T>, target: &NodeInfo<T>, observed_count: u32) -> u32 {
            if reporter.operator_did == target.operator_did {
                return 0;
            }

            let operator_credibility = Operators::<T>::get(&reporter.operator)
                .map(|operator| operator.credibility_ppm)
                .unwrap_or(PPM as u32);
            let observed = observed_count.min(100);

            // Region, relay cluster, and network range are operator-declared registry metadata.
            // They remain available for discovery and observability, but must not change an
            // economic outcome until the chain has an independently attestable topology source.
            (observed as u128)
                .saturating_mul(operator_credibility as u128)
                .checked_div(PPM)
                .unwrap_or_default()
                .saturated_into::<u32>()
        }

        fn has_corroboration(aggregate: &OutageAggregate<T>) -> bool {
            aggregate.reporter_count >= T::MinOutageReporters::get()
                && aggregate.independent_weight >= T::MinOutageWeight::get()
        }

        fn refresh_availability_score(summary: &mut AvailabilitySummary) {
            let validator_total = summary
                .validator_success_weight
                .saturating_add(summary.validator_failure_weight);
            if validator_total == 0 {
                summary.availability_score_ppm = 0;
                return;
            }

            let validator_score = (summary.validator_success_weight as u128).saturating_mul(PPM)
                / validator_total as u128;
            let relay_penalty = (summary.relay_failure_weight as u128)
                .saturating_mul(T::RelayPenaltyPerWeightPpm::get() as u128)
                .min(T::MaxRelayPenaltyPpm::get() as u128);
            summary.availability_score_ppm = validator_score
                .saturating_sub(relay_penalty)
                .saturated_into::<u32>();
        }

        fn penalize_contradicted_reporters(target_node_id: &NodeIdOf<T>, epoch: u64) {
            let aggregate = OutageAggregates::<T>::get(target_node_id, epoch);
            if !Self::has_corroboration(&aggregate) {
                return;
            }
            for reporter in aggregate.reporters {
                if let Some(node) = Nodes::<T>::get(&reporter.reporter_node_id) {
                    Operators::<T>::mutate(&node.operator, |maybe_operator| {
                        if let Some(operator) = maybe_operator {
                            operator.credibility_ppm = operator
                                .credibility_ppm
                                .saturating_sub(T::FalseReportPenaltyPpm::get());
                            Self::deposit_event(Event::ReporterCredibilityAdjusted {
                                reporter_node_id: reporter.reporter_node_id.clone(),
                                credibility_ppm: operator.credibility_ppm,
                            });
                        }
                    });
                }
            }
        }

        pub fn queue_depth_storage_multiplier_ppm(observed_average_bytes: u128) -> u32 {
            let unit = T::RewardStorageUnitBytes::get().max(1) as u128;
            let maximum = T::MaxStorageMultiplierPpm::get().max(PPM as u32) as u128;
            if observed_average_bytes <= unit {
                return PPM
                    .saturating_mul(observed_average_bytes)
                    .checked_div(unit)
                    .unwrap_or(0)
                    .min(maximum) as u32;
            }

            let mut multiplier = PPM;
            let mut marginal = PPM.saturating_mul(750_000) / PPM;
            let mut remaining = observed_average_bytes.saturating_sub(unit);
            while remaining >= unit && marginal > 0 && multiplier < maximum {
                multiplier = multiplier.saturating_add(marginal).min(maximum);
                marginal = marginal.saturating_mul(750_000) / PPM;
                remaining = remaining.saturating_sub(unit);
            }
            if remaining > 0 && marginal > 0 && multiplier < maximum {
                let fractional = marginal.saturating_mul(remaining) / unit;
                multiplier = multiplier.saturating_add(fractional).min(maximum);
            }
            multiplier as u32
        }

        fn calculate_amount(
            availability_score_ppm: u32,
            storage_multiplier_ppm: u32,
        ) -> BalanceOf<T> {
            let ppm: BalanceOf<T> = (PPM as u32).into();
            let availability: BalanceOf<T> = availability_score_ppm.into();
            let storage_multiplier: BalanceOf<T> = storage_multiplier_ppm.into();
            let availability_adjusted =
                T::BaseEpochReward::get().saturating_mul(availability) / ppm;
            availability_adjusted.saturating_mul(storage_multiplier) / ppm
        }

        fn bounded_did(raw: Vec<u8>) -> Result<DidOf<T>, Error<T>> {
            DidOf::<T>::try_from(raw).map_err(|_| Error::<T>::DidTooLong)
        }

        fn bounded_node_id(raw: Vec<u8>) -> Result<NodeIdOf<T>, Error<T>> {
            NodeIdOf::<T>::try_from(raw).map_err(|_| Error::<T>::NodeIdTooLong)
        }

        fn bounded_message_id(raw: Vec<u8>) -> Result<MessageIdOf<T>, Error<T>> {
            ensure!(!raw.is_empty(), Error::<T>::InvalidCacheTriggerReceipt);
            MessageIdOf::<T>::try_from(raw).map_err(|_| Error::<T>::InvalidCacheTriggerReceipt)
        }

        fn bounded_endpoint(raw: Vec<u8>) -> Result<EndpointOf<T>, Error<T>> {
            EndpointOf::<T>::try_from(raw).map_err(|_| Error::<T>::EndpointTooLong)
        }

        fn bounded_region(raw: Vec<u8>) -> Result<RegionOf<T>, Error<T>> {
            RegionOf::<T>::try_from(raw).map_err(|_| Error::<T>::RegionTooLong)
        }

        fn bounded_jurisdiction(raw: Vec<u8>) -> Result<JurisdictionOf<T>, Error<T>> {
            JurisdictionOf::<T>::try_from(raw).map_err(|_| Error::<T>::JurisdictionTooLong)
        }

        fn bounded_cluster(raw: Vec<u8>) -> Result<ClusterOf<T>, Error<T>> {
            ClusterOf::<T>::try_from(raw).map_err(|_| Error::<T>::ClusterTooLong)
        }

        fn bounded_network_range(raw: Vec<u8>) -> Result<NetworkRangeOf<T>, Error<T>> {
            NetworkRangeOf::<T>::try_from(raw).map_err(|_| Error::<T>::NetworkRangeTooLong)
        }

        fn bounded_proof_hash(raw: Vec<u8>) -> Result<ProofHashOf<T>, Error<T>> {
            ProofHashOf::<T>::try_from(raw).map_err(|_| Error::<T>::ProofHashTooLong)
        }

        fn bounded_exact_proof_hash(raw: Vec<u8>) -> Result<ProofHashOf<T>, Error<T>> {
            ensure!(raw.len() == 32, Error::<T>::InvalidProofHashLength);
            Self::bounded_proof_hash(raw)
        }

        fn bounded_signature(raw: Vec<u8>) -> Result<SignatureOf<T>, Error<T>> {
            SignatureOf::<T>::try_from(raw).map_err(|_| Error::<T>::SignatureTooLong)
        }
    }
}
