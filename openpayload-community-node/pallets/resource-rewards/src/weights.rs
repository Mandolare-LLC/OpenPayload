//! Weights for the sponsor, Cache-trigger, reward-settlement, and history-pruning calls.
//!
//! The benchmark definitions live in `benchmarking.rs`. The checked-in implementation is a
//! deliberately conservative pre-generation policy: each call reserves one quarter of the
//! runtime's maximum block weight. It contains no fabricated timing measurements. Replace this
//! file with benchmark-generated weights on the release reference hardware before the production
//! runtime is built. A typical generation command is:
//!
//! `./target/production/openpayload-node benchmark pallet --chain dev \
//!   --pallet pallet_resource_rewards --extrinsic '*' --steps 50 --repeat 20 \
//!   --output pallets/resource-rewards/src/weights.rs`

use core::marker::PhantomData;

use frame_support::{traits::Get, weights::Weight};

/// Weight functions for the permanent resource-reward lifecycle (call indexes 9 through 24).
pub trait WeightInfo {
    fn set_sponsor_authority() -> Weight;
    fn admit_reward_eligible_cache() -> Weight;
    fn revoke_reward_eligible_cache() -> Weight;
    fn propose_root_sponsor() -> Weight;
    fn accept_root_sponsor() -> Weight;
    fn issue_cache_trigger_ticket() -> Weight;
    fn submit_cache_trigger_receipt() -> Weight;
    fn attest_cache_trigger_ticket() -> Weight;
    fn finalize_cache_queue_depth_epoch() -> Weight;
    fn freeze_operator_queue_depth_epoch() -> Weight;
    fn finalize_cache_raw_reward() -> Weight;
    fn close_reward_epoch() -> Weight;
    fn claim_cache_reward() -> Weight;
    fn withdraw_accrued_reward() -> Weight;
    fn prune_cache_reward_history() -> Weight;
    fn prune_operator_queue_depth_history() -> Weight;
}

/// Conservative weights used until the benchmark CLI replaces this file with measured output.
pub struct SubstrateWeight<T>(PhantomData<T>);

impl<T: frame_system::Config> SubstrateWeight<T> {
    fn provisional() -> Weight {
        T::BlockWeights::get().max_block.saturating_div(4)
    }
}

macro_rules! weight_functions {
    ($weight:expr; $($name:ident),+ $(,)?) => {
        $(
            fn $name() -> Weight {
                $weight
            }
        )+
    };
}

impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
    weight_functions!(Self::provisional();
        set_sponsor_authority,
        admit_reward_eligible_cache,
        revoke_reward_eligible_cache,
        propose_root_sponsor,
        accept_root_sponsor,
        issue_cache_trigger_ticket,
        submit_cache_trigger_receipt,
        attest_cache_trigger_ticket,
        finalize_cache_queue_depth_epoch,
        freeze_operator_queue_depth_epoch,
        finalize_cache_raw_reward,
        close_reward_epoch,
        claim_cache_reward,
        withdraw_accrued_reward,
        prune_cache_reward_history,
        prune_operator_queue_depth_history,
    );
}

/// Test-only fallback. A runtime must wire `SubstrateWeight<Runtime>` or generated weights.
impl WeightInfo for () {
    weight_functions!(Weight::MAX;
        set_sponsor_authority,
        admit_reward_eligible_cache,
        revoke_reward_eligible_cache,
        propose_root_sponsor,
        accept_root_sponsor,
        issue_cache_trigger_ticket,
        submit_cache_trigger_receipt,
        attest_cache_trigger_ticket,
        finalize_cache_queue_depth_epoch,
        freeze_operator_queue_depth_epoch,
        finalize_cache_raw_reward,
        close_reward_epoch,
        claim_cache_reward,
        withdraw_accrued_reward,
        prune_cache_reward_history,
        prune_operator_queue_depth_history,
    );
}
