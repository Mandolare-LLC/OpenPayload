//! Weights for Policy V2 and Persona mutations.
//!
//! Policy validation is deliberately expressive and bounded, but its worst case is still large:
//! every one of the 32 rules can contain a 32-step graph and every step can reference the maximum
//! number of route targets. The aggregate validation-unit limit prevents the full Cartesian worst
//! case, but accepted policies still perform many target-DID and service-declaration storage checks.
//! A small fixed weight is therefore unsafe until this pallet has benchmark-generated weights.
//!
//! The checked-in release fallback reserves the runtime's complete Normal-extrinsic allowance for
//! direct Policy V2 and Persona writes. Proof-authorized writes split that same allowance between
//! transaction authorization and dispatch. This is intentionally conservative: only one such
//! mutation can fit in a normal block. Replace this file with benchmark-generated weights measured
//! at all configured bounds before increasing mutation throughput.

use core::marker::PhantomData;

use frame_support::{dispatch::DispatchClass, traits::Get, weights::Weight};

pub trait WeightInfo {
    fn set_did_delivery_constraints() -> Weight;
    fn register_persona() -> Weight;
    fn renew_persona() -> Weight;
    fn revoke_persona() -> Weight;
    fn set_did_policy_v2() -> Weight;
    fn clear_did_policy_v2() -> Weight;
    fn set_persona_policy_v2() -> Weight;
    fn clear_persona_policy_v2() -> Weight;
    fn apply_policy_v2_with_proof() -> Weight;
    fn authorize_apply_policy_v2_with_proof() -> Weight;
    fn set_persona_delivery_constraints() -> Weight;
    fn apply_persona_with_proof() -> Weight;
    fn authorize_apply_persona_with_proof() -> Weight;
    fn set_persona_attestor() -> Weight;
}

/// Conservative production weights used until reproducible hardware benchmarks are checked in.
pub struct SubstrateWeight<T>(PhantomData<T>);

impl<T: frame_system::Config> SubstrateWeight<T> {
    fn normal_max_extrinsic() -> Weight {
        let block_weights = T::BlockWeights::get();
        let normal = block_weights.get(DispatchClass::Normal);
        normal
            .max_extrinsic
            .or(normal.max_total)
            .unwrap_or(block_weights.max_block)
    }
}

impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
    fn set_did_delivery_constraints() -> Weight {
        Self::normal_max_extrinsic()
    }

    fn register_persona() -> Weight {
        Self::normal_max_extrinsic()
    }

    fn renew_persona() -> Weight {
        Self::normal_max_extrinsic()
    }

    fn revoke_persona() -> Weight {
        Self::normal_max_extrinsic()
    }

    fn set_did_policy_v2() -> Weight {
        Self::normal_max_extrinsic()
    }

    fn clear_did_policy_v2() -> Weight {
        Self::normal_max_extrinsic()
    }

    fn set_persona_policy_v2() -> Weight {
        Self::normal_max_extrinsic()
    }

    fn clear_persona_policy_v2() -> Weight {
        Self::normal_max_extrinsic()
    }

    fn apply_policy_v2_with_proof() -> Weight {
        Self::normal_max_extrinsic()
            .saturating_div(4)
            .saturating_mul(3)
    }

    fn authorize_apply_policy_v2_with_proof() -> Weight {
        Self::normal_max_extrinsic().saturating_div(4)
    }

    fn set_persona_delivery_constraints() -> Weight {
        Self::normal_max_extrinsic()
    }

    fn apply_persona_with_proof() -> Weight {
        Self::normal_max_extrinsic()
            .saturating_div(4)
            .saturating_mul(3)
    }

    fn authorize_apply_persona_with_proof() -> Weight {
        Self::normal_max_extrinsic().saturating_div(4)
    }

    fn set_persona_attestor() -> Weight {
        Self::normal_max_extrinsic()
    }
}

/// Pallet-test fallback. Production runtimes must wire `SubstrateWeight<Runtime>` or generated
/// weights explicitly.
impl WeightInfo for () {
    fn set_did_delivery_constraints() -> Weight {
        Weight::MAX
    }

    fn register_persona() -> Weight {
        Weight::MAX
    }

    fn renew_persona() -> Weight {
        Weight::MAX
    }

    fn revoke_persona() -> Weight {
        Weight::MAX
    }

    fn set_did_policy_v2() -> Weight {
        Weight::MAX
    }

    fn clear_did_policy_v2() -> Weight {
        Weight::MAX
    }

    fn set_persona_policy_v2() -> Weight {
        Weight::MAX
    }

    fn clear_persona_policy_v2() -> Weight {
        Weight::MAX
    }

    fn apply_policy_v2_with_proof() -> Weight {
        Weight::MAX
    }

    fn authorize_apply_policy_v2_with_proof() -> Weight {
        Weight::MAX
    }

    fn set_persona_delivery_constraints() -> Weight {
        Weight::MAX
    }

    fn apply_persona_with_proof() -> Weight {
        Weight::MAX
    }

    fn authorize_apply_persona_with_proof() -> Weight {
        Weight::MAX
    }

    fn set_persona_attestor() -> Weight {
        Weight::MAX
    }
}
