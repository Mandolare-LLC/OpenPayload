//! Measured opaque-policy envelope and conservative Persona mutation weights.
//!
//! Policy validation is deliberately expressive and bounded, but its worst case is still large:
//! every one of the 32 rules can contain a 32-step graph and every step can reference the maximum
//! number of route targets. The aggregate validation-unit limit prevents the full Cartesian worst
//! case, but accepted policies still perform many target-DID and service-declaration storage checks.
//! A small fixed weight is therefore unsafe until this pallet has benchmark-generated weights.
//!
//! The checked-in release fallback reserves the runtime's Normal-extrinsic allowance after
//! leaving room for framework extensions and encoded transaction length. Proof-authorized writes
//! split that mutation allowance between
//! transaction authorization and dispatch. This is intentionally conservative: only one such
//! mutation can fit in a normal block. Replace this file with benchmark-generated weights measured
//! at all configured bounds before increasing mutation throughput.

use core::marker::PhantomData;

use frame_support::{dispatch::DispatchClass, traits::Get, weights::Weight};

pub trait WeightInfo {
    fn policy_document() -> Weight;
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
    fn normal_mutation_budget() -> Weight {
        let block_weights = T::BlockWeights::get();
        let normal = block_weights.get(DispatchClass::Normal);
        let ceiling = normal
            .max_extrinsic
            .or(normal.max_total)
            .unwrap_or(block_weights.max_block);
        // FRAME checks call + extension weight + encoded length, not just the
        // call/AuthorizeCall split. Reserving the entire ceiling for the split
        // makes every General proof transaction exceed it. Leave 100 ms and
        // 1 MiB for the remaining framework extensions, plus the maximum Normal
        // encoded transaction length in the proof-size dimension. This remains
        // a conservative single-mutation fallback, not a benchmark result.
        let max_encoded = u64::from(*T::BlockLength::get().max.get(DispatchClass::Normal));
        ceiling.saturating_sub(Weight::from_parts(
            100_000_000_000,
            max_encoded.saturating_add(1_048_576),
        ))
    }
}

impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
    fn policy_document() -> Weight {
        let measured = crate::measured_weights::SubstrateWeight::<T>::policy_document_envelope();
        // FRAME's combined-envelope estimate takes a maximum although the fixture
        // reads three scopes. Floor the proof at the sum of all ten bounded reads:
        // genesis + time + nonce + 3 raw records + DID + Persona + marker + app.
        let bounded_proof = 2519 + 503 + 2629 + 3 * 68457 + 387659 + 5027 + 2746 + 2704;
        Weight::from_parts(
            measured.ref_time(),
            measured.proof_size().max(bounded_proof),
        )
        .saturating_mul(2)
    }
    fn set_did_delivery_constraints() -> Weight {
        Self::normal_mutation_budget()
    }

    fn register_persona() -> Weight {
        Self::normal_mutation_budget()
    }

    fn renew_persona() -> Weight {
        Self::normal_mutation_budget()
    }

    fn revoke_persona() -> Weight {
        Self::normal_mutation_budget()
    }

    fn set_did_policy_v2() -> Weight {
        Self::normal_mutation_budget()
    }

    fn clear_did_policy_v2() -> Weight {
        Self::normal_mutation_budget()
    }

    fn set_persona_policy_v2() -> Weight {
        Self::normal_mutation_budget()
    }

    fn clear_persona_policy_v2() -> Weight {
        Self::normal_mutation_budget()
    }

    fn apply_policy_v2_with_proof() -> Weight {
        Self::normal_mutation_budget()
            .saturating_div(4)
            .saturating_mul(3)
    }

    fn authorize_apply_policy_v2_with_proof() -> Weight {
        Self::normal_mutation_budget().saturating_div(4)
    }

    fn set_persona_delivery_constraints() -> Weight {
        Self::normal_mutation_budget()
    }

    fn apply_persona_with_proof() -> Weight {
        Self::normal_mutation_budget()
            .saturating_div(4)
            .saturating_mul(3)
    }

    fn authorize_apply_persona_with_proof() -> Weight {
        Self::normal_mutation_budget().saturating_div(4)
    }

    fn set_persona_attestor() -> Weight {
        Self::normal_mutation_budget()
    }
}

/// Pallet-test fallback. Production runtimes must wire `SubstrateWeight<Runtime>` or generated
/// weights explicitly.
impl WeightInfo for () {
    fn policy_document() -> Weight {
        Weight::MAX
    }
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
