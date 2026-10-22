use core::marker::PhantomData;
use frame_support::weights::Weight;

pub trait WeightInfo {
    fn apply_application_with_proof() -> Weight;
    fn authorize_application() -> Weight;
    fn register_application() -> Weight;
    fn update_application() -> Weight;
    fn set_application_status() -> Weight;
    fn force_set_application_status() -> Weight;
    fn set_application_policy() -> Weight;
    fn clear_application_policy() -> Weight;
    fn set_application_domain() -> Weight;
    fn set_application_linked_did() -> Weight;
}

pub struct SubstrateWeight<T>(PhantomData<T>);

impl<T: frame_system::Config> SubstrateWeight<T> {
    // One annotation pays twice the full pool+dispatch envelope for all five
    // operations, including two DID signatures, large records and index cleanup.
    fn measured_envelope() -> Weight {
        crate::measured_weights::SubstrateWeight::<T>::proof_envelope().saturating_mul(2)
    }
}

impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
    fn apply_application_with_proof() -> Weight {
        Self::measured_envelope()
    }
    fn authorize_application() -> Weight {
        Self::measured_envelope()
    }
    fn register_application() -> Weight {
        Self::measured_envelope()
    }
    fn update_application() -> Weight {
        Self::measured_envelope()
    }
    fn set_application_status() -> Weight {
        Self::measured_envelope()
    }
    fn force_set_application_status() -> Weight {
        Self::measured_envelope()
    }
    fn set_application_policy() -> Weight {
        Self::measured_envelope()
    }
    fn clear_application_policy() -> Weight {
        Self::measured_envelope()
    }
    fn set_application_domain() -> Weight {
        Self::measured_envelope()
    }
    fn set_application_linked_did() -> Weight {
        Self::measured_envelope()
    }
}

impl WeightInfo for () {
    fn apply_application_with_proof() -> Weight {
        Weight::MAX
    }
    fn authorize_application() -> Weight {
        Weight::MAX
    }
    fn register_application() -> Weight {
        Weight::MAX
    }
    fn update_application() -> Weight {
        Weight::MAX
    }
    fn set_application_status() -> Weight {
        Weight::MAX
    }
    fn force_set_application_status() -> Weight {
        Weight::MAX
    }
    fn set_application_policy() -> Weight {
        Weight::MAX
    }
    fn clear_application_policy() -> Weight {
        Weight::MAX
    }
    fn set_application_domain() -> Weight {
        Weight::MAX
    }
    fn set_application_linked_did() -> Weight {
        Weight::MAX
    }
}
