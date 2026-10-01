use core::marker::PhantomData;
use frame_support::{traits::Get, weights::Weight};

pub trait WeightInfo {
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
    fn provisional() -> Weight {
        T::BlockWeights::get().max_block.saturating_div(4)
    }
}

impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
    fn register_application() -> Weight {
        Self::provisional()
    }
    fn update_application() -> Weight {
        Self::provisional()
    }
    fn set_application_status() -> Weight {
        Self::provisional()
    }
    fn force_set_application_status() -> Weight {
        Self::provisional()
    }
    fn set_application_policy() -> Weight {
        Self::provisional()
    }
    fn clear_application_policy() -> Weight {
        Self::provisional()
    }
    fn set_application_domain() -> Weight {
        Self::provisional()
    }
    fn set_application_linked_did() -> Weight {
        Self::provisional()
    }
}

impl WeightInfo for () {
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
