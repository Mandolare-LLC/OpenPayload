#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use codec::{DecodeWithMemTracking, MaxEncodedLen};
use frame_support::{
    pallet_prelude::*,
    traits::{Currency, ExistenceRequirement, Imbalance, StorageVersion, WithdrawReasons},
    BoundedVec,
};
use frame_system::pallet_prelude::*;
use scale_info::TypeInfo;
use sp_runtime::traits::{AtLeast32BitUnsigned, Zero};

pub use pallet::*;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

#[frame_support::pallet]
pub mod pallet {
    use super::*;

    const STORAGE_VERSION: StorageVersion = StorageVersion::new(1);

    pub type BalanceOf<T> = <T as Config>::Balance;
    pub type AccountingRefOf<T> = BoundedVec<u8, <T as Config>::MaxAccountingRefLen>;

    #[pallet::config]
    pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
        type Balance: Parameter
            + Member
            + AtLeast32BitUnsigned
            + Default
            + Copy
            + DecodeWithMemTracking
            + MaxEncodedLen
            + TypeInfo;
        type Currency: Currency<Self::AccountId, Balance = Self::Balance>;
        type TokenGovernanceOrigin: EnsureOrigin<Self::RuntimeOrigin>;

        #[pallet::constant]
        type MaxAccountingRefLen: Get<u32>;
    }

    #[pallet::pallet]
    #[pallet::storage_version(STORAGE_VERSION)]
    pub struct Pallet<T>(_);

    /// Retrieval burns are dormant on the permanent alpha chain. Governance
    /// may enable them only if the product later adopts a recipient-funded
    /// retrieval model.
    #[pallet::storage]
    #[pallet::getter(fn retrieval_burns_enabled)]
    pub type RetrievalBurnsEnabled<T: Config> = StorageValue<_, bool, ValueQuery>;

    #[derive(frame_support::DefaultNoBound)]
    #[pallet::genesis_config]
    pub struct GenesisConfig<T: Config> {
        pub retrieval_burns_enabled: bool,
        #[serde(skip)]
        pub _config: core::marker::PhantomData<T>,
    }

    #[pallet::genesis_build]
    impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
        fn build(&self) {
            STORAGE_VERSION.put::<Pallet<T>>();
            RetrievalBurnsEnabled::<T>::put(self.retrieval_burns_enabled);
        }
    }

    #[pallet::storage]
    pub type RetrievalBurns<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        AccountingRefOf<T>,
        (T::AccountId, BalanceOf<T>),
        OptionQuery,
    >;

    #[pallet::storage]
    pub type RewardMints<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        AccountingRefOf<T>,
        (T::AccountId, BalanceOf<T>),
        OptionQuery,
    >;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        RetrievalBurned {
            recipient: T::AccountId,
            amount: BalanceOf<T>,
            retrieval_ref: AccountingRefOf<T>,
        },
        RewardMinted {
            operator: T::AccountId,
            amount: BalanceOf<T>,
            reward_ref: AccountingRefOf<T>,
        },
        Transferred {
            from: T::AccountId,
            to: T::AccountId,
            amount: BalanceOf<T>,
        },
        RetrievalBurnPolicyChanged {
            enabled: bool,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        AccountingRefTooLong,
        DuplicateRetrievalRef,
        DuplicateRewardRef,
        RewardMintFailed,
        ZeroAmount,
        RetrievalBurnsDisabled,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(T::DbWeight::get().reads_writes(2, 2))]
        pub fn burn_for_retrieval(
            origin: OriginFor<T>,
            amount: BalanceOf<T>,
            retrieval_ref: Vec<u8>,
        ) -> DispatchResult {
            let recipient = ensure_signed(origin)?;
            Self::burn_for_retrieval_from(&recipient, amount, retrieval_ref)?;
            Ok(())
        }

        #[pallet::call_index(1)]
        #[pallet::weight(T::DbWeight::get().reads_writes(2, 2))]
        pub fn transfer(
            origin: OriginFor<T>,
            to: T::AccountId,
            amount: BalanceOf<T>,
        ) -> DispatchResult {
            let from = ensure_signed(origin)?;
            ensure!(!amount.is_zero(), Error::<T>::ZeroAmount);
            T::Currency::transfer(&from, &to, amount, ExistenceRequirement::AllowDeath)?;
            Self::deposit_event(Event::Transferred { from, to, amount });
            Ok(())
        }

        #[pallet::call_index(2)]
        #[pallet::weight(T::DbWeight::get().writes(1))]
        pub fn set_retrieval_burns_enabled(origin: OriginFor<T>, enabled: bool) -> DispatchResult {
            T::TokenGovernanceOrigin::ensure_origin(origin)?;
            RetrievalBurnsEnabled::<T>::put(enabled);
            Self::deposit_event(Event::RetrievalBurnPolicyChanged { enabled });
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        pub fn burn_for_retrieval_from(
            recipient: &T::AccountId,
            amount: BalanceOf<T>,
            retrieval_ref: Vec<u8>,
        ) -> DispatchResult {
            ensure!(
                RetrievalBurnsEnabled::<T>::get(),
                Error::<T>::RetrievalBurnsDisabled
            );
            ensure!(!amount.is_zero(), Error::<T>::ZeroAmount);
            let retrieval_ref = Self::bounded_ref(retrieval_ref)?;
            ensure!(
                !RetrievalBurns::<T>::contains_key(&retrieval_ref),
                Error::<T>::DuplicateRetrievalRef
            );

            let imbalance = T::Currency::withdraw(
                recipient,
                amount,
                WithdrawReasons::TRANSFER,
                ExistenceRequirement::AllowDeath,
            )?;
            drop(imbalance);

            RetrievalBurns::<T>::insert(&retrieval_ref, (recipient.clone(), amount));
            Self::deposit_event(Event::RetrievalBurned {
                recipient: recipient.clone(),
                amount,
                retrieval_ref,
            });
            Ok(())
        }

        #[frame_support::transactional]
        pub fn mint_reward_to(
            operator: &T::AccountId,
            amount: BalanceOf<T>,
            reward_ref: Vec<u8>,
        ) -> DispatchResult {
            ensure!(!amount.is_zero(), Error::<T>::ZeroAmount);
            let reward_ref = Self::bounded_ref(reward_ref)?;
            ensure!(
                !RewardMints::<T>::contains_key(&reward_ref),
                Error::<T>::DuplicateRewardRef
            );

            let imbalance = T::Currency::deposit_creating(operator, amount);
            ensure!(imbalance.peek() == amount, Error::<T>::RewardMintFailed);
            drop(imbalance);

            RewardMints::<T>::insert(&reward_ref, (operator.clone(), amount));
            Self::deposit_event(Event::RewardMinted {
                operator: operator.clone(),
                amount,
                reward_ref,
            });
            Ok(())
        }

        fn bounded_ref(raw: Vec<u8>) -> Result<AccountingRefOf<T>, Error<T>> {
            AccountingRefOf::<T>::try_from(raw).map_err(|_| Error::<T>::AccountingRefTooLong)
        }
    }
}
