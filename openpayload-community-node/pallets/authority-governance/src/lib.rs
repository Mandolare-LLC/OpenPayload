#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use frame_support::{pallet_prelude::*, traits::EnsureOrigin, BoundedVec};
use frame_system::pallet_prelude::*;
use scale_info::TypeInfo;
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_consensus_grandpa::AuthorityId as GrandpaId;
use sp_runtime::traits::{CheckedAdd, Zero};

pub use pallet::*;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

#[frame_support::pallet]
pub mod pallet {
    use super::*;

    pub type AuthoritySetOf<T> = BoundedVec<AuthorityPair, <T as Config>::MaxAuthorities>;
    pub type ScheduledAuthorityChangeOf<T> =
        ScheduledAuthorityChange<BlockNumberFor<T>, <T as Config>::MaxAuthorities>;

    /// The Aura and GRANDPA public keys belonging to one consensus authority.
    #[derive(
        Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, Debug, TypeInfo, MaxEncodedLen,
    )]
    pub struct AuthorityPair {
        pub aura: AuraId,
        pub grandpa: GrandpaId,
    }

    /// A complete replacement authority set waiting for its activation block.
    #[derive(
        Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, Debug, TypeInfo, MaxEncodedLen,
    )]
    #[scale_info(skip_type_params(MaxAuthorities))]
    pub struct ScheduledAuthorityChange<BlockNumber, MaxAuthorities: Get<u32>> {
        pub authorities: BoundedVec<AuthorityPair, MaxAuthorities>,
        pub enact_at: BlockNumber,
    }

    #[pallet::config]
    pub trait Config:
        frame_system::Config<RuntimeEvent: From<Event<Self>>>
        + pallet_aura::Config<AuthorityId = AuraId>
        + pallet_grandpa::Config
    {
        /// Governance origin permitted to schedule or cancel a complete set replacement.
        type AuthorityOrigin: EnsureOrigin<Self::RuntimeOrigin>;

        /// Minimum authority count accepted for a governed set replacement.
        #[pallet::constant]
        type MinAuthorities: Get<u32>;

        /// Maximum authority count encoded by this pallet.
        #[pallet::constant]
        type MaxAuthorities: Get<u32>;

        /// Minimum notice period before a scheduled set can take effect.
        #[pallet::constant]
        type MinAuthorityChangeDelay: Get<BlockNumberFor<Self>>;
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    /// At most one full authority-set replacement may be pending.
    #[pallet::storage]
    #[pallet::getter(fn pending_authority_change)]
    pub type PendingAuthorityChange<T: Config> =
        StorageValue<_, ScheduledAuthorityChangeOf<T>, OptionQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        AuthorityChangeScheduled {
            authority_count: u32,
            enact_at: BlockNumberFor<T>,
        },
        AuthorityChangeCancelled {
            authority_count: u32,
            enact_at: BlockNumberFor<T>,
        },
        AuthorityChangeEnacted {
            authority_count: u32,
        },
        /// The activation block was reached while GRANDPA already had a change pending.
        /// The complete OpenPayload change remains pending and is retried on the next block.
        AuthorityChangeDeferred {
            authority_count: u32,
            enact_at: BlockNumberFor<T>,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        AuthoritySetTooSmall,
        AuthoritySetTooLarge,
        DuplicateAuraAuthority,
        DuplicateGrandpaAuthority,
        DelayTooShort,
        ActivationBlockOverflow,
        AuthorityChangeAlreadyPending,
        NoAuthorityChangePending,
        ConsensusChangeAlreadyPending,
        AuthoritySetUnchanged,
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_initialize(now: BlockNumberFor<T>) -> Weight {
            let Some(change) = PendingAuthorityChange::<T>::get() else {
                return T::DbWeight::get().reads(1);
            };

            if now < change.enact_at {
                return T::DbWeight::get().reads(1);
            }

            let authority_count = change.authorities.len() as u32;
            if Self::try_enact(&change).is_err() {
                Self::deposit_event(Event::AuthorityChangeDeferred {
                    authority_count,
                    enact_at: change.enact_at,
                });
                return T::DbWeight::get()
                    .reads_writes(4, 1)
                    .saturating_add(Weight::from_parts(100_000_000, 0));
            }

            PendingAuthorityChange::<T>::kill();
            Self::deposit_event(Event::AuthorityChangeEnacted { authority_count });

            T::DbWeight::get()
                .reads_writes(5, 4)
                .saturating_add(Weight::from_parts(100_000_000, 0))
        }
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Schedule an atomic replacement of the Aura and GRANDPA authority sets.
        ///
        /// Operators must provision every new key before the activation block. The
        /// current authority quorum must remain live long enough to finalize the
        /// activation block; on-chain governance cannot recover a chain that has
        /// already lost finality.
        #[pallet::call_index(0)]
        #[pallet::weight(
            T::DbWeight::get()
                .reads_writes(4, 2)
                .saturating_add(Weight::from_parts(100_000_000, 0))
        )]
        pub fn schedule_authority_change(
            origin: OriginFor<T>,
            authorities: AuthoritySetOf<T>,
            delay: BlockNumberFor<T>,
        ) -> DispatchResult {
            T::AuthorityOrigin::ensure_origin(origin)?;
            ensure!(
                !PendingAuthorityChange::<T>::exists(),
                Error::<T>::AuthorityChangeAlreadyPending
            );
            ensure!(
                !pallet_grandpa::PendingChange::<T>::exists(),
                Error::<T>::ConsensusChangeAlreadyPending
            );
            ensure!(
                authorities.len() as u32 >= T::MinAuthorities::get(),
                Error::<T>::AuthoritySetTooSmall
            );
            ensure!(
                authorities.len() as u32 <= <T as Config>::MaxAuthorities::get()
                    && authorities.len() as u32
                        <= <T as pallet_aura::Config>::MaxAuthorities::get()
                    && authorities.len() as u32
                        <= <T as pallet_grandpa::Config>::MaxAuthorities::get(),
                Error::<T>::AuthoritySetTooLarge
            );
            ensure!(
                delay >= T::MinAuthorityChangeDelay::get(),
                Error::<T>::DelayTooShort
            );

            Self::ensure_unique_authorities(&authorities)?;
            ensure!(
                !Self::matches_current_authorities(&authorities),
                Error::<T>::AuthoritySetUnchanged
            );

            let now = frame_system::Pallet::<T>::block_number();
            let enact_at = now
                .checked_add(&delay)
                .ok_or(Error::<T>::ActivationBlockOverflow)?;

            PendingAuthorityChange::<T>::put(ScheduledAuthorityChange {
                authorities: authorities.clone(),
                enact_at,
            });
            Self::deposit_event(Event::AuthorityChangeScheduled {
                authority_count: authorities.len() as u32,
                enact_at,
            });
            Ok(())
        }

        /// Cancel an OpenPayload authority change before its activation block begins.
        #[pallet::call_index(1)]
        #[pallet::weight(T::DbWeight::get().reads_writes(1, 1))]
        pub fn cancel_authority_change(origin: OriginFor<T>) -> DispatchResult {
            T::AuthorityOrigin::ensure_origin(origin)?;
            let change =
                PendingAuthorityChange::<T>::take().ok_or(Error::<T>::NoAuthorityChangePending)?;

            Self::deposit_event(Event::AuthorityChangeCancelled {
                authority_count: change.authorities.len() as u32,
                enact_at: change.enact_at,
            });
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        fn ensure_unique_authorities(authorities: &AuthoritySetOf<T>) -> DispatchResult {
            for (index, authority) in authorities.iter().enumerate() {
                for other in authorities.iter().skip(index + 1) {
                    ensure!(
                        authority.aura != other.aura,
                        Error::<T>::DuplicateAuraAuthority
                    );
                    ensure!(
                        authority.grandpa != other.grandpa,
                        Error::<T>::DuplicateGrandpaAuthority
                    );
                }
            }
            Ok(())
        }

        fn matches_current_authorities(authorities: &AuthoritySetOf<T>) -> bool {
            let current_aura = pallet_aura::Authorities::<T>::get();
            let current_grandpa = pallet_grandpa::Pallet::<T>::grandpa_authorities();

            current_aura.len() == authorities.len()
                && current_grandpa.len() == authorities.len()
                && authorities.iter().enumerate().all(|(index, authority)| {
                    current_aura[index] == authority.aura
                        && current_grandpa[index].0 == authority.grandpa
                        && current_grandpa[index].1 == 1
                })
        }

        fn try_enact(change: &ScheduledAuthorityChangeOf<T>) -> DispatchResult {
            let aura_authorities = change
                .authorities
                .iter()
                .map(|authority| authority.aura.clone())
                .collect::<Vec<_>>();
            let aura_authorities: BoundedVec<_, <T as pallet_aura::Config>::MaxAuthorities> =
                aura_authorities
                    .try_into()
                    .map_err(|_| Error::<T>::AuthoritySetTooLarge)?;

            let grandpa_authorities = change
                .authorities
                .iter()
                .map(|authority| (authority.grandpa.clone(), 1))
                .collect::<Vec<_>>();

            // GRANDPA can reject a concurrent pending change. Schedule it first so
            // Aura is never changed unless the finality transition is accepted.
            pallet_grandpa::Pallet::<T>::schedule_change(grandpa_authorities, Zero::zero(), None)?;
            pallet_aura::Pallet::<T>::change_authorities(aura_authorities);
            Ok(())
        }
    }
}
