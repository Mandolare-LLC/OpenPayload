use crate::{mock::*, Error, Event, PendingAuthorityChange};
use frame_support::{assert_noop, assert_ok, traits::Hooks};

fn bounded(authorities: Vec<crate::AuthorityPair>) -> crate::AuthoritySetOf<Test> {
    authorities.try_into().unwrap()
}

#[test]
fn only_root_can_schedule_or_cancel() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            AuthorityGovernance::schedule_authority_change(
                RuntimeOrigin::signed(1),
                bounded(replacement_authorities()),
                2,
            ),
            sp_runtime::DispatchError::BadOrigin
        );

        assert_ok!(AuthorityGovernance::schedule_authority_change(
            RuntimeOrigin::root(),
            bounded(replacement_authorities()),
            2,
        ));

        assert_noop!(
            AuthorityGovernance::cancel_authority_change(RuntimeOrigin::signed(1)),
            sp_runtime::DispatchError::BadOrigin
        );
        assert_ok!(AuthorityGovernance::cancel_authority_change(
            RuntimeOrigin::root()
        ));
    });
}

#[test]
fn rejects_unsafe_or_ambiguous_sets() {
    new_test_ext().execute_with(|| {
        let replacement = replacement_authorities();

        assert_noop!(
            AuthorityGovernance::schedule_authority_change(
                RuntimeOrigin::root(),
                bounded(replacement[..3].to_vec()),
                2,
            ),
            Error::<Test>::AuthoritySetTooSmall
        );

        assert_noop!(
            AuthorityGovernance::schedule_authority_change(
                RuntimeOrigin::root(),
                bounded(replacement.clone()),
                1,
            ),
            Error::<Test>::DelayTooShort
        );

        let mut duplicate_aura = replacement.clone();
        duplicate_aura[1].aura = duplicate_aura[0].aura.clone();
        assert_noop!(
            AuthorityGovernance::schedule_authority_change(
                RuntimeOrigin::root(),
                bounded(duplicate_aura),
                2,
            ),
            Error::<Test>::DuplicateAuraAuthority
        );

        let mut duplicate_grandpa = replacement;
        duplicate_grandpa[1].grandpa = duplicate_grandpa[0].grandpa.clone();
        assert_noop!(
            AuthorityGovernance::schedule_authority_change(
                RuntimeOrigin::root(),
                bounded(duplicate_grandpa),
                2,
            ),
            Error::<Test>::DuplicateGrandpaAuthority
        );

        assert_noop!(
            AuthorityGovernance::schedule_authority_change(
                RuntimeOrigin::root(),
                bounded(initial_authorities()),
                2,
            ),
            Error::<Test>::AuthoritySetUnchanged
        );
    });
}

#[test]
fn stores_one_cancellable_change_with_an_absolute_activation_block() {
    new_test_ext().execute_with(|| {
        System::set_block_number(10);
        let replacement = bounded(replacement_authorities());

        assert_ok!(AuthorityGovernance::schedule_authority_change(
            RuntimeOrigin::root(),
            replacement.clone(),
            5,
        ));

        let pending = PendingAuthorityChange::<Test>::get().unwrap();
        assert_eq!(pending.authorities, replacement);
        assert_eq!(pending.enact_at, 15);
        assert_noop!(
            AuthorityGovernance::schedule_authority_change(
                RuntimeOrigin::root(),
                bounded(initial_authorities()),
                5,
            ),
            Error::<Test>::AuthorityChangeAlreadyPending
        );

        assert_ok!(AuthorityGovernance::cancel_authority_change(
            RuntimeOrigin::root()
        ));
        assert!(PendingAuthorityChange::<Test>::get().is_none());
        assert_noop!(
            AuthorityGovernance::cancel_authority_change(RuntimeOrigin::root()),
            Error::<Test>::NoAuthorityChangePending
        );
    });
}

#[test]
fn enacts_aura_and_grandpa_as_one_governed_transition() {
    new_test_ext().execute_with(|| {
        System::set_block_number(1);
        let replacement = replacement_authorities();
        assert_ok!(AuthorityGovernance::schedule_authority_change(
            RuntimeOrigin::root(),
            bounded(replacement.clone()),
            2,
        ));

        System::set_block_number(2);
        AuthorityGovernance::on_initialize(2);
        assert_eq!(
            pallet_aura::Authorities::<Test>::get().into_inner(),
            initial_authorities()
                .into_iter()
                .map(|authority| authority.aura)
                .collect::<Vec<_>>()
        );

        System::set_block_number(3);
        AuthorityGovernance::on_initialize(3);
        assert_eq!(
            pallet_aura::Authorities::<Test>::get().into_inner(),
            replacement
                .iter()
                .map(|authority| authority.aura.clone())
                .collect::<Vec<_>>()
        );
        assert!(PendingAuthorityChange::<Test>::get().is_none());
        assert!(pallet_grandpa::PendingChange::<Test>::exists());

        Grandpa::on_finalize(3);
        assert_eq!(
            Grandpa::grandpa_authorities(),
            replacement
                .iter()
                .map(|authority| (authority.grandpa.clone(), 1))
                .collect::<Vec<_>>()
        );
        assert!(!pallet_grandpa::PendingChange::<Test>::exists());
        System::assert_has_event(RuntimeEvent::AuthorityGovernance(
            Event::AuthorityChangeEnacted { authority_count: 4 },
        ));
    });
}

#[test]
fn defers_without_changing_aura_when_grandpa_is_busy() {
    new_test_ext().execute_with(|| {
        System::set_block_number(1);
        let initial = initial_authorities();
        let replacement = replacement_authorities();
        assert_ok!(AuthorityGovernance::schedule_authority_change(
            RuntimeOrigin::root(),
            bounded(replacement),
            2,
        ));

        System::set_block_number(2);
        assert_ok!(Grandpa::schedule_change(
            initial
                .iter()
                .map(|authority| (authority.grandpa.clone(), 1))
                .collect(),
            5,
            None,
        ));

        System::set_block_number(3);
        AuthorityGovernance::on_initialize(3);

        assert_eq!(
            pallet_aura::Authorities::<Test>::get().into_inner(),
            initial
                .iter()
                .map(|authority| authority.aura.clone())
                .collect::<Vec<_>>()
        );
        assert!(PendingAuthorityChange::<Test>::get().is_some());
        System::assert_has_event(RuntimeEvent::AuthorityGovernance(
            Event::AuthorityChangeDeferred {
                authority_count: 4,
                enact_at: 3,
            },
        ));

        // Once GRANDPA's unrelated transition clears, the complete OpenPayload
        // transition retries and still applies both authority sets together.
        System::set_block_number(7);
        Grandpa::on_finalize(7);
        assert!(!pallet_grandpa::PendingChange::<Test>::exists());

        System::set_block_number(8);
        AuthorityGovernance::on_initialize(8);
        assert_eq!(
            pallet_aura::Authorities::<Test>::get().into_inner(),
            replacement_authorities()
                .iter()
                .map(|authority| authority.aura.clone())
                .collect::<Vec<_>>()
        );
        Grandpa::on_finalize(8);
        assert!(PendingAuthorityChange::<Test>::get().is_none());
    });
}

#[test]
fn rejects_scheduling_while_grandpa_change_is_already_pending() {
    new_test_ext().execute_with(|| {
        System::set_block_number(1);
        let initial = initial_authorities();
        assert_ok!(Grandpa::schedule_change(
            initial
                .iter()
                .map(|authority| (authority.grandpa.clone(), 1))
                .collect(),
            5,
            None,
        ));

        assert_noop!(
            AuthorityGovernance::schedule_authority_change(
                RuntimeOrigin::root(),
                bounded(replacement_authorities()),
                2,
            ),
            Error::<Test>::ConsensusChangeAlreadyPending
        );
    });
}
