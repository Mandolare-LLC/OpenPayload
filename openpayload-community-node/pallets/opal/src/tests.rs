use crate::{mock::*, AccountingRefOf, Error, RetrievalBurns, RetrievalBurnsEnabled, RewardMints};
use frame_support::{
    assert_noop, assert_ok,
    traits::{GetStorageVersion, StorageVersion},
};

#[test]
fn pallet_declares_and_genesis_records_storage_version_one() {
    new_test_ext().execute_with(|| {
        assert_eq!(Opal::in_code_storage_version(), StorageVersion::new(1));
        assert_eq!(Opal::on_chain_storage_version(), StorageVersion::new(1));
    });
}

fn accounting_ref(raw: &[u8]) -> AccountingRefOf<Test> {
    raw.to_vec().try_into().unwrap()
}

#[test]
fn runtime_reward_path_can_mint_with_unique_accounting_reference() {
    new_test_ext().execute_with(|| {
        let issuance_before = Balances::total_issuance();

        assert_ok!(Opal::mint_reward_to(&99, 500, b"reward:1".to_vec()));

        assert_eq!(Balances::free_balance(99), 500);
        assert_eq!(Balances::total_issuance(), issuance_before + 500);
        assert!(RewardMints::<Test>::contains_key(accounting_ref(
            b"reward:1"
        )));
    });
}

#[test]
fn runtime_reward_path_never_records_a_sub_existential_noop() {
    new_test_ext().execute_with(|| {
        let issuance_before = Balances::total_issuance();

        assert_noop!(
            Opal::mint_reward_to(&99, 9, b"reward:dust".to_vec()),
            Error::<Test>::RewardMintFailed
        );

        assert_eq!(Balances::free_balance(99), 0);
        assert_eq!(Balances::total_issuance(), issuance_before);
        assert!(!RewardMints::<Test>::contains_key(accounting_ref(
            b"reward:dust"
        )));
    });
}

#[test]
fn recipient_retrieval_burn_reduces_issuance() {
    new_test_ext().execute_with(|| {
        let issuance_before = Balances::total_issuance();
        let operator_before = Balances::free_balance(99);

        assert_ok!(Opal::burn_for_retrieval(
            RuntimeOrigin::signed(1),
            100,
            b"retrieval:1".to_vec()
        ));

        assert_eq!(Balances::free_balance(1), 900);
        assert_eq!(Balances::free_balance(99), operator_before);
        assert_eq!(Balances::total_issuance(), issuance_before - 100);
        assert!(RetrievalBurns::<Test>::contains_key(accounting_ref(
            b"retrieval:1"
        )));
    });
}

#[test]
fn retrieval_burn_is_fail_closed_until_governance_enables_it() {
    new_test_ext().execute_with(|| {
        RetrievalBurnsEnabled::<Test>::put(false);
        let issuance_before = Balances::total_issuance();
        assert_noop!(
            Opal::burn_for_retrieval(
                RuntimeOrigin::signed(1),
                100,
                b"retrieval:disabled".to_vec(),
            ),
            Error::<Test>::RetrievalBurnsDisabled
        );
        assert_eq!(Balances::total_issuance(), issuance_before);

        assert_noop!(
            Opal::set_retrieval_burns_enabled(RuntimeOrigin::signed(1), true),
            sp_runtime::DispatchError::BadOrigin
        );
        assert_ok!(Opal::set_retrieval_burns_enabled(
            RuntimeOrigin::root(),
            true,
        ));
        assert_ok!(Opal::burn_for_retrieval(
            RuntimeOrigin::signed(1),
            100,
            b"retrieval:enabled".to_vec(),
        ));
    });
}

#[test]
fn duplicate_refs_are_rejected() {
    new_test_ext().execute_with(|| {
        assert_ok!(Opal::burn_for_retrieval(
            RuntimeOrigin::signed(1),
            100,
            b"retrieval:1".to_vec()
        ));
        assert_noop!(
            Opal::burn_for_retrieval(RuntimeOrigin::signed(1), 50, b"retrieval:1".to_vec()),
            Error::<Test>::DuplicateRetrievalRef
        );

        assert_ok!(Opal::mint_reward_to(&99, 500, b"reward:1".to_vec()));
        assert_noop!(
            Opal::mint_reward_to(&99, 500, b"reward:1".to_vec()),
            Error::<Test>::DuplicateRewardRef
        );
    });
}

#[test]
fn transfer_moves_existing_opal() {
    new_test_ext().execute_with(|| {
        assert_ok!(Opal::transfer(RuntimeOrigin::signed(1), 2, 100));
        assert_eq!(Balances::free_balance(1), 900);
        assert_eq!(Balances::free_balance(2), 150);
    });
}
