// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::{
    AccountId, BalancesConfig, OpalConfig, ResourceRewardsConfig, RuntimeGenesisConfig, SudoConfig,
    CACHE_REWARD_HISTORY_RETENTION_EPOCHS,
};
use alloc::{vec, vec::Vec};
use frame_support::build_struct_json_patch;
use serde_json::Value;
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_consensus_grandpa::AuthorityId as GrandpaId;
use sp_genesis_builder::{self, PresetId};
use sp_keyring::Sr25519Keyring;

pub const OPENPAYLOAD_MAINNET_RUNTIME_PRESET: &str = "openpayload-mainnet";
pub const OPENPAYLOAD_DEV_RUNTIME_PRESET: &str = "openpayload-dev";
pub const OPENPAYLOAD_LOCAL_RUNTIME_PRESET: &str = "openpayload-local";
const DEVELOPMENT_CACHE_REWARD_HISTORY_RETENTION_EPOCHS: u64 = 1;

/// Dedicated Ed25519 resource-validator accounts for disposable development
/// chains. Their public development seeds are documented in the Dev roster;
/// these identities must never appear in a public chain specification.
pub const DEV_RESOURCE_VALIDATOR_ONE: [u8; 32] = [
    0x8a, 0x88, 0xe3, 0xdd, 0x74, 0x09, 0xf1, 0x95, 0xfd, 0x52, 0xdb, 0x2d, 0x3c, 0xba, 0x5d, 0x72,
    0xca, 0x67, 0x09, 0xbf, 0x1d, 0x94, 0x12, 0x1b, 0xf3, 0x74, 0x88, 0x01, 0xb4, 0x0f, 0x6f, 0x5c,
];
pub const DEV_RESOURCE_VALIDATOR_TWO: [u8; 32] = [
    0x81, 0x39, 0x77, 0x0e, 0xa8, 0x7d, 0x17, 0x5f, 0x56, 0xa3, 0x54, 0x66, 0xc3, 0x4c, 0x7e, 0xcc,
    0xcb, 0x8d, 0x8a, 0x91, 0xb4, 0xee, 0x37, 0xa2, 0x5d, 0xf6, 0x0f, 0x5b, 0x8f, 0xc9, 0xb3, 0x94,
];
pub const DEV_CACHE_NODE: [u8; 32] = [
    0xed, 0x49, 0x28, 0xc6, 0x28, 0xd1, 0xc2, 0xc6, 0xea, 0xe9, 0x03, 0x38, 0x90, 0x59, 0x95, 0x61,
    0x29, 0x59, 0x27, 0x3a, 0x5c, 0x63, 0xf9, 0x36, 0x36, 0xc1, 0x46, 0x14, 0xac, 0x87, 0x37, 0xd1,
];

fn development_resource_validator_accounts() -> Vec<AccountId> {
    vec![
        AccountId::from(DEV_RESOURCE_VALIDATOR_ONE),
        AccountId::from(DEV_RESOURCE_VALIDATOR_TWO),
    ]
}

// Returns the genesis config presets populated with given parameters.
fn testnet_genesis(
    initial_authorities: Vec<(AuraId, GrandpaId)>,
    endowed_accounts: Vec<AccountId>,
    root: AccountId,
    root_sponsor: AccountId,
    approved_resource_validators: Vec<AccountId>,
    cache_reward_history_retention_epochs: u64,
) -> Value {
    build_struct_json_patch!(RuntimeGenesisConfig {
        balances: BalancesConfig {
            balances: endowed_accounts
                .iter()
                .cloned()
                .map(|k| (k, 1u128 << 60))
                .collect::<Vec<_>>(),
        },
        aura: pallet_aura::GenesisConfig {
            authorities: initial_authorities
                .iter()
                .map(|x| x.0.clone())
                .collect::<Vec<_>>(),
        },
        grandpa: pallet_grandpa::GenesisConfig {
            authorities: initial_authorities
                .iter()
                .map(|x| (x.1.clone(), 1))
                .collect::<Vec<_>>(),
        },
        sudo: SudoConfig {
            key: Some(root.clone()),
        },
        opal: OpalConfig {
            retrieval_burns_enabled: false,
            _config: Default::default(),
        },
        resource_rewards: ResourceRewardsConfig {
            approved_validators: approved_resource_validators,
            validator_activity_paused: false,
            cache_trigger_evidence_enabled: true,
            reward_payments_paused: false,
            reward_payments_start_epoch: Some(0),
            reward_policy_version: 1,
            root_sponsor: Some(root_sponsor),
            cache_reward_history_retention_epochs,
        },
    })
}

/// Return the development genesis config.
pub fn development_config_genesis() -> Value {
    let resource_validators = development_resource_validator_accounts();
    let mut endowed_accounts = vec![
        Sr25519Keyring::Alice.to_account_id(),
        Sr25519Keyring::Bob.to_account_id(),
        Sr25519Keyring::AliceStash.to_account_id(),
        Sr25519Keyring::BobStash.to_account_id(),
    ];
    endowed_accounts.extend(resource_validators.clone());
    endowed_accounts.push(AccountId::from(DEV_CACHE_NODE));
    testnet_genesis(
        vec![(
            sp_keyring::Sr25519Keyring::Alice.public().into(),
            sp_keyring::Ed25519Keyring::Alice.public().into(),
        )],
        endowed_accounts,
        sp_keyring::Sr25519Keyring::Alice.to_account_id(),
        sp_keyring::Sr25519Keyring::Bob.to_account_id(),
        resource_validators,
        DEVELOPMENT_CACHE_REWARD_HISTORY_RETENTION_EPOCHS,
    )
}

/// Return the local genesis config preset.
pub fn local_config_genesis() -> Value {
    let resource_validators = development_resource_validator_accounts();
    let mut endowed_accounts = Sr25519Keyring::iter()
        .filter(|v| v != &Sr25519Keyring::One && v != &Sr25519Keyring::Two)
        .map(|v| v.to_account_id())
        .collect::<Vec<_>>();
    endowed_accounts.extend(resource_validators.clone());
    endowed_accounts.push(AccountId::from(DEV_CACHE_NODE));
    testnet_genesis(
        vec![
            (
                sp_keyring::Sr25519Keyring::Alice.public().into(),
                sp_keyring::Ed25519Keyring::Alice.public().into(),
            ),
            (
                sp_keyring::Sr25519Keyring::Bob.public().into(),
                sp_keyring::Ed25519Keyring::Bob.public().into(),
            ),
        ],
        endowed_accounts,
        Sr25519Keyring::Alice.to_account_id(),
        Sr25519Keyring::Bob.to_account_id(),
        resource_validators,
        DEVELOPMENT_CACHE_REWARD_HISTORY_RETENTION_EPOCHS,
    )
}

/// Return the OpenPayload mainnet genesis config preset.
///
/// This preset is intentionally minimal until the launch key ceremony provides
/// final authority, root/governance, endowment, and bootnode values. Generate a
/// plain chain spec from this preset and replace those launch values before
/// producing the raw production spec.
pub fn openpayload_mainnet_config_genesis() -> Value {
    testnet_genesis(
        vec![(
            sp_keyring::Sr25519Keyring::Alice.public().into(),
            sp_keyring::Ed25519Keyring::Alice.public().into(),
        )],
        // The live scaffold must not silently create development-account
        // issuance. Every non-reserve launch allocation is an explicit raw
        // chain-spec decision and is included in the 2% supply-based cap.
        Vec::new(),
        sp_keyring::Sr25519Keyring::Alice.to_account_id(),
        sp_keyring::Sr25519Keyring::Bob.to_account_id(),
        Vec::new(),
        CACHE_REWARD_HISTORY_RETENTION_EPOCHS,
    )
}

/// Provides the JSON representation of predefined genesis config for given `id`.
pub fn get_preset(id: &PresetId) -> Option<Vec<u8>> {
    let patch = match id.as_ref() {
        sp_genesis_builder::DEV_RUNTIME_PRESET => development_config_genesis(),
        sp_genesis_builder::LOCAL_TESTNET_RUNTIME_PRESET => local_config_genesis(),
        OPENPAYLOAD_DEV_RUNTIME_PRESET => development_config_genesis(),
        OPENPAYLOAD_LOCAL_RUNTIME_PRESET => local_config_genesis(),
        OPENPAYLOAD_MAINNET_RUNTIME_PRESET => openpayload_mainnet_config_genesis(),
        _ => return None,
    };
    Some(
        serde_json::to_string(&patch)
            .expect("serialization to json is expected to work. qed.")
            .into_bytes(),
    )
}

/// List of supported presets.
pub fn preset_names() -> Vec<PresetId> {
    vec![
        PresetId::from(sp_genesis_builder::DEV_RUNTIME_PRESET),
        PresetId::from(sp_genesis_builder::LOCAL_TESTNET_RUNTIME_PRESET),
        PresetId::from(OPENPAYLOAD_DEV_RUNTIME_PRESET),
        PresetId::from(OPENPAYLOAD_LOCAL_RUNTIME_PRESET),
        PresetId::from(OPENPAYLOAD_MAINNET_RUNTIME_PRESET),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_presets_require_an_explicit_resource_validator_roster() {
        let preset = openpayload_mainnet_config_genesis();
        assert_eq!(
            preset
                .pointer("/balances/balances")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(0)
        );
        assert_eq!(
            preset
                .pointer("/opal/retrievalBurnsEnabled")
                .and_then(Value::as_bool),
            Some(false)
        );
        assert_eq!(
            preset
                .pointer("/resourceRewards/approvedValidators")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(0)
        );
        assert_eq!(
            preset
                .pointer("/resourceRewards/validatorActivityPaused")
                .and_then(Value::as_bool),
            Some(false)
        );
        assert_eq!(
            preset
                .pointer("/resourceRewards/cacheTriggerEvidenceEnabled")
                .and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            preset
                .pointer("/resourceRewards/rewardPaymentsPaused")
                .and_then(Value::as_bool),
            Some(false)
        );
        assert_eq!(
            preset
                .pointer("/resourceRewards/rewardPaymentsStartEpoch")
                .and_then(Value::as_u64),
            Some(0)
        );
        assert_eq!(
            preset
                .pointer("/resourceRewards/rewardPolicyVersion")
                .and_then(Value::as_u64),
            Some(1)
        );
        assert!(preset
            .pointer("/resourceRewards/rootSponsor")
            .is_some_and(|value| !value.is_null()));
        assert_ne!(
            preset.pointer("/sudo/key"),
            preset.pointer("/resourceRewards/rootSponsor"),
            "sudo and root sponsor must be independent identities",
        );
        assert_eq!(
            preset
                .pointer("/resourceRewards/cacheRewardHistoryRetentionEpochs")
                .and_then(Value::as_u64),
            Some(CACHE_REWARD_HISTORY_RETENTION_EPOCHS)
        );
    }

    #[test]
    fn local_presets_remain_usable_for_validator_development() {
        assert_eq!(
            development_config_genesis()
                .pointer("/resourceRewards/approvedValidators")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(2)
        );
        assert_eq!(
            local_config_genesis()
                .pointer("/resourceRewards/approvedValidators")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(2)
        );
        for preset in [development_config_genesis(), local_config_genesis()] {
            assert_eq!(
                preset
                    .pointer("/resourceRewards/cacheRewardHistoryRetentionEpochs")
                    .and_then(Value::as_u64),
                Some(DEVELOPMENT_CACHE_REWARD_HISTORY_RETENTION_EPOCHS)
            );
        }
    }
}
