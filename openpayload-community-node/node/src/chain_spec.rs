use openpayload_runtime::{
    genesis_config_presets::{OPENPAYLOAD_DEV_RUNTIME_PRESET, OPENPAYLOAD_LOCAL_RUNTIME_PRESET},
    WASM_BINARY,
};
use sc_service::ChainType;
use serde_json::{Map, Value};

/// Specialized `ChainSpec`. This is a specialization of the general Substrate ChainSpec type.
pub type ChainSpec = sc_service::GenericChainSpec;

const OPENPAYLOAD_SS58_FORMAT: u16 = openpayload_runtime::SS58_PREFIX;

fn wasm_binary() -> Result<&'static [u8], String> {
    WASM_BINARY.ok_or_else(|| "OpenPayload runtime wasm not available".to_string())
}

fn openpayload_properties() -> Map<String, Value> {
    let mut properties = Map::new();
    properties.insert("tokenSymbol".into(), Value::from("OPAL"));
    properties.insert("tokenDecimals".into(), Value::from(12));
    properties.insert("ss58Format".into(), Value::from(OPENPAYLOAD_SS58_FORMAT));
    properties
}

pub fn development_chain_spec() -> Result<ChainSpec, String> {
    Ok(ChainSpec::builder(wasm_binary()?, None)
        .with_name("OpenPayload Development")
        .with_id("openpayload-dev")
        .with_chain_type(ChainType::Development)
        .with_protocol_id("openpayload-dev")
        .with_properties(openpayload_properties())
        .with_genesis_config_preset_name(OPENPAYLOAD_DEV_RUNTIME_PRESET)
        .build())
}

pub fn local_chain_spec() -> Result<ChainSpec, String> {
    Ok(ChainSpec::builder(wasm_binary()?, None)
        .with_name("OpenPayload Local")
        .with_id("openpayload-local")
        .with_chain_type(ChainType::Local)
        .with_protocol_id("openpayload-local")
        .with_properties(openpayload_properties())
        .with_genesis_config_preset_name(OPENPAYLOAD_LOCAL_RUNTIME_PRESET)
        .build())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_properties_use_runtime_ss58_prefix() {
        assert_eq!(
            openpayload_properties().get("ss58Format"),
            Some(&Value::from(openpayload_runtime::SS58_PREFIX))
        );
        assert_eq!(
            openpayload_properties().get("tokenSymbol"),
            Some(&Value::from("OPAL"))
        );
        assert_eq!(
            openpayload_properties().get("tokenDecimals"),
            Some(&Value::from(12))
        );
    }
}
