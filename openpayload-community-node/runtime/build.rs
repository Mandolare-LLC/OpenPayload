#[cfg(feature = "std")]
fn use_prebuilt_runtime_if_configured() -> bool {
    use std::{env, fs, path::PathBuf};

    const PREBUILT_RUNTIME_ENV: &str = "OPENPAYLOAD_PREBUILT_RUNTIME_WASM";

    println!("cargo:rerun-if-env-changed={PREBUILT_RUNTIME_ENV}");

    let Ok(configured_path) = env::var(PREBUILT_RUNTIME_ENV) else {
        return false;
    };

    let runtime_path = fs::canonicalize(&configured_path).unwrap_or_else(|error| {
        panic!("failed to resolve {PREBUILT_RUNTIME_ENV}={configured_path}: {error}")
    });
    let metadata = fs::metadata(&runtime_path).unwrap_or_else(|error| {
        panic!(
            "failed to inspect {PREBUILT_RUNTIME_ENV}={}: {error}",
            runtime_path.display()
        )
    });
    assert!(
        metadata.is_file() && metadata.len() > 0,
        "{PREBUILT_RUNTIME_ENV} must reference a non-empty file"
    );

    let runtime_path = runtime_path
        .to_str()
        .expect("prebuilt runtime path must be valid UTF-8");
    let runtime_path_literal = format!("{runtime_path:?}");
    let generated = format!(
        r#"
            pub const WASM_BINARY_PATH: Option<&str> = Some({runtime_path_literal});
            pub const WASM_BINARY: Option<&[u8]> = Some(include_bytes!({runtime_path_literal}));
            pub const WASM_BINARY_BLOATY: Option<&[u8]> = Some(include_bytes!({runtime_path_literal}));
        "#
    );

    let output =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set")).join("wasm_binary.rs");
    fs::write(&output, generated)
        .unwrap_or_else(|error| panic!("failed to write {}: {error}", output.display()));

    println!("cargo:rerun-if-changed={runtime_path}");
    println!("cargo:warning=using prebuilt OpenPayload runtime from {runtime_path}");
    true
}

#[cfg(all(feature = "std", feature = "metadata-hash"))]
fn main() {
    if use_prebuilt_runtime_if_configured() {
        return;
    }

    substrate_wasm_builder::WasmBuilder::init_with_defaults()
        .append_to_rust_flags("-C link-arg=--allow-undefined")
        .enable_metadata_hash("UNIT", 12)
        .build();
}

#[cfg(all(feature = "std", not(feature = "metadata-hash")))]
fn main() {
    if use_prebuilt_runtime_if_configured() {
        return;
    }

    substrate_wasm_builder::WasmBuilder::init_with_defaults()
        .append_to_rust_flags("-C link-arg=--allow-undefined")
        .build();
}

/// The wasm builder is deactivated when compiling
/// this crate for wasm to speed up the compilation.
#[cfg(not(feature = "std"))]
fn main() {}
