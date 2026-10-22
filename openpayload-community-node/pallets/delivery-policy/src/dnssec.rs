//! Offline DNSSEC verification. No resolver, Directory identity, or built-in anchor is trusted.

use alloc::vec::Vec;
use dnssec_prover::{rr::{DS, RR, Record}, ser::parse_rr_stream,
    validation::verify_rr_stream_with_trust_anchors};

pub const MAX_PROOF_BYTES: usize = 65_536;
pub const MAX_RECORDS: usize = 128;

/// Returns the earliest signature expiry in milliseconds after validating an exact TXT record.
/// Challenge freshness and intent binding are enforced separately by the pallet.
#[allow(clippy::result_unit_err)] // Callers intentionally receive one uniform proof-rejection result.
pub fn verify_txt(anchors: &[DS], now_ms: u64, name: &str, value: &[u8], proof: &[u8])
    -> Result<u64, ()> {
    if proof.is_empty() || proof.len() > MAX_PROOF_BYTES || anchors.is_empty() {
        return Err(());
    }
    // Bound record count before parsing: every record is at least 11 bytes. Scan the
    // uncompressed RFC 9102 wire stream without allocating attacker-controlled records.
    let mut at = 0usize;
    let mut count = 0usize;
    while at < proof.len() {
        count += 1;
        if count > MAX_RECORDS { return Err(()); }
        loop {
            let len = *proof.get(at).ok_or(())? as usize;
            at += 1;
            if len == 0 { break; }
            if len > 63 { return Err(()); }
            at = at.checked_add(len).ok_or(())?;
            if at > proof.len() { return Err(()); }
        }
        let header = proof.get(at..at + 10).ok_or(())?;
        if header[2..4] != [0, 1] { return Err(()); }
        let len = u16::from_be_bytes([header[8], header[9]]) as usize;
        at = at.checked_add(10 + len).ok_or(())?;
        if at > proof.len() { return Err(()); }
    }
    let records = parse_rr_stream(proof)?;
    let mut signatures = 0;
    let mut keys = 0;
    for rr in &records {
        match rr {
            RR::DnsKey(key) => {
                keys += 1;
                if keys > 32 || key.pubkey.len() > 516 || key.flags & 128 != 0 { return Err(()); }
                match key.alg {
                    8 | 10 => {
                        // Limit RSA exponent size and modulus to prevent excessive verification work.
                        let first = *key.pubkey.first().ok_or(())? as usize;
                        let (exponent, offset) = if first == 0 {
                            let bytes = key.pubkey.get(1..3).ok_or(())?;
                            (u16::from_be_bytes([bytes[0], bytes[1]]) as usize, 3)
                        } else { (first, 1) };
                        let modulus = key.pubkey.len().checked_sub(offset + exponent).ok_or(())?;
                        if exponent == 0 || exponent > 4 || !(128..=512).contains(&modulus) { return Err(()); }
                    }
                    13 if key.pubkey.len() == 64 => (),
                    14 if key.pubkey.len() == 96 => (),
                    _ => return Err(()),
                }
            }
            RR::RRSig(sig) => {
                signatures += 1;
                // A textual suffix is insufficient: example.com must not sign notexample.com.
                let owner = sig.name.as_str();
                let signer = sig.key_name.as_str();
                let within_zone = signer == "." || owner == signer
                    || owner.strip_suffix(signer).is_some_and(|prefix| prefix.ends_with('.'));
                if !within_zone || (sig.ty == 48 && owner != signer)
                    || (sig.ty == 43 && owner == signer) { return Err(()); }
                if signatures > 24 || sig.signature.len() > 512
                    || ![8, 10, 13, 14].contains(&sig.alg)
                    || usize::from(sig.labels) != sig.name.as_str().split('.').filter(|label| !label.is_empty()).count() { return Err(()); }
            }
            RR::DS(ds) if (ds.digest_type == 2 && ds.digest.len() == 32)
                || (ds.digest_type == 4 && ds.digest.len() == 48) => (),
            RR::Txt(txt) if txt.data.len() <= 4096 => (),
            // No aliases, wildcards, negative proofs, or unrelated record types on this path.
            _ => return Err(()),
        }
        if records.iter().filter(|other| other.name() == rr.name() && other.ty() == rr.ty()).count() > 16 {
            return Err(());
        }
    }
    let verified = verify_rr_stream_with_trust_anchors(&records, anchors).map_err(|_| ())?;
    let now = now_ms / 1000;
    if now < verified.valid_from || now >= verified.expires { return Err(()); }
    let exact_name = name.to_ascii_lowercase();
    if !verified.verified_rrs.iter().any(|rr| matches!(rr,
        RR::Txt(txt) if txt.name.as_str() == exact_name && txt.data.as_vec() == value)) {
        return Err(());
    }
    // DNSSEC proves a signed observation, not live DNS. Bound TXT observation age to
    // 48 hours as well as signature expiry so pre-signed future challenges cannot
    // turn a long-lived DNS signature into a deferred ownership claim.
    let txt_fresh_until = records.iter().filter_map(|rr| match rr {
        RR::RRSig(sig) if sig.ty == 16 && sig.name.as_str() == exact_name =>
            Some(u64::from(sig.inception).saturating_mul(1000).saturating_add(48 * 3_600_000)),
        _ => None,
    }).min().ok_or(())?;
    let expires = verified.expires.saturating_mul(1000).min(txt_fresh_until);
    if now_ms >= expires { return Err(()); }
    Ok(expires)
}

/// Canonical challenge material shared with OpenDispatch. All integers use SCALE encoding.
pub fn challenge_value(genesis: &[u8], persona: &[u8], operator: &[u8], action: &[u8],
    nonce: u64, expires: u64, request_id: &[u8; 32]) -> Vec<u8> {
    use codec::Encode;
    let mut intent = b"openpayload:persona:dnssec:v1".to_vec().encode();
    intent.extend_from_slice(genesis);
    intent.extend_from_slice(&persona.to_vec().encode());
    intent.extend_from_slice(&operator.to_vec().encode());
    intent.extend_from_slice(&action.to_vec().encode());
    intent.extend_from_slice(&nonce.encode());
    intent.extend_from_slice(&expires.encode());
    intent.extend_from_slice(request_id);
    let digest = sp_io::hashing::sha2_256(&intent);
    let mut value = b"openpayload-persona-dnssec-v1=".to_vec();
    for byte in digest {
        value.push(b"0123456789abcdef"[(byte >> 4) as usize]);
        value.push(b"0123456789abcdef"[(byte & 15) as usize]);
    }
    value
}
