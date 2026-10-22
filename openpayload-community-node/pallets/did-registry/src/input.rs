//! Deterministic input checks; never resolves URLs or executes overlay content.
use alloc::{
    collections::BTreeSet,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;
use serde::{
    de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor},
    Deserializer,
};
use serde_json::Value;

pub const OVERLAY_PREFIX: &[u8] = b"\0OP:SVC:1:";
pub fn token(value: &[u8]) -> bool {
    !value.is_empty()
        && value
            .iter()
            .all(|b| (33..127).contains(b) && !b"<>\"`\\".contains(b))
}
pub fn reserved(value: &[u8]) -> bool {
    value
        .windows(11)
        .any(|v| v.eq_ignore_ascii_case(b"openpayload"))
}
pub fn protected(value: &[u8]) -> bool {
    [
        b"OpenPayloadCacheService".as_slice(),
        b"OpenPayloadRelayService",
        b"OpenPayloadArchiveService",
        b"OpenPayloadApplicationControlService",
    ]
    .contains(&value)
}
pub fn uri(value: &[u8]) -> bool {
    if !token(value)
        || value.iter().filter(|b| **b == b'#').count() > 1
        || value.iter().any(|b| b"{}|^".contains(b))
    {
        return false;
    }
    for (i, b) in value.iter().enumerate() {
        if *b == b'%'
            && (i + 2 >= value.len()
                || !value[i + 1].is_ascii_hexdigit()
                || !value[i + 2].is_ascii_hexdigit())
        {
            return false;
        }
    }
    let Some(colon) = value.iter().position(|b| *b == b':') else {
        return false;
    };
    colon > 0
        && colon + 1 < value.len()
        && value[0].is_ascii_alphabetic()
        && value[..colon]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"+.-".contains(b))
}
pub fn https(value: &[u8]) -> bool {
    if !uri(value) || !value.starts_with(b"https://") || value.iter().any(|b| b"@?#".contains(b)) {
        return false;
    }
    let authority = value[8..].split(|b| *b == b'/').next().unwrap_or_default();
    let (host, port) = if authority.starts_with(b"[") {
        let Some(end) = authority.iter().position(|b| *b == b']') else {
            return false;
        };
        if core::str::from_utf8(&authority[1..end])
            .ok()
            .and_then(|s| s.parse::<core::net::Ipv6Addr>().ok())
            .is_none()
        {
            return false;
        }
        (&authority[..=end], &authority[end + 1..])
    } else {
        let colon = authority
            .iter()
            .position(|b| *b == b':')
            .unwrap_or(authority.len());
        let host = &authority[..colon];
        if !host
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b".-".contains(b))
        {
            return false;
        }
        (host, &authority[colon..])
    };
    !host.is_empty()
        && (port.is_empty()
            || port
                .strip_prefix(b":")
                .and_then(|p| core::str::from_utf8(p).ok())
                .and_then(|p| p.parse::<u16>().ok())
                .is_some_and(|p| p != 0))
}
pub fn component(did: &[u8], id: &[u8]) -> bool {
    if !token(id) {
        return false;
    }
    let fragment = if let Some(v) = id.strip_prefix(did) {
        v
    } else {
        id
    };
    fragment.starts_with(b"#") && fragment.len() > 1 && !fragment[1..].contains(&b'#')
}
pub fn normalized(did: &[u8], id: &[u8]) -> Vec<u8> {
    if id.starts_with(b"#") {
        [did, id].concat()
    } else {
        id.to_vec()
    }
}
pub fn key(encoded: &[u8], codec: u8) -> bool {
    let Some(payload) = encoded.strip_prefix(b"z") else {
        return false;
    };
    super::pallet::decode_base58btc(payload).is_some_and(|raw| {
        let key = match raw.as_slice() {
            bytes if bytes.len() == 32 => bytes,
            bytes if bytes.len() == 34 && bytes[0] == codec && bytes[1] == 1 => &bytes[2..],
            _ => return false,
        };
        let Ok(bytes) = <[u8; 32]>::try_from(key) else {
            return false;
        };
        if codec == 0xed {
            ed25519_point(bytes)
        } else {
            curve25519_dalek::montgomery::MontgomeryPoint(bytes)
                .mul_clamped([42; 32])
                .to_bytes()
                != [0; 32]
        }
    })
}

// Custom seed rejects duplicate names while bounding nesting and number of values.
struct Seed<'a> {
    depth: usize,
    count: &'a mut usize,
}
impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        *self.count += 1;
        if self.depth > 16 || *self.count > 256 {
            return Err(de::Error::custom("JSON complexity"));
        }
        d.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("bounded JSON")
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        serde_json::Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| de::Error::custom("number"))
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_string()))
    }
    fn visit_string<E: de::Error>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
        let mut result = Vec::new();
        while let Some(v) = a.next_element_seed(Seed {
            depth: self.depth + 1,
            count: self.count,
        })? {
            result.push(v);
        }
        Ok(Value::Array(result))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
        let mut result = serde_json::Map::new();
        while let Some(k) = a.next_key::<String>()? {
            if result.contains_key(&k) {
                return Err(de::Error::custom("duplicate property"));
            }
            let v = a.next_value_seed(Seed {
                depth: self.depth + 1,
                count: self.count,
            })?;
            result.insert(k, v);
        }
        Ok(Value::Object(result))
    }
}
pub fn overlay(data: &[u8], id: &[u8], type_: &[u8]) -> bool {
    if data.len() > 4096 || reserved(type_) {
        return false;
    }
    let Some(json) = data.strip_prefix(OVERLAY_PREFIX) else {
        return false;
    };
    let Some(value) = bounded_json(json) else {
        return false;
    };
    let Some(map) = value.as_object() else {
        return false;
    };
    if map.get("id").and_then(Value::as_str).map(str::as_bytes) != Some(id) {
        return false;
    }
    let Some(types) = map.get("type") else {
        return false;
    };
    let types: Vec<&Value> = if let Some(values) = types.as_array() {
        values.iter().collect()
    } else {
        alloc::vec![types]
    };
    let mut seen = BTreeSet::new();
    if types.is_empty() || types.len() > 5 {
        return false;
    }
    for t in &types {
        let Some(s) = t.as_str() else {
            return false;
        };
        if s.len() > 64 || !token(s.as_bytes()) || reserved(s.as_bytes()) || !seen.insert(s) {
            return false;
        }
    }
    if types[0].as_str().map(str::as_bytes) != Some(type_) {
        return false;
    }
    let Some(endpoint) = map.get("serviceEndpoint") else {
        return false;
    };
    let endpoints: Vec<&Value> = if let Some(values) = endpoint.as_array() {
        values.iter().collect()
    } else {
        alloc::vec![endpoint]
    };
    !endpoints.is_empty()
        && endpoints.len() <= 5
        && endpoints
            .iter()
            .all(|e| e.is_object() || e.as_str().is_some_and(|s| uri(s.as_bytes())))
}

pub fn proof_nonce(timestamp: &[u8], now: u64) -> Option<u64> {
    // v2 + two canonical u64 decimal strings + separators. Reject oversized
    // untrusted input before UTF-8 scanning or numeric parsing.
    if timestamp.len() > 45 {
        return None;
    }
    let text = core::str::from_utf8(timestamp).ok()?;
    let mut parts = text.split(':');
    if parts.next()? != "v2" {
        return None;
    }
    let n = parts.next()?;
    let expiry = parts.next()?;
    let nonce = n.parse::<u64>().ok()?;
    let until = expiry.parse::<u64>().ok()?;
    if parts.next().is_some()
        || n != nonce.to_string()
        || expiry != until.to_string()
        || until <= now
        || until > now.saturating_add(3_600_000)
    {
        return None;
    }
    Some(nonce)
}

pub fn ed25519_point(bytes: [u8; 32]) -> bool {
    use curve25519_dalek::traits::IsIdentity;
    curve25519_dalek::edwards::CompressedEdwardsY(bytes)
        .decompress()
        .is_some_and(|point| {
            point.is_torsion_free() && !point.is_identity() && point.compress().to_bytes() == bytes
        })
}

pub const KEY_PREFIX: &[u8] = b"\0OP:KEY:1:";
pub fn bounded_json(data: &[u8]) -> Option<Value> {
    // Match the API's integer range without silently rounding oversized integers to f64.
    let mut i = 0;
    let mut quoted = false;
    while i < data.len() {
        let b = data[i];
        if quoted {
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == b'"' {
                quoted = false;
            }
        } else if b == b'"' {
            quoted = true;
        } else if b == b'-' || b.is_ascii_digit() {
            let start = i;
            while i < data.len() && (data[i].is_ascii_digit() || b"-+.eE".contains(&data[i])) {
                i += 1;
            }
            let number = core::str::from_utf8(&data[start..i]).ok()?;
            if !number.parse::<f64>().ok()?.is_finite() {
                return None;
            }
            if !number.contains(['.', 'e', 'E'])
                && number.parse::<u64>().is_err()
                && number.parse::<i64>().is_err()
            {
                return None;
            }
            continue;
        }
        i += 1;
    }
    let mut d = serde_json::Deserializer::from_slice(data);
    let mut count = 0;
    let _value = (Seed {
        depth: 0,
        count: &mut count,
    })
    .deserialize(&mut d)
    .ok()?;
    d.end().ok()?;
    // Deserialize Value after the duplicate/depth pass so feature unification with
    // serde_json/arbitrary_precision cannot turn numeric scalars into marker maps.
    serde_json::from_slice(data).ok()
}
pub fn record_key(id: &[u8], type_: &[u8], controller: &[u8], material: &[u8]) -> bool {
    if !token(id)
        || !(id.starts_with(b"#") && id.len() > 1 || id.starts_with(b"did:") && uri(id))
        || !token(type_)
        || !controller.starts_with(b"did:")
        || !uri(controller)
    {
        return false;
    }
    if let Some(data) = material.strip_prefix(KEY_PREFIX) {
        if data.len() > 3900 {
            return false;
        }
        let Some(value) = bounded_json(data) else {
            return false;
        };
        let Some(map) = value.as_object() else {
            return false;
        };
        if map.get("id").and_then(Value::as_str).map(str::as_bytes) != Some(id)
            || map.get("type").and_then(Value::as_str).map(str::as_bytes) != Some(type_)
            || map
                .get("controller")
                .and_then(Value::as_str)
                .map(str::as_bytes)
                != Some(controller)
        {
            return false;
        }
        if let Some(m) = map.get("publicKeyMultibase") {
            if !m
                .as_str()
                .is_some_and(|v| v.len() <= 3900 && token(v.as_bytes()))
            {
                return false;
            }
        }
        if map.get("publicKeyJwk").is_some_and(|v| !v.is_object()) {
            return false;
        }
        true
    } else {
        material.len() <= 3900 && token(material)
    }
}
pub fn signing_material(material: &[u8]) -> Option<Vec<u8>> {
    let result = if let Some(data) = material.strip_prefix(KEY_PREFIX) {
        bounded_json(data)?
            .get("publicKeyMultibase")?
            .as_str()?
            .as_bytes()
            .to_vec()
    } else {
        material.to_vec()
    };
    if result.len() <= 128 && key(&result, 0xed) {
        Some(result)
    } else {
        None
    }
}
