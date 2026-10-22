//! Bounded, deterministic HTTPS URL checks; DNS and TLS remain off chain.

pub(crate) fn domain_valid(domain: &[u8]) -> bool {
    domain.len() <= 253
        && domain.contains(&b'.')
        && domain.split(|byte| *byte == b'.').all(|label| {
            !label.is_empty() && label.len() <= 63
                && label.first() != Some(&b'-') && label.last() != Some(&b'-')
                && label.iter().all(|byte| byte.is_ascii_lowercase()
                    || byte.is_ascii_digit() || *byte == b'-')
        })
        && domain.rsplit(|byte| *byte == b'.').next()
            .is_some_and(|label| label.iter().any(u8::is_ascii_lowercase))
}

pub(crate) fn host(url: &[u8]) -> Option<&[u8]> {
    if url.len() > 4096 || !url.iter().all(|byte| (33..=126).contains(byte))
        || url.iter().any(|byte| matches!(byte, b'\\' | b'?' | b'#')) {
        return None;
    }
    let rest = url.strip_prefix(b"https://")?;
    let slash = rest.iter().position(|byte| *byte == b'/')?;
    let authority = &rest[..slash];
    let host = if let Some(colon) = authority.iter().position(|byte| *byte == b':') {
        let port_bytes = &authority[colon + 1..];
        let port = core::str::from_utf8(port_bytes).ok()?.parse::<u16>().ok()?;
        if port == 0 || port == 443 || port_bytes.first() == Some(&b'0')
            || !port_bytes.iter().all(u8::is_ascii_digit) { return None; }
        &authority[..colon]
    } else { authority };
    if !domain_valid(host) { return None; }
    // Require canonical paths: valid escapes and no URL dot-segment rewriting.
    let path = &rest[slash..];
    let mut i = 0;
    while i < path.len() {
        if path[i] == b'%' {
            if i + 2 >= path.len() || !path[i + 1..i + 3].iter().all(u8::is_ascii_hexdigit) {
                return None;
            }
            i += 3;
        } else { i += 1; }
    }
    for segment in path.split(|byte| *byte == b'/') {
        let mut dots = 0;
        let mut rest = segment;
        while !rest.is_empty() {
            if rest[0] == b'.' { dots += 1; rest = &rest[1..]; }
            else if rest.len() >= 3 && rest[0] == b'%' && rest[1] == b'2'
                && matches!(rest[2], b'e' | b'E') { dots += 1; rest = &rest[3..]; }
            else { break; }
        }
        if rest.is_empty() && (dots == 1 || dots == 2) { return None; }
    }
    Some(host)
}

pub(crate) fn authorized(url: &[u8], domain: &[u8]) -> bool {
    domain_valid(domain) && host(url).is_some_and(|host| {
        host == domain || (host.len() > domain.len()
            && host.ends_with(domain) && host[host.len() - domain.len() - 1] == b'.')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parent_authorizes_descendants_with_label_boundaries() {
        for url in [b"https://talaria.chat/".as_slice(), b"https://api.talaria.chat/v1/calls",
            b"https://push.use2.talaria.chat:8443/v1/calls"] {
            assert!(authorized(url, b"talaria.chat"));
        }
        for url in [b"https://eviltalaria.chat/v1/calls".as_slice(),
            b"https://talaria.chat.example.com/v1/calls", b"https://talaria.chat@evil.chat/",
            b"http://talaria.chat/", b"https://talaria.chat:443/", b"https://talaria.chat:0/",
            b"https://talaria.chat:08443/", b"https://talaria.chat:65536/",
            b"https://127.0.0.1/", b"https://talaria.chat/../calls", b"https://talaria.chat/%2e./calls",
            b"https://talaria.chat/%zz", b"https://talaria.chat/?secret=x", b"https://talaria.chat/#x"] {
            assert!(!authorized(url, b"talaria.chat"));
        }
    }
}
