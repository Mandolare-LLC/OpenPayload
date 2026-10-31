use std::convert::TryInto;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::time::Duration;

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![(payload.len() >> 16) as u8, (payload.len() >> 8) as u8, payload.len() as u8, kind, flags];
    bytes.extend_from_slice(&stream.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

async fn flood(payload: &[u8]) {
    let (mut peer, server) = tokio::io::duplex(65536);
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server).await.unwrap();
        // Retain request bodies without reading them, so DATA remains queued.
        let mut requests = Vec::new();
        while let Some(request) = connection.accept().await {
            match request {
                Ok(request) => requests.push(request),
                Err(error) => { assert_eq!(error.reason(), Some(h2::Reason::ENHANCE_YOUR_CALM)); return; }
            }
        }
    });
    peer.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").await.unwrap();
    peer.write_all(&frame(4, 0, 0, &[])).await.unwrap();
    // HPACK: POST, http, /, :authority=x. Keep the request body open.
    peer.write_all(&frame(1, 4, 1, &[0x83, 0x86, 0x84, 0x01, 0x01, b'x'])).await.unwrap();
    for _ in 0..110 { peer.write_all(&frame(0, 0, 1, payload)).await.unwrap(); }
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let mut header = [0; 9];
            peer.read_exact(&mut header).await.unwrap();
            let len = ((header[0] as usize) << 16) | ((header[1] as usize) << 8) | header[2] as usize;
            let mut body = vec![0; len];
            peer.read_exact(&mut body).await.unwrap();
            if header[3] == 7 {
                assert!(body.len() >= 8);
                assert_eq!(u32::from_be_bytes(body[4..8].try_into().unwrap()), 11);
                break;
            }
        }
    }).await.expect("flood was not bounded by a GOAWAY");
    server.abort();
}

#[tokio::test]
async fn empty_data_flood_is_bounded() { flood(&[]).await; }

#[tokio::test]
async fn tiny_data_flood_is_bounded() { flood(b"x").await; }
