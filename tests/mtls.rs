//! Mutual-TLS tests against a server that demands a client certificate.
//!
//! The only tests that exercise a real handshake with a certificate from
//! the Windows store.  `.github/actions/start-mtls` sets `WREST_MTLS_URL`
//! and `WREST_MTLS_THUMBPRINT` (40 hex chars, for a `CurrentUser\MY`
//! certificate with a non-exportable key); without both, these skip.

#![cfg(all(native_winhttp, feature = "client-cert"))]
#![expect(clippy::tests_outside_test_module)]

use std::time::Duration;
use wrest::{Client, StatusCode, tls::Identity};

/// The CI-provided environment, or `None` when these tests should skip.
///
/// Also asserts the server is reachable. Without that check a dead
/// server is indistinguishable from a rejected handshake, which would
/// let [`without_an_identity_the_handshake_fails`] pass for entirely the
/// wrong reason -- as it did on the first CI run, when the server had
/// been reaped before the tests started.
fn mtls_env() -> Option<(String, [u8; 20])> {
    let url = std::env::var("WREST_MTLS_URL").ok()?;
    let thumbprint = std::env::var("WREST_MTLS_THUMBPRINT").ok()?;
    let thumbprint = parse_thumbprint(&thumbprint)
        .unwrap_or_else(|| panic!("WREST_MTLS_THUMBPRINT is not 40 hex chars: {thumbprint:?}"));

    let authority = url
        .strip_prefix("https://")
        .unwrap_or_else(|| panic!("WREST_MTLS_URL should be https: {url}"));
    if let Err(e) = std::net::TcpStream::connect(authority) {
        panic!("mTLS server at {authority} is not reachable ({e}); these tests cannot be trusted");
    }

    Some((url, thumbprint))
}

/// Parse 40 hex characters into a SHA-1 thumbprint. Windows reports
/// thumbprints in uppercase; accept either case.
fn parse_thumbprint(hex: &str) -> Option<[u8; 20]> {
    let hex = hex.trim();
    if hex.len() != 40 {
        return None;
    }
    let (pairs, remainder) = hex.as_bytes().as_chunks::<2>();
    debug_assert!(remainder.is_empty(), "40 is even");

    let mut out = [0u8; 20];
    for (slot, pair) in out.iter_mut().zip(pairs) {
        let pair = std::str::from_utf8(pair).ok()?;
        *slot = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(out)
}

fn hex_encode(bytes: &[u8; 20]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(40), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// The server answers with the thumbprint of the certificate it actually
/// received, so this asserts SChannel presented *our* certificate -- not
/// merely that some handshake succeeded.
#[tokio::test]
async fn client_certificate_is_presented_to_the_server() {
    let Some((url, thumbprint)) = mtls_env() else {
        eprintln!("skipping: WREST_MTLS_URL / WREST_MTLS_THUMBPRINT not set");
        return;
    };

    let identity = Identity::from_current_user(&thumbprint)
        .expect("CI installs this certificate in CurrentUser\\MY");

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        // The test server's certificate is self-signed and generated per
        // run: this exercises client authentication, not chain building.
        .tls_danger_accept_invalid_certs(true)
        .identity(identity)
        .build()
        .expect("client with identity should build");

    let response = client
        .get(format!("{url}/client-cert"))
        .send()
        .await
        .expect("mutual-TLS handshake should succeed");

    assert_eq!(response.status(), StatusCode::OK);

    let presented = response.text().await.expect("body should read");
    assert_eq!(
        presented.trim(),
        hex_encode(&thumbprint),
        "server saw a different certificate than the one configured"
    );
}

/// Without an identity the handshake must fail -- otherwise the test
/// above could pass for reasons unrelated to the certificate.
#[tokio::test]
async fn without_an_identity_the_handshake_fails() {
    let Some((url, _)) = mtls_env() else {
        eprintln!("skipping: WREST_MTLS_URL not set");
        return;
    };

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .tls_danger_accept_invalid_certs(true)
        .build()
        .expect("client without identity should build");

    let result = client.get(format!("{url}/client-cert")).send().await;

    // `mtls_env` has already proven the port is open, so this can only
    // be the server refusing a handshake with no client certificate.
    let err = result.expect_err("server requires a client certificate");
    eprintln!("no-identity error (informational): {err:?}");
}
