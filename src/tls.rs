//! TLS configuration types.
//!
//! Mirrors [`reqwest::tls`](https://docs.rs/reqwest/latest/reqwest/tls/index.html).
//! [`Version`] is used with
//! [`ClientBuilder::tls_version_min()`](crate::ClientBuilder::tls_version_min) and
//! [`ClientBuilder::tls_version_max()`](crate::ClientBuilder::tls_version_max)
//! to pin the protocol versions WinHTTP is allowed to negotiate.

use windows_sys::Win32::Networking::WinHttp::{
    WINHTTP_FLAG_SECURE_PROTOCOL_TLS1, WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_1,
    WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2, WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3,
};

/// A TLS protocol version.
///
/// Matches [`reqwest::tls::Version`](https://docs.rs/reqwest/latest/reqwest/tls/struct.Version.html):
/// an opaque type with one associated constant per supported protocol
/// version.  Values are ordered, so `Version::TLS_1_2 < Version::TLS_1_3`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(Inner);

/// The protocol versions WinHTTP can be asked to enable, in ascending order.
///
/// SSL 2.0 / SSL 3.0 have no `Version` constant: reqwest does not expose
/// them either, and modern SChannel refuses them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Inner {
    Tls1_0,
    Tls1_1,
    Tls1_2,
    Tls1_3,
}

impl Version {
    /// Version 1.0 of the TLS protocol.
    pub const TLS_1_0: Version = Version(Inner::Tls1_0);
    /// Version 1.1 of the TLS protocol.
    pub const TLS_1_1: Version = Version(Inner::Tls1_1);
    /// Version 1.2 of the TLS protocol.
    pub const TLS_1_2: Version = Version(Inner::Tls1_2);
    /// Version 1.3 of the TLS protocol.
    pub const TLS_1_3: Version = Version(Inner::Tls1_3);

    /// The `WINHTTP_FLAG_SECURE_PROTOCOL_*` bit for this version.
    const fn winhttp_flag(self) -> u32 {
        match self.0 {
            Inner::Tls1_0 => WINHTTP_FLAG_SECURE_PROTOCOL_TLS1,
            Inner::Tls1_1 => WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_1,
            Inner::Tls1_2 => WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2,
            Inner::Tls1_3 => WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3,
        }
    }
}

/// Every version wrest can enable, ascending.
const ALL: [Version; 4] = [Version::TLS_1_0, Version::TLS_1_1, Version::TLS_1_2, Version::TLS_1_3];

/// Build the `WINHTTP_OPTION_SECURE_PROTOCOLS` mask for a version range.
///
/// Returns `None` when neither bound is set -- the caller then leaves the
/// option untouched and WinHTTP keeps the system default.
///
/// # Implicit bounds
///
/// `WINHTTP_OPTION_SECURE_PROTOCOLS` is an explicit allowlist, so a
/// one-sided range still has to name a full set of versions:
///
/// - Only `max` set: the floor is TLS 1.2, so pinning a maximum never
///   silently *re-enables* TLS 1.0/1.1.  If `max` is itself below TLS 1.2
///   the caller has opted into legacy protocols, and the floor drops to
///   TLS 1.0.
/// - Only `min` set: the ceiling is TLS 1.3.
///
/// # Errors
///
/// Returns `Err(())` if `min > max`, which would enable nothing at all.
pub(crate) fn protocol_mask(min: Option<Version>, max: Option<Version>) -> Result<Option<u32>, ()> {
    if min.is_none() && max.is_none() {
        return Ok(None);
    }

    let high = max.unwrap_or(Version::TLS_1_3);
    let low = min.unwrap_or(if high >= Version::TLS_1_2 {
        Version::TLS_1_2
    } else {
        Version::TLS_1_0
    });

    if low > high {
        return Err(());
    }

    let mask = ALL
        .iter()
        .filter(|v| **v >= low && **v <= high)
        .fold(0u32, |acc, v| acc | v.winhttp_flag());

    Ok(Some(mask))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TLS1_0: u32 = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1;
    const TLS1_1: u32 = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_1;
    const TLS1_2: u32 = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
    const TLS1_3: u32 = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;

    #[test]
    fn versions_are_ordered() {
        assert!(Version::TLS_1_0 < Version::TLS_1_1);
        assert!(Version::TLS_1_1 < Version::TLS_1_2);
        assert!(Version::TLS_1_2 < Version::TLS_1_3);
        assert_eq!(Version::TLS_1_2, Version::TLS_1_2);
    }

    #[test]
    fn protocol_mask_table() {
        struct Case {
            min: Option<Version>,
            max: Option<Version>,
            expected: Result<Option<u32>, ()>,
            label: &'static str,
        }

        let cases = [
            Case {
                min: None,
                max: None,
                expected: Ok(None),
                label: "unset -- system default",
            },
            Case {
                min: Some(Version::TLS_1_2),
                max: None,
                expected: Ok(Some(TLS1_2 | TLS1_3)),
                label: "min only -- ceiling is TLS 1.3",
            },
            Case {
                min: Some(Version::TLS_1_3),
                max: None,
                expected: Ok(Some(TLS1_3)),
                label: "TLS 1.3 only",
            },
            Case {
                min: None,
                max: Some(Version::TLS_1_2),
                expected: Ok(Some(TLS1_2)),
                label: "max only -- floor stays at TLS 1.2",
            },
            Case {
                min: None,
                max: Some(Version::TLS_1_1),
                expected: Ok(Some(TLS1_0 | TLS1_1)),
                label: "legacy max -- floor drops to TLS 1.0",
            },
            Case {
                min: Some(Version::TLS_1_0),
                max: Some(Version::TLS_1_3),
                expected: Ok(Some(TLS1_0 | TLS1_1 | TLS1_2 | TLS1_3)),
                label: "full range",
            },
            Case {
                min: Some(Version::TLS_1_1),
                max: Some(Version::TLS_1_2),
                expected: Ok(Some(TLS1_1 | TLS1_2)),
                label: "middle range",
            },
            Case {
                min: Some(Version::TLS_1_2),
                max: Some(Version::TLS_1_2),
                expected: Ok(Some(TLS1_2)),
                label: "single version",
            },
            Case {
                min: Some(Version::TLS_1_3),
                max: Some(Version::TLS_1_2),
                expected: Err(()),
                label: "inverted range",
            },
        ];

        for case in cases {
            assert_eq!(protocol_mask(case.min, case.max), case.expected, "{}", case.label);
        }
    }

    #[test]
    fn mask_never_enables_ssl() {
        // SSL 2.0 (0x08) and SSL 3.0 (0x20) must never appear, whatever
        // the range.
        for min in ALL {
            for max in ALL {
                if let Ok(Some(mask)) = protocol_mask(Some(min), Some(max)) {
                    assert_eq!(mask & 0x28, 0, "SSL bits set for {min:?}..={max:?}");
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Client certificates (`client-cert` feature)
// ---------------------------------------------------------------------------

/// Which Windows system certificate store to search.
///
/// Requires the `client-cert` feature.
#[cfg(feature = "client-cert")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreLocation {
    /// The per-user store, as shown by `certmgr.msc`.
    CurrentUser,
    /// The machine-wide store, as shown by `certlm.msc`.
    LocalMachine,
}

#[cfg(feature = "client-cert")]
impl From<StoreLocation> for crate::abi::StoreLocation {
    fn from(location: StoreLocation) -> Self {
        match location {
            StoreLocation::CurrentUser => crate::abi::StoreLocation::CurrentUser,
            StoreLocation::LocalMachine => crate::abi::StoreLocation::LocalMachine,
        }
    }
}

/// A client certificate for mutual TLS, referenced in the Windows
/// certificate store.
///
/// Requires the `client-cert` feature.  Pass one to
/// [`ClientBuilder::identity()`](crate::ClientBuilder::identity).
///
/// # Deviation from reqwest
///
/// This is the same *path* as
/// [`reqwest::tls::Identity`](https://docs.rs/reqwest/latest/reqwest/tls/struct.Identity.html),
/// but not the same
/// type: reqwest's constructors (`from_pkcs12_der`, `from_pkcs8_pem`,
/// `from_pem`) all take exportable key material, and reqwest exposes no
/// way to reference a certificate that already lives in a store.  wrest
/// inverts that -- the certificate is referenced in place and **no private
/// key material is ever exported**, so smartcard, TPM and PIV-backed keys
/// work, which is exactly what reqwest's API cannot express.
///
/// The trade-off is that this constructor set is Windows-only.  On the
/// reqwest passthrough, `wrest::tls::Identity` is reqwest's own type with
/// reqwest's own constructors.  (reqwest already varies `Identity`'s
/// constructors by TLS backend -- `from_pkcs12_der` is native-tls only,
/// `from_pem` is rustls only -- so a backend-dependent constructor set is
/// how this type already behaves upstream.)
///
/// `Identity` is cheap to [`Clone`]: clones share the underlying
/// `CERT_CONTEXT` via its reference count.
#[cfg(feature = "client-cert")]
pub struct Identity {
    /// Owned reference to the certificate. Released on drop.
    ctx: *const windows_sys::Win32::Security::Cryptography::CERT_CONTEXT,
    /// SHA-1 thumbprint, when the identity was looked up by one. Only used
    /// for `Debug`; a thumbprint is public data, not a secret.
    sha1: Option<[u8; 20]>,
}

// SAFETY: a `CERT_CONTEXT` is an immutable, reference-counted crypt32
// object.  `CertDuplicateCertificateContext` / `CertFreeCertificateContext`
// adjust that count atomically, and wrest never mutates through the
// pointer -- it only hands it to WinHTTP, which takes its own duplicate.
#[cfg(feature = "client-cert")]
unsafe impl Send for Identity {}
// SAFETY: as above -- shared access is read-only.
#[cfg(feature = "client-cert")]
unsafe impl Sync for Identity {}

#[cfg(feature = "client-cert")]
impl Identity {
    /// Look up a certificate by SHA-1 thumbprint in a system store.
    ///
    /// `store_name` is a Windows store name such as `"MY"` (the personal
    /// store, where client certificates normally live) or `"ROOT"`.
    /// `certmgr.msc` displays the thumbprint as hex.
    ///
    /// # Errors
    ///
    /// Returns an error if the store cannot be opened, or if it holds no
    /// certificate with that thumbprint.
    pub fn from_system_store(
        location: StoreLocation,
        store_name: &str,
        sha1_thumbprint: &[u8; 20],
    ) -> Result<Self, crate::Error> {
        let ctx = crate::abi::find_cert_by_sha1(location.into(), store_name, sha1_thumbprint)?;
        Ok(Self {
            ctx,
            sha1: Some(*sha1_thumbprint),
        })
    }

    /// Look up a certificate by SHA-1 thumbprint in `CurrentUser\MY`.
    ///
    /// Shorthand for the common case; see
    /// [`from_system_store()`](Self::from_system_store).
    ///
    /// # Errors
    ///
    /// As [`from_system_store()`](Self::from_system_store).
    pub fn from_current_user(sha1_thumbprint: &[u8; 20]) -> Result<Self, crate::Error> {
        Self::from_system_store(StoreLocation::CurrentUser, "MY", sha1_thumbprint)
    }

    /// Adopt a `CERT_CONTEXT` obtained elsewhere -- for example from the
    /// [`schannel`](https://docs.rs/schannel) crate's `CertContext`, or
    /// from a certificate-selection dialog.
    ///
    /// This takes its own reference, so the caller keeps ownership of
    /// theirs and should release it as usual.
    ///
    /// # Safety
    ///
    /// `ctx` must point to a live `CERT_CONTEXT` that has not been freed.
    #[must_use]
    pub unsafe fn from_cert_context(ctx: *const std::ffi::c_void) -> Self {
        // SAFETY: delegated to this function's contract on `ctx`.
        let ctx = unsafe { crate::abi::duplicate_cert_context(ctx.cast()) };
        Self { ctx, sha1: None }
    }

    /// The raw context, for `WINHTTP_OPTION_CLIENT_CERT_CONTEXT`.
    pub(crate) fn as_ptr(&self) -> *const windows_sys::Win32::Security::Cryptography::CERT_CONTEXT {
        self.ctx
    }
}

#[cfg(feature = "client-cert")]
impl Clone for Identity {
    fn clone(&self) -> Self {
        // SAFETY: `self.ctx` is live for as long as `self` is.
        let ctx = unsafe { crate::abi::duplicate_cert_context(self.ctx) };
        Self {
            ctx,
            sha1: self.sha1,
        }
    }
}

#[cfg(feature = "client-cert")]
impl Drop for Identity {
    fn drop(&mut self) {
        // SAFETY: we own exactly one reference, taken in a constructor or
        // in `clone`, and this runs once.
        unsafe { crate::abi::free_cert_context(self.ctx) }
    }
}

#[cfg(feature = "client-cert")]
impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("Identity");
        match &self.sha1 {
            Some(sha1) => s.field("sha1", &crate::abi::hex_thumbprint(sha1)).finish(),
            None => s.finish_non_exhaustive(),
        }
    }
}

/// Per-request TLS configuration, resolved at `Client` build time.
///
/// Bundled rather than passed as loose arguments so the WinHTTP layer
/// keeps one TLS parameter regardless of which features are enabled.
#[derive(Clone, Debug, Default)]
pub(crate) struct TlsConfig {
    /// Whether to ignore certificate validation errors.
    pub accept_invalid_certs: bool,
    /// Client certificate for mutual TLS, if configured.
    #[cfg(feature = "client-cert")]
    pub identity: Option<Identity>,
}

#[cfg(all(test, feature = "client-cert"))]
mod identity_tests {
    use super::*;

    /// A self-signed certificate, only ever used to obtain a real
    /// `CERT_CONTEXT`.  Its private key is not present and never needed:
    /// these tests cover reference counting and option plumbing, not a
    /// handshake.
    const TEST_DER: &[u8] = include_bytes!("../tests/fixtures/test-client-cert.der");

    /// Build an `Identity` from the fixture without touching any store.
    fn fixture_identity() -> Identity {
        let ctx = crate::abi::create_cert_context(TEST_DER).expect("fixture DER should parse");
        // `from_cert_context` takes its own reference, so release ours.
        let identity = unsafe { Identity::from_cert_context(ctx.cast()) };
        unsafe { crate::abi::free_cert_context(ctx) };
        identity
    }

    #[test]
    fn fixture_parses_as_a_certificate() {
        let ctx = crate::abi::create_cert_context(TEST_DER).expect("fixture DER should parse");
        assert!(!ctx.is_null());
        unsafe { crate::abi::free_cert_context(ctx) };

        // Garbage must be rejected rather than producing a bogus context.
        assert!(
            crate::abi::create_cert_context(b"not a certificate").is_err(),
            "invalid DER should not yield a context"
        );
    }

    #[test]
    fn clones_outlive_each_other() {
        // Each clone holds its own reference, so dropping clones in any
        // order must leave the remaining ones usable.  A refcount bug
        // here is a use-after-free, so this runs under CI on Windows.
        let identity = fixture_identity();
        let a = identity.clone();
        let b = a.clone();
        drop(a);
        assert!(!b.as_ptr().is_null(), "clone still valid after sibling dropped");
        drop(b);
        assert!(!identity.as_ptr().is_null(), "original outlives its clones");

        // Dropping the last reference must not double-free.
        drop(identity);
    }

    #[test]
    fn debug_reports_thumbprint_only_when_known() {
        // Adopted contexts have no thumbprint recorded.
        let adopted = format!("{:?}", fixture_identity());
        assert!(adopted.starts_with("Identity"), "got {adopted}");
        assert!(!adopted.contains("sha1"), "no thumbprint is known: {adopted}");

        // A store lookup records one; check the formatting directly since
        // the lookup itself needs an installed certificate.  The context
        // is duplicated so this `Identity` owns its own reference and
        // drops normally.
        let base = fixture_identity();
        let identity = Identity {
            ctx: unsafe { crate::abi::duplicate_cert_context(base.as_ptr()) },
            sha1: Some([0xab; 20]),
        };
        let shown = format!("{identity:?}");
        assert!(shown.contains("abab"), "thumbprint should be shown: {shown}");
    }

    #[test]
    fn missing_certificate_is_an_error_not_a_panic() {
        let err = Identity::from_current_user(&[0u8; 20])
            .expect_err("all-zero thumbprint should not resolve");
        assert!(err.is_builder(), "a missing certificate is a builder error");
        // Detail is in the source chain (`Debug`), not `Display`.
        let detail = format!("{err:?}");
        assert!(detail.contains("no certificate"), "got {detail}");
    }

    #[test]
    fn winhttp_accepts_the_client_cert_option() {
        // The buffer for WINHTTP_OPTION_CLIENT_CERT_CONTEXT is the
        // CERT_CONTEXT itself with sizeof(CERT_CONTEXT) as the length; a
        // wrong pointer or size fails here rather than at handshake time.
        let session = crate::winhttp::WinHttpSession::open(&crate::winhttp::SessionConfig {
            user_agent: String::new(),
            connect_timeout_ms: 10_000,
            send_timeout_ms: 0,
            read_timeout_ms: 0,
            verbose: false,
            max_connections_per_host: None,
            proxy: crate::proxy::ProxyAction::Automatic,
            redirect_policy: None,
            http1_only: false,
            secure_protocols: None,
        })
        .expect("session should open");

        let connect = crate::abi::winhttp_connect(session.handle.0, "example.com", 443)
            .expect("connect handle should open");
        let request = crate::abi::winhttp_open_request(connect, "GET", "/", true)
            .expect("request handle should open");

        let identity = fixture_identity();
        let result = crate::abi::winhttp_set_client_cert(request, identity.as_ptr());

        crate::abi::close_winhttp_handle(request);
        crate::abi::close_winhttp_handle(connect);

        result.expect("WinHTTP should accept the client certificate context");
    }
}
