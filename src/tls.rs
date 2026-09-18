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
