//! Thin safe wrappers around the crypt32 certificate-store FFI.
//!
//! Only compiled with the `client-cert` feature.  These back
//! [`crate::tls::Identity`]: opening a system certificate store, finding a
//! certificate in it, and managing the reference count on a
//! `CERT_CONTEXT`.
//!
//! Nothing here parses certificates or touches private key material --
//! SChannel does that, driven by WinHTTP.  wrest only ever holds a
//! refcounted pointer to a certificate that already lives in a store.

use super::{last_win32_error, to_wide};
use crate::Error;
use windows_sys::Win32::Security::Cryptography::{
    CERT_CONTEXT, CERT_FIND_HASH, CERT_STORE_PROV_SYSTEM_W, CERT_STORE_READONLY_FLAG,
    CERT_SYSTEM_STORE_CURRENT_USER, CERT_SYSTEM_STORE_LOCAL_MACHINE, CRYPT_INTEGER_BLOB,
    CertCloseStore, CertDuplicateCertificateContext, CertFindCertificateInStore,
    CertFreeCertificateContext, CertOpenStore, HCERTSTORE, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
};

/// Which system store location to search.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StoreLocation {
    /// `CurrentUser` -- the per-user store (`certmgr.msc`).
    CurrentUser,
    /// `LocalMachine` -- the machine-wide store (`certlm.msc`).
    LocalMachine,
}

impl StoreLocation {
    const fn flag(self) -> u32 {
        match self {
            StoreLocation::CurrentUser => CERT_SYSTEM_STORE_CURRENT_USER,
            StoreLocation::LocalMachine => CERT_SYSTEM_STORE_LOCAL_MACHINE,
        }
    }
}

/// An open system certificate store, closed on drop.
///
/// Deliberately closed *without* `CERT_CLOSE_STORE_FORCE_FLAG`: WinHTTP
/// documents that force-closing the store a client certificate came from
/// can cause an access violation, since contexts handed to it outlive the
/// store handle.
struct CertStore(HCERTSTORE);

impl Drop for CertStore {
    fn drop(&mut self) {
        // No force flag -- see the type docs.  Failure here is not
        // actionable and the handle is gone either way.
        unsafe {
            let _ = CertCloseStore(self.0, 0);
        }
    }
}

/// Find a certificate by SHA-1 thumbprint in a named system store.
///
/// Returns a context the caller owns and must release with
/// [`free_cert_context`].  `store_name` is a store name such as `"MY"`
/// (personal) or `"ROOT"`.
///
/// # Errors
///
/// Returns the Win32 error if the store cannot be opened, or a
/// not-found error if no certificate in it has that thumbprint.
pub(crate) fn find_cert_by_sha1(
    location: StoreLocation,
    store_name: &str,
    sha1: &[u8; 20],
) -> Result<*const CERT_CONTEXT, Error> {
    let name_wide = to_wide(store_name);

    // SAFETY: `CERT_STORE_PROV_SYSTEM_W` selects the system-store
    // provider, for which `pvpara` is a wide store name.  `name_wide`
    // outlives the call.
    let handle = unsafe {
        CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            0,
            0,
            location.flag() | CERT_STORE_READONLY_FLAG,
            name_wide.as_ptr().cast(),
        )
    };
    if handle.is_null() {
        return Err(last_win32_error());
    }
    let store = CertStore(handle);

    let mut hash = *sha1;
    let blob = CRYPT_INTEGER_BLOB {
        cbData: 20,
        pbData: hash.as_mut_ptr(),
    };

    // SAFETY: `CERT_FIND_HASH` takes a `CRYPT_HASH_BLOB` as `pvFindPara`;
    // `blob` (and the `hash` it points at) outlive the call.  A null
    // `pPrevCertContext` starts the search from the beginning.
    let found = unsafe {
        CertFindCertificateInStore(
            store.0,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_HASH,
            std::ptr::from_ref(&blob).cast(),
            std::ptr::null(),
        )
    };

    if found.is_null() {
        // CertFindCertificateInStore sets CRYPT_E_NOT_FOUND, which maps to
        // a confusing message; say what actually happened instead.
        return Err(Error::builder(format!(
            "no certificate with SHA-1 thumbprint {} in {location:?}\\{store_name}",
            hex_thumbprint(sha1),
        )));
    }

    // The found context is owned by us; the store closes on drop below
    // without the force flag, which leaves the context valid.
    Ok(found.cast_const())
}

/// Increment the reference count on a certificate context.
///
/// # Safety
///
/// `ctx` must be a valid `CERT_CONTEXT` pointer.
pub(crate) unsafe fn duplicate_cert_context(ctx: *const CERT_CONTEXT) -> *const CERT_CONTEXT {
    // SAFETY: delegated to the caller's contract on `ctx`.  The returned
    // pointer is a new reference the caller owns.
    unsafe { CertDuplicateCertificateContext(ctx).cast_const() }
}

/// Release a reference taken by [`find_cert_by_sha1`] or
/// [`duplicate_cert_context`].
///
/// # Safety
///
/// `ctx` must be a valid `CERT_CONTEXT` pointer that has not already been
/// freed.
pub(crate) unsafe fn free_cert_context(ctx: *const CERT_CONTEXT) {
    // SAFETY: delegated to the caller's contract on `ctx`.
    unsafe {
        let _ = CertFreeCertificateContext(ctx);
    }
}

/// Build a standalone certificate context from DER bytes.
///
/// Only used by tests: it is the one way to obtain a real `CERT_CONTEXT`
/// without requiring a certificate to be installed in the runner's store,
/// which lets the reference-counting paths be exercised for real.
///
/// # Errors
///
/// Returns the Win32 error if `der` is not a well-formed certificate.
#[cfg(test)]
pub(crate) fn create_cert_context(der: &[u8]) -> Result<*const CERT_CONTEXT, Error> {
    let len = u32::try_from(der.len()).map_err(|_| Error::builder("certificate too large"))?;
    // SAFETY: `der`/`len` describe the same buffer, which outlives the
    // call; crypt32 copies what it needs into the returned context.
    let ctx = unsafe {
        windows_sys::Win32::Security::Cryptography::CertCreateCertificateContext(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            der.as_ptr(),
            len,
        )
    };
    if ctx.is_null() {
        return Err(last_win32_error());
    }
    Ok(ctx.cast_const())
}

/// Lowercase hex, for error messages and `Debug`.
pub(crate) fn hex_thumbprint(sha1: &[u8; 20]) -> String {
    use std::fmt::Write as _;
    sha1.iter().fold(String::with_capacity(40), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_thumbprint_formats_lowercase_fixed_width() {
        let mut sha1 = [0u8; 20];
        sha1[0] = 0x0a;
        sha1[19] = 0xff;
        let hex = hex_thumbprint(&sha1);
        assert_eq!(hex.len(), 40, "SHA-1 is always 40 hex chars");
        assert!(hex.starts_with("0a"), "leading zero must be kept: {hex}");
        assert!(hex.ends_with("ff"), "got {hex}");
    }

    #[test]
    fn missing_thumbprint_is_a_clear_error() {
        // An all-zero thumbprint will not be in anyone's store.  The
        // store itself must open, so this exercises the found.is_null()
        // path rather than the open failure path.
        let err = find_cert_by_sha1(StoreLocation::CurrentUser, "MY", &[0u8; 20])
            .expect_err("all-zero thumbprint should not match");
        assert!(err.is_builder(), "a missing certificate is a builder error");
        // `Display` is the error kind alone; the detail lives in the
        // source chain, which `Debug` prints.
        let detail = format!("{err:?}");
        assert!(
            detail.contains("no certificate with SHA-1 thumbprint"),
            "expected a not-found detail, got: {detail}"
        );
    }

    #[test]
    fn unknown_store_name_surfaces_win32_error() {
        let err = find_cert_by_sha1(StoreLocation::CurrentUser, "NoSuchStore\\Invalid", &[0u8; 20])
            .expect_err("an invalid store name should fail");
        // Either the open fails or the find does; both must be errors,
        // and neither may panic.
        assert!(!err.to_string().is_empty());
    }
}
