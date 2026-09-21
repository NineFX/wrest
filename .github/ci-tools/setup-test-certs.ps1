<#
.SYNOPSIS
    Creates (or removes) the certificates wrest's TLS tests need.

.DESCRIPTION
    Called by .github/actions/start-test-servers, and runnable by hand on a
    Windows box to reproduce what CI does.

    -ClientCertificate creates a certificate in CurrentUser\My with a
    NON-EXPORTABLE key -- the case reqwest's Identity cannot express -- and
    reports its thumbprint for tests/mtls.rs.

    -TrustServerCertificate trusts the DER that mtls-server wrote with
    -cert-out, which the https->http redirect test needs because it drives
    a default client that validates the chain.

.EXAMPLE
    # Local Windows run, from the repository root, with the server started
    # from .github/ci-tools/mtls-server:
    ./.github/ci-tools/setup-test-certs.ps1 -ClientCertificate
    ./.github/ci-tools/setup-test-certs.ps1 `
        -TrustServerCertificate mtls-server-cert.der -TrustStore CurrentUser
    $env:HTTPBIN_URL = 'http://127.0.0.1:8080'
    $env:WREST_TLS_URL = 'https://127.0.0.1:8444'
    $env:WREST_MTLS_URL = 'https://127.0.0.1:8443'
    cargo test --features __all-native-features

    # Afterwards, to remove the certificates again:
    ./.github/ci-tools/setup-test-certs.ps1 -Cleanup
#>
[CmdletBinding()]
param(
    # Create the client certificate and report its thumbprint.
    [switch] $ClientCertificate,

    # Create a second, disposable certificate for the test that deletes one
    # out from under a live Identity.  Separate from the main certificate so
    # that deletion cannot disturb tests running in parallel.
    [switch] $DisposableCertificate,

    # Path to the server certificate (DER) to add to the trust store.
    [string] $TrustServerCertificate,

    # Where to trust the server certificate.  LocalMachine needs
    # administrator rights and prompts for nothing, which is what CI
    # requires: trusting a root for CurrentUser raises a consent dialog
    # that never returns on a headless runner.  Interactively, CurrentUser
    # is the safer choice -- that dialog is the point.
    [ValidateSet('LocalMachine', 'CurrentUser')]
    [string] $TrustStore = 'LocalMachine',

    # Remove certificates left by an earlier run, then exit.
    [switch] $Cleanup
)

$ErrorActionPreference = 'Stop'

$ClientSubject = 'CN=wrest-mtls-test-client'
$DisposableSubject = 'CN=wrest-mtls-disposable-client'
$ServerSubject = 'CN=wrest-mtls-test-server'

# Append to GITHUB_ENV when running under Actions, and set the variable in
# the current session either way -- a .ps1 shares the caller's process, so
# a local run needs no copy-and-paste.
function Publish-Variable {
    param([string] $Name, [string] $Value)

    Write-Host "$Name=$Value"
    Set-Item -Path "env:$Name" -Value $Value
    if ($env:GITHUB_ENV) {
        "$Name=$Value" | Out-File -FilePath $env:GITHUB_ENV -Append -Encoding utf8
    }
}

function Remove-TestCertificates {
    $stores = @(
        'Cert:\CurrentUser\My',
        'Cert:\CurrentUser\Root',
        'Cert:\LocalMachine\Root'
    )

    foreach ($store in $stores) {
        if (-not (Test-Path $store)) { continue }

        # A store we lack rights to is not an error: CI runs elevated, a
        # developer machine may not.
        $certs = Get-ChildItem $store -ErrorAction SilentlyContinue | Where-Object {
            $_.Subject -eq $ClientSubject -or
            $_.Subject -eq $DisposableSubject -or
            $_.Subject -eq $ServerSubject
        }

        foreach ($cert in $certs) {
            Write-Host "removing $($cert.Thumbprint) from $store"
            Remove-Item $cert.PSPath -Force -ErrorAction SilentlyContinue
        }
    }
}

if ($Cleanup) {
    Remove-TestCertificates
    return
}

if ($ClientCertificate) {
    # Drop stale certificates first so a repeated run cannot leave several
    # candidates in the store.  Matters on self-hosted runners and laptops,
    # not on ephemeral CI.
    Remove-TestCertificates

    $cert = New-SelfSignedCertificate `
        -Subject $ClientSubject `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -KeyExportPolicy NonExportable `
        -KeyUsage DigitalSignature, KeyEncipherment `
        -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.2') `
        -NotAfter (Get-Date).AddDays(1)

    if (-not $cert.Thumbprint) {
        throw 'certificate created without a thumbprint'
    }

    Publish-Variable -Name 'WREST_MTLS_THUMBPRINT' -Value $cert.Thumbprint
}

if ($DisposableCertificate) {
    # Deliberately does not purge first: the client certificate created
    # above must survive.
    $cert = New-SelfSignedCertificate `
        -Subject $DisposableSubject `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -KeyExportPolicy NonExportable `
        -KeyUsage DigitalSignature, KeyEncipherment `
        -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.2') `
        -NotAfter (Get-Date).AddDays(1)

    if (-not $cert.Thumbprint) {
        throw 'disposable certificate created without a thumbprint'
    }

    Publish-Variable -Name 'WREST_MTLS_DISPOSABLE_THUMBPRINT' -Value $cert.Thumbprint
}

if ($TrustServerCertificate) {
    if (-not (Test-Path $TrustServerCertificate)) {
        throw "mtls-server did not write $TrustServerCertificate"
    }

    $cert = Import-Certificate `
        -FilePath $TrustServerCertificate `
        -CertStoreLocation "Cert:\$TrustStore\Root"

    # Import-Certificate reporting success is not proof the certificate is
    # in the store; check, so a failure names itself here rather than
    # surfacing later as an unexplained TLS error in the redirect test.
    $installed = "Cert:\$TrustStore\Root\$($cert.Thumbprint)"
    if (-not (Test-Path $installed)) {
        throw "server certificate is not present at $installed after import"
    }

    Write-Host "trusted server certificate $($cert.Thumbprint) in $TrustStore\Root"
}
