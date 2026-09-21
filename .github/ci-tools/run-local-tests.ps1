<#
.SYNOPSIS
    Runs the tests that need the local TLS servers, on Windows.

.DESCRIPTION
    Does what .github/actions/start-test-servers does in CI -- builds and
    starts the test server, creates the client certificate, trusts the
    server certificate, exports the variables -- then runs the tests and
    stops the server again.

    Everything it generates goes in .local/, which is gitignored, so a run
    leaves the working tree clean.

    The default -TrustStore is CurrentUser, which raises a consent dialog:
    interactively that is the point.  CI uses LocalMachine, which needs an
    elevated shell and prompts for nothing; pass -TrustStore LocalMachine
    from an elevated prompt to exercise exactly what CI does.

.EXAMPLE
    ./.github/ci-tools/run-local-tests.ps1
    ./.github/ci-tools/run-local-tests.ps1 -TrustStore LocalMachine
    ./.github/ci-tools/run-local-tests.ps1 -TestArgs '--test','mtls'
    ./.github/ci-tools/run-local-tests.ps1 -Cleanup
#>
[CmdletBinding()]
param(
    # Cargo feature set; the default matches CI's all-native job.
    [string] $Features = '__all-native-features',

    # Where to trust the server certificate.
    [ValidateSet('CurrentUser', 'LocalMachine')]
    [string] $TrustStore = 'CurrentUser',

    # Extra arguments for cargo test, e.g. '--test','mtls'.
    [string[]] $TestArgs = @(),

    # Remove the certificates and .local/, then exit.
    [switch] $Cleanup
)

$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$LocalDir = Join-Path $RepoRoot '.local'
$SetupCerts = Join-Path $PSScriptRoot 'setup-test-certs.ps1'

if ($Cleanup) {
    & $SetupCerts -Cleanup
    if (Test-Path $LocalDir) {
        Remove-Item $LocalDir -Recurse -Force
        Write-Host "removed $LocalDir"
    }
    return
}

New-Item -ItemType Directory -Force -Path $LocalDir | Out-Null

$ServerBinary = Join-Path $LocalDir 'mtls-server.exe'
$ServerCert = Join-Path $LocalDir 'mtls-server-cert.der'
$ServerLog = Join-Path $LocalDir 'mtls-server.log'
$ServerErrorLog = Join-Path $LocalDir 'mtls-server.err.log'

Write-Host 'building the test server'
& go build -o $ServerBinary (Join-Path $PSScriptRoot 'mtls-server')
if ($LASTEXITCODE -ne 0) { throw 'go build failed' }

Remove-Item $ServerLog, $ServerErrorLog -ErrorAction SilentlyContinue

$server = Start-Process -FilePath $ServerBinary `
    -ArgumentList '-cert-out', $ServerCert `
    -RedirectStandardOutput $ServerLog `
    -RedirectStandardError $ServerErrorLog `
    -NoNewWindow -PassThru

try {
    $ready = $false
    foreach ($attempt in 1..60) {
        if ((Test-Path $ServerLog) -and (Select-String -Path $ServerLog -Pattern 'mtls-server ready' -Quiet)) {
            $ready = $true
            break
        }
        Start-Sleep -Milliseconds 250
    }
    if (-not $ready) {
        Get-Content $ServerLog, $ServerErrorLog -ErrorAction SilentlyContinue
        throw 'the test server did not start'
    }
    Get-Content $ServerLog | Select-Object -First 1

    # These set the variables in this session, so cargo test below sees them.
    & $SetupCerts -ClientCertificate
    & $SetupCerts -TrustServerCertificate $ServerCert -TrustStore $TrustStore

    $env:HTTPBIN_URL = 'http://127.0.0.1:8080'
    $env:WREST_TLS_URL = 'https://127.0.0.1:8444'
    $env:WREST_MTLS_URL = 'https://127.0.0.1:8443'

    Write-Host "running cargo test --features $Features $TestArgs"
    & cargo test --all-targets --features $Features @TestArgs
    $testExit = $LASTEXITCODE
} finally {
    if ($server -and -not $server.HasExited) {
        Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
    }
}

if ($testExit -ne 0) {
    throw "cargo test failed with exit code $testExit"
}

Write-Host 'tests passed; run with -Cleanup to remove the certificates and .local/'
