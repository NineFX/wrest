<#
.SYNOPSIS
    Waits until mtls-server is accepting TLS, then exports WREST_MTLS_URL.

.DESCRIPTION
    Called by .github/actions/start-mtls after the server is launched, and
    runnable by hand on a Windows box to reproduce what CI does.

    The server is launched from bash with `&` rather than from here: a
    process started by Start-Process does not outlive the step that starts
    it, and the tests then fail with ERROR_WINHTTP_CANNOT_CONNECT.

    Readiness is taken from the server's own line in the log rather than by
    probing the port, because a bare TCP connect logs a spurious handshake
    error on a listener that requires a client certificate.

.EXAMPLE
    ./.github/ci-tools/wait-for-mtls-server.ps1
#>

$ServerAddress = '127.0.0.1:8443'
$LogName = 'mtls-server.log'
$TimeoutSeconds = 30

$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$Log = Join-Path $RepoRoot $LogName

$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
$ready = $false
while ((Get-Date) -lt $deadline) {
    if ((Test-Path $Log) -and (Select-String -Path $Log -Pattern 'mtls-server ready' -Quiet)) {
        $ready = $true
        break
    }
    Start-Sleep -Milliseconds 250
}

if (-not $ready) {
    Write-Host "::error::mtls-server did not start within ${TimeoutSeconds}s"
    Get-Content $Log -ErrorAction SilentlyContinue
    exit 1
}

Get-Content $Log -TotalCount 1

if ($env:GITHUB_ENV) {
    "WREST_MTLS_URL=https://$ServerAddress" | Out-File -FilePath $env:GITHUB_ENV -Append -Encoding utf8
}
$env:WREST_MTLS_URL = "https://$ServerAddress"
Write-Host "WREST_MTLS_URL=https://$ServerAddress"
