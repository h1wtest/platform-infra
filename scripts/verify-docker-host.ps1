[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Repository,
    [switch]$AllowSharedHostOutage
)
$ErrorActionPreference = 'Stop'
if (-not $AllowSharedHostOutage) {
    throw 'HOST_OUTAGE_APPROVAL_REQUIRED: this interrupts every Docker Desktop workload, including unrelated containers.'
}
if ($Repository -ne '/home/bpqvg/dev/h1wtest-remediation/platform-infra') {
    throw 'Host verification is restricted to the isolated SSO acceptance workspace.'
}
# No redirected native stderr: Windows stdlib owns observation, deadlines and cleanup.
# Keep native diagnostics from becoming PowerShell 5.1 pipeline error records.
$ErrorActionPreference = 'Continue'
& py.exe -3 (Join-Path $PSScriptRoot 'verify_docker_host.py') -Repository $Repository -AllowSharedHostOutage
if ($null -eq $LASTEXITCODE) { exit 1 }
exit $LASTEXITCODE
