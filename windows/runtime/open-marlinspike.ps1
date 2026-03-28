param([int]$Port = 5001)

$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "common.ps1")

if (-not (Get-MarlinSpikeShellProcessId)) {
    & (Join-Path $PSScriptRoot "start-marlinspike.ps1") -Port $Port
    exit $LASTEXITCODE
}

Start-Process (Get-MarlinSpikeUrl -Port $Port)
