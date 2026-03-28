param()

$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "common.ps1")

$rootPid = Get-MarlinSpikeShellProcessId
if (-not $rootPid) {
    Write-Host "MarlinSpike is not running."
    exit 0
}

$processIds = Get-ProcessTreeIds -RootPid $rootPid | Sort-Object -Descending
foreach ($processId in $processIds) {
    Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
}

Remove-MarlinSpikePidFile
Write-Host "Stopped MarlinSpike."
