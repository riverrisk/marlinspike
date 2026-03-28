param([int]$Port = 5001)

$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "common.ps1")

$pidValue = Get-MarlinSpikeShellProcessId
$httpReady = Test-MarlinSpikeHttp -Port $Port
$wiresharkReady = Test-WiresharkTooling

if ($pidValue -and $httpReady) {
    Write-Host "MarlinSpike is running on $(Get-MarlinSpikeUrl -Port $Port) (PID $pidValue)."
    if (-not $wiresharkReady) {
        Write-WiresharkGuidance
    }
    exit 0
}

if ($pidValue) {
    Write-Host "MarlinSpike process is present (PID $pidValue), but HTTP is not responding yet."
    exit 1
}

Write-Host "MarlinSpike is not running."
if (-not $wiresharkReady) {
    Write-WiresharkGuidance
}
exit 1
