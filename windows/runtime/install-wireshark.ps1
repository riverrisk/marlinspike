param(
    [switch]$NoBrowser,
    [switch]$IncludeGuide
)

$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "common.ps1")

if (Test-WiresharkTooling) {
    $binDir = Get-WiresharkBinDir
    Write-Host "Wireshark CLI tools are already installed at $binDir."
    exit 0
}

$missing = Get-WiresharkMissingTools
$toolList = [string]::Join(", ", $missing)

Write-Host "MarlinSpike needs the official Wireshark Windows install before scans can run."
Write-Host "Required tools: $toolList"
Write-Host "Download page: $(Get-WiresharkDownloadUrl)"
Write-Host "Install guide: $(Get-WiresharkInstallGuideUrl)"

if (-not $NoBrowser) {
    Open-WiresharkDownloadResources -IncludeGuide:$IncludeGuide
}
