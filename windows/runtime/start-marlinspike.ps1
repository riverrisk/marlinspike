param(
    [int]$Port = 5001,
    [int]$StartupTimeoutSeconds = 45,
    [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "common.ps1")

New-MarlinSpikeDirectories

$existingPid = Get-MarlinSpikeShellProcessId
if ($existingPid) {
    Write-Host "MarlinSpike is already running (PID $existingPid)."
    if (-not (Test-WiresharkTooling)) {
        Write-WiresharkGuidance
    }
    if (-not $NoBrowser) {
        Start-Process (Get-MarlinSpikeUrl -Port $Port)
    }
    exit 0
}

if (-not (Test-WiresharkTooling)) {
    Write-WiresharkGuidance
}

$launcher = Join-Path $PSScriptRoot "run-marlinspike.ps1"
$process = Start-Process -FilePath "powershell.exe" `
    -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $launcher, "-Port", $Port) `
    -WindowStyle Hidden `
    -PassThru

[System.IO.File]::WriteAllText($script:PidFile, [string]$process.Id)

if (Wait-MarlinSpikeHttp -Port $Port -TimeoutSeconds $StartupTimeoutSeconds) {
    Write-Host "MarlinSpike is running at $(Get-MarlinSpikeUrl -Port $Port)"
} else {
    Write-Warning "MarlinSpike did not answer on $(Get-MarlinSpikeUrl -Port $Port) within $StartupTimeoutSeconds seconds. Check logs in $script:LogDir."
}

if (-not $NoBrowser) {
    Start-Process (Get-MarlinSpikeUrl -Port $Port)
}
