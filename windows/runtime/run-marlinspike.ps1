param([int]$Port = 5001)

$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "common.ps1")

New-MarlinSpikeDirectories

$pythonExe = Get-MarlinSpikePythonExe
$servePy = Join-Path $script:InstallRoot "serve.py"
$stdoutLog = Join-Path $script:LogDir "marlinspike.out.log"
$stderrLog = Join-Path $script:LogDir "marlinspike.err.log"

foreach ($entry in (Get-MarlinSpikeRuntimeEnvironment -Port $Port).GetEnumerator()) {
    [System.Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, "Process")
}

"[$(Get-Date -Format s)] Starting MarlinSpike on $(Get-MarlinSpikeUrl -Port $Port)" |
    Out-File -FilePath $stdoutLog -Encoding ascii -Append

try {
    & $pythonExe $servePy 1>> $stdoutLog 2>> $stderrLog
    exit $LASTEXITCODE
} finally {
    Remove-MarlinSpikePidFile
}
