param(
    [string]$PythonExe = "",
    [switch]$BuildInstaller
)

$ErrorActionPreference = "Stop"

if (-not $IsWindows) {
    throw "This packaging script must be run on Windows."
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$buildRoot = Join-Path $PSScriptRoot "build"
$bundleRoot = Join-Path $buildRoot "bundle"
$venvRoot = Join-Path $buildRoot "venv"
$installerScript = Join-Path $PSScriptRoot "installer\MarlinSpike.iss"

function Resolve-PythonExe {
    param([string]$Requested)

    if ($Requested) {
        return $Requested
    }

    foreach ($candidate in @("py", "python")) {
        $command = Get-Command $candidate -ErrorAction SilentlyContinue
        if ($command) {
            return $command.Source
        }
    }

    throw "Python launcher not found. Pass -PythonExe with a valid Python executable."
}

function Resolve-InnoSetupCompiler {
    $candidates = @(
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
    )

    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path $candidate)) {
            return $candidate
        }
    }

    throw "ISCC.exe not found. Install Inno Setup 6 or run without -BuildInstaller."
}

Write-Host "Preparing Windows bundle under $buildRoot"
if (Test-Path $buildRoot) {
    Remove-Item -Path $buildRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $bundleRoot -Force | Out-Null

$python = Resolve-PythonExe -Requested $PythonExe
Write-Host "Using Python launcher: $python"
& $python -m venv $venvRoot

$venvPython = Join-Path $venvRoot "Scripts\python.exe"
& $venvPython -m pip install --upgrade pip
& $venvPython -m pip install -r (Join-Path $repoRoot "requirements.txt")

$payload = @(
    "_auth.py",
    "_config.py",
    "_models.py",
    "_ms_engine.py",
    "app.py",
    "auth.py",
    "config.py",
    "models.py",
    "marlinspike.py",
    "serve.py",
    "requirements.txt",
    "LICENSE",
    "README.md",
    "templates",
    "static",
    "presets",
    "plugins",
    "rules"
)

foreach ($item in $payload) {
    $source = Join-Path $repoRoot $item
    if (Test-Path $source) {
        Copy-Item -Path $source -Destination $bundleRoot -Recurse -Force
    }
}

Copy-Item -Path $venvRoot -Destination (Join-Path $bundleRoot "venv") -Recurse -Force
Copy-Item -Path (Join-Path $PSScriptRoot "runtime") -Destination (Join-Path $bundleRoot "runtime") -Recurse -Force

$vendorDir = Join-Path $PSScriptRoot "vendor"
if (Test-Path $vendorDir) {
    Copy-Item -Path $vendorDir -Destination (Join-Path $bundleRoot "vendor") -Recurse -Force
}

$appVersion = "dev"
$match = Select-String -Path (Join-Path $repoRoot "app.py") -Pattern 'APP_VERSION = "([^"]+)"'
if ($match.Matches.Count -gt 0) {
    $appVersion = $match.Matches[0].Groups[1].Value
}
Set-Content -Path (Join-Path $bundleRoot "VERSION.txt") -Value $appVersion -Encoding ascii

Write-Host "Bundle ready at $bundleRoot"

if ($BuildInstaller) {
    $iscc = Resolve-InnoSetupCompiler
    Write-Host "Compiling installer with $iscc"
    & $iscc $installerScript
    Write-Host "Installer ready under $(Join-Path $buildRoot 'installer')"
}
