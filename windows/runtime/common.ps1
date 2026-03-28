$script:InstallRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$localAppDataRoot = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } elseif ($env:LocalAppData) { $env:LocalAppData } else { $null }
$programDataRoot = if ($env:ProgramData) { $env:ProgramData } else { Join-Path $env:SystemDrive "ProgramData" }
$baseDataRoot = if ($localAppDataRoot) { $localAppDataRoot } else { $programDataRoot }
$script:AppHome = Join-Path $baseDataRoot "MarlinSpike"
$script:DataDir = Join-Path $script:AppHome "data"
$script:LogDir = Join-Path $script:AppHome "logs"
$script:RunDir = Join-Path $script:AppHome "run"
$script:PidFile = Join-Path $script:RunDir "marlinspike.pid"
$script:AdminPasswordFile = Join-Path $script:AppHome "admin-password.txt"
$script:WiresharkDownloadUrl = "https://www.wireshark.org/download.html"
$script:WiresharkInstallGuideUrl = "https://www.wireshark.org/docs/wsug_html_chunked/ChBuildInstallWinInstall"
$script:RequiredWiresharkTools = @("tshark.exe", "capinfos.exe", "editcap.exe")

function New-MarlinSpikeDirectories {
    foreach ($path in @($script:AppHome, $script:DataDir, $script:LogDir, $script:RunDir)) {
        if (-not (Test-Path $path)) {
            New-Item -ItemType Directory -Path $path -Force | Out-Null
        }
    }
}

function Get-MarlinSpikeUrl {
    param([int]$Port = 5001)
    return "http://127.0.0.1:$Port/"
}

function Get-MarlinSpikePythonExe {
    $candidates = @(
        (Join-Path $script:InstallRoot "python\python.exe"),
        (Join-Path $script:InstallRoot "python\pythonw.exe"),
        (Join-Path $script:InstallRoot "venv\Scripts\python.exe"),
        (Join-Path $script:InstallRoot "venv\Scripts\pythonw.exe")
    )

    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            return $candidate
        }
    }

    throw "Bundled Python runtime not found under $script:InstallRoot."
}

function Get-WiresharkDownloadUrl {
    return $script:WiresharkDownloadUrl
}

function Get-WiresharkInstallGuideUrl {
    return $script:WiresharkInstallGuideUrl
}

function Get-WiresharkBinDir {
    $candidates = @()
    if ($env:WIRESHARK_BIN_DIR) {
        $candidates += $env:WIRESHARK_BIN_DIR
    }
    if ($env:ProgramFiles) {
        $candidates += (Join-Path $env:ProgramFiles "Wireshark")
    }
    if (${env:ProgramFiles(x86)}) {
        $candidates += (Join-Path ${env:ProgramFiles(x86)} "Wireshark")
    }

    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path $candidate)) {
            return $candidate
        }
    }

    return $null
}

function Test-WiresharkTooling {
    return (Get-WiresharkMissingTools).Count -eq 0
}

function Get-WiresharkMissingTools {
    $binDir = Get-WiresharkBinDir
    if (-not $binDir) {
        return @($script:RequiredWiresharkTools)
    }

    $missing = @()
    foreach ($tool in $script:RequiredWiresharkTools) {
        if (-not (Test-Path (Join-Path $binDir $tool))) {
            $missing += $tool
        }
    }

    return $missing
}

function Write-WiresharkGuidance {
    if (Test-WiresharkTooling) {
        $binDir = Get-WiresharkBinDir
        Write-Host "Wireshark CLI tools detected at $binDir."
        return
    }

    $missing = Get-WiresharkMissingTools
    $toolList = [string]::Join(", ", $missing)

    Write-Warning "Wireshark CLI tools are not ready yet. MarlinSpike scans need: $toolList."
    Write-Host "Use the 'Install Wireshark (Official)' shortcut or visit $(Get-WiresharkDownloadUrl)"
    Write-Host "Install guide: $(Get-WiresharkInstallGuideUrl)"
}

function Open-WiresharkDownloadResources {
    param([switch]$IncludeGuide)

    Start-Process (Get-WiresharkDownloadUrl)
    if ($IncludeGuide) {
        Start-Process (Get-WiresharkInstallGuideUrl)
    }
}

function Get-MarlinSpikeAdminPassword {
    New-MarlinSpikeDirectories

    if (Test-Path $script:AdminPasswordFile) {
        return (Get-Content -Path $script:AdminPasswordFile -Raw).Trim()
    }

    $alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%&*".ToCharArray()
    $passwordChars = for ($i = 0; $i -lt 20; $i++) {
        $alphabet[(Get-Random -Maximum $alphabet.Length)]
    }
    $password = -join $passwordChars
    [System.IO.File]::WriteAllText($script:AdminPasswordFile, $password)
    return $password
}

function Get-MarlinSpikeRuntimeEnvironment {
    param([int]$Port = 5001)

    $envMap = @{
        "MARLINSPIKE_HOME" = $script:AppHome
        "MARLINSPIKE_DESKTOP_MODE" = "true"
        "HOST" = "127.0.0.1"
        "PORT" = "$Port"
        "SESSION_COOKIE_SECURE" = "false"
        "ENABLE_LIVE_CAPTURE" = "false"
        "ADMIN_PASSWORD" = Get-MarlinSpikeAdminPassword
    }

    $wiresharkBinDir = Get-WiresharkBinDir
    if ($wiresharkBinDir) {
        $envMap["WIRESHARK_BIN_DIR"] = $wiresharkBinDir
    }

    return $envMap
}

function Remove-MarlinSpikePidFile {
    if (Test-Path $script:PidFile) {
        Remove-Item -Path $script:PidFile -Force
    }
}

function Get-MarlinSpikeShellProcessId {
    if (-not (Test-Path $script:PidFile)) {
        return $null
    }

    try {
        $pidValue = [int](Get-Content -Path $script:PidFile -Raw)
    } catch {
        Remove-MarlinSpikePidFile
        return $null
    }

    if (Get-Process -Id $pidValue -ErrorAction SilentlyContinue) {
        return $pidValue
    }

    Remove-MarlinSpikePidFile
    return $null
}

function Get-ChildProcessIds {
    param([int]$ParentPid)

    $children = @()
    foreach ($process in (Get-CimInstance Win32_Process -Filter "ParentProcessId = $ParentPid")) {
        $children += [int]$process.ProcessId
        $children += Get-ChildProcessIds -ParentPid ([int]$process.ProcessId)
    }
    return $children
}

function Get-ProcessTreeIds {
    param([int]$RootPid)

    $all = @($RootPid)
    $all += Get-ChildProcessIds -ParentPid $RootPid
    return $all | Sort-Object -Unique
}

function Test-MarlinSpikeHttp {
    param([int]$Port = 5001)

    try {
        $response = Invoke-WebRequest -Uri (Get-MarlinSpikeUrl -Port $Port) -UseBasicParsing -TimeoutSec 3
        return $response.StatusCode -ge 200 -and $response.StatusCode -lt 500
    } catch {
        return $false
    }
}

function Wait-MarlinSpikeHttp {
    param(
        [int]$Port = 5001,
        [int]$TimeoutSeconds = 45
    )

    for ($attempt = 0; $attempt -lt ($TimeoutSeconds * 2); $attempt++) {
        if (Test-MarlinSpikeHttp -Port $Port) {
            return $true
        }
        Start-Sleep -Milliseconds 500
    }

    return $false
}
