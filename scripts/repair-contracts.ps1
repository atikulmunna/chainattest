param(
    [switch]$SkipInstall
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$contractsDir = Join-Path $repoRoot "contracts"
$nodeModulesDir = Join-Path $contractsDir "node_modules"
$packageLockPath = Join-Path $contractsDir "package-lock.json"

if (-not (Test-Path $contractsDir)) {
    throw "contracts directory not found at $contractsDir"
}

function Stop-ProjectNodeProcesses {
    $processes = Get-CimInstance Win32_Process -Filter "name = 'node.exe'" |
        Where-Object {
            $_.CommandLine -and (
                $_.CommandLine -like "*crosschain\\contracts*" -or
                $_.CommandLine -like "*npx-cli.js*hardhat node*"
            )
        }

    foreach ($process in $processes) {
        try {
            Stop-Process -Id $process.ProcessId -Force -ErrorAction Stop
            Write-Host "Stopped node process $($process.ProcessId)"
        } catch {
            Write-Warning "Failed to stop node process $($process.ProcessId): $($_.Exception.Message)"
        }
    }
}

function Remove-StaleNpmDirectories {
    if (-not (Test-Path $nodeModulesDir)) {
        return
    }

    Get-ChildItem -Path $nodeModulesDir -Directory -Force -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like ".*-*" } |
        ForEach-Object {
            try {
                Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction Stop
                Write-Host "Removed stale npm temp directory $($_.FullName)"
            } catch {
                Write-Warning "Failed to remove stale directory $($_.FullName): $($_.Exception.Message)"
            }
        }
}

function Repair-Install {
    Push-Location $contractsDir
    try {
        if (-not (Test-Path $packageLockPath)) {
            throw "package-lock.json is required for repair"
        }

        if ($SkipInstall) {
            Write-Host "Skipping npm install as requested."
            return
        }

        npm install
        if ($LASTEXITCODE -ne 0) {
            throw "npm install failed with exit code $LASTEXITCODE"
        }
    } finally {
        Pop-Location
    }
}

Write-Host "Repairing contracts workspace at $contractsDir"
Stop-ProjectNodeProcesses
Remove-StaleNpmDirectories
Repair-Install
Write-Host "Contracts workspace repair complete."
