# Clean Installation Script for GhidraMCP
# This script completely removes old installations before deploying new version

param(
    [string]$GhidraPath = "F:\ghidra_11.4.2"
)

function Write-Success { param($msg) Write-Host "[SUCCESS] $msg" -ForegroundColor Green }
function Write-Info { param($msg) Write-Host "[INFO] $msg" -ForegroundColor Cyan }
function Write-Warning { param($msg) Write-Host "[WARNING] $msg" -ForegroundColor Yellow }
function Write-Error { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red }

Write-Info "GhidraMCP Clean Installation Script"
Write-Info "====================================="
Write-Host ""

# Check if Ghidra is running
$ghidraProcess = Get-Process | Where-Object { $_.ProcessName -like "*ghidra*" -or $_.ProcessName -like "*java*" -and $_.MainWindowTitle -like "*Ghidra*" }
if ($ghidraProcess) {
    Write-Error "Ghidra appears to be running!"
    Write-Warning "Please close Ghidra completely before running this script."
    Write-Warning "Running processes: $($ghidraProcess.ProcessName -join ', ')"
    exit 1
}

Write-Success "Ghidra is not running - proceeding with clean installation"
Write-Host ""

# Step 1: Remove ALL old GhidraMCP files
Write-Info "Step 1: Removing all old GhidraMCP installations..."

$locationsToClean = @(
    "$GhidraPath\Extensions\Ghidra\GhidraMCP*.zip",
    "$env:USERPROFILE\AppData\Roaming\ghidra\ghidra_11.4.2_PUBLIC\Extensions\GhidraMCP",
    "$env:USERPROFILE\.ghidra\.ghidra_11.4.2_PUBLIC\Extensions\GhidraMCP"
)

foreach ($location in $locationsToClean) {
    if (Test-Path $location) {
        Remove-Item $location -Recurse -Force -ErrorAction SilentlyContinue
        Write-Success "Removed: $location"
    } else {
        Write-Info "Not found (OK): $location"
    }
}

Write-Host ""
Write-Info "Step 2: Waiting 2 seconds for filesystem sync..."
Start-Sleep -Seconds 2

# Step 3: Deploy fresh installation
Write-Info "Step 3: Installing GhidraMCP v1.5.0..."

# Install ZIP to Ghidra Extensions
$zipSource = "$PSScriptRoot\target\GhidraMCP-1.5.0.zip"
$zipDest = "$GhidraPath\Extensions\Ghidra\GhidraMCP-1.5.0.zip"

if (-not (Test-Path $zipSource)) {
    Write-Error "Build artifact not found: $zipSource"
    Write-Info "Please run: mvn clean package assembly:single"
    exit 1
}

try {
    $extensionsDir = "$GhidraPath\Extensions\Ghidra"
    if (-not (Test-Path $extensionsDir)) {
        New-Item -ItemType Directory -Path $extensionsDir -Force | Out-Null
    }

    Copy-Item $zipSource $zipDest -Force
    Write-Success "Installed ZIP: $zipDest"
} catch {
    Write-Error "Failed to install ZIP: $($_.Exception.Message)"
    exit 1
}

# Install JAR to user Extensions
$jarSource = "$PSScriptRoot\target\GhidraMCP.jar"
$jarDestDir = "$env:USERPROFILE\AppData\Roaming\ghidra\ghidra_11.4.2_PUBLIC\Extensions\GhidraMCP\lib"
$jarDest = "$jarDestDir\GhidraMCP.jar"

try {
    if (-not (Test-Path $jarDestDir)) {
        New-Item -ItemType Directory -Path $jarDestDir -Force | Out-Null
    }

    Copy-Item $jarSource $jarDest -Force
    Write-Success "Installed JAR: $jarDest"
} catch {
    Write-Error "Failed to install JAR: $($_.Exception.Message)"
    exit 1
}

# Install Python bridge
$bridgeSource = "$PSScriptRoot\bridge_mcp_ghidra.py"
$bridgeDest = "$GhidraPath\bridge_mcp_ghidra.py"

if (Test-Path $bridgeSource) {
    Copy-Item $bridgeSource $bridgeDest -Force
    Write-Success "Installed Python bridge: $bridgeDest"
}

# Install requirements
$reqSource = "$PSScriptRoot\requirements.txt"
$reqDest = "$GhidraPath\requirements.txt"

if (Test-Path $reqSource) {
    Copy-Item $reqSource $reqDest -Force
    Write-Success "Installed requirements: $reqDest"
}

Write-Host ""
Write-Success "Clean installation completed successfully!"
Write-Host ""
Write-Info "IMPORTANT - Next Steps:"
Write-Host "  1. Start Ghidra (it may take 30-60 seconds to load)"
Write-Host "  2. Go to: File > Configure > Plugin Configuration"
Write-Host "  3. In the filter box, type: GhidraMCP"
Write-Host "  4. Check the checkbox next to 'GhidraMCPPlugin'"
Write-Host "  5. Click 'OK'"
Write-Host "  6. The plugin should load and show: 'GhidraMCPPlugin loaded successfully'"
Write-Host ""
Write-Info "If you see any errors, check the Ghidra console window for details"
Write-Host ""

$fileSize = (Get-Item $zipDest).Length
Write-Success "Installation verified: $([math]::Round($fileSize/1KB, 2)) KB"
