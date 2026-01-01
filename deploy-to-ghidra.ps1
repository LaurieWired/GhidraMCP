# GhidraMCP Deployment Script
# Automatically installs and configures the GhidraMCP plugin

param(
    [string]$GhidraPath = "",
    [switch]$Verbose = $false
)

# Color output functions
function Write-Success { param($msg) Write-Host "[SUCCESS] $msg" -ForegroundColor Green }
function Write-Info { param($msg) Write-Host "[INFO] $msg" -ForegroundColor Cyan }
function Write-Warning { param($msg) Write-Host "[WARNING] $msg" -ForegroundColor Yellow }
function Write-Error { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red }

Write-Info "GhidraMCP Deployment Script"
Write-Info "============================"

# Build the extension first
Write-Info "Building GhidraMCP extension..."

# Try multiple Maven locations
$mavenPaths = @(
    "$env:USERPROFILE\tools\apache-maven-3.9.6\bin\mvn.cmd",
    "C:\Program Files\JetBrains\IntelliJ IDEA Community Edition 2025.1.1.1\plugins\maven\lib\maven3\bin\mvn.cmd",
    (Get-Command mvn -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source)
)

$mavenPath = $null
foreach ($path in $mavenPaths) {
    if ($path -and (Test-Path $path)) {
        $mavenPath = $path
        Write-Info "Found Maven at: $mavenPath"
        break
    }
}

if (-not $mavenPath) {
    Write-Error "Maven not found. Tried:"
    foreach ($path in $mavenPaths) {
        if ($path) { Write-Host "  - $path" }
    }
    Write-Info "Please ensure Maven is installed or add it to PATH"
    exit 1
}

try {
    $buildOutput = & $mavenPath clean package assembly:single -DskipTests 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Build failed with exit code: $LASTEXITCODE"
        Write-Host $buildOutput
        exit 1
    }
    Write-Success "Build completed successfully"
} catch {
    Write-Error "Build failed: $($_.Exception.Message)"
    exit 1
}

# Detect version from pom.xml
$pomPath = "$PSScriptRoot\pom.xml"
if (Test-Path $pomPath) {
    try {
        [xml]$pom = Get-Content $pomPath
        $version = $pom.project.version
        Write-Success "Detected version: $version"
    } catch {
        Write-Warning "Could not parse version from pom.xml, using manual detection"
        $version = $null
    }
} else {
    Write-Warning "pom.xml not found, using manual version detection"
    $version = $null
}

# Find Ghidra installation
$possiblePaths = @(
    "F:\ghidra_11.4.2_PUBLIC",
    "F:\ghidra_11.4.2",
    "C:\ghidra",
    "C:\ghidra_11.4.2_PUBLIC",
    "$env:USERPROFILE\ghidra",
    "$env:USERPROFILE\ghidra_11.4.2_PUBLIC",
    "$env:USERPROFILE\tools\ghidra",
    "$env:ProgramFiles\ghidra",
    "$env:ProgramFiles\ghidra_11.4.2_PUBLIC"
)

if (-not $GhidraPath) {
    Write-Info "Searching for Ghidra installation..."
    foreach ($path in $possiblePaths) {
        if (Test-Path "$path\ghidraRun.bat") {
            $GhidraPath = $path
            Write-Success "Found Ghidra at: $GhidraPath"
            break
        }
    }
    
    if (-not $GhidraPath) {
        Write-Warning "Ghidra installation not found automatically."
        $GhidraPath = Read-Host "Please enter your Ghidra installation path"
        if (-not (Test-Path "$GhidraPath\ghidraRun.bat")) {
            Write-Error "Invalid Ghidra path. ghidraRun.bat not found."
            exit 1
        }
    }
}

# Find latest build artifact
if ($version) {
    $artifactPath = "$PSScriptRoot\target\GhidraMCP-$version.zip"
} else {
    # Auto-detect latest artifact if version not found
    $artifacts = Get-ChildItem -Path "$PSScriptRoot\target" -Filter "GhidraMCP-*.zip" -ErrorAction SilentlyContinue |
                 Sort-Object LastWriteTime -Descending

    if ($artifacts) {
        $artifactPath = $artifacts[0].FullName
        # Extract version from filename
        if ($artifacts[0].Name -match 'GhidraMCP-(.+)\.zip') {
            $version = $Matches[1]
        }
        Write-Info "Auto-detected latest artifact: $($artifacts[0].Name)"
    } else {
        Write-Error "No build artifacts found in target/"
        Write-Info "Please run the build first: mvn clean package assembly:single"
        exit 1
    }
}

if (-not (Test-Path $artifactPath)) {
    Write-Error "Build artifact not found: $artifactPath"
    Write-Info "Please run the build first: mvn clean package assembly:single"
    exit 1
}

Write-Success "Using artifact: $(Split-Path $artifactPath -Leaf) ($version)"

# Find Ghidra Extensions directory
$extensionsDir = "$GhidraPath\Extensions\Ghidra"
if (-not (Test-Path $extensionsDir)) {
    Write-Info "Extensions directory doesn't exist, creating: $extensionsDir"
    New-Item -ItemType Directory -Path $extensionsDir -Force | Out-Null
}

# Remove existing installations
$existingPlugins = Get-ChildItem -Path $extensionsDir -Filter "GhidraMCP*.zip" -ErrorAction SilentlyContinue

if ($existingPlugins) {
    Write-Info "Removing existing GhidraMCP installations..."
    foreach ($plugin in $existingPlugins) {
        Remove-Item $plugin.FullName -Force
        Write-Success "Removed: $($plugin.Name)"
    }
}

# Copy new plugin
try {
    $artifactName = Split-Path $artifactPath -Leaf
    $destinationPath = Join-Path $extensionsDir $artifactName
    Copy-Item $artifactPath $destinationPath -Force
    Write-Success "Installed: $artifactName → $extensionsDir"
} catch {
    Write-Error "Failed to copy plugin: $($_.Exception.Message)"
    exit 1
}

# Also copy JAR to user's local Extensions directory for development/debugging
$jarSourcePath = "$PSScriptRoot\target\GhidraMCP.jar"
if (Test-Path $jarSourcePath) {
    # Detect Ghidra version from installation path
    $ghidraVersionDir = $null
    $ghidraUserBase = "$env:USERPROFILE\AppData\Roaming\ghidra"

    if (Test-Path $ghidraUserBase) {
        # Find the most recent ghidra version directory
        $ghidraVersionDirs = Get-ChildItem -Path $ghidraUserBase -Directory -Filter "ghidra_*" |
                             Sort-Object Name -Descending
        if ($ghidraVersionDirs) {
            $ghidraVersionDir = $ghidraVersionDirs[0].Name
            Write-Info "Detected Ghidra user config version: $ghidraVersionDir"
        }
    }

    if (-not $ghidraVersionDir) {
        # Fallback: extract version from Ghidra installation path
        if ($GhidraPath -match "ghidra_([0-9.]+)") {
            $ghidraVersionDir = "ghidra_$($Matches[1])_PUBLIC"
        } else {
            $ghidraVersionDir = "ghidra_11.4.2_PUBLIC"
        }
        Write-Info "Using Ghidra version dir: $ghidraVersionDir"
    }

    $userExtensionsDir = "$ghidraUserBase\$ghidraVersionDir\Extensions\GhidraMCP\lib"

    if (-not (Test-Path $userExtensionsDir)) {
        Write-Info "Creating user Extensions directory: $userExtensionsDir"
        New-Item -ItemType Directory -Path $userExtensionsDir -Force | Out-Null
    }

    try {
        $jarDestinationPath = Join-Path $userExtensionsDir "GhidraMCP.jar"
        Copy-Item $jarSourcePath $jarDestinationPath -Force
        Write-Success "Installed: GhidraMCP.jar → $userExtensionsDir"
    } catch {
        Write-Warning "Failed to copy JAR to user Extensions: $($_.Exception.Message)"
        Write-Info "JAR copy is optional - plugin will work without it"
    }
} else {
    Write-Warning "JAR file not found: $jarSourcePath"
}

# Copy Python MCP bridge to Ghidra root
$bridgeSourcePath = "$PSScriptRoot\bridge_mcp_ghidra.py"
$requirementsSourcePath = "$PSScriptRoot\requirements.txt"

if (Test-Path $bridgeSourcePath) {
    try {
        $bridgeDestinationPath = Join-Path $GhidraPath "bridge_mcp_ghidra.py"
        
        # Remove existing bridge if it exists
        if (Test-Path $bridgeDestinationPath) {
            Remove-Item $bridgeDestinationPath -Force
            Write-Success "Removed existing bridge"
        }
        
        Copy-Item $bridgeSourcePath $bridgeDestinationPath -Force
        Write-Success "Installed: bridge_mcp_ghidra.py → $GhidraPath"
        
        # Also copy requirements.txt for convenience
        if (Test-Path $requirementsSourcePath) {
            $requirementsDestinationPath = Join-Path $GhidraPath "requirements.txt"
            Copy-Item $requirementsSourcePath $requirementsDestinationPath -Force
            Write-Success "Installed: requirements.txt → $GhidraPath"
        }
        
    } catch {
        Write-Warning "Failed to copy Python bridge: $($_.Exception.Message)"
        Write-Info "You can manually copy bridge_mcp_ghidra.py to your Ghidra installation"
    }
} else {
    Write-Warning "Python bridge not found: $bridgeSourcePath"
}

# Check for user preferences directory
$userDir = "$env:USERPROFILE\.ghidra"
if (Test-Path $userDir) {
    # Try to find and update plugin preferences
    $prefsPattern = "$userDir\*\preferences\*\plugins.xml"
    $prefsFiles = Get-ChildItem -Path $prefsPattern -Recurse -ErrorAction SilentlyContinue
    
    if ($prefsFiles) {
        Write-Info "Found Ghidra preferences files, attempting to enable plugin..."
        foreach ($prefsFile in $prefsFiles) {
            try {
                [xml]$xmlContent = Get-Content $prefsFile.FullName
                $pluginNode = $xmlContent.SelectSingleNode("//PLUGIN[@NAME='GhidraMCPPlugin']")
                
                if ($pluginNode) {
                    $pluginNode.SetAttribute("ENABLED", "true")
                    $xmlContent.Save($prefsFile.FullName)
                    Write-Success "Enabled GhidraMCP plugin in: $($prefsFile.Name)"
                } else {
                    if ($Verbose) {
                        Write-Info "GhidraMCP plugin not found in: $($prefsFile.Name)"
                    }
                }
            } catch {
                if ($Verbose) {
                    Write-Warning "Could not modify preferences file: $($prefsFile.Name)"
                }
            }
        }
    }
}

# Create quick reference message
Write-Host ""
Write-Success "GhidraMCP v$version Successfully Deployed!"
Write-Host ""
Write-Info "Installation Locations:"
Write-Host "   Plugin: $destinationPath"
if ($userExtensionsDir) {
    Write-Host "   JAR: $jarDestinationPath"
}
Write-Host "   Python Bridge: $GhidraPath\bridge_mcp_ghidra.py"
Write-Host "   Requirements: $GhidraPath\requirements.txt"
Write-Host ""
Write-Info "Next Steps:"
Write-Host "1. Install Python dependencies: pip install -r requirements.txt"
Write-Host "2. Start Ghidra"
Write-Host "3. If plugin isn't automatically enabled:"
Write-Host "      - Go to File > Configure..."
Write-Host "      - Navigate to Miscellaneous > GhidraMCP"
Write-Host "      - Check the checkbox to enable"
Write-Host "      - Click OK and restart Ghidra"
Write-Host ""
Write-Info "Usage:"
Write-Host "   Ghidra: Tools > GhidraMCP > Start MCP Server"
Write-Host "   Python: python bridge_mcp_ghidra.py (from Ghidra root directory)"
Write-Host ""
Write-Info "Default Server: http://127.0.0.1:8089/"
Write-Host ""

# Show version-specific release notes
if ($version -match "1\.5\.1") {
    Write-Info "New in v1.5.1 - Batch Operations & ROADMAP Documentation:"
    Write-Host "   + batch_create_labels - Create labels in single atomic transaction"
    Write-Host "   + Enhanced batch_set_comments - Fixed JSON parsing (90% error reduction)"
    Write-Host "   + ROADMAP v2.0 - 10 tools clearly marked with implementation plans"
    Write-Host "   + Performance: 91% API call reduction (57 → 5 calls per function)"
    Write-Host "   + Documentation: Organized structure, comprehensive user prompts"
    Write-Host ""
    Write-Info "For full release notes, see: RELEASE_NOTES.md"
} elseif ($version -match "1\.5\.0") {
    Write-Info "New in v1.5.0 - Workflow Optimization Tools (9 new tools):"
    Write-Host "   + batch_set_comments - Set multiple comments in one call"
    Write-Host "   + set_plate_comment - Function header documentation"
    Write-Host "   + get_function_variables - List all parameters and locals"
    Write-Host "   + batch_rename_function_components - Atomic rename operations"
    Write-Host "   + analyze_function_completeness - Automated quality verification"
} else {
    Write-Info "For release notes, see: docs/releases/v$version/"
}
Write-Host ""



# Verify installation
if (Test-Path $destinationPath) {
    $fileSize = (Get-Item $destinationPath).Length
    Write-Success "Installation verified: $([math]::Round($fileSize/1KB, 2)) KB"
    
    # Automatically restart Ghidra if running
    # Look for javaw process with "Ghidra: PD2" window
    $ghidraProcess = Get-Process | Where-Object { $_.ProcessName -eq "javaw" -and $_.MainWindowTitle -eq "Ghidra: PD2" }
    
    if ($ghidraProcess) {
        Write-Info "Found Ghidra window 'Ghidra: PD2' (PID: $($ghidraProcess.Id)) - closing it..."
        try {
            $ghidraProcess.CloseMainWindow() | Out-Null
            Start-Sleep -Seconds 2
            
            if (!$ghidraProcess.HasExited) {
                Write-Warning "Force closing Ghidra process (PID: $($ghidraProcess.Id))..."
                Stop-Process -Id $ghidraProcess.Id -Force
            }
            Write-Success "Closed Ghidra (PID: $($ghidraProcess.Id))"
        } catch {
            Write-Warning "Could not close process $($ghidraProcess.Id): $($_.Exception.Message)"
        }
        
        Write-Info "Waiting for Ghidra to fully terminate..."
        Start-Sleep -Seconds 3
    } else {
        Write-Info "No running Ghidra instance detected"
    }
    
    # Always start Ghidra
    Write-Info "Starting Ghidra..."
    Start-Process "$GhidraPath\ghidraRun.bat"
    Write-Success "Ghidra started! The updated plugin (v$version) is now available."
} else {
    Write-Error "Installation verification failed!"
    exit 1
}

Write-Success "Deployment completed successfully!"