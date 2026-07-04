param (
    [string]$InstallDir = $env:GHIDRA_INSTALL_DIR
)

if ([string]::IsNullOrWhiteSpace($InstallDir)) {
    Write-Error "GHIDRA_INSTALL_DIR environment variable is not set and no directory was passed as an argument."
    Write-Host 'Please set it, e.g.: $env:GHIDRA_INSTALL_DIR="C:\Users\user\Development\Java\ghidra_12.1.2_PUBLIC"'
    exit 1
}

if (-not (Test-Path -Path $InstallDir)) {
    Write-Error "The specified Ghidra install directory does not exist: $InstallDir"
    exit 1
}

$Libs = @(
    "Ghidra/Features/Base/lib/Base.jar",
    "Ghidra/Features/Decompiler/lib/Decompiler.jar",
    "Ghidra/Framework/Docking/lib/Docking.jar",
    "Ghidra/Framework/Generic/lib/Generic.jar",
    "Ghidra/Framework/Project/lib/Project.jar",
    "Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar",
    "Ghidra/Framework/Utility/lib/Utility.jar",
    "Ghidra/Framework/Gui/lib/Gui.jar"
)

# Ensure local lib directory exists
$LocalLibDir = Join-Path -Path $PSScriptRoot -ChildPath "lib"
if (-not (Test-Path -Path $LocalLibDir)) {
    New-Item -ItemType Directory -Path $LocalLibDir | Out-Null
}

foreach ($Lib in $Libs) {
    $SourcePath = Join-Path -Path $InstallDir -ChildPath $Lib
    if (Test-Path -Path $SourcePath) {
        Write-Host "Copying $Lib to ./lib/"
        Copy-Item -Path $SourcePath -Destination $LocalLibDir -Force
    } else {
        Write-Error "Missing required library in Ghidra installation: $SourcePath"
        exit 1
    }
}

Write-Host "All Ghidra JARs copied successfully."
exit 0
