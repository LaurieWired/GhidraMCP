<#
.SYNOPSIS
    Batch rename Ghidra string labels (s_*) to Hungarian notation.

.DESCRIPTION
    This script finds all string data labels in Ghidra that follow the auto-detected 
    pattern (s_content_address) and renames them to proper Hungarian notation (sz*/wsz*).
    
    Ghidra auto-detects strings and labels them like:
    - s_%s\UI\AutoMap\MaxiMap_6fbb2124
    - s_Hello_World_6fb12345
    
    These should be renamed to:
    - szAutomapMaxiMapPath
    - szHelloWorldMessage

.PARAMETER GhidraServer
    URL of the Ghidra MCP server (default: http://127.0.0.1:8089)

.PARAMETER DryRun
    Show what would be renamed without making changes

.PARAMETER Limit
    Maximum number of strings to process (default: 100)

.PARAMETER Pattern
    Filter strings matching this pattern (default: all s_* strings)

.PARAMETER Interactive
    Prompt for confirmation before each rename

.EXAMPLE
    .\strings-rename.ps1 -DryRun
    Preview what strings would be renamed

.EXAMPLE
    .\strings-rename.ps1 -Limit 10
    Rename first 10 strings

.EXAMPLE
    .\strings-rename.ps1 -Pattern "AutoMap" -Interactive
    Interactively rename strings containing "AutoMap"
#>

param(
    [string]$GhidraServer = "http://127.0.0.1:8089",
    [switch]$DryRun,
    [int]$Limit = 100,
    [string]$Pattern = "",
    [switch]$Interactive,
    [switch]$Help
)

if ($Help) {
    Get-Help $MyInvocation.MyCommand.Path -Detailed
    exit 0
}

# Helper function to generate Hungarian notation name from string content
function Get-HungarianName {
    param([string]$OriginalName, [string]$StringContent)
    
    # Extract just the content part (remove s_ prefix and _address suffix)
    $content = $OriginalName
    if ($content -match "^s_(.+)_[0-9a-fA-F]{6,8}$") {
        $content = $Matches[1]
    } elseif ($content -match "^s_(.+)$") {
        $content = $Matches[1]
    }
    
    # Determine prefix based on content patterns
    $prefix = "sz"  # Default ANSI string
    
    # Check for wide string indicators
    if ($content -match "^L`"" -or $StringContent -match "\\x00.\\x00") {
        $prefix = "wsz"
    }
    
    # Check for format string
    if ($content -match "%[dxsicfl]" -or $content -match "%[-+0-9]*[dxsicfl]") {
        $prefix = "szFmt"
    }
    
    # Check for path string
    if ($content -match "[\\/]" -or $content -match "^[A-Z]:" -or $content -match "\.dll$|\.exe$|\.ini$|\.txt$") {
        $prefix = "szPath"
    }
    
    # Clean up content for use as variable name
    # Remove path separators and special characters
    $cleanContent = $content -replace "\\", "_"
    $cleanContent = $cleanContent -replace "/", "_"
    $cleanContent = $cleanContent -replace "%[0-9]*[dxsicfluphneEgG]", ""  # Remove format specifiers
    $cleanContent = $cleanContent -replace "[^a-zA-Z0-9_]", ""
    
    # Convert to PascalCase
    $parts = $cleanContent -split "_"
    $pascalCase = ""
    foreach ($part in $parts) {
        if ($part.Length -gt 0) {
            # Capitalize first letter, rest lowercase (unless all caps like UI, API)
            if ($part -cmatch "^[A-Z]+$" -and $part.Length -le 4) {
                # Keep short acronyms as-is (UI, API, ID)
                $pascalCase += $part
            } else {
                $pascalCase += $part.Substring(0,1).ToUpper() + $part.Substring(1).ToLower()
            }
        }
    }
    
    # Limit length and ensure valid name
    if ($pascalCase.Length -gt 50) {
        $pascalCase = $pascalCase.Substring(0, 50)
    }
    
    if ($pascalCase.Length -eq 0) {
        $pascalCase = "String"
    }
    
    return "$prefix$pascalCase"
}

# Check connection to Ghidra
Write-Host "Connecting to Ghidra at $GhidraServer..." -ForegroundColor Cyan
try {
    $metadata = Invoke-RestMethod -Uri "$GhidraServer/get_metadata" -Method GET -TimeoutSec 10
    Write-Host "Connected to: $($metadata.program_name)" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Cannot connect to Ghidra MCP server at $GhidraServer" -ForegroundColor Red
    Write-Host "Make sure Ghidra is running with the MCP plugin enabled." -ForegroundColor Yellow
    exit 1
}

# Get all defined data items
Write-Host "`nFetching string labels from Ghidra..." -ForegroundColor Cyan
try {
    # Use list_data_items to get all defined data
    $dataItems = Invoke-RestMethod -Uri "$GhidraServer/list_data_items?offset=0&limit=5000" -Method GET -TimeoutSec 30
} catch {
    Write-Host "ERROR: Failed to fetch data items: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Filter for s_* labels
$stringLabels = @()
if ($dataItems.items) {
    foreach ($item in $dataItems.items) {
        $name = $item.name
        if ($name -match "^s_" -and $name -notmatch "^sz" -and $name -notmatch "^wsz") {
            # Apply pattern filter if specified
            if ($Pattern -and $name -notmatch $Pattern) {
                continue
            }
            $stringLabels += @{
                Address = $item.address
                Name = $name
                Type = $item.type
                Size = $item.size
            }
        }
    }
}

if ($stringLabels.Count -eq 0) {
    Write-Host "`nNo s_* string labels found that need renaming." -ForegroundColor Yellow
    Write-Host "All strings may already be using Hungarian notation (sz*/wsz*)." -ForegroundColor Gray
    exit 0
}

Write-Host "`nFound $($stringLabels.Count) string labels to process" -ForegroundColor Green

# Limit processing
if ($stringLabels.Count -gt $Limit) {
    Write-Host "Limiting to first $Limit strings (use -Limit to change)" -ForegroundColor Yellow
    $stringLabels = $stringLabels[0..($Limit-1)]
}

# Preview/process each string
$successCount = 0
$failCount = 0
$skipCount = 0

Write-Host ""
Write-Host ("-" * 80)
Write-Host "STRING LABEL RENAMING" -ForegroundColor Cyan
Write-Host ("-" * 80)

foreach ($label in $stringLabels) {
    $address = $label.Address
    $oldName = $label.Name
    
    # Generate new name
    $newName = Get-HungarianName -OriginalName $oldName -StringContent ""
    
    # Check if names are different
    if ($oldName -eq $newName) {
        Write-Host "  SKIP: $oldName (name unchanged)" -ForegroundColor Gray
        $skipCount++
        continue
    }
    
    Write-Host "`n$address" -ForegroundColor White
    Write-Host "  OLD: $oldName" -ForegroundColor Yellow
    Write-Host "  NEW: $newName" -ForegroundColor Green
    
    if ($DryRun) {
        Write-Host "  [DRY RUN - no changes made]" -ForegroundColor Cyan
        $successCount++
        continue
    }
    
    if ($Interactive) {
        $confirm = Read-Host "  Rename? (y/n/q)"
        if ($confirm -eq "q") {
            Write-Host "`nQuitting..." -ForegroundColor Yellow
            break
        }
        if ($confirm -ne "y") {
            Write-Host "  SKIPPED" -ForegroundColor Gray
            $skipCount++
            continue
        }
    }
    
    # Perform rename
    try {
        $body = @{
            address = $address
            name = $newName
        } | ConvertTo-Json
        
        $result = Invoke-RestMethod -Uri "$GhidraServer/rename_or_label" -Method POST -Body $body -ContentType "application/json" -TimeoutSec 10
        
        if ($result.success -or $result -match "success|renamed|created") {
            Write-Host "  SUCCESS" -ForegroundColor Green
            $successCount++
        } else {
            Write-Host "  FAILED: $result" -ForegroundColor Red
            $failCount++
        }
    } catch {
        Write-Host "  ERROR: $($_.Exception.Message)" -ForegroundColor Red
        $failCount++
    }
    
    # Small delay to avoid overwhelming the server
    Start-Sleep -Milliseconds 50
}

# Summary
Write-Host ""
Write-Host ("-" * 80)
Write-Host "SUMMARY" -ForegroundColor Cyan
Write-Host ("-" * 80)
Write-Host "  Processed: $($stringLabels.Count)"
Write-Host "  Success:   $successCount" -ForegroundColor Green
Write-Host "  Failed:    $failCount" -ForegroundColor $(if ($failCount -gt 0) { "Red" } else { "Gray" })
Write-Host "  Skipped:   $skipCount" -ForegroundColor Gray

if ($DryRun) {
    Write-Host ""
    Write-Host "This was a dry run. Use without -DryRun to apply changes." -ForegroundColor Yellow
}
