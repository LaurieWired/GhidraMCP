#!/usr/bin/env powershell
# Project Cleanup Script - Removes outdated files

param([switch]$Force, [switch]$Dry)

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "   GHIDRA-MCP PROJECT CLEANUP - PHASE 1" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

if ($Dry) {
    Write-Host "DRY RUN MODE - No files will be deleted" -ForegroundColor Yellow
    Write-Host "Use -Force to actually delete files" -ForegroundColor Yellow
} else {
    Write-Host "LIVE MODE - Files WILL BE DELETED" -ForegroundColor Red
}
Write-Host ""

Set-Location (Split-Path -Parent $MyInvocation.MyCommand.Path)

# Define files to delete
$toDelete = @(
    "ordinal_fix_log.txt",
    "nul", "UNIT_MONSTER_SEARCH_RESULTS.txt",
    "ACTION_PLAN_TESTING.md", "ACTION_REQUIRED.md", "AUTOMATED_FIX_STATUS.md",
    "IMPLEMENTATION_COMPLETE.md", "PROJECT_CLEANUP_COMPLETE.md",
    "DETECTION_SCRIPT_USAGE_GUIDE.md", "DETECTION_SCRIPT_V2_COMPLETE.md",
    "DETECTION_SCRIPT_V2_SUMMARY.md", "DETECTION_VALIDATION_RESULTS.md",
    "HEADLESS_EXECUTION_GUIDE.md", "HEADLESS_SCRIPT_SUMMARY.md",
    "SCRIPT_ANALYSIS_RESULTS.md", "SCRIPT_IMPROVEMENTS_SUMMARY.md",
    "TESTING_CHECKLIST.md", "QUICK_TEST_GUIDE.md", "QUICK_START_FIX.md",
    "EXECUTE_D2NET_FIX.md", "EXECUTE_NOW.md",
    "PARAMETER_FIXING_ANALYSIS.md", "PARAMETER_FIXING_STATUS.md",
    "FUNCTION_DOCUMENTATION_AUDIT.md",
    "EXTERNAL_LOCATION_TOOLS.md", "EXTERNAL_LOCATION_WORKFLOW.md",
    "EDGE_CASE_DETECTION_README.md", "EDGE_CASE_FINDINGS.md",
    "EDGE_CASE_FIXES_IMPLEMENTATION.md", "EDGE_CASE_INDEX.md",
    "EDGE_CASE_TEST_RESULTS.md", "SESSION_SUMMARY_EDGE_CASES.md",
    "DATA_IMPROVEMENT_EXAMPLES.md", "UNIT_MONSTER_STRUCTURES_REPORT.md",
    "D2_ANALYSIS_QUICK_START.md", "D2_ANALYSIS_SUMMARY.md",
    "D2_CUSTOMIZATIONS_README.md", "DIABLO2_ANALYSIS_COMPLETE_SUMMARY.md",
    "DIABLO2_COMPLETE_BINARY_ANALYSIS.md", "DIABLO2_DOCUMENTATION_INDEX.md",
    "START_DIABLO2_ANALYSIS.md",
    "dll_exports_GUIDE.md", "dll_exports_USAGE.md"
)

$filesFound = 0
$filesDeleted = 0
$logsDeleted = 0

# Process named files
foreach ($file in $toDelete) {
    if (Test-Path -Path $file -ErrorAction SilentlyContinue) {
        $filesFound++
        if (!$Force) {
            Write-Host "[DRY] Would delete: $file" -ForegroundColor Gray
        } else {
            Remove-Item -Path $file -Force -ErrorAction SilentlyContinue
            Write-Host "✓ Deleted: $file" -ForegroundColor Green
            $filesDeleted++
        }
    }
}

# Delete ordinal logs (pattern)
$logs = @(Get-ChildItem -Path "ordinal_fix_log_*.txt" -ErrorAction SilentlyContinue)
if ($logs.Count -gt 0) {
    foreach ($log in $logs) {
        $filesFound++
        if (!$Force) {
            Write-Host "[DRY] Would delete: $($log.Name)" -ForegroundColor Gray
        } else {
            Remove-Item -Path $log.FullName -Force -ErrorAction SilentlyContinue
            Write-Host "✓ Deleted: $($log.Name)" -ForegroundColor Green
            $logsDeleted++
        }
    }
}

# Summary
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "SUMMARY" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan

$remainingMD = @(Get-ChildItem -Filter "*.md" -ErrorAction SilentlyContinue).Count
$totalFound = $filesFound

Write-Host "Files Found:          $totalFound" -ForegroundColor Yellow
if (!$Force) {
    Write-Host "Would Delete:         $totalFound" -ForegroundColor Gray
} else {
    Write-Host "Actually Deleted:     $($filesDeleted + $logsDeleted)" -ForegroundColor Green
}
Write-Host "Remaining .md files:  $remainingMD" -ForegroundColor Cyan
Write-Host ""

if (!$Force) {
    Write-Host "This was a DRY RUN. To actually delete files, run:" -ForegroundColor Yellow
    Write-Host "  .\cleanup.ps1 -Force" -ForegroundColor Gray
} else {
    Write-Host "Cleanup complete!" -ForegroundColor Green
}
Write-Host ""
