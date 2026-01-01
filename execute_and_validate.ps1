# Execute Headless Fix Script and Validate Results
# This script guides you through manual execution due to MCP timeout limitations

$ErrorActionPreference = "Stop"

Write-Host "=" -NoNewline -ForegroundColor Cyan
Write-Host ("=" * 59) -ForegroundColor Cyan
Write-Host "EXECUTE HEADLESS FIX SCRIPT" -ForegroundColor Yellow
Write-Host "=" -NoNewline -ForegroundColor Cyan
Write-Host ("=" * 59) -ForegroundColor Cyan
Write-Host ""

Write-Host "Current Accuracy: " -NoNewline
Write-Host "12.5% (CRITICAL)" -ForegroundColor Red
Write-Host "Target Accuracy:  " -NoNewline
Write-Host "90%+ (EXCELLENT)" -ForegroundColor Green
Write-Host ""

Write-Host "=" -NoNewline -ForegroundColor Cyan
Write-Host ("=" * 59) -ForegroundColor Cyan
Write-Host "STEP 1: MANUAL EXECUTION IN GHIDRA" -ForegroundColor Yellow
Write-Host "=" -NoNewline -ForegroundColor Cyan
Write-Host ("=" * 59) -ForegroundColor Cyan
Write-Host ""

Write-Host "MCP automatic execution is blocked by timeouts." -ForegroundColor Yellow
Write-Host "Please execute the script manually in Ghidra:" -ForegroundColor Yellow
Write-Host ""

Write-Host "1. " -NoNewline -ForegroundColor Cyan
Write-Host "Open Ghidra with D2Common.dll loaded"

Write-Host "2. " -NoNewline -ForegroundColor Cyan
Write-Host "Click: " -NoNewline
Write-Host "Window → Script Manager" -ForegroundColor White

Write-Host "3. " -NoNewline -ForegroundColor Cyan
Write-Host "In filter box, type: " -NoNewline
Write-Host "FixFunction" -ForegroundColor White

Write-Host "4. " -NoNewline -ForegroundColor Cyan
Write-Host "Find: " -NoNewline
Write-Host "FixFunctionParametersHeadless" -ForegroundColor White

Write-Host "5. " -NoNewline -ForegroundColor Cyan
Write-Host "Click the " -NoNewline
Write-Host "green PLAY button (▶)" -ForegroundColor Green

Write-Host "6. " -NoNewline -ForegroundColor Cyan
Write-Host "Watch console output (should show progress every 50 functions)"

Write-Host "7. " -NoNewline -ForegroundColor Cyan
Write-Host "Wait ~10 minutes for completion"

Write-Host ""
Write-Host "Expected console output:" -ForegroundColor Yellow
Write-Host @"
========================================
FIX FUNCTION PARAMETERS AND CONVENTIONS
HEADLESS VERSION
========================================
Program: D2Common.dll
Mode: Analyze and Fix (AUTO)

[50/2766] Analyzed: 50 | Params Fixed: 12 | Conv Fixed: 38 | ETA: 540 sec
[100/2766] Analyzed: 100 | Params Fixed: 24 | Conv Fixed: 76 | ETA: 510 sec
...
[FIXED CONV] GetUnitOrItemProperties @ 0x6fd6a3d0: __d2regcall -> __stdcall
...
[COMPLETE] Analysis finished in 600 seconds
[SUMMARY] Fixed 150 parameters, 890 conventions, 12 failures
[SAVE] Program saved successfully
"@ -ForegroundColor Gray

Write-Host ""
Write-Host "=" -NoNewline -ForegroundColor Cyan
Write-Host ("=" * 59) -ForegroundColor Cyan
Write-Host ""

# Wait for user confirmation
Write-Host "Press ENTER after the script completes in Ghidra..." -ForegroundColor Yellow
$null = Read-Host

Write-Host ""
Write-Host "=" -NoNewline -ForegroundColor Cyan
Write-Host ("=" * 59) -ForegroundColor Cyan
Write-Host "STEP 2: VALIDATE RESULTS" -ForegroundColor Yellow
Write-Host "=" -NoNewline -ForegroundColor Cyan
Write-Host ("=" * 59) -ForegroundColor Cyan
Write-Host ""

Write-Host "Running validation script..." -ForegroundColor Cyan
Write-Host ""

# Run validation
python scripts\validate_function_accuracy.py

$validationExitCode = $LASTEXITCODE

Write-Host ""
Write-Host "=" -NoNewline -ForegroundColor Cyan
Write-Host ("=" * 59) -ForegroundColor Cyan
Write-Host "RESULTS" -ForegroundColor Yellow
Write-Host "=" -NoNewline -ForegroundColor Cyan
Write-Host ("=" * 59) -ForegroundColor Cyan
Write-Host ""

if ($validationExitCode -eq 0) {
    Write-Host "✓ " -NoNewline -ForegroundColor Green
    Write-Host "VALIDATION PASSED - Accuracy is 90%+ (EXCELLENT)" -ForegroundColor Green
    Write-Host ""
    Write-Host "Success! The edge case fixes have been applied correctly." -ForegroundColor Green
    Write-Host "The calling convention issues have been resolved." -ForegroundColor Green
} else {
    Write-Host "⚠ " -NoNewline -ForegroundColor Yellow
    Write-Host "VALIDATION SHOWS IMPROVEMENTS NEEDED" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "The script ran but accuracy is still below 90%." -ForegroundColor Yellow
    Write-Host "Review the validation output above for details." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Possible reasons:" -ForegroundColor Yellow
    Write-Host "  1. Script did not complete successfully in Ghidra" -ForegroundColor Gray
    Write-Host "  2. Additional edge cases need to be addressed" -ForegroundColor Gray
    Write-Host "  3. Detection algorithm needs refinement" -ForegroundColor Gray
}

Write-Host ""
Write-Host "=" -NoNewline -ForegroundColor Cyan
Write-Host ("=" * 59) -ForegroundColor Cyan
Write-Host ""

exit $validationExitCode
