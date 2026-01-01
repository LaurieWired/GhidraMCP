# Simple Execution and Validation Script
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "EXECUTE HEADLESS FIX SCRIPT AND VALIDATE" -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Current Accuracy: 12.5% (CRITICAL)" -ForegroundColor Red
Write-Host "Target Accuracy:  90%+ (EXCELLENT)" -ForegroundColor Green
Write-Host ""

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "MANUAL EXECUTION REQUIRED" -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Due to MCP timeout limitations, please execute manually:" -ForegroundColor Yellow
Write-Host ""
Write-Host "1. Open Ghidra with D2Common.dll loaded"
Write-Host "2. Window -> Script Manager"
Write-Host "3. Type 'FixFunction' in filter"
Write-Host "4. Find 'FixFunctionParametersHeadless'"
Write-Host "5. Click green PLAY button"
Write-Host "6. Wait ~10 minutes for completion"
Write-Host ""
Write-Host "Expected output:" -ForegroundColor Cyan
Write-Host "  [50/2766] Analyzed: 50 | Params Fixed: 12 | Conv Fixed: 38"
Write-Host "  [100/2766] Analyzed: 100 | Params Fixed: 24 | Conv Fixed: 76"
Write-Host "  ..."
Write-Host "  [COMPLETE] Analysis finished"
Write-Host "  [SAVE] Program saved successfully"
Write-Host ""

Write-Host "Press ENTER after script completes in Ghidra..." -ForegroundColor Yellow
Read-Host

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "VALIDATING RESULTS" -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

python scripts\validate_function_accuracy.py

$exitCode = $LASTEXITCODE

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
if ($exitCode -eq 0) {
    Write-Host "SUCCESS - Accuracy is 90%+ (EXCELLENT)" -ForegroundColor Green
} else {
    Write-Host "NEEDS IMPROVEMENT - Accuracy below 90%" -ForegroundColor Yellow
}
Write-Host "============================================================" -ForegroundColor Cyan

exit $exitCode
