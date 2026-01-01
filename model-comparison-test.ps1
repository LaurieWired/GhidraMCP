<#
.SYNOPSIS
    Compare Haiku vs Opus model performance on Ghidra function documentation.

.DESCRIPTION
    This script runs the same functions through both Haiku and Opus models,
    captures their output, and provides a side-by-side comparison for evaluation.
    
    It does NOT apply changes to Ghidra - it only captures and compares outputs.

.PARAMETER NumFunctions
    Number of functions to test with each model (default: 5)

.PARAMETER GhidraServer
    Ghidra MCP server URL (default: http://127.0.0.1:8089)

.EXAMPLE
    .\model-comparison-test.ps1 -NumFunctions 3
#>

param(
    [int]$NumFunctions = 5,
    [string]$GhidraServer = "http://127.0.0.1:8089"
)

$ErrorActionPreference = "Stop"

# Models to compare
$Models = @(
    @{ Name = "haiku"; FullName = "claude-haiku-4-5-20251001"; Description = "Fast, cost-effective" },
    @{ Name = "opus"; FullName = "claude-opus-4-5"; Description = "Most capable" }
)

$todoFile = ".\FunctionsTodo.txt"
$promptFile = ".\docs\prompts\FUNCTION_DOC_WORKFLOW_V2.md"
$outputDir = ".\model-comparison-output"
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$reportFile = "$outputDir\comparison-report-$timestamp.md"

# Create output directory
New-Item -ItemType Directory -Force -Path $outputDir | Out-Null

Write-Host "=== Model Comparison Test ===" -ForegroundColor Cyan
Write-Host "Testing Haiku vs Opus on $NumFunctions functions" -ForegroundColor Cyan
Write-Host ""

# Check prerequisites
if (-not (Test-Path $todoFile)) {
    Write-Host "ERROR: Todo file not found at $todoFile" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $promptFile)) {
    Write-Host "ERROR: Prompt file not found at $promptFile" -ForegroundColor Red
    exit 1
}

# Get pending functions
$content = Get-Content $todoFile
$pending = @()
foreach ($line in $content) {
    if ($line -match '^\[ \] (.+?) @ ([0-9a-fA-F]+)') {
        $pending += @{
            Name = $Matches[1]
            Address = $Matches[2]
        }
    }
}

if ($pending.Count -lt $NumFunctions) {
    Write-Host "WARNING: Only $($pending.Count) pending functions available" -ForegroundColor Yellow
    $NumFunctions = $pending.Count
}

# Select functions for testing (spread them out for variety)
$step = [Math]::Max(1, [Math]::Floor($pending.Count / $NumFunctions))
$testFunctions = @()
for ($i = 0; $i -lt $NumFunctions; $i++) {
    $idx = $i * $step
    if ($idx -lt $pending.Count) {
        $testFunctions += $pending[$idx]
    }
}

Write-Host "Selected $($testFunctions.Count) functions for testing:" -ForegroundColor Green
foreach ($func in $testFunctions) {
    Write-Host "  - $($func.Name) @ $($func.Address)" -ForegroundColor Gray
}
Write-Host ""

# Load the base prompt
$basePrompt = Get-Content $promptFile -Raw

# Function to get decompiled code from Ghidra
function Get-DecompiledCode {
    param([string]$Address)
    
    try {
        $response = Invoke-RestMethod -Uri "$GhidraServer/decompile_function?address=0x$Address" -Method Get -TimeoutSec 30
        return $response
    } catch {
        Write-Host "  WARNING: Could not get decompiled code for 0x$Address - $_" -ForegroundColor Yellow
        return $null
    }
}

# Function to get function completeness
function Get-FunctionCompleteness {
    param([string]$Address)
    
    try {
        $response = Invoke-RestMethod -Uri "$GhidraServer/analyze_function_completeness?address=0x$Address" -Method Get -TimeoutSec 30
        return $response
    } catch {
        return $null
    }
}

# Results storage
$results = @{}

# Test each function with each model
foreach ($func in $testFunctions) {
    $funcName = $func.Name
    $address = $func.Address
    
    Write-Host "Processing $funcName @ 0x$address" -ForegroundColor Cyan
    
    # Get decompiled code first
    $decompiledCode = Get-DecompiledCode -Address $address
    if (-not $decompiledCode) {
        Write-Host "  Skipping - could not get decompiled code" -ForegroundColor Yellow
        continue
    }
    
    # Get completeness score
    $completeness = Get-FunctionCompleteness -Address $address
    $completenessInfo = ""
    if ($completeness) {
        $completenessInfo = "`n`nCurrent Completeness Score: $($completeness.score)%"
    }
    
    # Build the prompt
    $prompt = $basePrompt + "`n`n## TARGET FUNCTION TO DOCUMENT`n`nFunction Name: **$funcName**`nFunction Address: **0x$address**$completenessInfo`n`n**BEGIN DOCUMENTATION:** Proceed with complete and thorough documentation of this function following the workflow above."
    
    $results[$funcName] = @{
        Address = $address
        DecompiledCode = $decompiledCode
        Completeness = $completeness
        Models = @{}
    }
    
    foreach ($model in $Models) {
        Write-Host "  Testing with $($model.Name)..." -ForegroundColor Yellow
        
        $startTime = Get-Date
        
        try {
            # IMPORTANT: Use --print to only display the response, not apply MCP tools
            # This is a DRY RUN - we capture what the model WOULD do
            $output = echo $prompt | claude --model $($model.FullName) --print 2>&1
            $exitCode = $LASTEXITCODE
            
            $endTime = Get-Date
            $duration = ($endTime - $startTime).TotalSeconds
            
            $outputStr = $output -join "`n"
            
            # Check for rate limit
            if ($outputStr -match "5-hour limit|hour limit reached|resets \d+[ap]m") {
                Write-Host "    Rate limit hit for $($model.Name)!" -ForegroundColor Red
                $results[$funcName].Models[$model.Name] = @{
                    Success = $false
                    Error = "Rate limit"
                    Duration = $duration
                }
                continue
            }
            
            # Save output to file
            $outputFile = "$outputDir\$funcName-$($model.Name)-$timestamp.txt"
            $outputStr | Out-File -FilePath $outputFile -Encoding UTF8
            
            # Analyze the output
            $analysis = @{
                Success = ($exitCode -eq 0)
                Duration = [Math]::Round($duration, 2)
                OutputLength = $outputStr.Length
                OutputFile = $outputFile
                
                # Check for key documentation elements
                HasFunctionName = ($outputStr -match "rename_function|set_function_prototype")
                HasComments = ($outputStr -match "set_plate_comment|set_decompiler_comment|batch_set_comments")
                HasLabels = ($outputStr -match "batch_create_labels|create_label")
                HasVariableTypes = ($outputStr -match "batch_set_variable_types|set_variable_type")
                HasStructures = ($outputStr -match "create_struct")
                
                # Count tool calls
                ToolCallCount = ([regex]::Matches($outputStr, "mcp_ghidra_")).Count
                
                # Extract proposed function name if found
                ProposedName = if ($outputStr -match 'rename_function[^"]*"([^"]+)"') { $Matches[1] } else { "N/A" }
            }
            
            $results[$funcName].Models[$model.Name] = $analysis
            
            Write-Host "    Done in $($analysis.Duration)s - $($analysis.ToolCallCount) tool calls" -ForegroundColor Green
            
        } catch {
            Write-Host "    Error: $_" -ForegroundColor Red
            $results[$funcName].Models[$model.Name] = @{
                Success = $false
                Error = $_.ToString()
                Duration = 0
            }
        }
        
        # Small delay between models to avoid rate limits
        Start-Sleep -Seconds 2
    }
    
    Write-Host ""
}

# Generate comparison report
Write-Host "Generating comparison report..." -ForegroundColor Cyan

$report = @"
# Model Comparison Report: Haiku vs Opus

**Generated:** $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
**Functions Tested:** $($testFunctions.Count)

## Summary

| Function | Haiku Time | Opus Time | Haiku Tools | Opus Tools | Haiku Name | Opus Name |
|----------|------------|-----------|-------------|------------|------------|-----------|
"@

foreach ($funcName in $results.Keys) {
    $r = $results[$funcName]
    $haiku = $r.Models["haiku"]
    $opus = $r.Models["opus"]
    
    $haikuTime = if ($haiku.Success) { "$($haiku.Duration)s" } else { "Failed" }
    $opusTime = if ($opus.Success) { "$($opus.Duration)s" } else { "Failed" }
    $haikuTools = if ($haiku.Success) { $haiku.ToolCallCount } else { "-" }
    $opusTools = if ($opus.Success) { $opus.ToolCallCount } else { "-" }
    $haikuName = if ($haiku.Success) { $haiku.ProposedName } else { "-" }
    $opusName = if ($opus.Success) { $opus.ProposedName } else { "-" }
    
    $report += "`n| $funcName | $haikuTime | $opusTime | $haikuTools | $opusTools | $haikuName | $opusName |"
}

$report += @"


## Detailed Analysis

"@

foreach ($funcName in $results.Keys) {
    $r = $results[$funcName]
    
    $report += @"

### $funcName @ 0x$($r.Address)

**Original Completeness:** $($r.Completeness.score)%

| Metric | Haiku | Opus |
|--------|-------|------|
"@
    
    $haiku = $r.Models["haiku"]
    $opus = $r.Models["opus"]
    
    if ($haiku.Success -and $opus.Success) {
        $report += @"

| Duration | $($haiku.Duration)s | $($opus.Duration)s |
| Tool Calls | $($haiku.ToolCallCount) | $($opus.ToolCallCount) |
| Output Length | $($haiku.OutputLength) chars | $($opus.OutputLength) chars |
| Has Function Rename | $($haiku.HasFunctionName) | $($opus.HasFunctionName) |
| Has Comments | $($haiku.HasComments) | $($opus.HasComments) |
| Has Labels | $($haiku.HasLabels) | $($opus.HasLabels) |
| Has Variable Types | $($haiku.HasVariableTypes) | $($opus.HasVariableTypes) |
| Has Structures | $($haiku.HasStructures) | $($opus.HasStructures) |
| Proposed Name | $($haiku.ProposedName) | $($opus.ProposedName) |

**Haiku Output:** ``$($haiku.OutputFile)``
**Opus Output:** ``$($opus.OutputFile)``
"@
    } else {
        $report += "`n| Status | $(if ($haiku.Success) { 'Success' } else { $haiku.Error }) | $(if ($opus.Success) { 'Success' } else { $opus.Error }) |"
    }
}

$report += @"


## Evaluation Criteria

When reviewing the outputs, consider:

1. **Function Name Quality**: Is the proposed name descriptive and accurate?
2. **Comment Quality**: Are comments insightful and explain the logic?
3. **Label Accuracy**: Are assembly labels placed at meaningful locations?
4. **Type Inference**: Are variable types correctly identified?
5. **Structure Detection**: Are data structures properly identified?
6. **Overall Understanding**: Does the model demonstrate understanding of the code's purpose?

## Conclusion

*Review the individual output files to make a qualitative assessment of each model's performance.*

- **Haiku Outputs:** Faster, cheaper - check if quality is sufficient
- **Opus Outputs:** Slower, more expensive - check if extra quality justifies cost

"@

$report | Out-File -FilePath $reportFile -Encoding UTF8

Write-Host ""
Write-Host "=== Comparison Complete ===" -ForegroundColor Green
Write-Host "Report saved to: $reportFile" -ForegroundColor Cyan
Write-Host "Individual outputs saved to: $outputDir" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Open the report: code `"$reportFile`"" -ForegroundColor Gray
Write-Host "  2. Compare individual function outputs in $outputDir" -ForegroundColor Gray
Write-Host "  3. Look for qualitative differences in naming, comments, and understanding" -ForegroundColor Gray
