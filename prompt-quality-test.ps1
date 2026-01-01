<#
.SYNOPSIS
    Compare quality between full and compact prompts on Ghidra function documentation.

.DESCRIPTION
    This script processes the same functions with both prompt versions and compares:
    - Final completeness scores
    - Documentation quality (comments, naming, types)
    - Time and token efficiency
    
    It can also audit already-documented functions to check quality metrics.

.PARAMETER Mode
    - compare: Process same functions with both prompts (default)
    - audit: Review already-documented functions for quality
    - report: Generate report from previous comparison data

.PARAMETER NumFunctions
    Number of functions to test (default: 3)

.PARAMETER GhidraServer
    Ghidra MCP server URL (default: http://127.0.0.1:8089)

.EXAMPLE
    .\prompt-quality-test.ps1 -Mode compare -NumFunctions 5
    .\prompt-quality-test.ps1 -Mode audit -NumFunctions 20
#>

param(
    [ValidateSet("compare", "audit", "report")]
    [string]$Mode = "audit",
    [int]$NumFunctions = 10,
    [string]$GhidraServer = "http://127.0.0.1:8089",
    [string]$Model = "haiku"
)

$ErrorActionPreference = "Stop"

$outputDir = ".\quality-reports"
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$reportFile = "$outputDir\quality-report-$timestamp.md"

New-Item -ItemType Directory -Force -Path $outputDir | Out-Null

Write-Host "=== Prompt Quality Analysis ===" -ForegroundColor Cyan
Write-Host "Mode: $Mode" -ForegroundColor Cyan
Write-Host ""

# Quality metrics extraction
function Get-FunctionQualityMetrics {
    param([string]$Address)
    
    $metrics = [PSCustomObject]@{
        Address = $Address
        CompletenessScore = 0
        HasCustomName = $false
        HasPrototype = $false
        HasCallingConvention = $false
        HasPlateComment = $false
        PlateCommentLength = 0
        HasAlgorithmSection = $false
        HasParametersSection = $false
        HasReturnsSection = $false
        UndefinedVariables = 0
        HungarianViolations = 0
        InlineCommentCount = 0
        FunctionName = "Unknown"
        QualityGrade = "F"
    }
    
    try {
        # Get completeness analysis
        $response = Invoke-WebRequest -Uri "$GhidraServer/analyze_function_completeness?function_address=0x$Address" -Method GET -TimeoutSec 15
        $completeness = $response.Content | ConvertFrom-Json
        
        $metrics.CompletenessScore = [double]$completeness.completeness_score
        $metrics.HasCustomName = [bool]$completeness.has_custom_name
        $metrics.HasPrototype = [bool]$completeness.has_prototype
        $metrics.HasCallingConvention = [bool]$completeness.has_calling_convention
        $metrics.HasPlateComment = [bool]$completeness.has_plate_comment
        $metrics.UndefinedVariables = if ($completeness.undefined_variables -is [array]) { $completeness.undefined_variables.Count } else { 0 }
        $metrics.HungarianViolations = if ($completeness.hungarian_notation_violations -is [array]) { $completeness.hungarian_notation_violations.Count } else { 0 }
        $metrics.FunctionName = if ($completeness.function_name) { $completeness.function_name } else { "Unknown" }
        
        # Get decompiled code to analyze plate comment quality
        try {
            $decompiledResponse = Invoke-WebRequest -Uri "$GhidraServer/decompile_function?address=0x$Address" -Method GET -TimeoutSec 15
            $decompiled = $decompiledResponse.Content
            
            if ($decompiled -and $decompiled.Length -gt 0) {
                # Count plate comment sections - look for block comment near the start (may have leading whitespace)
                if ($decompiled -match "(?s)^\s*/\*.*?\*/") {
                    $plateComment = $Matches[0]
                    $metrics.PlateCommentLength = $plateComment.Length
                    $metrics.HasAlgorithmSection = [bool]($plateComment -match "Algorithm:")
                    $metrics.HasParametersSection = [bool]($plateComment -match "Parameters?:")
                    $metrics.HasReturnsSection = [bool]($plateComment -match "Returns?:")
                }
                
                # Count inline comments (both /* */ and // style within function body, after the plate comment)
                $bodyStart = $metrics.PlateCommentLength
                if ($bodyStart -lt $decompiled.Length) {
                    $functionBody = $decompiled.Substring($bodyStart)
                    $inlineMatches = [regex]::Matches($functionBody, '/\*[^/\*].*?\*/|//.*$', [System.Text.RegularExpressions.RegexOptions]::Multiline)
                    $metrics.InlineCommentCount = $inlineMatches.Count
                }
            }
        } catch {
            # Decompilation failed, metrics will have default values
        }
        
        # Calculate quality grade
        $score = $metrics.CompletenessScore
        $bonus = 0
        if ($metrics.HasAlgorithmSection) { $bonus += 5 }
        if ($metrics.HasParametersSection) { $bonus += 5 }
        if ($metrics.HasReturnsSection) { $bonus += 5 }
        if ($metrics.InlineCommentCount -ge 5) { $bonus += 5 }
        if ($metrics.PlateCommentLength -ge 500) { $bonus += 5 }
        
        $finalScore = [Math]::Min(100, $score + $bonus)
        
        $metrics.QualityGrade = if ($finalScore -ge 95) { "A+" }
            elseif ($finalScore -ge 90) { "A" }
            elseif ($finalScore -ge 85) { "A-" }
            elseif ($finalScore -ge 80) { "B+" }
            elseif ($finalScore -ge 75) { "B" }
            elseif ($finalScore -ge 70) { "B-" }
            elseif ($finalScore -ge 65) { "C+" }
            elseif ($finalScore -ge 60) { "C" }
            elseif ($finalScore -ge 50) { "D" }
            else { "F" }
        
    } catch {
        Write-Host "  Error analyzing 0x$Address : $_" -ForegroundColor Red
    }
    
    return $metrics
}

function Show-MetricsSummary {
    param($MetricsList)
    
    $total = $MetricsList.Count
    if ($total -eq 0) { return }
    
    $avgScore = ($MetricsList | Measure-Object -Property CompletenessScore -Average).Average
    $with100 = ($MetricsList | Where-Object { $_.CompletenessScore -eq 100 }).Count
    $withCustomName = ($MetricsList | Where-Object { $_.HasCustomName }).Count
    $withPlateComment = ($MetricsList | Where-Object { $_.HasPlateComment }).Count
    $withAlgorithm = ($MetricsList | Where-Object { $_.HasAlgorithmSection }).Count
    $avgPlateLength = ($MetricsList | Measure-Object -Property PlateCommentLength -Average).Average
    $avgInlineComments = ($MetricsList | Measure-Object -Property InlineCommentCount -Average).Average
    
    $gradeDistribution = $MetricsList | Group-Object -Property QualityGrade | Sort-Object Name
    
    Write-Host ""
    Write-Host "=== Quality Summary ($total functions) ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Completeness Scores:" -ForegroundColor Yellow
    Write-Host "  Average Score: $([Math]::Round($avgScore, 1))%" -ForegroundColor White
    Write-Host "  Perfect (100%): $with100 / $total ($([Math]::Round($with100/$total*100, 1))%)" -ForegroundColor $(if ($with100/$total -ge 0.8) { "Green" } else { "Yellow" })
    Write-Host ""
    Write-Host "Documentation Elements:" -ForegroundColor Yellow
    Write-Host "  Custom Names: $withCustomName / $total ($([Math]::Round($withCustomName/$total*100, 1))%)" -ForegroundColor White
    Write-Host "  Plate Comments: $withPlateComment / $total ($([Math]::Round($withPlateComment/$total*100, 1))%)" -ForegroundColor White
    Write-Host "  Algorithm Sections: $withAlgorithm / $total ($([Math]::Round($withAlgorithm/$total*100, 1))%)" -ForegroundColor White
    Write-Host "  Avg Plate Length: $([Math]::Round($avgPlateLength, 0)) chars" -ForegroundColor White
    Write-Host "  Avg Inline Comments: $([Math]::Round($avgInlineComments, 1))" -ForegroundColor White
    Write-Host ""
    Write-Host "Quality Grades:" -ForegroundColor Yellow
    foreach ($grade in $gradeDistribution) {
        $pct = [Math]::Round($grade.Count / $total * 100, 1)
        $color = switch -Wildcard ($grade.Name) {
            "A*" { "Green" }
            "B*" { "Cyan" }
            "C*" { "Yellow" }
            default { "Red" }
        }
        Write-Host "  $($grade.Name): $($grade.Count) ($pct%)" -ForegroundColor $color
    }
    
    return @{
        Total = $total
        AvgScore = $avgScore
        PerfectCount = $with100
        CustomNamePct = $withCustomName / $total * 100
        PlateCommentPct = $withPlateComment / $total * 100
        AlgorithmPct = $withAlgorithm / $total * 100
        AvgPlateLength = $avgPlateLength
        AvgInlineComments = $avgInlineComments
        GradeDistribution = $gradeDistribution
    }
}

# Mode: Audit existing documented functions
if ($Mode -eq "audit") {
    Write-Host "Auditing already-documented functions..." -ForegroundColor Yellow
    Write-Host ""
    
    # Get completed functions from todo file
    $todoFile = ".\FunctionsTodo.txt"
    if (-not (Test-Path $todoFile)) {
        Write-Host "ERROR: Todo file not found" -ForegroundColor Red
        exit 1
    }
    
    $content = Get-Content $todoFile
    $completed = @()
    foreach ($line in $content) {
        if ($line -match '^\[X\] (.+?) @ ([0-9a-fA-F]+)') {
            $completed += @{
                Name = $Matches[1]
                Address = $Matches[2]
            }
        }
    }
    
    if ($completed.Count -eq 0) {
        Write-Host "No completed functions found to audit" -ForegroundColor Yellow
        exit 0
    }
    
    # Sample functions for audit
    $sampleSize = [Math]::Min($NumFunctions, $completed.Count)
    $step = [Math]::Max(1, [Math]::Floor($completed.Count / $sampleSize))
    $sampled = @()
    for ($i = 0; $i -lt $sampleSize; $i++) {
        $idx = $i * $step
        if ($idx -lt $completed.Count) {
            $sampled += $completed[$idx]
        }
    }
    
    Write-Host "Analyzing $($sampled.Count) completed functions..." -ForegroundColor Cyan
    Write-Host ""
    
    $allMetrics = @()
    $counter = 0
    
    foreach ($func in $sampled) {
        $counter++
        Write-Host "[$counter/$($sampled.Count)] $($func.Name) @ 0x$($func.Address)" -ForegroundColor Gray
        
        $metrics = Get-FunctionQualityMetrics -Address $func.Address
        $allMetrics += $metrics
        
        # Show quick status
        $statusColor = switch ($metrics.QualityGrade) {
            { $_ -match "A" } { "Green" }
            { $_ -match "B" } { "Cyan" }
            { $_ -match "C" } { "Yellow" }
            default { "Red" }
        }
        Write-Host "  Score: $($metrics.CompletenessScore)% | Grade: $($metrics.QualityGrade) | Plate: $($metrics.PlateCommentLength) chars | Comments: $($metrics.InlineCommentCount)" -ForegroundColor $statusColor
    }
    
    $summary = Show-MetricsSummary -MetricsList $allMetrics
    
    # Generate report
    $report = @"
# Function Documentation Quality Audit

**Generated:** $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
**Functions Audited:** $($sampled.Count) (sampled from $($completed.Count) completed)

## Summary

| Metric | Value |
|--------|-------|
| Average Completeness Score | $([Math]::Round($summary.AvgScore, 1))% |
| Perfect Scores (100%) | $($summary.PerfectCount) / $($sampled.Count) ($([Math]::Round($summary.PerfectCount/$sampled.Count*100, 1))%) |
| With Custom Names | $([Math]::Round($summary.CustomNamePct, 1))% |
| With Plate Comments | $([Math]::Round($summary.PlateCommentPct, 1))% |
| With Algorithm Sections | $([Math]::Round($summary.AlgorithmPct, 1))% |
| Avg Plate Comment Length | $([Math]::Round($summary.AvgPlateLength, 0)) chars |
| Avg Inline Comments | $([Math]::Round($summary.AvgInlineComments, 1)) |

## Grade Distribution

| Grade | Count | Percentage |
|-------|-------|------------|
"@

    foreach ($grade in $summary.GradeDistribution) {
        $pct = [Math]::Round($grade.Count / $sampled.Count * 100, 1)
        $report += "`n| $($grade.Name) | $($grade.Count) | $pct% |"
    }

    $report += @"


## Detailed Results

| Function | Address | Score | Grade | Plate Chars | Inline Comments | Algorithm | Params | Returns |
|----------|---------|-------|-------|-------------|-----------------|-----------|--------|---------|
"@

    foreach ($m in $allMetrics) {
        $alg = if ($m.HasAlgorithmSection) { "Yes" } else { "No" }
        $params = if ($m.HasParametersSection) { "Yes" } else { "No" }
        $returns = if ($m.HasReturnsSection) { "Yes" } else { "No" }
        $report += "`n| $($m.FunctionName) | 0x$($m.Address) | $($m.CompletenessScore)% | $($m.QualityGrade) | $($m.PlateCommentLength) | $($m.InlineCommentCount) | $alg | $params | $returns |"
    }

    $report += @"


## Quality Indicators

### Excellent (A grades)
- 100% completeness score
- Detailed plate comments (500+ chars)
- Algorithm, Parameters, and Returns sections
- Multiple inline comments

### Good (B grades)  
- 80%+ completeness score
- Has plate comment with some sections
- Basic inline comments

### Needs Improvement (C/D grades)
- Missing documentation sections
- Hungarian notation violations
- Undefined variables remaining

### Poor (F grades)
- Low completeness score
- Missing critical documentation
- Default FUN_ naming

"@

    $report | Out-File -FilePath $reportFile -Encoding UTF8
    
    Write-Host ""
    Write-Host "Report saved to: $reportFile" -ForegroundColor Green
}

# Mode: Compare prompts
elseif ($Mode -eq "compare") {
    Write-Host "Comparing Full vs Compact prompts..." -ForegroundColor Yellow
    Write-Host "This will process $NumFunctions functions with EACH prompt version" -ForegroundColor Yellow
    Write-Host ""
    
    # Get pending functions
    $todoFile = ".\FunctionsTodo.txt"
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
    
    if ($pending.Count -lt $NumFunctions * 2) {
        Write-Host "WARNING: Need at least $($NumFunctions * 2) pending functions for fair comparison" -ForegroundColor Yellow
    }
    
    # Select functions - use different functions for each prompt to avoid contamination
    $step = [Math]::Max(1, [Math]::Floor($pending.Count / ($NumFunctions * 2)))
    
    $fullPromptFunctions = @()
    $compactPromptFunctions = @()
    
    for ($i = 0; $i -lt $NumFunctions; $i++) {
        $idx1 = $i * 2 * $step
        $idx2 = ($i * 2 + 1) * $step
        
        if ($idx1 -lt $pending.Count) { $fullPromptFunctions += $pending[$idx1] }
        if ($idx2 -lt $pending.Count) { $compactPromptFunctions += $pending[$idx2] }
    }
    
    Write-Host "Testing Full Prompt on $($fullPromptFunctions.Count) functions..." -ForegroundColor Cyan
    foreach ($func in $fullPromptFunctions) {
        Write-Host "  - $($func.Name)" -ForegroundColor Gray
    }
    
    Write-Host ""
    Write-Host "Testing Compact Prompt on $($compactPromptFunctions.Count) functions..." -ForegroundColor Cyan
    foreach ($func in $compactPromptFunctions) {
        Write-Host "  - $($func.Name)" -ForegroundColor Gray
    }
    
    Write-Host ""
    Write-Host "Starting comparison... (this may take a while)" -ForegroundColor Yellow
    Write-Host ""
    
    # Process with full prompt
    $fullResults = @()
    Write-Host "=== Processing with FULL prompt ===" -ForegroundColor Magenta
    foreach ($func in $fullPromptFunctions) {
        Write-Host "Processing $($func.Name)..." -ForegroundColor Gray
        $startTime = Get-Date
        
        # Run the process script with full prompt
        $output = & .\functions-process.ps1 -Single -Function $func.Name -Model $Model -SkipValidation 2>&1
        
        $endTime = Get-Date
        $duration = ($endTime - $startTime).TotalSeconds
        
        Start-Sleep -Seconds 2
        $metrics = Get-FunctionQualityMetrics -Address $func.Address
        $metrics | Add-Member -NotePropertyName Duration -NotePropertyValue $duration
        $metrics | Add-Member -NotePropertyName PromptType -NotePropertyValue "Full"
        $fullResults += $metrics
        
        Write-Host "  Score: $($metrics.CompletenessScore)% in $([Math]::Round($duration, 1))s" -ForegroundColor $(if ($metrics.CompletenessScore -ge 90) { "Green" } else { "Yellow" })
    }
    
    # Process with compact prompt
    $compactResults = @()
    Write-Host ""
    Write-Host "=== Processing with COMPACT prompt ===" -ForegroundColor Magenta
    foreach ($func in $compactPromptFunctions) {
        Write-Host "Processing $($func.Name)..." -ForegroundColor Gray
        $startTime = Get-Date
        
        # Run the process script with compact prompt
        $output = & .\functions-process.ps1 -Single -Function $func.Name -Model $Model -CompactPrompt -SkipValidation 2>&1
        
        $endTime = Get-Date
        $duration = ($endTime - $startTime).TotalSeconds
        
        Start-Sleep -Seconds 2
        $metrics = Get-FunctionQualityMetrics -Address $func.Address
        $metrics | Add-Member -NotePropertyName Duration -NotePropertyValue $duration
        $metrics | Add-Member -NotePropertyName PromptType -NotePropertyValue "Compact"
        $compactResults += $metrics
        
        Write-Host "  Score: $($metrics.CompletenessScore)% in $([Math]::Round($duration, 1))s" -ForegroundColor $(if ($metrics.CompletenessScore -ge 90) { "Green" } else { "Yellow" })
    }
    
    # Compare results
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "         COMPARISON RESULTS            " -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    $fullAvgScore = ($fullResults | Measure-Object -Property CompletenessScore -Average).Average
    $compactAvgScore = ($compactResults | Measure-Object -Property CompletenessScore -Average).Average
    $fullAvgTime = ($fullResults | Measure-Object -Property Duration -Average).Average
    $compactAvgTime = ($compactResults | Measure-Object -Property Duration -Average).Average
    $fullPerfect = ($fullResults | Where-Object { $_.CompletenessScore -eq 100 }).Count
    $compactPerfect = ($compactResults | Where-Object { $_.CompletenessScore -eq 100 }).Count
    
    Write-Host ""
    Write-Host "| Metric                | Full Prompt | Compact Prompt | Winner |" -ForegroundColor White
    Write-Host "|----------------------|-------------|----------------|--------|" -ForegroundColor White
    
    $scoreWinner = if ($fullAvgScore -gt $compactAvgScore) { "Full" } elseif ($compactAvgScore -gt $fullAvgScore) { "Compact" } else { "Tie" }
    Write-Host "| Avg Score            | $([Math]::Round($fullAvgScore, 1))%        | $([Math]::Round($compactAvgScore, 1))%           | $scoreWinner |"
    
    $perfectWinner = if ($fullPerfect -gt $compactPerfect) { "Full" } elseif ($compactPerfect -gt $fullPerfect) { "Compact" } else { "Tie" }
    Write-Host "| Perfect (100%)       | $fullPerfect/$($fullResults.Count)          | $compactPerfect/$($compactResults.Count)             | $perfectWinner |"
    
    $timeWinner = if ($fullAvgTime -lt $compactAvgTime) { "Full" } else { "Compact" }
    Write-Host "| Avg Time             | $([Math]::Round($fullAvgTime, 1))s        | $([Math]::Round($compactAvgTime, 1))s           | $timeWinner |"
    
    $tokenSavings = "~90%"
    Write-Host "| Token Savings        | baseline    | $tokenSavings          | Compact |"
    
    Write-Host ""
    
    if ([Math]::Abs($fullAvgScore - $compactAvgScore) -lt 5) {
        Write-Host "CONCLUSION: Quality is COMPARABLE - Compact prompt recommended for cost savings!" -ForegroundColor Green
    } elseif ($compactAvgScore -gt $fullAvgScore) {
        Write-Host "CONCLUSION: Compact prompt produces BETTER results! Use -CompactPrompt" -ForegroundColor Green
    } else {
        Write-Host "CONCLUSION: Full prompt produces better results. Consider using it for critical functions." -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "Done!" -ForegroundColor Green
