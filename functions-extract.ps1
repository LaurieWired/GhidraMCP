# PowerShell script to extract Ghidra functions via REST API and format for todo list
param(
    [string]$ProgramName = "Game.exe",
    [string]$OutputFile = "",
    [string]$GhidraUrl = "http://127.0.0.1:8089",
    [int]$BatchSize = 1000,
    [switch]$FunOnly,
    [switch]$OrdinalsOnly,
    [switch]$All,
    [switch]$UndocumentedOnly,
    [int]$MinCompletenessScore = 80,
    [switch]$ExcludeLibraryFunctions,
    [switch]$IncludeOnlyLibraryFunctions,
    [switch]$IncludeThunks,
    [switch]$IncludeExternals,
    [switch]$Preview,
    [switch]$Help
)

# Auto-generate output file name if not provided
if ([string]::IsNullOrEmpty($OutputFile)) {
    $OutputFile = "FunctionsTodo.txt"
}

function Show-Help {
    Write-Host @"
GHIDRA FUNCTION EXTRACTOR - REST API VERSION
============================================

USAGE:
    .\functions-extract.ps1 [OPTIONS]

OPTIONS:
    -ProgramName <name>   Program name (default: Game.exe)
    -OutputFile <file>    Output file path (default: auto-generated from program name)
    -GhidraUrl <url>      Ghidra REST API URL (default: http://127.0.0.1:8089)
    -BatchSize <number>   Functions per batch request (default: 1000)
    -FunOnly              Extract ONLY functions starting with FUN_ prefix (unnamed/auto-generated)
    -OrdinalsOnly         Extract ONLY functions starting with Ordinal_ prefix
    -All                  Include ALL functions (including named functions, ignores prefix filtering)
    -UndocumentedOnly     Filter to only include functions needing documentation
    -MinCompletenessScore Minimum completeness score to exclude (default: 50, range: 0-100)
    -ExcludeLibraryFunctions  Exclude library functions (starting with ___, __, or _)
    -IncludeOnlyLibraryFunctions  Include ONLY library functions (starting with ___, __, or _)
    -IncludeThunks        Include thunk functions (excluded by default)
    -IncludeExternals     Include external/imported function pointers (excluded by default)
    -Preview              Show preview without writing file
    -Help                 Show this help message

EXAMPLES:
    .\functions-extract.ps1
    .\functions-extract.ps1 -ProgramName "Game.exe"
    .\functions-extract.ps1 -ProgramName "Server.exe" -Preview
    .\functions-extract.ps1 -ProgramName "Client.exe" -OutputFile "ClientTodo.txt"
    .\functions-extract.ps1 -GhidraUrl "http://localhost:8089"
    .\functions-extract.ps1 -FunOnly
    .\functions-extract.ps1 -OrdinalsOnly
    .\functions-extract.ps1 -All
    .\functions-extract.ps1 -All -ExcludeLibraryFunctions
    .\functions-extract.ps1 -UndocumentedOnly
    .\functions-extract.ps1 -UndocumentedOnly -MinCompletenessScore 60
    .\functions-extract.ps1 -ExcludeLibraryFunctions
    .\functions-extract.ps1 -IncludeOnlyLibraryFunctions
    .\functions-extract.ps1 -IncludeThunks -IncludeExternals

DESCRIPTION:
    Extracts functions from Ghidra using REST API calls for the specified program.
    By default, only FUN_ and Ordinal_ prefixed functions are included (undocumented functions).
    Thunk functions and external/imported function pointers are excluded by default.
    Use -FunOnly or -OrdinalsOnly to filter to a specific prefix type.
    Use -All to get all functions including named functions (ignores prefix filtering).
    Use -UndocumentedOnly to filter for functions that need documentation (completeness score < threshold).
    Use -ExcludeLibraryFunctions to filter out library functions (starting with _, __, or ___).
    Use -IncludeOnlyLibraryFunctions to include ONLY library functions (starting with _, __, or ___).
    Use -IncludeThunks to include thunk functions (jump stubs to other functions).
    Use -IncludeExternals to include external/imported function pointers.
    Functions are formatted as "[ ] FUN_035b14f0 @ 035b14f0" or "[ ] Ordinal_123 @ 035b14f0" for todo tracking.
"@
    exit 0
}

if ($Help) {
    Show-Help
}

# Validate conflicting parameters
if ($FunOnly -and $OrdinalsOnly) {
    Write-Host "ERROR: Cannot specify both -FunOnly and -OrdinalsOnly" -ForegroundColor Red
    Write-Host "Use -FunOnly for FUN_ functions only, -OrdinalsOnly for Ordinal_ functions only, or neither for both types." -ForegroundColor Yellow
    exit 1
}

if ($All -and $UndocumentedOnly) {
    Write-Host "ERROR: Cannot specify both -All and -UndocumentedOnly" -ForegroundColor Red
    Write-Host "Use -All to get all functions, or -UndocumentedOnly to filter by completeness score." -ForegroundColor Yellow
    exit 1
}

if ($ExcludeLibraryFunctions -and $IncludeOnlyLibraryFunctions) {
    Write-Host "ERROR: Cannot specify both -ExcludeLibraryFunctions and -IncludeOnlyLibraryFunctions" -ForegroundColor Red
    Write-Host "Use -ExcludeLibraryFunctions to exclude library functions, or -IncludeOnlyLibraryFunctions to include only library functions." -ForegroundColor Yellow
    exit 1
}

Write-Host "GHIDRA FUNCTION EXTRACTOR - REST API VERSION" -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Green
Write-Host "Output file: $OutputFile"
Write-Host "Ghidra URL: $GhidraUrl"
Write-Host "Batch size: $BatchSize"
if ($FunOnly) {
    Write-Host "Function filter: FUN_ only" -ForegroundColor Yellow
} elseif ($OrdinalsOnly) {
    Write-Host "Function filter: Ordinals only" -ForegroundColor Yellow
} elseif ($All) {
    Write-Host "Function filter: ALL functions (including named)" -ForegroundColor Cyan
} else {
    Write-Host "Function filter: FUN_ and Ordinal_ only (default)" -ForegroundColor Cyan
}
if ($ExcludeLibraryFunctions) {
    Write-Host "Library functions: EXCLUDED (_, __, ___)" -ForegroundColor Yellow
}
if ($IncludeOnlyLibraryFunctions) {
    Write-Host "Library functions: ONLY INCLUDED (_, __, ___)" -ForegroundColor Yellow
}
if (-not $IncludeThunks) {
    Write-Host "Thunk functions: EXCLUDED (default)" -ForegroundColor Cyan
} else {
    Write-Host "Thunk functions: INCLUDED" -ForegroundColor Yellow
}
if (-not $IncludeExternals) {
    Write-Host "External functions: EXCLUDED (default)" -ForegroundColor Cyan
} else {
    Write-Host "External functions: INCLUDED" -ForegroundColor Yellow
}
if ($All) {
    Write-Host "Documentation filter: ALL FUNCTIONS (no completeness filtering)" -ForegroundColor Cyan
} elseif ($UndocumentedOnly) {
    Write-Host "Documentation filter: Undocumented only" -ForegroundColor Yellow
    Write-Host "Min completeness score: $MinCompletenessScore" -ForegroundColor Yellow
} else {
    Write-Host "Documentation filter: All functions (default)" -ForegroundColor Cyan
}
Write-Host ""

$allFunctions = @()
$offset = 0
$totalFetched = 0
$filteredCount = 0
$libraryFunctionsFiltered = 0
$thunkFunctionsFiltered = 0
$externalFunctionsFiltered = 0
$listFunctionsUrl = "$GhidraUrl/list_functions_enhanced"
$completenessApiUrl = "$GhidraUrl/analyze_function_completeness"

try {
    Write-Host "Fetching functions from Ghidra..." -ForegroundColor Blue
    
    # Make single REST API call - list_functions_enhanced returns JSON with thunk/external flags
    $requestUrl = "$listFunctionsUrl"
    
    # Make REST API call
    $response = Invoke-WebRequest -Uri $requestUrl -Method GET -TimeoutSec 60
    
    if ($response.StatusCode -eq 200) {
        $content = $response.Content
        Write-Host "Response length: $($content.Length) characters" -ForegroundColor Cyan
        
        # Parse JSON response
        $jsonResponse = $content | ConvertFrom-Json
        
        if ($jsonResponse.error) {
            Write-Host "ERROR: $($jsonResponse.error)" -ForegroundColor Red
            exit 1
        }
        
        $functions = $jsonResponse.functions
        Write-Host "Total functions received: $($functions.Count)" -ForegroundColor Cyan
        
        foreach ($func in $functions) {
            $funcName = $func.name
            $address = $func.address -replace '^0x', ''  # Remove 0x prefix if present
            $isThunk = $func.isThunk
            $isExternal = $func.isExternal
            
            # Filter thunk functions (excluded by default)
            if ($isThunk -and -not $IncludeThunks) {
                $thunkFunctionsFiltered++
                continue
            }
            
            # Filter external functions (excluded by default)
            if ($isExternal -and -not $IncludeExternals) {
                $externalFunctionsFiltered++
                continue
            }
            
            # Apply function type filtering
            if ($FunOnly) {
                # Only include functions that start with FUN_
                if (-not ($funcName -like "FUN_*")) {
                    continue
                }
            } elseif ($OrdinalsOnly) {
                # Only include functions that start with Ordinal_
                if (-not ($funcName -like "Ordinal_*")) {
                    continue
                }
            } elseif (-not $All) {
                # Default: Only include FUN_ and Ordinal_ prefixed functions
                if (-not (($funcName -like "FUN_*") -or ($funcName -like "Ordinal_*"))) {
                    continue
                }
            }
            # -All flag: include all functions (no prefix filtering)
            
            # Filter library functions if requested
            if ($ExcludeLibraryFunctions) {
                # Check if function name starts with ___, __, or _
                if ($funcName -match '^_+') {
                    $libraryFunctionsFiltered++
                    continue
                }
            }
            
            # Include only library functions if requested
            if ($IncludeOnlyLibraryFunctions) {
                # Check if function name starts with ___, __, or _
                if (-not ($funcName -match '^_+')) {
                    continue
                }
            }
            
            # Check documentation completeness if -UndocumentedOnly is specified
            # Skip completeness check if -All is specified
            $includeFunction = $true
            if ($UndocumentedOnly -and -not $All) {
                try {
                    $completenessUrl = "$completenessApiUrl`?function_address=0x$address"
                    $completenessResponse = Invoke-RestMethod -Uri $completenessUrl -Method GET -TimeoutSec 10
                    
                    if ($completenessResponse -and $null -ne $completenessResponse.completeness_score) {
                        $score = [int]$completenessResponse.completeness_score
                        
                        # Adjust score: Ordinal_XXX and FUN_XXX are both "default names"
                        # Treat Ordinal_ names as needing documentation like FUN_ names
                        $hasRealName = $completenessResponse.has_custom_name -and 
                                       -not ($funcName -match '^(FUN_|Ordinal_)')
                        
                        # If it's a default name (FUN_ or Ordinal_), subtract 25 points
                        # This makes Ordinal_XXX and FUN_XXX equivalent in scoring
                        if (-not $hasRealName -and $completenessResponse.has_custom_name) {
                            $score = $score - 25
                            Write-Host "  Adjusted score for $funcName : $score (default name penalty)" -ForegroundColor DarkYellow
                        }
                        
                        if ($score -ge $MinCompletenessScore) {
                            $includeFunction = $false
                            $filteredCount++
                            Write-Host "  Filtered $funcName (score: $score >= $MinCompletenessScore)" -ForegroundColor DarkGray
                        } else {
                            Write-Host "  Include $funcName (score: $score < $MinCompletenessScore)" -ForegroundColor Cyan
                        }
                    }
                } catch {
                    Write-Host "  Warning: Could not check completeness for $funcName : $($_.Exception.Message)" -ForegroundColor Yellow
                    # Include function if completeness check fails
                }
            }
            
            if ($includeFunction) {
                $allFunctions += "[ ] $funcName @ $address"
                $totalFetched++
            }
        }
        
        Write-Host "Processed $($functions.Count) functions, found $totalFetched matching functions" -ForegroundColor Green
        if ($thunkFunctionsFiltered -gt 0) {
            Write-Host "  Filtered $thunkFunctionsFiltered thunk functions" -ForegroundColor DarkGray
        }
        if ($externalFunctionsFiltered -gt 0) {
            Write-Host "  Filtered $externalFunctionsFiltered external functions" -ForegroundColor DarkGray
        }
        if ($libraryFunctionsFiltered -gt 0) {
            Write-Host "  Filtered $libraryFunctionsFiltered library functions" -ForegroundColor DarkGray
        }
    } else {
        Write-Host "ERROR: HTTP $($response.StatusCode) - $($response.StatusDescription)" -ForegroundColor Red
    }
        
} catch {
    Write-Host "ERROR: Exception occurred: $($_.Exception.Message)" -ForegroundColor Red
    
    if ($_.Exception.InnerException) {
        Write-Host "Inner Exception: $($_.Exception.InnerException.Message)" -ForegroundColor Red
    }
    
    # Check if it's a connection error
    if ($_.Exception.Message -like "*Unable to connect*" -or $_.Exception.Message -like "*refused*") {
        Write-Host ""
        Write-Host "TROUBLESHOOTING:" -ForegroundColor Yellow
        Write-Host "1. Make sure Ghidra is running with REST API enabled"
        Write-Host "2. Verify the URL: $GhidraUrl"
        Write-Host "3. Check if port 8089 is accessible"
        Write-Host "4. Try: Test-NetConnection -ComputerName 127.0.0.1 -Port 8089"
    }
}

Write-Host ""
Write-Host "WRITING RESULTS..." -ForegroundColor Green

if ($allFunctions.Count -gt 0) {
    if ($Preview) {
        Write-Host "PREVIEW MODE - First 10 functions:" -ForegroundColor Cyan
        $allFunctions | Select-Object -First 10 | ForEach-Object { Write-Host "  $_" }
        if ($allFunctions.Count -gt 10) {
            Write-Host "  ... and $($allFunctions.Count - 10) more functions"
        }
    } else {
        Write-Host "Writing $($allFunctions.Count) functions to $OutputFile..." -ForegroundColor Green
        
        # Create header for the file
        $functionType = if ($FunOnly) { "FUN_ functions only" } elseif ($OrdinalsOnly) { "Ordinal_ functions only" } else { "FUN_ and Ordinal_ functions" }
        $filterNote = if ($All) { " (all functions)" } elseif ($UndocumentedOnly) { " (completeness < $MinCompletenessScore)" } else { "" }
        $libraryNote = if ($ExcludeLibraryFunctions) { " (excluding library functions)" } else { "" }
        $header = @(
            "# $ProgramName Function Todo List"
            "# Format: [ ] FUN_address @ address $(if (-not $FunOnly) { 'or [ ] Ordinal_number @ address' })"
            "# Generated by functions-extract.ps1 on $(Get-Date)"
            "# Total functions: $($allFunctions.Count) ($functionType$filterNote$libraryNote)"
            $(if ($UndocumentedOnly) { "# Filtered out: $filteredCount functions (completeness >= $MinCompletenessScore)" })
            $(if ($ExcludeLibraryFunctions) { "# Filtered out: $libraryFunctionsFiltered library functions (_, __, ___)" })
            "#"
            ""
        )
        
        # Write to file
        ($header + $allFunctions) | Out-File -FilePath $OutputFile -Encoding UTF8
        
        Write-Host "SUCCESS! $($allFunctions.Count) functions written to $OutputFile" -ForegroundColor Green
    }
} else {
    Write-Host "No functions found to write" -ForegroundColor Yellow
    
    if (-not $Preview) {
        # Create empty file with header
        $functionType = if ($FunOnly) { "FUN_ functions only" } elseif ($OrdinalsOnly) { "Ordinal_ functions only" } else { "FUN_ and Ordinal_ functions" }
        $filterNote = if ($All) { " (all functions)" } elseif ($UndocumentedOnly) { " (completeness < $MinCompletenessScore)" } else { "" }
        $libraryNote = if ($ExcludeLibraryFunctions) { " (excluding library functions)" } else { "" }
        $header = @(
            "# $ProgramName Function Todo List"
            "# Format: [ ] FUN_address @ address $(if (-not $FunOnly) { 'or [ ] Ordinal_number @ address' })"
            "# Generated by functions-extract.ps1 on $(Get-Date)"
            "# No functions found ($functionType filter$filterNote$libraryNote)"
            "#"
            ""
        )
        $header | Out-File -FilePath $OutputFile -Encoding UTF8
    }
}

Write-Host ""
Write-Host "STATISTICS:" -ForegroundColor Green
Write-Host "  Total functions found: $($allFunctions.Count)"
if ($ExcludeLibraryFunctions) {
    Write-Host "  Filtered out (library functions): $libraryFunctionsFiltered" -ForegroundColor Cyan
}
if ($UndocumentedOnly) {
    Write-Host "  Filtered out (well-documented): $filteredCount" -ForegroundColor Cyan
}
Write-Host "  Output file: $OutputFile"
if (Test-Path $OutputFile) {
    $fileSize = (Get-Item $OutputFile).Length
    Write-Host "  File size: $fileSize bytes"
}

Write-Host ""
Write-Host "EXTRACTION COMPLETE!" -ForegroundColor Green