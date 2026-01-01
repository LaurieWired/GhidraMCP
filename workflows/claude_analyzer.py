#!/usr/bin/env python3
"""
Claude Integration for Automated Function Analysis

This module provides integration with Claude API for automated reverse engineering
analysis. It can analyze decompiled code, suggest function names, infer types,
and generate documentation comments.

Usage:
    from workflows.claude_analyzer import ClaudeAnalyzer

    analyzer = ClaudeAnalyzer()
    result = analyzer.analyze_function(decompiled_code, context)

    # Apply suggestions
    loop.apply_documentation(
        func_address=address,
        new_name=result["suggested_name"],
        prototype=result["prototype"],
        plate_comment=result["plate_comment"],
        variable_types=result["variable_types"]
    )

Environment:
    ANTHROPIC_API_KEY: API key for Claude (required)
    CLAUDE_MODEL: Model to use (default: claude-sonnet-4-20250514)
"""

import os
import json
import logging
import re
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

# Setup logging
LOG_DIR = Path(__file__).parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

logger = logging.getLogger('claude_analyzer')
logger.setLevel(logging.INFO)

if not logger.handlers:
    file_handler = logging.FileHandler(
        LOG_DIR / f"claude_analyzer_{datetime.now().strftime('%Y%m%d')}.log",
        encoding='utf-8'
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    logger.addHandler(file_handler)


# Default model - using claude-sonnet-4-20250514 for good balance of speed and quality
DEFAULT_MODEL = "claude-sonnet-4-20250514"

# Analysis prompt template
ANALYSIS_PROMPT = """You are an expert reverse engineer analyzing decompiled code from a game binary.
Analyze this function and provide structured documentation.

## Function Context
- Current Name: {func_name}
- Address: {func_address}
- Calling Convention: {calling_convention}

## Decompiled Code
```c
{decompiled_code}
```

## Assembly (if available)
```asm
{disassembly}
```

## Call Graph
- Calls (callees): {callees}
- Called by (callers): {callers}

## Current Variables
{variables}

## Analysis Instructions

1. **Function Purpose**: What does this function do? Consider:
   - Algorithm or logic pattern
   - Side effects (memory writes, state changes)
   - Return value meaning

2. **Suggested Name**: Provide a PascalCase name that describes the function's purpose.
   - Format: VerbNoun (e.g., ProcessPlayerSlots, ValidateBuffer, InitializeState)
   - Be specific but concise

3. **Prototype**: Suggest the complete C function prototype with:
   - Return type (use specific types, not void* where possible)
   - Parameter types and Hungarian notation names
   - Calling convention if non-default

4. **Variable Types**: For each variable, suggest:
   - Appropriate C type (DWORD, BYTE, pointer, etc.)
   - Hungarian notation name (dwFlags, pBuffer, nCount, fEnabled)

5. **Plate Comment**: Write a brief documentation comment (3-5 lines) including:
   - One-line summary
   - Algorithm description (if non-trivial)
   - Parameters (brief)
   - Return value meaning

## Output Format
Respond with ONLY a JSON object in this exact format:
```json
{{
    "purpose": "Brief description of what the function does",
    "suggested_name": "PascalCaseName",
    "confidence": 0.85,
    "prototype": "ReturnType FunctionName(Type1 param1, Type2 param2)",
    "calling_convention": "__cdecl",
    "variable_types": {{
        "local_8": "DWORD",
        "param_1": "void*"
    }},
    "variable_names": {{
        "local_8": "dwIndex",
        "param_1": "pData"
    }},
    "plate_comment": "Brief summary of function purpose.\\nAlgorithm: Description of how it works.\\nReturns: What the return value means.",
    "reasoning": "Brief explanation of why you made these choices"
}}
```
"""


@dataclass
class AnalysisResult:
    """Result of Claude's function analysis."""
    purpose: str = ""
    suggested_name: str = ""
    confidence: float = 0.0
    prototype: str = ""
    calling_convention: str = "__cdecl"
    variable_types: Dict[str, str] = field(default_factory=dict)
    variable_names: Dict[str, str] = field(default_factory=dict)
    plate_comment: str = ""
    reasoning: str = ""
    raw_response: str = ""
    error: Optional[str] = None
    tokens_used: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "purpose": self.purpose,
            "suggested_name": self.suggested_name,
            "confidence": self.confidence,
            "prototype": self.prototype,
            "calling_convention": self.calling_convention,
            "variable_types": self.variable_types,
            "variable_names": self.variable_names,
            "plate_comment": self.plate_comment,
            "reasoning": self.reasoning,
            "error": self.error,
            "tokens_used": self.tokens_used
        }


class ClaudeAnalyzer:
    """
    Claude-powered function analyzer for reverse engineering.

    This class provides automated analysis of decompiled functions using
    Claude's language model. It can suggest function names, types, and
    documentation based on code patterns and context.
    """

    def __init__(self, api_key: str = None, model: str = None):
        """
        Initialize the Claude analyzer.

        Args:
            api_key: Anthropic API key (defaults to ANTHROPIC_API_KEY env var)
            model: Model to use (defaults to claude-sonnet-4-20250514)
        """
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self.model = model or os.environ.get("CLAUDE_MODEL", DEFAULT_MODEL)
        self._client = None
        self._stats = {
            "analyses_performed": 0,
            "total_tokens": 0,
            "errors": 0,
            "avg_confidence": 0.0
        }

        if not self.api_key:
            logger.warning("No ANTHROPIC_API_KEY found - Claude analysis will be unavailable")

    @property
    def client(self):
        """Lazy-load the Anthropic client."""
        if self._client is None:
            try:
                import anthropic
                self._client = anthropic.Anthropic(api_key=self.api_key)
                logger.info(f"Anthropic client initialized with model {self.model}")
            except ImportError:
                logger.error("anthropic package not installed. Run: pip install anthropic")
                raise ImportError("anthropic package required. Run: pip install anthropic")
        return self._client

    def is_available(self) -> bool:
        """Check if Claude analysis is available."""
        if not self.api_key:
            return False
        try:
            import anthropic
            return True
        except ImportError:
            return False

    def analyze_function(
        self,
        decompiled_code: str,
        func_name: str = "FUN_unknown",
        func_address: str = "0x0",
        calling_convention: str = "__cdecl",
        disassembly: str = "",
        callees: str = "",
        callers: str = "",
        variables: str = "",
        max_tokens: int = 2000
    ) -> AnalysisResult:
        """
        Analyze a decompiled function and suggest documentation.

        Args:
            decompiled_code: The decompiled C pseudocode
            func_name: Current function name
            func_address: Function address
            calling_convention: Current calling convention
            disassembly: Optional assembly listing
            callees: Functions this function calls
            callers: Functions that call this function
            variables: Current variable information
            max_tokens: Maximum response tokens

        Returns:
            AnalysisResult with suggested documentation
        """
        if not self.is_available():
            return AnalysisResult(error="Claude API not available (no API key or anthropic package)")

        # Format the prompt
        prompt = ANALYSIS_PROMPT.format(
            func_name=func_name,
            func_address=func_address,
            calling_convention=calling_convention,
            decompiled_code=decompiled_code,
            disassembly=disassembly or "(not provided)",
            callees=callees or "(none)",
            callers=callers or "(none)",
            variables=variables or "(none)"
        )

        logger.info(f"Analyzing function {func_name} @ {func_address}")

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )

            # Extract response text
            raw_response = response.content[0].text
            tokens_used = response.usage.input_tokens + response.usage.output_tokens

            # Parse JSON from response
            result = self._parse_response(raw_response)
            result.raw_response = raw_response
            result.tokens_used = tokens_used

            # Update stats
            self._stats["analyses_performed"] += 1
            self._stats["total_tokens"] += tokens_used
            if result.confidence > 0:
                # Running average
                n = self._stats["analyses_performed"]
                self._stats["avg_confidence"] = (
                    (self._stats["avg_confidence"] * (n - 1) + result.confidence) / n
                )

            logger.info(f"Analysis complete: {result.suggested_name} (confidence: {result.confidence})")
            return result

        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            self._stats["errors"] += 1
            return AnalysisResult(error=str(e))

    def _parse_response(self, response_text: str) -> AnalysisResult:
        """Parse Claude's JSON response into an AnalysisResult."""
        result = AnalysisResult()

        # Try to extract JSON from the response
        # Claude sometimes wraps JSON in markdown code blocks
        json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', response_text, re.DOTALL)
        if json_match:
            json_str = json_match.group(1)
        else:
            # Try to find raw JSON
            json_match = re.search(r'\{[^{}]*"suggested_name"[^{}]*\}', response_text, re.DOTALL)
            if json_match:
                json_str = json_match.group(0)
            else:
                # Last resort - try the whole response
                json_str = response_text

        try:
            data = json.loads(json_str)

            result.purpose = data.get("purpose", "")
            result.suggested_name = data.get("suggested_name", "")
            result.confidence = float(data.get("confidence", 0.5))
            result.prototype = data.get("prototype", "")
            result.calling_convention = data.get("calling_convention", "__cdecl")
            result.variable_types = data.get("variable_types", {})
            result.variable_names = data.get("variable_names", {})
            result.plate_comment = data.get("plate_comment", "")
            result.reasoning = data.get("reasoning", "")

        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse JSON response: {e}")
            result.error = f"JSON parse error: {e}"
            # Try to extract at least the suggested name
            name_match = re.search(r'"suggested_name"\s*:\s*"([^"]+)"', response_text)
            if name_match:
                result.suggested_name = name_match.group(1)
                result.confidence = 0.3  # Low confidence due to parse failure

        return result

    def batch_analyze(
        self,
        functions: List[Dict[str, Any]],
        progress_callback: callable = None
    ) -> List[AnalysisResult]:
        """
        Analyze multiple functions in sequence.

        Args:
            functions: List of function dicts with keys:
                - decompiled_code, func_name, func_address, etc.
            progress_callback: Optional callback(current, total, result)

        Returns:
            List of AnalysisResults
        """
        results = []
        total = len(functions)

        for i, func in enumerate(functions):
            result = self.analyze_function(**func)
            results.append(result)

            if progress_callback:
                progress_callback(i + 1, total, result)

        return results

    def get_stats(self) -> Dict[str, Any]:
        """Get analysis statistics."""
        return {
            **self._stats,
            "model": self.model,
            "api_available": self.is_available()
        }

    def estimate_cost(self, input_chars: int, output_tokens: int = 1000) -> float:
        """
        Estimate API cost for an analysis.

        Rough estimates based on typical pricing:
        - Input: ~$3/MTok for Sonnet
        - Output: ~$15/MTok for Sonnet

        Args:
            input_chars: Approximate input character count
            output_tokens: Expected output tokens

        Returns:
            Estimated cost in USD
        """
        # Rough token estimate (1 token ~ 4 chars)
        input_tokens = input_chars / 4

        # Sonnet pricing (as of 2024)
        input_cost = (input_tokens / 1_000_000) * 3
        output_cost = (output_tokens / 1_000_000) * 15

        return input_cost + output_cost


class AutoDocumenter:
    """
    Automated function documenter that combines Claude analysis with Ghidra updates.

    This class orchestrates the full workflow:
    1. Fetch function data from Ghidra
    2. Send to Claude for analysis
    3. Apply Claude's suggestions back to Ghidra
    4. Verify completeness
    """

    def __init__(self, improvement_loop, analyzer: ClaudeAnalyzer = None):
        """
        Initialize the auto-documenter.

        Args:
            improvement_loop: ContinuousImprovementLoop instance
            analyzer: ClaudeAnalyzer instance (created if not provided)
        """
        self.loop = improvement_loop
        self.analyzer = analyzer or ClaudeAnalyzer()
        self._session_stats = {
            "functions_analyzed": 0,
            "functions_documented": 0,
            "skipped_low_confidence": 0,
            "errors": 0,
            "total_tokens": 0
        }

    def document_function(
        self,
        func_name: str = None,
        func_address: str = None,
        min_confidence: float = 0.6,
        dry_run: bool = False
    ) -> Dict[str, Any]:
        """
        Automatically analyze and document a function.

        Args:
            func_name: Function name (or will find next undocumented)
            func_address: Function address
            min_confidence: Minimum confidence to apply changes
            dry_run: If True, analyze but don't apply changes

        Returns:
            Dict with analysis results and applied changes
        """
        # Find function if not specified
        if not func_name:
            func_data = self.loop.get_next_function_to_document()
            if not func_data:
                return {"status": "no_functions", "message": "No undocumented functions found"}
            func_name = func_data["name"]
            func_address = func_data["address"]

        logger.info(f"Auto-documenting: {func_name} @ {func_address}")

        # Mark work started for resume capability
        self.loop.start_function_work(func_name, func_address)

        try:
            # Gather analysis data
            analysis_data = self.loop.get_function_analysis(func_name)

            if not analysis_data.get("decompiled"):
                self.loop.complete_function_work(func_address, success=False)
                return {
                    "status": "error",
                    "message": "Could not decompile function",
                    "function": func_name
                }

            # Send to Claude for analysis
            result = self.analyzer.analyze_function(
                decompiled_code=analysis_data["decompiled"],
                func_name=func_name,
                func_address=func_address,
                disassembly=analysis_data.get("disassembly", ""),
                callees=analysis_data.get("callees", ""),
                callers=analysis_data.get("callers", ""),
                variables=analysis_data.get("variables", "")
            )

            self._session_stats["functions_analyzed"] += 1
            self._session_stats["total_tokens"] += result.tokens_used

            if result.error:
                self._session_stats["errors"] += 1
                self.loop.complete_function_work(func_address, success=False)
                return {
                    "status": "analysis_error",
                    "error": result.error,
                    "function": func_name
                }

            # Check confidence threshold
            if result.confidence < min_confidence:
                self._session_stats["skipped_low_confidence"] += 1
                logger.info(f"Skipping {func_name}: confidence {result.confidence} < {min_confidence}")
                self.loop.complete_function_work(func_address, success=False)
                return {
                    "status": "low_confidence",
                    "confidence": result.confidence,
                    "threshold": min_confidence,
                    "analysis": result.to_dict(),
                    "function": func_name
                }

            # Apply changes (unless dry run)
            applied = {}
            if not dry_run:
                applied = self.loop.apply_documentation(
                    func_address=func_address,
                    new_name=result.suggested_name,
                    prototype=result.prototype,
                    plate_comment=result.plate_comment,
                    variable_types=result.variable_types
                )

                if any(applied.values()):
                    self._session_stats["functions_documented"] += 1

            self.loop.complete_function_work(func_address, success=True)

            return {
                "status": "success" if not dry_run else "dry_run",
                "function": func_name,
                "address": func_address,
                "analysis": result.to_dict(),
                "applied": applied,
                "dry_run": dry_run
            }

        except Exception as e:
            logger.error(f"Error documenting {func_name}: {e}")
            self._session_stats["errors"] += 1
            self.loop.complete_function_work(func_address, success=False)
            return {
                "status": "error",
                "error": str(e),
                "function": func_name
            }

    def run_session(
        self,
        max_functions: int = 10,
        min_confidence: float = 0.6,
        dry_run: bool = False,
        progress_callback: callable = None
    ) -> Dict[str, Any]:
        """
        Run an automated documentation session.

        Args:
            max_functions: Maximum functions to document
            min_confidence: Minimum confidence threshold
            dry_run: If True, analyze but don't apply changes
            progress_callback: Optional callback(current, total, result)

        Returns:
            Session summary with results for each function
        """
        logger.info(f"Starting auto-documentation session (max={max_functions}, min_conf={min_confidence})")

        results = []

        for i in range(max_functions):
            result = self.document_function(
                min_confidence=min_confidence,
                dry_run=dry_run
            )
            results.append(result)

            if progress_callback:
                progress_callback(i + 1, max_functions, result)

            # Stop if no more functions
            if result.get("status") == "no_functions":
                break

        # Generate summary
        summary = {
            "session_stats": self._session_stats.copy(),
            "analyzer_stats": self.analyzer.get_stats(),
            "results": results,
            "successful": sum(1 for r in results if r.get("status") == "success"),
            "skipped": sum(1 for r in results if r.get("status") == "low_confidence"),
            "errors": sum(1 for r in results if r.get("status") in ("error", "analysis_error"))
        }

        logger.info(f"Session complete: {summary['successful']} documented, "
                   f"{summary['skipped']} skipped, {summary['errors']} errors")

        return summary

    def get_session_stats(self) -> Dict[str, Any]:
        """Get current session statistics."""
        return {
            **self._session_stats,
            "analyzer": self.analyzer.get_stats()
        }


# =============================================================================
# Convenience functions for integration
# =============================================================================

def create_analyzer(api_key: str = None, model: str = None) -> ClaudeAnalyzer:
    """Create a Claude analyzer instance."""
    return ClaudeAnalyzer(api_key=api_key, model=model)


def analyze_single_function(
    decompiled_code: str,
    func_name: str = "FUN_unknown",
    func_address: str = "0x0",
    **kwargs
) -> Dict[str, Any]:
    """
    Analyze a single function without needing the full workflow.

    Args:
        decompiled_code: The decompiled C code
        func_name: Current function name
        func_address: Function address
        **kwargs: Additional arguments for analyze_function

    Returns:
        Analysis result as a dict
    """
    analyzer = ClaudeAnalyzer()
    result = analyzer.analyze_function(
        decompiled_code=decompiled_code,
        func_name=func_name,
        func_address=func_address,
        **kwargs
    )
    return result.to_dict()


def run_auto_documentation_session(
    loop,
    max_functions: int = 10,
    min_confidence: float = 0.6,
    dry_run: bool = False
) -> Dict[str, Any]:
    """
    Run an automated documentation session.

    Args:
        loop: ContinuousImprovementLoop instance
        max_functions: Maximum functions to document
        min_confidence: Minimum confidence threshold
        dry_run: If True, analyze but don't apply changes

    Returns:
        Session summary
    """
    documenter = AutoDocumenter(loop)
    return documenter.run_session(
        max_functions=max_functions,
        min_confidence=min_confidence,
        dry_run=dry_run
    )


# =============================================================================
# CLI for testing
# =============================================================================

def main():
    """CLI entry point for testing."""
    import argparse

    parser = argparse.ArgumentParser(description="Claude Function Analyzer")
    parser.add_argument("--test", action="store_true", help="Run a test analysis")
    parser.add_argument("--check", action="store_true", help="Check API availability")
    parser.add_argument("--stats", action="store_true", help="Show analyzer stats")

    args = parser.parse_args()

    analyzer = ClaudeAnalyzer()

    if args.check:
        print(f"API Available: {analyzer.is_available()}")
        print(f"Model: {analyzer.model}")
        return 0

    if args.stats:
        print(json.dumps(analyzer.get_stats(), indent=2))
        return 0

    if args.test:
        if not analyzer.is_available():
            print("Error: ANTHROPIC_API_KEY not set")
            return 1

        # Test with sample code
        test_code = """
        int FUN_00401000(int param_1, void *param_2) {
            int local_8;

            local_8 = 0;
            while (local_8 < param_1) {
                if (*(byte *)(param_2 + local_8) == 0) {
                    return local_8;
                }
                local_8 = local_8 + 1;
            }
            return -1;
        }
        """

        print("Testing Claude analysis...")
        result = analyzer.analyze_function(
            decompiled_code=test_code,
            func_name="FUN_00401000",
            func_address="0x00401000"
        )

        print(f"\nResult:")
        print(f"  Suggested Name: {result.suggested_name}")
        print(f"  Confidence: {result.confidence}")
        print(f"  Purpose: {result.purpose}")
        print(f"  Prototype: {result.prototype}")
        print(f"  Tokens Used: {result.tokens_used}")

        if result.error:
            print(f"  Error: {result.error}")

        return 0

    # Default: show usage
    parser.print_help()
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
