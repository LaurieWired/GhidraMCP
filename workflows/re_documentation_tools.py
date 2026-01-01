#!/usr/bin/env python3
"""
Curated MCP Tool Subset for Binary Documentation

This module provides a minimal, focused set of tools specifically designed
for the task of documenting/reverse-engineering binaries. It removes tools
that are not essential for documentation workflows, reducing cognitive load
and improving efficiency.

Philosophy:
- Include only tools that directly support understanding and documenting code
- Prefer batch operations over individual calls
- Every tool should have a clear purpose in the documentation workflow
- No redundant or rarely-used tools

Tool Categories:
1. DISCOVERY - Finding functions to work on
2. ANALYSIS - Understanding what code does
3. DOCUMENTATION - Recording understanding
4. DATA TYPES - Creating/managing structures
5. VERIFICATION - Validating work quality
"""

import os
import sys
import json
import time
import logging
from functools import lru_cache
from typing import List, Dict, Any, Optional

import requests

# Configuration
GHIDRA_SERVER = os.environ.get("GHIDRA_SERVER", "http://127.0.0.1:8089")
DEFAULT_TIMEOUT = 30
DECOMPILE_TIMEOUT = 60

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("re_documentation_tools")


class GhidraConnectionError(Exception):
    """Raised when Ghidra server is not accessible."""
    pass


class GhidraOperationError(Exception):
    """Raised when a Ghidra operation fails."""
    pass


# =============================================================================
# HTTP Client Layer
# =============================================================================

_session: Optional[requests.Session] = None


def _get_session() -> requests.Session:
    """Get or create a reusable HTTP session."""
    global _session
    if _session is None:
        _session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=10,
            pool_maxsize=10,
            max_retries=3
        )
        _session.mount('http://', adapter)
    return _session


def _call_ghidra(endpoint: str, params: Dict[str, Any] = None,
                 method: str = "GET", timeout: int = DEFAULT_TIMEOUT) -> str:
    """
    Make a call to the Ghidra REST API.

    Args:
        endpoint: API endpoint (without leading /)
        params: Query parameters or POST data
        method: HTTP method (GET or POST)
        timeout: Request timeout in seconds

    Returns:
        Response text

    Raises:
        GhidraConnectionError: If server is not accessible
        GhidraOperationError: If the operation fails
    """
    url = f"{GHIDRA_SERVER}/{endpoint}"
    session = _get_session()

    try:
        if method == "GET":
            response = session.get(url, params=params, timeout=timeout)
        else:
            response = session.post(url, data=params, timeout=timeout)

        if response.status_code == 404:
            raise GhidraOperationError(f"Endpoint not found: {endpoint}")

        if response.status_code != 200:
            raise GhidraOperationError(
                f"Request failed: {response.status_code} - {response.text[:200]}"
            )

        return response.text

    except requests.exceptions.ConnectionError as e:
        raise GhidraConnectionError(f"Cannot connect to Ghidra server: {e}")
    except requests.exceptions.Timeout:
        raise GhidraOperationError(f"Request timed out after {timeout}s")


# =============================================================================
# CATEGORY 1: DISCOVERY
# Tools for finding functions to document
# =============================================================================

def get_program_info() -> Dict[str, Any]:
    """
    Get metadata about the currently loaded program.

    Returns:
        Dictionary with program name, architecture, base address, etc.

    Example:
        >>> info = get_program_info()
        >>> print(info["name"])  # "D2Win.dll"
    """
    data = _call_ghidra("get_metadata")
    result = {}
    for line in data.strip().split('\n'):
        if ':' in line:
            key, value = line.split(':', 1)
            result[key.strip()] = value.strip()
    return result


def find_undocumented_functions(pattern: str = "FUN_",
                                 limit: int = 50) -> List[Dict[str, str]]:
    """
    Find functions that haven't been documented yet.

    Args:
        pattern: Name pattern to search (default: "FUN_" for default names)
        limit: Maximum number of results

    Returns:
        List of dicts with 'name' and 'address' keys, sorted by potential importance

    Example:
        >>> funcs = find_undocumented_functions(limit=10)
        >>> for f in funcs:
        ...     print(f"{f['name']} @ {f['address']}")
    """
    data = _call_ghidra("searchFunctions", {"query": pattern, "limit": limit})
    functions = []

    for line in data.strip().split('\n'):
        if ' @ ' in line:
            name, address = line.split(' @ ')
            functions.append({"name": name.strip(), "address": address.strip()})

    return functions


def list_functions(offset: int = 0, limit: int = 100) -> List[Dict[str, str]]:
    """
    List all functions in the program.

    Args:
        offset: Starting offset for pagination
        limit: Maximum number of results

    Returns:
        List of function dictionaries with name, address, size

    Example:
        >>> funcs = list_functions(limit=50)
    """
    data = _call_ghidra("list_functions", {"offset": offset, "limit": limit})
    return json.loads(data) if data.startswith('[') else []


# =============================================================================
# CATEGORY 2: ANALYSIS
# Tools for understanding what code does
# =============================================================================

def decompile(function_name: str, force_refresh: bool = False) -> str:
    """
    Get decompiled C pseudocode for a function.

    This is the primary analysis tool - produces readable C-like code.

    Args:
        function_name: Name of the function to decompile
        force_refresh: If True, force re-decompilation

    Returns:
        Decompiled C code as a string

    Example:
        >>> code = decompile("FUN_6f8e1000")
        >>> print(code)
    """
    endpoint = "force_decompile" if force_refresh else "decompile"
    return _call_ghidra(endpoint, {"name": function_name}, timeout=DECOMPILE_TIMEOUT)


def disassemble(function_name: str) -> str:
    """
    Get assembly listing for a function.

    Use when you need to see the actual machine code, especially for:
    - Understanding calling conventions
    - Analyzing register usage
    - Identifying inline assembly patterns

    Args:
        function_name: Name of the function to disassemble

    Returns:
        Assembly listing as a string

    Example:
        >>> asm = disassemble("FUN_6f8e1000")
        >>> print(asm)
    """
    return _call_ghidra("disassemble_function", {"name": function_name})


def get_function_variables(function_name: str) -> List[Dict[str, Any]]:
    """
    Get all parameters and local variables for a function.

    Essential for understanding function signatures and local state.

    Args:
        function_name: Name of the function

    Returns:
        List of variable dictionaries with name, type, storage info

    Example:
        >>> vars = get_function_variables("ProcessSlots")
        >>> for v in vars:
        ...     print(f"{v['type']} {v['name']}")
    """
    data = _call_ghidra("function_variables", {"name": function_name})
    try:
        return json.loads(data)
    except json.JSONDecodeError:
        # Parse text format if not JSON
        variables = []
        for line in data.strip().split('\n'):
            if line.strip():
                variables.append({"raw": line.strip()})
        return variables


def get_callees(function_name: str) -> List[Dict[str, str]]:
    """
    Get functions called by this function.

    Use to understand dependencies and function behavior.

    Args:
        function_name: Name of the function

    Returns:
        List of called function info

    Example:
        >>> callees = get_callees("ProcessSlots")
        >>> print(f"Calls {len(callees)} functions")
    """
    data = _call_ghidra("function_callees", {"name": function_name})
    try:
        return json.loads(data)
    except json.JSONDecodeError:
        return [{"raw": line} for line in data.strip().split('\n') if line.strip()]


def get_callers(function_name: str) -> List[Dict[str, str]]:
    """
    Get functions that call this function.

    Use to understand usage context and importance.

    Args:
        function_name: Name of the function

    Returns:
        List of calling function info

    Example:
        >>> callers = get_callers("ProcessSlots")
        >>> print(f"Called by {len(callers)} functions")
    """
    data = _call_ghidra("function_callers", {"name": function_name})
    try:
        return json.loads(data)
    except json.JSONDecodeError:
        return [{"raw": line} for line in data.strip().split('\n') if line.strip()]


def get_xrefs(address: str) -> Dict[str, List[str]]:
    """
    Get cross-references to and from an address.

    Args:
        address: Address to query (hex string)

    Returns:
        Dictionary with 'to' and 'from' reference lists

    Example:
        >>> xrefs = get_xrefs("0x6f8e1000")
        >>> print(f"Referenced by {len(xrefs['to'])} locations")
    """
    refs_to = _call_ghidra("xrefs_to", {"address": address})
    refs_from = _call_ghidra("xrefs_from", {"address": address})

    return {
        "to": [line for line in refs_to.strip().split('\n') if line.strip()],
        "from": [line for line in refs_from.strip().split('\n') if line.strip()]
    }


def get_jump_targets(function_name: str) -> List[str]:
    """
    Get addresses of jump targets within a function.

    Use to identify important code locations for labeling.

    Args:
        function_name: Name of the function

    Returns:
        List of addresses that are jump targets

    Example:
        >>> targets = get_jump_targets("ProcessSlots")
        >>> # These are good candidates for labels
    """
    data = _call_ghidra("function_jump_target_addresses", {"name": function_name})
    return [line.strip() for line in data.strip().split('\n') if line.strip()]


# =============================================================================
# CATEGORY 3: DOCUMENTATION
# Tools for recording understanding
# =============================================================================

def rename_function(old_name: str, new_name: str) -> bool:
    """
    Rename a function.

    Convention: Use PascalCase (e.g., ProcessPlayerSlots, ValidateBuffer)

    Args:
        old_name: Current function name
        new_name: New function name (PascalCase)

    Returns:
        True if successful

    Example:
        >>> rename_function("FUN_6f8e1000", "ProcessPlayerSlots")
    """
    result = _call_ghidra("rename_function",
                          {"old_name": old_name, "new_name": new_name},
                          method="POST")
    return "success" in result.lower() or "renamed" in result.lower()


def set_function_signature(address: str, prototype: str,
                           calling_convention: str = "__cdecl") -> bool:
    """
    Set a function's signature/prototype.

    Args:
        address: Function address (hex string)
        prototype: C function prototype string
        calling_convention: Calling convention (__cdecl, __stdcall, __fastcall, __thiscall)

    Returns:
        True if successful

    Example:
        >>> set_function_signature(
        ...     "0x6f8e1000",
        ...     "int ProcessSlots(int maxCount, void* pData)",
        ...     "__stdcall"
        ... )
    """
    result = _call_ghidra("set_function_prototype", {
        "function_address": address,
        "prototype": prototype,
        "calling_convention": calling_convention
    }, method="POST")
    return "success" in result.lower() or "set" in result.lower()


def rename_variable(function_name: str, old_name: str, new_name: str) -> bool:
    """
    Rename a variable within a function.

    Convention: Use camelCase (e.g., playerIndex, bufferSize)
    Or Hungarian: dwFlags, pBuffer, nCount, fEnabled

    Args:
        function_name: Name of the function containing the variable
        old_name: Current variable name
        new_name: New variable name

    Returns:
        True if successful

    Example:
        >>> rename_variable("ProcessSlots", "local_8", "playerIndex")
    """
    result = _call_ghidra("rename_variable", {
        "function_name": function_name,
        "old_name": old_name,
        "new_name": new_name
    }, method="POST")
    return "success" in result.lower() or "renamed" in result.lower()


def set_variable_type(function_address: str, variable_name: str,
                      data_type: str) -> bool:
    """
    Set the type of a local variable.

    Args:
        function_address: Address of the function (hex string)
        variable_name: Name of the variable
        data_type: Ghidra data type name

    Returns:
        True if successful

    Example:
        >>> set_variable_type("0x6f8e1000", "local_8", "DWORD")
    """
    result = _call_ghidra("set_local_variable_type", {
        "function_address": function_address,
        "variable_name": variable_name,
        "data_type": data_type
    }, method="POST")
    return "success" in result.lower()


def batch_set_types(function_address: str,
                    variable_types: Dict[str, str]) -> Dict[str, bool]:
    """
    Set types for multiple variables at once (more efficient).

    Args:
        function_address: Address of the function (hex string)
        variable_types: Dict mapping variable names to types

    Returns:
        Dict mapping variable names to success status

    Example:
        >>> batch_set_types("0x6f8e1000", {
        ...     "local_8": "DWORD",
        ...     "local_c": "pointer",
        ...     "param_1": "int"
        ... })
    """
    result = _call_ghidra("batch_set_variable_types", {
        "function_address": function_address,
        "variable_types": json.dumps(variable_types)
    }, method="POST", timeout=60)

    try:
        return json.loads(result)
    except json.JSONDecodeError:
        return {"_raw": result}


def create_label(address: str, name: str) -> bool:
    """
    Create a label at an address.

    Convention: Use snake_case (e.g., loop_start, error_handler)

    Args:
        address: Address for the label (hex string)
        name: Label name (snake_case)

    Returns:
        True if successful

    Example:
        >>> create_label("0x6f8e1050", "validation_failed")
    """
    result = _call_ghidra("create_label", {
        "address": address,
        "name": name
    }, method="POST")
    return "success" in result.lower() or "created" in result.lower()


def batch_create_labels(labels: List[Dict[str, str]]) -> Dict[str, bool]:
    """
    Create multiple labels at once (more efficient).

    Args:
        labels: List of dicts with 'address' and 'name' keys

    Returns:
        Dict mapping addresses to success status

    Example:
        >>> batch_create_labels([
        ...     {"address": "0x6f8e1010", "name": "loop_start"},
        ...     {"address": "0x6f8e1050", "name": "error_handler"},
        ...     {"address": "0x6f8e1080", "name": "exit_function"}
        ... ])
    """
    result = _call_ghidra("batch_create_labels", {
        "labels": json.dumps(labels)
    }, method="POST", timeout=60)

    try:
        return json.loads(result)
    except json.JSONDecodeError:
        return {"_raw": result}


def set_plate_comment(function_name: str, comment: str) -> bool:
    """
    Set the plate (header) comment for a function.

    This is the main documentation block at the top of a function.

    Args:
        function_name: Name of the function
        comment: Multi-line comment text

    Returns:
        True if successful

    Example:
        >>> set_plate_comment("ProcessSlots", '''
        ... Processes player inventory slots.
        ...
        ... Algorithm: Iterates through all slots and validates each
        ... Returns: Number of valid slots processed
        ... ''')
    """
    result = _call_ghidra("set_plate_comment", {
        "function_name": function_name,
        "comment": comment
    }, method="POST")
    return "success" in result.lower()


def batch_set_comments(function_address: str,
                       plate_comment: str = None,
                       disassembly_comments: List[Dict[str, str]] = None,
                       decompiler_comments: List[Dict[str, str]] = None) -> bool:
    """
    Set all comments for a function in one call (most efficient).

    Args:
        function_address: Address of the function (hex string)
        plate_comment: Header comment for the function
        disassembly_comments: List of {'address': ..., 'comment': ...}
        decompiler_comments: List of {'address': ..., 'comment': ...}

    Returns:
        True if successful

    Example:
        >>> batch_set_comments(
        ...     "0x6f8e1000",
        ...     plate_comment="Processes player slots",
        ...     disassembly_comments=[
        ...         {"address": "0x6f8e1005", "comment": "Save ECX"},
        ...         {"address": "0x6f8e1010", "comment": "Loop start"}
        ...     ],
        ...     decompiler_comments=[
        ...         {"address": "0x6f8e1020", "comment": "Must be < MAX_PLAYERS"}
        ...     ]
        ... )
    """
    params = {"function_address": function_address}
    if plate_comment:
        params["plate_comment"] = plate_comment
    if disassembly_comments:
        params["disassembly_comments"] = json.dumps(disassembly_comments)
    if decompiler_comments:
        params["decompiler_comments"] = json.dumps(decompiler_comments)

    result = _call_ghidra("batch_set_comments", params, method="POST", timeout=120)
    return "success" in result.lower() or "set" in result.lower()


# =============================================================================
# CATEGORY 4: DATA TYPES
# Tools for creating and managing structures
# =============================================================================

def list_data_types(category: str = None, limit: int = 100) -> List[str]:
    """
    List available data types.

    Args:
        category: Optional category filter (e.g., "/MyTypes")
        limit: Maximum results

    Returns:
        List of data type names

    Example:
        >>> types = list_data_types()
        >>> if "DWORD" in types:
        ...     print("DWORD is available")
    """
    params = {"limit": limit}
    if category:
        params["category"] = category

    data = _call_ghidra("list_data_types", params)
    return [line.strip() for line in data.strip().split('\n') if line.strip()]


def search_data_types(pattern: str) -> List[str]:
    """
    Search for data types by name pattern.

    Args:
        pattern: Search pattern (partial match)

    Returns:
        List of matching type names

    Example:
        >>> types = search_data_types("Player")
        >>> # Returns types like PlayerData, PlayerInfo, etc.
    """
    data = _call_ghidra("search_data_types", {"pattern": pattern})
    return [line.strip() for line in data.strip().split('\n') if line.strip()]


def create_struct(name: str, fields: List[Dict[str, Any]],
                  category: str = "/MyTypes") -> bool:
    """
    Create a new structure type.

    Args:
        name: Structure name (PascalCase)
        fields: List of field dicts with 'name', 'type', optional 'comment'
        category: Category path for the type

    Returns:
        True if successful

    Example:
        >>> create_struct("PlayerSlot", [
        ...     {"name": "dwFlags", "type": "dword", "comment": "Slot flags"},
        ...     {"name": "pItem", "type": "pointer", "comment": "Item pointer"},
        ...     {"name": "nQuantity", "type": "word", "comment": "Stack count"}
        ... ])
    """
    result = _call_ghidra("create_struct", {
        "name": name,
        "fields": json.dumps(fields),
        "category": category
    }, method="POST")
    return "success" in result.lower() or "created" in result.lower()


def create_enum(name: str, values: Dict[str, int],
                category: str = "/MyTypes") -> bool:
    """
    Create a new enumeration type.

    Args:
        name: Enum name (PascalCase)
        values: Dict mapping member names to integer values
        category: Category path for the type

    Returns:
        True if successful

    Example:
        >>> create_enum("SlotType", {
        ...     "SLOT_EMPTY": 0,
        ...     "SLOT_ITEM": 1,
        ...     "SLOT_EQUIPMENT": 2
        ... })
    """
    result = _call_ghidra("create_enum", {
        "name": name,
        "values": json.dumps(values),
        "category": category
    }, method="POST")
    return "success" in result.lower() or "created" in result.lower()


def apply_data_type(address: str, type_name: str) -> bool:
    """
    Apply a data type to a memory address.

    Args:
        address: Target address (hex string)
        type_name: Name of the type to apply

    Returns:
        True if successful

    Example:
        >>> apply_data_type("0x6f900000", "PlayerSlot")
    """
    result = _call_ghidra("apply_data_type", {
        "address": address,
        "data_type": type_name
    }, method="POST")
    return "success" in result.lower() or "applied" in result.lower()


# =============================================================================
# CATEGORY 5: VERIFICATION
# Tools for validating documentation quality
# =============================================================================

def analyze_completeness(function_address: str) -> Dict[str, Any]:
    """
    Analyze how well a function is documented.

    Checks for:
    - Custom name (not FUN_xxx)
    - Defined prototype
    - Typed variables
    - Comments present
    - Labels at jump targets

    Args:
        function_address: Address of the function (hex string)

    Returns:
        Dictionary with completeness metrics

    Example:
        >>> result = analyze_completeness("0x6f8e1000")
        >>> print(f"Completeness: {result['score']}%")
    """
    data = _call_ghidra("analyze_function_completeness",
                        {"function_address": function_address})
    try:
        return json.loads(data)
    except json.JSONDecodeError:
        return {"raw": data}


def get_function_info(name_or_address: str) -> Dict[str, Any]:
    """
    Get comprehensive information about a function.

    Args:
        name_or_address: Function name or address

    Returns:
        Dictionary with function details

    Example:
        >>> info = get_function_info("ProcessSlots")
    """
    # Try by name first
    data = _call_ghidra("get_function_by_address", {"address": name_or_address})
    try:
        return json.loads(data)
    except json.JSONDecodeError:
        return {"raw": data}


def check_documentation_quality(function_addresses: List[str]) -> List[Dict[str, Any]]:
    """
    Check documentation quality for multiple functions at once.

    Analyzes each function's decompiled output to determine if it has
    detailed documentation (Algorithm:, Parameters: sections) or just
    basic library identification.

    Args:
        function_addresses: List of function addresses (hex strings)

    Returns:
        List of dicts with quality metrics for each function:
        - address: Function address
        - name: Function name
        - has_detailed_docs: True if has Algorithm:/Parameters: sections
        - has_library_comment: True if has Library Function comment
        - comment_length: Length of plate comment
        - quality: "detailed", "basic", or "none"

    Example:
        >>> results = check_documentation_quality(["0x6f8e1000", "0x6f8e1aae"])
        >>> for r in results:
        ...     if r['quality'] != 'detailed':
        ...         print(f"{r['name']} needs work")
    """
    results = []

    for addr in function_addresses:
        result = {
            "address": addr,
            "name": None,
            "has_detailed_docs": False,
            "has_library_comment": False,
            "comment_length": 0,
            "quality": "none"
        }

        try:
            # Decompile to get the full output with comments
            code = _call_ghidra("decompile_function", {"address": addr}, timeout=60)

            if code:
                # Check for detailed documentation markers
                result["has_detailed_docs"] = (
                    "Algorithm:" in code or
                    "Parameters:" in code[:1000] or
                    "Returns:" in code[:1000]
                )
                result["has_library_comment"] = "Library Function" in code[:300]

                # Extract function name from decompiled output
                lines = code.split('\n')
                for line in lines:
                    if '(' in line and ')' in line and not line.strip().startswith('/*'):
                        # This looks like a function signature
                        parts = line.split('(')[0].split()
                        if parts:
                            result["name"] = parts[-1]
                            break

                # Estimate comment length (everything before first non-comment line)
                comment_end = code.find('*/') + 2 if '/*' in code else 0
                result["comment_length"] = comment_end

                # Determine quality level
                if result["has_detailed_docs"]:
                    result["quality"] = "detailed"
                elif result["has_library_comment"]:
                    result["quality"] = "basic"
                else:
                    result["quality"] = "none"

        except Exception as e:
            result["error"] = str(e)

        results.append(result)

    return results


# =============================================================================
# WORKFLOW HELPERS
# High-level functions that combine multiple operations
# =============================================================================

def analyze_function_complete(function_name: str) -> Dict[str, Any]:
    """
    Perform complete analysis of a function.

    Combines: decompile + disassemble + variables + callees + callers

    Args:
        function_name: Name of the function

    Returns:
        Dictionary with all analysis data

    Example:
        >>> analysis = analyze_function_complete("FUN_6f8e1000")
        >>> print(analysis['decompiled'])
        >>> print(f"Calls {len(analysis['callees'])} functions")
    """
    return {
        "name": function_name,
        "decompiled": decompile(function_name),
        "disassembly": disassemble(function_name),
        "variables": get_function_variables(function_name),
        "callees": get_callees(function_name),
        "callers": get_callers(function_name),
        "jump_targets": get_jump_targets(function_name)
    }


def document_function_batch(function_address: str,
                            new_name: str,
                            prototype: str = None,
                            calling_convention: str = "__cdecl",
                            variable_types: Dict[str, str] = None,
                            variable_renames: Dict[str, str] = None,
                            labels: List[Dict[str, str]] = None,
                            plate_comment: str = None,
                            disassembly_comments: List[Dict[str, str]] = None,
                            decompiler_comments: List[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Document a function with all information in optimized batch calls.

    This is the preferred way to document a function - minimizes API calls.

    Args:
        function_address: Address of the function (hex string)
        new_name: New name for the function
        prototype: Optional function prototype
        calling_convention: Calling convention
        variable_types: Dict mapping variable names to types
        variable_renames: Dict mapping old names to new names
        labels: List of label definitions
        plate_comment: Header comment
        disassembly_comments: List of disassembly comments
        decompiler_comments: List of decompiler comments

    Returns:
        Dictionary with results of each operation

    Example:
        >>> document_function_batch(
        ...     "0x6f8e1000",
        ...     new_name="ProcessPlayerSlots",
        ...     prototype="int ProcessPlayerSlots(int maxCount, void* pData)",
        ...     variable_types={"local_8": "DWORD", "local_c": "pointer"},
        ...     labels=[{"address": "0x6f8e1010", "name": "loop_start"}],
        ...     plate_comment="Processes player inventory slots"
        ... )
    """
    results = {}

    # Get current function name for rename
    funcs = find_undocumented_functions(pattern=function_address[-8:], limit=1)
    old_name = funcs[0]["name"] if funcs else None

    # 1. Rename function
    if old_name and new_name:
        results["rename"] = rename_function(old_name, new_name)

    # 2. Set prototype
    if prototype:
        results["prototype"] = set_function_signature(
            function_address, prototype, calling_convention
        )

    # 3. Set variable types (batch)
    if variable_types:
        results["types"] = batch_set_types(function_address, variable_types)

    # 4. Rename variables (must be done individually)
    if variable_renames:
        func_name = new_name or old_name
        if func_name:
            results["renames"] = {}
            for old, new in variable_renames.items():
                results["renames"][old] = rename_variable(func_name, old, new)

    # 5. Create labels (batch)
    if labels:
        results["labels"] = batch_create_labels(labels)

    # 6. Set comments (batch)
    if plate_comment or disassembly_comments or decompiler_comments:
        results["comments"] = batch_set_comments(
            function_address,
            plate_comment,
            disassembly_comments,
            decompiler_comments
        )

    return results


# =============================================================================
# TOOL INVENTORY
# List of all available tools for reference
# =============================================================================

TOOL_INVENTORY = {
    "discovery": [
        "get_program_info",
        "find_undocumented_functions",
        "list_functions"
    ],
    "analysis": [
        "decompile",
        "disassemble",
        "get_function_variables",
        "get_callees",
        "get_callers",
        "get_xrefs",
        "get_jump_targets"
    ],
    "documentation": [
        "rename_function",
        "set_function_signature",
        "rename_variable",
        "set_variable_type",
        "batch_set_types",
        "create_label",
        "batch_create_labels",
        "set_plate_comment",
        "batch_set_comments"
    ],
    "data_types": [
        "list_data_types",
        "search_data_types",
        "create_struct",
        "create_enum",
        "apply_data_type"
    ],
    "verification": [
        "analyze_completeness",
        "get_function_info",
        "check_documentation_quality"
    ],
    "workflow_helpers": [
        "analyze_function_complete",
        "document_function_batch"
    ]
}


def list_tools() -> Dict[str, List[str]]:
    """Return the inventory of available tools by category."""
    return TOOL_INVENTORY


if __name__ == "__main__":
    # Self-test when run directly
    print("RE Documentation Tools - Self Test")
    print("=" * 40)

    try:
        info = get_program_info()
        print(f"Connected to: {info.get('Program Name', 'Unknown')}")
        print(f"Architecture: {info.get('Architecture', 'Unknown')}")

        funcs = find_undocumented_functions(limit=5)
        print(f"\nFound {len(funcs)} undocumented functions")
        if funcs:
            print(f"First: {funcs[0]['name']} @ {funcs[0]['address']}")

        print("\n" + "=" * 40)
        print("AVAILABLE TOOLS:")
        for category, tools in TOOL_INVENTORY.items():
            print(f"\n{category.upper()}:")
            for tool in tools:
                print(f"  - {tool}")

    except GhidraConnectionError as e:
        print(f"ERROR: {e}")
        print("\nMake sure Ghidra is running with a binary loaded")
        sys.exit(1)
