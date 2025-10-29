# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

import sys
import requests
import argparse
import logging
from urllib.parse import urljoin

from mcp.server.fastmcp import FastMCP

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080/"

logger = logging.getLogger(__name__)

mcp = FastMCP("ghidra-mcp")

# Initialize ghidra_server_url with default value
ghidra_server_url = DEFAULT_GHIDRA_SERVER

def safe_get(endpoint: str, params: dict = None) -> list:
    """
    Perform a GET request with optional query parameters.
    """
    if params is None:
        params = {}

    url = urljoin(ghidra_server_url, endpoint)

    try:
        response = requests.get(url, params=params, timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]

def safe_post(endpoint: str, data: dict | str) -> str:
    try:
        url = urljoin(ghidra_server_url, endpoint)
        if isinstance(data, dict):
            response = requests.post(url, data=data, timeout=5)
        else:
            response = requests.post(url, data=data.encode("utf-8"), timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100) -> list:
    """
    List all function names in the program with pagination.
    """
    return safe_get("methods", {"offset": offset, "limit": limit})

@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100) -> list:
    """
    List all namespace/class names in the program with pagination.
    """
    return safe_get("classes", {"offset": offset, "limit": limit})

@mcp.tool()
def decompile_function(name: str) -> str:
    """
    Decompile a specific function by name and return the decompiled C code.
    """
    return safe_post("decompile", name)

@mcp.tool()
def rename_function(old_name: str, new_name: str) -> str:
    """
    Rename a function by its current name to a new user-defined name.
    """
    return safe_post("renameFunction", {"oldName": old_name, "newName": new_name})

@mcp.tool()
def rename_data(address: str, new_name: str) -> str:
    """
    Rename a data label at the specified address.
    """
    return safe_post("renameData", {"address": address, "newName": new_name})

@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100) -> list:
    """
    List all memory segments in the program with pagination.
    """
    return safe_get("segments", {"offset": offset, "limit": limit})

@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100) -> list:
    """
    List imported symbols in the program with pagination.
    """
    return safe_get("imports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100) -> list:
    """
    List exported functions/symbols with pagination.
    """
    return safe_get("exports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100) -> list:
    """
    List all non-global namespaces in the program with pagination.
    """
    return safe_get("namespaces", {"offset": offset, "limit": limit})

@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100) -> list:
    """
    List defined data labels and their values with pagination.
    """
    return safe_get("data", {"offset": offset, "limit": limit})

@mcp.tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> list:
    """
    Search for functions whose name contains the given substring.
    """
    if not query:
        return ["Error: query string is required"]
    return safe_get("searchFunctions", {"query": query, "offset": offset, "limit": limit})

@mcp.tool()
def rename_variable(function_name: str, old_name: str, new_name: str) -> str:
    """
    Rename a local variable within a function.
    """
    return safe_post("renameVariable", {
        "functionName": function_name,
        "oldName": old_name,
        "newName": new_name
    })

@mcp.tool()
def get_function_by_address(address: str) -> str:
    """
    Get a function by its address.
    """
    return "\n".join(safe_get("get_function_by_address", {"address": address}))

@mcp.tool()
def get_current_address() -> str:
    """
    Get the address currently selected by the user.
    """
    return "\n".join(safe_get("get_current_address"))

@mcp.tool()
def get_current_function() -> str:
    """
    Get the function currently selected by the user.
    """
    return "\n".join(safe_get("get_current_function"))

@mcp.tool()
def list_functions() -> list:
    """
    List all functions in the database.
    """
    return safe_get("list_functions")

@mcp.tool()
def decompile_function_by_address(address: str) -> str:
    """
    Decompile a function at the given address.
    """
    return "\n".join(safe_get("decompile_function", {"address": address}))

@mcp.tool()
def disassemble_function(address: str) -> list:
    """
    Get assembly code (address: instruction; comment) for a function.
    """
    return safe_get("disassemble_function", {"address": address})

@mcp.tool()
def set_decompiler_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function pseudocode.
    """
    return safe_post("set_decompiler_comment", {"address": address, "comment": comment})

@mcp.tool()
def set_disassembly_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function disassembly.
    """
    return safe_post("set_disassembly_comment", {"address": address, "comment": comment})

@mcp.tool()
def rename_function_by_address(function_address: str, new_name: str) -> str:
    """
    Rename a function by its address.
    """
    return safe_post("rename_function_by_address", {"function_address": function_address, "new_name": new_name})

@mcp.tool()
def set_function_prototype(function_address: str, prototype: str) -> str:
    """
    Set a function's prototype.
    """
    return safe_post("set_function_prototype", {"function_address": function_address, "prototype": prototype})

@mcp.tool()
def set_local_variable_type(function_address: str, variable_name: str, new_type: str) -> str:
    """
    Set a local variable's type.
    """
    return safe_post("set_local_variable_type", {"function_address": function_address, "variable_name": variable_name, "new_type": new_type})

@mcp.tool()
def get_xrefs_to(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified address (xref to).
    
    Args:
        address: Target address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified address
    """
    return safe_get("xrefs_to", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_xrefs_from(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references from the specified address (xref from).
    
    Args:
        address: Source address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references from the specified address
    """
    return safe_get("xrefs_from", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_function_xrefs(name: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified function by name.
    
    Args:
        name: Function name to search for
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified function
    """
    return safe_get("function_xrefs", {"name": name, "offset": offset, "limit": limit})

@mcp.tool()
def list_strings(offset: int = 0, limit: int = 2000, filter: str = None) -> list:
    """
    List all defined strings in the program with their addresses.

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of strings to return (default: 2000)
        filter: Optional filter to match within string content

    Returns:
        List of strings with their addresses
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return safe_get("strings", params)

@mcp.tool()
def health_check() -> str:
    """
    Check the health status of the Ghidra MCP server.

    Returns JSON with:
    - status: "healthy" or "degraded"
    - server: "running"
    - program_loaded: true/false
    - program_name: name of currently loaded program
    """
    try:
        url = urljoin(ghidra_server_url, "health")
        response = requests.get(url, timeout=5)
        if response.ok:
            return response.text
        else:
            return f"{{\"status\":\"error\",\"code\":{response.status_code}}}"
    except Exception as e:
        return f"{{\"status\":\"unreachable\",\"error\":\"{str(e)}\"}}"

@mcp.tool()
def get_version() -> str:
    """
    Get version information for the GhidraMCP plugin and Ghidra.

    Returns JSON with:
    - plugin: Plugin name
    - version: Plugin version
    - ghidra_version: Ghidra version
    """
    try:
        url = urljoin(ghidra_server_url, "version")
        response = requests.get(url, timeout=5)
        if response.ok:
            return response.text
        else:
            return f"{{\"error\":\"Failed to get version\",\"code\":{response.status_code}}}"
    except Exception as e:
        return f"{{\"error\":\"Request failed: {str(e)}\"}}"

@mcp.tool()
def get_api_info() -> list:
    """
    Get information about all available API endpoints.

    Returns a list of available endpoints with their descriptions.
    """
    return safe_get("api/info")

@mcp.tool()
def list_bookmarks(offset: int = 0, limit: int = 100, type: str = None) -> list:
    """
    List all bookmarks in the program.

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of bookmarks to return (default: 100)
        type: Optional filter by bookmark type (NOTE, INFO, WARNING, ERROR, ANALYSIS)

    Returns:
        List of bookmarks with address, type, category, and comment
    """
    params = {"offset": offset, "limit": limit}
    if type:
        params["type"] = type
    return safe_get("bookmarks", params)

@mcp.tool()
def add_bookmark(address: str, type: str = "NOTE", category: str = "", comment: str = "") -> str:
    """
    Add a bookmark at the specified address.

    Args:
        address: Memory address (e.g., 0x00401000)
        type: Bookmark type - NOTE, INFO, WARNING, ERROR, or ANALYSIS (default: NOTE)
        category: Optional category for organization
        comment: Optional comment or description

    Returns:
        Success or error message
    """
    data = {
        "address": address,
        "type": type,
        "category": category,
        "comment": comment
    }
    return safe_post("add_bookmark", data)

@mcp.tool()
def remove_bookmark(address: str, type: str) -> str:
    """
    Remove a bookmark at the specified address.

    Args:
        address: Memory address (e.g., 0x00401000)
        type: Bookmark type to remove (NOTE, INFO, WARNING, ERROR, ANALYSIS)

    Returns:
        Success or error message
    """
    return safe_get("remove_bookmark", {"address": address, "type": type})

@mcp.tool()
def get_bookmark_types() -> list:
    """
    Get all available bookmark types in Ghidra.

    Returns:
        List of available bookmark types (typically: NOTE, INFO, WARNING, ERROR, ANALYSIS)
    """
    return safe_get("bookmark_types")

# Advanced Analysis Tools

@mcp.tool()
def analyze_function(address: str) -> str:
    """
    Perform comprehensive analysis on a function.

    Returns detailed information including:
    - Basic information (name, signature, calling convention)
    - Size and complexity metrics (instruction count, body size)
    - Parameters and local variables
    - Stack frame information
    - Cross-references (callers and callees)
    - Thunk and external function information

    Args:
        address: Function address in hex format (e.g., "0x00401000")

    Returns:
        Comprehensive function analysis report
    """
    return "\n".join(safe_get("analyze_function", {"address": address}))

@mcp.tool()
def get_program_statistics() -> str:
    """
    Get comprehensive program statistics.

    Returns detailed information including:
    - Program information (name, format, language, compiler)
    - Image base and address range
    - Function statistics (total, external, thunks)
    - Memory statistics (size, blocks, permissions)
    - Symbol and data statistics
    - Instruction counts
    - Data type statistics

    Returns:
        Comprehensive program statistics report
    """
    return "\n".join(safe_get("program_stats"))

@mcp.tool()
def read_memory(address: str, size: int = 16, format: str = "hex") -> str:
    """
    Read memory bytes at specified address.

    Args:
        address: Memory address in hex format (e.g., "0x00401000")
        size: Number of bytes to read (1-10000, default: 16)
        format: Output format - "hex" for hex dump with ASCII, "raw" for hex bytes only

    Returns:
        Memory dump in requested format
    """
    return "\n".join(safe_get("read_memory", {"address": address, "size": size, "format": format}))

@mcp.tool()
def search_memory(pattern: str, start: str = None, end: str = None, limit: int = 100) -> str:
    """
    Search for byte pattern in memory.

    Args:
        pattern: Hex byte pattern to search for (e.g., "4883EC20" or "48 83 EC 20")
        start: Starting address for search (optional, defaults to min address)
        end: Ending address for search (optional, defaults to max address)
        limit: Maximum number of results to return (default: 100)

    Returns:
        List of addresses where pattern was found
    """
    data = {"pattern": pattern, "limit": str(limit)}
    if start:
        data["start"] = start
    if end:
        data["end"] = end
    return safe_post("search_memory", data)

@mcp.tool()
def get_memory_map() -> str:
    """
    Get detailed memory map with permissions and types.

    Returns memory layout showing:
    - Start and end addresses
    - Block sizes
    - Permissions (R=Read, W=Write, X=Execute, I=Initialized, U=Uninitialized)
    - Block names

    Returns:
        Formatted memory map table
    """
    return "\n".join(safe_get("memory_map"))

@mcp.tool()
def get_basic_blocks(address: str) -> str:
    """
    Get basic blocks for a function.

    Args:
        address: Function address in hex format (e.g., "0x00401000")

    Returns:
        List of basic blocks with start/end addresses, sizes, and instruction counts
    """
    return "\n".join(safe_get("basic_blocks", {"address": address}))

@mcp.tool()
def get_control_flow_graph(address: str) -> str:
    """
    Get control flow graph information for a function.

    Shows how basic blocks connect to each other with flow types
    (conditional branches, unconditional jumps, calls, etc.)

    Args:
        address: Function address in hex format (e.g., "0x00401000")

    Returns:
        Control flow graph showing block relationships
    """
    return "\n".join(safe_get("control_flow_graph", {"address": address}))

@mcp.tool()
def get_call_graph(address: str, depth: int = 3, direction: str = "both") -> str:
    """
    Build call graph showing function relationships.

    Args:
        address: Function address in hex format (e.g., "0x00401000")
        depth: Maximum depth to traverse (1-10, default: 3)
        direction: "callers" (functions that call this), "callees" (functions called by this), or "both"

    Returns:
        Call graph showing function call hierarchy
    """
    return "\n".join(safe_get("call_graph", {"address": address, "depth": depth, "direction": direction}))

# Data Type Operations

@mcp.tool()
def list_data_types(category: str = None, offset: int = 0, limit: int = 100) -> list:
    """
    List available data types in the program.

    Args:
        category: Optional category filter (e.g., "winnt" for Windows types)
        offset: Pagination offset (default: 0)
        limit: Maximum number of types to return (default: 100)

    Returns:
        List of data types with sizes
    """
    params = {"offset": offset, "limit": limit}
    if category:
        params["category"] = category
    return safe_get("list_data_types", params)

@mcp.tool()
def get_data_type_info(name: str) -> str:
    """
    Get detailed information about a data type.

    Args:
        name: Data type name (e.g., "DWORD", "IMAGE_DOS_HEADER")

    Returns:
        Detailed data type information including size and description
    """
    return "\n".join(safe_get("data_type_info", {"name": name}))

@mcp.tool()
def create_data(address: str, type_name: str) -> str:
    """
    Create data at specified address with given type.

    Args:
        address: Memory address (e.g., "0x00401000")
        type_name: Data type name (e.g., "DWORD", "char", "byte")

    Returns:
        Success or error message
    """
    return safe_post("create_data", {"address": address, "type": type_name})

@mcp.tool()
def delete_data(address: str) -> str:
    """
    Delete data at specified address (clear to undefined).

    Args:
        address: Memory address (e.g., "0x00401000")

    Returns:
        Success or error message
    """
    return safe_post("delete_data", {"address": address})

@mcp.tool()
def apply_data_type(address: str, type_name: str) -> str:
    """
    Apply or change data type at specified address.

    Clears existing data and applies the new type.

    Args:
        address: Memory address (e.g., "0x00401000")
        type_name: Data type name (e.g., "DWORD", "char[]")

    Returns:
        Success or error message
    """
    return safe_post("apply_data_type", {"address": address, "type": type_name})

# Enhanced Decompilation Tools

@mcp.tool()
def decompile_advanced(address: str, simplification_style: str = "decompile",
                      include_syntax_tree: bool = False, timeout: int = 60) -> str:
    """
    Advanced decompilation with configurable options.

    Provides fine-grained control over the decompilation process with multiple
    simplification styles and optional syntax tree (AST) output.

    Args:
        address: Function address in hex format (e.g., "0x00401000")
        simplification_style: Decompilation style - options include:
            - "decompile" (default): Full decompilation with all simplifications
            - "normalize": Minimal simplification, more literal translation
            - "firstpass": First pass only, least simplified
            - "paramid": Parameter identification pass
            - "jumptable": Jump table analysis
            - "unreachable": Unreachable code analysis
        include_syntax_tree: Include abstract syntax tree in output (default: False)
        timeout: Decompilation timeout in seconds (default: 60)

    Returns:
        Decompiled code with optional syntax tree
    """
    data = {
        "address": address,
        "simplification_style": simplification_style,
        "include_syntax_tree": "true" if include_syntax_tree else "false",
        "timeout": str(timeout)
    }
    return safe_post("decompile_advanced", data)

@mcp.tool()
def decompile_with_options(address: str) -> str:
    """
    Decompile with custom decompiler options.

    Uses enhanced decompiler options for better output quality:
    - Eliminates unreachable code
    - Simplifies double precision floating point
    - Optimizes for readability

    Args:
        address: Function address in hex format (e.g., "0x00401000")

    Returns:
        Decompiled code with enhanced options
    """
    return safe_post("decompile_with_options", {"address": address})

@mcp.tool()
def get_syntax_tree(address: str) -> str:
    """
    Get the abstract syntax tree (AST) for a decompiled function.

    The syntax tree shows the hierarchical structure of the decompiled code,
    useful for understanding code structure and implementing custom analysis.

    Args:
        address: Function address in hex format (e.g., "0x00401000")

    Returns:
        Formatted syntax tree showing node hierarchy
    """
    return safe_post("get_syntax_tree", {"address": address})

@mcp.tool()
def decompile_raw(address: str) -> str:
    """
    Get raw decompiler output with minimal processing.

    Uses first-pass simplification for a more literal translation
    of the assembly code. Useful for:
    - Understanding exact assembly behavior
    - Debugging decompilation issues
    - Analyzing obfuscated code

    Args:
        address: Function address in hex format (e.g., "0x00401000")

    Returns:
        Raw decompiled code with minimal simplification
    """
    return safe_post("decompile_raw", {"address": address})

def main():
    parser = argparse.ArgumentParser(description="MCP server for Ghidra")
    parser.add_argument("--ghidra-server", type=str, default=DEFAULT_GHIDRA_SERVER,
                        help=f"Ghidra server URL, default: {DEFAULT_GHIDRA_SERVER}")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Host to run MCP server on (only used for sse), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int,
                        help="Port to run MCP server on (only used for sse), default: 8081")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"],
                        help="Transport protocol for MCP, default: stdio")
    args = parser.parse_args()
    
    # Use the global variable to ensure it's properly updated
    global ghidra_server_url
    if args.ghidra_server:
        ghidra_server_url = args.ghidra_server
    
    if args.transport == "sse":
        try:
            # Set up logging
            log_level = logging.INFO
            logging.basicConfig(level=log_level)
            logging.getLogger().setLevel(log_level)

            # Configure MCP settings
            mcp.settings.log_level = "INFO"
            if args.mcp_host:
                mcp.settings.host = args.mcp_host
            else:
                mcp.settings.host = "127.0.0.1"

            if args.mcp_port:
                mcp.settings.port = args.mcp_port
            else:
                mcp.settings.port = 8081

            logger.info(f"Connecting to Ghidra server at {ghidra_server_url}")
            logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            logger.info(f"Using transport: {args.transport}")

            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()
        
if __name__ == "__main__":
    main()

