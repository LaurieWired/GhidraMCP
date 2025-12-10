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
def search_variables(pattern: str, offset: int = 0, limit: int = 100) -> list:
    """
    Search for variables across all functions whose name matches a pattern.

    Args:
        pattern: The pattern to search for (e.g., "param_", "iVar", "local_")
        offset: Pagination offset (default: 0)
        limit: Maximum number of results to return (default: 100)

    Returns:
        List of matches in format: "FunctionName @ address: variableName (type)"

    Note: This operation can be slow as it decompiles functions to find variables.
    """
    if not pattern:
        return ["Error: pattern string is required"]
    return safe_get("searchVariables", {"pattern": pattern, "offset": offset, "limit": limit})


# ============================================================================
# Structure/Type Management Functions
# ============================================================================

@mcp.tool()
def create_struct(name: str, size: int = 0, category: str = None) -> str:
    """
    Create a new structure data type.

    Args:
        name: Name of the structure (e.g., "LFGCooldownNode")
        size: Initial size in bytes (0 for undefined/growable structure)
        category: Category path for the structure (e.g., "/WoW" or None for root)

    Returns:
        Success message with structure path, or error message

    Example:
        create_struct("SavedInstanceEntry", 32, "/WoW/LFG")
    """
    data = {"name": name}
    if size > 0:
        data["size"] = str(size)
    if category:
        data["category"] = category
    return safe_post("create_struct", data)


@mcp.tool()
def add_struct_field(struct_name: str, field_type: str, field_name: str,
                     offset: int = -1, field_size: int = 0) -> str:
    """
    Add a field to an existing structure.

    Args:
        struct_name: Name of the structure to modify
        field_type: Data type of the field (e.g., "uint", "int", "char", "pointer")
        field_name: Name for the new field
        offset: Byte offset for the field (-1 to append at end)
        field_size: Size override in bytes (0 to use type's natural size)

    Returns:
        Success or error message

    Example:
        add_struct_field("LFGCooldownNode", "uint", "dungeonId", offset=0x08)
        add_struct_field("LFGCooldownNode", "pointer", "pNextNode", offset=0x04)
    """
    data = {
        "struct_name": struct_name,
        "field_type": field_type,
        "field_name": field_name,
        "offset": str(offset)
    }
    if field_size > 0:
        data["field_size"] = str(field_size)
    return safe_post("add_struct_field", data)


@mcp.tool()
def list_structs(offset: int = 0, limit: int = 100, filter: str = None) -> list:
    """
    List all structure types defined in the program.

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of structures to return (default: 100)
        filter: Optional filter to match structure names

    Returns:
        List of structure names with their sizes and field counts
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return safe_get("list_structs", params)


@mcp.tool()
def get_struct(name: str) -> str:
    """
    Get detailed information about a structure including all fields.

    Args:
        name: Name of the structure

    Returns:
        Structure details with all fields, offsets, types, and sizes

    Example output:
        Structure: LFGCooldownNode
        Path: /WoW/LFG/LFGCooldownNode
        Size: 24 bytes
        Fields (5):
          +0x0000: uint flags (size: 4)
          +0x0004: pointer pNextNode (size: 4)
          +0x0008: uint dungeonId (size: 4)
          ...
    """
    return "\n".join(safe_get("get_struct", {"name": name}))


@mcp.tool()
def apply_struct_at_address(address: str, struct_name: str) -> str:
    """
    Apply a structure type at a specific memory address.

    Args:
        address: Memory address in hex format (e.g., "0x00acdc00")
        struct_name: Name of the structure to apply

    Returns:
        Success or error message

    Example:
        apply_struct_at_address("0x00bcfae8", "SavedInstanceArray")
    """
    return safe_post("apply_struct_at_address", {
        "address": address,
        "struct_name": struct_name
    })


@mcp.tool()
def create_enum(name: str, size: int = 4, category: str = None) -> str:
    """
    Create a new enum data type.

    Args:
        name: Name of the enum (e.g., "LFG_LOCKSTATUS")
        size: Size in bytes (1, 2, 4, or 8; default: 4)
        category: Category path for the enum (e.g., "/WoW/Enums")

    Returns:
        Success message with enum path, or error message

    Example:
        create_enum("LFG_LOCKSTATUS", 4, "/WoW/LFG")
    """
    data = {"name": name, "size": str(size)}
    if category:
        data["category"] = category
    return safe_post("create_enum", data)


@mcp.tool()
def add_enum_value(enum_name: str, value_name: str, value: int) -> str:
    """
    Add a value to an existing enum.

    Args:
        enum_name: Name of the enum to modify
        value_name: Name for the enum value
        value: Numeric value

    Returns:
        Success or error message

    Example:
        add_enum_value("LFG_LOCKSTATUS", "NOT_LOCKED", 0)
        add_enum_value("LFG_LOCKSTATUS", "TOO_LOW_LEVEL", 1)
        add_enum_value("LFG_LOCKSTATUS", "RAID_LOCKED", 6)
    """
    return safe_post("add_enum_value", {
        "enum_name": enum_name,
        "value_name": value_name,
        "value": str(value)
    })


@mcp.tool()
def list_types(offset: int = 0, limit: int = 100, category: str = None) -> list:
    """
    List all data types, optionally filtered by category.

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of types to return (default: 100)
        category: Category path to list (e.g., "/WoW" or None for all)

    Returns:
        List of type names with their kinds and sizes
    """
    params = {"offset": offset, "limit": limit}
    if category:
        params["category"] = category
    return safe_get("list_types", params)


@mcp.tool()
def delete_struct(name: str) -> str:
    """
    Delete a structure or other data type.

    Args:
        name: Name of the structure/type to delete

    Returns:
        Success or error message

    Warning: This will fail if the type is in use elsewhere.
    """
    return safe_post("delete_struct", {"name": name})


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
