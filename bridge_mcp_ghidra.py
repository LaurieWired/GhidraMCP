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
def create_function(address: str, name: str = "") -> str:
    """
    Create a new function at the given entry address.

    Uses Ghidra's CreateFunctionCmd, so disassembly and body computation happen
    automatically (the same path as the "Create Function" UI action).

    Args:
        address: Entry-point address in hex (e.g. "0x1400010a0").
        name: Optional function name. If omitted, Ghidra assigns the default
              FUN_<addr> name.
    """
    data = {"address": address}
    if name:
        data["name"] = name
    return safe_post("create_function", data)

@mcp.tool()
def create_structure(name: str, size: int = 0) -> str:
    """
    Create a new structure data type in the program's data type manager.

    Args:
        name: Name for the new structure (must not collide with an existing type).
        size: Initial size in bytes. 0 (default) creates an empty structure that
              grows as fields are appended; a positive value reserves that many
              bytes up front (additional fields still grow the structure).
    """
    return safe_post("create_structure", {"name": name, "size": size})

@mcp.tool()
def add_structure_field(struct_name: str, field_name: str, field_type: str, offset: int = -1) -> str:
    """
    Add a field to an existing structure.

    Args:
        struct_name: Name of the existing structure to modify.
        field_name: Field name to assign.
        field_type: Field type. Accepts built-ins ("int", "uint", ...), existing
                    data type names ("MyStruct"), and pointer syntax
                    ("MyStruct *", "void **", or the Windows-style "PMyStruct").
        offset: Byte offset to insert at. -1 (default) appends to the end.
    """
    data = {
        "struct_name": struct_name,
        "field_name": field_name,
        "field_type": field_type,
    }
    if offset >= 0:
        data["offset"] = offset
    return safe_post("add_structure_field", data)

@mcp.tool()
def rename_structure(old_name: str, new_name: str) -> str:
    """
    Rename an existing structure data type.

    Args:
        old_name: Current structure name.
        new_name: New structure name. Must not collide with another data type.
    """
    return safe_post("rename_structure", {"old_name": old_name, "new_name": new_name})

@mcp.tool()
def delete_structure(name: str) -> str:
    """
    Delete a structure data type from the program's data type manager.

    References to the structure elsewhere in the program (struct fields, function
    parameters, local variables) will be replaced with undefined types.
    """
    return safe_post("delete_structure", {"name": name})

@mcp.tool()
def rename_structure_field(struct_name: str, old_field_name: str, new_field_name: str) -> str:
    """
    Rename a field in an existing structure.

    Args:
        struct_name: Name of the existing structure.
        old_field_name: Current field name. Default-generated names like "field_0x4"
                        are valid identifiers for unnamed fields.
        new_field_name: New field name. Must not collide with an existing field name
                        in the same structure.
    """
    return safe_post("rename_structure_field", {
        "struct_name": struct_name,
        "old_field_name": old_field_name,
        "new_field_name": new_field_name,
    })

@mcp.tool()
def set_field_type(struct_name: str, field_name: str, new_type: str, length: int = 0) -> str:
    """
    Change the data type of a structure field.

    If the new type is larger than the current field, subsequent components in
    the structure are absorbed; if smaller, the freed bytes become undefined.
    This is the right tool for collapsing several scalar slots into a single
    composite field (e.g. "convert four consecutive qwords into one Pubkey").

    Args:
        struct_name: Existing structure name.
        field_name: Field whose type should be replaced.
        new_type: New type. Accepts built-ins, existing data types, and pointer
                  syntax ("MyType *").
        length: Explicit byte length override. 0 (default) uses the type's
                natural length. Required for types with dynamic size.
    """
    data = {
        "struct_name": struct_name,
        "field_name": field_name,
        "new_type": new_type,
    }
    if length > 0:
        data["length"] = length
    return safe_post("set_field_type", data)

@mcp.tool()
def resize_structure_field(struct_name: str, field_name: str, new_length: int) -> str:
    """
    Change a field's length in bytes while preserving its data type.

    Growing absorbs subsequent components; shrinking turns the freed bytes into
    undefined slots.

    Args:
        struct_name: Existing structure name.
        field_name: Field to resize.
        new_length: New length in bytes (must be > 0).
    """
    return safe_post("resize_structure_field", {
        "struct_name": struct_name,
        "field_name": field_name,
        "new_length": new_length,
    })

@mcp.tool()
def delete_structure_field(struct_name: str, field_name: str) -> str:
    """
    Delete a field from an existing structure.

    Args:
        struct_name: Name of the existing structure.
        field_name: Field name to remove. Default-generated names like "field_0x4"
                    are valid identifiers for unnamed fields.
    """
    return safe_post("delete_structure_field", {
        "struct_name": struct_name,
        "field_name": field_name,
    })

@mcp.tool()
def create_structure_pointer(struct_name: str, pointer_name: str = "") -> str:
    """
    Register a pointer type for an existing structure.

    Args:
        struct_name: Name of the existing structure.
        pointer_name: Optional name for a typedef pointing at "<struct_name> *"
                      (e.g. "PMyStruct"). When empty, the bare "<struct_name> *"
                      pointer type is added to the data type manager.
    """
    data = {"struct_name": struct_name}
    if pointer_name:
        data["pointer_name"] = pointer_name
    return safe_post("create_structure_pointer", data)

@mcp.tool()
def list_structures(offset: int = 0, limit: int = 100) -> list:
    """
    List all structure data types defined in the program.
    """
    return safe_get("list_structures", {"offset": offset, "limit": limit})

@mcp.tool()
def get_structure(name: str) -> str:
    """
    Get the field layout of a structure by name.
    """
    return "\n".join(safe_get("get_structure", {"name": name}))

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

