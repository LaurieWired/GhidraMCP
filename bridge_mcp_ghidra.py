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

def safe_post(endpoint: str, data: dict | str, params: dict = None) -> str:
    try:
        url = urljoin(ghidra_server_url, endpoint)
        if isinstance(data, dict):
            response = requests.post(url, data=data, params=params, timeout=5)
        else:
            response = requests.post(url, data=data.encode("utf-8"), params=params, timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

def _with_program(params: dict, program: str) -> dict:
    """Attach the optional 'program' selector to a params dict when provided."""
    if program:
        params = dict(params)
        params["program"] = program
    return params

# Note on the `program` argument (present on every tool below):
# Ghidra can have several binaries open at once. Leave `program` empty ("") to
# act on the currently focused program (the original behavior). Pass a program
# name or project path (see list_open_programs) to target a specific binary,
# so multiple loaded binaries can be analyzed without switching tabs.

@mcp.tool()
def list_open_programs() -> list:
    """
    List all programs currently open in Ghidra. Each line is
    "name<TAB>path[<TAB>(current)]". Use a name or path as the `program`
    argument of other tools to target a specific binary.
    """
    return safe_get("list_open_programs")

@mcp.tool()
def get_current_program() -> str:
    """
    Get the name and path of the currently focused program in Ghidra.
    """
    return "\n".join(safe_get("get_current_program"))

@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100, program: str = "") -> list:
    """
    List all function names in the program with pagination.
    """
    return safe_get("methods", _with_program({"offset": offset, "limit": limit}, program))

@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100, program: str = "") -> list:
    """
    List all namespace/class names in the program with pagination.
    """
    return safe_get("classes", _with_program({"offset": offset, "limit": limit}, program))

@mcp.tool()
def decompile_function(name: str, program: str = "") -> str:
    """
    Decompile a specific function by name and return the decompiled C code.
    """
    return safe_post("decompile", name, _with_program({}, program))

@mcp.tool()
def rename_function(old_name: str, new_name: str, program: str = "") -> str:
    """
    Rename a function by its current name to a new user-defined name.
    """
    return safe_post("renameFunction", _with_program({"oldName": old_name, "newName": new_name}, program))

@mcp.tool()
def rename_data(address: str, new_name: str, program: str = "") -> str:
    """
    Rename a data label at the specified address.
    """
    return safe_post("renameData", _with_program({"address": address, "newName": new_name}, program))

@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100, program: str = "") -> list:
    """
    List all memory segments in the program with pagination.
    """
    return safe_get("segments", _with_program({"offset": offset, "limit": limit}, program))

@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100, program: str = "") -> list:
    """
    List imported symbols in the program with pagination.
    """
    return safe_get("imports", _with_program({"offset": offset, "limit": limit}, program))

@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100, program: str = "") -> list:
    """
    List exported functions/symbols with pagination.
    """
    return safe_get("exports", _with_program({"offset": offset, "limit": limit}, program))

@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100, program: str = "") -> list:
    """
    List all non-global namespaces in the program with pagination.
    """
    return safe_get("namespaces", _with_program({"offset": offset, "limit": limit}, program))

@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100, program: str = "") -> list:
    """
    List defined data labels and their values with pagination.
    """
    return safe_get("data", _with_program({"offset": offset, "limit": limit}, program))

@mcp.tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100, program: str = "") -> list:
    """
    Search for functions whose name contains the given substring.
    """
    if not query:
        return ["Error: query string is required"]
    return safe_get("searchFunctions", _with_program({"query": query, "offset": offset, "limit": limit}, program))

@mcp.tool()
def rename_variable(function_name: str, old_name: str, new_name: str, program: str = "") -> str:
    """
    Rename a local variable within a function.
    """
    return safe_post("renameVariable", _with_program({
        "functionName": function_name,
        "oldName": old_name,
        "newName": new_name
    }, program))

@mcp.tool()
def get_function_by_address(address: str, program: str = "") -> str:
    """
    Get a function by its address.
    """
    return "\n".join(safe_get("get_function_by_address", _with_program({"address": address}, program)))

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
def list_functions(program: str = "") -> list:
    """
    List all functions in the database.
    """
    return safe_get("list_functions", _with_program({}, program))

@mcp.tool()
def decompile_function_by_address(address: str, program: str = "") -> str:
    """
    Decompile a function at the given address.
    """
    return "\n".join(safe_get("decompile_function", _with_program({"address": address}, program)))

@mcp.tool()
def disassemble_function(address: str, program: str = "") -> list:
    """
    Get assembly code (address: instruction; comment) for a function.
    """
    return safe_get("disassemble_function", _with_program({"address": address}, program))

@mcp.tool()
def set_decompiler_comment(address: str, comment: str, program: str = "") -> str:
    """
    Set a comment for a given address in the function pseudocode.
    """
    return safe_post("set_decompiler_comment", _with_program({"address": address, "comment": comment}, program))

@mcp.tool()
def set_disassembly_comment(address: str, comment: str, program: str = "") -> str:
    """
    Set a comment for a given address in the function disassembly.
    """
    return safe_post("set_disassembly_comment", _with_program({"address": address, "comment": comment}, program))

@mcp.tool()
def rename_function_by_address(function_address: str, new_name: str, program: str = "") -> str:
    """
    Rename a function by its address.
    """
    return safe_post("rename_function_by_address", _with_program({"function_address": function_address, "new_name": new_name}, program))

@mcp.tool()
def set_function_prototype(function_address: str, prototype: str, program: str = "") -> str:
    """
    Set a function's prototype.
    """
    return safe_post("set_function_prototype", _with_program({"function_address": function_address, "prototype": prototype}, program))

@mcp.tool()
def set_local_variable_type(function_address: str, variable_name: str, new_type: str, program: str = "") -> str:
    """
    Set a local variable's type.
    """
    return safe_post("set_local_variable_type", _with_program({"function_address": function_address, "variable_name": variable_name, "new_type": new_type}, program))

@mcp.tool()
def get_xrefs_to(address: str, offset: int = 0, limit: int = 100, program: str = "") -> list:
    """
    Get all references to the specified address (xref to).

    Args:
        address: Target address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        program: Optional program selector (see list_open_programs); empty = current

    Returns:
        List of references to the specified address
    """
    return safe_get("xrefs_to", _with_program({"address": address, "offset": offset, "limit": limit}, program))

@mcp.tool()
def get_xrefs_from(address: str, offset: int = 0, limit: int = 100, program: str = "") -> list:
    """
    Get all references from the specified address (xref from).

    Args:
        address: Source address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        program: Optional program selector (see list_open_programs); empty = current

    Returns:
        List of references from the specified address
    """
    return safe_get("xrefs_from", _with_program({"address": address, "offset": offset, "limit": limit}, program))

@mcp.tool()
def get_function_xrefs(name: str, offset: int = 0, limit: int = 100, program: str = "") -> list:
    """
    Get all references to the specified function by name.

    Args:
        name: Function name to search for
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        program: Optional program selector (see list_open_programs); empty = current

    Returns:
        List of references to the specified function
    """
    return safe_get("function_xrefs", _with_program({"name": name, "offset": offset, "limit": limit}, program))

@mcp.tool()
def list_strings(offset: int = 0, limit: int = 2000, filter: str = None, program: str = "") -> list:
    """
    List all defined strings in the program with their addresses.

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of strings to return (default: 2000)
        filter: Optional filter to match within string content
        program: Optional program selector (see list_open_programs); empty = current

    Returns:
        List of strings with their addresses
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return safe_get("strings", _with_program(params, program))

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
