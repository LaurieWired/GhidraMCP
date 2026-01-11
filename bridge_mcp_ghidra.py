# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "httpx>=0.27.0",
#     "tenacity>=8.2.0",
#     "mcp>=1.2.0,<2",
# ]
# ///

import sys
import httpx
import argparse
import logging
from urllib.parse import urljoin
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from mcp.server.fastmcp import FastMCP

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080/"
PORT_RANGE = range(8080, 8090)

logger = logging.getLogger(__name__)

mcp = FastMCP("ghidra-mcp")

# Initialize ghidra_server_url with default value
ghidra_server_url = DEFAULT_GHIDRA_SERVER

# Multi-instance support
active_instances = {}  # Maps program name -> {"port": int, "url": str}
primary_port = 8080

def discover_instances():
    """Scan port range to discover active Ghidra instances."""
    global active_instances, primary_port
    instances = {}
    for port in PORT_RANGE:
        try:
            url = f"http://127.0.0.1:{port}/"
            response = httpx.get(urljoin(url, "get_current_address"), timeout=1.0)
            if response.status_code == 200:
                program_name = f"program@{port}"
                instances[program_name] = {"port": port, "url": url}
                if not active_instances:
                    primary_port = port
        except:
            continue
    active_instances = instances
    return instances

def get_instance_url(target_binary=None):
    """Get the base URL for the target binary instance."""
    if target_binary and target_binary in active_instances:
        return active_instances[target_binary]["url"]
    if target_binary:
        discover_instances()
        if target_binary in active_instances:
            return active_instances[target_binary]["url"]
    return f"http://127.0.0.1:{primary_port}/"

# HTTP client with connection pooling
_http_client = None

def get_http_client():
    global _http_client
    if _http_client is None:
        _http_client = httpx.Client(
            timeout=30.0,
            limits=httpx.Limits(max_keepalive_connections=5, max_connections=10)
        )
    return _http_client

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    retry=retry_if_exception_type((httpx.ConnectError, httpx.ConnectTimeout)),
    reraise=True,
)
def safe_get(endpoint: str, params: dict = None, target_binary: str = None) -> list:
    """
    Perform a GET request with optional query parameters.
    """
    if params is None:
        params = {}

    url = urljoin(get_instance_url(target_binary), endpoint)

    try:
        response = get_http_client().get(url, params=params)
        response.encoding = 'utf-8'
        if response.status_code == 200:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    retry=retry_if_exception_type((httpx.ConnectError, httpx.ConnectTimeout)),
    reraise=True,
)
def safe_post(endpoint: str, data: dict | str, target_binary: str = None) -> str:
    try:
        url = urljoin(get_instance_url(target_binary), endpoint)
        if isinstance(data, dict):
            response = get_http_client().post(url, data=data)
        else:
            response = get_http_client().post(url, content=data.encode("utf-8"))
        response.encoding = 'utf-8'
        if response.status_code == 200:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

@mcp.tool()
def list_ghidra_instances() -> list:
    """
    List all active Ghidra instances.
    Use this to find which target_binary values are available.
    """
    instances = discover_instances()
    return [{"target_binary": name, "port": info["port"], "url": info["url"]} 
            for name, info in instances.items()]

@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100, target_binary: str = None) -> list:
    """
    List all function names in the program with pagination.
    Provide target_binary if multiple Ghidra windows are open.
    """
    return safe_get("methods", {"offset": offset, "limit": limit}, target_binary)

@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100, target_binary: str = None) -> list:
    """
    List all namespace/class names in the program with pagination.
    Provide target_binary if multiple Ghidra windows are open.
    """
    return safe_get("classes", {"offset": offset, "limit": limit}, target_binary)

@mcp.tool()
def decompile_function(name: str, target_binary: str = None) -> str:
    """
    Decompile a specific function by name and return the decompiled C code.
    Provide target_binary if multiple Ghidra windows are open.
    """
    return safe_post("decompile", name, target_binary)

@mcp.tool()
def rename_function(old_name: str, new_name: str, target_binary: str = None) -> str:
    """
    Rename a function by its current name to a new user-defined name.
    Provide target_binary if multiple Ghidra windows are open.
    """
    return safe_post("renameFunction", {"oldName": old_name, "newName": new_name}, target_binary)

@mcp.tool()
def rename_data(address: str, new_name: str, target_binary: str = None) -> str:
    """
    Rename a data label at the specified address.
    Provide target_binary if multiple Ghidra windows are open.
    """
    return safe_post("renameData", {"address": address, "newName": new_name}, target_binary)

@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100, target_binary: str = None) -> list:
    """
    List all memory segments in the program with pagination.
    Provide target_binary if multiple Ghidra windows are open.
    """
    return safe_get("segments", {"offset": offset, "limit": limit}, target_binary)

@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100, target_binary: str = None) -> list:
    """
    List imported symbols in the program with pagination.
    Provide target_binary if multiple Ghidra windows are open.
    """
    return safe_get("imports", {"offset": offset, "limit": limit}, target_binary)

@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100, target_binary: str = None) -> list:
    """
    List exported functions/symbols with pagination.
    Provide target_binary if multiple Ghidra windows are open.
    """
    return safe_get("exports", {"offset": offset, "limit": limit}, target_binary)

@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100, target_binary: str = None) -> list:
    """
    List all non-global namespaces in the program with pagination.
    Provide target_binary if multiple Ghidra windows are open.
    """
    return safe_get("namespaces", {"offset": offset, "limit": limit}, target_binary)

@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100, target_binary: str = None) -> list:
    """
    List defined data labels and their values with pagination.
    Provide target_binary if multiple Ghidra windows are open.
    """
    return safe_get("data", {"offset": offset, "limit": limit}, target_binary)

@mcp.tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100, target_binary: str = None) -> list:
    """
    Search for functions whose name contains the given substring.
    Provide target_binary if multiple Ghidra windows are open.
    """
    if not query:
        return ["Error: query string is required"]
    return safe_get("searchFunctions", {"query": query, "offset": offset, "limit": limit}, target_binary)

@mcp.tool()
def rename_variable(function_name: str, old_name: str, new_name: str, target_binary: str = None) -> str:
    """
    Rename a local variable within a function.
    Provide target_binary if multiple Ghidra windows are open.
    """
    return safe_post("renameVariable", {
        "functionName": function_name,
        "oldName": old_name,
        "newName": new_name
    }, target_binary)

@mcp.tool()
def get_function_by_address(address: str, target_binary: str = None) -> str:
    """
    Get a function by its address.
    Provide target_binary if multiple Ghidra windows are open.
    """
    return "\n".join(safe_get("get_function_by_address", {"address": address}, target_binary))

@mcp.tool()
def get_current_address(target_binary: str = None) -> str:
    """
    Get the address currently selected by the user.
    Provide target_binary if multiple Ghidra windows are open.
    """
    return "\n".join(safe_get("get_current_address", None, target_binary))

@mcp.tool()
def get_current_function(target_binary: str = None) -> str:
    """
    Get the function currently selected by the user.
    Provide target_binary if multiple Ghidra windows are open.
    """
    return "\n".join(safe_get("get_current_function", None, target_binary))

@mcp.tool()
def list_functions(offset: int = 0, limit: int = 100, target_binary: str = None) -> list:
    """
    List all functions in the database.
    Provide target_binary if multiple Ghidra windows are open.
    """
    return safe_get("list_functions", {"offset": offset, "limit": limit}, target_binary)

@mcp.tool()
def decompile_function_by_address(address: str, target_binary: str = None) -> str:
    """
    Decompile a function at the given address.
    Provide target_binary if multiple Ghidra windows are open.
    """
    return "\n".join(safe_get("decompile_function", {"address": address}, target_binary))

@mcp.tool()
def disassemble_function(address: str, target_binary: str = None) -> list:
    """
    Get assembly code (address: instruction; comment) for a function.
    Provide target_binary if multiple Ghidra windows are open.
    """
    return safe_get("disassemble_function", {"address": address}, target_binary)

@mcp.tool()
def set_decompiler_comment(address: str, comment: str, target_binary: str = None) -> str:
    """
    Set a comment for a given address in the function pseudocode.
    Provide target_binary if multiple Ghidra windows are open.
    """
    return safe_post("set_decompiler_comment", {"address": address, "comment": comment}, target_binary)

@mcp.tool()
def set_disassembly_comment(address: str, comment: str, target_binary: str = None) -> str:
    """
    Set a comment for a given address in the function disassembly.
    Provide target_binary if multiple Ghidra windows are open.
    """
    return safe_post("set_disassembly_comment", {"address": address, "comment": comment}, target_binary)

@mcp.tool()
def rename_function_by_address(function_address: str, new_name: str, target_binary: str = None) -> str:
    """
    Rename a function by its address.
    Provide target_binary if multiple Ghidra windows are open.
    """
    return safe_post("rename_function_by_address", {"function_address": function_address, "new_name": new_name}, target_binary)

@mcp.tool()
def set_function_prototype(function_address: str, prototype: str, target_binary: str = None) -> str:
    """
    Set a function's prototype.
    Provide target_binary if multiple Ghidra windows are open.
    """
    return safe_post("set_function_prototype", {"function_address": function_address, "prototype": prototype}, target_binary)

@mcp.tool()
def set_local_variable_type(function_address: str, variable_name: str, new_type: str, target_binary: str = None) -> str:
    """
    Set a local variable's type.
    Provide target_binary if multiple Ghidra windows are open.
    """
    return safe_post("set_local_variable_type", {"function_address": function_address, "variable_name": variable_name, "new_type": new_type}, target_binary)

@mcp.tool()
def get_xrefs_to(address: str, offset: int = 0, limit: int = 100, target_binary: str = None) -> list:
    """
    Get all references to the specified address (xref to).
    
    Args:
        address: Target address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        target_binary: Target Ghidra instance (from list_ghidra_instances)
        
    Returns:
        List of references to the specified address
    """
    return safe_get("xrefs_to", {"address": address, "offset": offset, "limit": limit}, target_binary)

@mcp.tool()
def get_xrefs_from(address: str, offset: int = 0, limit: int = 100, target_binary: str = None) -> list:
    """
    Get all references from the specified address (xref from).
    
    Args:
        address: Source address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        target_binary: Target Ghidra instance (from list_ghidra_instances)
        
    Returns:
        List of references from the specified address
    """
    return safe_get("xrefs_from", {"address": address, "offset": offset, "limit": limit}, target_binary)

@mcp.tool()
def get_function_xrefs(name: str, offset: int = 0, limit: int = 100, target_binary: str = None) -> list:
    """
    Get all references to the specified function by name.
    
    Args:
        name: Function name to search for
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        target_binary: Target Ghidra instance (from list_ghidra_instances)
        
    Returns:
        List of references to the specified function
    """
    return safe_get("function_xrefs", {"name": name, "offset": offset, "limit": limit}, target_binary)

@mcp.tool()
def list_strings(offset: int = 0, limit: int = 2000, filter: str = None, target_binary: str = None) -> list:
    """
    List all defined strings in the program with their addresses.
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of strings to return (default: 2000)
        filter: Optional filter to match within string content
        target_binary: Target Ghidra instance (from list_ghidra_instances)
        
    Returns:
        List of strings with their addresses
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return safe_get("strings", params, target_binary)

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
    global ghidra_server_url, primary_port
    if args.ghidra_server:
        ghidra_server_url = args.ghidra_server
        try:
            from urllib.parse import urlparse
            parsed = urlparse(args.ghidra_server)
            if parsed.port:
                primary_port = parsed.port
        except:
            pass
    
    # Discover instances on startup
    logging.basicConfig(level=logging.INFO)
    logger.info("Discovering Ghidra instances...")
    instances = discover_instances()
    if instances:
        logger.info(f"Found {len(instances)} instance(s): {list(instances.keys())}")
    else:
        logger.info("No active instances found, using default port")
    
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

