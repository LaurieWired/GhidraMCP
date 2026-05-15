# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

import sys
import os
import subprocess
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

# Path to Ghidra installation (set via --ghidra-path or auto-detected)
ghidra_path = None

# Default project directory for headless imports
ghidra_projects_dir = None

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

def _find_headless_analyzer():
    """Locate the analyzeHeadless script relative to Ghidra install path."""
    if ghidra_path is None:
        return None
    candidates = [
        os.path.join(ghidra_path, "support", "analyzeHeadless"),
        os.path.join(ghidra_path, "support", "analyzeHeadless.bat"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


@mcp.tool()
def import_binary(binary_path: str, project_name: str = None, project_dir: str = None,
                  analysis_timeout: int = 600) -> str:
    """
    Import a binary into a Ghidra project using headless analysis.
    Creates the project if it doesn't exist. Runs auto-analysis on the binary.

    Args:
        binary_path: Absolute path to the binary file to import.
        project_name: Name for the Ghidra project (defaults to binary filename).
        project_dir: Directory for Ghidra projects (defaults to configured projects dir).
        analysis_timeout: Timeout in seconds for analysis per file (default 600).

    Returns:
        Status message with project location and analysis summary.
    """
    headless = _find_headless_analyzer()
    if headless is None:
        return ("Error: Cannot find analyzeHeadless. "
                "Set --ghidra-path to your Ghidra installation directory.")

    if not os.path.isfile(binary_path):
        return f"Error: Binary not found: {binary_path}"

    if project_dir is None:
        project_dir = ghidra_projects_dir or os.path.join(os.path.expanduser("~"), "cerg", "projects")
    os.makedirs(project_dir, exist_ok=True)

    if project_name is None:
        base = os.path.basename(binary_path)
        project_name = base.split(".")[0].replace(" ", "_")

    cmd = [
        headless,
        project_dir,
        project_name,
        "-import", binary_path,
        "-overwrite",
        "-analysisTimeoutPerFile", str(analysis_timeout),
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=analysis_timeout + 120)
        output_lines = result.stdout.splitlines()
        # Extract key info lines
        summary = []
        for line in output_lines:
            lower = line.lower()
            if any(k in lower for k in ["import", "analyz", "error", "warning", "report", "save"]):
                summary.append(line.strip())

        status = "SUCCESS" if result.returncode == 0 else f"FAILED (exit code {result.returncode})"
        stderr_msg = ""
        if result.returncode != 0 and result.stderr:
            stderr_msg = "\n\nStderr:\n" + result.stderr[-2000:]

        return (f"Headless import {status}\n"
                f"Project: {project_dir}/{project_name}\n"
                f"Binary: {binary_path}\n\n"
                f"Output:\n" + "\n".join(summary[-30:]) + stderr_msg)
    except subprocess.TimeoutExpired:
        return f"Error: Headless analysis timed out after {analysis_timeout + 120}s"
    except Exception as e:
        return f"Error running headless analysis: {str(e)}"


@mcp.tool()
def list_projects(project_dir: str = None) -> str:
    """
    List existing Ghidra projects in the projects directory.

    Args:
        project_dir: Directory to scan (defaults to configured projects dir).

    Returns:
        List of project names and their .gpr files.
    """
    if project_dir is None:
        project_dir = ghidra_projects_dir or os.path.join(os.path.expanduser("~"), "cerg", "projects")

    if not os.path.isdir(project_dir):
        return f"Projects directory does not exist: {project_dir}"

    projects = []
    for f in sorted(os.listdir(project_dir)):
        if f.endswith(".gpr"):
            name = f[:-4]
            rep_dir = os.path.join(project_dir, name + ".rep")
            has_rep = os.path.isdir(rep_dir)
            projects.append(f"{name}  {'(valid)' if has_rep else '(no .rep)'}")

    if not projects:
        return f"No Ghidra projects found in {project_dir}"

    return f"Projects in {project_dir}:\n" + "\n".join(projects)


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
    parser.add_argument("--ghidra-path", type=str, default=None,
                        help="Path to Ghidra installation directory (for headless analysis)")
    parser.add_argument("--projects-dir", type=str, default=None,
                        help="Directory for Ghidra projects (default: ~/cerg/projects)")
    args = parser.parse_args()

    # Use the global variable to ensure it's properly updated
    global ghidra_server_url, ghidra_path, ghidra_projects_dir
    if args.ghidra_server:
        ghidra_server_url = args.ghidra_server
    if args.ghidra_path:
        ghidra_path = args.ghidra_path
    if args.projects_dir:
        ghidra_projects_dir = args.projects_dir
    
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

