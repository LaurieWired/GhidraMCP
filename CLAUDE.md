# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## User Communication Preferences

**Always respond to the user in Chinese**, but code should be in English, except comments. Comments should also be in Chinese.

## Project Overview

GhidraMCP is a Model Context Protocol (MCP) server that enables LLMs (like Claude) to autonomously reverse engineer applications using Ghidra's functionality. The project consists of two main components:

1. **Ghidra Plugin (Java)** - An embedded HTTP server running inside Ghidra that exposes reverse engineering capabilities
2. **MCP Bridge (Python)** - A FastMCP server that bridges the Ghidra HTTP API to MCP clients (Claude Desktop, Cline, 5ire, etc.)

## Architecture

### Ghidra Plugin (src/main/java/com/lauriewired/GhidraMCPPlugin.java)
- Single large plugin file (~1650+ lines) running an embedded HTTP server
- Default port: 8080 (configurable via Ghidra Tool Options: `Edit` -> `Tool Options` -> `GhidraMCP HTTP Server`)
- Uses Ghidra's transaction system for all program modifications
- Thread safety: All UI/modification operations use `SwingUtilities.invokeAndWait()`

### MCP Bridge (bridge_mcp_ghidra.py)
- FastMCP server using `mcp>=1.2.0`
- Communicates with Ghidra plugin via HTTP
- Supports two transport modes:
  - `stdio` (default) - For Claude Desktop and similar clients
  - `sse` - For Cline and other HTTP-based MCP clients

## Build Commands

### Development Build (requires manual Ghidra JAR setup)
```bash
# 1. Copy Ghidra JARs to lib/ directory first
cp /path/to/ghidra/Ghidra/Features/Base/lib/Base.jar lib/
cp /path/to/ghidra/Ghidra/Features/Decompiler/lib/Decompiler.jar lib/
cp /path/to/ghidra/Ghidra/Framework/Docking/lib/Docking.jar lib/
cp /path/to/ghidra/Ghidra/Framework/Generic/lib/Generic.jar lib/
cp /path/to/ghidra/Ghidra/Framework/Project/lib/Project.jar lib/
cp /path/to/ghidra/Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar lib/
cp /path/to/ghidra/Ghidra/Framework/Utility/lib/Utility.jar lib/
cp /path/to/ghidra/Ghidra/Framework/Gui/lib/Gui.jar lib/

# 2. Build with Maven
mvn clean package assembly:single
```

### CI/CD Build (GitHub Actions)
- Automatically downloads Ghidra 11.3.2, copies JARs, and builds
- No manual setup required
- Builds on push to main branch or PRs

## Testing

### Running the MCP Bridge (for manual testing)
```bash
# For Claude Desktop (stdio mode - default)
python bridge_mcp_ghidra.py --ghidra-server http://127.0.0.1:8080/

# For Cline/HTTP clients (sse mode)
python bridge_mcp_ghidra.py --transport sse --mcp-host 127.0.0.1 --mcp-port 8081 --ghidra-server http://127.0.0.1:8080/
```

### Testing HTTP Endpoints Directly
```bash
# Test connection
curl http://127.0.0.1:8080/methods

# List functions (with pagination)
curl "http://127.0.0.1:8080/methods?offset=0&limit=10"

# Decompile a function
curl -X POST http://127.0.0.1:8080/decompile -d "function_name"
```

## Key Requirements

- **Java**: JDK 21
- **Ghidra**: Version 11.3.2 (target version)
- **Python**: 3.10+
- **Maven**: For building the Java plugin

## Ghidra-Specific Patterns

### Threading Model
When modifying Ghidra program state (renaming functions, setting comments, etc.), the plugin uses:
```java
SwingUtilities.invokeAndWait(() -> {
    int txId = program.startTransaction("description");
    try {
        // Modification code here
    } finally {
        program.endTransaction(txId, true);
    }
});
```

### HTTP API Structure
- `GET` endpoints for queries (listing, searching, getting info)
- `POST` endpoints for modifications (renaming, setting comments/types)
- Most list operations support `offset` and `limit` for pagination
- Error responses return HTTP status codes with descriptive messages

## MCP Tools Registration

The Python bridge registers Ghidra HTTP endpoints as MCP tools using FastMCP decorators:
```python
@mcp.tool()
def tool_name(param: type) -> return_type:
    """Tool description for LLM."""
    return safe_get("endpoint", params)  # or safe_post()
```

## Common Operations

When adding new features:
1. Add HTTP endpoint in `GhidraMCPPlugin.java` (handle GET/POST, threading, transactions)
2. Add corresponding MCP tool in `bridge_mcp_ghidra.py` with `@mcp.tool()` decorator
3. Use `safe_get()` for GET requests, `safe_post()` for POST requests

## Planning and Documentation

**Planning Files**: All planning-related documents should be stored in the `.planning/` directory. This includes:
- Implementation plans
- Design documents
- Technical specifications
- Architecture diagrams

When starting a new feature or significant change, create a planning document in `.planning/` before implementing.

## Important Files

| File | Purpose |
|------|---------|
| `src/main/java/com/lauriewired/GhidraMCPPlugin.java` | Main Ghidra plugin with HTTP server |
| `bridge_mcp_ghidra.py` | MCP bridge server |
| `pom.xml` | Maven build configuration (Ghidra JAR dependencies) |
| `.github/workflows/build.yml` | CI/CD pipeline |
| `src/assembly/ghidra-extension.xml` | Assembly descriptor for packaging |
| `.planning/` | Planning and implementation documents |
