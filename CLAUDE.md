# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## User Communication Preferences

**Always respond to the user in Chinese**, but code should be in English, except comments. Comments should also be in Chinese.

## Git Commit Preferences

**Do NOT add Co-Authored-By tags** (e.g., `Co-Authored-By: Claude Haiku 4.5 <noreply@anthropic.com>`) to commit messages. Keep commit messages clean without AI attribution tags.

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

### Debugging Ghidra Plugin Output

**IMPORTANT**: When debugging plugin issues, there are **two places** to check for output:

#### 1. Ghidra Console Window (Real-time)
- **Location**: `Window` → `Console` (title: "Console - Scripting")
- **What shows here**: Plugin output via `ConsoleService`
- **How to use**:
  - Use `printToConsole(message)` method in plugin code
  - Requires Ghidra to be running with GUI
  - Real-time output for debugging

#### 2. Application Log File (Persistent)
- **Location (macOS)**: `~/Library/ghidra/ghidra_12.0.1_PUBLIC/application.log`
- **Location (Linux)**: `~/.ghidra/application.log`
- **Location (Windows)**: `C:\Users\<username>\.ghidra\application.log`
- **What shows here**: All `Msg.info()`, `Msg.error()`, and exception stack traces
- **How to view**:
  ```bash
  # View latest logs
  tail -100 ~/Library/ghidra/ghidra_12.0.1_PUBLIC/application.log

  # Filter for specific plugin output
  grep "GhidraMCP" ~/Library/ghidra/ghidra_12.0.1_PUBLIC/application.log

  # View error messages only
  grep "ERROR.*GhidraMCP" ~/Library/ghidra/ghidra_12.0.1_PUBLIC/application.log
  ```

#### 3. Plugin Console Output Implementation

The plugin uses **ConsoleService** for reliable Console output:

```java
// In GhidraMCPPlugin class
private ConsoleService consoleService;

// Constructor: Get the service
public GhidraMCPPlugin(PluginTool tool) {
    super(tool);
    this.consoleService = tool.getService(ConsoleService.class);
}

// Helper method: Output to Console
private void printToConsole(String message) {
    if (consoleService != null) {
        consoleService.addMessage("GhidraMCP", message);  // (source, message)
    }
    Msg.info(this, message);  // Also log to file
}
```

**Why `System.out.println()` doesn't work**:
- Ghidra redirects standard output
- ConsoleService is the correct way to output to Ghidra's Console window
- `Msg.info()` only goes to log file, not GUI Console

#### 4. Common Debugging Issues

| Issue | Solution |
|-------|----------|
| No output in Console | Check if `consoleService` is null; verify Ghidra is running with GUI |
| Output in log file but not Console | Use `printToConsole()` instead of `Msg.info()` |
| "Paths must have non-empty elements" | Check if dataType path has double slashes (`//int`) |

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
