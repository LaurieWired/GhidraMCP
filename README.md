[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/Sarks0/AutoREV)](https://github.com/Sarks0/AutoREV/releases)

![ghidra_MCP_logo](https://github.com/user-attachments/assets/4986d702-be3f-4697-acce-aea55cd79ad3)

# AutoREV (GhidraMCP)

> **Fork Notice**: Enhanced fork of [LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP) with additional features and automation.

AutoREV is a Model Context Protocol (MCP) server that enables LLMs to autonomously reverse engineer applications through Ghidra. It exposes Ghidra's reverse engineering functionality via HTTP endpoints to MCP clients like Claude Desktop, Cline, and 5ire.

## Video Demo

https://github.com/user-attachments/assets/36080514-f227-44bd-af84-78e29ee1d7f9

# Features

**Core Capabilities:**
- Decompile and analyze binaries
- Rename functions, variables, and data
- Search and list methods, classes, imports, exports, strings
- Cross-reference analysis
- Memory inspection and namespace management

**Enhanced (This Fork):**
- Health monitoring endpoint (`/health`)
- Version information endpoint (`/version`)
- API documentation endpoint (`/api/info`)
- CORS support and JSON responses
- Automated Ghidra release monitoring
- Auto-update workflows

# Installation

## Prerequisites
- [Ghidra 11.4.2](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_11.4.2_build) or later
- Python 3.10+
- JDK 21 (for building from source)

## Ghidra Plugin

### From Release
1. Download the latest release from [releases](https://github.com/Sarks0/AutoREV/releases)
2. Open Ghidra: `File` → `Install Extensions`
3. Click `+` and select the downloaded ZIP
4. Restart Ghidra
5. Enable plugin: `File` → `Configure` → `Developer` → Check **GhidraMCPPlugin**
6. Optional: Configure port in `Edit` → `Tool Options` → `GhidraMCP HTTP Server` (default: 8080)

### Installation Video

https://github.com/user-attachments/assets/75f0c176-6da1-48dc-ad96-c182eb4648c3

## Python MCP Bridge

```bash
pip install -r requirements.txt
```

## MCP Client Setup

### Claude Desktop

Edit `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "python",
      "args": [
        "/ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py",
        "--ghidra-server",
        "http://127.0.0.1:8080/"
      ]
    }
  }
}
```

**Config locations:**
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

### Cline

Run the MCP server in SSE mode:

```bash
python bridge_mcp_ghidra.py --transport sse --mcp-host 127.0.0.1 --mcp-port 8081 --ghidra-server http://127.0.0.1:8080/
```

In Cline: **MCP Servers** → **Remote Servers** → Add server:
- Server Name: `GhidraMCP`
- Server URL: `http://127.0.0.1:8081/sse`

### 5ire

In 5ire: `Tools` → `New`:
- Tool Key: `ghidra`
- Name: `GhidraMCP`
- Command: `python /ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py`

# Building from Source

## Copy Ghidra JARs

Copy these JARs from your Ghidra 11.4.2 installation to `lib/`:

```bash
mkdir -p lib
cp Ghidra/Features/Base/lib/Base.jar lib/
cp Ghidra/Features/Decompiler/lib/Decompiler.jar lib/
cp Ghidra/Framework/Docking/lib/Docking.jar lib/
cp Ghidra/Framework/Generic/lib/Generic.jar lib/
cp Ghidra/Framework/Project/lib/Project.jar lib/
cp Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar lib/
cp Ghidra/Framework/Utility/lib/Utility.jar lib/
cp Ghidra/Framework/Gui/lib/Gui.jar lib/
```

## Build

```bash
mvn clean package assembly:single
```

Output: `target/GhidraMCP-1.0-SNAPSHOT.zip`

# API Endpoints

## Core Endpoints
- `GET /health` - Server health and program status
- `GET /version` - Plugin and Ghidra version
- `GET /api/info` - List all available endpoints

## Analysis
- `GET /methods`, `/classes`, `/list_functions`, `/segments`, `/imports`, `/exports`, `/namespaces`, `/data`, `/strings` (with `?offset=0&limit=100`)
- `POST /decompile` - Decompile function by name
- `GET /decompile_function?address=0x...` - Decompile by address
- `GET /disassemble_function?address=0x...` - Disassemble
- `GET /searchFunctions?query=name` - Search functions

## Modification
- `POST /renameFunction`, `/rename_function_by_address`, `/renameData`, `/renameVariable`
- `POST /set_function_prototype`, `/set_local_variable_type`
- `POST /set_decompiler_comment`, `/set_disassembly_comment`

## Cross-References
- `GET /xrefs_to?address=0x...`, `/xrefs_from?address=0x...`, `/function_xrefs?name=func`

# Configuration

**Server Port:** Default is 8080. Change in Ghidra: `Edit` → `Tool Options` → `GhidraMCP HTTP Server`

**Security:** The server runs without authentication. Recommended for localhost only. For remote access, implement authentication, HTTPS, and firewall rules.

# Automation

This fork includes GitHub Actions workflows for:
- **Automated Ghidra release monitoring** (runs weekly, creates issues for new versions)
- **Auto-update workflow** (updates configuration files and creates PRs)

# Troubleshooting

**Plugin not loading:** Verify JDK 21 is installed and plugin is enabled in Ghidra

**Connection refused:** Check Ghidra is running with a program loaded, test with `curl http://localhost:8080/health`

**Build failures:** Ensure all 8 Ghidra JARs are in `lib/`, Maven 3.x and JDK 21 are installed

# Contributing

Contributions welcome via [GitHub Issues](https://github.com/Sarks0/AutoREV/issues) and pull requests.

# License

Apache License 2.0 - see [LICENSE](LICENSE)

# Credits

- **Original Author:** [LaurieWired](https://github.com/LaurieWired) - [GhidraMCP](https://github.com/LaurieWired/GhidraMCP)
- **Fork Maintainer:** [Sarks0](https://github.com/Sarks0)
- **Ghidra Team:** NSA - [ghidra-sre.org](https://ghidra-sre.org)

# Links

- [Original Project](https://github.com/LaurieWired/GhidraMCP)
- [This Fork](https://github.com/Sarks0/AutoREV)
- [Ghidra](https://ghidra-sre.org)
- [Model Context Protocol](https://modelcontextprotocol.io)
