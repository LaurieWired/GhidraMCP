[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/Sarks0/AutoREV)](https://github.com/Sarks0/AutoREV/releases)
[![GitHub stars](https://img.shields.io/github/stars/Sarks0/AutoREV)](https://github.com/Sarks0/AutoREV/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/Sarks0/AutoREV)](https://github.com/Sarks0/AutoREV/network/members)

![ghidra_MCP_logo](https://github.com/user-attachments/assets/4986d702-be3f-4697-acce-aea55cd79ad3)

# AutoREV (GhidraMCP)

> **Fork Notice**: This is an enhanced fork of [LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP) with additional features and automation. All credit for the original implementation goes to [LaurieWired](https://github.com/LaurieWired).

AutoREV is a Model Context Protocol (MCP) server that enables LLMs to autonomously reverse engineer applications through Ghidra. It exposes comprehensive reverse engineering tools from Ghidra's core functionality to MCP clients like Claude Desktop, Cline, and 5ire.

## Video Demo

Original demonstration by LaurieWired:

https://github.com/user-attachments/assets/36080514-f227-44bd-af84-78e29ee1d7f9

# Features

**MCP Server + Ghidra Plugin Architecture:**

## Core Reverse Engineering
- 🔍 **Decompile and analyze** binaries in Ghidra
- ✏️ **Automatically rename** functions, variables, and data
- 📋 **List and search** methods, classes, imports, exports, and strings
- 🔗 **Cross-reference analysis** for functions and data
- 💾 **Memory inspection** with segments and defined data
- 🏷️ **Namespace management** and organization

## Enhanced Features (This Fork)
- ❤️ **Health monitoring** endpoint (`/health`) - Check server and program status
- 📦 **Version information** endpoint (`/version`) - Track plugin and Ghidra versions
- 📚 **API documentation** endpoint (`/api/info`) - Self-documenting API
- 🌐 **CORS support** for web-based clients
- 📊 **JSON responses** with proper HTTP status codes
- 🤖 **Automated release monitoring** for Ghidra updates
- 🔄 **Auto-update workflows** for streamlined version management

## Supported Operations
- Decompile functions by name or address
- Disassemble functions at specific addresses
- Rename functions, variables, and data labels
- Set function prototypes and variable types
- Add comments to decompiled code and disassembly
- Search for functions by name or pattern
- Get cross-references to/from addresses
- List imports, exports, and strings with filtering

# Installation

## Prerequisites
- **[Ghidra 11.4.2](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_11.4.2_build)** or later
- **Python 3.10+**
- **JDK 21** (for building from source)
- **Maven 3.x** (for building from source)

## Ghidra Plugin Installation

### Option 1: From Release (Recommended)
1. Download the latest release ZIP from [releases](https://github.com/Sarks0/AutoREV/releases)
2. Launch Ghidra
3. Navigate to `File` → `Install Extensions`
4. Click the `+` button
5. Select the downloaded `GhidraMCP-*.zip` file
6. Restart Ghidra
7. Enable the plugin: `File` → `Configure` → `Developer` → Check **GhidraMCPPlugin**
8. _(Optional)_ Configure the server port: `Edit` → `Tool Options` → `GhidraMCP HTTP Server` → `Server Port` (default: 8080)

### Installation Video Guide

Original video by LaurieWired:

https://github.com/user-attachments/assets/75f0c176-6da1-48dc-ad96-c182eb4648c3

### Option 2: Building from Source

See the [Building from Source](#building-from-source) section below.

## Python MCP Bridge Setup

### Install Dependencies
```bash
pip install -r requirements.txt
```

The bridge requires:
- `mcp>=1.5.0` - Model Context Protocol SDK
- `requests>=2.32.3` - HTTP client library

### Testing the Connection
After installing the Ghidra plugin and starting Ghidra with a program loaded:

```bash
# Test health endpoint
curl http://localhost:8080/health

# Test version endpoint
curl http://localhost:8080/version

# Test API documentation
curl http://localhost:8080/api/info
```

## MCP Client Configuration

The MCP bridge supports multiple clients. Choose the one that fits your workflow:

### Example 1: Claude Desktop

1. Open Claude Desktop settings: `Claude` → `Settings` → `Developer` → `Edit Config`
2. Add the following to `claude_desktop_config.json`:

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

**Config file location:**
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

**Notes:**
- Replace `/ABSOLUTE_PATH_TO/` with the actual path to `bridge_mcp_ghidra.py`
- The `--ghidra-server` URL should point to your Ghidra instance (default: `http://127.0.0.1:8080/`)
- Restart Claude Desktop after configuration

### Example 2: Cline (VSCode Extension)

Cline requires running the MCP server manually in SSE (Server-Sent Events) mode:

```bash
python bridge_mcp_ghidra.py --transport sse --mcp-host 127.0.0.1 --mcp-port 8081 --ghidra-server http://127.0.0.1:8080/
```

Then in Cline:
1. Click **MCP Servers** at the top
2. Select **Remote Servers**
3. Add a new server:
   - **Server Name**: `GhidraMCP`
   - **Server URL**: `http://127.0.0.1:8081/sse`

**Available Arguments:**
- `--transport` - Transport mode: `stdio` (default) or `sse`
- `--mcp-host` - MCP server host (default: `127.0.0.1`)
- `--mcp-port` - MCP server port (default: `8081`)
- `--ghidra-server` - Ghidra plugin URL (default: `http://127.0.0.1:8080/`)

### Example 3: 5ire

[5ire](https://github.com/nanbingxyz/5ire) is a multi-model MCP client.

1. Open 5ire
2. Navigate to `Tools` → `New`
3. Configure:
   - **Tool Key**: `ghidra`
   - **Name**: `GhidraMCP`
   - **Command**: `python /ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py`

Replace `/ABSOLUTE_PATH_TO/` with the actual path to the script.

# Building from Source

## Prerequisites
- **Ghidra 11.4.2** installed on your system
- **JDK 21** (required by Ghidra 11.4.2)
- **Maven 3.x**

## Build Steps

### 1. Copy Ghidra Dependencies

Copy the following JAR files from your Ghidra installation to this project's `lib/` directory:

```bash
mkdir -p lib

# From Ghidra installation directory (e.g., /opt/ghidra_11.4.2_PUBLIC/)
cp Ghidra/Features/Base/lib/Base.jar lib/
cp Ghidra/Features/Decompiler/lib/Decompiler.jar lib/
cp Ghidra/Framework/Docking/lib/Docking.jar lib/
cp Ghidra/Framework/Generic/lib/Generic.jar lib/
cp Ghidra/Framework/Project/lib/Project.jar lib/
cp Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar lib/
cp Ghidra/Framework/Utility/lib/Utility.jar lib/
cp Ghidra/Framework/Gui/lib/Gui.jar lib/
```

### 2. Build with Maven

```bash
mvn clean package assembly:single
```

### 3. Output Files

The build process generates:
- `target/GhidraMCP.jar` - The compiled plugin
- `target/GhidraMCP-1.0-SNAPSHOT.zip` - Complete Ghidra extension package (ready for installation)

### 4. Install the Built Plugin

Follow the [Ghidra Plugin Installation](#ghidra-plugin-installation) instructions using the generated ZIP file from `target/`.

## Project Structure

```
AutoREV/
├── .github/workflows/          # CI/CD automation
│   ├── build.yml              # Build and test workflow
│   ├── check-ghidra-release.yml   # Automated Ghidra release monitoring
│   └── auto-update-ghidra.yml     # Automated version update workflow
├── src/
│   ├── main/
│   │   ├── java/              # Ghidra plugin source (Java)
│   │   ├── resources/         # Plugin metadata and manifests
│   │   └── assembly/          # Maven assembly descriptor
│   └── test/                  # Unit tests
├── lib/                       # Ghidra JARs (copied locally, not in repo)
├── bridge_mcp_ghidra.py       # Python MCP server bridge
├── pom.xml                    # Maven build configuration
├── requirements.txt           # Python dependencies
└── README.md                  # This file
```

# API Reference

## Available Endpoints

### Monitoring & Information
- `GET /health` - Server health check (JSON)
- `GET /version` - Plugin and Ghidra version info (JSON)
- `GET /api/info` - List all available endpoints

### Program Analysis
- `GET /methods?offset=0&limit=100` - List function names
- `GET /classes?offset=0&limit=100` - List class/namespace names
- `GET /list_functions?offset=0&limit=100` - Complete function listing
- `GET /segments?offset=0&limit=100` - List memory segments
- `GET /imports?offset=0&limit=100` - List imported symbols
- `GET /exports?offset=0&limit=100` - List exported symbols
- `GET /namespaces?offset=0&limit=100` - List namespaces
- `GET /data?offset=0&limit=100` - List defined data items
- `GET /strings?offset=0&limit=100&filter=text` - List strings with optional filter

### Code Analysis
- `POST /decompile` - Decompile function by name (POST body: function name)
- `GET /decompile_function?address=0x...` - Decompile by address
- `GET /disassemble_function?address=0x...` - Get assembly listing
- `GET /get_function_by_address?address=0x...` - Get function info
- `GET /searchFunctions?query=name` - Search functions by name

### Navigation & Context
- `GET /get_current_address` - Get current cursor address in Ghidra UI
- `GET /get_current_function` - Get currently selected function

### Cross-References
- `GET /xrefs_to?address=0x...&offset=0&limit=100` - References TO address
- `GET /xrefs_from?address=0x...&offset=0&limit=100` - References FROM address
- `GET /function_xrefs?name=func&offset=0&limit=100` - Function cross-references

### Modification Operations (POST)
- `POST /renameFunction` - Rename function (params: oldName, newName)
- `POST /rename_function_by_address?address=0x...&name=new` - Rename by address
- `POST /renameData` - Rename data label (params: address, newName)
- `POST /renameVariable` - Rename variable (params: functionName, oldName, newName)
- `POST /set_function_prototype` - Set function signature
- `POST /set_local_variable_type` - Change variable type
- `POST /set_decompiler_comment` - Add pseudocode comment
- `POST /set_disassembly_comment` - Add assembly comment

## MCP Tools

The Python bridge exposes 29 tools to MCP clients:

**Inspection:** `list_methods`, `list_classes`, `list_functions`, `list_segments`, `list_imports`, `list_exports`, `list_namespaces`, `list_data_items`, `list_strings`

**Analysis:** `decompile_function`, `decompile_function_by_address`, `disassemble_function`, `search_functions_by_name`, `get_function_by_address`, `get_current_address`, `get_current_function`

**Modification:** `rename_function`, `rename_function_by_address`, `rename_data`, `rename_variable`, `set_function_prototype`, `set_local_variable_type`, `set_decompiler_comment`, `set_disassembly_comment`

**Cross-References:** `get_xrefs_to`, `get_xrefs_from`, `get_function_xrefs`

**Monitoring (New):** `health_check`, `get_version`, `get_api_info`

# Automation Features

## Automated Ghidra Release Monitoring

This fork includes a GitHub Actions workflow that automatically monitors for new Ghidra releases:

- **Schedule**: Runs every Monday at 9:00 AM UTC
- **Manual Trigger**: Can be triggered manually from GitHub Actions
- **Notifications**: Creates GitHub issues when new Ghidra versions are available
- **Tracking**: Includes links to release notes and update checklists

## Auto-Update Workflow

Streamline version updates with the auto-update workflow:

1. Navigate to **Actions** → **Auto-Update Ghidra Version**
2. Click **Run workflow**
3. Enter the new Ghidra version and release date
4. The workflow will:
   - Update all configuration files
   - Test the build
   - Create a pull request with changes
   - Include build status and review checklist

This reduces manual update work by ~90%!

# Configuration

## Server Port

The default HTTP server port is **8080**. To change it:

1. In Ghidra: `Edit` → `Tool Options` → `GhidraMCP HTTP Server` → `Server Port`
2. Restart Ghidra for changes to take effect
3. Update your MCP client configuration to use the new port

## Security Considerations

⚠️ **Important Security Notes:**

- The HTTP server runs **without authentication** by default
- Recommended for **localhost/development only**
- For production/remote access:
  - Implement authentication (API keys, OAuth)
  - Use HTTPS with SSL/TLS certificates
  - Configure firewall rules
  - Restrict CORS origins
  - Enable request logging and monitoring

# Troubleshooting

## Common Issues

### Plugin Not Loading
- Ensure JDK 21 is installed (required by Ghidra 11.4.2)
- Verify the plugin is enabled: `File` → `Configure` → `Developer`
- Check Ghidra console for error messages

### Connection Refused
- Verify Ghidra is running with a program loaded
- Check the configured port (default: 8080)
- Test with: `curl http://localhost:8080/health`
- Ensure no firewall is blocking the port

### MCP Bridge Issues
- Verify Python dependencies: `pip install -r requirements.txt`
- Check the Ghidra server URL in your configuration
- Test the connection manually with curl
- Review Python bridge logs for errors

### Build Failures
- Ensure all 8 Ghidra JARs are copied to `lib/`
- Verify Maven 3.x and JDK 21 are installed
- Check for correct Ghidra version (11.4.2)
- Review Maven output for specific errors

# Contributing

Contributions are welcome! Please feel free to:

- Report bugs via [GitHub Issues](https://github.com/Sarks0/AutoREV/issues)
- Submit feature requests
- Create pull requests with improvements
- Improve documentation

## Development Setup

1. Fork this repository
2. Follow the [Building from Source](#building-from-source) instructions
3. Make your changes
4. Test thoroughly with Ghidra 11.4.2
5. Submit a pull request

# License

This project is licensed under the **Apache License 2.0** - see the [LICENSE](LICENSE) file for details.

# Credits

- **Original Author**: [LaurieWired](https://github.com/LaurieWired) - Creator of [GhidraMCP](https://github.com/LaurieWired/GhidraMCP)
- **Fork Maintainer**: [Sarks0](https://github.com/Sarks0)
- **Contributors**: See [contributors](https://github.com/Sarks0/AutoREV/graphs/contributors)

Special thanks to the [Ghidra](https://ghidra-sre.org) team at the NSA for the excellent reverse engineering framework.

# Links

- **Original Project**: [LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP)
- **This Fork**: [Sarks0/AutoREV](https://github.com/Sarks0/AutoREV)
- **Ghidra**: [https://ghidra-sre.org](https://ghidra-sre.org)
- **Model Context Protocol**: [https://modelcontextprotocol.io](https://modelcontextprotocol.io)
- **Issues**: [GitHub Issues](https://github.com/Sarks0/AutoREV/issues)
- **Releases**: [GitHub Releases](https://github.com/Sarks0/AutoREV/releases)

---

**Version**: 11.4.2 | **Last Updated**: October 2025
