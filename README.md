[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/releases)
[![GitHub stars](https://img.shields.io/github/stars/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/network/members)
[![GitHub contributors](https://img.shields.io/github/contributors/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/graphs/contributors)
[![Follow @lauriewired](https://img.shields.io/twitter/follow/lauriewired?style=social)](https://twitter.com/lauriewired)

![ghidra_MCP_logo](https://github.com/user-attachments/assets/4986d702-be3f-4697-acce-aea55cd79ad3)


# ghidraMCP
ghidraMCP is an Model Context Protocol server for allowing LLMs to autonomously reverse engineer applications. It exposes numerous tools from core Ghidra functionality to MCP clients.

https://github.com/user-attachments/assets/36080514-f227-44bd-af84-78e29ee1d7f9


# Features
MCP Server + Ghidra Plugin

- Decompile and analyze binaries in Ghidra
- Automatically rename methods and data
- List methods, classes, imports, and exports

# Installation

## Prerequisites
- Install [Ghidra](https://ghidra-sre.org)
- Python3
- MCP [SDK](https://github.com/modelcontextprotocol/python-sdk)

## Ghidra
First, download the latest [release](https://github.com/LaurieWired/GhidraMCP/releases) from this repository. This contains the Ghidra plugin and Python MCP client. Then, you can directly import the plugin into Ghidra.

### Plugin Installation
1. Run Ghidra
2. Select `File` -> `Install Extensions`
3. Click the `+` button
4. Select the `GhidraMCP-1-2.zip` (or your chosen version) from the downloaded release
5. Restart Ghidra

### Plugin Configuration and Activation
**Important**: The GhidraMCP plugin operates within Ghidra's **CodeBrowser** tool, not the Project Manager.

6. **Create or open a Ghidra project** in the Project Manager
7. **Import and open a binary** for analysis (the plugin requires an active program)
8. **Open the CodeBrowser** tool (double-click your imported program or use Tools → CodeBrowser)
9. In the CodeBrowser, navigate to `File` → `Configure` → `Developer`
10. **Enable the GhidraMCPPlugin** in the Developer tools list
11. The HTTP server will start automatically when the plugin is enabled with an active program

### Server Configuration
- *Optional*: Configure the server port in CodeBrowser via `Edit` → `Tool Options` → `GhidraMCP HTTP Server`
- Default server address: `http://127.0.0.1:8080/`
- The HTTP server only runs when:
  - CodeBrowser is open
  - A program is loaded
  - GhidraMCPPlugin is enabled

### Understanding Ghidra's Architecture
Ghidra uses a multi-tool architecture:
- **Project Manager**: Manages projects and imports binaries
- **CodeBrowser**: The main analysis tool where most plugins operate
- **Other Tools**: Various specialized analysis tools

The GhidraMCP plugin specifically integrates with the CodeBrowser tool's analysis capabilities.

### Troubleshooting
**Plugin not visible in File → Configure → Developer:**
- Ensure you've restarted Ghidra after installing the extension
- Verify you're in the CodeBrowser tool, not the Project Manager
- Check that a program is loaded and active

**HTTP server not responding:**
- Confirm the plugin is enabled in CodeBrowser's Developer tools
- Verify a binary program is loaded and analyzed
- Check the server port configuration in Tool Options
- Ensure no firewall is blocking localhost connections

**"Connection refused" errors:**
- The HTTP server only starts when CodeBrowser is open with the plugin enabled
- Close and reopen CodeBrowser if the server seems stuck
- Verify the port matches your MCP client configuration

### Typical Workflow
1. **Start Ghidra Project Manager**
2. **Import your target binary** (File → Import File)
3. **Open CodeBrowser** by double-clicking the imported program
4. **Enable GhidraMCP plugin** (File → Configure → Developer)
5. **Start your MCP client** (Claude Desktop, Cline, etc.)
6. **Begin reverse engineering** with AI assistance

The HTTP server runs continuously while CodeBrowser remains open with the plugin enabled.

## Documentation

Comprehensive API documentation is available via Doxygen. See **[DOCUMENTATION.md](DOCUMENTATION.md)** for the complete documentation guide.

### Quick Access
- **HTML Documentation**: Open `docs/html/index.html` in your web browser
- **Main Plugin Class**: [GhidraMCPPlugin Documentation](docs/html/classcom_1_1lauriewired_1_1_ghidra_m_c_p_plugin.html)
- **Package Overview**: [com.lauriewired Package](docs/html/namespacecom_1_1lauriewired.html)

### Generating Updated Documentation
To regenerate documentation after code changes:
```bash
doxygen Doxyfile
```

The documentation includes:
- Complete API reference for all HTTP endpoints
- Method signatures and parameter descriptions
- Usage examples and code patterns
- Class hierarchy and relationships
- Thread safety and transaction information
- Integration examples and best practices

Video Installation Guide:


https://github.com/user-attachments/assets/75f0c176-6da1-48dc-ad96-c182eb4648c3



## MCP Clients

Theoretically, any MCP client should work with ghidraMCP.  Three examples are given below.

## Example 1: Claude Desktop
To set up Claude Desktop as a Ghidra MCP client, go to `Claude` -> `Settings` -> `Developer` -> `Edit Config` -> `claude_desktop_config.json` and add the following:

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

Alternatively, edit this file directly:
```
/Users/YOUR_USER/Library/Application Support/Claude/claude_desktop_config.json
```

The server IP and port are configurable and should be set to point to the target Ghidra instance. If not set, both will default to localhost:8080.

## Example 2: Cline
To use GhidraMCP with [Cline](https://cline.bot), this requires manually running the MCP server as well. First run the following command:

```
python bridge_mcp_ghidra.py --transport sse --mcp-host 127.0.0.1 --mcp-port 8081 --ghidra-server http://127.0.0.1:8080/
```

The only *required* argument is the transport. If all other arguments are unspecified, they will default to the above. Once the MCP server is running, open up Cline and select `MCP Servers` at the top.

![Cline select](https://github.com/user-attachments/assets/88e1f336-4729-46ee-9b81-53271e9c0ce0)

Then select `Remote Servers` and add the following, ensuring that the url matches the MCP host and port:

1. Server Name: GhidraMCP
2. Server URL: `http://127.0.0.1:8081/sse`

## Example 3: 5ire
Another MCP client that supports multiple models on the backend is [5ire](https://github.com/nanbingxyz/5ire). To set up GhidraMCP, open 5ire and go to `Tools` -> `New` and set the following configurations:

1. Tool Key: ghidra
2. Name: GhidraMCP
3. Command: `python /ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py`

# Building from Source
1. Copy the following files from your Ghidra directory to this project's `lib/` directory:
- `Ghidra/Features/Base/lib/Base.jar`
- `Ghidra/Features/Decompiler/lib/Decompiler.jar`
- `Ghidra/Framework/Docking/lib/Docking.jar`
- `Ghidra/Framework/Generic/lib/Generic.jar`
- `Ghidra/Framework/Project/lib/Project.jar`
- `Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar`
- `Ghidra/Framework/Utility/lib/Utility.jar`
- `Ghidra/Framework/Gui/lib/Gui.jar`
2. Build with Maven by running:

`mvn clean package assembly:single`

The generated zip file includes the built Ghidra plugin and its resources. These files are required for Ghidra to recognize the new extension.

- lib/GhidraMCP.jar
- extensions.properties
- Module.manifest
