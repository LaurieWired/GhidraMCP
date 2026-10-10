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
- Install [Ghidra](https://ghidra-sre.org) 12.1.4
- Install [uv](https://docs.astral.sh/uv/) (or Python 3.10+ with `pip install git+https://github.com/LaurieWired/GhidraMCP`, then use `ghidra-mcp` as the command below)

## Ghidra
First, download the latest [release](https://github.com/LaurieWired/GhidraMCP/releases) from this repository. This contains the Ghidra plugin and Python MCP client. Then, you can directly import the plugin into Ghidra.

1. Run Ghidra
2. Select `File` -> `Install Extensions`
3. Click the `+` button
4. Select the `ghidra_12.1.4_PUBLIC_<date>_GhidraMCP.zip` from the downloaded release
5. Restart Ghidra
6. Make sure the GhidraMCPPlugin is enabled in `File` -> `Configure` -> `Developer`
7. *Optional*: Configure the port in Ghidra with `Edit` -> `Tool Options` -> `GhidraMCP HTTP Server`

Video Installation Guide:


https://github.com/user-attachments/assets/75f0c176-6da1-48dc-ad96-c182eb4648c3



## MCP Clients

Theoretically, any MCP client should work with ghidraMCP. Most clients accept a JSON config like the following:

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/LaurieWired/GhidraMCP",
        "ghidra-mcp",
        "--ghidra-server",
        "http://127.0.0.1:8080/"
      ]
    }
  }
}
```

The server IP and port are configurable and should be set to point to the target Ghidra instance. If not set, both will default to localhost:8080.

For clients that connect to a URL instead of launching a command, first run the MCP server yourself:

```
uvx --from git+https://github.com/LaurieWired/GhidraMCP ghidra-mcp --transport streamable-http --mcp-host 127.0.0.1 --mcp-port 8081 --ghidra-server http://127.0.0.1:8080/
```

Then add `http://127.0.0.1:8081/mcp` as a remote server in your client.

## Example 1: VS Code
Run `MCP: Add Server` from the Command Palette, or add the following to `.vscode/mcp.json` in your workspace:

```json
{
  "servers": {
    "ghidra": {
      "type": "stdio",
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/LaurieWired/GhidraMCP",
        "ghidra-mcp",
        "--ghidra-server",
        "http://127.0.0.1:8080/"
      ]
    }
  }
}
```

## Example 2: Claude Code
Run the following command:

```
claude mcp add ghidra -- uvx --from git+https://github.com/LaurieWired/GhidraMCP ghidra-mcp --ghidra-server http://127.0.0.1:8080/
```

## Headless (no Ghidra GUI)
`ghidra-mcp` can also import and analyze a binary itself using [PyGhidra](https://pypi.org/project/pyghidra/), with no Ghidra GUI running. This needs Python 3.10–3.13, the GhidraMCP extension installed in Ghidra (or `--extension-jar /path/to/GhidraMCP.jar`), and `GHIDRA_INSTALL_DIR` set to your Ghidra 12.1.4 directory:

```
uvx --python 3.13 --from "ghidra-mcp[headless] @ git+https://github.com/LaurieWired/GhidraMCP" ghidra-mcp --headless --binary /path/to/target
```

Use the same command and arguments in any of the client configs above. Add `--project DIR` to keep the Ghidra project (and save changes) between runs. On macOS, build Ghidra's decompiler once with `support/gradle/gradlew buildNatives` from the Ghidra directory.

# Building from Source
1. Set `GHIDRA_INSTALL_DIR` to your Ghidra 12.1.4 directory
2. Build the extension with Gradle (Java 21) by running:

`cd extension && $GHIDRA_INSTALL_DIR/support/gradle/gradlew buildExtension`

The generated zip file in `extension/dist/` includes the built Ghidra plugin and its resources. These files are required for Ghidra to recognize the new extension.

- lib/GhidraMCP.jar
- extension.properties
- Module.manifest

The Python MCP server can be run from a checkout with `uv run ghidra-mcp`, and tested with `uv run pytest`.
