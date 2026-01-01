# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Ghidra MCP Server is a production-ready Model Context Protocol (MCP) server that bridges Ghidra's reverse engineering capabilities with AI tools. It exposes **111 MCP tools** for binary analysis plus **7 script lifecycle management tools** for batch automation and automatic troubleshooting. The hybrid MCP/Script architecture enables 10x performance improvement on repetitive tasks through dual-layer access: a Java plugin running in Ghidra that provides REST endpoints, and a Python bridge that implements the MCP protocol.

**Current Version**: Configured in `pom.xml`
**Package**: com.xebyte
**Ghidra Version**: 11.4.2
**Java Version**: 21 LTS
**Python Version**: 3.8+
**MCP Protocol**: stdio (default) and SSE transports
**Features**: 105 core MCP tools + 6 script lifecycle tools (save, list, get, run, update, delete) for complete automation

## Architecture

### Three-Layer System

1. **Ghidra Java Plugin** (`src/main/java/com/xebyte/GhidraMCPPlugin.java`)
   - Embedded HTTP server running on port 8089 (configurable)
   - Exposes Ghidra's reverse engineering API as REST endpoints
   - Single-file plugin (~10,900 lines) with 107 endpoints (105 analysis + 1 generation + 1 execution)
   - Handles function analysis, decompilation, symbols, data types, cross-references
   - Script generation for batch automation (10x performance on bulk operations)
   - Script execution with validation and error reporting for automatic troubleshooting
   - Batch operations: atomic transactions with 93% API call reduction

2. **Python MCP Bridge** (`bridge_mcp_ghidra.py`)
   - Translates REST API to MCP protocol using FastMCP framework
   - **111 MCP tools** exposed to AI assistants (105 analysis + 1 generation + 6 lifecycle)
   - `generate_ghidra_script()` for batch automation workflows
   - Complete script lifecycle management (save, list, get, run, update, delete)
   - Implements connection pooling, retry logic, request caching
   - **Dynamic timeout calculation**: Automatically scales timeouts based on operation complexity (14 variables = 600s vs 5 variables = 307s)
   - Input validation and security restrictions (localhost-only connections)
   - Two transport modes: stdio (default, for AI tools) and SSE (for web clients)

3. **Java Build System** (Maven-based)
   - System-scoped dependencies to Ghidra JARs in `lib/`
   - Custom assembly descriptor for Ghidra extension ZIP format
   - Fixed JAR name: `GhidraMCP.jar` (version-independent)

### Critical Architecture Details

- **Ghidra libraries must be copied first**: Before building, run `copy-ghidra-libs.bat` on Windows to copy JARs from your Ghidra installation to `lib/`
- **Plugin loads at Ghidra startup**: The Java plugin starts automatically when Ghidra launches if properly installed
- **REST API is stateful**: All operations work on the currently open program in Ghidra's CodeBrowser
- **MCP bridge is stateless**: Each MCP tool call translates to one or more HTTP requests

## Build and Development

### Initial Setup

```bash
# 1. Copy Ghidra libraries (required before first build)
copy-ghidra-libs.bat "C:\path\to\ghidra"

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Build the Java plugin
mvn clean package assembly:single
```

This produces:
- `target/GhidraMCP.jar` - The plugin JAR
- `target/GhidraMCP.zip` - Ghidra extension package

### Testing

```bash
# Unit tests only (no Ghidra required) - 66 tests
pytest tests/unit/

# Integration tests (requires running Ghidra with plugin and loaded binary)
pytest tests/integration/

# Functional end-to-end tests (requires Ghidra + binary)
pytest tests/functional/

# Run specific test file
pytest tests/unit/test_api_client.py

# Run with coverage
pytest tests/ --cov=src --cov-report=html
```

**Test Architecture**: Tests follow the Test Pyramid pattern:
- `tests/unit/` - Fast, isolated component tests (no dependencies)
- `tests/integration/` - REST API endpoint tests (requires Ghidra server)
- `tests/functional/` - Complete workflow tests (requires Ghidra + binary)

### Deployment to Ghidra

Automated installation (recommended):
```powershell
# Windows - automatically detects version and Ghidra installation
.\deploy-to-ghidra.ps1
```

Manual installation:
```bash
# Option 1: Copy JAR to Ghidra extensions
cp target/GhidraMCP.jar "<ghidra_install>/Extensions/Ghidra/"

# Option 2: Install ZIP via Ghidra GUI
# File → Install Extensions → Add Extension → Select GhidraMCP.zip
```

### Running the MCP Bridge

```bash
# Stdio transport (default, for AI tools like Claude)
python bridge_mcp_ghidra.py

# SSE transport (for web/HTTP clients)
python bridge_mcp_ghidra.py --transport sse --mcp-host 127.0.0.1 --mcp-port 8081

# Custom Ghidra server URL
python bridge_mcp_ghidra.py --ghidra-server http://127.0.0.1:8089/
```

## Version Management

This project uses **Maven-based version management** with a single source of truth. This section documents the complete versioning workflow.

### Architecture: Single Source of Truth ✅

**The system works like this:**

1. Developer edits pom.xml (version tag only)
2. Maven build processes resources
3. Maven substitutes ${project.version} in property files
4. Java plugin loads correct version at runtime
5. All APIs report version dynamically (no hardcoding)

### How to Update Project Version

**When you need to release a new version (e.g., X.Y.Z → X.Y.Z+1):**

#### Step 1: Update `pom.xml` (This is the ONLY file you manually edit)

```xml
<!-- File: pom.xml -->
<project>
    <version>X.Y.Z</version>  <!-- ← Change this only (use semantic versioning) -->
    <!-- Rest of pom.xml unchanged -->
</project>
```

#### Step 2: Build (Maven handles everything else automatically)

```bash
mvn clean package assembly:single
```

**That's it!** Maven automatically:

- ✅ Substitutes version in `src/main/resources/version.properties`
- ✅ Substitutes version in `src/main/resources/extension.properties`
- ✅ Java plugin loads correct version at runtime via `VersionInfo` class
- ✅ ZIP artifact names include version: `GhidraMCP-X.Y.Z.zip`
- ✅ All REST APIs report correct version dynamically

### Files Involved in Version Management

These files work together to implement version management. **You only edit `pom.xml`; the rest are handled automatically by Maven:**

| File | Purpose | What You Do |
|------|---------|------------|
| `pom.xml` | **Single source of truth** | ✏️ **Edit version here only** |
| `src/main/resources/version.properties` | Runtime version source for Java plugin | 🔄 Maven auto-substitutes `${project.version}` |
| `src/main/resources/extension.properties` | Ghidra extension metadata | 🔄 Maven auto-substitutes `${project.version}` |
| `src/main/java/com/xebyte/GhidraMCPPlugin.java` | Plugin code with `VersionInfo` class | 🔍 Loads version dynamically at runtime |
| `CHANGELOG.md` | Version history and release notes | 📝 Update manually for each release |
| `README.md` | User documentation | ✅ No version refs (generic) |
| `CLAUDE.md` | AI guidance (this file) | ✅ No version refs (generic) |
| Other documentation files | User guides, references, examples | ✅ All generic (no version refs) |

### What Each File Does

#### **`pom.xml` (The Control Center)**

- Contains `<version>X.Y.Z</version>` - This is what you change
- Maven reads this value and substitutes it everywhere else
- Build command: `mvn clean package assembly:single`

#### **`src/main/resources/version.properties` (Runtime Source)**

```properties
app.version=${project.version}  # Maven substitutes current version from pom.xml
app.name=GhidraMCP
app.description=Production-ready MCP server for Ghidra
ghidra.version=11.4.2
java.version=21
```

- Created by Maven resource filtering during build
- Read by `VersionInfo` class in Java plugin
- Available to REST APIs for version reporting

#### **`src/main/resources/extension.properties` (Ghidra Metadata)**

```properties
version=${project.version}  # Maven substitutes current version from pom.xml
name=GhidraMCP
description=Production-ready MCP server for Ghidra
```

- Tells Ghidra the plugin version
- Substituted by Maven during build

#### **`GhidraMCPPlugin.java` (Dynamic Loading)**

- Contains `VersionInfo` class that loads version from `version.properties` at plugin startup
- `getVersion()` method returns the version loaded from properties
- REST `/version` endpoint uses this to report current version
- No hardcoded version strings anywhere in code

#### **`CHANGELOG.md` (Release Notes)**

```markdown
## [X.Y.Z] - YYYY-MM-DD

### Added
- New feature description

### Fixed
- Bug fix description

### Changed
- Behavior change description
```

- Only documentation file that should reference versions
- Manually updated with each release
- Helps users understand what changed in each version

#### **Documentation Files (Generic)**

- `README.md`, `START_HERE.md`, all `docs/` files: Reference version generically or not at all
- Exceptions: Any file that lists historical versions (like CHANGELOG.md)
- Benefit: Documentation stays evergreen and requires no updates when version changes

### Complete Version Update Workflow

```bash
# 1. Update version in pom.xml
vim pom.xml
# Change <version>CURRENT</version> to <version>NEW_VERSION</version>
# Save file

# 2. Update CHANGELOG.md with release notes
vim CHANGELOG.md
# Add new [NEW_VERSION] section at top with features/fixes
# Save file

# 3. Build (Maven handles version substitution automatically)
mvn clean package assembly:single

# 4. Verify build artifacts
ls -lh target/GhidraMCP-NEW_VERSION.zip  # Should exist with new version
# Check: target/GhidraMCP.jar and target/GhidraMCP-NEW_VERSION.zip created

# 5. Commit and tag
git add pom.xml CHANGELOG.md
git commit -m "Release vNEW_VERSION"
git tag vNEW_VERSION
git push --tags

# 6. Deploy
# Copy target/GhidraMCP-NEW_VERSION.zip to release/distribution
# Or use: .\deploy-to-ghidra.ps1
```

### Key Principles

✅ **Single Point of Edit**: Only `pom.xml` needs manual version updates  
✅ **Automatic Consistency**: Maven ensures version is correct everywhere  
✅ **Zero Manual File Edits**: No need to manually update 20+ version references  
✅ **Build-Verified**: Maven build succeeds only if substitution works  
✅ **Runtime Dynamic**: Java plugin loads version at startup, always current  
✅ **Documentation Generic**: Docs stay clean, version-agnostic, evergreen  

### Troubleshooting Version Issues

**Q: ZIP file still has old version name?**
```bash
# A: Maven caches. Do a clean build:
mvn clean package assembly:single
# Check target/ directory for new versioned ZIP
```

**Q: Plugin reports old version at runtime?**
```bash
# A: Ghidra caches the old plugin. Restart Ghidra completely:
# 1. Close Ghidra
# 2. Delete old plugin from Ghidra extensions folder
# 3. Copy new GhidraMCP.jar or install new ZIP
# 4. Restart Ghidra
```

**Q: Which files should NOT have version numbers?**
```
These files should NOT contain hardcoded version numbers:
- README.md (use "Latest" or generic language)
- START_HERE.md (use "Current implementation" or generic)
- CLAUDE.md (use "Configured in pom.xml")
- docs/TOOL_REFERENCE.md (examples show generic "X.Y.Z")
- docs/PERFORMANCE_BASELINES.md (generic timing references)
- All other documentation

Exception: CHANGELOG.md should list all versions and release notes
```

For detailed implementation information, see `MAVEN_VERSION_MANAGEMENT.md`.

## Key Files and Structure

### Core Implementation

- `bridge_mcp_ghidra.py` - Main MCP server (**111 MCP tools**: 105 analysis + 1 generation + 6 lifecycle)
  - `generate_ghidra_script()` - Generate optimized Ghidra scripts for batch automation
  - Script lifecycle tools for complete automation:
    - `save_ghidra_script()` - Save generated scripts to disk
    - `list_ghidra_scripts()` - List all available scripts with metadata
    - `get_ghidra_script()` - Retrieve script content from disk
    - `run_ghidra_script()` - Execute scripts with validation and error capture
    - `update_ghidra_script()` - Modify existing scripts iteratively
    - `delete_ghidra_script()` - Remove scripts safely with backups
  - Performance: 10x faster for bulk operations (100+ items)
  - Hybrid workflow: MCP tools for exploration, scripts for bulk automation
- `src/main/java/com/xebyte/GhidraMCPPlugin.java` - Ghidra plugin (~10,900 lines)
  - 107 REST endpoints (105 analysis + 1 generation + 1 execution)
  - `runGhidraScriptWithCapture()` - Script discovery, validation, and error reporting
- `pom.xml` - Maven build configuration with system-scoped Ghidra dependencies
- `src/assembly/ghidra-extension.xml` - Assembly descriptor for ZIP packaging

### Automation & Scripts

- `ghidra_scripts/` - Ghidra scripts for automation
  - `DocumentFunctionWithClaude.java` - AI-assisted function documentation (Ctrl+Shift+P)
  - `ClearCallReturnOverrides.java` - Clean orphaned flow overrides
- `mcp_function_processor.py` - Batch function processing automation
- `scripts/hybrid-function-processor.ps1` - Automated analysis workflows

### Configuration

- `.env.template` - Environment variables template (copy to `.env` for local config)
- `mcp-config.json` - Claude MCP configuration template
- `pytest.ini` - Test configuration with markers and coverage settings
- `requirements.txt` - Production dependencies (mcp, requests, fastmcp)
- `requirements-test.txt` - Test dependencies

### Documentation Structure

- `START_HERE.md` - Getting started guide with multiple learning paths
- `README.md` - User-facing documentation and quick start
- `DOCUMENTATION_INDEX.md` - Complete documentation map
- `SCRIPT_GENERATION_GUIDE.md` - Script generation workflows with performance examples
- `SCRIPT_GENERATION_IMPLEMENTATION.md` - Implementation details and case studies
- `SCRIPT_LIFECYCLE_DESIGN.md` - Complete lifecycle management architecture and automatic troubleshooting
- `GHIDRA_SCRIPTS_VS_MCP_ANALYSIS.md` - Strategic comparison of MCP tools vs Ghidra scripts
- `VERSION_UPDATE_CHECKLIST.md` - Release process checklist
- `docs/examples/` - Case studies and practical examples
  - `examples/punit/` - Complete UnitAny structure analysis (8 files)
  - `examples/diablo2/` - Diablo II structure references (2 files)
- `docs/conventions/` - Calling convention documentation (5 files)
- `docs/guides/` - Structure discovery methodologies (4 files)
- `docs/prompts/` - AI workflow templates (8 optimized prompts)

## Development Guidelines

### When Modifying the Java Plugin

1. **Port changes**: Server port configurable via Ghidra Tool Options (default: 8089)
2. **Thread safety**: All Ghidra API calls must use `SwingUtilities.invokeAndWait()` for thread-safe access
3. **Error handling**: Return HTTP 500 with error messages, never throw exceptions to HTTP layer
4. **Endpoint patterns**: GET for queries, POST for mutations
5. **Testing**: Requires full Ghidra restart to load plugin changes

### When Modifying the MCP Bridge

1. **Input validation**: Use `validate_hex_address()` and `validate_function_name()` for all user inputs
2. **Server URL restrictions**: Only local/private IPs allowed (security requirement)
3. **Request patterns**: Use `safe_get()` and `safe_post()` helpers, not direct requests
4. **Caching**: GET requests cached for 3 minutes (configurable), disabled for mutations
5. **Error propagation**: Return descriptive error messages, log with `logger.error()`

### Test Development Standards

- **Unit tests**: Must not depend on external services, use mocking
- **Integration tests**: Require running Ghidra server on port 8089
- **Functional tests**: Require Ghidra with loaded binary
- **Markers**: Use `@pytest.mark.integration`, `@pytest.mark.functional`, `@pytest.mark.slow`
- **All new features require 100% test pass rate**

### Release Process

When preparing a new release:
- Edit `pom.xml` version tag only (Maven handles all other substitutions)
- Update `CHANGELOG.md` with release notes
- Run `mvn clean package assembly:single` to build
- Verify artifacts in `target/` directory
- Commit, tag with `git tag vX.Y.Z`, and push
- Deploy built ZIP to distribution
- Refer to `MAVEN_VERSION_MANAGEMENT.md` for detailed procedures

## Common Patterns

### Adding a New MCP Tool

1. Add REST endpoint to Java plugin (`GhidraMCPPlugin.java`)
2. Add MCP tool function to `bridge_mcp_ghidra.py` with `@mcp.tool()` decorator
3. Implement input validation using validation functions
4. Use `safe_get()` or `safe_post()` for HTTP calls
5. Add integration test in `tests/integration/`

### Working with Data Types

Data type operations use JSON payloads for complex structures:
```python
# Creating structs - use safe_post_json()
fields = [{"name": "id", "type": "int"}, {"name": "name", "type": "char[32]"}]
result = safe_post_json("create_struct", {"name": "MyStruct", "fields": fields})
```

### Generating Ghidra Scripts for Batch Automation

**When to use**: For batch operations on 100+ items, scripts provide 10x performance improvement:

```python
# Generate script for bulk function documentation
result = generate_ghidra_script(
    script_purpose="Document all functions with 3+ cross-references",
    workflow_type="document_functions",
    parameters={"min_xrefs": 3}
)

# Get the generated script content
script_content = result["script_content"]

# Save to Ghidra scripts directory
with open("ghidra_scripts/DocumentFunctions.java", "w") as f:
    f.write(script_content)

# Run in Ghidra: Window → Script Manager → Find script → Click play button
# Execution time: 2-3 minutes for 500 functions (vs 30 minutes with MCP calls)
```

**Available Workflow Types**:
- `document_functions` - Bulk function documentation with custom names/comments
- `fix_ordinals` - Restore ordinal imports to real function names
- `bulk_rename` - Rename symbols matching patterns
- `analyze_structures` - Discover and document data structures
- `find_patterns` - Identify and document code patterns
- `custom` - AI-generated script from purpose description

**Performance Comparison**:
- MCP: 500 functions × 16 calls = 8,000 HTTP calls → 30 minutes
- Script: 1 execution → 3 minutes
- **Improvement: 10x faster, no network overhead**

See `SCRIPT_GENERATION_GUIDE.md` for comprehensive examples and best practices.

### Complete Script Lifecycle Management

**Full automation workflow**: Generate → Save → Run with error capture → Iteratively fix → Delete when done.

```python
# Phase 1: Generate script
result = generate_ghidra_script(
    script_purpose="Document all important functions",
    workflow_type="document_functions"
)
script_content = result["script_content"]

# Phase 2: Save to disk
save_result = save_ghidra_script(
    script_name="DocumentFunctions",
    script_content=script_content
)
print(f"Saved to: {save_result['script_path']}")

# Phase 3: List available scripts (optional, for discovery)
scripts = list_ghidra_scripts()
print(f"Total scripts: {scripts['total_scripts']}")

# Phase 4: Run script and capture output/errors
run_result = run_ghidra_script("DocumentFunctions")
print(f"Success: {run_result['success']}")
print(f"Output: {run_result['console_output']}")

# Phase 5: If there are errors, update and re-run
if not run_result['success'] and run_result['errors']:
    # Read current content
    current_script = get_ghidra_script("DocumentFunctions")

    # Fix the issues (AI-assisted or manual)
    fixed_script = ai_fix_script_errors(current_script, run_result['errors'])

    # Update the script
    update_result = update_ghidra_script(
        script_name="DocumentFunctions",
        new_content=fixed_script
    )
    print(f"Updated: {update_result['lines_changed']} lines changed")

    # Re-run to verify fix
    run_result = run_ghidra_script("DocumentFunctions")
    if run_result['success']:
        print("✓ Script now works!")

# Phase 6: Clean up when done
delete_result = delete_ghidra_script(
    script_name="DocumentFunctions",
    confirm=True
)
print(f"Deleted and archived to: {delete_result['archive_location']}")
```

**Key Features**:
- **Automatic troubleshooting loop**: Read errors → fix → re-run until success
- **Full error capture**: Console output, exceptions, stack traces for debugging
- **Safe deletion**: Scripts backed up before removal
- **Complete CRUD**: Create, read, update, delete scripts entirely through MCP
- **Access any Ghidra feature**: Use custom scripts when MCP tools don't exist

See `SCRIPT_LIFECYCLE_DESIGN.md` for comprehensive lifecycle architecture and automatic troubleshooting patterns.

### Calling Conventions Support

The plugin supports custom calling conventions including Diablo II conventions:
```python
# Standard conventions
set_function_prototype(
    function_address="0x401000",
    prototype="int main(int argc, char* argv[])",
    calling_convention="__cdecl"  # __cdecl, __stdcall, __fastcall, __thiscall
)

# Custom Diablo II conventions
# __d2call: Context in ECX (uses game.exe context pointer)
# __d2regcall: Context in EDI (uses EDI for state management)
# See docs/conventions/ for complete documentation
```

## Important Constraints

1. **Ghidra JARs are system-scoped**: Maven won't download them; they must exist in `lib/` before building
2. **Plugin requires Ghidra restart**: Changes to Java plugin only take effect after restarting Ghidra completely
3. **Python 3.8+ required**: MCP framework uses modern Python features (async/await)
4. **No concurrent program access**: Ghidra API is single-threaded; all operations serialize through Swing EDT
5. **Security restrictions**: Bridge only accepts localhost/private IP connections for Ghidra server
6. **Version consistency**: Use `VERSION_UPDATE_CHECKLIST.md` when releasing (16 locations to update)

## Troubleshooting

### Build fails with missing Ghidra JARs
Run `copy-ghidra-libs.bat` to copy JARs from Ghidra installation to `lib/`

### Plugin doesn't appear in Ghidra
Verify JAR is in `<ghidra>/Extensions/Ghidra/` and restart Ghidra completely

### MCP bridge can't connect
Ensure Ghidra is running with a program loaded and plugin started (check port 8089)

### Tests failing
- Unit tests: Should always pass (no dependencies)
- Integration tests: Requires Ghidra running with GhidraMCP plugin
- Functional tests: Requires Ghidra with a binary loaded in CodeBrowser
