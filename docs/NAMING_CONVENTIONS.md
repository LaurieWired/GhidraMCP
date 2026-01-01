# Naming Conventions Guide

This document establishes naming standards for the Ghidra MCP project to ensure consistency and maintainability.

---

## Markdown Files

### Root-Level Documentation (UPPERCASE)
All primary markdown files in the root directory use **UPPERCASE** for visibility and discoverability:

```
README.md                    — Main project overview and getting started
CHANGELOG.md                 — Version history and release notes
CONTRIBUTING.md              — Contribution guidelines and development setup
LICENSE                      — Project license (no extension)
START_HERE.md                — Quick start guide for new users
INSTALLATION.md              — Setup and installation instructions (future)
SECURITY.md                  — Security guidelines and reporting (future)
```

**Rationale**: 
- UPPERCASE files stand out in file listings
- GitHub automatically renders `.md` files
- Consistent with industry standards (Python, Node.js, etc.)

### Documentation Folder (`docs/`)
Organized reference documentation also uses **UPPERCASE**:

```
docs/TOOL_REFERENCE.md           — Complete documentation of all 109 MCP tools
docs/ERROR_CODES.md              — Error catalog and troubleshooting guide
docs/PERFORMANCE_BASELINES.md    — Performance metrics and optimization
docs/ARCHITECTURE.md             — System architecture and design
docs/API.md                      — API overview and integration guide
docs/EXAMPLES.md                 — Example workflows and use cases
```

**Rationale**:
- Easy to find reference documentation
- Consistent naming across docs folder
- Self-documenting purpose from filename

### Project Management Files
Status tracking and organization files:

```
IMPROVEMENTS.md                  — Improvement roadmap and feature tracking
PROJECT_STATUS.md                — Current project status (replaces dated reports)
QUICKWIN_CHECKLIST.md            — Quick win task tracking
```

**Rationale**:
- Clear that these are project-level documents
- Centralized status tracking

---

## Java Code

### File Naming (PascalCase)
Java files use **PascalCase** matching the public class name:

```java
✅ GOOD
GhidraMCPPlugin.java          — Main plugin entry point
ToolRegistry.java             — Tool registration system
MCSProtocolHandler.java       — Protocol implementation

❌ AVOID
GhidraMcpPlugin.java
ghidra_mcp_plugin.java
Ghidra-MCP-Plugin.java
```

### Class Naming (PascalCase)
```java
public class GhidraMCPPlugin { }           ✅
public class ToolRegistry { }               ✅
public class MCSProtocolHandler { }         ✅
```

### Method Naming (camelCase)
```java
public void registerTool() { }              ✅
private String getToolName() { }            ✅
protected void parseRequest() { }           ✅
```

### Constant Naming (UPPER_SNAKE_CASE)
```java
public static final String VERSION = "1.9.2";        ✅
public static final int MAX_BATCH_SIZE = 100;        ✅
private static final long TIMEOUT_MS = 5000L;        ✅
```

### Variable Naming (camelCase)
```java
String toolName = "decompile";             ✅
int maxRetries = 3;                        ✅
boolean isEnabled = true;                  ✅
```

---

## Python Code

### File Naming (snake_case)
Python files use **snake_case** following PEP 8:

```
✅ GOOD
analyze_functions.py
create_struct_workflow.py
bridge_mcp_ghidra.py
ordinal_auto_fixer.py

❌ AVOID
AnalyzeFunctions.py
analyze-functions.py
Analyze_Functions.py
```

### Function Naming (snake_case)
```python
def get_function_xrefs():                   ✅
def batch_rename_functions():               ✅
def extract_ioc_strings():                  ✅
```

### Class Naming (PascalCase)
```python
class GhidraBridge:                         ✅
class ToolRegistry:                         ✅
class MCPServer:                            ✅
```

### Constant Naming (UPPER_SNAKE_CASE)
```python
DEFAULT_TIMEOUT = 300                       ✅
MAX_BATCH_SIZE = 100                        ✅
API_VERSION = "1.0"                         ✅
```

### Variable Naming (snake_case)
```python
tool_name = "decompile"                     ✅
is_enabled = True                           ✅
max_retries = 3                             ✅
```

---

## Shell Scripts

### File Naming (kebab-case or snake_case)
PowerShell and Bash scripts use lowercase with separators:

```
✅ GOOD
deploy-to-ghidra.ps1
copy-ghidra-libs.bat
run_tests.sh
build-docker.sh

❌ AVOID
DeployToGhidra.ps1
deploy_to_ghidra.ps1
```

### Function Naming
```powershell
# PowerShell: PascalCase
function Deploy-ToGhidra { }                ✅

# Bash: kebab-case or snake_case
deploy_to_ghidra() { }                      ✅
```

---

## Configuration Files

### Format: lowercase with dots
```
mcp-config.json               — MCP server configuration
pytest.ini                    — Python test configuration
.gitignore                    — Git ignore rules
.env.template                 — Environment variable template
```

### Maven Configuration (root)
```
pom.xml                       — Maven project file (standardized)
```

---

## Log and Temporary Files

### Log Files (snake_case with timestamps)
```
ordinal_fix_log_20251105_120000.txt        — Process logs with timestamp
build.log                                   — Build output
test_results.log                            — Test output
```

**Format**: `process_type_log_YYYYMMDD_HHMMSS.txt`

### Temporary/Archive Files
```
logs/                         — Archive old logs here
archive/                      — Store completed reports here
.backups/                     — Backup files (gitignored)
```

---

## Directory Structure

### Standard Layout (recommended)
```
ghidra-mcp/
├── README.md                 — Project overview
├── CONTRIBUTING.md           — Contribution guide
├── CHANGELOG.md              — Version history
├── docs/
│   ├── TOOL_REFERENCE.md
│   ├── ERROR_CODES.md
│   ├── PERFORMANCE_BASELINES.md
│   └── ARCHITECTURE.md
├── examples/
│   ├── README.md
│   ├── analyze_functions.py
│   ├── create_struct_workflow.py
│   └── ...
├── src/
│   ├── main/java/
│   │   └── com/xebyte/
│   │       ├── GhidraMCPPlugin.java
│   │       ├── ToolRegistry.java
│   │       └── ...
│   └── test/java/
│       └── com/xebyte/
│           └── GhidraMCPPluginTest.java
├── scripts/
│   ├── deploy.sh
│   ├── build.ps1
│   └── ...
├── logs/
│   └── (archived logs here)
└── ...
```

---

## Quick Reference

| Type | Standard | Example | Rationale |
|------|----------|---------|-----------|
| **Markdown (root)** | UPPERCASE | `README.md` | Visibility, GitHub convention |
| **Markdown (docs)** | UPPERCASE | `TOOL_REFERENCE.md` | Organization, consistency |
| **Java files** | PascalCase | `GhidraMCPPlugin.java` | Java convention |
| **Java classes** | PascalCase | `class ToolRegistry` | Java convention |
| **Java methods** | camelCase | `getTool()` | Java convention |
| **Java constants** | UPPER_SNAKE_CASE | `MAX_SIZE` | Java convention |
| **Python files** | snake_case | `analyze_functions.py` | PEP 8 convention |
| **Python classes** | PascalCase | `class GhidraBridge` | PEP 8 convention |
| **Python functions** | snake_case | `get_xrefs()` | PEP 8 convention |
| **Python constants** | UPPER_SNAKE_CASE | `API_VERSION` | PEP 8 convention |
| **Shell scripts** | kebab-case | `deploy-to-ghidra.ps1` | Shell convention |
| **Config files** | lowercase.ext | `mcp-config.json` | Convention |
| **Logs** | snake_case_date | `build_log_20251105.txt` | Readability |

---

## Enforcement

### GitHub Actions
Add to CI/CD pipeline (when implemented):
- **Python**: `flake8` and `black` enforce snake_case naming
- **Java**: `checkstyle` enforces Java naming conventions

### Pre-commit Hooks (future)
```bash
# Validate file naming on commit
- Check Markdown files are UPPERCASE
- Check Python files are snake_case
- Check Java files are PascalCase
```

---

## Migration Plan

For existing files that don't follow conventions:

| Current | Recommended | Action | Priority |
|---------|-------------|--------|----------|
| `CLAUDE.md` | `ARCHITECTURE.md` | Rename when restructuring | Low |
| `ordinal_fix_log_*.txt` | Archive to `logs/` folder | Organize existing logs | Low |
| Old reports | Archive or consolidate | Move to `archive/` | Low |
| Examples `.py` files | Already `snake_case` ✅ | No action | — |
| Docs in `docs/` | Already `UPPERCASE` ✅ | No action | — |

---

## References

- [Python PEP 8 Style Guide](https://www.python.org/dev/peps/pep-0008/)
- [Google Java Style Guide](https://google.github.io/styleguide/javaguide.html)
- [GitHub's Naming Conventions](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-readmes)
- [Markdown Best Practices](https://www.markdownguide.org/basic-syntax/)

---

**Last Updated**: November 5, 2025  
**Version**: 1.0
