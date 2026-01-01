# Contributing to Ghidra MCP

Thank you for your interest in contributing to Ghidra MCP! This guide explains how to contribute tools, fixes, and improvements.

## Quick Links

- **Issues**: [GitHub Issues](https://github.com/bethington/ghidra-mcp/issues)
- **Discussions**: [GitHub Discussions](https://github.com/bethington/ghidra-mcp/discussions)
- **Documentation**: [DOCUMENTATION_INDEX.md](DOCUMENTATION_INDEX.md)
- **Tools Reference**: [docs/TOOL_REFERENCE.md](docs/TOOL_REFERENCE.md)

---

## Types of Contributions

### 1. Bug Reports
**When**: You found something broken

**How**:
1. Check [existing issues](https://github.com/bethington/ghidra-mcp/issues) first
2. Create new issue with:
   - Clear title: "Connection timeout when decompiling large functions"
   - Environment: OS, Ghidra version, binary size
   - Steps to reproduce
   - Expected vs actual behavior
   - Error message or logs

**Example**:
```
Title: Decompile timeout on binary > 10MB

Environment:
- OS: Windows 11
- Ghidra: 11.4.2
- Binary: 12MB x86-64

Steps:
1. Load 12MB binary in Ghidra
2. Wait for analysis
3. Call decompile_function("main")

Error: RequestTimeout after 30 seconds

Expected: Decompilation completes or returns gracefully
```

---

### 2. Feature Requests
**When**: You want a new MCP tool or capability

**How**:
1. Search [existing discussions](https://github.com/bethington/ghidra-mcp/discussions)
2. Open Discussion or Issue with:
   - Use case: Why do you need this?
   - Proposed solution
   - Alternative approaches considered
   - Priority (critical/high/medium/low)

**Example**:
```
Title: Add tool to analyze register usage patterns

Use Case:
Need to find functions that don't follow calling convention
for obfuscation analysis

Proposed Solution:
New tool: analyze_register_usage(function_name)
Returns: {"register_changes": {...}, "violations": [...]}

Priority: Medium - helpful for malware analysis
```

---

### 3. Code Contributions

#### 3a. Fix a Bug
**Steps**:

1. Fork repository
   ```bash
   git clone https://github.com/YOUR-USERNAME/ghidra-mcp.git
   cd ghidra-mcp
   ```

2. Create feature branch
   ```bash
   git checkout -b fix/connection-timeout-issue
   ```

3. Make changes and test
   ```bash
   mvn clean test  # Run tests
   python -m pytest tests/  # Python tests
   ```

4. Commit with clear message
   ```bash
   git commit -m "Fix: Increase default timeout for large binaries

   - Changed REQUEST_TIMEOUT from 30s to 60s
   - Added per-endpoint timeout configuration
   - Updated documentation with timeout guidelines
   
   Fixes #123"
   ```

5. Push and create Pull Request
   ```bash
   git push origin fix/connection-timeout-issue
   ```

#### 3b. Add a New MCP Tool

**Requirements**:
- Solves a real problem (check discussions first)
- Follows existing code patterns
- Includes error handling
- Has docstring with parameters/return
- Tested (manual or automated)

**Steps**:

1. Understand tool categories in `bridge_mcp_ghidra.py`:
   ```python
   @mcp.tool()
   def my_new_tool(param1: str, param2: int = 0) -> dict:
       """
       Brief description of what tool does.
       
       Args:
           param1: Description
           param2: Description (default: 0)
       
       Returns:
           Dictionary with results
       
       Use when: Specific use case
       """
       # Implementation
       endpoint = "/my_endpoint"
       return safe_get(endpoint, {"param1": param1, "param2": param2})
   ```

2. Add Java endpoint in `GhidraMCPPlugin.java`:
   ```java
   @Override
   public void processEvent(PluginEvent event) {
       if (httpServer == null) return;
       
       // Add route handler
       httpServer.createContext("/my_endpoint", exchange -> {
           String param1 = getParam(exchange, "param1");
           // Implementation
           sendResponse(exchange, result);
       });
   }
   ```

3. Document in `docs/TOOL_REFERENCE.md`:
   ```markdown
   ### my_new_tool()
   
   Brief description.
   
   ```python
   result = my_new_tool(param1="value", param2=5)
   # Returns: {...}
   ```
   
   **Use when**: Specific use case
   ```

4. Add example in `examples/`:
   ```python
   # examples/use-new-tool.py
   result = my_new_tool("example")
   print(result)
   ```

5. Test and commit:
   ```bash
   git commit -m "feat: Add my_new_tool() for analysis

   - Implements /my_endpoint in REST API
   - Adds MCP tool wrapper in Python bridge
   - Includes example usage
   - Tested on sample binary
   
   Contributes to: #456"
   ```

#### 3c. Improve Documentation

**What to contribute**:
- Fix typos
- Add examples
- Clarify confusing sections
- Add troubleshooting steps
- Update outdated information

**How**:
```bash
# 1. Edit documentation
vim docs/TOOL_REFERENCE.md

# 2. Preview if possible
cat docs/TOOL_REFERENCE.md | grep "my_section"

# 3. Commit
git commit -m "docs: Clarify batch operation performance benefits"
```

---

## Code Style & Standards

### Java (GhidraMCPPlugin.java)

```java
// Use clear naming
private String analyzeFunction(String functionName) {
    // Comment complex logic
    
    // Handle errors explicitly
    try {
        // Implementation
    } catch (Exception e) {
        logger.error("Error analyzing function: " + e.getMessage());
        return null;
    }
}
```

### Python (bridge_mcp_ghidra.py)

```python
@mcp.tool()
def my_tool(param: str, optional: int = 0) -> dict:
    """
    Clear docstring explaining purpose.
    
    Args:
        param: Description
        optional: Description (default: 0)
    
    Returns:
        Dictionary result
    """
    try:
        # Validate inputs
        if not param:
            raise ValueError("param cannot be empty")
        
        # Make request
        result = safe_get("/endpoint", {"param": param})
        return result
    except Exception as e:
        logger.error(f"Tool error: {e}")
        raise
```

**Style Guide**:
- PEP 8 for Python
- Use type hints
- Clear variable names (not `x`, `y`, `z`)
- Comment complex logic
- Error handling with try/except
- Logging for debugging

---

## Testing

### Java Tests
```java
// src/test/java/com/xebyte/GhidraMCPPluginTest.java

@Test
public void testDecompileFunction() {
    String result = ghidra.decompile("main");
    assertNotNull(result);
    assertTrue(result.contains("void"));
}
```

**Run tests**:
```bash
mvn test
```

### Python Tests
```python
# tests/test_bridge.py

def test_list_functions():
    functions = list_functions(limit=10)
    assert isinstance(functions, list)
    assert all("name" in f for f in functions)
```

**Run tests**:
```bash
pytest tests/ -v
```

**Add tests for**:
- New functionality
- Edge cases
- Error handling
- Performance critical paths

---

## Pull Request Process

1. **Before Submitting**:
   - [ ] Fork and create feature branch
   - [ ] Make changes following code style
   - [ ] Run tests: `mvn test` and `pytest`
   - [ ] Update documentation
   - [ ] Test changes manually if possible

2. **Create PR**:
   ```markdown
   ## Description
   Brief summary of changes
   
   Fixes #123
   
   ## Changes
   - Change 1
   - Change 2
   
   ## Testing
   Describe testing performed
   
   ## Checklist
   - [x] Tests added/updated
   - [x] Documentation updated
   - [x] No breaking changes
   ```

3. **Review Process**:
   - Maintainer reviews code
   - May request changes
   - Once approved, merges to main
   - Included in next release

---

## Contribution Ideas

### Quick Wins (1-2 hours)
- [ ] Fix typos in documentation
- [ ] Add error handling example to docs
- [ ] Create unit test for existing tool
- [ ] Add tool to TOOL_REFERENCE.md if missing
- [ ] Update example scripts with new features

### Medium Tasks (4-8 hours)
- [ ] Write comprehensive example script
- [ ] Add performance benchmarks
- [ ] Create troubleshooting guide section
- [ ] Improve error messages
- [ ] Add logging to problematic areas

### Larger Features (1-2 weeks)
- [ ] Implement new MCP tool
- [ ] Add comprehensive test suite
- [ ] Create web dashboard UI
- [ ] Implement auto-update system
- [ ] Add Docker support

---

## Development Setup

### Prerequisites
- Java 21 LTS
- Apache Maven 3.9+
- Python 3.8+
- Ghidra 11.4.2

### Local Development
```bash
# 1. Clone repository
git clone https://github.com/YOUR-USERNAME/ghidra-mcp.git
cd ghidra-mcp

# 2. Copy Ghidra libraries
copy-ghidra-libs.bat "C:\path\to\ghidra"  # Windows

# 3. Build plugin
mvn clean package

# 4. Install Python dependencies
pip install -r requirements.txt
pip install -r requirements-test.txt

# 5. Run MCP server
python bridge_mcp_ghidra.py

# 6. Run tests
mvn test
pytest tests/ -v
```

### Building Documentation
```bash
# Tools are auto-documented from docstrings
# Manually update docs/ folder

# Preview markdown
cat docs/TOOL_REFERENCE.md | more

# Check for linting errors (optional)
markdownlint docs/
```

---

## Commit Message Convention

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types**:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Code style
- `refactor`: Code refactoring
- `test`: Tests
- `perf`: Performance

**Example**:
```
feat(tools): Add batch_analyze_structures tool

- Implements bulk structure discovery
- 90% API call reduction vs individual calls
- Tested on 3 large binaries

Closes #123
```

---

## Getting Help

- **Questions**: Open GitHub Discussion
- **Issues**: Check existing issues first
- **Documentation**: See DOCUMENTATION_INDEX.md
- **Examples**: See examples/ directory
- **API**: See docs/TOOL_REFERENCE.md

---

## Code of Conduct

- Be respectful and constructive
- Assume good intent
- Focus on code, not people
- Help others learn
- Report harassment to maintainers

---

## License

By contributing, you agree that your contributions will be licensed under the same Apache 2.0 license as the project.

---

## What Happens After PR

1. Automated tests run (CI/CD)
2. Maintainer reviews code
3. Feedback provided (if needed)
4. Changes merged to `main`
5. Included in next release
6. You're added to contributors list!

---

## Recognition

Contributors are recognized in:
- `CHANGELOG.md` - Release notes
- GitHub profile - As contributor
- `CONTRIBUTORS.md` - List of contributors

---

## Questions?

Open a GitHub Discussion or issue. The community is here to help!

---

**Thank you for contributing to Ghidra MCP! 🚀**
