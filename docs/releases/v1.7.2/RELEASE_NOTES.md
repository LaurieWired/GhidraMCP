# GhidraMCP v1.7.2 Release Notes

**Release Date**: October 13, 2025
**Type**: Patch Release - Bug Fix
**Severity**: High - Fixes critical off-by-one error

## Overview

Version 1.7.2 fixes a critical off-by-one bug in the new `disassemble_bytes` endpoint introduced in v1.7.1. The bug caused incorrect address range calculations and could lead to failed disassembly operations or incorrect memory ranges being processed.

## 🐛 Bug Fixes

### Critical: Off-By-One Error in disassemble_bytes (v1.7.2)

**Issue**: `GhidraMCPPlugin.java:9648`
The `disassemble_bytes` endpoint had an off-by-one error when calculating the end address from a length parameter:

```java
// BEFORE (v1.7.1) - INCORRECT
end = start.add(length);  // Off by one!

// AFTER (v1.7.2) - CORRECT
end = start.add(length - 1);  // Inclusive end address
```

**Impact**:
- Attempted to disassemble one extra byte beyond the requested range
- Could cause `AddressOutOfBoundsException` when disassembling near segment boundaries
- Resulted in incorrect `bytes_disassembled` counts in responses

**Example**:
```python
# Request: Disassemble 21 bytes starting at 0x6fb4ca14
disassemble_bytes("0x6fb4ca14", length=21)

# v1.7.1 (WRONG): Would try to disassemble 0x6fb4ca14 to 0x6fb4ca29 (22 bytes!)
# v1.7.2 (CORRECT): Disassembles 0x6fb4ca14 to 0x6fb4ca28 (21 bytes)
```

**Verification**:
Tested with problematic address `0x6fb4ca14` that exposed the bug:
```bash
curl -X POST http://127.0.0.1:8089/disassemble_bytes \
  -H "Content-Type: application/json" \
  -d '{"start_address": "0x6fb4ca14", "length": 21}'

# Response:
{
  "success": true,
  "start_address": "6fb4ca14",
  "end_address": "6fb4ca28",  # Correctly 21 bytes (0x15 in hex)
  "bytes_disassembled": 21,
  "message": "Successfully disassembled 21 byte(s)"
}
```

## 📋 Changes

### Java Plugin (GhidraMCPPlugin.java)

**Line 9648** - Fixed end address calculation:
```java
// Use length to calculate end address
try {
    end = start.add(length - 1);  // Fixed: subtract 1 for inclusive end
} catch (Exception e) {
    errorMsg.set("End address calculation from length failed: " + e.getMessage());
    return;
}
```

### Python Bridge (bridge_mcp_ghidra.py)

**Line 49** - Increased timeout for `disassemble_bytes`:
```python
'disassemble_bytes': 120,  # Increased from 60s to 120s (2 minutes)
```

Reason: Disassembly operations on large ranges can take significant time, especially when Ghidra analyzes the newly disassembled code.

### Version Updates

Updated version strings in all locations:
- `pom.xml`: `<version>1.7.2</version>`
- `src/main/resources/extension.properties`: `version=1.7.2`
- `GhidraMCPPlugin.java:64`: `shortDescription = "GhidraMCP v1.7.2"`
- `GhidraMCPPlugin.java:65`: `description = "GhidraMCP v1.7.2"`
- `GhidraMCPPlugin.java:4807`: `"plugin_version": "1.7.2"`

## 🧪 Testing

### Test Case: 0x6fb4ca14 (21 bytes)

This address was chosen because it exposed the off-by-one bug in v1.7.1.

**Test 1: Direct curl**
```bash
curl -s -X POST http://127.0.0.1:8089/disassemble_bytes \
  -H "Content-Type: application/json" \
  -d '{"start_address": "0x6fb4ca14", "length": 21}'
```
✅ **Result**: SUCCESS - Correctly disassembled 21 bytes

**Test 2: Python requests.post()**
```python
import requests
response = requests.post(
    "http://127.0.0.1:8089/disassemble_bytes",
    json={"start_address": "0x6fb4ca14", "length": 21},
    timeout=120
)
print(response.json())
```
✅ **Result**: SUCCESS - Correctly disassembled 21 bytes

**Test 3: MCP Bridge (via FastMCP)**
```python
mcp__ghidra__disassemble_bytes("0x6fb4ca14", length=21)
```
⚠️ **Result**: Intermittent connection pool issue (see Known Issues section)
Note: The endpoint itself works correctly; the issue is with MCP bridge's connection pooling.

## ⚠️ Known Issues

### MCP Bridge Connection Pool Issue

When calling `disassemble_bytes` through the MCP bridge, you may encounter:
```
Error: Request failed - ('Connection aborted.', RemoteDisconnected('Remote end closed connection without response'))
```

**Root Cause**: The MCP bridge's persistent HTTP session may reuse a keep-alive connection that Ghidra closes during long operations.

**Workarounds**:
1. Use direct HTTP API (curl or requests.post())
2. Retry the operation (automatic retry logic in place)
3. Use smaller byte ranges

**Status**: Non-critical - Feature works correctly, only MCP bridge transport affected. Fix planned for v1.7.3.

See `KNOWN_ISSUES.md` for full details.

## 📦 Installation

### Automated Deployment (Windows)

```powershell
# Rebuild with correct version
mvn clean package assembly:single -DskipTests

# Deploy to Ghidra
.\deploy-to-ghidra.ps1
```

### Manual Installation

1. Copy `target/GhidraMCP.jar` to `<ghidra>/Extensions/Ghidra/`
2. **Restart Ghidra completely** (required to load new JAR)
3. Open your program in CodeBrowser
4. Start plugin: Tools → GhidraMCP → Start MCP Server

### Verification

Check the plugin version:
```bash
curl -s http://127.0.0.1:8089/get_version
```

Expected output:
```json
{
  "plugin_version": "1.7.2",
  "plugin_name": "GhidraMCP",
  "ghidra_version": "11.4.2",
  "java_version": "21.0.7",
  "endpoint_count": 108,
  "implementation_status": "101 implemented + 7 ROADMAP v2.0"
}
```

## 🔄 Upgrade Path

### From v1.7.1

**Required**: Yes - Critical bug fix
**Breaking Changes**: None
**Data Migration**: Not required

Simply rebuild and redeploy. All existing code using `disassemble_bytes` will work correctly without modifications.

### From v1.7.0 or earlier

Upgrade to v1.7.2 directly (skip v1.7.1 due to off-by-one bug).

## 📝 Documentation

Updated documentation files:
- `KNOWN_ISSUES.md` - New file documenting MCP bridge connection pool issue
- `V1.7.2_RELEASE_NOTES.md` - This file
- Test script: `test_disassemble.py` - Direct Python test for disassemble_bytes

## 🙏 Acknowledgments

Thanks to the testing process that identified the off-by-one error at address `0x6fb4ca14` in the D2Client.dll binary.

## 📞 Support

- **Issues**: https://github.com/xebyte/ghidra-mcp/issues
- **Discussions**: https://github.com/xebyte/ghidra-mcp/discussions
- **Documentation**: See `docs/` directory

## 🔮 Next Release

**v1.7.3** (Planned)
- Fix: MCP bridge connection pool issue for long operations
- Enhancement: Connection header management for slow endpoints
- Test: Comprehensive integration tests for disassemble_bytes

---

**Full Changelog**: v1.7.1...v1.7.2
