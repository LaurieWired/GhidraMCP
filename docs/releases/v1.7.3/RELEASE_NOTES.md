# Release Notes: v1.7.3

**Release Date**: 2025-10-13
**Type**: Patch Release (Bug Fix)
**Previous Version**: v1.7.2

## Summary

Version 1.7.3 fixes a critical transaction management bug in the `disassemble_bytes` endpoint that prevented disassembly changes from being persisted to the Ghidra database. While the endpoint reported success, the disassembled instructions were not being saved due to an incorrect transaction commit condition.

## Critical Bug Fix

### Issue: disassemble_bytes Transaction Commit Failure

**Problem**: The `disassemble_bytes` endpoint contained a transaction management bug where the success flag was not being set correctly before the transaction commit. This caused all disassembly operations to be rolled back even when they succeeded.

**Symptom**: Users reported that calling `disassemble_bytes` returned `{"success": true}` but the bytes were not actually disassembled in Ghidra's database. The changes were visible during the request but disappeared after the transaction ended.

**Root Cause**:
```java
// BEFORE (v1.7.2) - BUG:
if (cmd.applyTo(program, ghidra.util.task.TaskMonitor.DUMMY)) {
    // Build success response
    result.append("{\"success\": true, ...}");
    // BUG: success flag NOT set here!
} else {
    errorMsg.set("Disassembly failed: " + cmd.getStatusMsg());
}
// Transaction committed with success=false, rolling back changes!
program.endTransaction(tx, success);
```

**Fix** (v1.7.3):
```java
// AFTER - FIXED:
if (cmd.applyTo(program, ghidra.util.task.TaskMonitor.DUMMY)) {
    // Build success response
    result.append("{\"success\": true, ...}");
    success = true;  // ✓ FIXED: Set success flag to commit transaction
} else {
    errorMsg.set("Disassembly failed: " + cmd.getStatusMsg());
}
// Transaction now commits properly when disassembly succeeds
program.endTransaction(tx, success);
```

**Impact**:
- ✅ **HIGH** - Critical functionality was broken
- ✅ All `disassemble_bytes` calls now properly persist changes
- ✅ Ghidra scripts using this endpoint will function correctly
- ✅ Manual disassembly workflows via MCP are now reliable

## Changes

### src/main/java/com/xebyte/GhidraMCPPlugin.java

**Line 9716** - Added missing success flag assignment:
```diff
  if (cmd.applyTo(program, ghidra.util.task.TaskMonitor.DUMMY)) {
      // Success - build result
      Msg.debug(this, "disassembleBytes: Successfully disassembled " + numBytes + " byte(s)");
      result.append("{");
      result.append("\"success\": true, ");
      result.append("\"start_address\": \"").append(start).append("\", ");
      result.append("\"end_address\": \"").append(end).append("\", ");
      result.append("\"bytes_disassembled\": ").append(numBytes).append(", ");
      result.append("\"message\": \"Successfully disassembled ").append(numBytes).append(" byte(s)\"");
      result.append("}");
+     success = true;  // CRITICAL FIX: Set flag to commit transaction
  } else {
      errorMsg.set("Disassembly failed: " + cmd.getStatusMsg());
  }
```

### Version Updates

- `pom.xml` - Updated version from 1.7.2 to 1.7.3
- `src/main/resources/extension.properties` - Updated version to 1.7.3

## Testing Performed

### Test Case: Address 0x6fb4ca14 (21 bytes)

**Test Script**: `test_disassemble.py`
```python
POST http://127.0.0.1:8089/disassemble_bytes
{
  "start_address": "0x6fb4ca14",
  "length": 21
}
```

**v1.7.2 Result**:
- ❌ API returned success but changes not persisted
- ❌ Bytes remained undefined after transaction
- ❌ Subsequent reads showed no instructions

**v1.7.3 Result**:
- ✅ API returns: `{"success": true, "bytes_disassembled": 21}`
- ✅ Transaction commits successfully
- ✅ Disassembled instructions visible in function listing
- ✅ Changes persist across server restarts

### Verification Script

**File**: `verify_disassembly.py`
```python
# Comprehensive verification:
# 1. Test disassemble_bytes API call
# 2. Verify instruction creation via get_xrefs_from
# 3. Check memory content inspection
# 4. Validate function disassembly includes new instructions
```

**Full test results documented in**: `DISASSEMBLE_BYTES_VERIFICATION.md`

## Upgrade Instructions

### For Users

1. **Stop the MCP bridge** (if running):
   ```bash
   # Press Ctrl+C in terminal running bridge_mcp_ghidra.py
   ```

2. **Close Ghidra** (if open):
   - Save any open programs
   - Exit Ghidra completely

3. **Build the new version**:
   ```bash
   cd ghidra-mcp
   mvn clean package assembly:single -DskipTests
   ```

4. **Install the updated plugin**:
   ```bash
   # Windows PowerShell (recommended):
   .\deploy-to-ghidra.ps1

   # Or manual installation:
   copy target\GhidraMCP.jar "<ghidra_install>\Extensions\Ghidra\"
   ```

5. **Restart Ghidra**:
   - Launch Ghidra
   - Open your project and program
   - Verify GhidraMCP plugin loaded (Tools → GhidraMCP)

6. **Restart the MCP bridge**:
   ```bash
   python bridge_mcp_ghidra.py
   ```

7. **Verify the fix**:
   ```bash
   python verify_disassembly.py
   ```

### For Developers

No API changes - this is a drop-in replacement. All existing client code will work correctly without modifications.

## Compatibility

- **Ghidra Version**: 11.4.2 (unchanged)
- **Java Version**: 21 LTS (unchanged)
- **Python Version**: 3.8+ (unchanged)
- **MCP Framework**: 1.2.0+ (unchanged)

## Breaking Changes

None - this is a bug fix release with no API changes.

## Known Issues

None related to this release. See `KNOWN_ISSUES.md` for general project issues.

## Related Documentation

- `DISASSEMBLE_BYTES_VERIFICATION.md` - Comprehensive testing report
- `test_disassemble.py` - Simple API test script
- `verify_disassembly.py` - Full verification suite
- `TEST_CASE_6FB4CA14.md` - Original test case documentation

## Migration Notes

This fix is **highly recommended** for all users of v1.7.0 through v1.7.2 who use the `disassemble_bytes` endpoint. If you have workflows that depend on this functionality, they will start working correctly after upgrading to v1.7.3.

## Credits

- Bug discovered through comprehensive testing of noreturn function fix workflows
- Fix verified with multiple test cases and edge conditions
- Thanks to the Ghidra team for the robust transaction API

## Next Steps

After upgrading, users can:
1. Re-run any failed `disassemble_bytes` operations
2. Use the endpoint reliably in automated analysis scripts
3. Integrate with noreturn function fix workflows (see `NORETURN_FIX_GUIDE.md`)

---

For questions or issues, please file a bug report at:
https://github.com/bethington/ghidra-mcp/issues
