# Plate Comment Best Practices

## Quick Reference

When setting plate comments via `batch_set_comments` or `set_plate_comment`, always **wait 1-2 seconds** before calling `analyze_function_completeness` or retrieving the function's decompiled code.

## The Issue

Ghidra's event system is asynchronous. When you set a plate comment:
1. The comment is stored in the Function object
2. Events are flushed to propagate the change
3. A 500ms delay is added for cache refresh
4. **But this may not be enough time** if you immediately query the same function

## Recommended Workflow

### Pattern 1: Sequential Operations with Delay

```python
# Step 1: Set plate comment
result = batch_set_comments(
    function_address="0x6fb6aef0",
    plate_comment=comprehensive_comment,
    decompiler_comments=[...],
    disassembly_comments=[...]
)

# Step 2: Wait for cache propagation
import time
time.sleep(1.5)  # 1.5 seconds is safe

# Step 3: Analyze completeness
completeness = analyze_function_completeness(
    function_address="0x6fb6aef0"
)

# Now completeness.plate_comment_issues should be accurate
print(f"Plate comment issues: {completeness['plate_comment_issues']}")
```

### Pattern 2: Batch Processing with Delays

```python
functions_to_document = [
    "0x6fb6aef0",
    "0x6fb6b120",
    "0x6fb6c340"
]

for func_addr in functions_to_document:
    # Document the function
    batch_set_comments(
        function_address=func_addr,
        plate_comment=generate_plate_comment(func_addr),
        decompiler_comments=generate_decompiler_comments(func_addr)
    )

    # Wait for propagation
    time.sleep(1.5)

    # Verify completeness
    completeness = analyze_function_completeness(func_addr)

    if completeness['completeness_score'] >= 100:
        print(f"✓ {func_addr} is 100% complete")
    else:
        print(f"✗ {func_addr} needs work: {completeness['recommendations']}")
```

### Pattern 3: Async/Await Style (Python 3.7+)

```python
import asyncio

async def document_and_verify(function_address, plate_comment):
    """Document a function and verify completeness."""

    # Set comment
    result = batch_set_comments(
        function_address=function_address,
        plate_comment=plate_comment
    )

    # Wait for propagation (non-blocking)
    await asyncio.sleep(1.5)

    # Verify
    completeness = analyze_function_completeness(function_address)

    return completeness

# Use it
async def main():
    tasks = [
        document_and_verify("0x6fb6aef0", comment1),
        document_and_verify("0x6fb6b120", comment2),
        document_and_verify("0x6fb6c340", comment3)
    ]

    results = await asyncio.gather(*tasks)

    for result in results:
        print(f"Completeness: {result['completeness_score']}")

asyncio.run(main())
```

## Why This Works

### The Cache Propagation Chain

When you set a plate comment, this is what happens internally:

1. **Transaction Start** (`program.startTransaction()`)
2. **Set Comment** (`func.setComment(comment)`)
3. **Transaction Commit** (`program.endTransaction(tx, true)`)
4. **Flush Events** (`program.flushEvents()`)
   - Notifies all listeners that the function changed
   - Decompiler cache may need invalidation
   - UI views need refresh
5. **Sleep 500ms** (built-in delay)
6. **Return to Client**

When you immediately call `analyze_function_completeness`:

1. **Request arrives** at server
2. **Flush Decompiler Cache** (`tempDecomp.flushCache()`)
3. **Decompile Function** (to get fresh variables)
4. **Read Plate Comment** (`func.getComment()`)
5. **Validate Structure**

**Problem:** If step 2 of the analysis runs before step 4 of the setting completes across all Ghidra subsystems, you may read stale data.

**Solution:** Add 1-2 second delay to ensure the event queue is fully drained.

## Common Pitfalls

### Pitfall 1: Checking Decompiled Code for Plate Comment

❌ **Wrong:**
```python
# Set plate comment
batch_set_comments(function_address="0x6fb6aef0", plate_comment=comment)

# Get decompiled code
decompiled = get_decompiled_code(function_address="0x6fb6aef0")

# Check if comment appears
if "Algorithm:" in decompiled:
    print("Plate comment is present")
```

**Why it fails:** The decompiled C code (`getDecompiledFunction().getC()`) does NOT include the plate comment. Plate comments only appear in Ghidra's UI header, not in the decompilation output.

✅ **Correct:**
```python
# Set plate comment
batch_set_comments(function_address="0x6fb6aef0", plate_comment=comment)

# Wait for propagation
time.sleep(1.5)

# Analyze completeness (this reads func.getComment() directly)
completeness = analyze_function_completeness(function_address="0x6fb6aef0")

if not completeness['plate_comment_issues']:
    print("Plate comment is valid")
```

### Pitfall 2: No Delay in Loops

❌ **Wrong:**
```python
for func_addr in functions:
    batch_set_comments(func_addr, plate_comment=comments[func_addr])
    completeness = analyze_function_completeness(func_addr)  # Too fast!
```

✅ **Correct:**
```python
for func_addr in functions:
    batch_set_comments(func_addr, plate_comment=comments[func_addr])
    time.sleep(1.5)  # Wait for each function
    completeness = analyze_function_completeness(func_addr)
```

### Pitfall 3: Assuming 500ms is Enough

The server already waits 500ms internally, but this is not always sufficient when:
- Multiple functions are being documented rapidly
- Ghidra's event queue is backed up
- The decompiler cache is being heavily used

**Best practice:** Always add your own client-side delay of 1-2 seconds for reliability.

## Plate Comment Format Requirements

For `analyze_function_completeness` to report 100% completeness, your plate comment must:

1. **Minimum 10 lines total**
2. **Algorithm section** with header (`Algorithm:`)
3. **Numbered steps** (1., 2., 3., etc.)
4. **Parameters section** with header (`Parameters:`)
5. **Returns section** with header (`Returns:`)

### Valid Example

```
Algorithm:
1. Initialize context variables
2. Validate input parameters
3. Process data
4. Update state
5. Return result

Parameters:
- pContext: Pointer to context
- nValue: Value to process

Returns:
- 0 on success
- Error code on failure
```

### Invalid Examples

❌ **Too short (only 5 lines):**
```
Process data.

Parameters:
- pContext: Context pointer

Returns: Success code
```

❌ **Missing numbered steps:**
```
Algorithm:
Initialize variables, validate inputs, process data, return result.

Parameters:
- pContext: Context pointer

Returns:
- 0 on success
```

❌ **Missing sections:**
```
Algorithm:
1. Initialize
2. Process
3. Return

This function processes data.
```

## Debugging Tips

### Tip 1: Use Logging

```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Before setting
logging.debug("Setting plate comment...")
result = batch_set_comments(...)

# After setting
logging.debug(f"Set result: {result}")
logging.debug("Waiting for cache propagation...")
time.sleep(1.5)

# Before analyzing
logging.debug("Analyzing completeness...")
completeness = analyze_function_completeness(...)

# After analyzing
logging.debug(f"Completeness: {completeness['completeness_score']}")
logging.debug(f"Issues: {completeness['plate_comment_issues']}")
```

### Tip 2: Run the Test Script

Use the provided test script to verify timing:

```bash
python test_plate_comment_timing.py 0x6fb6aef0
```

This will show you:
- Immediate analysis results (may have issues)
- Delayed analysis results (should be correct)
- Timing hypothesis confirmation

### Tip 3: Check Ghidra Console

If issues persist, check Ghidra's console for:
- Event processing warnings
- Transaction rollback messages
- Cache invalidation logs

Look for messages like:
```
INFO  Refreshed decompiler cache before completeness analysis for ProcessSkillCooldowns
WARN  Failed to refresh cache before completeness analysis: ...
```

## Performance Considerations

### Trade-offs

**Shorter delay (0.5s):**
- Faster workflow
- Risk of stale data
- May need retries

**Longer delay (2s):**
- More reliable
- Slower workflow
- No retries needed

**Recommended:** Use 1.5s as a balance between speed and reliability.

### Batch Operations

For bulk documentation (100+ functions), consider:
1. **Set all comments first** (no delays)
2. **Wait 5 seconds** for bulk propagation
3. **Verify all completeness** (with 1s delays between checks)

This is faster than waiting after each individual function.

## Future Improvements

These improvements are planned for future plugin versions:

1. **Server-side synchronization:** Replace fixed delays with event queue monitoring
2. **Verification reads:** Immediately verify plate comment after setting
3. **Retry logic:** Automatically retry if completeness check shows stale data
4. **Status endpoint:** Check if events are still propagating before analysis

Until these are implemented, use the delay patterns shown in this guide.

## Summary

✅ **Do:**
- Wait 1-2 seconds between setting and analyzing
- Use `analyze_function_completeness` to verify plate comments
- Follow the plate comment format requirements (10+ lines, sections, numbered steps)

❌ **Don't:**
- Immediately analyze after setting (race condition)
- Look for plate comments in decompiled C code (they're not there)
- Assume 500ms is enough (it's not always)

**Golden Rule:** When in doubt, add a 2-second delay. It's a small price for reliable results.
