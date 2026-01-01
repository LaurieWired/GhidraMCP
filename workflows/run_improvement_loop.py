#!/usr/bin/env python3
"""
Simple entry point for the continuous improvement loop.

This script provides the context and instructions for Claude Code
to run the improvement loop autonomously.

Usage:
    Just read this file and Claude will know what to do!
"""

IMPROVEMENT_LOOP_INSTRUCTIONS = """
# CONTINUOUS IMPROVEMENT LOOP - AUTONOMOUS MODE

You are running an autonomous improvement loop for Ghidra reverse engineering tooling.
Your goal is to continuously:
1. Document binary functions in Ghidra
2. Identify and fix issues with the MCP tools
3. Add new tools that would be helpful
4. Remove tools that aren't useful

## HOW TO RUN

Execute this Python code to start:

```python
import sys
sys.path.insert(0, r"C:\\Users\\benam\\source\\mcp\\ghidra-mcp")

from workflows.continuous_improvement import (
    get_loop_instance,
    document_next_function,
    apply_function_documentation,
    report_tool_friction,
    propose_new_tool,
    implement_proposed_change,
    test_and_deploy
)

# Initialize
loop = get_loop_instance()
loop.start_session()

# Check Ghidra connection
if not loop.check_ghidra_connection():
    print("ERROR: Ghidra not available. Please start Ghidra with a binary loaded.")
else:
    print("Connected to Ghidra!")
    print(f"Session {loop.state.session_count} started")
```

## THE IMPROVEMENT CYCLE

For each iteration, do the following:

### 1. Get Next Function
```python
result = document_next_function(loop)
if result:
    func = result["function"]
    analysis = result["analysis"]
    print(f"Analyzing: {func['name']} @ {func['address']}")
    print("Decompiled code:")
    print(analysis["decompiled"][:2000])  # First 2000 chars
else:
    print("No more undocumented functions!")
```

### 2. Analyze and Document
Look at the decompiled code and determine:
- What does this function do?
- What should it be named? (Use PascalCase like ProcessPlayerData)
- What is its prototype? (return type, parameters)
- What are the variable types?
- What comment explains its purpose?

Then apply:
```python
apply_function_documentation(
    loop,
    address=func["address"],
    name="YourChosenName",
    prototype="int YourChosenName(int param1, void* param2)",
    comment="Brief description of what the function does",
    var_types={"local_8": "int", "local_c": "void*"}
)
```

### 3. Note Any Friction
If you encountered issues with the tools:
```python
report_tool_friction(loop, "tool_name", "what went wrong", "suggested fix")
```

### 4. Propose Improvements
If you think of a tool that would help:
```python
change_id = propose_new_tool(
    loop,
    tool_name="new_tool_name",
    description="What it does",
    rationale="Why it would help"
)
```

### 5. Implement Improvements (if any)
Generate the actual code for proposed tools:
```python
code = '''
@mcp.tool()
def new_tool_name(param: str) -> str:
    """Tool description."""
    return safe_get("endpoint", {"param": param})
'''
implement_proposed_change(loop, change_id, code)
```

### 6. Test and Deploy
```python
success, results = test_and_deploy(loop)
if success:
    print("Changes deployed successfully!")
else:
    print("Deployment failed, changes rolled back")
    print(results)
```

### 7. Repeat
Go back to step 1 and continue until:
- No more functions to document
- User asks to stop
- You've done enough iterations

### 8. End Session
```python
loop.end_session()
```

## IMPORTANT GUIDELINES

1. **Be conservative with tool changes** - Only propose changes when you've encountered
   real friction multiple times

2. **Test everything** - Never deploy untested changes

3. **Document thoroughly** - Good function names and comments are valuable

4. **Use batch operations** - batch_set_comments is much faster than individual calls

5. **Follow naming conventions**:
   - Functions: PascalCase (ProcessData, ValidateInput)
   - Variables: camelCase (playerIndex, bufferSize)
   - Labels: snake_case (loop_start, error_handler)
   - Hungarian notation for types: dwFlags, pBuffer, nCount

6. **Keep iterating** - The more functions you document, the more patterns you'll see

## CHECKING STATUS

```python
print(loop.get_improvement_summary())
```

This shows:
- How many sessions you've run
- How many functions documented
- How many tools added/removed/modified
- Pending changes
- Recorded friction points

Now start the loop and begin improving!
"""

if __name__ == "__main__":
    print(IMPROVEMENT_LOOP_INSTRUCTIONS)
