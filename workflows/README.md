# RE Improvement Workflow

An autonomous workflow for continuously improving both:
1. **Binary documentation** inside Ghidra
2. **The MCP tools themselves** that interface with Ghidra

## Quick Start - Running the Continuous Loop

The easiest way to use this is with Claude Code:

```
You: Run the continuous improvement loop for Ghidra

Claude: [Starts the loop, documents functions, improves tools]
```

Or invoke the slash command: `/improve`

## How It Works

```
┌─────────────────────────────────────────────────────────────────────┐
│                    CONTINUOUS IMPROVEMENT LOOP                       │
│                                                                      │
│   ┌─────────────┐     ┌─────────────┐     ┌─────────────┐          │
│   │   PHASE 1   │────>│   PHASE 2   │────>│   PHASE 3   │          │
│   │   Document  │     │   Improve   │     │   Deploy    │          │
│   │   Functions │     │   Tools     │     │   Changes   │          │
│   └─────────────┘     └─────────────┘     └─────────────┘          │
│         │                   │                   │                   │
│         v                   v                   v                   │
│   ┌─────────────┐     ┌─────────────┐     ┌─────────────┐          │
│   │  - Decompile│     │  - Record   │     │  - Test     │          │
│   │  - Analyze  │     │    friction │     │  - Build    │          │
│   │  - Name     │     │  - Propose  │     │  - Deploy   │          │
│   │  - Comment  │     │    new tools│     │  - Verify   │          │
│   │  - Type vars│     │  - Generate │     │  - Rollback │          │
│   └─────────────┘     │    code     │     │    if fail  │          │
│                       └─────────────┘     └─────────────┘          │
│                                                                      │
│                         ↓ REPEAT ↓                                  │
└─────────────────────────────────────────────────────────────────────┘
```

## The Two Improvement Targets

### 1. Binary Documentation (in Ghidra)
- Find functions with default names (FUN_*)
- Analyze decompiled code to understand purpose
- Apply meaningful names, types, and comments
- Create structures and enums as needed

### 2. Tool Improvements (the MCP bridge itself)
- Record friction when tools are slow/broken/missing
- Propose new tools that would help
- Generate actual code for new tools
- Modify `bridge_mcp_ghidra.py` or `GhidraMCPPlugin.java`
- Test and deploy changes

## Usage

### With Claude Code (Recommended)

```python
# Start the improvement loop
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

# Document a function
result = document_next_function(loop)
if result:
    # Claude analyzes the decompiled code and applies documentation
    apply_function_documentation(
        loop,
        address=result["function"]["address"],
        name="ProcessPlayerData",
        prototype="int ProcessPlayerData(Player* p)",
        comment="Updates player state",
        var_types={"local_8": "Player*"}
    )

# Report friction if tools were problematic
report_tool_friction(loop, "decompile", "Slow on large functions")

# Propose a new tool
change_id = propose_new_tool(
    loop,
    tool_name="get_string_refs",
    description="Get string references in function",
    rationale="Helps identify function purpose"
)

# Implement the tool (generate actual code)
implement_proposed_change(loop, change_id, '''
@mcp.tool()
def get_string_refs(function_name: str) -> list:
    """Get all string references in a function."""
    return safe_get("function_strings", {"name": function_name})
''')

# Test and deploy
success, results = test_and_deploy(loop)

loop.end_session()
```

### Standalone (Limited)

```bash
# Check status
python workflows/continuous_improvement.py --status

# Preview mode (no changes)
python workflows/continuous_improvement.py --dry-run --standalone
```

## Files

| File | Purpose |
|------|---------|
| `continuous_improvement.py` | Main loop with source code modification |
| `re_documentation_tools.py` | Curated 25-tool subset for RE work |
| `re_improvement_workflow.py` | Original agent-based workflow |
| `test_workflow.py` | Test harness |
| `run_improvement_loop.py` | Instructions for Claude Code |

## State Persistence

The loop maintains state across sessions in `.improvement_state.json`:
- Session count
- Functions documented
- Tools added/removed/modified
- Friction history
- Pending and completed changes

```python
# Check current state
loop = get_loop_instance()
print(loop.get_improvement_summary())
```

## Tool Modification Capabilities

The system can modify:

### Python Bridge (`bridge_mcp_ghidra.py`)
- Add new MCP tools
- Modify existing tools
- Remove unused tools

### Java Plugin (`GhidraMCPPlugin.java`)
- Add new REST endpoints
- Modify endpoint behavior

Changes are:
1. Backed up before modification
2. Tested with unit and integration tests
3. Built with Maven (Java changes)
4. Deployed via `deploy-to-ghidra.ps1`
5. Rolled back if tests fail

## Curated Tool Set

The workflow uses a minimal 25-tool set (vs 118+ in full bridge):

| Category | Tools |
|----------|-------|
| Discovery | get_program_info, find_undocumented_functions, list_functions |
| Analysis | decompile, disassemble, get_function_variables, get_callees, get_callers, get_xrefs, get_jump_targets |
| Documentation | rename_function, set_function_signature, rename_variable, set_variable_type, batch_set_types, create_label, batch_create_labels, set_plate_comment, batch_set_comments |
| Data Types | list_data_types, search_data_types, create_struct, create_enum, apply_data_type |
| Verification | analyze_completeness, get_function_info |
| Cross-Binary | get_function_hash, get_bulk_function_hashes, get_function_documentation, apply_function_documentation |

## Example Session

```
Session 1 Started
├── Found: FUN_6f8e1000 @ 6f8e1000
├── Decompiled: 150 lines of C code
├── Analysis: Calls ProcessSlot, ValidateData
├── Named: ProcessPlayerInventory
├── Typed: 5 variables
├── Commented: Purpose and algorithm
├── Friction: batch_set_types was slow (recorded)
├── Tests: 25 passed, 0 failed
└── Session complete

Summary:
  Functions documented: 1
  Tools modified: 0
  Friction points: 1
```

## Requirements

- Python 3.8+
- requests library
- Ghidra running with GhidraMCP plugin
- A loaded binary in Ghidra
- Claude Code (for full autonomous operation)
