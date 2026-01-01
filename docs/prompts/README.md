# Ghidra MCP Documentation Prompts

This directory contains optimized prompts for documenting binary code in Ghidra using the MCP tools. These prompts are designed to be used with Claude or other AI assistants to systematically reverse engineer and document functions.

⚠️ **NEW: Comprehensive Workflow Enhancement** - After documenting 4 complex Diablo II functions, the workflow was refined to eliminate missing globals and string constants. **All new documentation should follow the updated guidance below.**

## Quick Navigation

- **Starting a new function?** → Start with DOCUMENTATION_WORKFLOW_INDEX.md for the decision tree, then read OPTIMIZED_FUNCTION_DOCUMENTATION.md
- **Missing global data?** → Use GLOBAL_DATA_NAMING_CHECKLIST.md
- **Naming questions?** → Reference [NAMING_CONVENTIONS.md](../../NAMING_CONVENTIONS.md)
- **Complete workflow guide?** → Read the new **BINARY_FUNCTION_DOCUMENTATION_COMPLETE_GUIDE.md** (comprehensive overview)

## Available Prompts

### ⭐ NEW: Complete Workflow Documentation (Start Here)

1. **BINARY_FUNCTION_DOCUMENTATION_COMPLETE_GUIDE.md** ⭐ **START HERE**
   - Complete overview of the proven 12-step workflow
   - Built from experience documenting 4 complex functions
   - Includes gap analysis and fixes (prevents missing globals/strings)
   - Lists all 14 completion criteria
   - Troubleshooting guide for common issues
   - Cross-references all supporting documents
   - Best for: Understanding the complete workflow before starting
   - Use when: First time with this project or want complete context

2. **DOCUMENTATION_WORKFLOW_INDEX.md** ⭐ **QUICK REFERENCE**
   - Decision tree for which tool to use when
   - Quick reference for all MCP tools
   - Naming convention quick reference
   - Common patterns by function type
   - Troubleshooting common issues
   - Tool batch size limits and workarounds
   - Best for: Fast lookups while working
   - Use when: Need specific tool info or workflow step

3. **GLOBAL_DATA_NAMING_CHECKLIST.md** ⭐ **CRITICAL FOR STEP 6**
   - Systematic checklist for finding and renaming ALL global data
   - Prevents missing string constants, buffers, configuration variables
   - Explains difference between local rename_variable and global rename_or_label
   - 5 categories of global data with naming patterns
   - Search strategies for each category
   - Integration with main 12-step workflow
   - Best for: Completing step 6 (variables) properly
   - Use when: Renaming variables in any function

### Core Documentation Workflows

4. **OPTIMIZED_FUNCTION_DOCUMENTATION.md** ⭐ **MAIN WORKFLOW**
   - Most comprehensive and detailed workflow (updated with global data requirements)
   - Complete step-by-step instructions for thorough function documentation
   - Now includes explicit requirements for string constants and globals
   - Verification steps and structure identification
   - Best for: Detailed analysis requiring full documentation
   - Use when: Working on critical functions or complex algorithms

5. **UNIFIED_ANALYSIS_PROMPT.md**
   - Combined function and data analysis workflow
   - Comprehensive approach for complex binaries
   - Best for: Full system analysis including structures
   - Use when: Need to understand relationships between code and data

6. **ENHANCED_ANALYSIS_PROMPT.md**
   - Advanced analysis techniques
   - Specialized for data structure discovery and application
   - Best for: Complex reverse engineering scenarios
   - Use when: Standard workflow isn't sufficient

7. **QUICK_START_PROMPT.md**
   - Simplified workflow for beginners
   - Essential steps without advanced features
   - Best for: Getting started quickly
   - Use when: Learning the system or simple functions

### Formatting Guides

8. **PLATE_COMMENT_FORMAT_GUIDE.md** ⭐ **ESSENTIAL**
   - Exact template for creating structured function header comments
   - Plain text format (Ghidra adds formatting automatically)
   - Detailed formatting rules for all sections
   - Best for: Creating consistent, professional plate comments
   - Use when: You need to format function headers correctly

9. **PLATE_COMMENT_EXAMPLES.md** ⭐ **PRACTICAL**
   - Real-world examples of properly formatted plate comments
   - Multiple function types (validation, processing, initialization, etc.)
   - Quick reference templates
   - Best for: Seeing complete examples before creating your own
   - Use when: You need inspiration or want to copy a template

### Data Analysis

10. **DATA_DOCUMENTATION_TEMPLATE.md**
    - Comprehensive template for documenting data structures and global variables
    - Includes usage analysis, structure context, and naming conventions
    - Best for: Analyzing data regions and applying proper types
    - Use when: Documenting global variables, tables, or data structures

## Recommended Usage Workflow

### For Beginners

1. Start with **OPTIMIZED_FUNCTION_DOCUMENTATION.md** to understand the complete process
2. Reference **PLATE_COMMENT_FORMAT_GUIDE.md** when creating function headers
3. Use **PLATE_COMMENT_EXAMPLES.md** to see what good documentation looks like
4. Practice on simple functions before moving to complex ones

### For Experienced Users

1. Use **SINGLE_FUNCTION_COMPLETE_DOCUMENTATION.md** as your primary reference
2. Keep **PLATE_COMMENT_FORMAT_GUIDE.md** open for header formatting
3. Refer to **PLATE_COMMENT_EXAMPLES.md** when documenting different function types
4. Customize based on project-specific conventions

### For High-Volume Documentation

1. Use **analyze_function_complete** MCP tool for comprehensive analysis
2. Follow **OPTIMIZED_FUNCTION_DOCUMENTATION.md** workflow
3. Use **PLATE_COMMENT_EXAMPLES.md** templates for consistency
4. Automate using batch tools (batch_rename_variables, batch_create_labels, etc.)

## Plate Comment Format

The plate comment format is a critical component of documentation. Here's the basic structure:

```c
/**********************************************************************************************
 * [Function summary - one clear sentence]                                                   *
 *                                                                                            *
 * Algorithm:                                                                                 *
 * 1. [First step]                                                                            *
 * 2. [Second step]                                                                           *
 * ...                                                                                        *
 *                                                                                            *
 * Parameters:                                                                                *
 *   paramName: [Description]                                                                 *
 *                                                                                            *
 * Returns:                                                                                   *
 *   [Type]: [What it means]                                                                  *
 *                                                                                            *
 * Special Cases:                                                                             *
 *   - [Edge cases and special handling]                                                      *
 *********************************************************************************************/
```

**Critical formatting rules:**
- Each line must be exactly **96 characters** including newline
- Content lines: ` * ` + content + ` *`
- Top border: `/*` + 93 asterisks
- Bottom border: 1 space + 94 asterisks + `*/`

See **PLATE_COMMENT_FORMAT_GUIDE.md** for complete details and **PLATE_COMMENT_EXAMPLES.md** for working examples.

## Diablo II Specific Conventions

When working with Diablo II binaries, these prompts include specific guidance for:

### Common Structures
- **UnitAny**: dwType, dwUnitId, dwMode, pInventory, pStats, wX, wY
- **Room1/Room2**: pRoom2, dwPosX, dwPosY, dwSizeX, dwSizeY, pLevel
- **PlayerData**: szName, pNormalQuest, pNightmareQuest, pHellQuest
- **ItemData**: dwQuality, dwItemFlags, wPrefix, wSuffix, BodyLocation
- **MonsterData**: anEnchants, wUniqueNo, wName
- **Inventory**: pOwner, pFirstItem, pCursorItem, dwItemCount

### Naming Conventions (Hungarian Notation)
- `dw`: DWORD (dwFlags, dwUnitId)
- `p`/`lp`: Pointers (pNext, lpPlayerUnit)
- `w`: WORD (wLevel, wStatIndex)
- `n`: Counts (nCount, nMaxXCells)
- `sz`: Strings (szName, szGameName)
- `f`/`b`: Boolean (fSaved, bActive)

## Integration with MCP Tools

These prompts are designed to work with the following Ghidra MCP tools:

### Analysis Tools
- `analyze_function_complete`: Get all function info in one call
- `analyze_data_region`: Analyze data structures
- `detect_array_bounds`: Identify array sizes
- `search_functions_enhanced`: Find functions to document

### Documentation Tools
- `set_plate_comment`: Add function header
- `batch_set_comments`: Add multiple comments
- `batch_create_labels`: Create jump target labels
- `batch_rename_variables`: Rename multiple variables
- `set_function_prototype`: Define function signature

### Cross-Binary Documentation (v1.9.4+)
- `get_function_hash`: Get normalized SHA-256 hash for matching across binaries
- `get_bulk_function_hashes`: Paginated bulk hashing with filter (documented/undocumented/all)
- `get_function_documentation`: Export complete function docs (name, prototype, comments, labels)
- `apply_function_documentation`: Import documentation to target function
- `build_function_hash_index`: Build persistent JSON index from programs
- `lookup_function_by_hash`: Find matching functions in index
- `propagate_documentation`: Apply docs to all matching instances

### Verification Tools
- `analyze_function_completeness`: Check documentation status
- `validate_function_prototype`: Verify prototype syntax
- `can_rename_at_address`: Check if rename will work

## Tips for Effective Documentation

1. **Always verify function boundaries first** - Incorrect boundaries lead to wrong analysis
2. **Use batch operations** - Minimize API calls with batch_* tools
3. **Cross-reference assembly** - Verify offsets match disassembly, not decompiler
4. **Document structures inline** - Include structure layouts in plate comments
5. **Name meaningfully** - Use descriptive names that explain purpose, not just type
6. **Reference magic numbers** - Always explain hex values and sentinel values
7. **Format consistently** - Use the plate comment template for every function

## Common Issues and Solutions

### Plate Comment Formatting
- **Problem**: Lines don't align or exceed 96 characters
- **Solution**: Use PLATE_COMMENT_FORMAT_GUIDE.md template exactly

### Variable Rename Failures
- **Problem**: "Variable not found" errors
- **Solution**: Use analyze_function_complete to get exact variable names first

### Offset Mismatches
- **Problem**: Comments reference wrong offsets
- **Solution**: Always verify against disassembly, not decompiler output

### Connection Timeouts
- **Problem**: batch_* operations timeout
- **Solution**: Split into smaller batches or use individual operations

## Contributing

When creating new prompts or improving existing ones:

1. Test the prompt on multiple function types
2. Verify it produces consistent, accurate documentation
3. Include examples and formatting guidelines
4. Update this README to reference the new prompt
5. Follow the existing structure and style

## Version History

- **v1.9.4**: Added cross-binary documentation propagation tools (Function Hash Index)
- **v1.6.5**: Added PLATE_COMMENT_FORMAT_GUIDE.md and PLATE_COMMENT_EXAMPLES.md
- **v1.6.0**: Added validation tools and enhanced search
- **v1.5.1**: Added batch operation support
- **v1.5.0**: Initial prompt collection
