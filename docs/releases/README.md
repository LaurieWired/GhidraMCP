# Release Documentation Index

This directory contains version-specific release documentation for the Ghidra MCP project.

## Available Releases

### v1.9.4 (Latest)

- **Function Hash Index Release** - Cross-binary documentation propagation
- New tools: `get_function_hash`, `get_bulk_function_hashes`, `get_function_documentation`, `apply_function_documentation`, `build_function_hash_index`, `lookup_function_by_hash`, `propagate_documentation`
- SHA-256 normalized opcode hashing for position-independent function matching
- See [CHANGELOG.md](../../CHANGELOG.md) for full details

### v1.9.3

- [Release Notes](v1.9.3/RELEASE_NOTES_v1.9.3.md) - Documentation organization and workflow enhancements
- [Release Checklist](v1.9.3/RELEASE_CHECKLIST_v1.9.3.md) - Pre-release verification tasks

### v1.9.2

- [Release Checklist](v1.9.2/RELEASE_CHECKLIST_v1.9.2.md) - Pre-release verification tasks
- [Release Notes](v1.9.2/RELEASE_NOTES_v1.9.2.md) - Features, fixes, and changes
- [Release Completion Report](v1.9.2/RELEASE_COMPLETE_v1.9.2.md) - Post-release summary

### v1.7.3

- [Release Notes](v1.7.3/RELEASE_NOTES.md) - Version 1.7.3 changes
- [Documentation Review](v1.7.3/DOCUMENTATION_REVIEW.md) - Documentation updates

### v1.7.2

- [Release Notes](v1.7.2/RELEASE_NOTES.md) - Version 1.7.2 changes

### v1.7.0

- [Release Notes](v1.7.0/RELEASE_NOTES.md) - Version 1.7.0 changes

### v1.6.0

- [Release Notes](v1.6.0/RELEASE_NOTES.md) - Version 1.6.0 changes
- [Feature Status](v1.6.0/FEATURE_STATUS.md) - Feature implementation status
- [Implementation Summary](v1.6.0/IMPLEMENTATION_SUMMARY.md) - Technical implementation details
- [Verification Report](v1.6.0/VERIFICATION_REPORT.md) - Testing and verification results

### v1.5.1

- [Final Improvements](v1.5.1/FINAL_IMPROVEMENTS_V1.5.1.md) - Final improvements implemented
- [Improvements Implemented](v1.5.1/IMPROVEMENTS_IMPLEMENTED.md) - Detailed improvement list

### v1.5.0

- [Release Notes](v1.5.0/RELEASE_NOTES_V1.5.0.md) - Version 1.5.0 changes
- [Implementation Details](v1.5.0/IMPLEMENTATION_V1.5.0.md) - Technical implementation
- [Hotfix v1.5.0.1](v1.5.0/HOTFIX_V1.5.0.1.md) - Emergency hotfix details

### v1.4.0

- [Code Review](v1.4.0/CODE_REVIEW_V1.4.0.md) - Code review findings
- [Data Structures Summary](v1.4.0/DATA_STRUCTURES_SUMMARY.md) - Data structure documentation
- [Field Analysis Implementation](v1.4.0/FIELD_ANALYSIS_IMPLEMENTATION.md) - Field analysis features
- [Fixes Applied](v1.4.0/FIXES_APPLIED_V1.4.0.md) - Bug fixes and corrections

## Documentation Standards

Each release directory should contain:

1. **Release Notes** (`RELEASE_NOTES.md` or `RELEASE_NOTES_vX.Y.Z.md`) - User-facing changes
2. **Implementation Details** - Technical implementation specifics
3. **Feature Status** - Feature completion and status reports
4. **Bug Fixes** - Detailed fix documentation
5. **Verification Reports** - Testing and validation results

## Navigation

- For the latest release: See [v1.9.2/](v1.9.2/)
- For specific versions: Browse the version directories above
- For overall project changes: See [CHANGELOG.md](../CHANGELOG.md) in the project root
