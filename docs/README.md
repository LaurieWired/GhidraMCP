# Documentation Organization

This directory contains all project documentation organized by category for easy navigation and maintenance.

## Directory Structure

```text
docs/
├── project-management/     # Project administration and reports
│   ├── CLAUDE.md          # Claude AI interaction notes
│   └── CLEANUP_FINAL_REPORT.md  # Project cleanup documentation
│
├── prompts/               # AI prompting workflows and guides
│   ├── README.md         # Overview of prompting system
│   ├── FUNCTION_DOC_WORKFLOW_V*.md  # Function documentation workflows
│   ├── PLATE_COMMENT_*.md # Plate comment formatting guides
│   └── *.md              # Various specialized prompts
│
├── releases/              # Version-specific release documentation
│   ├── v1.4.0/           # Release 1.4.0 documentation
│   ├── v1.5.0/           # Release 1.5.0 documentation
│   ├── v1.5.1/           # Release 1.5.1 documentation
│   ├── v1.6.0/           # Release 1.6.0 documentation
│   ├── v1.7.0/           # Release 1.7.0 documentation
│   ├── v1.7.2/           # Release 1.7.2 documentation
│   ├── v1.7.3/           # Release 1.7.3 documentation
│   └── v1.9.2/           # Release 1.9.2 documentation
│
├── GHIDRA_VARIABLE_APIS_EXPLAINED.md  # Ghidra variable API documentation
├── MARKDOWN_NAMING.md                 # Markdown naming conventions
├── MAVEN_VERSION_MANAGEMENT.md        # Maven version management guide
├── NAMING_CONVENTIONS.md              # General naming conventions
├── ORGANIZATION_SUMMARY.md            # Project organization overview
├── PLATE_COMMENT_BEST_PRACTICES.md    # Plate comment guidelines
└── PROJECT_STRUCTURE.md               # Project structure documentation
```

## Documentation Categories

### Core Documentation (Root Level)

- **Technical guides**: Ghidra APIs, naming conventions, project structure
- **Development standards**: Code organization, best practices

### Project Management

- Administrative documentation
- Project reports and cleanup notes
- AI interaction logs and notes

### Prompts

- AI prompting workflows for function documentation
- Template prompts for various analysis tasks
- Formatting guides for comments and documentation

### Releases

- Version-specific release notes
- Implementation summaries
- Feature status reports
- Bug fix documentation

## Navigation Guidelines

1. **For developers**: Start with `PROJECT_STRUCTURE.md` and `NAMING_CONVENTIONS.md`
2. **For AI prompting**: Check `prompts/README.md` for workflow overview
3. **For release information**: Browse `releases/` by version
4. **For project history**: See `project-management/` for administrative docs

## Maintenance

- Keep this README updated when adding new documentation categories
- Follow naming conventions defined in `MARKDOWN_NAMING.md`
- Version-specific docs go in `releases/vX.Y.Z/`
- General guides stay at the top level
