# Markdown File Naming Best Practices

> **Standards for naming markdown files** in the Ghidra MCP project.

---

## 📋 Best Practices Summary

### ✅ Standard Conventions

1. **Use kebab-case** (lowercase with hyphens) for most files
   - ✅ `getting-started.md`
   - ❌ `GETTING_STARTED.md`

2. **Reserve UPPERCASE** for special files only
   - ✅ `README.md` - Entry point documentation
   - ✅ `CHANGELOG.md` - Version history (industry standard)
   - ✅ `CONTRIBUTING.md` - Contribution guide (GitHub standard)
   - ✅ `LICENSE.md` - License file (legal document)

3. **Use descriptive, readable names**
   - ✅ `binary-analysis-guide.md`
   - ❌ `BAG.md`

4. **Keep it concise** (under 40 characters)
   - ✅ `structure-discovery-guide.md`
   - ⚠️ `comprehensive-structure-discovery-master-guide-with-examples.md` (too long)

5. **Avoid special characters**
   - ✅ `api-reference.md`
   - ❌ `api_reference.md` (use hyphens, not underscores)
   - ❌ `api reference.md` (no spaces)

6. **Use singular form** unless plural is standard
   - ✅ `error-code.md`
   - ❌ `error-codes.md` (unless documenting multiple)

---

## 🔄 Recommended Renames

### Root Level Files

| Current Name | Recommended Name | Reason | Priority |
|--------------|------------------|--------|----------|
| **Keep As-Is (Industry Standards)** ||||
| `README.md` | ✅ Keep | GitHub/industry standard | - |
| `CHANGELOG.md` | ✅ Keep | Industry standard | - |
| `CONTRIBUTING.md` | ✅ Keep | GitHub standard | - |
| `LICENSE` | ✅ Keep | Legal standard | - |
| **Project Core** ||||
| `START_HERE.md` | `getting-started.md` | More descriptive, kebab-case | High |
| `CLAUDE.md` | `ai-assistant-guide.md` | Generic, descriptive | Medium |
| `DOCUMENTATION_INDEX.md` | `docs-index.md` | Shorter, kebab-case | High |
| `PROJECT_STRUCTURE.md` | `project-structure.md` | Consistent casing | Medium |
| **Configuration** ||||
| `NAMING_CONVENTIONS.md` | `naming-conventions.md` | Kebab-case | Medium |
| `MAVEN_VERSION_MANAGEMENT.md` | `maven-guide.md` | Shorter, clearer | Low |
| **Reports** ||||
| `ORGANIZATION_SUMMARY.md` | `reports/organization-summary.md` | Move to reports/, kebab-case | High |
| `PROJECT_CLEANUP_SUMMARY.md` | `reports/cleanup-summary.md` | Move to reports/, shorter | High |
| `QUICKWIN_COMPLETION_REPORT.md` | `reports/quickwin-report.md` | Move to reports/, shorter | High |
| `SESSION_SUMMARY_BINARY_ANALYSIS.md` | `reports/binary-analysis-session.md` | Move to reports/, clearer order | High |
| `CLEANUP_FINAL_REPORT.md` | `reports/cleanup-final.md` | Move to reports/, shorter | High |
| `VERSION_FIX_COMPLETE.md` | `reports/version-fix-complete.md` | Move to reports/, kebab-case | High |
| `VERSION_MANAGEMENT_COMPLETE.md` | `reports/version-management-complete.md` | Move to reports/, kebab-case | High |
| `VERSION_MANAGEMENT_STRATEGY.md` | `reports/version-management-strategy.md` | Move to reports/, kebab-case | High |
| **Improvements** ||||
| `IMPROVEMENTS.md` | `improvements.md` | Kebab-case | Low |
| `IMPROVEMENTS_QUICK_REFERENCE.md` | `improvements-quick-ref.md` | Shorter, kebab-case | Medium |
| `MCP_TOOLS_IMPROVEMENTS.md` | `mcp-tools-improvements.md` | Kebab-case | Medium |
| `GAME_EXE_IMPROVEMENTS.md` | `game-exe-improvements.md` | Kebab-case | Medium |

---

## 📂 Directory-Specific Naming

### docs/ Directory

**Pattern**: `<topic>-<type>.md`

Examples:
- `api-reference.md` ✅
- `development-guide.md` ✅
- `troubleshooting-guide.md` ✅
- `error-codes.md` ✅

### docs/guides/ Directory

**Pattern**: `<subject>-guide.md` or `<subject>-<action>.md`

Examples:
- `ordinal-restoration-guide.md` ✅
- `structure-discovery-guide.md` ✅
- `register-reuse-fix.md` ✅

### docs/analysis/ Directory

**Pattern**: `<binary-name>-analysis.md`

Examples:
- `game-exe-analysis.md` ✅
- `d2client-analysis.md` ✅
- `storm-library-analysis.md` ✅

### docs/reports/ Directory

**Pattern**: `<topic>-report.md` or `<topic>-<date>.md`

Examples:
- `cleanup-report.md` ✅
- `performance-report-2025-11.md` ✅
- `organization-summary.md` ✅

---

## 🎯 Implementation Plan

### Phase 1: Critical Renames (High Priority)

**Impact**: Improves discoverability and consistency

```bash
# Move reports to docs/reports/
mv ORGANIZATION_SUMMARY.md docs/reports/organization-summary.md
mv PROJECT_CLEANUP_SUMMARY.md docs/reports/cleanup-summary.md
mv QUICKWIN_COMPLETION_REPORT.md docs/reports/quickwin-report.md
mv SESSION_SUMMARY_BINARY_ANALYSIS.md docs/reports/binary-analysis-session.md
mv CLEANUP_FINAL_REPORT.md docs/reports/cleanup-final.md
mv VERSION_FIX_COMPLETE.md docs/reports/version-fix-complete.md
mv VERSION_MANAGEMENT_COMPLETE.md docs/reports/version-management-complete.md
mv VERSION_MANAGEMENT_STRATEGY.md docs/reports/version-management-strategy.md

# Rename core files
mv START_HERE.md getting-started.md
mv DOCUMENTATION_INDEX.md docs-index.md
```

### Phase 2: Consistency Updates (Medium Priority)

**Impact**: Consistent naming across project

```bash
# Rename to kebab-case
mv CLAUDE.md ai-assistant-guide.md
mv PROJECT_STRUCTURE.md project-structure.md
mv NAMING_CONVENTIONS.md naming-conventions.md
mv IMPROVEMENTS_QUICK_REFERENCE.md improvements-quick-ref.md
mv MCP_TOOLS_IMPROVEMENTS.md mcp-tools-improvements.md
mv GAME_EXE_IMPROVEMENTS.md game-exe-improvements.md
```

### Phase 3: Reference Updates (Required after renaming)

**Action items**:
1. Update all internal links in markdown files
2. Update references in code/scripts
3. Update VSCode settings
4. Update .gitignore patterns
5. Update CI/CD paths

---

## 📝 Naming Rules by File Type

### Documentation Files

| Type | Pattern | Example |
|------|---------|---------|
| Guide | `<topic>-guide.md` | `installation-guide.md` |
| Reference | `<topic>-reference.md` | `api-reference.md` |
| Tutorial | `<topic>-tutorial.md` | `quickstart-tutorial.md` |
| Index | `<category>-index.md` | `docs-index.md` |

### Analysis Files

| Type | Pattern | Example |
|------|---------|---------|
| Binary | `<name>-analysis.md` | `game-exe-analysis.md` |
| Component | `<name>-<component>.md` | `d2client-ui-analysis.md` |
| Overview | `<topic>-overview.md` | `architecture-overview.md` |

### Report Files

| Type | Pattern | Example |
|------|---------|---------|
| Status | `<topic>-status.md` | `project-status.md` |
| Summary | `<topic>-summary.md` | `cleanup-summary.md` |
| Report | `<topic>-report.md` | `performance-report.md` |
| Dated | `<topic>-YYYY-MM.md` | `milestone-2025-11.md` |

### Configuration Files

| Type | Pattern | Example |
|------|---------|---------|
| Standards | `<topic>-conventions.md` | `naming-conventions.md` |
| Config Guide | `<tool>-guide.md` | `maven-guide.md` |
| Setup | `<topic>-setup.md` | `environment-setup.md` |

---

## ✅ Checklist for New Files

Before creating a new markdown file:

- [ ] Use kebab-case (lowercase with hyphens)
- [ ] Keep name under 40 characters
- [ ] Make it descriptive and searchable
- [ ] Follow directory-specific patterns
- [ ] Avoid abbreviations unless widely known
- [ ] Check for similar existing files
- [ ] Add to appropriate index file
- [ ] Use `.md` extension (not `.markdown`)

---

## 🔍 Special Cases

### When to Use UPPERCASE

**ONLY for these standard files**:
- `README.md` - Primary documentation entry
- `CHANGELOG.md` - Version history (Keep-a-Changelog standard)
- `CONTRIBUTING.md` - Contribution guidelines (GitHub standard)
- `LICENSE` or `LICENSE.md` - Legal license file
- `CODE_OF_CONDUCT.md` - Community standards (GitHub standard)
- `SECURITY.md` - Security policies (GitHub standard)

### When to Use Underscores

**AVOID** underscores in markdown files. Use hyphens instead.

Exception: Generated files that must match tool conventions.

### When to Use Numbers

**Prefix with zero** for ordering:
- ✅ `01-introduction.md`
- ✅ `02-installation.md`
- ✅ `03-usage.md`

**Date suffixes**:
- ✅ `report-2025-11-06.md`
- ❌ `report-11-6-2025.md`

---

## 📊 Impact Analysis

### Benefits of Standardization

1. **Improved Discoverability**
   - Files easier to find with predictable patterns
   - Better IDE autocomplete

2. **Consistency**
   - Uniform appearance in file listings
   - Professional presentation

3. **Maintainability**
   - Clear naming conventions for contributors
   - Reduced confusion

4. **SEO/Search**
   - Better search results with descriptive names
   - Easier to remember and share

### Migration Effort

| Phase | Files Affected | Effort | Risk |
|-------|----------------|--------|------|
| Phase 1 | 8 reports | 1-2 hours | Low |
| Phase 2 | 6 core files | 2-3 hours | Medium |
| Phase 3 | Link updates | 3-4 hours | Medium |
| **Total** | **14 files** | **6-9 hours** | **Low-Medium** |

---

## 🚀 Migration Strategy

### Safe Renaming Process

1. **Create branch**
   ```bash
   git checkout -b standardize-markdown-names
   ```

2. **Rename files** (preserves history)
   ```bash
   git mv OLD_NAME.md new-name.md
   ```

3. **Update references**
   - Search and replace in all markdown files
   - Update scripts and code references
   - Update documentation indexes

4. **Test**
   - Verify all links work
   - Check CI/CD pipelines
   - Test local builds

5. **Commit and PR**
   ```bash
   git commit -m "refactor: standardize markdown file naming conventions"
   ```

---

## 📚 References

- [GitHub Documentation Standards](https://docs.github.com/en/communities)
- [Keep a Changelog](https://keepachangelog.com/)
- [Semantic File Names](https://semver.org/)
- [Markdown Guide](https://www.markdownguide.org/basic-syntax/)

---

**Last Updated**: November 6, 2025  
**Version**: 1.0.0  
**Status**: Proposed Standard
