# Markdown Naming Standards - Quick Reference

> **Quick guide** to markdown file naming best practices for Ghidra MCP

---

## 🎯 Key Principles

### 1. Use kebab-case (lowercase-with-hyphens)
```
✅ getting-started.md
✅ api-reference.md
✅ project-structure.md
❌ GETTING_STARTED.md
❌ API_Reference.md
❌ Project_Structure.md
```

### 2. Reserve UPPERCASE for Standards Only
```
✅ README.md          (GitHub standard)
✅ CHANGELOG.md       (industry standard)
✅ CONTRIBUTING.md    (GitHub standard)
✅ LICENSE            (legal standard)
❌ CLAUDE.md          (project-specific)
❌ START_HERE.md      (project-specific)
```

### 3. Be Descriptive
```
✅ structure-discovery-guide.md
✅ binary-analysis-report.md
❌ guide.md
❌ report.md
❌ doc1.md
```

### 4. Keep It Concise (< 40 characters)
```
✅ api-reference.md (16 chars)
✅ getting-started.md (18 chars)
⚠️ comprehensive-structure-discovery-master-guide.md (51 chars - too long)
```

---

## 📋 Current Files Assessment

### ✅ Already Following Best Practices
- `README.md` - Standard
- `CHANGELOG.md` - Standard
- `CONTRIBUTING.md` - Standard

### 🔄 Recommended Changes

| Current | Recommended | Reason |
|---------|-------------|--------|
| `START_HERE.md` | `getting-started.md` | Descriptive kebab-case |
| `DOCUMENTATION_INDEX.md` | `docs-index.md` | Shorter, kebab-case |
| `CLAUDE.md` | `ai-assistant-guide.md` | Descriptive, not tool-specific |
| `PROJECT_STRUCTURE.md` | `project-structure.md` | Consistent kebab-case |
| `NAMING_CONVENTIONS.md` | `naming-conventions.md` | Consistent kebab-case |
| `IMPROVEMENTS_QUICK_REFERENCE.md` | `improvements-quick-ref.md` | Shorter |

### 📁 Move to Subdirectories

**Reports** → `docs/reports/`:
- `ORGANIZATION_SUMMARY.md` → `docs/reports/organization-summary.md`
- `PROJECT_CLEANUP_SUMMARY.md` → `docs/reports/cleanup-summary.md`
- `QUICKWIN_COMPLETION_REPORT.md` → `docs/reports/quickwin-report.md`
- `SESSION_SUMMARY_BINARY_ANALYSIS.md` → `docs/reports/binary-analysis-session.md`
- `CLEANUP_FINAL_REPORT.md` → `docs/reports/cleanup-final.md`
- `VERSION_FIX_COMPLETE.md` → `docs/reports/version-fix-complete.md`
- `VERSION_MANAGEMENT_COMPLETE.md` → `docs/reports/version-management-complete.md`

---

## 📐 Naming Patterns by Type

### Documentation
```
<topic>-guide.md        → installation-guide.md
<topic>-reference.md    → api-reference.md
<topic>-tutorial.md     → quickstart-tutorial.md
<category>-index.md     → docs-index.md
```

### Analysis
```
<binary>-analysis.md    → game-exe-analysis.md
<dll>-analysis.md       → d2client-analysis.md
```

### Reports
```
<topic>-report.md       → performance-report.md
<topic>-summary.md      → cleanup-summary.md
<topic>-YYYY-MM.md      → milestone-2025-11.md
```

### Configuration
```
<topic>-conventions.md  → naming-conventions.md
<tool>-guide.md         → maven-guide.md
<topic>-setup.md        → environment-setup.md
```

---

## ✅ New File Checklist

Before creating a markdown file:

- [ ] Use kebab-case (lowercase with hyphens)
- [ ] Name is under 40 characters
- [ ] Name is descriptive and searchable
- [ ] Not using UPPERCASE (unless standard file)
- [ ] Not using underscores
- [ ] No spaces in filename
- [ ] Follows directory pattern
- [ ] Adds to documentation index

---

## 🚀 Implementation

See [MARKDOWN_NAMING_GUIDE.md](.github/MARKDOWN_NAMING_GUIDE.md) for:
- Complete renaming recommendations
- Migration strategy
- Impact analysis
- Safe renaming process

---

**Standard**: Proposed  
**Last Updated**: November 6, 2025
