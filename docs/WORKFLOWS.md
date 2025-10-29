# GitHub Actions Workflows

This document describes the automated workflows for AutoREV.

## Available Workflows

### 1. Build Workflow (`build.yml`)

**Trigger:** Push to `main` or Pull Requests

**Purpose:** Builds and tests the plugin on every code change

**Steps:**
1. Downloads specified Ghidra version
2. Copies required JARs to `lib/`
3. Builds with Maven
4. Creates release artifacts

**Configuration:**
```yaml
env:
  GHIDRA_VERSION: 11.4.2
  GHIDRA_DATE: 20250826
```

---

### 2. Check Ghidra Release (`check-ghidra-release.yml`)

**Trigger:**
- Every Monday at 9:00 AM UTC (scheduled)
- Manual trigger via GitHub Actions UI

**Purpose:** Automatically monitors for new Ghidra releases

**What it does:**
1. Fetches latest Ghidra release from GitHub API
2. Compares with current version in repository
3. Creates GitHub issue if new version is available
4. Issue includes:
   - Version comparison
   - Link to release notes
   - Update checklist
   - Links to auto-update and release workflows

**Manual Trigger:**
```
Actions → Check for New Ghidra Release → Run workflow
```

---

### 3. Auto-Update Ghidra Version (`auto-update-ghidra.yml`)

**Trigger:** Manual via GitHub Actions UI

**Purpose:** Automates version updates and creates PR

**Inputs:**
- `ghidra_version` - Ghidra version (e.g., 11.4.2)
- `ghidra_date` - Release date in YYYYMMDD format

**What it does:**
1. Creates new branch: `auto-update/ghidra-{version}`
2. Updates all configuration files:
   - `.github/workflows/build.yml`
   - `pom.xml`
   - `src/main/resources/extension.properties`
3. Downloads Ghidra and tests the build
4. Commits changes
5. Creates Pull Request with:
   - Build status indicator
   - Link to Ghidra release notes
   - Review checklist

**Usage:**
```
Actions → Auto-Update Ghidra Version → Run workflow
  ghidra_version: 11.5.0
  ghidra_date: 20251015
```

---

### 4. Create Release (`create-release.yml`)

**Trigger:**
- Manual via GitHub Actions UI
- Can be called by other workflows

**Purpose:** Automatically creates GitHub releases

**Inputs:**
- `ghidra_version` - Ghidra version (e.g., 11.4.2)
- `release_notes` - Optional additional notes

**What it does:**
1. Fetches Ghidra release information from API
2. Automatically determines build date from asset filename
3. Downloads and extracts Ghidra
4. Copies required JARs
5. Builds plugin with Maven
6. Creates release artifacts:
   - `GhidraMCP-{version}.zip` - Plugin
   - `bridge_mcp_ghidra.py` - Python bridge
   - `requirements.txt` - Dependencies
   - `checksums.txt` - SHA-256 checksums
7. Generates comprehensive release notes
8. Creates GitHub release with tag `v{version}`

**Usage:**
```
Actions → Create Release on Ghidra Update → Run workflow
  ghidra_version: 11.4.2
  release_notes: "Added new features..."
```

**Generated Release:**
- **Tag:** `v11.4.2`
- **Title:** `AutoREV 11.4.2`
- **Assets:** Plugin ZIP, Python bridge, requirements, checksums
- **Notes:** Installation instructions, features, requirements

---

## Workflow Integration

### Complete Update Process

When a new Ghidra version is released:

1. **Automatic Detection**
   ```
   check-ghidra-release.yml (scheduled)
     ↓
   Creates GitHub issue
   ```

2. **Update Code**
   ```
   Manual trigger: auto-update-ghidra.yml
     ↓
   Creates PR with updated versions
     ↓
   Review and merge PR
   ```

3. **Create Release**
   ```
   Manual trigger: create-release.yml
     ↓
   Builds and publishes release
     ↓
   Users can download from releases page
   ```

### Quick Reference

| Task | Workflow | When to Use |
|------|----------|-------------|
| Monitor for new Ghidra | `check-ghidra-release.yml` | Automatic (weekly) |
| Update version in code | `auto-update-ghidra.yml` | After new Ghidra release |
| Create public release | `create-release.yml` | After merging updates |
| Test build | `build.yml` | Automatic (on push/PR) |

---

## Permissions

All workflows require specific GitHub permissions:

- **Build:** `contents: read`
- **Check Release:** `contents: read`, `issues: write`
- **Auto-Update:** `contents: write`, `pull-requests: write`
- **Create Release:** `contents: write`

These are configured via:
```yaml
permissions:
  contents: write
  pull-requests: write
```

---

## Best Practices

### For Maintainers

1. **After Ghidra Release:**
   - Wait for `check-ghidra-release.yml` to create issue (or trigger manually)
   - Run `auto-update-ghidra.yml` with new version
   - Review and test the PR
   - Merge PR to `main`
   - Run `create-release.yml` to publish

2. **Testing:**
   - Always review the auto-update PR build status
   - Test locally before releasing
   - Check changelog for API breaking changes

3. **Release Notes:**
   - Use the `release_notes` input for custom additions
   - Mention any breaking changes
   - List new features specific to your fork

### For Contributors

1. **PRs trigger `build.yml` automatically**
2. **Don't manually edit version numbers** - use `auto-update-ghidra.yml`
3. **Wait for CI to pass** before requesting review

---

## Troubleshooting

### Build Failures

**Issue:** Maven build fails in workflow

**Solution:**
- Check Ghidra download URL is correct
- Verify all 8 JARs are being copied
- Review build logs for specific errors

### Release Creation Fails

**Issue:** Release workflow cannot create release

**Solution:**
- Verify `GITHUB_TOKEN` has permissions
- Check if tag already exists
- Ensure version string is valid

### Auto-Update PR Creation Fails

**Issue:** PR creation fails or has conflicts

**Solution:**
- Ensure base branch is up to date
- Check for existing branches with same name
- Verify file paths in `sed` commands are correct

---

## Configuration Variables

### Environment Variables

Located in workflow files:

```yaml
env:
  GHIDRA_VERSION: 11.4.2      # Current Ghidra version
  GHIDRA_DATE: 20250826       # Build date from filename
  GHIDRA_LIBS: >-             # JARs to copy
    Features/Base/lib/Base.jar
    Features/Decompiler/lib/Decompiler.jar
    ...
```

### Secrets

Required secrets (automatically provided by GitHub):
- `GITHUB_TOKEN` - For API access and release creation

No additional secrets needed!

---

## Examples

### Example 1: Update to Ghidra 11.5.0

```bash
# Step 1: Issue is created automatically (or trigger check manually)
# Step 2: Run auto-update workflow
Actions → Auto-Update Ghidra Version → Run workflow
  ghidra_version: 11.5.0
  ghidra_date: 20251201  # Find this from Ghidra release assets

# Step 3: Review PR, test, merge
# Step 4: Create release
Actions → Create Release on Ghidra Update → Run workflow
  ghidra_version: 11.5.0
  release_notes: "Updated to support Ghidra 11.5.0 with new features..."
```

### Example 2: Hotfix Release

```bash
# For releases without version change (bug fixes only)
# Just create a new release with patch version

Actions → Create Release on Ghidra Update → Run workflow
  ghidra_version: 11.4.2
  release_notes: "Hotfix: Fixed critical bug in bookmark management"
```

---

## Future Enhancements

Potential workflow improvements:

1. **Automated Testing**
   - Add integration tests
   - Test plugin in actual Ghidra instance

2. **Release Automation**
   - Trigger release automatically after PR merge
   - Add changelogs from commit messages

3. **Multi-Version Support**
   - Build for multiple Ghidra versions
   - Create matrix builds

4. **Notification Integration**
   - Discord/Slack notifications
   - Email alerts for new releases

---

Last Updated: October 2025
