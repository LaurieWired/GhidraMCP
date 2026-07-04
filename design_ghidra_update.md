# Ghidra 12.1.2 Update Design

## Understanding Summary
*   **What is being built**: An update to the GhidraMCP extension to make it compatible with Ghidra 12.1.2. This includes updating code version strings, establishing a local dependency copying mechanism, and updating the GitHub Actions CI/CD pipeline.
*   **Why it exists**: The extension currently explicitly targets Ghidra 11.3.2, preventing it from building and running against the local 12.1.2 installation.
*   **Who it is for**: Developers and users looking to run this extension on the latest Ghidra releases.
*   **Key constraints**: Local paths to Ghidra must not be hardcoded in version control. The build must remain functional for automated CI/CD pipelines.
*   **Explicit non-goals**: We are not migrating the build system from Maven to Gradle, nor are we adding new functionality to the extension beyond ensuring 12.1.2 compatibility.

## Assumptions
*   The local JAR copy mechanism will be implemented via a clean, standalone PowerShell script (`update_jars.ps1`) that reads an environment variable (e.g., `GHIDRA_INSTALL_DIR`) to find the local installation.
*   The CI/CD pipeline will continue to download Ghidra automatically using the updated version and release date.
*   We assume that any required API refactoring due to changes between Ghidra 11.3.2 and 12.1.2 will be handled dynamically during the implementation phase guided by compiler output.

## Decision Log
1.  **Dependency Handling Approach**: Chose Option 1 (External Script + POM Bump) over Maven AntRun or Maven Local Repository integration.
    *   *Why*: Recommended for low complexity, easy maintenance, and keeping the CI/CD pipeline mostly unmodified.
2.  **Version targets**: Bumped from 11.3.2 to 12.1.2.
    *   *Why*: User requirement.

## Final Design

### 1. Version Updates
*   **`pom.xml`**: Update the `<version>` tags for all seven `ghidra` system dependencies from `11.3.2` to `12.1.2`.
*   **`src/main/resources/extension.properties`**: Update `version=12.1.2` and `ghidraVersion=12.1.2`.
*   **`.github/workflows/build.yml`**: Update `GHIDRA_VERSION` to `12.1.2` and `GHIDRA_DATE` to `20240924` (or the exact release date required).

### 2. Local Setup Script (`update_jars.ps1`)
*   Create a PowerShell script in the root directory.
*   **Logic**: Check for `$env:GHIDRA_INSTALL_DIR`. If missing, prompt the user. Iterate through the relative paths defined in the CI/CD pipeline, copy the JARs from the install directory to `./lib`, and overwrite any old JARs.
*   **Error Handling**: Halt and print an error if a specific JAR isn't found.

### 3. API Refactoring
*   After dependencies are updated, run `mvn clean package`.
*   Fix any compilation errors arising from deprecated or removed methods in the Ghidra 12.1.2 API.
