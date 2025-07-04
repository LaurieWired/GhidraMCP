# GhidraMCP Documentation Guide

## Overview

This project now includes comprehensive Javadoc documentation generated with Doxygen. The documentation provides detailed information about all classes, methods, and API endpoints.

## Viewing Documentation

### Local HTML Documentation
Open `docs/html/index.html` in your web browser to view the complete documentation.

### Key Documentation Pages
- **Main Class**: [GhidraMCPPlugin](docs/html/classcom_1_1lauriewired_1_1_ghidra_m_c_p_plugin.html)
- **Package Overview**: [com.lauriewired Package](docs/html/namespacecom_1_1lauriewired.html)
- **All Classes**: [Class List](docs/html/annotated.html)
- **File Browser**: [Source Files](docs/html/files.html)

## Documentation Structure

### Class Documentation
Each class includes:
- **Detailed Description**: Purpose and functionality overview
- **Usage Examples**: Code snippets showing proper usage
- **Thread Safety Notes**: Information about concurrent access
- **See Also References**: Links to related classes and methods

### Method Documentation
Each method provides:
- **Parameter Details**: Type and purpose of each parameter
- **Return Values**: What the method returns and possible values
- **Exception Information**: When and why exceptions might be thrown
- **Code Examples**: Practical usage demonstrations
- **Cross-References**: Related methods and classes

### API Endpoint Documentation
HTTP endpoints include:
- **Request Format**: HTTP method, URL pattern, parameters
- **Response Format**: Expected output structure
- **Error Conditions**: Common failure scenarios
- **Example Requests**: Working examples with curl/HTTP

## Generating Documentation

### Prerequisites
- Doxygen 1.12+ installed and in PATH
- Graphviz (dot) for generating diagrams (optional)

### Generate Fresh Documentation
```bash
# From project root directory
doxygen Doxyfile
```

### Configuration
The `Doxyfile` contains all configuration options:
- **INPUT**: Source directories to scan
- **OUTPUT_DIRECTORY**: Where to place generated docs
- **EXTRACT_ALL**: Include private/protected members
- **GENERATE_HTML**: Create HTML output
- **CLASS_GRAPH**: Generate class hierarchy diagrams

## Documentation Standards

### Javadoc Comment Style
```java
/**
 * Brief description of the method or class.
 * 
 * Detailed description explaining the purpose, behavior,
 * and any important implementation details.
 * 
 * <h3>Usage Example:</h3>
 * <pre>{@code
 * // Example code showing proper usage
 * String result = methodName("parameter");
 * }</pre>
 * 
 * @param paramName Description of parameter purpose and constraints
 * @return Description of return value and possible states
 * @throws ExceptionType When this exception occurs
 * @see RelatedClass#relatedMethod()
 * @since Version when this was added
 */
```

### Documentation Guidelines
1. **Start with Brief Summary**: One-line description of purpose
2. **Provide Context**: Explain when and why to use this
3. **Include Examples**: Show realistic usage scenarios
4. **Document Thread Safety**: Note any concurrency concerns
5. **Cross-Reference**: Link to related functionality
6. **Explain Parameters**: Describe constraints and expected values
7. **Cover Error Cases**: Document when things can go wrong

## API Reference Quick Start

### Core Plugin Methods
- `GhidraMCPPlugin()` - Constructor and server initialization
- `startServer()` - HTTP server setup and endpoint registration
- `getCurrentProgram()` - Access to active Ghidra program
- `dispose()` - Clean shutdown and resource cleanup

### Function Analysis
- `decompileFunctionByName(String)` - Generate C pseudocode
- `decompileFunctionByAddress(String)` - Decompile by memory address
- `disassembleFunction(String)` - Get assembly listing
- `renameFunction(String, String)` - Change function names

### Symbol Management
- `renameVariableInFunction(...)` - Rename local variables
- `setFunctionPrototype(...)` - Define function signatures
- `setLocalVariableType(...)` - Set variable data types

### Program Analysis
- `getXrefsTo(String, int, int)` - Find references to address
- `getXrefsFrom(String, int, int)` - Find references from address
- `listDefinedStrings(...)` - Extract string constants

### Utility Methods
- `parseQueryParams(HttpExchange)` - Parse URL parameters
- `paginateList(List, int, int)` - Apply pagination to results
- `sendResponse(HttpExchange, String)` - Send HTTP responses

## Contributing to Documentation

### Adding New Features
When adding new methods or endpoints:
1. Follow the established Javadoc patterns
2. Include practical usage examples
3. Document thread safety considerations
4. Add cross-references to related functionality
5. Regenerate documentation: `doxygen Doxyfile`

### Improving Existing Docs
- Add missing parameter descriptions
- Include more detailed examples
- Fix broken cross-references
- Update version information
- Clarify complex algorithms

### Documentation Review Checklist
- [ ] All public methods documented
- [ ] Parameters and return values described
- [ ] Usage examples provided
- [ ] Thread safety noted where applicable
- [ ] Cross-references to related methods
- [ ] Error conditions documented
- [ ] Code examples compile and work

## Integration with IDEs

### IntelliJ IDEA
- Documentation appears in Quick Documentation (Ctrl+Q)
- Parameter hints use Javadoc descriptions
- Code completion shows method summaries

### Eclipse
- Hover tooltips display Javadoc content
- Content assist includes parameter descriptions
- Help view shows detailed documentation

### VS Code
- Hover information includes method documentation
- IntelliSense enhanced with Javadoc details
- Go to Definition includes doc comments

## Maintenance

### Regular Updates
- Regenerate docs after significant changes
- Update version numbers in package-info.java
- Review and improve unclear descriptions
- Add examples for new API patterns

### Quality Checks
- Run `doxygen Doxyfile` and check for warnings
- Verify all links work correctly
- Test examples in documentation
- Ensure diagrams generate properly

This documentation framework ensures that GhidraMCP maintains professional-grade documentation suitable for both end users and contributors in the digital forensics community.
