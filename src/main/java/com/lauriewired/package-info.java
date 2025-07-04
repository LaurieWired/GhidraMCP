/**
 * GhidraMCP - Model Context Protocol Server for Ghidra Reverse Engineering
 * 
 * <p>This package provides an HTTP server plugin that bridges Ghidra's powerful reverse
 * engineering capabilities with AI language models through the Model Context Protocol (MCP).
 * The integration enables autonomous binary analysis, function decompilation, symbol
 * management, and annotation tasks.</p>
 * 
 * <h2>Core Components</h2>
 * 
 * <dl>
 * <dt>{@link com.lauriewired.GhidraMCPPlugin}</dt>
 * <dd>The main plugin class that implements the HTTP server and all API endpoints.
 *     Handles plugin lifecycle, transaction management, and thread safety.</dd>
 * 
 * <dt>{@link com.lauriewired.GhidraMCPPlugin.PrototypeResult}</dt>
 * <dd>Result container for function prototype operations, providing detailed
 *     success/failure information and error diagnostics.</dd>
 * </dl>
 * 
 * <h2>Key Features</h2>
 * 
 * <h3>Function Analysis</h3>
 * <ul>
 * <li><strong>Decompilation:</strong> Convert assembly code to readable C pseudocode</li>
 * <li><strong>Disassembly:</strong> Generate annotated assembly listings</li>
 * <li><strong>Symbol Management:</strong> Rename functions, variables, and data labels</li>
 * <li><strong>Prototype Setting:</strong> Define function signatures and parameter types</li>
 * </ul>
 * 
 * <h3>Program Analysis</h3>
 * <ul>
 * <li><strong>Cross-Reference Analysis:</strong> Trace function calls and data usage</li>
 * <li><strong>String Extraction:</strong> Locate and filter string constants</li>
 * <li><strong>Memory Structure:</strong> Examine segments, imports, and exports</li>
 * <li><strong>Symbol Tables:</strong> Navigate namespaces and class hierarchies</li>
 * </ul>
 * 
 * <h3>Annotation and Documentation</h3>
 * <ul>
 * <li><strong>Code Comments:</strong> Add explanatory comments to assembly and pseudocode</li>
 * <li><strong>Function Documentation:</strong> Annotate purpose and behavior</li>
 * <li><strong>Data Labeling:</strong> Name and describe data structures</li>
 * </ul>
 * 
 * <h2>API Design</h2>
 * 
 * <p>The HTTP API follows RESTful principles with:</p>
 * <ul>
 * <li><strong>GET endpoints</strong> for read-only operations (listing, querying)</li>
 * <li><strong>POST endpoints</strong> for modifications (renaming, commenting)</li>
 * <li><strong>Query parameters</strong> for pagination and filtering</li>
 * <li><strong>Form data</strong> for complex operation parameters</li>
 * </ul>
 * 
 * <h2>Thread Safety and Transactions</h2>
 * 
 * <p>All Ghidra API interactions are carefully synchronized:</p>
 * <ul>
 * <li><strong>Swing EDT:</strong> Modifications use SwingUtilities.invokeAndWait()</li>
 * <li><strong>Transactions:</strong> Changes are wrapped in atomic transactions</li>
 * <li><strong>Error Handling:</strong> Failed operations are properly rolled back</li>
 * </ul>
 * 
 * <h2>Usage Requirements</h2>
 * 
 * <p>The plugin requires:</p>
 * <ol>
 * <li>Ghidra 11.3.2 or later</li>
 * <li>A loaded program in CodeBrowser</li>
 * <li>Plugin enabled in Developer tools configuration</li>
 * <li>Network access to the configured HTTP port (default: 8080)</li>
 * </ol>
 * 
 * <h2>Integration Example</h2>
 * 
 * <pre>{@code
 * // Example HTTP requests to the GhidraMCP server:
 * 
 * // List first 10 functions
 * GET /methods?offset=0&limit=10
 * 
 * // Decompile function at specific address
 * GET /decompile_function?address=0x401000
 * 
 * // Rename a function
 * POST /renameFunction
 * Content-Type: application/x-www-form-urlencoded
 * oldName=FUN_00401000&newName=parse_command_line
 * 
 * // Add a comment to assembly listing
 * POST /set_disassembly_comment
 * Content-Type: application/x-www-form-urlencoded
 * address=0x401010&comment=Initialize input buffer
 * }</pre>
 * 
 * @author LaurieWired
 * @version 1.3.2
 * @since Ghidra 11.3.2
 * @see <a href="https://github.com/LaurieWired/GhidraMCP">GhidraMCP GitHub Repository</a>
 * @see <a href="https://ghidra-sre.org/">Ghidra Software Reverse Engineering Suite</a>
 * @see <a href="https://modelcontextprotocol.io/">Model Context Protocol Specification</a>
 */
package com.lauriewired;
