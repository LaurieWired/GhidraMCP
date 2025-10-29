package com.lauriewired;

import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.cmd.function.SetVariableNameCmd;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.listing.Variable;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.decompiler.ClangToken;
import ghidra.framework.options.Options;
import ghidra.program.model.block.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Category;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.InstructionIterator;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import javax.swing.SwingUtilities;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.app.DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "HTTP server plugin",
    description = "Starts an embedded HTTP server to expose program data. Port configurable via Tool Options."
)
public class GhidraMCPPlugin extends Plugin {

    private HttpServer server;
    private static final String OPTION_CATEGORY_NAME = "GhidraMCP HTTP Server";
    private static final String PORT_OPTION_NAME = "Server Port";
    private static final int DEFAULT_PORT = 8080;

    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
        Msg.info(this, "GhidraMCPPlugin loading...");

        // Register the configuration option
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        options.registerOption(PORT_OPTION_NAME, DEFAULT_PORT,
            null, // No help location for now
            "The network port number the embedded HTTP server will listen on. " +
            "Requires Ghidra restart or plugin reload to take effect after changing.");

        try {
            startServer();
        }
        catch (IOException e) {
            Msg.error(this, "Failed to start HTTP server", e);
        }
        Msg.info(this, "GhidraMCPPlugin loaded!");
    }

    private void startServer() throws IOException {
        // Read the configured port
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        int port = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);

        // Stop existing server if running (e.g., if plugin is reloaded)
        if (server != null) {
            Msg.info(this, "Stopping existing HTTP server before starting new one.");
            server.stop(0);
            server = null;
        }

        server = HttpServer.create(new InetSocketAddress(port), 0);

        // Each listing endpoint uses offset & limit from query params:
        server.createContext("/methods", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, getAllFunctionNames(offset, limit));
        });

        server.createContext("/classes", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, getAllClassNames(offset, limit));
        });

        server.createContext("/decompile", exchange -> {
            String name = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            sendResponse(exchange, decompileFunctionByName(name));
        });

        server.createContext("/renameFunction", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String response = renameFunction(params.get("oldName"), params.get("newName"))
                    ? "Renamed successfully" : "Rename failed";
            sendResponse(exchange, response);
        });

        server.createContext("/renameData", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            renameDataAtAddress(params.get("address"), params.get("newName"));
            sendResponse(exchange, "Rename data attempted");
        });

        server.createContext("/renameVariable", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionName = params.get("functionName");
            String oldName = params.get("oldName");
            String newName = params.get("newName");
            String result = renameVariableInFunction(functionName, oldName, newName);
            sendResponse(exchange, result);
        });

        server.createContext("/segments", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listSegments(offset, limit));
        });

        server.createContext("/imports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listImports(offset, limit));
        });

        server.createContext("/exports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listExports(offset, limit));
        });

        server.createContext("/namespaces", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listNamespaces(offset, limit));
        });

        server.createContext("/data", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listDefinedData(offset, limit));
        });

        server.createContext("/searchFunctions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String searchTerm = qparams.get("query");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, searchFunctionsByName(searchTerm, offset, limit));
        });

        // New API endpoints based on requirements
        
        server.createContext("/get_function_by_address", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, getFunctionByAddress(address));
        });

        server.createContext("/get_current_address", exchange -> {
            sendResponse(exchange, getCurrentAddress());
        });

        server.createContext("/get_current_function", exchange -> {
            sendResponse(exchange, getCurrentFunction());
        });

        server.createContext("/list_functions", exchange -> {
            sendResponse(exchange, listFunctions());
        });

        server.createContext("/decompile_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, decompileFunctionByAddress(address));
        });

        server.createContext("/disassemble_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, disassembleFunction(address));
        });

        server.createContext("/set_decompiler_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = setDecompilerComment(address, comment);
            sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        server.createContext("/set_disassembly_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = setDisassemblyComment(address, comment);
            sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        server.createContext("/rename_function_by_address", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String newName = params.get("new_name");
            boolean success = renameFunctionByAddress(functionAddress, newName);
            sendResponse(exchange, success ? "Function renamed successfully" : "Failed to rename function");
        });

        server.createContext("/set_function_prototype", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String prototype = params.get("prototype");

            // Call the set prototype function and get detailed result
            PrototypeResult result = setFunctionPrototype(functionAddress, prototype);

            if (result.isSuccess()) {
                // Even with successful operations, include any warning messages for debugging
                String successMsg = "Function prototype set successfully";
                if (!result.getErrorMessage().isEmpty()) {
                    successMsg += "\n\nWarnings/Debug Info:\n" + result.getErrorMessage();
                }
                sendResponse(exchange, successMsg);
            } else {
                // Return the detailed error message to the client
                sendResponse(exchange, "Failed to set function prototype: " + result.getErrorMessage());
            }
        });

        server.createContext("/set_local_variable_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String variableName = params.get("variable_name");
            String newType = params.get("new_type");

            // Capture detailed information about setting the type
            StringBuilder responseMsg = new StringBuilder();
            responseMsg.append("Setting variable type: ").append(variableName)
                      .append(" to ").append(newType)
                      .append(" in function at ").append(functionAddress).append("\n\n");

            // Attempt to find the data type in various categories
            Program program = getCurrentProgram();
            if (program != null) {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType directType = findDataTypeByNameInAllCategories(dtm, newType);
                if (directType != null) {
                    responseMsg.append("Found type: ").append(directType.getPathName()).append("\n");
                } else if (newType.startsWith("P") && newType.length() > 1) {
                    String baseTypeName = newType.substring(1);
                    DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
                    if (baseType != null) {
                        responseMsg.append("Found base type for pointer: ").append(baseType.getPathName()).append("\n");
                    } else {
                        responseMsg.append("Base type not found for pointer: ").append(baseTypeName).append("\n");
                    }
                } else {
                    responseMsg.append("Type not found directly: ").append(newType).append("\n");
                }
            }

            // Try to set the type
            boolean success = setLocalVariableType(functionAddress, variableName, newType);

            String successMsg = success ? "Variable type set successfully" : "Failed to set variable type";
            responseMsg.append("\nResult: ").append(successMsg);

            sendResponse(exchange, responseMsg.toString());
        });

        server.createContext("/xrefs_to", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getXrefsTo(address, offset, limit));
        });

        server.createContext("/xrefs_from", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getXrefsFrom(address, offset, limit));
        });

        server.createContext("/function_xrefs", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = qparams.get("name");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getFunctionXrefs(name, offset, limit));
        });

        server.createContext("/strings", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String filter = qparams.get("filter");
            sendResponse(exchange, listDefinedStrings(offset, limit, filter));
        });

        // Bookmark endpoints
        server.createContext("/bookmarks", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String type = qparams.get("type");  // Optional filter by type
            sendResponse(exchange, listBookmarks(offset, limit, type));
        });

        server.createContext("/add_bookmark", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String addressStr = params.get("address");
            String type = params.get("type");
            String category = params.get("category");
            String comment = params.get("comment");
            String result = addBookmark(addressStr, type, category, comment);
            sendResponse(exchange, result);
        });

        server.createContext("/remove_bookmark", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String addressStr = qparams.get("address");
            String type = qparams.get("type");
            String result = removeBookmark(addressStr, type);
            sendResponse(exchange, result);
        });

        server.createContext("/bookmark_types", exchange -> {
            sendResponse(exchange, listBookmarkTypes());
        });

        // Advanced Analysis endpoints
        server.createContext("/analyze_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, analyzeFunction(address));
        });

        server.createContext("/program_stats", exchange -> {
            sendResponse(exchange, getProgramStatistics());
        });

        server.createContext("/read_memory", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int size = parseIntOrDefault(qparams.get("size"), 16);
            String format = qparams.get("format"); // "hex" or "raw"
            sendResponse(exchange, readMemory(address, size, format));
        });

        server.createContext("/search_memory", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String pattern = params.get("pattern");
            String startAddr = params.get("start");
            String endAddr = params.get("end");
            int limit = parseIntOrDefault(params.get("limit"), 100);
            sendResponse(exchange, searchMemory(pattern, startAddr, endAddr, limit));
        });

        server.createContext("/memory_map", exchange -> {
            sendResponse(exchange, getDetailedMemoryMap());
        });

        server.createContext("/basic_blocks", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, getBasicBlocks(address));
        });

        server.createContext("/control_flow_graph", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, getControlFlowGraph(address));
        });

        server.createContext("/call_graph", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int depth = parseIntOrDefault(qparams.get("depth"), 3);
            String direction = qparams.get("direction"); // "callers", "callees", or "both"
            sendResponse(exchange, getCallGraph(address, depth, direction));
        });

        // Data Type Operations
        server.createContext("/list_data_types", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String category = qparams.get("category");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, listDataTypes(category, offset, limit));
        });

        server.createContext("/data_type_info", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String typeName = qparams.get("name");
            sendResponse(exchange, getDataTypeInfo(typeName));
        });

        server.createContext("/create_data", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String typeName = params.get("type");
            sendResponse(exchange, createDataAtAddress(address, typeName));
        });

        server.createContext("/delete_data", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            sendResponse(exchange, deleteDataAtAddress(address));
        });

        server.createContext("/apply_data_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String typeName = params.get("type");
            sendResponse(exchange, applyDataType(address, typeName));
        });

        // Enhanced Decompilation endpoints
        server.createContext("/decompile_advanced", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String simplificationStyle = params.get("simplification_style"); // "normalize", "decompile", "firstpass", etc.
            boolean includeSyntaxTree = "true".equalsIgnoreCase(params.get("include_syntax_tree"));
            int timeout = parseIntOrDefault(params.get("timeout"), 60);
            sendResponse(exchange, decompileAdvanced(address, simplificationStyle, includeSyntaxTree, timeout));
        });

        server.createContext("/decompile_with_options", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String optionsJson = params.get("options"); // JSON string with decompiler options
            sendResponse(exchange, decompileWithOptions(address, optionsJson));
        });

        server.createContext("/get_syntax_tree", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            sendResponse(exchange, getSyntaxTree(address));
        });

        server.createContext("/decompile_raw", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            sendResponse(exchange, decompileRaw(address));
        });

        // Health check endpoint
        server.createContext("/health", exchange -> {
            String status = "healthy";
            boolean hasProgramLoaded = false;
            String programName = "none";

            try {
                ProgramManager pm = tool.getService(ProgramManager.class);
                if (pm != null && pm.getCurrentProgram() != null) {
                    hasProgramLoaded = true;
                    programName = pm.getCurrentProgram().getName();
                }
            } catch (Exception e) {
                status = "degraded";
            }

            String healthResponse = String.format(
                "{\"status\":\"%s\",\"server\":\"running\",\"program_loaded\":%b,\"program_name\":\"%s\"}",
                status, hasProgramLoaded, programName
            );
            sendJsonResponse(exchange, healthResponse, 200);
        });

        // Version endpoint
        server.createContext("/version", exchange -> {
            String version = "11.4.2";  // GhidraMCP version (matches Ghidra version)
            String pluginName = "GhidraMCP";

            String versionResponse = String.format(
                "{\"plugin\":\"%s\",\"version\":\"%s\",\"ghidra_version\":\"%s\"}",
                pluginName, version, version
            );
            sendJsonResponse(exchange, versionResponse, 200);
        });

        // API info endpoint - lists all available endpoints
        server.createContext("/api/info", exchange -> {
            StringBuilder info = new StringBuilder();
            info.append("GhidraMCP API Endpoints:\n\n");
            info.append("GET  /health - Health check\n");
            info.append("GET  /version - Version information\n");
            info.append("GET  /api/info - This endpoint\n\n");
            info.append("GET  /methods?offset=0&limit=100 - List function names\n");
            info.append("GET  /classes?offset=0&limit=100 - List class names\n");
            info.append("GET  /list_functions?offset=0&limit=100 - List all functions\n");
            info.append("GET  /segments?offset=0&limit=100 - List memory segments\n");
            info.append("GET  /imports?offset=0&limit=100 - List imports\n");
            info.append("GET  /exports?offset=0&limit=100 - List exports\n");
            info.append("GET  /namespaces?offset=0&limit=100 - List namespaces\n");
            info.append("GET  /data?offset=0&limit=100 - List data items\n");
            info.append("GET  /strings?offset=0&limit=100&filter=text - List strings\n");
            info.append("GET  /get_current_address - Get current cursor address\n");
            info.append("GET  /get_current_function - Get current function\n");
            info.append("GET  /searchFunctions?query=name - Search functions\n");
            info.append("GET  /get_function_by_address?address=0x... - Get function info\n");
            info.append("GET  /xrefs_to?address=0x... - Get references TO address\n");
            info.append("GET  /xrefs_from?address=0x... - Get references FROM address\n");
            info.append("GET  /function_xrefs?name=func - Get function cross-references\n\n");
            info.append("POST /decompile - Decompile function by name\n");
            info.append("POST /decompile_function?address=0x... - Decompile by address\n");
            info.append("POST /disassemble_function?address=0x... - Disassemble by address\n");
            info.append("POST /renameFunction - Rename function (oldName, newName)\n");
            info.append("POST /rename_function_by_address?address=0x...&name=new - Rename by address\n");
            info.append("POST /renameData - Rename data (address, newName)\n");
            info.append("POST /renameVariable - Rename variable (functionName, oldName, newName)\n");
            info.append("POST /set_function_prototype - Set function signature\n");
            info.append("POST /set_local_variable_type - Set variable type\n");
            info.append("POST /set_decompiler_comment - Add pseudocode comment\n");
            info.append("POST /set_disassembly_comment - Add assembly comment\n\n");
            info.append("GET  /bookmarks?offset=0&limit=100&type=NOTE - List bookmarks (optional type filter)\n");
            info.append("POST /add_bookmark - Add bookmark (address, type, category, comment)\n");
            info.append("GET  /remove_bookmark?address=0x...&type=NOTE - Remove bookmark\n");
            info.append("GET  /bookmark_types - List available bookmark types\n\n");

            info.append("=== ADVANCED ANALYSIS ===\n");
            info.append("GET  /analyze_function?address=0x... - Comprehensive function analysis\n");
            info.append("GET  /program_stats - Program statistics and metadata\n");
            info.append("GET  /read_memory?address=0x...&size=16&format=hex - Read memory bytes\n");
            info.append("POST /search_memory - Search for byte pattern (pattern, start, end, limit)\n");
            info.append("GET  /memory_map - Detailed memory map with permissions\n");
            info.append("GET  /basic_blocks?address=0x... - List basic blocks for function\n");
            info.append("GET  /control_flow_graph?address=0x... - Get CFG for function\n");
            info.append("GET  /call_graph?address=0x...&depth=3&direction=both - Build call graph\n\n");

            info.append("=== DATA TYPE OPERATIONS ===\n");
            info.append("GET  /list_data_types?category=&offset=0&limit=100 - List data types\n");
            info.append("GET  /data_type_info?name=DWORD - Get data type details\n");
            info.append("POST /create_data - Create data (address, type)\n");
            info.append("POST /delete_data - Delete data (address)\n");
            info.append("POST /apply_data_type - Apply type to address (address, type)\n\n");

            info.append("=== ENHANCED DECOMPILATION ===\n");
            info.append("POST /decompile_advanced - Advanced decompile (address, simplification_style, include_syntax_tree, timeout)\n");
            info.append("POST /decompile_with_options - Decompile with custom options (address)\n");
            info.append("POST /get_syntax_tree - Get AST/syntax tree (address)\n");
            info.append("POST /decompile_raw - Raw decompile with minimal processing (address)\n");
            info.append("\nSimplification styles: decompile, normalize, firstpass, paramid, jumptable, unreachable\n");

            sendResponse(exchange, info.toString());
        });

        server.setExecutor(null);
        new Thread(() -> {
            try {
                server.start();
                Msg.info(this, "GhidraMCP HTTP server started on port " + port);
            } catch (Exception e) {
                Msg.error(this, "Failed to start HTTP server on port " + port + ". Port might be in use.", e);
                server = null; // Ensure server isn't considered running
            }
        }, "GhidraMCP-HTTP-Server").start();
    }

    // ----------------------------------------------------------------------------------
    // Pagination-aware listing methods
    // ----------------------------------------------------------------------------------

    private String getAllFunctionNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> names = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            names.add(f.getName());
        }
        return paginateList(names, offset, limit);
    }

    private String getAllClassNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> classNames = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !ns.isGlobal()) {
                classNames.add(ns.getName());
            }
        }
        // Convert set to list for pagination
        List<String> sorted = new ArrayList<>(classNames);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listSegments(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            lines.add(String.format("%s: %s - %s", block.getName(), block.getStart(), block.getEnd()));
        }
        return paginateList(lines, offset, limit);
    }

    private String listImports(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (Symbol symbol : program.getSymbolTable().getExternalSymbols()) {
            lines.add(symbol.getName() + " -> " + symbol.getAddress());
        }
        return paginateList(lines, offset, limit);
    }

    private String listExports(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        SymbolTable table = program.getSymbolTable();
        SymbolIterator it = table.getAllSymbols(true);

        List<String> lines = new ArrayList<>();
        while (it.hasNext()) {
            Symbol s = it.next();
            // On older Ghidra, "export" is recognized via isExternalEntryPoint()
            if (s.isExternalEntryPoint()) {
                lines.add(s.getName() + " -> " + s.getAddress());
            }
        }
        return paginateList(lines, offset, limit);
    }

    private String listNamespaces(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> namespaces = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !(ns instanceof GlobalNamespace)) {
                namespaces.add(ns.getName());
            }
        }
        List<String> sorted = new ArrayList<>(namespaces);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listDefinedData(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
            while (it.hasNext()) {
                Data data = it.next();
                if (block.contains(data.getAddress())) {
                    String label   = data.getLabel() != null ? data.getLabel() : "(unnamed)";
                    String valRepr = data.getDefaultValueRepresentation();
                    lines.add(String.format("%s: %s = %s",
                        data.getAddress(),
                        escapeNonAscii(label),
                        escapeNonAscii(valRepr)
                    ));
                }
            }
        }
        return paginateList(lines, offset, limit);
    }

    private String searchFunctionsByName(String searchTerm, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (searchTerm == null || searchTerm.isEmpty()) return "Search term is required";
    
        List<String> matches = new ArrayList<>();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            String name = func.getName();
            // simple substring match
            if (name.toLowerCase().contains(searchTerm.toLowerCase())) {
                matches.add(String.format("%s @ %s", name, func.getEntryPoint()));
            }
        }
    
        Collections.sort(matches);
    
        if (matches.isEmpty()) {
            return "No functions matching '" + searchTerm + "'";
        }
        return paginateList(matches, offset, limit);
    }    

    // ----------------------------------------------------------------------------------
    // Logic for rename, decompile, etc.
    // ----------------------------------------------------------------------------------

    private String decompileFunctionByName(String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (func.getName().equals(name)) {
                DecompileResults result =
                    decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
                if (result != null && result.decompileCompleted()) {
                    return result.getDecompiledFunction().getC();
                } else {
                    return "Decompilation failed";
                }
            }
        }
        return "Function not found";
    }

    private boolean renameFunction(String oldName, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;

        AtomicBoolean successFlag = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename function via HTTP");
                try {
                    for (Function func : program.getFunctionManager().getFunctions(true)) {
                        if (func.getName().equals(oldName)) {
                            func.setName(newName, SourceType.USER_DEFINED);
                            successFlag.set(true);
                            break;
                        }
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Error renaming function", e);
                }
                finally {
                    successFlag.set(program.endTransaction(tx, successFlag.get()));
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename on Swing thread", e);
        }
        return successFlag.get();
    }

    private void renameDataAtAddress(String addressStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return;

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename data");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    Listing listing = program.getListing();
                    Data data = listing.getDefinedDataAt(addr);
                    if (data != null) {
                        SymbolTable symTable = program.getSymbolTable();
                        Symbol symbol = symTable.getPrimarySymbol(addr);
                        if (symbol != null) {
                            symbol.setName(newName, SourceType.USER_DEFINED);
                        } else {
                            symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                        }
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Rename data error", e);
                }
                finally {
                    program.endTransaction(tx, true);
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename data on Swing thread", e);
        }
    }

    private String renameVariableInFunction(String functionName, String oldVarName, String newVarName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);

        Function func = null;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                func = f;
                break;
            }
        }

        if (func == null) {
            return "Function not found";
        }

        DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
        if (result == null || !result.decompileCompleted()) {
            return "Decompilation failed";
        }

        HighFunction highFunction = result.getHighFunction();
        if (highFunction == null) {
            return "Decompilation failed (no high function)";
        }

        LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
        if (localSymbolMap == null) {
            return "Decompilation failed (no local symbol map)";
        }

        HighSymbol highSymbol = null;
        Iterator<HighSymbol> symbols = localSymbolMap.getSymbols();
        while (symbols.hasNext()) {
            HighSymbol symbol = symbols.next();
            String symbolName = symbol.getName();
            
            if (symbolName.equals(oldVarName)) {
                highSymbol = symbol;
            }
            if (symbolName.equals(newVarName)) {
                return "Error: A variable with name '" + newVarName + "' already exists in this function";
            }
        }

        if (highSymbol == null) {
            return "Variable not found";
        }

        boolean commitRequired = checkFullCommit(highSymbol, highFunction);

        final HighSymbol finalHighSymbol = highSymbol;
        final Function finalFunction = func;
        AtomicBoolean successFlag = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {           
                int tx = program.startTransaction("Rename variable");
                try {
                    if (commitRequired) {
                        HighFunctionDBUtil.commitParamsToDatabase(highFunction, false,
                            ReturnCommitOption.NO_COMMIT, finalFunction.getSignatureSource());
                    }
                    HighFunctionDBUtil.updateDBVariable(
                        finalHighSymbol,
                        newVarName,
                        null,
                        SourceType.USER_DEFINED
                    );
                    successFlag.set(true);
                }
                catch (Exception e) {
                    Msg.error(this, "Failed to rename variable", e);
                }
                finally {
                    successFlag.set(program.endTransaction(tx, true));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            String errorMsg = "Failed to execute rename on Swing thread: " + e.getMessage();
            Msg.error(this, errorMsg, e);
            return errorMsg;
        }
        return successFlag.get() ? "Variable renamed" : "Failed to rename variable";
    }

    /**
     * Copied from AbstractDecompilerAction.checkFullCommit, it's protected.
	 * Compare the given HighFunction's idea of the prototype with the Function's idea.
	 * Return true if there is a difference. If a specific symbol is being changed,
	 * it can be passed in to check whether or not the prototype is being affected.
	 * @param highSymbol (if not null) is the symbol being modified
	 * @param hfunction is the given HighFunction
	 * @return true if there is a difference (and a full commit is required)
	 */
	protected static boolean checkFullCommit(HighSymbol highSymbol, HighFunction hfunction) {
		if (highSymbol != null && !highSymbol.isParameter()) {
			return false;
		}
		Function function = hfunction.getFunction();
		Parameter[] parameters = function.getParameters();
		LocalSymbolMap localSymbolMap = hfunction.getLocalSymbolMap();
		int numParams = localSymbolMap.getNumParams();
		if (numParams != parameters.length) {
			return true;
		}

		for (int i = 0; i < numParams; i++) {
			HighSymbol param = localSymbolMap.getParamSymbol(i);
			if (param.getCategoryIndex() != i) {
				return true;
			}
			VariableStorage storage = param.getStorage();
			// Don't compare using the equals method so that DynamicVariableStorage can match
			if (0 != storage.compareTo(parameters[i].getVariableStorage())) {
				return true;
			}
		}

		return false;
	}

    // ----------------------------------------------------------------------------------
    // New methods to implement the new functionalities
    // ----------------------------------------------------------------------------------

    /**
     * Get function by address
     */
    private String getFunctionByAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = program.getFunctionManager().getFunctionAt(addr);

            if (func == null) return "No function found at address " + addressStr;

            return String.format("Function: %s at %s\nSignature: %s\nEntry: %s\nBody: %s - %s",
                func.getName(),
                func.getEntryPoint(),
                func.getSignature(),
                func.getEntryPoint(),
                func.getBody().getMinAddress(),
                func.getBody().getMaxAddress());
        } catch (Exception e) {
            return "Error getting function: " + e.getMessage();
        }
    }

    /**
     * Get current address selected in Ghidra GUI
     */
    private String getCurrentAddress() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        return (location != null) ? location.getAddress().toString() : "No current location";
    }

    /**
     * Get current function selected in Ghidra GUI
     */
    private String getCurrentFunction() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        if (location == null) return "No current location";

        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Function func = program.getFunctionManager().getFunctionContaining(location.getAddress());
        if (func == null) return "No function at current location: " + location.getAddress();

        return String.format("Function: %s at %s\nSignature: %s",
            func.getName(),
            func.getEntryPoint(),
            func.getSignature());
    }

    /**
     * List all functions in the database
     */
    private String listFunctions() {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        StringBuilder result = new StringBuilder();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            result.append(String.format("%s at %s\n", 
                func.getName(), 
                func.getEntryPoint()));
        }

        return result.toString();
    }

    /**
     * Gets a function at the given address or containing the address
     * @return the function or null if not found
     */
    private Function getFunctionForAddress(Program program, Address addr) {
        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = program.getFunctionManager().getFunctionContaining(addr);
        }
        return func;
    }

    /**
     * Decompile a function at the given address
     */
    private String decompileFunctionByAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(program);
            DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());

            return (result != null && result.decompileCompleted()) 
                ? result.getDecompiledFunction().getC() 
                : "Decompilation failed";
        } catch (Exception e) {
            return "Error decompiling function: " + e.getMessage();
        }
    }

    /**
     * Get assembly code for a function
     */
    private String disassembleFunction(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            StringBuilder result = new StringBuilder();
            Listing listing = program.getListing();
            Address start = func.getEntryPoint();
            Address end = func.getBody().getMaxAddress();

            InstructionIterator instructions = listing.getInstructions(start, true);
            while (instructions.hasNext()) {
                Instruction instr = instructions.next();
                if (instr.getAddress().compareTo(end) > 0) {
                    break; // Stop if we've gone past the end of the function
                }
                String comment = listing.getComment(CodeUnit.EOL_COMMENT, instr.getAddress());
                comment = (comment != null) ? "; " + comment : "";

                result.append(String.format("%s: %s %s\n", 
                    instr.getAddress(), 
                    instr.toString(),
                    comment));
            }

            return result.toString();
        } catch (Exception e) {
            return "Error disassembling function: " + e.getMessage();
        }
    }    

    /**
     * Set a comment using the specified comment type (PRE_COMMENT or EOL_COMMENT)
     */
    private boolean setCommentAtAddress(String addressStr, String comment, int commentType, String transactionName) {
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (addressStr == null || addressStr.isEmpty() || comment == null) return false;

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction(transactionName);
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    program.getListing().setComment(addr, commentType, comment);
                    success.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Error setting " + transactionName.toLowerCase(), e);
                } finally {
                    success.set(program.endTransaction(tx, success.get()));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute " + transactionName.toLowerCase() + " on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Set a comment for a given address in the function pseudocode
     */
    private boolean setDecompilerComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.PRE_COMMENT, "Set decompiler comment");
    }

    /**
     * Set a comment for a given address in the function disassembly
     */
    private boolean setDisassemblyComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.EOL_COMMENT, "Set disassembly comment");
    }

    /**
     * Class to hold the result of a prototype setting operation
     */
    private static class PrototypeResult {
        private final boolean success;
        private final String errorMessage;

        public PrototypeResult(boolean success, String errorMessage) {
            this.success = success;
            this.errorMessage = errorMessage;
        }

        public boolean isSuccess() {
            return success;
        }

        public String getErrorMessage() {
            return errorMessage;
        }
    }

    /**
     * Rename a function by its address
     */
    private boolean renameFunctionByAddress(String functionAddrStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() || 
            newName == null || newName.isEmpty()) {
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                performFunctionRename(program, functionAddrStr, newName, success);
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename function on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Helper method to perform the actual function rename within a transaction
     */
    private void performFunctionRename(Program program, String functionAddrStr, String newName, AtomicBoolean success) {
        int tx = program.startTransaction("Rename function by address");
        try {
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }

            func.setName(newName, SourceType.USER_DEFINED);
            success.set(true);
        } catch (Exception e) {
            Msg.error(this, "Error renaming function by address", e);
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    /**
     * Set a function's prototype with proper error handling using ApplyFunctionSignatureCmd
     */
    private PrototypeResult setFunctionPrototype(String functionAddrStr, String prototype) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) return new PrototypeResult(false, "No program loaded");
        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return new PrototypeResult(false, "Function address is required");
        }
        if (prototype == null || prototype.isEmpty()) {
            return new PrototypeResult(false, "Function prototype is required");
        }

        final StringBuilder errorMessage = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> 
                applyFunctionPrototype(program, functionAddrStr, prototype, success, errorMessage));
        } catch (InterruptedException | InvocationTargetException e) {
            String msg = "Failed to set function prototype on Swing thread: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }

        return new PrototypeResult(success.get(), errorMessage.toString());
    }

    /**
     * Helper method that applies the function prototype within a transaction
     */
    private void applyFunctionPrototype(Program program, String functionAddrStr, String prototype, 
                                       AtomicBoolean success, StringBuilder errorMessage) {
        try {
            // Get the address and function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                String msg = "Could not find function at address: " + functionAddrStr;
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            Msg.info(this, "Setting prototype for function " + func.getName() + ": " + prototype);

            // Store original prototype as a comment for reference
            addPrototypeComment(program, func, prototype);

            // Use ApplyFunctionSignatureCmd to parse and apply the signature
            parseFunctionSignatureAndApply(program, addr, prototype, success, errorMessage);

        } catch (Exception e) {
            String msg = "Error setting function prototype: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }
    }

    /**
     * Add a comment showing the prototype being set
     */
    private void addPrototypeComment(Program program, Function func, String prototype) {
        int txComment = program.startTransaction("Add prototype comment");
        try {
            program.getListing().setComment(
                func.getEntryPoint(), 
                CodeUnit.PLATE_COMMENT, 
                "Setting prototype: " + prototype
            );
        } finally {
            program.endTransaction(txComment, true);
        }
    }

    /**
     * Parse and apply the function signature with error handling
     */
    private void parseFunctionSignatureAndApply(Program program, Address addr, String prototype,
                                              AtomicBoolean success, StringBuilder errorMessage) {
        // Use ApplyFunctionSignatureCmd to parse and apply the signature
        int txProto = program.startTransaction("Set function prototype");
        try {
            // Get data type manager
            DataTypeManager dtm = program.getDataTypeManager();

            // Get data type manager service
            ghidra.app.services.DataTypeManagerService dtms = 
                tool.getService(ghidra.app.services.DataTypeManagerService.class);

            // Create function signature parser
            ghidra.app.util.parser.FunctionSignatureParser parser = 
                new ghidra.app.util.parser.FunctionSignatureParser(dtm, dtms);

            // Parse the prototype into a function signature
            ghidra.program.model.data.FunctionDefinitionDataType sig = parser.parse(null, prototype);

            if (sig == null) {
                String msg = "Failed to parse function prototype";
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            // Create and apply the command
            ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd = 
                new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                    addr, sig, SourceType.USER_DEFINED);

            // Apply the command to the program
            boolean cmdResult = cmd.applyTo(program, new ConsoleTaskMonitor());

            if (cmdResult) {
                success.set(true);
                Msg.info(this, "Successfully applied function signature");
            } else {
                String msg = "Command failed: " + cmd.getStatusMsg();
                errorMessage.append(msg);
                Msg.error(this, msg);
            }
        } catch (Exception e) {
            String msg = "Error applying function signature: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        } finally {
            program.endTransaction(txProto, success.get());
        }
    }

    /**
     * Set a local variable's type using HighFunctionDBUtil.updateDBVariable
     */
    private boolean setLocalVariableType(String functionAddrStr, String variableName, String newType) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() || 
            variableName == null || variableName.isEmpty() ||
            newType == null || newType.isEmpty()) {
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> 
                applyVariableType(program, functionAddrStr, variableName, newType, success));
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute set variable type on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Helper method that performs the actual variable type change
     */
    private void applyVariableType(Program program, String functionAddrStr, 
                                  String variableName, String newType, AtomicBoolean success) {
        try {
            // Find the function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }

            DecompileResults results = decompileFunction(func, program);
            if (results == null || !results.decompileCompleted()) {
                return;
            }

            ghidra.program.model.pcode.HighFunction highFunction = results.getHighFunction();
            if (highFunction == null) {
                Msg.error(this, "No high function available");
                return;
            }

            // Find the symbol by name
            HighSymbol symbol = findSymbolByName(highFunction, variableName);
            if (symbol == null) {
                Msg.error(this, "Could not find variable '" + variableName + "' in decompiled function");
                return;
            }

            // Get high variable
            HighVariable highVar = symbol.getHighVariable();
            if (highVar == null) {
                Msg.error(this, "No HighVariable found for symbol: " + variableName);
                return;
            }

            Msg.info(this, "Found high variable for: " + variableName + 
                     " with current type " + highVar.getDataType().getName());

            // Find the data type
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dataType = resolveDataType(dtm, newType);

            if (dataType == null) {
                Msg.error(this, "Could not resolve data type: " + newType);
                return;
            }

            Msg.info(this, "Using data type: " + dataType.getName() + " for variable " + variableName);

            // Apply the type change in a transaction
            updateVariableType(program, symbol, dataType, success);

        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        }
    }

    /**
     * Find a high symbol by name in the given high function
     */
    private HighSymbol findSymbolByName(ghidra.program.model.pcode.HighFunction highFunction, String variableName) {
        Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol s = symbols.next();
            if (s.getName().equals(variableName)) {
                return s;
            }
        }
        return null;
    }

    /**
     * Decompile a function and return the results
     */
    private DecompileResults decompileFunction(Function func, Program program) {
        // Set up decompiler for accessing the decompiled function
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        decomp.setSimplificationStyle("decompile"); // Full decompilation

        // Decompile the function
        DecompileResults results = decomp.decompileFunction(func, 60, new ConsoleTaskMonitor());

        if (!results.decompileCompleted()) {
            Msg.error(this, "Could not decompile function: " + results.getErrorMessage());
            return null;
        }

        return results;
    }

    /**
     * Apply the type update in a transaction
     */
    private void updateVariableType(Program program, HighSymbol symbol, DataType dataType, AtomicBoolean success) {
        int tx = program.startTransaction("Set variable type");
        try {
            // Use HighFunctionDBUtil to update the variable with the new type
            HighFunctionDBUtil.updateDBVariable(
                symbol,                // The high symbol to modify
                symbol.getName(),      // Keep original name
                dataType,              // The new data type
                SourceType.USER_DEFINED // Mark as user-defined
            );

            success.set(true);
            Msg.info(this, "Successfully set variable type using HighFunctionDBUtil");
        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    /**
     * Get all references to a specific address (xref to)
     */
    private String getXrefsTo(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();
            
            ReferenceIterator refIter = refManager.getReferencesTo(addr);
            
            List<String> refs = new ArrayList<>();
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                RefType refType = ref.getReferenceType();
                
                Function fromFunc = program.getFunctionManager().getFunctionContaining(fromAddr);
                String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";
                
                refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references to address: " + e.getMessage();
        }
    }

    /**
     * Get all references from a specific address (xref from)
     */
    private String getXrefsFrom(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();
            
            Reference[] references = refManager.getReferencesFrom(addr);
            
            List<String> refs = new ArrayList<>();
            for (Reference ref : references) {
                Address toAddr = ref.getToAddress();
                RefType refType = ref.getReferenceType();
                
                String targetInfo = "";
                Function toFunc = program.getFunctionManager().getFunctionAt(toAddr);
                if (toFunc != null) {
                    targetInfo = " to function " + toFunc.getName();
                } else {
                    Data data = program.getListing().getDataAt(toAddr);
                    if (data != null) {
                        targetInfo = " to data " + (data.getLabel() != null ? data.getLabel() : data.getPathName());
                    }
                }
                
                refs.add(String.format("To %s%s [%s]", toAddr, targetInfo, refType.getName()));
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references from address: " + e.getMessage();
        }
    }

    /**
     * Get all references to a specific function by name
     */
    private String getFunctionXrefs(String functionName, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (functionName == null || functionName.isEmpty()) return "Function name is required";

        try {
            List<String> refs = new ArrayList<>();
            FunctionManager funcManager = program.getFunctionManager();
            for (Function function : funcManager.getFunctions(true)) {
                if (function.getName().equals(functionName)) {
                    Address entryPoint = function.getEntryPoint();
                    ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(entryPoint);
                    
                    while (refIter.hasNext()) {
                        Reference ref = refIter.next();
                        Address fromAddr = ref.getFromAddress();
                        RefType refType = ref.getReferenceType();
                        
                        Function fromFunc = funcManager.getFunctionContaining(fromAddr);
                        String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";
                        
                        refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
                    }
                }
            }
            
            if (refs.isEmpty()) {
                return "No references found to function: " + functionName;
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting function references: " + e.getMessage();
        }
    }

/**
 * List all defined strings in the program with their addresses
 */
    private String listDefinedStrings(int offset, int limit, String filter) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        DataIterator dataIt = program.getListing().getDefinedData(true);
        
        while (dataIt.hasNext()) {
            Data data = dataIt.next();
            
            if (data != null && isStringData(data)) {
                String value = data.getValue() != null ? data.getValue().toString() : "";
                
                if (filter == null || value.toLowerCase().contains(filter.toLowerCase())) {
                    String escapedValue = escapeString(value);
                    lines.add(String.format("%s: \"%s\"", data.getAddress(), escapedValue));
                }
            }
        }
        
        return paginateList(lines, offset, limit);
    }

    /**
     * Check if the given data is a string type
     */
    private boolean isStringData(Data data) {
        if (data == null) return false;
        
        DataType dt = data.getDataType();
        String typeName = dt.getName().toLowerCase();
        return typeName.contains("string") || typeName.contains("char") || typeName.equals("unicode");
    }

    // ----------------------------------------------------------------------------------
    // Bookmark Management
    // ----------------------------------------------------------------------------------

    /**
     * List all bookmarks, optionally filtered by type
     */
    private String listBookmarks(int offset, int limit, String typeFilter) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        BookmarkManager bmgr = program.getBookmarkManager();
        List<String> lines = new ArrayList<>();

        // Get all bookmark types or just the filtered one
        String[] types;
        if (typeFilter != null && !typeFilter.isEmpty()) {
            types = new String[] { typeFilter };
        } else {
            BookmarkType[] bookmarkTypes = bmgr.getBookmarkTypes();
            types = new String[bookmarkTypes.length];
            for (int i = 0; i < bookmarkTypes.length; i++) {
                types[i] = bookmarkTypes[i].getTypeString();
            }
        }

        for (String type : types) {
            Iterator<Bookmark> it = bmgr.getBookmarksIterator(type);
            while (it.hasNext()) {
                Bookmark bm = it.next();
                String category = bm.getCategory() != null ? bm.getCategory() : "(none)";
                String comment = bm.getComment() != null ? escapeString(bm.getComment()) : "";
                lines.add(String.format("%s [%s] %s: %s",
                    bm.getAddress(), type, category, comment));
            }
        }

        if (lines.isEmpty()) {
            return typeFilter != null
                ? "No bookmarks of type '" + typeFilter + "'"
                : "No bookmarks found";
        }

        Collections.sort(lines);
        return paginateList(lines, offset, limit);
    }

    /**
     * Add a bookmark at the specified address
     */
    private String addBookmark(String addressStr, String type, String category, String comment) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        // Default to NOTE type if not specified
        if (type == null || type.isEmpty()) {
            type = "NOTE";
        }

        // Validate type
        BookmarkManager bmgr = program.getBookmarkManager();
        boolean validType = false;
        BookmarkType[] bookmarkTypes = bmgr.getBookmarkTypes();
        List<String> typeNames = new ArrayList<>();
        for (BookmarkType bt : bookmarkTypes) {
            String typeName = bt.getTypeString();
            typeNames.add(typeName);
            if (typeName.equalsIgnoreCase(type)) {
                type = typeName;  // Use exact case from Ghidra
                validType = true;
            }
        }
        if (!validType) {
            return "Invalid bookmark type: " + type + ". Valid types: " + String.join(", ", typeNames);
        }

        final String finalType = type;
        final String finalCategory = (category != null && !category.isEmpty()) ? category : "";
        final String finalComment = (comment != null) ? comment : "";

        AtomicBoolean successFlag = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Add bookmark");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    if (addr == null) {
                        Msg.error(this, "Invalid address: " + addressStr);
                        return;
                    }

                    bmgr.setBookmark(addr, finalType, finalCategory, finalComment);
                    successFlag.set(true);
                }
                catch (Exception e) {
                    Msg.error(this, "Error adding bookmark", e);
                }
                finally {
                    program.endTransaction(tx, successFlag.get());
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute add bookmark on Swing thread", e);
            return "Failed to add bookmark: " + e.getMessage();
        }

        return successFlag.get()
            ? "Bookmark added successfully at " + addressStr
            : "Failed to add bookmark";
    }

    /**
     * Remove bookmark at the specified address and type
     */
    private String removeBookmark(String addressStr, String type) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        if (type == null || type.isEmpty()) return "Type is required";

        AtomicBoolean successFlag = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Remove bookmark");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    if (addr == null) {
                        Msg.error(this, "Invalid address: " + addressStr);
                        return;
                    }

                    BookmarkManager bmgr = program.getBookmarkManager();
                    Bookmark[] bookmarks = bmgr.getBookmarks(addr, type);

                    if (bookmarks.length > 0) {
                        for (Bookmark bm : bookmarks) {
                            bmgr.removeBookmark(bm);
                        }
                        successFlag.set(true);
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Error removing bookmark", e);
                }
                finally {
                    program.endTransaction(tx, successFlag.get());
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute remove bookmark on Swing thread", e);
            return "Failed to remove bookmark: " + e.getMessage();
        }

        return successFlag.get()
            ? "Bookmark removed at " + addressStr
            : "No bookmark found at " + addressStr + " with type " + type;
    }

    /**
     * List available bookmark types
     */
    private String listBookmarkTypes() {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        BookmarkManager bmgr = program.getBookmarkManager();
        BookmarkType[] bookmarkTypes = bmgr.getBookmarkTypes();
        List<String> typeNames = new ArrayList<>();
        for (BookmarkType bt : bookmarkTypes) {
            typeNames.add(bt.getTypeString());
        }

        return String.join("\n", typeNames);
    }

    /**
     * Escape special characters in a string for display
     */
    private String escapeString(String input) {
        if (input == null) return "";

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c >= 32 && c < 127) {
                sb.append(c);
            } else if (c == '\n') {
                sb.append("\\n");
            } else if (c == '\r') {
                sb.append("\\r");
            } else if (c == '\t') {
                sb.append("\\t");
            } else {
                sb.append(String.format("\\x%02x", (int)c & 0xFF));
            }
        }
        return sb.toString();
    }

    /**
     * Resolves a data type by name, handling common types and pointer types
     * @param dtm The data type manager
     * @param typeName The type name to resolve
     * @return The resolved DataType, or null if not found
     */
    private DataType resolveDataType(DataTypeManager dtm, String typeName) {
        // First try to find exact match in all categories
        DataType dataType = findDataTypeByNameInAllCategories(dtm, typeName);
        if (dataType != null) {
            Msg.info(this, "Found exact data type match: " + dataType.getPathName());
            return dataType;
        }

        // Check for Windows-style pointer types (PXXX)
        if (typeName.startsWith("P") && typeName.length() > 1) {
            String baseTypeName = typeName.substring(1);

            // Special case for PVOID
            if (baseTypeName.equals("VOID")) {
                return new PointerDataType(dtm.getDataType("/void"));
            }

            // Try to find the base type
            DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
            if (baseType != null) {
                return new PointerDataType(baseType);
            }

            Msg.warn(this, "Base type not found for " + typeName + ", defaulting to void*");
            return new PointerDataType(dtm.getDataType("/void"));
        }

        // Handle common built-in types
        switch (typeName.toLowerCase()) {
            case "int":
            case "long":
                return dtm.getDataType("/int");
            case "uint":
            case "unsigned int":
            case "unsigned long":
            case "dword":
                return dtm.getDataType("/uint");
            case "short":
                return dtm.getDataType("/short");
            case "ushort":
            case "unsigned short":
            case "word":
                return dtm.getDataType("/ushort");
            case "char":
            case "byte":
                return dtm.getDataType("/char");
            case "uchar":
            case "unsigned char":
                return dtm.getDataType("/uchar");
            case "longlong":
            case "__int64":
                return dtm.getDataType("/longlong");
            case "ulonglong":
            case "unsigned __int64":
                return dtm.getDataType("/ulonglong");
            case "bool":
            case "boolean":
                return dtm.getDataType("/bool");
            case "void":
                return dtm.getDataType("/void");
            default:
                // Try as a direct path
                DataType directType = dtm.getDataType("/" + typeName);
                if (directType != null) {
                    return directType;
                }

                // Fallback to int if we couldn't find it
                Msg.warn(this, "Unknown type: " + typeName + ", defaulting to int");
                return dtm.getDataType("/int");
        }
    }
    
    /**
     * Find a data type by name in all categories/folders of the data type manager
     * This searches through all categories rather than just the root
     */
    private DataType findDataTypeByNameInAllCategories(DataTypeManager dtm, String typeName) {
        // Try exact match first
        DataType result = searchByNameInAllCategories(dtm, typeName);
        if (result != null) {
            return result;
        }

        // Try lowercase
        return searchByNameInAllCategories(dtm, typeName.toLowerCase());
    }

    /**
     * Helper method to search for a data type by name in all categories
     */
    private DataType searchByNameInAllCategories(DataTypeManager dtm, String name) {
        // Get all data types from the manager
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            // Check if the name matches exactly (case-sensitive) 
            if (dt.getName().equals(name)) {
                return dt;
            }
            // For case-insensitive, we want an exact match except for case
            if (dt.getName().equalsIgnoreCase(name)) {
                return dt;
            }
        }
        return null;
    }

    // ----------------------------------------------------------------------------------
    // Utility: parse query params, parse post params, pagination, etc.
    // ----------------------------------------------------------------------------------

    /**
     * Parse query parameters from the URL, e.g. ?offset=10&limit=100
     */
    private Map<String, String> parseQueryParams(HttpExchange exchange) {
        Map<String, String> result = new HashMap<>();
        String query = exchange.getRequestURI().getQuery(); // e.g. offset=10&limit=100
        if (query != null) {
            String[] pairs = query.split("&");
            for (String p : pairs) {
                String[] kv = p.split("=");
                if (kv.length == 2) {
                    // URL decode parameter values
                    try {
                        String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                        String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                        result.put(key, value);
                    } catch (Exception e) {
                        Msg.error(this, "Error decoding URL parameter", e);
                    }
                }
            }
        }
        return result;
    }

    /**
     * Parse post body form params, e.g. oldName=foo&newName=bar
     */
    private Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
        byte[] body = exchange.getRequestBody().readAllBytes();
        String bodyStr = new String(body, StandardCharsets.UTF_8);
        Map<String, String> params = new HashMap<>();
        for (String pair : bodyStr.split("&")) {
            String[] kv = pair.split("=");
            if (kv.length == 2) {
                // URL decode parameter values
                try {
                    String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                    String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                    params.put(key, value);
                } catch (Exception e) {
                    Msg.error(this, "Error decoding URL parameter", e);
                }
            }
        }
        return params;
    }

    /**
     * Convert a list of strings into one big newline-delimited string, applying offset & limit.
     */
    private String paginateList(List<String> items, int offset, int limit) {
        int start = Math.max(0, offset);
        int end   = Math.min(items.size(), offset + limit);

        if (start >= items.size()) {
            return ""; // no items in range
        }
        List<String> sub = items.subList(start, end);
        return String.join("\n", sub);
    }

    /**
     * Parse an integer from a string, or return defaultValue if null/invalid.
     */
    private int parseIntOrDefault(String val, int defaultValue) {
        if (val == null) return defaultValue;
        try {
            return Integer.parseInt(val);
        }
        catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    /**
     * Escape non-ASCII chars to avoid potential decode issues.
     */
    private String escapeNonAscii(String input) {
        if (input == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (c >= 32 && c < 127) {
                sb.append(c);
            }
            else {
                sb.append("\\x");
                sb.append(Integer.toHexString(c & 0xFF));
            }
        }
        return sb.toString();
    }

    public Program getCurrentProgram() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        return pm != null ? pm.getCurrentProgram() : null;
    }

    private void sendResponse(HttpExchange exchange, String response) throws IOException {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    /**
     * Send a JSON response with a specific HTTP status code
     */
    private void sendJsonResponse(HttpExchange exchange, String jsonResponse, int statusCode) throws IOException {
        byte[] bytes = jsonResponse.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");  // Allow CORS
        exchange.sendResponseHeaders(statusCode, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    /**
     * Send an error response with proper HTTP status code
     */
    private void sendErrorResponse(HttpExchange exchange, String errorMessage, int statusCode) throws IOException {
        String errorJson = String.format("{\"error\":\"%s\",\"status\":%d}",
            errorMessage.replace("\"", "\\\""), statusCode);
        sendJsonResponse(exchange, errorJson, statusCode);
    }

    //======================================================================================
    // HELPER METHODS
    //======================================================================================

    /**
     * Parse an address string to an Address object
     */
    private Address parseAddress(Program program, String addressStr) {
        if (program == null || addressStr == null || addressStr.isEmpty()) {
            return null;
        }
        try {
            return program.getAddressFactory().getAddress(addressStr);
        } catch (Exception e) {
            return null;
        }
    }

    //======================================================================================
    // ADVANCED ANALYSIS METHODS
    //======================================================================================

    /**
     * Perform comprehensive analysis on a function
     */
    private String analyzeFunction(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        Address addr = parseAddress(program, addressStr);
        if (addr == null) return "Invalid address: " + addressStr;

        Function func = getFunctionForAddress(program, addr);
        if (func == null) return "No function at address: " + addressStr;

        StringBuilder result = new StringBuilder();
        result.append("Function Analysis: ").append(func.getName()).append("\n\n");

        // Basic Information
        result.append("=== Basic Information ===\n");
        result.append("Entry Point: ").append(func.getEntryPoint()).append("\n");
        result.append("Name: ").append(func.getName()).append("\n");
        result.append("Signature: ").append(func.getPrototypeString(false, false)).append("\n");
        result.append("Calling Convention: ").append(func.getCallingConventionName()).append("\n");
        result.append("Return Type: ").append(func.getReturnType()).append("\n\n");

        // Function Size and Complexity
        result.append("=== Size and Complexity ===\n");
        result.append("Body Size: ").append(func.getBody().getNumAddresses()).append(" bytes\n");

        // Count instructions
        int instructionCount = 0;
        try {
            InstructionIterator iter = program.getListing().getInstructions(func.getBody(), true);
            while (iter.hasNext()) {
                iter.next();
                instructionCount++;
            }
        } catch (Exception e) {
            instructionCount = -1;
        }
        result.append("Instruction Count: ").append(instructionCount).append("\n");

        // Parameter and Variable Information
        result.append("\n=== Parameters and Variables ===\n");
        result.append("Parameter Count: ").append(func.getParameterCount()).append("\n");
        result.append("Auto Parameter Count: ").append(func.getAutoParameterCount()).append("\n");
        Variable[] localVars = func.getLocalVariables();
        result.append("Local Variables: ").append(localVars != null ? localVars.length : 0).append("\n");

        // Stack Frame Information
        StackFrame frame = func.getStackFrame();
        if (frame != null) {
            result.append("Stack Frame Size: ").append(frame.getFrameSize()).append(" bytes\n");
            result.append("Local Size: ").append(frame.getLocalSize()).append(" bytes\n");
            result.append("Parameter Offset: ").append(frame.getParameterOffset()).append("\n");
            result.append("Parameter Size: ").append(frame.getParameterSize()).append(" bytes\n");
            result.append("Return Address Offset: ").append(frame.getReturnAddressOffset()).append("\n");
        }

        // Cross-references
        result.append("\n=== Cross-references ===\n");
        int callersCount = func.getCallingFunctions(TaskMonitor.DUMMY).size();
        Set<Function> callees = func.getCalledFunctions(TaskMonitor.DUMMY);
        result.append("Called By (Callers): ").append(callersCount).append(" functions\n");
        result.append("Calls (Callees): ").append(callees.size()).append(" functions\n");

        // Thunk information
        if (func.isThunk()) {
            result.append("\n=== Thunk Function ===\n");
            Function thunkedFunc = func.getThunkedFunction(true);
            if (thunkedFunc != null) {
                result.append("Thunked Function: ").append(thunkedFunc.getName()).append("\n");
            }
        }

        // External information
        if (func.isExternal()) {
            result.append("\n=== External Function ===\n");
            result.append("External Location: ").append(func.getExternalLocation()).append("\n");
        }

        return result.toString();
    }

    /**
     * Get comprehensive program statistics
     */
    private String getProgramStatistics() {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        StringBuilder result = new StringBuilder();
        result.append("Program Statistics\n\n");

        // Program Information
        result.append("=== Program Information ===\n");
        result.append("Name: ").append(program.getName()).append("\n");
        result.append("Path: ").append(program.getExecutablePath()).append("\n");
        result.append("Format: ").append(program.getExecutableFormat()).append("\n");
        result.append("Language: ").append(program.getLanguage().getLanguageID()).append("\n");
        result.append("Compiler: ").append(program.getCompilerSpec().getCompilerSpecID()).append("\n");
        result.append("Processor: ").append(program.getLanguage().getProcessor()).append("\n");
        result.append("Endian: ").append(program.getLanguage().isBigEndian() ? "Big" : "Little").append("\n");
        result.append("Address Size: ").append(program.getAddressFactory().getDefaultAddressSpace().getSize()).append(" bits\n");

        // Image Base
        result.append("Image Base: ").append(program.getImageBase()).append("\n");
        result.append("Min Address: ").append(program.getMinAddress()).append("\n");
        result.append("Max Address: ").append(program.getMaxAddress()).append("\n\n");

        // Function Statistics
        FunctionManager funcMgr = program.getFunctionManager();
        result.append("=== Functions ===\n");
        result.append("Total Functions: ").append(funcMgr.getFunctionCount()).append("\n");

        int externalFuncs = 0;
        int thunkFuncs = 0;
        for (Function func : funcMgr.getFunctions(true)) {
            if (func.isExternal()) externalFuncs++;
            if (func.isThunk()) thunkFuncs++;
        }
        result.append("External Functions: ").append(externalFuncs).append("\n");
        result.append("Thunk Functions: ").append(thunkFuncs).append("\n\n");

        // Memory Statistics
        Memory memory = program.getMemory();
        result.append("=== Memory ===\n");
        result.append("Total Size: ").append(memory.getSize()).append(" bytes\n");

        MemoryBlock[] blocks = memory.getBlocks();
        result.append("Memory Blocks: ").append(blocks.length).append("\n");

        long initializedSize = 0;
        long uninitializedSize = 0;
        int executableBlocks = 0;
        int writableBlocks = 0;
        for (MemoryBlock block : blocks) {
            if (block.isInitialized()) {
                initializedSize += block.getSize();
            } else {
                uninitializedSize += block.getSize();
            }
            if (block.isExecute()) executableBlocks++;
            if (block.isWrite()) writableBlocks++;
        }
        result.append("Initialized: ").append(initializedSize).append(" bytes\n");
        result.append("Uninitialized: ").append(uninitializedSize).append(" bytes\n");
        result.append("Executable Blocks: ").append(executableBlocks).append("\n");
        result.append("Writable Blocks: ").append(writableBlocks).append("\n\n");

        // Symbol Statistics
        SymbolTable symTable = program.getSymbolTable();
        result.append("=== Symbols ===\n");
        result.append("Total Symbols: ").append(symTable.getNumSymbols()).append("\n");

        // Count defined data
        Listing listing = program.getListing();
        int definedDataCount = 0;
        try {
            Iterator<Data> dataIter = listing.getDefinedData(true);
            while (dataIter.hasNext()) {
                dataIter.next();
                definedDataCount++;
            }
        } catch (Exception e) {
            definedDataCount = -1;
        }
        result.append("Defined Data Items: ").append(definedDataCount).append("\n\n");

        // Instruction Statistics
        result.append("=== Instructions ===\n");
        int totalInstructions = 0;
        try {
            InstructionIterator iter = listing.getInstructions(true);
            while (iter.hasNext()) {
                iter.next();
                totalInstructions++;
            }
        } catch (Exception e) {
            totalInstructions = -1;
        }
        result.append("Total Instructions: ").append(totalInstructions).append("\n\n");

        // Data Type Statistics
        DataTypeManager dtMgr = program.getDataTypeManager();
        result.append("=== Data Types ===\n");
        result.append("Total Data Types: ").append(dtMgr.getDataTypeCount(true)).append("\n");
        result.append("Categories: ").append(dtMgr.getCategoryCount()).append("\n");

        return result.toString();
    }

    /**
     * Read memory bytes at specified address
     */
    private String readMemory(String addressStr, int size, String format) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        Address addr = parseAddress(program, addressStr);
        if (addr == null) return "Invalid address: " + addressStr;

        if (size <= 0 || size > 10000) {
            return "Invalid size: " + size + " (must be 1-10000)";
        }

        Memory memory = program.getMemory();
        byte[] bytes = new byte[size];

        try {
            int bytesRead = memory.getBytes(addr, bytes);
            if (bytesRead != size) {
                return String.format("Warning: Only read %d of %d bytes", bytesRead, size);
            }

            StringBuilder result = new StringBuilder();
            result.append("Memory at ").append(addr).append(" (").append(size).append(" bytes):\n\n");

            if ("raw".equals(format)) {
                // Raw format: just the bytes
                for (int i = 0; i < bytesRead; i++) {
                    result.append(String.format("%02X ", bytes[i] & 0xFF));
                    if ((i + 1) % 16 == 0) result.append("\n");
                }
            } else {
                // Hex dump format with address and ASCII
                for (int i = 0; i < bytesRead; i += 16) {
                    // Address
                    result.append(String.format("%s: ", addr.add(i)));

                    // Hex bytes
                    for (int j = 0; j < 16 && (i + j) < bytesRead; j++) {
                        result.append(String.format("%02X ", bytes[i + j] & 0xFF));
                    }

                    // Padding
                    for (int j = bytesRead - i; j < 16; j++) {
                        result.append("   ");
                    }

                    // ASCII representation
                    result.append(" |");
                    for (int j = 0; j < 16 && (i + j) < bytesRead; j++) {
                        byte b = bytes[i + j];
                        char c = (b >= 32 && b < 127) ? (char) b : '.';
                        result.append(c);
                    }
                    result.append("|\n");
                }
            }

            return result.toString();
        } catch (MemoryAccessException e) {
            return "Memory access error at " + addr + ": " + e.getMessage();
        }
    }

    /**
     * Search for byte pattern in memory
     */
    private String searchMemory(String pattern, String startAddr, String endAddr, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (pattern == null || pattern.isEmpty()) return "Pattern is required";

        // Parse pattern from hex string
        pattern = pattern.replace(" ", "").replace("0x", "");
        if (pattern.length() % 2 != 0) {
            return "Pattern must be an even number of hex digits";
        }

        byte[] searchBytes = new byte[pattern.length() / 2];
        try {
            for (int i = 0; i < searchBytes.length; i++) {
                searchBytes[i] = (byte) Integer.parseInt(pattern.substring(i * 2, i * 2 + 2), 16);
            }
        } catch (NumberFormatException e) {
            return "Invalid hex pattern: " + pattern;
        }

        Address start = startAddr != null ? parseAddress(program, startAddr) : program.getMinAddress();
        Address end = endAddr != null ? parseAddress(program, endAddr) : program.getMaxAddress();

        if (start == null || end == null) {
            return "Invalid address range";
        }

        Memory memory = program.getMemory();
        List<String> results = new ArrayList<>();
        int count = 0;

        try {
            Address found = memory.findBytes(start, end, searchBytes, null, true, TaskMonitor.DUMMY);
            while (found != null && count < limit) {
                results.add(found.toString());
                count++;
                // Search for next occurrence
                Address nextStart = found.add(1);
                if (nextStart.compareTo(end) > 0) break;
                found = memory.findBytes(nextStart, end, searchBytes, null, true, TaskMonitor.DUMMY);
            }
        } catch (Exception e) {
            return "Search error: " + e.getMessage();
        }

        if (results.isEmpty()) {
            return "Pattern not found";
        }

        return String.format("Found %d occurrences (limit: %d):\n%s",
            results.size(), limit, String.join("\n", results));
    }

    /**
     * Get detailed memory map with permissions and types
     */
    private String getDetailedMemoryMap() {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Memory memory = program.getMemory();
        MemoryBlock[] blocks = memory.getBlocks();

        StringBuilder result = new StringBuilder();
        result.append("Memory Map (").append(blocks.length).append(" blocks):\n\n");
        result.append(String.format("%-20s %-20s %-12s %-6s %s\n",
            "Start", "End", "Size", "Perms", "Name"));
        result.append("=".repeat(80)).append("\n");

        for (MemoryBlock block : blocks) {
            String perms = "";
            perms += block.isRead() ? "R" : "-";
            perms += block.isWrite() ? "W" : "-";
            perms += block.isExecute() ? "X" : "-";
            perms += block.isInitialized() ? "I" : "U";

            result.append(String.format("%-20s %-20s %,12d  %-6s %s\n",
                block.getStart(),
                block.getEnd(),
                block.getSize(),
                perms,
                block.getName()
            ));
        }

        return result.toString();
    }

    /**
     * Get basic blocks for a function
     */
    private String getBasicBlocks(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        Address addr = parseAddress(program, addressStr);
        if (addr == null) return "Invalid address: " + addressStr;

        Function func = getFunctionForAddress(program, addr);
        if (func == null) return "No function at address: " + addressStr;

        try {
            BasicBlockModel bbModel = new BasicBlockModel(program);
            CodeBlockIterator blockIter = bbModel.getCodeBlocksContaining(func.getBody(), TaskMonitor.DUMMY);

            if (blockIter == null || !blockIter.hasNext()) {
                return "No basic blocks found";
            }

            StringBuilder result = new StringBuilder();
            result.append("Basic Blocks for ").append(func.getName()).append(":\n\n");
            result.append(String.format("%-20s %-20s %10s %10s\n",
                "Start", "End", "Size", "Inst Count"));
            result.append("=".repeat(70)).append("\n");

            int blockCount = 0;
            while (blockIter.hasNext()) {
                CodeBlock block = blockIter.next();
                blockCount++;

                Address start = block.getFirstStartAddress();
                Address end = block.getMaxAddress();
                long size = block.getNumAddresses();

                // Count instructions in block
                int instCount = 0;
                try {
                    InstructionIterator iter = program.getListing().getInstructions(block, true);
                    while (iter.hasNext()) {
                        iter.next();
                        instCount++;
                    }
                } catch (Exception e) {
                    instCount = -1;
                }

                result.append(String.format("%-20s %-20s %,10d %,10d\n",
                    start, end, size, instCount));
            }

            result.append("\nTotal blocks: ").append(blockCount);
            return result.toString();
        } catch (Exception e) {
            return "Error analyzing basic blocks: " + e.getMessage();
        }
    }

    /**
     * Get control flow graph information
     */
    private String getControlFlowGraph(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        Address addr = parseAddress(program, addressStr);
        if (addr == null) return "Invalid address: " + addressStr;

        Function func = getFunctionForAddress(program, addr);
        if (func == null) return "No function at address: " + addressStr;

        try {
            BasicBlockModel bbModel = new BasicBlockModel(program);
            CodeBlockIterator blockIter = bbModel.getCodeBlocksContaining(func.getBody(), TaskMonitor.DUMMY);

            if (blockIter == null || !blockIter.hasNext()) {
                return "No basic blocks found";
            }

            StringBuilder result = new StringBuilder();
            result.append("Control Flow Graph for ").append(func.getName()).append(":\n\n");

            // For each block, show its connections
            while (blockIter.hasNext()) {
                CodeBlock block = blockIter.next();
                Address start = block.getFirstStartAddress();
                result.append("Block ").append(start).append(":\n");

                // Get destinations (where this block flows to)
                CodeBlockReferenceIterator destIter = block.getDestinations(TaskMonitor.DUMMY);
                List<String> destinations = new ArrayList<>();
                while (destIter.hasNext()) {
                    CodeBlockReference ref = destIter.next();
                    FlowType flowType = ref.getFlowType();
                    Address destAddr = ref.getDestinationAddress();
                    destinations.add(String.format("%s (%s)", destAddr, flowType.getName()));
                }

                if (!destinations.isEmpty()) {
                    result.append("  Flows to: ").append(String.join(", ", destinations)).append("\n");
                }

                // Get sources (where this block is reached from)
                CodeBlockReferenceIterator sourceIter = block.getSources(TaskMonitor.DUMMY);
                List<String> sources = new ArrayList<>();
                while (sourceIter.hasNext()) {
                    CodeBlockReference ref = sourceIter.next();
                    Address sourceAddr = ref.getSourceAddress();
                    sources.add(sourceAddr.toString());
                }

                if (!sources.isEmpty()) {
                    result.append("  From: ").append(String.join(", ", sources)).append("\n");
                }

                result.append("\n");
            }

            return result.toString();
        } catch (Exception e) {
            return "Error analyzing control flow: " + e.getMessage();
        }
    }

    /**
     * Build call graph showing function relationships
     */
    private String getCallGraph(String addressStr, int depth, String direction) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        Address addr = parseAddress(program, addressStr);
        if (addr == null) return "Invalid address: " + addressStr;

        Function func = getFunctionForAddress(program, addr);
        if (func == null) return "No function at address: " + addressStr;

        if (depth <= 0 || depth > 10) {
            depth = 3; // Default depth
        }

        if (direction == null || direction.isEmpty()) {
            direction = "both";
        }

        StringBuilder result = new StringBuilder();
        result.append("Call Graph for ").append(func.getName()).append(" (depth: ").append(depth).append("):\n\n");

        if ("callers".equals(direction) || "both".equals(direction)) {
            result.append("=== Callers (functions that call this) ===\n");
            buildCallersGraph(func, depth, 0, new HashSet<>(), result);
            result.append("\n");
        }

        if ("callees".equals(direction) || "both".equals(direction)) {
            result.append("=== Callees (functions called by this) ===\n");
            buildCalleesGraph(func, depth, 0, new HashSet<>(), result);
        }

        return result.toString();
    }

    private void buildCallersGraph(Function func, int maxDepth, int currentDepth, Set<Long> visited, StringBuilder result) {
        if (currentDepth >= maxDepth || func == null) return;

        long funcId = func.getID();
        if (visited.contains(funcId)) {
            return; // Avoid cycles
        }
        visited.add(funcId);

        String indent = "  ".repeat(currentDepth);
        result.append(indent).append(func.getName()).append(" @ ").append(func.getEntryPoint()).append("\n");

        Set<Function> callers = func.getCallingFunctions(TaskMonitor.DUMMY);
        for (Function caller : callers) {
            buildCallersGraph(caller, maxDepth, currentDepth + 1, visited, result);
        }
    }

    private void buildCalleesGraph(Function func, int maxDepth, int currentDepth, Set<Long> visited, StringBuilder result) {
        if (currentDepth >= maxDepth || func == null) return;

        long funcId = func.getID();
        if (visited.contains(funcId)) {
            return; // Avoid cycles
        }
        visited.add(funcId);

        String indent = "  ".repeat(currentDepth);
        result.append(indent).append(func.getName()).append(" @ ").append(func.getEntryPoint()).append("\n");

        Set<Function> callees = func.getCalledFunctions(TaskMonitor.DUMMY);
        for (Function callee : callees) {
            buildCalleesGraph(callee, maxDepth, currentDepth + 1, visited, result);
        }
    }

    //======================================================================================
    // DATA TYPE OPERATIONS
    //======================================================================================

    /**
     * List available data types
     */
    private String listDataTypes(String category, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        DataTypeManager dtMgr = program.getDataTypeManager();
        List<String> types = new ArrayList<>();

        if (category != null && !category.isEmpty()) {
            // List types in specific category
            CategoryPath catPath = new CategoryPath("/" + category);
            try {
                Category cat = dtMgr.getCategory(catPath);
                if (cat != null) {
                    for (DataType dt : cat.getDataTypes()) {
                        types.add(dt.getPathName() + " (size: " + dt.getLength() + ")");
                    }
                }
            } catch (Exception e) {
                return "Category not found: " + category;
            }
        } else {
            // List all data types
            Iterator<DataType> iter = dtMgr.getAllDataTypes();
            while (iter.hasNext()) {
                DataType dt = iter.next();
                types.add(dt.getPathName() + " (size: " + dt.getLength() + ")");
            }
        }

        Collections.sort(types);
        return paginateList(types, offset, limit);
    }

    /**
     * Get detailed information about a data type
     */
    private String getDataTypeInfo(String typeName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (typeName == null || typeName.isEmpty()) return "Type name is required";

        DataTypeManager dtMgr = program.getDataTypeManager();
        DataType dt = dtMgr.getDataType(typeName);

        if (dt == null) {
            // Try to find by name only (without path)
            Iterator<DataType> iter = dtMgr.getAllDataTypes();
            while (iter.hasNext()) {
                DataType candidate = iter.next();
                if (candidate.getName().equals(typeName)) {
                    dt = candidate;
                    break;
                }
            }
        }

        if (dt == null) {
            return "Data type not found: " + typeName;
        }

        StringBuilder result = new StringBuilder();
        result.append("Data Type: ").append(dt.getName()).append("\n\n");
        result.append("Full Path: ").append(dt.getPathName()).append("\n");
        result.append("Category: ").append(dt.getCategoryPath()).append("\n");
        result.append("Size: ").append(dt.getLength()).append(" bytes\n");
        result.append("Description: ").append(dt.getDescription()).append("\n");
        result.append("Display Name: ").append(dt.getDisplayName()).append("\n");

        return result.toString();
    }

    /**
     * Create data at specified address with given type
     */
    private String createDataAtAddress(String addressStr, String typeName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        if (typeName == null || typeName.isEmpty()) return "Type name is required";

        Address addr = parseAddress(program, addressStr);
        if (addr == null) return "Invalid address: " + addressStr;

        DataType dataType = resolveDataType(program.getDataTypeManager(), typeName);
        if (dataType == null) {
            return "Data type not found: " + typeName;
        }

        final String[] resultHolder = {null};
        try {
            SwingUtilities.invokeAndWait(() -> {
                int txId = program.startTransaction("Create Data");
                try {
                    CreateDataCmd cmd = new CreateDataCmd(addr, dataType);
                    if (cmd.applyTo(program)) {
                        program.endTransaction(txId, true);
                        resultHolder[0] = "Data created at " + addr + " with type " + dataType.getName();
                    } else {
                        program.endTransaction(txId, false);
                        resultHolder[0] = "Failed to create data: " + cmd.getStatusMsg();
                    }
                } catch (Exception e) {
                    program.endTransaction(txId, false);
                    resultHolder[0] = "Error creating data: " + e.getMessage();
                }
            });
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }

        return resultHolder[0] != null ? resultHolder[0] : "Unknown error";
    }

    /**
     * Delete data at specified address
     */
    private String deleteDataAtAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        Address addr = parseAddress(program, addressStr);
        if (addr == null) return "Invalid address: " + addressStr;

        final String[] resultHolder = {null};
        try {
            SwingUtilities.invokeAndWait(() -> {
                int txId = program.startTransaction("Delete Data");
                try {
                    Listing listing = program.getListing();
                    Data data = listing.getDataAt(addr);

                    if (data == null) {
                        program.endTransaction(txId, false);
                        resultHolder[0] = "No data at address: " + addr;
                        return;
                    }

                    listing.clearCodeUnits(addr, addr.add(data.getLength() - 1), false);
                    program.endTransaction(txId, true);
                    resultHolder[0] = "Data deleted at " + addr;
                } catch (Exception e) {
                    program.endTransaction(txId, false);
                    resultHolder[0] = "Error deleting data: " + e.getMessage();
                }
            });
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }

        return resultHolder[0] != null ? resultHolder[0] : "Unknown error";
    }

    /**
     * Apply data type at specified address
     */
    private String applyDataType(String addressStr, String typeName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        if (typeName == null || typeName.isEmpty()) return "Type name is required";

        Address addr = parseAddress(program, addressStr);
        if (addr == null) return "Invalid address: " + addressStr;

        DataType dataType = resolveDataType(program.getDataTypeManager(), typeName);
        if (dataType == null) {
            return "Data type not found: " + typeName;
        }

        final String[] resultHolder = {null};
        try {
            SwingUtilities.invokeAndWait(() -> {
                int txId = program.startTransaction("Apply Data Type");
                try {
                    Listing listing = program.getListing();
                    Data existingData = listing.getDataAt(addr);

                    if (existingData != null) {
                        // Clear existing data first
                        listing.clearCodeUnits(addr, addr.add(existingData.getLength() - 1), false);
                    }

                    // Create new data with the type
                    CreateDataCmd cmd = new CreateDataCmd(addr, dataType);
                    if (cmd.applyTo(program)) {
                        program.endTransaction(txId, true);
                        resultHolder[0] = "Applied type " + dataType.getName() + " at " + addr;
                    } else {
                        program.endTransaction(txId, false);
                        resultHolder[0] = "Failed to apply type: " + cmd.getStatusMsg();
                    }
                } catch (Exception e) {
                    program.endTransaction(txId, false);
                    resultHolder[0] = "Error applying type: " + e.getMessage();
                }
            });
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }

        return resultHolder[0] != null ? resultHolder[0] : "Unknown error";
    }

    //======================================================================================
    // ENHANCED DECOMPILATION METHODS
    //======================================================================================

    /**
     * Advanced decompilation with configurable options
     */
    private String decompileAdvanced(String addressStr, String simplificationStyle, boolean includeSyntaxTree, int timeout) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        Address addr = parseAddress(program, addressStr);
        if (addr == null) return "Invalid address: " + addressStr;

        Function func = getFunctionForAddress(program, addr);
        if (func == null) return "No function at address: " + addressStr;

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);

        // Set simplification style
        if (simplificationStyle != null && !simplificationStyle.isEmpty()) {
            decomp.setSimplificationStyle(simplificationStyle);
        } else {
            decomp.setSimplificationStyle("decompile"); // Default
        }

        // Decompile with specified timeout
        DecompileResults results = decomp.decompileFunction(func, timeout, TaskMonitor.DUMMY);

        if (results == null || !results.decompileCompleted()) {
            decomp.dispose();
            return "Decompilation failed: " + (results != null ? results.getErrorMessage() : "Unknown error");
        }

        StringBuilder output = new StringBuilder();
        output.append("=== Advanced Decompilation ===\n");
        output.append("Function: ").append(func.getName()).append("\n");
        output.append("Address: ").append(func.getEntryPoint()).append("\n");
        output.append("Simplification Style: ").append(simplificationStyle != null ? simplificationStyle : "decompile").append("\n");
        output.append("\n=== Decompiled Code ===\n");
        output.append(results.getDecompiledFunction().getC()).append("\n");

        if (includeSyntaxTree) {
            output.append("\n=== Syntax Tree (AST) ===\n");
            ClangTokenGroup tokens = results.getCCodeMarkup();
            if (tokens != null) {
                output.append(formatSyntaxTree(tokens, 0));
            } else {
                output.append("No syntax tree available\n");
            }
        }

        decomp.dispose();
        return output.toString();
    }

    /**
     * Decompile with custom options (for future extensibility)
     */
    private String decompileWithOptions(String addressStr, String optionsJson) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        Address addr = parseAddress(program, addressStr);
        if (addr == null) return "Invalid address: " + addressStr;

        Function func = getFunctionForAddress(program, addr);
        if (func == null) return "No function at address: " + addressStr;

        DecompInterface decomp = new DecompInterface();

        // Get default options and allow customization
        DecompileOptions options = new DecompileOptions();

        // Parse simple options (in future could parse JSON)
        // For now, use sensible defaults
        options.setEliminateUnreachable(true);
        options.setSimplifyDoublePrecision(true);

        decomp.setOptions(options);
        decomp.openProgram(program);

        DecompileResults results = decomp.decompileFunction(func, 60, TaskMonitor.DUMMY);

        if (results == null || !results.decompileCompleted()) {
            decomp.dispose();
            return "Decompilation failed: " + (results != null ? results.getErrorMessage() : "Unknown error");
        }

        StringBuilder output = new StringBuilder();
        output.append("=== Decompilation with Custom Options ===\n");
        output.append("Function: ").append(func.getName()).append("\n\n");
        output.append(results.getDecompiledFunction().getC());

        decomp.dispose();
        return output.toString();
    }

    /**
     * Get syntax tree (AST) representation
     */
    private String getSyntaxTree(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        Address addr = parseAddress(program, addressStr);
        if (addr == null) return "Invalid address: " + addressStr;

        Function func = getFunctionForAddress(program, addr);
        if (func == null) return "No function at address: " + addressStr;

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        decomp.setSimplificationStyle("decompile");

        DecompileResults results = decomp.decompileFunction(func, 60, TaskMonitor.DUMMY);

        if (results == null || !results.decompileCompleted()) {
            decomp.dispose();
            return "Decompilation failed: " + (results != null ? results.getErrorMessage() : "Unknown error");
        }

        StringBuilder output = new StringBuilder();
        output.append("=== Syntax Tree for ").append(func.getName()).append(" ===\n\n");

        ClangTokenGroup tokens = results.getCCodeMarkup();
        if (tokens != null) {
            output.append(formatSyntaxTree(tokens, 0));
        } else {
            output.append("No syntax tree available");
        }

        decomp.dispose();
        return output.toString();
    }

    /**
     * Get raw decompiler output with minimal processing
     */
    private String decompileRaw(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        Address addr = parseAddress(program, addressStr);
        if (addr == null) return "Invalid address: " + addressStr;

        Function func = getFunctionForAddress(program, addr);
        if (func == null) return "No function at address: " + addressStr;

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);

        // Use "firstpass" or "normalize" for minimal simplification
        decomp.setSimplificationStyle("firstpass");

        DecompileResults results = decomp.decompileFunction(func, 60, TaskMonitor.DUMMY);

        if (results == null || !results.decompileCompleted()) {
            decomp.dispose();
            return "Decompilation failed: " + (results != null ? results.getErrorMessage() : "Unknown error");
        }

        StringBuilder output = new StringBuilder();
        output.append("=== Raw Decompilation (Minimal Processing) ===\n");
        output.append("Function: ").append(func.getName()).append("\n\n");
        output.append(results.getDecompiledFunction().getC());

        decomp.dispose();
        return output.toString();
    }

    /**
     * Format syntax tree recursively for display
     */
    private String formatSyntaxTree(ClangNode node, int depth) {
        StringBuilder sb = new StringBuilder();
        String indent = "  ".repeat(depth);

        // Add current node info
        sb.append(indent);
        sb.append(node.getClass().getSimpleName());

        if (node instanceof ClangToken) {
            ClangToken token = (ClangToken) node;
            sb.append(": \"").append(escapeString(token.getText())).append("\"");
        }
        sb.append("\n");

        // Recursively add children
        if (node instanceof ClangTokenGroup) {
            ClangTokenGroup group = (ClangTokenGroup) node;
            for (int i = 0; i < group.numChildren(); i++) {
                sb.append(formatSyntaxTree(group.Child(i), depth + 1));
            }
        }

        return sb.toString();
    }

    @Override
    public void dispose() {
        if (server != null) {
            Msg.info(this, "Stopping GhidraMCP HTTP server...");
            server.stop(1); // Stop with a small delay (e.g., 1 second) for connections to finish
            server = null; // Nullify the reference
            Msg.info(this, "GhidraMCP HTTP server stopped.");
        }
        super.dispose();
    }
}
