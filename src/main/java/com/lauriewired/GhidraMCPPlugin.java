package com.lauriewired;

import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.listing.*;
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

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

// BSim imports
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.BSimServerInfo;
import ghidra.features.bsim.query.BSimClientFactory;
import ghidra.features.bsim.query.GenSignatures;
import ghidra.features.bsim.query.description.*;
import ghidra.features.bsim.query.protocol.*;
import generic.lsh.vector.LSHVectorFactory;

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

    // BSim database connection state
    private FunctionDatabase bsimDatabase = null;
    private String currentBSimDatabasePath = null;

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

        // BSim endpoints
        server.createContext("/bsim/select_database", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String dbPath = params.get("database_path");
            sendResponse(exchange, selectBSimDatabase(dbPath));
        });

        server.createContext("/bsim/query_function", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            int maxMatches = parseIntOrDefault(params.get("max_matches"), 10);
            double similarityThreshold = parseDoubleOrDefault(params.get("similarity_threshold"), "0.7");
            double confidenceThreshold = parseDoubleOrDefault(params.get("confidence_threshold"), "0.0");
            double maxSimilarity = parseDoubleOrDefault(params.get("max_similarity"), String.valueOf(Double.POSITIVE_INFINITY));
            double maxConfidence = parseDoubleOrDefault(params.get("max_confidence"), String.valueOf(Double.POSITIVE_INFINITY));
            int offset = parseIntOrDefault(params.get("offset"), 0);
            int limit = parseIntOrDefault(params.get("limit"), 100);
            sendResponse(exchange, queryBSimFunction(functionAddress, maxMatches, similarityThreshold, confidenceThreshold, maxSimilarity, maxConfidence, offset, limit));
        });

        server.createContext("/bsim/query_all_functions", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            int maxMatchesPerFunction = parseIntOrDefault(params.get("max_matches_per_function"), 5);
            double similarityThreshold = parseDoubleOrDefault(params.get("similarity_threshold"), "0.7");
            double confidenceThreshold = parseDoubleOrDefault(params.get("confidence_threshold"), "0.0");
            double maxSimilarity = parseDoubleOrDefault(params.get("max_similarity"), String.valueOf(Double.POSITIVE_INFINITY));
            double maxConfidence = parseDoubleOrDefault(params.get("max_confidence"), String.valueOf(Double.POSITIVE_INFINITY));
            int offset = parseIntOrDefault(params.get("offset"), 0);
            int limit = parseIntOrDefault(params.get("limit"), 100);
            sendResponse(exchange, queryAllBSimFunctions(maxMatchesPerFunction, similarityThreshold, confidenceThreshold, maxSimilarity, maxConfidence, offset, limit));
        });

        server.createContext("/bsim/disconnect", exchange -> {
            sendResponse(exchange, disconnectBSimDatabase());
        });

        server.createContext("/bsim/status", exchange -> {
            sendResponse(exchange, getBSimStatus());
        });

        server.createContext("/bsim/get_match_disassembly", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String executablePath = params.get("executable_path");
            String functionName = params.get("function_name");
            String functionAddress = params.get("function_address");
            sendResponse(exchange, getBSimMatchDisassembly(executablePath, functionName, functionAddress));
        });

        server.createContext("/bsim/get_match_decompile", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String executablePath = params.get("executable_path");
            String functionName = params.get("function_name");
            String functionAddress = params.get("function_address");
            sendResponse(exchange, getBSimMatchDecompile(executablePath, functionName, functionAddress));
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

            String decompCode = decompileFunctionInProgram(func, program);
            return (decompCode != null && !decompCode.isEmpty()) 
                ? decompCode 
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

            return disassembleFunctionInProgram(func, program);
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
     * Parse a double from a string, or return defaultValue if null/invalid.
     */
    private double parseDoubleOrDefault(String val, String defaultValue) {
        if (val == null) val = defaultValue;
        try {
            return Double.parseDouble(val);
        }
        catch (NumberFormatException e) {
            try {
                return Double.parseDouble(defaultValue);
            }
            catch (NumberFormatException e2) {
                return 0.0;
            }
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

    // ----------------------------------------------------------------------------------
    // BSim functionality
    // ----------------------------------------------------------------------------------

    /**
     * Select and connect to a BSim database
     */
    private String selectBSimDatabase(String databasePath) {
        if (databasePath == null || databasePath.isEmpty()) {
            return "Error: Database path is required";
        }

        try {
            // Disconnect from any existing database first
            if (bsimDatabase != null) {
                disconnectBSimDatabase();
            }

            // Create BSimServerInfo from the path/URL
            // Use URL constructor for URLs (postgresql://, file://, etc.)
            // Use String constructor only for file paths
            BSimServerInfo serverInfo;
            if (databasePath.contains("://")) {
                // It's a URL - use URL constructor
                serverInfo = new BSimServerInfo(new java.net.URL(databasePath));
            } else {
                // It's a file path - use String constructor
                serverInfo = new BSimServerInfo(databasePath);
            }
            
            // Initialize the database connection
            bsimDatabase = BSimClientFactory.buildClient(serverInfo, false);
            
            if (bsimDatabase == null) {
                return "Error: Failed to create BSim database client";
            }

            // Try to initialize the connection
            if (!bsimDatabase.initialize()) {
                bsimDatabase = null;
                return "Error: Failed to initialize BSim database connection";
            }

            currentBSimDatabasePath = databasePath;
            return "Successfully connected to BSim database: " + databasePath;

        } catch (Exception e) {
            bsimDatabase = null;
            currentBSimDatabasePath = null;
            return "Error connecting to BSim database: " + e.getMessage();
        }
    }

    /**
     * Disconnect from the current BSim database
     */
    private String disconnectBSimDatabase() {
        if (bsimDatabase != null) {
            try {
                bsimDatabase.close();
                bsimDatabase = null;
                String path = currentBSimDatabasePath;
                currentBSimDatabasePath = null;
                return "Disconnected from BSim database: " + path;
            } catch (Exception e) {
                return "Error disconnecting from BSim database: " + e.getMessage();
            }
        }
        return "No BSim database connection to disconnect";
    }

    /**
     * Get the current BSim database connection status
     */
    private String getBSimStatus() {
        if (bsimDatabase != null && currentBSimDatabasePath != null) {
            try {
                StringBuilder status = new StringBuilder();
                status.append("Connected to: ").append(currentBSimDatabasePath).append("\n");
                status.append("Database info:\n");
                
                LSHVectorFactory vectorFactory = bsimDatabase.getLSHVectorFactory();
                if (vectorFactory != null) {
                    status.append("  Vector Factory: ").append(vectorFactory.getClass().getSimpleName()).append("\n");
                } else {
                    status.append("  Vector Factory: null (ERROR)\n");
                }
                
                // Try to get database info
                QueryInfo infoQuery = new QueryInfo();
                ResponseInfo infoResponse = infoQuery.execute(bsimDatabase);
                if (infoResponse != null && infoResponse.info != null) {
                    status.append("  Database name: ").append(infoResponse.info.databasename).append("\n");
                }
                
                return status.toString();
            } catch (Exception e) {
                return "Connected to: " + currentBSimDatabasePath + " (Error getting details: " + e.getMessage() + ")";
            }
        }
        return "Not connected to any BSim database";
    }

    /**
     * Query a single function against the BSim database
     * 
     * @param functionAddress Address of the function to query
     * @param maxMatches Maximum number of matches to return
     * @param similarityThreshold Minimum similarity score (inclusive, 0.0-1.0)
     * @param confidenceThreshold Minimum confidence score (inclusive, 0.0-1.0)
     * @param maxSimilarity Maximum similarity score (exclusive, 0.0-1.0, default: unbounded/infinity)
     * @param maxConfidence Maximum confidence score (exclusive, 0.0-1.0, default: unbounded/infinity)
     * @param offset Pagination offset
     * @param limit Maximum number of results to return
     */
    private String queryBSimFunction(String functionAddress, int maxMatches, 
                                     double similarityThreshold, double confidenceThreshold,
                                     double maxSimilarity, double maxConfidence,
                                     int offset, int limit) {
        if (bsimDatabase == null) {
            return "Error: Not connected to a BSim database. Use bsim_select_database first.";
        }

        Program program = getCurrentProgram();
        if (program == null) {
            return "Error: No program loaded";
        }

        try {
            Address addr = program.getAddressFactory().getAddress(functionAddress);
            Function func = program.getFunctionManager().getFunctionAt(addr);
            if (func == null) {
                func = program.getFunctionManager().getFunctionContaining(addr);
            }
            if (func == null) {
                return "Error: No function found at address " + functionAddress;
            }

            // Generate signature for this function
            GenSignatures gensig = new GenSignatures(false);
            gensig.setVectorFactory(bsimDatabase.getLSHVectorFactory());
            
            // Set up the executable record for the current program
            String exeName = program.getName();
            String exePath = program.getExecutablePath();
            gensig.openProgram(program, exeName, exePath, null, null, null);
            
            DescriptionManager descManager = gensig.getDescriptionManager();
            gensig.scanFunction(func);

            if (descManager.numFunctions() == 0) {
                return "Error: Failed to generate signature for function";
            }

            // Create and execute query
            // Note: We don't set query.max here because we need to filter by max similarity/confidence first,
            // then limit to maxMatches. Setting query.max too early might exclude valid matches.
            QueryNearest query = new QueryNearest();
            query.manage = descManager;
            query.max = Integer.MAX_VALUE; // Get all potential matches
            query.thresh = similarityThreshold;
            query.signifthresh = confidenceThreshold;

            // Execute query
            ResponseNearest response = query.execute(bsimDatabase);
            
            if (response == null) {
                return "Error: Query returned no response";
            }

            // Debug info
            Msg.info(this, String.format("Query completed for %s: threshold=%.2f, results=%d", 
                func.getName(), similarityThreshold,
                response.result != null ? response.result.size() : 0));

            // Filter results by max similarity and max confidence, and limit to maxMatches
            filterBSimResults(response, maxSimilarity, maxConfidence, maxMatches);

            // Format results with pagination
            return formatBSimResults(response, func.getName(), offset, limit);

        } catch (Exception e) {
            return "Error querying BSim database: " + e.getMessage();
        }
    }

    /**
     * Query all functions in the current program against the BSim database
     * 
     * @param maxMatchesPerFunction Maximum number of matches per function
     * @param similarityThreshold Minimum similarity score (inclusive, 0.0-1.0)
     * @param confidenceThreshold Minimum confidence score (inclusive, 0.0-1.0)
     * @param maxSimilarity Maximum similarity score (exclusive, 0.0-1.0, default: unbounded/infinity)
     * @param maxConfidence Maximum confidence score (exclusive, 0.0-1.0, default: unbounded/infinity)
     * @param offset Pagination offset
     * @param limit Maximum number of results to return
     */
    private String queryAllBSimFunctions(int maxMatchesPerFunction, 
                                        double similarityThreshold, double confidenceThreshold,
                                        double maxSimilarity, double maxConfidence,
                                        int offset, int limit) {
        if (bsimDatabase == null) {
            return "Error: Not connected to a BSim database. Use bsim_select_database first.";
        }

        Program program = getCurrentProgram();
        if (program == null) {
            return "Error: No program loaded";
        }

        try {
            StringBuilder results = new StringBuilder();
            FunctionManager funcManager = program.getFunctionManager();
            int totalFunctions = funcManager.getFunctionCount();
            int queriedFunctions = 0;

            results.append("Querying ").append(totalFunctions).append(" functions against BSim database...\n\n");

            // Generate signatures for all functions
            GenSignatures gensig = new GenSignatures(false);
            gensig.setVectorFactory(bsimDatabase.getLSHVectorFactory());
            
            // Set up the executable record for the current program
            String exeName = program.getName();
            String exePath = program.getExecutablePath();
            gensig.openProgram(program, exeName, exePath, null, null, null);
            
            DescriptionManager descManager = gensig.getDescriptionManager();

            // Use built-in scanFunctions to scan all at once
            try {
                gensig.scanFunctions(funcManager.getFunctions(true), 30, new ConsoleTaskMonitor());
                queriedFunctions = descManager.numFunctions();
            } catch (Exception e) {
                return "Error: Failed to generate signatures: " + e.getMessage();
            }

            if (queriedFunctions == 0) {
                return "Error: No function signatures were generated";
            }

            // Create query
            // Note: We don't set query.max here because we need to filter by max similarity/confidence first,
            // then limit to maxMatchesPerFunction. Setting query.max too early might exclude valid matches.
            QueryNearest query = new QueryNearest();
            query.manage = descManager;
            query.max = Integer.MAX_VALUE; // Get all potential matches
            query.thresh = similarityThreshold;
            query.signifthresh = confidenceThreshold;

            // Execute query
            ResponseNearest response = query.execute(bsimDatabase);
            
            if (response == null) {
                return "Error: Query returned no response";
            }

            // Filter results by max similarity and max confidence, and limit to maxMatchesPerFunction
            filterBSimResults(response, maxSimilarity, maxConfidence, maxMatchesPerFunction);

            results.append("Successfully queried ").append(queriedFunctions).append(" functions\n");

            // Format detailed results with pagination
            results.append(formatBSimResults(response, null, offset, limit));

            return results.toString();

        } catch (Exception e) {
            return "Error querying all functions: " + e.getMessage();
        }
    }

    /**
     * Get detailed information about a BSim match from a program in the Ghidra project.
     * Falls back gracefully if the program is not found in the project.
     */
    /**
     * Get the disassembly of a BSim match from a program in the Ghidra project.
     */
    private String getBSimMatchDisassembly(String executablePath, String functionName, String functionAddress) {
        return getBSimMatchFunction(executablePath, functionName, functionAddress, true, false);
    }

    /**
     * Get the decompilation of a BSim match from a program in the Ghidra project.
     */
    private String getBSimMatchDecompile(String executablePath, String functionName, String functionAddress) {
        return getBSimMatchFunction(executablePath, functionName, functionAddress, false, true);
    }

    /**
     * Get function details for a BSim match from a program in the Ghidra project.
     * Falls back gracefully if the program is not found in the project.
     */
    private String getBSimMatchFunction(String executablePath, String functionName, String functionAddress,
                                        boolean includeDisassembly, boolean includeDecompile) {
        // Input validation
        if (executablePath == null || executablePath.isEmpty()) {
            return "Error: Executable path is required";
        }
        if (functionName == null || functionName.isEmpty()) {
            return "Error: Function name is required";
        }
        if (functionAddress == null || functionAddress.isEmpty()) {
            return "Error: Function address is required";
        }

        StringBuilder result = new StringBuilder();
        result.append("Match Details\n");
        result.append("=============\n");
        result.append(String.format("Executable: %s\n", executablePath));
        result.append(String.format("Function: %s\n", functionName));
        result.append(String.format("Address: %s\n\n", functionAddress));

        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm == null) {
            result.append("ERROR: ProgramManager service not available\n");
            return result.toString();
        }

        String fileName = new java.io.File(executablePath).getName();
        Program matchedProgram = null;
        boolean needsRelease = false;

        // Strategy 1: Check all open programs
        Program[] openPrograms = pm.getAllOpenPrograms();
        for (Program program : openPrograms) {
            if (executablePath.equals(program.getExecutablePath()) || fileName.equals(program.getName())) {
                matchedProgram = program;
                needsRelease = false;
                break;
            }
        }

        // Strategy 2: Try to find in project but not currently open
        if (matchedProgram == null) {
            ghidra.framework.model.Project project = tool.getProject();
            if (project != null) {
                ghidra.framework.model.DomainFile domainFile = findDomainFileRecursive(
                    project.getProjectData().getRootFolder(), fileName);
                
                if (domainFile != null) {
                    try {
                        ghidra.framework.model.DomainObject domainObject = 
                            domainFile.getDomainObject(this, false, false, new ConsoleTaskMonitor());
                        if (domainObject instanceof Program) {
                            matchedProgram = (Program) domainObject;
                            needsRelease = true;
                        }
                    } catch (Exception e) {
                        Msg.error(this, "Failed to open program from project: " + fileName, e);
                    }
                }
            }
        }

        if (matchedProgram == null) {
            result.append("ERROR: Program not found in Ghidra project\n");
            result.append("The matched executable is not in the current project.\n");
            result.append("\nTo view match details, please import the program into Ghidra:\n");
            result.append("  ").append(executablePath).append("\n");
            return result.toString();
        }

        try {
            // Find the function
            Address addr = matchedProgram.getAddressFactory().getAddress(functionAddress);
            Function func = matchedProgram.getFunctionManager().getFunctionAt(addr);
            
            if (func == null) {
                func = matchedProgram.getFunctionManager().getFunctionContaining(addr);
            }
            
            if (func == null) {
                result.append("ERROR: Function not found at address ").append(functionAddress).append("\n");
                return result.toString();
            }

            // Get function prototype
            result.append("Function Prototype:\n");
            result.append("-------------------\n");
            result.append(func.getSignature()).append("\n\n");

            // Get decompilation if requested
            if (includeDecompile) {
                result.append("Decompilation:\n");
                result.append("--------------\n");
                String decompCode = decompileFunctionInProgram(func, matchedProgram);
                if (decompCode != null && !decompCode.isEmpty()) {
                    result.append(decompCode).append("\n");
                } else {
                    result.append("(Decompilation not available)\n");
                }
            }

            // Get assembly if requested
            if (includeDisassembly) {
                if (includeDecompile) {
                    result.append("\n");
                }
                result.append("Assembly:\n");
                result.append("---------\n");
                String asmCode = disassembleFunctionInProgram(func, matchedProgram);
                if (asmCode != null && !asmCode.isEmpty()) {
                    result.append(asmCode);
                } else {
                    result.append("(Assembly not available)\n");
                }
            }

            return result.toString();

        } catch (Exception e) {
            result.append("ERROR: Exception while processing program: ").append(e.getMessage()).append("\n");
            Msg.error(this, "Error getting BSim match function", e);
            return result.toString();
        } finally {
            // Release the program if we opened it from the project
            if (needsRelease && matchedProgram != null) {
                matchedProgram.release(this);
            }
        }
    }

    /**
     * Recursively search for a domain file by name in a folder and its subfolders
     */
    private ghidra.framework.model.DomainFile findDomainFileRecursive(
            ghidra.framework.model.DomainFolder folder, String fileName) {
        
        // Check files in current folder
        for (ghidra.framework.model.DomainFile file : folder.getFiles()) {
            if (fileName.equals(file.getName())) {
                return file;
            }
        }
        
        // Recursively check subfolders
        for (ghidra.framework.model.DomainFolder subfolder : folder.getFolders()) {
            ghidra.framework.model.DomainFile result = findDomainFileRecursive(subfolder, fileName);
            if (result != null) {
                return result;
            }
        }
        
        return null;
    }

    /**
     * Decompile a function within a specific program
     */
    private String decompileFunctionInProgram(Function func, Program program) {
        try {
            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(program);
            DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
            
            if (result != null && result.decompileCompleted()) {
                return result.getDecompiledFunction().getC();
            }
        } catch (Exception e) {
            Msg.error(this, "Error decompiling function in external program", e);
        }
        return null;
    }

    /**
     * Disassemble a function within a specific program
     */
    private String disassembleFunctionInProgram(Function func, Program program) {
        try {
            StringBuilder result = new StringBuilder();
            Listing listing = program.getListing();
            Address start = func.getEntryPoint();
            Address end = func.getBody().getMaxAddress();

            InstructionIterator instructions = listing.getInstructions(start, true);
            while (instructions.hasNext()) {
                Instruction instr = instructions.next();
                if (instr.getAddress().compareTo(end) > 0) {
                    break;
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
            Msg.error(this, "Error disassembling function in external program", e);
        }
        return null;
    }

    /**
     * Filter BSim results by maximum similarity and confidence thresholds, and limit matches.
     * Removes matches that exceed the specified maximum values, and limits the number of 
     * matches per function. Implements early stopping for efficiency.
     * 
     * Note: Maximum thresholds are exclusive (values >= max are filtered out),
     * while minimum thresholds (applied in the query) are inclusive.
     * 
     * @param response The BSim query response to filter
     * @param maxSimilarity Maximum similarity score (exclusive) - matches >= this value are removed
     * @param maxConfidence Maximum confidence score (exclusive) - matches >= this value are removed
     * @param maxMatches Maximum number of matches to keep per function (for early stopping)
     */
    private void filterBSimResults(ResponseNearest response, double maxSimilarity, double maxConfidence, int maxMatches) {
        if (response == null || response.result == null) {
            return;
        }

        Iterator<SimilarityResult> iter = response.result.iterator();
        while (iter.hasNext()) {
            SimilarityResult simResult = iter.next();
            Iterator<SimilarityNote> noteIter = simResult.iterator();
            
            int validMatchCount = 0;
            
            while (noteIter.hasNext()) {
                SimilarityNote note = noteIter.next();
                
                // Remove matches that meet or exceed max similarity or max confidence (exclusive)
                if (note.getSimilarity() >= maxSimilarity || note.getSignificance() >= maxConfidence) {
                    noteIter.remove();
                } else {
                    // This is a valid match
                    validMatchCount++;
                    
                    // Early stopping: if we've reached maxMatches valid matches, remove all remaining
                    if (validMatchCount > maxMatches) {
                        noteIter.remove();
                    }
                }
            }
        }
    }
    
    private Address getAddressFromLong(long address) {
        Program program = getCurrentProgram();
        String hexAddr = Long.toHexString(address);
        return program.getAddressFactory().getAddress(hexAddr);
    }

    /**
     * Format BSim query results into a readable string with pagination
     */
    private String formatBSimResults(ResponseNearest response, String queryFunctionName, int offset, int limit) {
        StringBuilder result = new StringBuilder();
        
        if (queryFunctionName != null) {
            result.append("Matches for function: ").append(queryFunctionName).append("\n\n");
        }

        Iterator<SimilarityResult> iter = response.result.iterator();
        int totalMatchCount = 0;
        int displayedMatchCount = 0;

        while (iter.hasNext()) {
            SimilarityResult simResult = iter.next();
            FunctionDescription base = simResult.getBase();
            
            if (simResult.size() == 0) {
                if (queryFunctionName == null) {
                    continue; // Skip functions with no matches when querying all
                }
                result.append("No matches found (all matches filtered out or none available)\n");
                return result.toString(); // Early return for single function with no matches
            }

            // For single function query, paginate the matches
            // For all functions query, paginate the functions
            if (queryFunctionName != null) {
                // Single function: paginate through similarity matches
                int totalMatches = simResult.size();
                
                Iterator<SimilarityNote> noteIter = simResult.iterator();
                int matchIndex = 0;
                
                while (noteIter.hasNext()) {
                    SimilarityNote note = noteIter.next();
                    
                    // Skip matches before offset
                    if (matchIndex < offset) {
                        matchIndex++;
                        continue;
                    }
                    
                    // Stop if we've reached the limit
                    if (displayedMatchCount >= limit) {
                        break;
                    }
                    
                    FunctionDescription match = note.getFunctionDescription();
                    ExecutableRecord exe = match.getExecutableRecord();

                    result.append(String.format("Match %d:\n", matchIndex + 1));
                    
                    if (exe != null) {
                        result.append(String.format("  Executable: %s\n", exe.getNameExec()));
                    }
                    
                    result.append(String.format("  Function: %s\n", match.getFunctionName()));
                    result.append(String.format("  Address: %s\n", getAddressFromLong(match.getAddress())));
                    result.append(String.format("  Similarity: %.4f\n", note.getSimilarity()));
                    result.append(String.format("  Confidence: %.4f\n", note.getSignificance()));
                    
                    if (exe != null) {
                        String arch = exe.getArchitecture();
                        String compiler = exe.getNameCompiler();
                        if (arch != null && !arch.isEmpty()) {
                            result.append(String.format("  Architecture: %s\n", arch));
                        }
                        if (compiler != null && !compiler.isEmpty()) {
                            result.append(String.format("  Compiler: %s\n", compiler));
                        }
                    }
                    
                    result.append("\n");
                    matchIndex++;
                    displayedMatchCount++;
                }
                
                // Add pagination info for single function
                int remaining = totalMatches - offset - displayedMatchCount;
                if (remaining < 0) remaining = 0;
                
                result.append(String.format("Showing matches %d-%d of %d", 
                    offset + 1, offset + displayedMatchCount, totalMatches));
                if (remaining > 0) {
                    result.append(String.format(" (%d more available)\n", remaining));
                } else {
                    result.append("\n");
                }
            } else {                
                // All functions query: paginate by function (skip if before offset)
                if (totalMatchCount < offset) {
                    totalMatchCount++;
                    continue;
                }
                
                result.append("Function: ").append(base.getFunctionName())
                        .append(" at ").append(getAddressFromLong(base.getAddress())).append("\n");
            
                // Stop if we've reached the limit
                if (displayedMatchCount >= limit) {
                    break;
                }
                
                result.append("Found ").append(simResult.size()).append(" match(es):\n");

                Iterator<SimilarityNote> noteIter = simResult.iterator();
                int matchNum = 1;
                while (noteIter.hasNext()) {
                    SimilarityNote note = noteIter.next();
                    FunctionDescription match = note.getFunctionDescription();
                    ExecutableRecord exe = match.getExecutableRecord();

                    result.append(String.format("Match %d:\n", matchNum));
                    
                    result.append(String.format("  Executable: %s\n", exe.getNameExec()));
                    result.append(String.format("  Function: %s\n", match.getFunctionName()));
                    result.append(String.format("  Address: %s\n", getAddressFromLong(match.getAddress())));
                    result.append(String.format("  Similarity: %.4f\n", note.getSimilarity()));
                    result.append(String.format("  Confidence: %.4f\n", note.getSignificance()));
                    
                    result.append("\n");
                    matchNum++;
                }
                result.append("\n");
                totalMatchCount++;
                displayedMatchCount++;
            }
        }

        // Add pagination info for all functions query
        if (queryFunctionName == null) {
            // Count remaining functions
            int remaining = 0;
            while (iter.hasNext()) {
                SimilarityResult simResult = iter.next();
                if (simResult.size() > 0) {
                    remaining++;
                }
            }
            
            if (displayedMatchCount == 0) {
                result.append("No matches found for any functions\n");
            } else {
                result.append(String.format("Showing functions %d-%d of %d+ results", 
                    offset + 1, offset + displayedMatchCount, offset + displayedMatchCount + remaining));
                if (remaining > 0) {
                    result.append(String.format(" (%d more available)\n", remaining));
                } else {
                    result.append("\n");
                }
            }
        }

        return result.toString();
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
