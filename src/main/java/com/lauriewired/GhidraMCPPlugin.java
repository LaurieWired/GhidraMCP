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
import ghidra.app.services.ConsoleService;
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
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.listing.Variable;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.decompiler.ClangToken;
import ghidra.framework.options.Options;

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
    private ConsoleService consoleService;
    private static final String OPTION_CATEGORY_NAME = "GhidraMCP HTTP Server";
    private static final String PORT_OPTION_NAME = "Server Port";
    private static final int DEFAULT_PORT = 28382;

    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);

        // 获取 ConsoleService 用于输出到 Console
        this.consoleService = tool.getService(ConsoleService.class);

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

        server.createContext("/set_plate_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = setPlateComment(address, comment);
            sendResponse(exchange, success ? "Plate comment set successfully" : "Failed to set plate comment");
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

        // 搜索数据类型 - 必须在 /data_types 和 /data_types/ 之前注册
        server.createContext("/data_types/search", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = qparams.get("name");
            if (name == null || name.isEmpty()) {
                try {
                    sendResponse(exchange, "Error: 'name' parameter is required", 400);
                } catch (IOException e) {
                    Msg.error(this, "Failed to send error response", e);
                }
                return;
            }
            boolean caseSensitive = Boolean.parseBoolean(qparams.getOrDefault("case_sensitive", "false"));
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, searchDataTypes(name, caseSensitive, offset, limit));
        });

        // 获取特定数据类型的详情 - 必须在 /data_types 之前注册
        server.createContext("/data_types/", exchange -> {
            // 从路径中提取数据类型路径,例如 "/data_types/int" -> "int"
            String path = exchange.getRequestURI().getPath();
            String typePath = path.substring("/data_types/".length());
            // URL 解码
            try {
                typePath = URLDecoder.decode(typePath, StandardCharsets.UTF_8);
            } catch (Exception e) {
                Msg.error(this, "Error decoding type path", e);
            }
            sendResponse(exchange, getDataTypeDetails(typePath));
        });

        // 创建结构体数据类型 - 必须在 /data_types 之前注册
        server.createContext("/data_types/struct", exchange -> {
            printToConsole("========== HTTP: /data_types/struct called ==========");

            if (!"POST".equals(exchange.getRequestMethod())) {
                printToConsole("Method not allowed: " + exchange.getRequestMethod());
                try {
                    sendResponse(exchange, "Method not allowed. Use POST.", 405);
                } catch (IOException e) {
                    Msg.error(this, "Failed to send error response", e);
                }
                return;
            }

            // 解析 JSON 请求体
            String requestBody;
            try {
                byte[] body = exchange.getRequestBody().readAllBytes();
                requestBody = new String(body, StandardCharsets.UTF_8);
                printToConsole("Received body: " + requestBody);
            } catch (IOException e) {
                printErrorToConsole("Failed to read request body");
                Msg.error(this, "Failed to read request body", e);
                try {
                    sendResponse(exchange, "Failed to read request body", 500);
                } catch (IOException ex) {
                    Msg.error(this, "Failed to send error response", ex);
                }
                return;
            }

            printToConsole("Calling createStructFromJson...");
            String result = createStructFromJson(requestBody);
            printToConsole("Result: " + result);

            try {
                if (result.startsWith("Error")) {
                    sendResponse(exchange, result, 400);
                } else {
                    sendResponse(exchange, result);
                }
            } catch (IOException e) {
                printErrorToConsole("Failed to send response: " + e.getMessage());
                Msg.error(this, "Failed to send response", e);
            }
        });

        // 列出所有数据类型 - 最后注册,作为默认端点
        server.createContext("/data_types", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getAllDataTypePaths(offset, limit));
        });

        // 创建枚举数据类型 - 必须在 /data_types 之前注册
        server.createContext("/data_types/enum", exchange -> {
            if (!"POST".equals(exchange.getRequestMethod())) {
                try {
                    sendResponse(exchange, "Method not allowed. Use POST.", 405);
                } catch (IOException e) {
                    Msg.error(this, "Failed to send error response", e);
                }
                return;
            }

            // 解析 JSON 请求体
            String requestBody;
            try {
                byte[] body = exchange.getRequestBody().readAllBytes();
                requestBody = new String(body, StandardCharsets.UTF_8);
            } catch (IOException e) {
                Msg.error(this, "Failed to read request body", e);
                try {
                    sendResponse(exchange, "Failed to read request body", 500);
                } catch (IOException ex) {
                    Msg.error(this, "Failed to send error response", ex);
                }
                return;
            }

            String result = createEnumFromJson(requestBody);
            try {
                if (result.startsWith("Error")) {
                    sendResponse(exchange, result, 400);
                } else {
                    sendResponse(exchange, result);
                }
            } catch (IOException e) {
                Msg.error(this, "Failed to send response", e);
            }
        });

        // 创建 Typedef 数据类型 - 必须在 /data_types 之前注册
        server.createContext("/data_types/typedef", exchange -> {
            if (!"POST".equals(exchange.getRequestMethod())) {
                try {
                    sendResponse(exchange, "Method not allowed. Use POST.", 405);
                } catch (IOException e) {
                    Msg.error(this, "Failed to send error response", e);
                }
                return;
            }

            // 解析 JSON 请求体
            String requestBody;
            try {
                byte[] body = exchange.getRequestBody().readAllBytes();
                requestBody = new String(body, StandardCharsets.UTF_8);
            } catch (IOException e) {
                Msg.error(this, "Failed to read request body", e);
                try {
                    sendResponse(exchange, "Failed to read request body", 500);
                } catch (IOException ex) {
                    Msg.error(this, "Failed to send error response", ex);
                }
                return;
            }

            String result = createTypedefFromJson(requestBody);
            try {
                if (result.startsWith("Error")) {
                    sendResponse(exchange, result, 400);
                } else {
                    sendResponse(exchange, result);
                }
            } catch (IOException e) {
                Msg.error(this, "Failed to send response", e);
            }
        });

        // 创建联合体 (Union) 数据类型 - 必须在 /data_types 之前注册
        server.createContext("/data_types/union", exchange -> {
            if (!"POST".equals(exchange.getRequestMethod())) {
                try {
                    sendResponse(exchange, "Method not allowed. Use POST.", 405);
                } catch (IOException e) {
                    Msg.error(this, "Failed to send error response", e);
                }
                return;
            }

            // 解析 JSON 请求体
            String requestBody;
            try {
                byte[] body = exchange.getRequestBody().readAllBytes();
                requestBody = new String(body, StandardCharsets.UTF_8);
            } catch (IOException e) {
                Msg.error(this, "Failed to read request body", e);
                try {
                    sendResponse(exchange, "Failed to read request body", 500);
                } catch (IOException ex) {
                    Msg.error(this, "Failed to send error response", ex);
                }
                return;
            }

            String result = createUnionFromJson(requestBody);
            try {
                if (result.startsWith("Error")) {
                    sendResponse(exchange, result, 400);
                } else {
                    sendResponse(exchange, result);
                }
            } catch (IOException e) {
                Msg.error(this, "Failed to send response", e);
            }
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

    /**
     * 获取所有数据类型的路径名
     * @param offset 分页偏移量
     * @param limit 返回的最大数量
     * @return 分页后的数据类型路径列表,每行一个路径
     */
    private String getAllDataTypePaths(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        DataTypeManager dtm = program.getDataTypeManager();
        if (dtm == null) return "No data type manager available";

        List<String> dataTypePaths = new ArrayList<>();

        // 获取所有数据类型的迭代器
        Iterator<DataType> allDataTypes = dtm.getAllDataTypes();

        // 收集所有数据类型的路径
        while (allDataTypes.hasNext()) {
            DataType dataType = allDataTypes.next();
            String pathName = dataType.getPathName();
            if (pathName != null && !pathName.isEmpty()) {
                dataTypePaths.add(pathName);
            }
        }

        // 排序以便于查看
        Collections.sort(dataTypePaths);

        // 应用分页
        return paginateList(dataTypePaths, offset, limit);
    }

    /**
     * 根据名称关键词搜索数据类型
     *
     * @param query 搜索关键词
     * @param caseSensitive 是否大小写敏感
     * @param offset 分页偏移
     * @param limit 返回数量限制
     * @return 匹配的数据类型路径列表,每行一个路径
     */
    private String searchDataTypes(String query, boolean caseSensitive, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        DataTypeManager dtm = program.getDataTypeManager();
        if (dtm == null) return "No data type manager available";

        List<String> matchingPaths = new ArrayList<>();

        // 准备搜索字符串
        String searchQuery = caseSensitive ? query : query.toLowerCase();

        // 获取所有数据类型的迭代器
        Iterator<DataType> allDataTypes = dtm.getAllDataTypes();

        // 收集匹配的数据类型路径
        while (allDataTypes.hasNext()) {
            DataType dataType = allDataTypes.next();
            String pathName = dataType.getPathName();

            if (pathName == null || pathName.isEmpty()) {
                continue;
            }

            // 根据大小写敏感设置进行匹配
            String targetPath = caseSensitive ? pathName : pathName.toLowerCase();

            // 检查路径是否包含搜索关键词
            if (targetPath.contains(searchQuery)) {
                matchingPaths.add(pathName);
            }
        }

        // 排序以便于查看
        Collections.sort(matchingPaths);

        // 应用分页
        return paginateList(matchingPaths, offset, limit);
    }

    /**
     * 获取特定数据类型的详细信息 (JSON 格式)
     * @param typePath 数据类型的完整路径,如 "int" 或 "/MyTypes/MyStruct"
     * @return JSON 格式的数据类型详情
     */
    private String getDataTypeDetails(String typePath) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
        }

        DataTypeManager dtm = program.getDataTypeManager();
        if (dtm == null) {
            return "{\"error\": \"No data type manager available\"}";
        }

        if (typePath == null || typePath.isEmpty()) {
            return "{\"error\": \"Type path is required\"}";
        }

        // 确保路径以 / 开头
        if (!typePath.startsWith("/")) {
            typePath = "/" + typePath;
        }

        try {
            // 获取数据类型
            DataType dataType = dtm.getDataType(typePath);
            if (dataType == null) {
                return "{\"error\": \"Data type not found: " + escapeJson(typePath) + "\"}";
            }

            // 构建 JSON
            StringBuilder json = new StringBuilder();
            json.append("{\n");

            // 基本信息
            json.append("  \"path\": ").append(jsonEscape(dataType.getPathName())).append(",\n");
            json.append("  \"name\": ").append(jsonEscape(dataType.getName())).append(",\n");
            json.append("  \"categoryPath\": ").append(jsonEscape(dataType.getCategoryPath().getPath())).append(",\n");
            json.append("  \"length\": ").append(dataType.getLength()).append(",\n");

            // 描述
            String description = dataType.getDescription();
            if (description != null && !description.isEmpty()) {
                json.append("  \"description\": ").append(jsonEscape(description)).append(",\n");
            } else {
                json.append("  \"description\": \"\",\n");
            }

            json.append("  \"isDeleted\": ").append(dataType.isDeleted()).append(",\n");

            // 数据类型类别
            String typeCategory = getDataTypeCategory(dataType);
            json.append("  \"type\": \"").append(typeCategory).append("\"");

            // 对于复合类型,添加额外信息
            if (dataType instanceof ghidra.program.model.data.Structure) {
                json.append(",\n  \"fields\": [");
                json.append(getStructureFields((ghidra.program.model.data.Structure) dataType));
                json.append("\n  ]");
            } else if (dataType instanceof ghidra.program.model.data.TypeDef) {
                ghidra.program.model.data.TypeDef typedef = (ghidra.program.model.data.TypeDef) dataType;
                json.append(",\n  \"baseType\": ").append(jsonEscape(typedef.getDataType().getPathName()));
            } else if (dataType instanceof ghidra.program.model.data.Enum) {
                json.append(",\n  \"values\": [");
                json.append(getEnumValues((ghidra.program.model.data.Enum) dataType));
                json.append("\n  ]");
            } else if (dataType instanceof ghidra.program.model.data.FunctionDefinition) {
                ghidra.program.model.data.FunctionDefinition funcDef = (ghidra.program.model.data.FunctionDefinition) dataType;
                json.append(",\n  \"returnType\": ").append(jsonEscape(funcDef.getReturnType().getPathName()));
                json.append(",\n  \"hasVarArgs\": ").append(funcDef.hasVarArgs());
            }

            json.append("\n}");
            return json.toString();

        } catch (Exception e) {
            Msg.error(this, "Error getting data type details", e);
            return "{\"error\": \"Error retrieving data type: " + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * 获取数据类型的类别名称
     */
    private String getDataTypeCategory(DataType dataType) {
        if (dataType instanceof ghidra.program.model.data.Structure) {
            return "Structure";
        } else if (dataType instanceof ghidra.program.model.data.Union) {
            return "Union";
        } else if (dataType instanceof ghidra.program.model.data.Enum) {
            return "Enum";
        } else if (dataType instanceof ghidra.program.model.data.TypeDef) {
            return "Typedef";
        } else if (dataType instanceof ghidra.program.model.data.FunctionDefinition) {
            return "FunctionDefinition";
        } else if (dataType instanceof ghidra.program.model.data.Array) {
            return "Array";
        } else if (dataType instanceof PointerDataType) {
            return "Pointer";
        } else {
            return "BuiltIn";
        }
    }

    /**
     * 获取结构体的字段列表
     */
    private String getStructureFields(ghidra.program.model.data.Structure struct) {
        StringBuilder json = new StringBuilder();
        ghidra.program.model.data.DataTypeComponent[] components = struct.getDefinedComponents();

        for (int i = 0; i < components.length; i++) {
            ghidra.program.model.data.DataTypeComponent component = components[i];
            if (i > 0) {
                json.append(",");
            }
            json.append("\n    {");
            json.append("\"name\": ").append(jsonEscape(component.getFieldName()));
            json.append(", \"offset\": ").append(component.getOffset());
            json.append(", \"length\": ").append(component.getLength());
            json.append(", \"dataType\": ").append(jsonEscape(component.getDataType().getPathName()));

            // 添加注释
            String comment = component.getComment();
            if (comment != null && !comment.isEmpty()) {
                json.append(", \"comment\": ").append(jsonEscape(comment));
            }

            json.append("}");
        }

        return json.toString();
    }

    /**
     * 获取枚举的值列表
     */
    private String getEnumValues(ghidra.program.model.data.Enum enumType) {
        StringBuilder json = new StringBuilder();
        String[] names = enumType.getNames();

        for (int i = 0; i < names.length; i++) {
            String name = names[i];
            if (i > 0) {
                json.append(",");
            }
            json.append("\n    {");
            json.append("\"name\": ").append(jsonEscape(name));
            json.append(", \"value\": ").append(enumType.getValue(name));

            // 添加注释
            String comment = enumType.getComment(name);
            if (comment != null && !comment.isEmpty()) {
                json.append(", \"comment\": ").append(jsonEscape(comment));
            }

            json.append("}");
        }

        return json.toString();
    }

    /**
     * JSON 字符串转义
     */
    private String jsonEscape(String input) {
        if (input == null) {
            return "\"\"";
        }
        return "\"" + input.replace("\\", "\\\\")
                           .replace("\"", "\\\"")
                           .replace("\n", "\\n")
                           .replace("\r", "\\r")
                           .replace("\t", "\\t") + "\"";
    }

    /**
     * 简单的 JSON 转义用于错误消息
     */
    private String escapeJson(String input) {
        if (input == null) {
            return "";
        }
        return input.replace("\\", "\\\\")
                    .replace("\"", "\\\"")
                    .replace("\n", "\\n")
                    .replace("\r", "\\r")
                    .replace("\t", "\\t");
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
        if (addressStr == null || addressStr.isEmpty()) return false;
        if (comment == null) return false;

        // 将空字符串转换为 null,以便在 Ghidra 中正确删除注释
        // "" -> null 会删除注释,而 "" -> "" 只会设置一个空注释
        String commentValue = comment.isEmpty() ? null : comment;

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction(transactionName);
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    program.getListing().setComment(addr, commentType, commentValue);
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
     * Set a plate comment for a given address
     */
    private boolean setPlateComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.PLATE_COMMENT, "Set plate comment");
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
                // 如果 typeName 已经以 / 开头，直接使用；否则添加前缀
                String typePath = typeName.startsWith("/") ? typeName : "/" + typeName;
                DataType directType = dtm.getDataType(typePath);
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
            String[] kv = pair.split("=", 2); // 限制分割为2个部分,允许值中包含"="
            // URL decode parameter values
            try {
                String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                String value = kv.length > 1 ? URLDecoder.decode(kv[1], StandardCharsets.UTF_8) : "";
                params.put(key, value);
            } catch (Exception e) {
                Msg.error(this, "Error decoding URL parameter", e);
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

    /**
     * 从 JSON 字符串创建枚举数据类型
     * @param jsonStr JSON 格式的枚举定义
     * @return 成功消息或错误消息
     */
    private String createEnumFromJson(String jsonStr) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "Error: No program loaded";
        }

        // 简单的 JSON 解析 (不使用外部库)
        try {
            // 提取 name
            String name = extractJsonString(jsonStr, "name");
            if (name == null || name.isEmpty()) {
                return "Error: 'name' field is required";
            }

            // 提取 categoryPath
            String categoryPath = extractJsonString(jsonStr, "categoryPath");
            if (categoryPath == null || categoryPath.isEmpty()) {
                return "Error: 'categoryPath' field is required";
            }

            // 提取 size
            int size = extractJsonInt(jsonStr, "size");
            if (size == -1) {
                return "Error: 'size' field is required and must be a valid integer";
            }
            if (size != 1 && size != 2 && size != 4 && size != 8) {
                return "Error: 'size' must be 1, 2, 4, or 8";
            }

            // 提取 description (可选)
            String description = extractJsonString(jsonStr, "description");

            // 提取 values 数组
            String valuesArray = extractJsonArray(jsonStr, "values");
            if (valuesArray == null || valuesArray.isEmpty()) {
                return "Error: 'values' array is required and must contain at least one value";
            }

            // 解析枚举值
            List<EnumValue> enumValues = parseEnumValues(valuesArray);
            if (enumValues == null) {
                return "Error: Failed to parse enum values";
            }
            if (enumValues.isEmpty()) {
                return "Error: At least one enum value is required";
            }

            // 检查枚举值名称是否重复
            Set<String> valueNames = new HashSet<>();
            for (EnumValue ev : enumValues) {
                if (valueNames.contains(ev.name)) {
                    return "Error: Duplicate enum value name: " + ev.name;
                }
                valueNames.add(ev.name);
            }

            // 创建枚举
            return createEnum(program, categoryPath, name, size, description, enumValues);

        } catch (Exception e) {
            Msg.error(this, "Error creating enum from JSON", e);
            return "Error: Invalid JSON format - " + e.getMessage();
        }
    }

    /**
     * 枚举值内部类
     */
    private static class EnumValue {
        String name;
        long value;
        String comment;

        EnumValue(String name, long value, String comment) {
            this.name = name;
            this.value = value;
            this.comment = comment;
        }
    }

    /**
     * 解析枚举值数组
     */
    private List<EnumValue> parseEnumValues(String valuesArray) {
        List<EnumValue> result = new ArrayList<>();

        // valuesArray 格式: [{"name": "RED", "value": 0, "comment": "..."}, ...]
        // 简单解析: 移除外层方括号,然后按 },{ 分割
        String content = valuesArray.trim();
        if (content.startsWith("[")) {
            content = content.substring(1);
        }
        if (content.endsWith("]")) {
            content = content.substring(0, content.length() - 1);
        }

        if (content.trim().isEmpty()) {
            return result;
        }

        // 分割对象 (简单地按 "},{" 分割)
        String[] objects = content.split("\\},\\s*\\{");

        for (String obj : objects) {
            // 移除可能的 { 和 }
            obj = obj.trim();
            if (obj.startsWith("{")) {
                obj = obj.substring(1);
            }
            if (obj.endsWith("}")) {
                obj = obj.substring(0, obj.length() - 1);
            }

            String name = extractJsonString(obj, "name");
            long value = extractJsonLong(obj, "value");
            String comment = extractJsonString(obj, "comment");

            if (name != null && value != -1) {
                result.add(new EnumValue(name, value, comment));
            }
        }

        return result;
    }

    /**
     * 从 JSON 中提取字符串值
     */
    private String extractJsonString(String json, String key) {
        String pattern = "\"" + key + "\"\\s*:\\s*\"([^\"]*)\"";
        java.util.regex.Pattern p = java.util.regex.Pattern.compile(pattern);
        java.util.regex.Matcher m = p.matcher(json);
        if (m.find()) {
            return m.group(1);
        }
        return null;
    }

    /**
     * 从 JSON 中提取整数值
     */
    private int extractJsonInt(String json, String key) {
        String pattern = "\"" + key + "\"\\s*:\\s*(\\d+)";
        java.util.regex.Pattern p = java.util.regex.Pattern.compile(pattern);
        java.util.regex.Matcher m = p.matcher(json);
        if (m.find()) {
            try {
                return Integer.parseInt(m.group(1));
            } catch (NumberFormatException e) {
                return -1;
            }
        }
        return -1;
    }

    /**
     * 从 JSON 中提取长整数值
     */
    private long extractJsonLong(String json, String key) {
        String pattern = "\"" + key + "\"\\s*:\\s*(\\d+)";
        java.util.regex.Pattern p = java.util.regex.Pattern.compile(pattern);
        java.util.regex.Matcher m = p.matcher(json);
        if (m.find()) {
            try {
                return Long.parseLong(m.group(1));
            } catch (NumberFormatException e) {
                return -1;
            }
        }
        return -1;
    }

    /**
     * 从 JSON 中提取数组
     */
    private String extractJsonArray(String json, String key) {
        String pattern = "\"" + key + "\"\\s*:\\s*(\\[.*?\\])";
        java.util.regex.Pattern p = java.util.regex.Pattern.compile(pattern);
        java.util.regex.Matcher m = p.matcher(json);
        if (m.find()) {
            return m.group(1);
        }
        return null;
    }

    /**
     * 创建枚举数据类型
     */
    private String createEnum(Program program, String categoryPathStr, String name,
                             int size, String description, List<EnumValue> enumValues) {
        final AtomicBoolean success = new AtomicBoolean(false);
        final StringBuilder errorMsg = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create enum data type");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();

                    // 创建类别路径
                    CategoryPath categoryPath = new CategoryPath(categoryPathStr);

                    // 检查枚举是否已存在
                    String fullPath = categoryPath.getPath() + (categoryPath.getPath().endsWith("/") ? "" : "/") + name;
                    DataType existingType = dtm.getDataType(fullPath);
                    if (existingType != null) {
                        errorMsg.append("Error: Enum '" + fullPath + "' already exists");
                        return;
                    }

                    // 创建枚举数据类型
                    EnumDataType enumDT = new EnumDataType(categoryPath, name, size);

                    // 添加描述
                    if (description != null && !description.isEmpty()) {
                        enumDT.setDescription(description);
                    }

                    // 添加枚举值
                    for (EnumValue ev : enumValues) {
                        enumDT.add(ev.name, ev.value);
                        // 枚举值注释暂不支持（Ghidra EnumDataType API 限制）
                    }

                    // 添加到数据类型管理器
                    dtm.addDataType(enumDT, null);

                    success.set(true);
                    Msg.info(this, "Successfully created enum: " + enumDT.getPathName());

                } catch (Exception e) {
                    errorMsg.append("Error: Failed to create enum - " + e.getMessage());
                    Msg.error(this, "Error creating enum", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Error: Failed to execute enum creation on Swing thread - " + e.getMessage();
        }

        if (success.get()) {
            return "Enum created successfully";
        } else {
            return errorMsg.toString();
        }
    }

    public Program getCurrentProgram() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        return pm != null ? pm.getCurrentProgram() : null;
    }

    private void sendResponse(HttpExchange exchange, String response) throws IOException {
        sendResponse(exchange, response, 200);
    }

    private void sendResponse(HttpExchange exchange, String response, int statusCode) throws IOException {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(statusCode, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    
    /**
     * 从 JSON 创建结构体数据类型
     * JSON 格式:
     * {
     *   "name": "Person",
     *   "categoryPath": "/MyTypes",
     *   "description": "Person information",
     *   "fields": [
     *     {"name": "id", "dataType": "/int", "length": 4, "comment": "Person ID"},
     *     {"name": "name", "dataType": "/char", "length": 32, "comment": "Person name"}
     *   ]
     * }
     */
    private String createStructFromJson(String jsonStr) {
        printToConsole("========== CREATE STRUCT START ==========");
        printToConsole("Received JSON: " + jsonStr);

        Program program = getCurrentProgram();
        if (program == null) {
            printErrorToConsole("ERROR - No program loaded!");
            return "Error: No program loaded";
        }

        printToConsole("Program loaded: " + program.getName());

        // 简单的 JSON 解析 (不使用外部库)
        String name = extractJsonString(jsonStr, "name");
        String categoryPath = extractJsonString(jsonStr, "categoryPath");
        String description = extractJsonString(jsonStr, "description");

        printToConsole("Parsed - name: '" + name + "', categoryPath: '" + categoryPath + "'");

        // 验证必需字段
        if (name == null || name.isEmpty()) {
            return "Error: 'name' field is required";
        }
        if (categoryPath == null || categoryPath.isEmpty()) {
            return "Error: 'categoryPath' field is required";
        }

        // 提取 fields 数组
        String fieldsStr = extractJsonArray(jsonStr, "fields");
        printToConsole("Extracted fields string: " + (fieldsStr != null ? fieldsStr : "null"));
        if (fieldsStr == null) {
            return "Error: 'fields' array is required";
        }

        // 解析字段
        List<StructField> fields = parseFields(fieldsStr);
        if (fields == null) {
            return "Error: Failed to parse fields";
        }

        // 创建结构体
        AtomicBoolean success = new AtomicBoolean(false);
        AtomicString errorMsg = new AtomicString("");

        try {
            SwingUtilities.invokeAndWait(() -> {
                int txId = program.startTransaction("Create struct: " + name);
                try {
                    DataTypeManager dtm = program.getDataTypeManager();

                    // 创建类别路径
                    // 注意：Ghidra 的根路径 "/" 不能直接用于存放数据类型
                    // 需要创建一个默认分类或使用用户指定的分类
                    CategoryPath catPath;
                    if (categoryPath.equals("/") || categoryPath.isEmpty()) {
                        // 根路径不能直接使用，创建一个默认分类
                        catPath = new CategoryPath("/MyTypes");
                        Msg.info(this, "根路径 / 不支持，自动使用 /MyTypes");
                    } else {
                        catPath = new CategoryPath(categoryPath);
                    }

                    // DEBUG: 详细输出 CategoryPath 信息
                    printToConsole("=== CategoryPath Debug ===");
                    printToConsole("Input categoryPath: '" + categoryPath + "'");
                    printToConsole("Actual catPath: '" + catPath.getPath() + "'");
                    printToConsole("catPath.toString(): '" + catPath.toString() + "'");
                    printToConsole("catPath.getName(): '" + catPath.getName() + "'");
                    printToConsole("========================");

                    // 检查结构体是否已存在
                    String existingPath = catPath.getPath() + (catPath.getPath().endsWith("/") ? "" : "/") + name;
                    if (dtm.getDataType(existingPath) != null) {
                        errorMsg.set("Error: Structure '" + name + "' already exists in category '" + categoryPath + "'");
                        return;
                    }

                    // 创建结构体
                    StructureDataType struct = new StructureDataType(catPath, name, 0);
                    printToConsole("Created struct object: " + struct.getPathName());
                    if (description != null && !description.isEmpty()) {
                        struct.setDescription(description);
                    }

                    // 添加字段
                    for (StructField field : fields) {
                        // DEBUG: 打印字段信息
                        printToConsole("Processing field: name=" + field.name + ", dataType=" + field.dataType + ", length=" + field.length);

                        // 解析数据类型
                        DataType fieldType = resolveDataType(dtm, field.dataType);
                        if (fieldType == null) {
                            errorMsg.set("Error: Data type '" + field.dataType + "' not found for field '" + field.name + "'");
                            return;
                        }

                        printToConsole("Resolved field type: " + fieldType.getPathName() + ", category=" + fieldType.getCategoryPath().getPath());

                        // 添加字段到结构体
                        try {
                            DataTypeComponent component = struct.add(fieldType, field.length, field.name, field.comment);
                            if (component == null) {
                                errorMsg.set("Error: Failed to add field '" + field.name + "' to structure");
                                return;
                            }
                        } catch (Exception e) {
                            errorMsg.set("Error: Failed to add field '" + field.name + "': " + e.getMessage());
                            Msg.error(this, "Failed to add struct field", e);
                            return;
                        }
                    }

                    // 添加到数据类型管理器
                    DataType addedStruct = dtm.addDataType(struct, null);
                    if (addedStruct != null) {
                        success.set(true);
                        printToConsole("Created structure: " + addedStruct.getPathName());
                    } else {
                        errorMsg.set("Error: Failed to add structure to data type manager");
                    }
                } catch (Exception e) {
                    errorMsg.set("Error: Failed to create structure: " + e.getMessage());
                    printErrorToConsole("Failed to create struct: " + e.getMessage());
                    Msg.error(this, "Failed to create struct", e);
                } finally {
                    program.endTransaction(txId, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute struct creation on Swing thread", e);
            return "Error: Failed to execute struct creation: " + e.getMessage();
        }

        if (success.get()) {
            return "Structure '" + name + "' created successfully in category '" + categoryPath + "'";
        } else {
            return errorMsg.get();
        }
    }

    /**
     * 结构体字段定义
     */
    private static class StructField {
        String name;
        String dataType;
        int length;
        String comment;

        StructField(String name, String dataType, int length, String comment) {
            this.name = name;
            this.dataType = dataType;
            this.length = length;
            this.comment = comment;
        }
    }

    /**
     * 解析字段数组
     * 输入格式: [{"name":"id","dataType":"/int","length":4,"comment":"Person ID"},{"name":"name",...}]
     */
    private List<StructField> parseFields(String fieldsStr) {
        List<StructField> fields = new ArrayList<>();
        // 移除开头和结尾的方括号
        if (fieldsStr.startsWith("[") && fieldsStr.endsWith("]")) {
            fieldsStr = fieldsStr.substring(1, fieldsStr.length() - 1);
        }

        if (fieldsStr.trim().isEmpty()) {
            return fields;
        }

        // 简单分割字段对象 (不处理嵌套的花括号)
        int braceLevel = 0;
        int start = 0;
        for (int i = 0; i < fieldsStr.length(); i++) {
            char c = fieldsStr.charAt(i);
            if (c == '{') braceLevel++;
            else if (c == '}') braceLevel--;
            else if (c == ',' && braceLevel == 0) {
                String fieldStr = fieldsStr.substring(start, i).trim();
                StructField field = parseField(fieldStr);
                if (field == null) return null;
                fields.add(field);
                start = i + 1;
            }
        }

        // 添加最后一个字段
        String lastFieldStr = fieldsStr.substring(start).trim();
        if (!lastFieldStr.isEmpty()) {
            StructField field = parseField(lastFieldStr);
            if (field == null) return null;
            fields.add(field);
        }

        return fields;
    }

    /**
     * 解析单个字段
     * 输入格式: {"name":"id","dataType":"/int","length":4,"comment":"Person ID"}
     */
    private StructField parseField(String fieldStr) {
        // 移除开头和结尾的花括号
        if (fieldStr.startsWith("{") && fieldStr.endsWith("}")) {
            fieldStr = fieldStr.substring(1, fieldStr.length() - 1);
        }

        String name = extractJsonString(fieldStr, "name");
        String dataType = extractJsonString(fieldStr, "dataType");
        int length = extractJsonInt(fieldStr, "length");
        String comment = extractJsonString(fieldStr, "comment");

        // DEBUG
        Msg.info(this, "parseField: name='" + name + "', dataType='" + dataType + "', length=" + length);

        if (name == null || name.isEmpty()) {
            return null;
        }
        if (dataType == null || dataType.isEmpty()) {
            return null;
        }

        return new StructField(name, dataType, length, comment);
    }


    /**
     * 从 JSON 字符串创建 Typedef 数据类型
     * @param jsonStr JSON 格式的 Typedef 定义
     * @return 成功消息或错误消息
     *
     * 请求格式:
     * {
     *   "name": "MyIntPtr",
     *   "categoryPath": "/MyTypes",
     *   "baseDataType": "/int",
     *   "isPointer": false  // 可选,默认 false
     * }
     */
    private String createTypedefFromJson(String jsonStr) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "Error: No program loaded";
        }

        // 简单的 JSON 解析 (不使用外部库)
        try {
            // 提取必需字段
            String name = extractJsonString(jsonStr, "name");
            if (name == null || name.isEmpty()) {
                return "Error: 'name' field is required";
            }

            String categoryPath = extractJsonString(jsonStr, "categoryPath");
            if (categoryPath == null || categoryPath.isEmpty()) {
                return "Error: 'categoryPath' field is required";
            }

            String baseDataType = extractJsonString(jsonStr, "baseDataType");
            if (baseDataType == null || baseDataType.isEmpty()) {
                return "Error: 'baseDataType' field is required";
            }

            // 提取可选字段 isPointer
            String isPointerStr = extractJsonString(jsonStr, "isPointer");
            boolean isPointer = isPointerStr != null && isPointerStr.equalsIgnoreCase("true");

            // 创建 Typedef
            return createTypedef(program, categoryPath, name, baseDataType, isPointer);

        } catch (Exception e) {
            Msg.error(this, "Error creating typedef from JSON", e);
            return "Error: Invalid JSON format - " + e.getMessage();
        }
    }

    /**
     * 创建 Typedef 数据类型
     * @param program 程序对象
     * @param categoryPathStr 类别路径
     * @param name Typedef 名称
     * @param baseDataTypeStr 基础数据类型
     * @param isPointer 是否为指针类型
     * @return 成功消息或错误消息
     */
    private String createTypedef(Program program, String categoryPathStr, String name,
                                String baseDataTypeStr, boolean isPointer) {
        final AtomicBoolean success = new AtomicBoolean(false);
        final AtomicString errorMsg = new AtomicString("");

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create typedef: " + name);
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    CategoryPath catPath = new CategoryPath(categoryPathStr);

                    // 检查 Typedef 是否已存在
                    String existingPath = catPath.getPath() + (catPath.getPath().endsWith("/") ? "" : "/") + name;
                    if (dtm.getDataType(existingPath) != null) {
                        errorMsg.set("Error: Typedef '" + name + "' already exists in category '" + categoryPathStr + "'");
                        return;
                    }

                    // 解析基础数据类型
                    DataType baseType = resolveDataType(dtm, baseDataTypeStr);
                    if (baseType == null) {
                        errorMsg.set("Error: Base data type '" + baseDataTypeStr + "' not found");
                        return;
                    }

                    // 创建 Typedef
                    DataType typedef;
                    if (isPointer) {
                        // 创建指针 Typedef
                        typedef = new TypedefDataType(
                            catPath,
                            name,
                            new PointerDataType(baseType)
                        );
                    } else {
                        // 创建普通 Typedef
                        typedef = new TypedefDataType(
                            catPath,
                            name,
                            baseType
                        );
                    }

                    // 添加到数据类型管理器
                    DataType addedTypedef = dtm.addDataType(typedef, null);
                    if (addedTypedef != null) {
                        success.set(true);
                        Msg.info(this, "Created typedef: " + addedTypedef.getPathName());
                    } else {
                        errorMsg.set("Error: Failed to add typedef to data type manager");
                    }
                } catch (Exception e) {
                    errorMsg.set("Error: Failed to create typedef: " + e.getMessage());
                    Msg.error(this, "Failed to create typedef", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute typedef creation on Swing thread", e);
            return "Error: Failed to execute typedef creation: " + e.getMessage();
        }

        if (success.get()) {
            return "Typedef '" + name + "' created successfully in category '" + categoryPathStr + "'";
        } else {
            return errorMsg.get();
        }
    }

    /**
     * 用于在 Lambda 中传递可变字符串
     */
    private static class AtomicString {
        private String value;

        public AtomicString(String initialValue) {
            this.value = initialValue;
        }

        public String get() {
            return value;
        }

        public void set(String value) {
            this.value = value;
        }
    }

    /**
     * 从 JSON 字符串创建联合体 (Union) 数据类型
     * @param jsonStr JSON 格式的联合体定义
     * @return 成功消息或错误消息
     *
     * 请求格式:
     * {
     *   "name": "Variant",
     *   "categoryPath": "/MyTypes",
     *   "description": "Union data type",
     *   "fields": [
     *     {"name": "asInt", "dataType": "/int", "length": 4, "comment": "As integer"},
     *     {"name": "asFloat", "dataType": "/float", "length": 4, "comment": "As float"}
     *   ]
     * }
     */
    private String createUnionFromJson(String jsonStr) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "Error: No program loaded";
        }

        // 简单的 JSON 解析 (不使用外部库)
        String name = extractJsonString(jsonStr, "name");
        String categoryPath = extractJsonString(jsonStr, "categoryPath");
        String description = extractJsonString(jsonStr, "description");

        // 验证必需字段
        if (name == null || name.isEmpty()) {
            return "Error: 'name' field is required";
        }
        if (categoryPath == null || categoryPath.isEmpty()) {
            return "Error: 'categoryPath' field is required";
        }

        // 提取 fields 数组
        String fieldsStr = extractJsonArray(jsonStr, "fields");
        if (fieldsStr == null) {
            return "Error: 'fields' array is required";
        }

        // 解析字段 (使用与结构体相同的解析逻辑)
        List<StructField> fields = parseFields(fieldsStr);
        if (fields == null) {
            return "Error: Failed to parse fields";
        }

        // 创建联合体
        AtomicBoolean success = new AtomicBoolean(false);
        AtomicString errorMsg = new AtomicString("");

        try {
            SwingUtilities.invokeAndWait(() -> {
                int txId = program.startTransaction("Create union: " + name);
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    CategoryPath catPath = new CategoryPath(categoryPath);

                    // 检查联合体是否已存在
                    String existingPath = catPath.getPath() + (catPath.getPath().endsWith("/") ? "" : "/") + name;
                    if (dtm.getDataType(existingPath) != null) {
                        errorMsg.set("Error: Union '" + name + "' already exists in category '" + categoryPath + "'");
                        return;
                    }

                    // 创建联合体 (注意: 联合体的构造函数与结构体相同)
                    UnionDataType union = new UnionDataType(catPath, name);
                    if (description != null && !description.isEmpty()) {
                        union.setDescription(description);
                    }

                    // 添加字段 (联合体的字段添加逻辑与结构体相同)
                    for (StructField field : fields) {
                        // 解析数据类型
                        DataType fieldType = resolveDataType(dtm, field.dataType);
                        if (fieldType == null) {
                            errorMsg.set("Error: Data type '" + field.dataType + "' not found for field '" + field.name + "'");
                            return;
                        }

                        // 添加字段到联合体
                        try {
                            DataTypeComponent component = union.add(fieldType, field.length, field.name, field.comment);
                            if (component == null) {
                                errorMsg.set("Error: Failed to add field '" + field.name + "' to union");
                                return;
                            }
                        } catch (Exception e) {
                            errorMsg.set("Error: Failed to add field '" + field.name + "': " + e.getMessage());
                            Msg.error(this, "Failed to add union field", e);
                            return;
                        }
                    }

                    // 添加到数据类型管理器
                    DataType addedUnion = dtm.addDataType(union, null);
                    if (addedUnion != null) {
                        success.set(true);
                        Msg.info(this, "Created union: " + addedUnion.getPathName());
                    } else {
                        errorMsg.set("Error: Failed to add union to data type manager");
                    }
                } catch (Exception e) {
                    errorMsg.set("Error: Failed to create union: " + e.getMessage());
                    Msg.error(this, "Failed to create union", e);
                } finally {
                    program.endTransaction(txId, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute union creation on Swing thread", e);
            return "Error: Failed to execute union creation: " + e.getMessage();
        }

        if (success.get()) {
            return "Union '" + name + "' created successfully in category '" + categoryPath + "'";
        } else {
            return errorMsg.get();
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

    /**
     * 辅助方法：输出消息到 Ghidra Console
     * 这比 System.out.println 和 Msg.info 更可靠，因为 ConsoleService 直接输出到 Ghidra Console
     * ConsoleService.addMessage(source, message) 需要两个参数
     */
    private void printToConsole(String message) {
        if (consoleService != null) {
            consoleService.addMessage("GhidraMCP", message);
        }
        // 同时输出到日志
        Msg.info(this, message);
    }

    /**
     * 辅助方法：输出错误到 Ghidra Console
     */
    private void printErrorToConsole(String message) {
        if (consoleService != null) {
            consoleService.addErrorMessage("GhidraMCP", message);
        }
        // 同时输出到日志
        Msg.error(this, message);
    }
}
